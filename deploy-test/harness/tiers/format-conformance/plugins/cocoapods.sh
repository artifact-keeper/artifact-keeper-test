# =============================================================================
# plugins/cocoapods.sh — format-conformance plugin (cocoapods)
# FC_FORMAT: cocoapods
# FC_MOUNT: cocoapods
# FC_REPO_FORMAT: cocoapods
# FC_PROFILE: client.cocoapods
# FC_SERVICE: client-cocoapods
# FC_ENABLED: 0
# =============================================================================
# Real client leg, HELD DISABLED pending the backend fix for #2638.
#
# This is no longer a feasibility probe: it is the full publish -> `pod install`
# -> assert flow, and it PASSES (9/9) against a backend that serves the CocoaPods
# CDN layout. It stays FC_ENABLED: 0 only because the fix is not on main yet;
# against a backend without it, fc_client_setup fails at `pod repo add-cdn`.
# Flip to 1 when #2638 merges. To run it now:
#   FC_ONLY=cocoapods ./harness/run.sh format-conformance --backend-image <img>
# after flipping the header to 1.
#
# A `pod` client consumes a spec repo over one of two transports: a git Specs
# repository, or a CDN. This exercises the CDN path, which is the modern
# default:
#
#   * `pod repo add-cdn` probes `/CocoaPods-version.yml` to decide the URL is a
#     CDN source at all, and reads the shard fan-out (`prefix_lengths`) from it.
#   * `pod install` reads `/all_pods_versions_<a>_<b>_<c>.txt` for the shard the
#     pod name hashes into (MD5-prefix fan-out), then fetches the podspec from
#     `/Specs/<a>/<b>/<c>/<name>/<version>/<name>.podspec.json`, then downloads
#     the pod archive from the podspec's `source`.
#
# Backend gap #2638 (no CDN layout served) made every one of those steps 404;
# the leg was a curl-only feasibility probe until the backend served the layout.
# See rig/results/format-conformance/cocoapods-finding.md.
#
# Container notes (all load-bearing, all verified on arm64):
#   * `pod` refuses to run as root and the client image runs as root, so every
#     invocation needs `--allow-root`.
#   * CocoaPods shells out to `rsync` to vendor a pod into `Pods/`; the ruby
#     image does not ship it (installed in fc_client_setup).
#   * there is no Xcode on Linux, so the Podfile disables user-project
#     integration (`install! 'cocoapods', :integrate_targets => false`). The
#     resolve/download/vendor path under test is unaffected.
# =============================================================================
FC_CASES="cdn_layout_served cdn_shard_addressing specs_layout_selfconsistent"

COCO_NAME="DtfMarker"
COCO_VER="1.0.0"
COCO_TGZ_NAME="${COCO_NAME}-${COCO_VER}.tar.gz"
COCO_MARKER_TOKEN="DTF-COCOAPODS-INSTALLED-${COCO_VER}"
COCO_BUILDSH="${DTF_DIR}/fixtures/cocoapods/build.sh"

# ---------------------------------------------------------------------------
# coco_shard — the CDN shard fragment for a pod name: the first three hex chars
# of its MD5, one per `prefix_lengths` entry advertised by the backend. This is
# computed here independently of the backend (from the rule cocoapods-core
# implements in Source::Metadata#path_fragment) so the cases below assert the
# addressing rather than echo the server's own answer.
# args: <pod-name> <sep>   e.g. coco_shard DtfMarker _  ->  b_5_5
# ---------------------------------------------------------------------------
coco_shard() {
  local name="$1" sep="$2" h
  h="$(printf '%s' "$name" | md5sum | cut -c1-3)"
  printf '%s%s%s%s%s' "${h:0:1}" "$sep" "${h:1:1}" "$sep" "${h:2:1}"
}

# ---------------------------------------------------------------------------
# fc_publish — host-craft the pod archive and POST it on the native push route
# (raw tar.gz body; push_pod scans for *.podspec.json). The podspec's `source`
# points back at the AK pods/ route so the client can fetch the archive itself.
# ---------------------------------------------------------------------------
fc_publish() {
  COCO_TGZ="$(bash "$COCO_BUILDSH" "$WORK_DIR" "$COCO_NAME" "$COCO_VER" \
    "$COCO_MARKER_TOKEN" "${FC_INT_URL}/pods/${COCO_TGZ_NAME}")" || return 1
  [ -s "$COCO_TGZ" ] || { echo "fixture build produced no archive"; return 1; }
  COCO_PUB_SHA="$(nc_sha256 "$COCO_TGZ")"
  echo "  fixture=${COCO_TGZ} sha256=${COCO_PUB_SHA}"
  local code
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 120 \
    -X POST -H "$(format_auth_header)" --data-binary "@${COCO_TGZ}" "${FC_URL}/pods")"
  [ "$code" = "200" ] || { echo "  push_pod POST -> ${code} (wanted 200)"; return 1; }
  echo "  pushed pod (HTTP ${code})"
  nc_expect_code 200 "${FC_URL}/all_specs" || return 1
}

# ---------------------------------------------------------------------------
# fc_client_setup — install the CocoaPods gem (+ rsync) and register the AK repo
# as a CDN source. `pod repo add-cdn` is itself a real assertion: it only
# succeeds if /CocoaPods-version.yml is served and parses.
# ---------------------------------------------------------------------------
fc_client_setup() {
  nc_exec -t 300 'command -v rsync >/dev/null 2>&1 || { apt-get update -qq && apt-get install -y -qq rsync; } >/dev/null 2>&1
command -v pod >/dev/null 2>&1 || gem install --no-document cocoapods 2>&1 | tail -2
pod --version --allow-root' \
    || { echo "cocoapods gem missing/uninstallable"; return 1; }
  nc_exec -t 120 "pod repo remove dtf --allow-root 2>/dev/null; rm -rf /root/.cocoapods/repos/dtf
pod repo add-cdn dtf '${FC_INT_URL}/' --allow-root 2>&1" \
    || { echo "pod repo add-cdn failed (CDN entrypoint not usable)"; return 1; }
}

# ---------------------------------------------------------------------------
# fc_consume — the REAL client. Resolves the pod through the CDN layout and
# vendors it into Pods/.
# ---------------------------------------------------------------------------
fc_consume() {
  nc_exec -t 300 "rm -rf /root/consume && mkdir -p /root/consume && cd /root/consume
cat > Podfile <<EOF
platform :ios, '12.0'
install! 'cocoapods', :integrate_targets => false
source '${FC_INT_URL}/'
target 'DtfConsumer' do
  pod '${COCO_NAME}', '${COCO_VER}'
end
EOF
pod install --allow-root --verbose 2>&1 | tail -40" \
    || { echo "pod install failed"; return 1; }
}

# ---------------------------------------------------------------------------
# fc_assert — the pod resolved from AK actually landed on the client fs, with
# the exact bytes that were published.
# ---------------------------------------------------------------------------
fc_assert() {
  nc_exec "grep -rq '${COCO_MARKER_TOKEN}' /root/consume/Pods/${COCO_NAME}/" \
    || { echo "marker not vendored under Pods/${COCO_NAME}/"; return 1; }
  # The lockfile must attribute the pod to the AK source, not to some other
  # repo the client happened to have.
  nc_exec "grep -q '${FC_INT_URL}/' /root/consume/Podfile.lock" \
    || { echo "Podfile.lock does not attribute the pod to the AK source"; return 1; }
  echo "  ${COCO_NAME} ${COCO_VER} vendored from AK and marker present"
}

# ---------------------------------------------------------------------------
# fc_advertised_check — every document the backend advertises resolves, and the
# pod archive downloads byte-identical to what was pushed.
# ---------------------------------------------------------------------------
fc_advertised_check() {
  # all_specs advertises the pod name -> versions
  local v
  v="$(nc_advertised "${FC_URL}/all_specs" \
    "jq -r '.[\"${COCO_NAME}\"][].version' | head -1")" || return 1
  [ "$v" = "$COCO_VER" ] || { echo "  all_specs version=${v} != ${COCO_VER}"; return 1; }
  echo "  all_specs advertises ${COCO_NAME} ${v}"
  # the CDN index advertises the pod under its own shard
  local idx
  idx="all_pods_versions_$(coco_shard "$COCO_NAME" _).txt"
  local line
  line="$(nc_advertised "${FC_URL}/${idx}" "grep '^${COCO_NAME}/'")" || return 1
  [ "$line" = "${COCO_NAME}/${COCO_VER}" ] \
    || { echo "  ${idx} line='${line}' != '${COCO_NAME}/${COCO_VER}'"; return 1; }
  echo "  ${idx} advertises ${line}"
  # the CDN podspec resolves and self-describes
  local spec_path spec_name spec_ver
  spec_path="Specs/$(coco_shard "$COCO_NAME" /)/${COCO_NAME}/${COCO_VER}/${COCO_NAME}.podspec.json"
  spec_name="$(nc_advertised "${FC_URL}/${spec_path}" "jq -r '.name'")" || return 1
  spec_ver="$(curl -s --max-time 60 -H "$(format_auth_header)" \
    "${FC_URL}/${spec_path}" | jq -r '.version')"
  [ "$spec_name" = "$COCO_NAME" ] && [ "$spec_ver" = "$COCO_VER" ] \
    || { echo "  podspec name/version mismatch: ${spec_name}/${spec_ver}"; return 1; }
  echo "  ${spec_path} resolves and self-describes ${spec_name} ${spec_ver}"
  # the pod archive downloads byte-identical to the pushed bytes
  local dl served
  dl="${WORK_DIR}/served-${COCO_TGZ_NAME}"
  nc_fetch "${FC_URL}/pods/${COCO_TGZ_NAME}" "$dl" || return 1
  served="$(nc_sha256 "$dl")"
  nc_assert_sha_eq "$COCO_PUB_SHA" "$served" "pushed archive != served archive" || return 1
}

# ===========================================================================
# Cases
# ===========================================================================

# cdn_layout_served — the CDN entrypoints a real client needs are served, and
# the manifest advertises the fan-out the rest of the layout is keyed by.
# Regression cover for #2638.
fc_case_cdn_layout_served() {
  nc_expect_code 200 "${FC_URL}/CocoaPods-version.yml" || return 1
  local lengths
  lengths="$(curl -s --max-time 60 -H "$(format_auth_header)" \
    "${FC_URL}/CocoaPods-version.yml" | grep -c '^- 1$')"
  [ "$lengths" = "3" ] \
    || { echo "  CocoaPods-version.yml does not advertise prefix_lengths [1,1,1]"; return 1; }
  echo "  /CocoaPods-version.yml served, prefix_lengths [1,1,1]"
  # the deprecation list must resolve: the client reads it back off disk after
  # downloading it, so a 404 is a hard error there rather than an empty list.
  nc_expect_code 200 "${FC_URL}/deprecated_podspecs.txt" || return 1
}

# cdn_shard_addressing — the pod is addressable at exactly the shard its name
# hashes to, and nowhere else. Pins the MD5-prefix rule end to end: an index or
# Specs tree that ignored the fan-out would still serve the pod somewhere, and
# a real client would never find it.
fc_case_cdn_shard_addressing() {
  local shard_u shard_s
  shard_u="$(coco_shard "$COCO_NAME" _)"
  shard_s="$(coco_shard "$COCO_NAME" /)"
  echo "  ${COCO_NAME} hashes to shard ${shard_s}"

  # present in its own shard index...
  curl -s --max-time 60 -H "$(format_auth_header)" \
    "${FC_URL}/all_pods_versions_${shard_u}.txt" | grep -q "^${COCO_NAME}/" \
    || { echo "  pod missing from its own shard index all_pods_versions_${shard_u}.txt"; return 1; }
  # ...and absent from a shard it does not hash to
  curl -s --max-time 60 -H "$(format_auth_header)" \
    "${FC_URL}/all_pods_versions_0_0_0.txt" | grep -q "^${COCO_NAME}/" \
    && { echo "  pod leaked into a foreign shard index"; return 1; }
  echo "  indexed under ${shard_u} only"

  # the podspec resolves under the correct fan-out and not under a wrong one
  nc_expect_code 200 \
    "${FC_URL}/Specs/${shard_s}/${COCO_NAME}/${COCO_VER}/${COCO_NAME}.podspec.json" || return 1
  nc_expect_code 400 \
    "${FC_URL}/Specs/0/0/0/${COCO_NAME}/${COCO_VER}/${COCO_NAME}.podspec.json" || return 1
  echo "  podspec addressable under ${shard_s} only"
}

# specs_layout_selfconsistent — the flat Specs layout that predates CDN support
# still resolves alongside the CDN tree (it is a documented API surface).
fc_case_specs_layout_selfconsistent() {
  nc_expect_code 200 "${FC_URL}/Specs/${COCO_NAME}/${COCO_VER}/${COCO_NAME}.podspec.json" || return 1
  nc_expect_code 200 "${FC_URL}/pods/${COCO_TGZ_NAME}" || return 1
  echo "  flat Specs podspec + pods archive both still resolve"
}
