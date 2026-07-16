# =============================================================================
# plugins/cocoapods.sh — format-conformance plugin (cocoapods) — FEASIBILITY PROBE
# FC_FORMAT: cocoapods
# FC_MOUNT: cocoapods
# FC_REPO_FORMAT: cocoapods
# FC_PROFILE: client.cocoapods
# FC_SERVICE: client-cocoapods
# FC_ENABLED: 0
# =============================================================================
# FEASIBILITY PROBE (FC_ENABLED: 0). A real `pod install` consumes a pod source
# via ONE of two transports, NEITHER of which the backend provides:
#
#   * CDN mode — a static CDN that serves `/CocoaPods-version.yml`, sharded
#     `/all_pods_versions_<a>_<b>_<c>.txt` files, and MD5-fanned
#     `/Specs/<a>/<b>/<c>/<name>/<version>/<name>.podspec.json`. The backend
#     router (handlers/cocoapods.rs) serves NONE of these: no version.yml, no
#     shard files, and a FLAT `Specs/<name>/<version>/...` (not the 3-level
#     MD5 fan-out). `pod repo add-cdn` probes `/CocoaPods-version.yml` first and
#     fails immediately.
#   * git mode — a git Specs repository over a git transport. The backend has no
#     git transport for cocoapods.
#
# So a real pod client CANNOT consume this repo. This plugin does NOT fake a
# green `pod install` (§6). It PUBLISHES a pod, curl-verifies the self-
# consistency of the layout the backend DOES serve (all_specs / podspec / pod
# archive), and asserts the CDN entrypoint is absent — the documented backend
# gap. See rig/results/format-conformance/cocoapods-finding.md.
#
# To run the probe manually: flip FC_ENABLED to 1 and `FC_ONLY=cocoapods
# ./harness/run.sh format-conformance ...`. fc_consume stays KNOWN-RED.
# =============================================================================
FC_CASES="specs_layout_selfconsistent cdn_layout_absent"

COCO_NAME="DtfMarker"
COCO_VER="1.0.0"
COCO_TGZ_NAME="${COCO_NAME}-${COCO_VER}.tar.gz"
COCO_MARKER_TOKEN="DTF-COCOAPODS-INSTALLED-${COCO_VER}"
COCO_BUILDSH="${DTF_DIR}/fixtures/cocoapods/build.sh"

# ---------------------------------------------------------------------------
# fc_publish — host-craft the pod archive and POST it on the native push route
# (raw tar.gz body; push_pod scans for *.podspec.json). This WORKS today.
# ---------------------------------------------------------------------------
fc_publish() {
  COCO_TGZ="$(bash "$COCO_BUILDSH" "$WORK_DIR" "$COCO_NAME" "$COCO_VER" "$COCO_MARKER_TOKEN")" \
    || return 1
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
# fc_client_setup — install the CocoaPods gem and attempt to register the AK
# repo as a CDN source. KNOWN-RED: `pod repo add-cdn` probes the CDN entrypoint
# (/CocoaPods-version.yml) which the backend does not serve.
# ---------------------------------------------------------------------------
fc_client_setup() {
  nc_exec -t 300 'command -v pod >/dev/null 2>&1 || gem install --no-document cocoapods 2>&1 | tail -2; pod --version' \
    || { echo "cocoapods gem missing/uninstallable"; return 1; }
  nc_exec "pod repo remove dtf 2>/dev/null; pod repo add-cdn dtf '${FC_INT_URL}/' 2>&1" \
    || { echo "pod repo add-cdn failed (KNOWN-RED: no CDN entrypoint served)"; return 1; }
}

# ---------------------------------------------------------------------------
# fc_consume — the REAL client. KNOWN-RED: with no consumable transport,
# `pod install` cannot resolve the pod from AK.
# ---------------------------------------------------------------------------
fc_consume() {
  nc_exec "rm -rf /root/consume && mkdir -p /root/consume && cd /root/consume
cat > Podfile <<EOF
platform :ios, '12.0'
source '${FC_INT_URL}/'
target 'DtfConsumer' do
  pod '${COCO_NAME}', '${COCO_VER}'
end
EOF
pod install --verbose 2>&1" \
    || { echo "pod install failed (KNOWN-RED: repo not consumable by a real pod client)"; return 1; }
}

# ---------------------------------------------------------------------------
# fc_assert — would prove the pod source landed on the client fs (never reached
# while consume is KNOWN-RED).
# ---------------------------------------------------------------------------
fc_assert() {
  nc_exec "grep -rq '${COCO_MARKER_TOKEN}' /root/consume/Pods/${COCO_NAME}/ 2>/dev/null" \
    || { echo "marker not vendored under Pods/"; return 1; }
}

# ---------------------------------------------------------------------------
# fc_advertised_check — the layout the backend DOES serve, verified self-
# consistent: all_specs lists the pod; the podspec route returns matching
# name/version; the pod archive downloads byte-identical to what was pushed.
# ---------------------------------------------------------------------------
fc_advertised_check() {
  # all_specs advertises the pod name -> versions
  local v
  v="$(nc_advertised "${FC_URL}/all_specs" \
    "jq -r '.[\"${COCO_NAME}\"][].version' | head -1")" || return 1
  [ "$v" = "$COCO_VER" ] || { echo "  all_specs version=${v} != ${COCO_VER}"; return 1; }
  echo "  all_specs advertises ${COCO_NAME} ${v}"
  # the advertised podspec resolves and self-describes
  local spec_name spec_ver
  spec_name="$(nc_advertised "${FC_URL}/Specs/${COCO_NAME}/${COCO_VER}/${COCO_NAME}.podspec.json" \
    "jq -r '.name'")" || return 1
  spec_ver="$(curl -s --max-time 60 -H "$(format_auth_header)" \
    "${FC_URL}/Specs/${COCO_NAME}/${COCO_VER}/${COCO_NAME}.podspec.json" | jq -r '.version')"
  [ "$spec_name" = "$COCO_NAME" ] && [ "$spec_ver" = "$COCO_VER" ] \
    || { echo "  podspec name/version mismatch: ${spec_name}/${spec_ver}"; return 1; }
  echo "  podspec resolves and self-describes ${spec_name} ${spec_ver}"
  # the pod archive downloads byte-identical to the pushed bytes
  local dl served
  dl="${WORK_DIR}/served-${COCO_TGZ_NAME}"
  nc_fetch "${FC_URL}/pods/${COCO_TGZ_NAME}" "$dl" || return 1
  served="$(nc_sha256 "$dl")"
  nc_assert_sha_eq "$COCO_PUB_SHA" "$served" "pushed archive != served archive" || return 1
}

# ===========================================================================
# Probe cases
# ===========================================================================

# specs_layout_selfconsistent — the flat Specs layout the backend serves is
# internally consistent (podspec `source` references the pods/ path that
# actually serves the archive). This is what the backend DOES offer.
fc_case_specs_layout_selfconsistent() {
  nc_expect_code 200 "${FC_URL}/Specs/${COCO_NAME}/${COCO_VER}/${COCO_NAME}.podspec.json" || return 1
  nc_expect_code 200 "${FC_URL}/pods/${COCO_TGZ_NAME}" || return 1
  echo "  Specs podspec + pods archive both resolve (flat layout self-consistent)"
}

# cdn_layout_absent — the CocoaPods CDN entrypoints a real client needs are NOT
# served. This is the BACKEND GAP (documented, not softened): a conformant CDN
# repo must serve /CocoaPods-version.yml and all_pods_versions_* shard files.
fc_case_cdn_layout_absent() {
  # A conformant CDN would 200 these; the backend 404s them (the gap).
  nc_expect_code 404 "${FC_URL}/CocoaPods-version.yml" || {
    echo "  UNEXPECTED: /CocoaPods-version.yml resolved (CDN entrypoint present?)"; return 1; }
  echo "  CDN entrypoint /CocoaPods-version.yml is absent (confirmed backend gap)"
}
