#!/usr/bin/env bash
# =============================================================================
# tiers/vscode-gallery-protocol/oracle.sh
#   #3961 a VSIX publish reads the archive: header/archive mismatch 400,
#         missing engines.vscode 400, headerless publish, parsed metadata
#   #3956 a hosted vscode repository answers the gallery protocol
#   #3962 a virtual vscode repository aggregates hosted + remote members
#   #4099 /api/v1/formats reports scan_on_proxy; the legacy download route on
#         a Remote is scanned
# See the manifest for the behaviour, the primitives and the gates.
#
# run.sh exported BASE_URL, ADMIN_PASS, DB_CONTAINER, RUN_ID, DTF_SLOT,
# TRIVY_PORT (the mock's published control port), RELEASE_GATE=1,
# JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"; : "${DB_CONTAINER:?}"
: "${DTF_SLOT:?}"; : "${TRIVY_PORT:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

BASE="$BASE_URL"
MOCK="http://127.0.0.1:${TRIVY_PORT}"
# Where the BACKEND reaches the mock Open VSX (profiles/upstreams.mock-recorder.yml).
UPHOST="http://172.16.${DTF_SLOT}.77"
GALLERY_UP="${UPHOST}/vscode/gallery"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

setup_workdir
W="$WORK_DIR"

jqr(){ jq -r "$1" 2>/dev/null || true; }
sha_of(){ sha256sum "$1" 2>/dev/null | awk '{print $1}' || true; }
hdr_of(){ grep -i "^$2:" "$1" 2>/dev/null | tr -d '\r' | awk '{print $2}' | head -n1 || true; }
psql_q(){ docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null || true; }

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

mock_put(){ # <path> <file> [ctype] [status] -> stored byte count
  curl -s --max-time 30 -X PUT --data-binary @"$2" \
    "${MOCK}/__file?path=$1&ctype=${3:-application/octet-stream}&status=${4:-200}" | jqr '.bytes // empty'
}

auth(){ printf 'Authorization: Bearer %s' "$TOK"; }
basic(){ printf 'Authorization: Basic %s' "$(printf '%s:%s' admin "$ADMIN_PASS" | base64 | tr -d '\n')"; }
vsix(){ python3 -I "${HERE}/fixtures/make_vsix.py" "$@" >/dev/null 2>&1 || true; }
# publish <repo> <file> [x-publisher x-extension-name x-extension-version]
#   -> HTTP code; body in $W/pub.o
publish(){
  local repo="$1" file="$2"; shift 2
  local hdr=()
  if [ "$#" -eq 3 ]; then
    hdr=(-H "x-publisher: $1" -H "x-extension-name: $2" -H "x-extension-version: $3")
  fi
  curl -s --max-time 60 -o "$W/pub.o" -w '%{http_code}' -X POST -H "$(basic)" \
    -H 'Content-Type: application/octet-stream' "${hdr[@]}" --data-binary @"$file" \
    "$BASE/vscode/${repo}/api/extensions" 2>/dev/null || echo 000
}
# gq <repo> <json body> <out> -> HTTP code (anonymous: the gallery is public-only)
gq(){
  curl -s --max-time 60 -o "$3" -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
    -d "$2" "$BASE/vscode/$1/gallery/extensionquery" 2>/dev/null || echo 000
}
q_name(){ # <extension id> <flags>
  jq -cn --arg v "$1" --argjson f "$2" '{filters:[{criteria:[{filterType:7,value:$v}],pageNumber:1,pageSize:10}],flags:$f}'
}
q_search(){ # <text> <flags> <pageNumber> <pageSize>
  jq -cn --arg v "$1" --argjson f "$2" --argjson n "$3" --argjson s "$4" \
    '{filters:[{criteria:[{filterType:10,value:$v}],pageNumber:$n,pageSize:$s}],flags:$f}'
}
ids_of(){ jq -r '[.results[0].extensions[]? | (.publisher.publisherName + "." + .extensionName)] | sort | join(",")' "$1" 2>/dev/null || true; }
total_of(){ jqr '.results[0].resultMetadata[0].metadataItems[0].count // empty' < "$1"; }
artifact_id(){ # <repo> <extension id> <version>
  psql_q "SELECT a.id FROM artifacts a JOIN repositories r ON r.id = a.repository_id
          WHERE r.key = '$1' AND LOWER(a.name) = LOWER('$2') AND a.version = '$3' AND a.is_deleted = false LIMIT 1"
}
meta_of(){ # <repo> <extension id> <version> -> metadata JSON
  psql_q "SELECT am.metadata FROM artifact_metadata am JOIN artifacts a ON a.id = am.artifact_id
          JOIN repositories r ON r.id = a.repository_id
          WHERE r.key = '$1' AND LOWER(a.name) = LOWER('$2') AND a.version = '$3' AND a.is_deleted = false LIMIT 1"
}

# Flags: 19 = IncludeVersions | IncludeFiles | IncludeVersionProperties
#        914 = IncludeFiles | IncludeVersionProperties | IncludeAssetUri |
#              IncludeStatistics | IncludeLatestVersionOnly (VS Code's search)
F_ALL=19
F_SEARCH=914

# =============================================================================
begin_suite "vscode-gallery-protocol"

begin_test "setup: admin login, VSIX fixtures, mock Open VSX, hosted / remote / virtual vscode repositories"
TOK="$(curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"${ADMIN_PASS}\"}" | jqr '.access_token // .token // empty')"
if [ -z "$TOK" ]; then infra_fail "admin login failed at $BASE"; end_suite; fi
if [ "$(curl -s --max-time 5 "${MOCK}/__readyz" || true)" != "ok" ]; then
  infra_fail "mock upstream not reachable on ${MOCK} (profiles/upstreams.mock-recorder.yml)"; end_suite
fi
SUF="${RUN_ID##*-}-$$"
H="vgp-h-${SUF}"     # hosted
R="vgp-r-${SUF}"     # remote over the mock Open VSX, no scanning
RS="vgp-rs-${SUF}"   # remote over the mock Open VSX, scan-on-proxy
V="vgp-v-${SUF}"     # virtual: H (priority 1), R (priority 2)
SETUP_ERR=""
P="dtfpub"
vsix "$W/shared1.vsix" "$P" shared 1.0.0 --description "hosted shared one"
vsix "$W/shared2.vsix" "$P" shared 2.0.0 --description "hosted shared two"
vsix "$W/hostedonly.vsix" "$P" hostedonly 1.0.0 --description "hosted only" --target linux-x64
vsix "$W/noengine.vsix" "$P" noengine 1.0.0 --engine ""
vsix "$W/mismatch.vsix" "$P" mismatch 1.0.0 --description "mismatch"
vsix "$W/legacyplain.vsix" "$P" legacyplain 1.0.0 --description "legacy plain"
vsix "$W/legacyscan.vsix" "$P" legacyscan 1.0.0 --description "legacy scan"
for f in shared1 shared2 hostedonly noengine mismatch legacyplain legacyscan; do
  [ -s "$W/${f}.vsix" ] || SETUP_ERR="${SETUP_ERR} vsix:${f}"
done

# The mock Open VSX gallery: one canned extensionquery page (a remote copy of
# dtfpub.shared that the hosted member must shadow, and dtfpub.remoteonly),
# whose asset URLs point at the mock itself, plus the legacy download bytes.
jq -n --arg up "$GALLERY_UP" '
  def ext($name; $desc): {
    publisher: {publisherName: "dtfpub", displayName: "dtfpub"},
    extensionName: $name, displayName: $name, shortDescription: $desc,
    versions: [{
      version: "5.0.0", lastUpdated: "2020-01-01T00:00:00Z",
      assetUri: ($up + "/asset/dtfpub/" + $name + "/5.0.0"),
      fallbackAssetUri: ($up + "/asset/dtfpub/" + $name + "/5.0.0"),
      files: [{assetType: "Microsoft.VisualStudio.Services.VSIXPackage",
               source: ($up + "/asset/dtfpub/" + $name + "/5.0.0/Microsoft.VisualStudio.Services.VSIXPackage")}],
      properties: [{key: "Microsoft.VisualStudio.Code.Engine", value: "^1.70.0"}]
    }]
  };
  {results: [{extensions: [ext("shared"; "REMOTE copy of shared"), ext("remoteonly"; "remote only")],
              resultMetadata: [{metadataType: "ResultCount",
                                metadataItems: [{name: "TotalCount", count: 2}]}]}]}' > "$W/remote-page.json"
[ -n "$(mock_put "/vscode/gallery/extensionquery" "$W/remote-page.json" application/json)" ] || SETUP_ERR="${SETUP_ERR} mock:extensionquery"
[ -n "$(mock_put "/vscode/gallery/extensions/${P}/legacyplain/1.0.0/download" "$W/legacyplain.vsix")" ] || SETUP_ERR="${SETUP_ERR} mock:legacyplain"
[ -n "$(mock_put "/vscode/gallery/extensions/${P}/legacyscan/1.0.0/download" "$W/legacyscan.vsix")" ] || SETUP_ERR="${SETUP_ERR} mock:legacyscan"

mk(){ # <key> <type> [upstream] -> key
  curl -s -X POST "$BASE/api/v1/repositories" -H "$(auth)" -H 'Content-Type: application/json' \
    -d "$(jq -n --arg k "$1" --arg t "$2" --arg u "${3:-}" \
          '{key:$k,name:$k,format:"vscode",repo_type:$t,is_public:true} + (if $u == "" then {} else {upstream_url:$u} end)')" \
    | jqr '.key // empty'
}
member(){ # <virtual> <member> <priority>
  curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/v1/repositories/$1/members" -H "$(auth)" \
    -H 'Content-Type: application/json' -d "$(jq -n --arg k "$2" --argjson p "$3" '{member_key:$k,priority:$p}')" || true
}
[ "$(mk "$H" local)" = "$H" ] || SETUP_ERR="${SETUP_ERR} ${H}"
[ "$(mk "$R" remote "$GALLERY_UP")" = "$R" ] || SETUP_ERR="${SETUP_ERR} ${R}"
[ "$(mk "$RS" remote "$GALLERY_UP")" = "$RS" ] || SETUP_ERR="${SETUP_ERR} ${RS}"
[ "$(mk "$V" virtual)" = "$V" ] || SETUP_ERR="${SETUP_ERR} ${V}"
case "$(member "$V" "$H" 1)" in 2*) ;; *) SETUP_ERR="${SETUP_ERR} member:${H}";; esac
case "$(member "$V" "$R" 2)" in 2*) ;; *) SETUP_ERR="${SETUP_ERR} member:${R}";; esac
sec="$(curl -s -X PUT "$BASE/api/v1/repositories/${RS}/security" -H "$(auth)" -H 'Content-Type: application/json' \
  -d '{"scan_enabled":true,"scan_on_proxy":true,"proxy_scan_action":"fail_closed","block_on_policy_violation":true}' | jqr '.scan_on_proxy // empty')"
[ "$sec" = "true" ] || SETUP_ERR="${SETUP_ERR} security:${RS}"
if [ -n "$SETUP_ERR" ]; then infra_fail "setup failed:${SETUP_ERR}"; end_suite; fi
pass

# =============================================================================
# CONTROLS (both images)
# =============================================================================
begin_test "CONTROL: a VSIX published with matching x-* headers is stored and downloads byte-exact on the legacy route"
reset_case
c1="$(publish "$H" "$W/shared1.vsix" "$P" shared 1.0.0)"
c2="$(publish "$H" "$W/shared2.vsix" "$P" shared 2.0.0)"
code="$(curl -s -o "$W/dl1.o" -w '%{http_code}' -H "$(basic)" "$BASE/vscode/${H}/extensions/${P}/shared/1.0.0/download" || true)"
note "publish 1.0.0 -> ${c1}, 2.0.0 -> ${c2}; download 1.0.0 -> ${code}"
case "$c1" in 2*) ;; *) fail_g "publish of shared 1.0.0 with matching headers answered ${c1}: $(head -c 200 "$W/pub.o")";; esac
case "$c2" in 2*) ;; *) fail_g "publish of shared 2.0.0 with matching headers answered ${c2}";; esac
[ "$code" = "200" ] && [ "$(sha_of "$W/dl1.o")" = "$(sha_of "$W/shared1.vsix")" ] || fail_g "legacy download is not the published VSIX (HTTP ${code})"
finish_case "header-identified VSIX publish / download broken"

begin_test "CONTROL: a Remote gallery passes the upstream extensionquery through with every asset URL rewritten onto AK"
reset_case
code="$(gq "$R" "$(q_search dtfpub "$F_SEARCH" 1 10)" "$W/rq.o")"
ids="$(ids_of "$W/rq.o")"
srcs="$(jq -r '[.results[0].extensions[]?.versions[]?.files[]?.source] | join(" ")' "$W/rq.o" 2>/dev/null || true)"
note "HTTP ${code}; ids ${ids}; sources ${srcs}"
[ "$code" = "200" ] || fail_g "Remote extensionquery answered ${code}"
[ "$ids" = "dtfpub.remoteonly,dtfpub.shared" ] || fail_g "Remote page lists '${ids}', expected the mock's two extensions"
case "$srcs" in *"/vscode/${R}/"*) ;; *) fail_g "no files[].source points at AK's /vscode/${R}/ routes";; esac
case "$srcs" in *"172.16.${DTF_SLOT}.77"*) fail_g "a files[].source still names the upstream host";; esac
finish_case "Remote gallery passthrough broken"

begin_test "CONTROL: the legacy download route on an unscanned Remote proxies the VSIX with no scan verdict"
reset_case
code="$(curl -s -D "$W/lp.h" -o "$W/lp.o" -w '%{http_code}' "$BASE/vscode/${R}/extensions/${P}/legacyplain/1.0.0/download" || true)"
xs="$(hdr_of "$W/lp.h" x-ak-scan)"
note "HTTP ${code}; X-AK-Scan '${xs:-<absent>}'"
[ "$code" = "200" ] && [ "$(sha_of "$W/lp.o")" = "$(sha_of "$W/legacyplain.vsix")" ] || fail_g "legacy Remote download answered ${code} or wrong bytes"
[ -z "$xs" ] || fail_g "an unscanned Remote carried X-AK-Scan '${xs}'"
finish_case "legacy Remote download broken"

# =============================================================================
# FIX #3961: the archive is the source of truth.
# =============================================================================
begin_test "FIX #3961: an x-extension-version header that disagrees with the archive is refused 400 naming the header, and nothing is stored"
reset_case
code="$(publish "$H" "$W/mismatch.vsix" "$P" mismatch 9.9.9)"
body="$(head -c 300 "$W/pub.o")"
rows="$(psql_q "SELECT COUNT(*) FROM artifacts a JOIN repositories r ON r.id = a.repository_id WHERE r.key = '${H}' AND LOWER(a.name) = 'dtfpub.mismatch'")"
note "HTTP ${code}; body '${body}'; dtfpub.mismatch rows ${rows}"
[ "$code" = "400" ] || fail_g "mismatching header publish answered ${code} (1.10.0 stores it under the header's 9.9.9)"
case "$body" in *x-extension-version*) ;; *) fail_g "the 400 does not name x-extension-version";; esac
[ "${rows:-x}" = "0" ] || fail_g "${rows:-?} artifact rows were stored for the refused publish"
finish_case "a header that contradicts the VSIX is trusted"

begin_test "FIX #3961: a package.json without engines.vscode is refused 400 even with complete headers"
reset_case
code="$(publish "$H" "$W/noengine.vsix" "$P" noengine 1.0.0)"
body="$(head -c 300 "$W/pub.o")"
note "HTTP ${code}; body '${body}'"
[ "$code" = "400" ] || fail_g "publish without engines.vscode answered ${code}"
case "$body" in *engines.vscode*) ;; *) fail_g "the 400 does not name engines.vscode";; esac
finish_case "a VSIX with no engines.vscode is accepted"

begin_test "FIX #3961: a headerless publish takes its identity from the archive and stores description, engine and targetPlatform"
reset_case
code="$(publish "$H" "$W/hostedonly.vsix")"
meta="$(meta_of "$H" dtfpub.hostedonly 1.0.0)"
meta1="$(meta_of "$H" dtfpub.shared 1.0.0)"
note "HTTP ${code}; body '$(head -c 160 "$W/pub.o")'"
note "hostedonly metadata ${meta:-<none>}"
note "shared 1.0.0 metadata ${meta1:-<none>}"
case "$code" in 2*) ;; *) fail_g "headerless publish answered ${code} (1.10.0 requires the x-* headers)";; esac
[ "$(printf '%s' "$meta" | jqr '.description // empty')" = "hosted only" ] || fail_g "headerless publish did not store the archive's description"
[ "$(printf '%s' "$meta" | jqr '.engine // empty')" = "^1.80.0" ] || fail_g "headerless publish did not store engines.vscode"
[ "$(printf '%s' "$meta" | jqr '.target_platform // empty')" = "linux-x64" ] || fail_g "headerless publish did not store Identity/@TargetPlatform"
[ "$(printf '%s' "$meta1" | jqr '.description // empty')" = "hosted shared one" ] || fail_g "a header-identified publish did not store the archive's description either"
finish_case "VSIX metadata is not read from the archive"

# =============================================================================
# FIX #3956: hosted gallery protocol.
# =============================================================================
begin_test "FIX #3956: hosted extensionquery (filterType 7) lists every version with its VSIXPackage file and engine property"
reset_case
code="$(gq "$H" "$(q_name dtfpub.shared "$F_ALL")" "$W/hq.o")"
vers="$(jq -r '[.results[0].extensions[0].versions[]?.version] | join(",")' "$W/hq.o" 2>/dev/null || true)"
src1="$(jq -r '.results[0].extensions[0].versions[]? | select(.version=="1.0.0") | .files[]? | select(.assetType=="Microsoft.VisualStudio.Services.VSIXPackage") | .source' "$W/hq.o" 2>/dev/null || true)"
eng="$(jq -r '.results[0].extensions[0].versions[0].properties[]? | select(.key=="Microsoft.VisualStudio.Code.Engine") | .value' "$W/hq.o" 2>/dev/null || true)"
note "HTTP ${code}; versions ${vers}; 1.0.0 VSIXPackage ${src1:-<none>}; engine ${eng:-<none>}; body $(head -c 120 "$W/hq.o")"
[ "$code" = "200" ] || fail_g "hosted extensionquery answered ${code} (1.10.0: 501, gallery routes are Remote-only)"
[ "$vers" = "2.0.0,1.0.0" ] || fail_g "versions '${vers}', expected 2.0.0,1.0.0 (newest first)"
[ "$src1" = "${BASE}/vscode/${H}/extensions/dtfpub/shared/1.0.0/download" ] || fail_g "the 1.0.0 VSIXPackage source is '${src1:-none}'"
[ "$eng" = "^1.80.0" ] || fail_g "the Microsoft.VisualStudio.Code.Engine property is '${eng:-absent}'"
finish_case "hosted gallery extensionquery"

begin_test "FIX #3956: hosted vspackage answers 307 to the legacy download, which serves the published bytes"
reset_case
code="$(curl -s -D "$W/vp.h" -o /dev/null -w '%{http_code}' "$BASE/vscode/${H}/gallery/publishers/dtfpub/vsextensions/shared/1.0.0/vspackage" || true)"
loc="$(hdr_of "$W/vp.h" location)"
note "HTTP ${code}; Location ${loc:-<none>}"
[ "$code" = "307" ] || fail_g "vspackage answered ${code} (1.10.0: 501)"
[ "$loc" = "/vscode/${H}/extensions/dtfpub/shared/1.0.0/download" ] || fail_g "Location is '${loc:-none}'"
if [ -n "$loc" ]; then
  c2="$(curl -s -o "$W/vp.o" -w '%{http_code}' -H "$(basic)" "${BASE}${loc}" || true)"
  [ "$c2" = "200" ] && [ "$(sha_of "$W/vp.o")" = "$(sha_of "$W/shared1.vsix")" ] || fail_g "following the redirect answered ${c2} or other bytes"
fi
finish_case "hosted vspackage"

begin_test "FIX #3956: search pages by pageNumber/pageSize and TotalCount counts every match"
reset_case
c1="$(gq "$H" "$(q_search dtfpub "$F_SEARCH" 1 1)" "$W/p1.o")"
c2="$(gq "$H" "$(q_search dtfpub "$F_SEARCH" 2 1)" "$W/p2.o")"
p1="$(ids_of "$W/p1.o")"; p2="$(ids_of "$W/p2.o")"; t1="$(total_of "$W/p1.o")"
note "page 1 (${c1}) ${p1} TotalCount ${t1}; page 2 (${c2}) ${p2}"
[ "$c1" = "200" ] && [ "$c2" = "200" ] || fail_g "search answered ${c1} / ${c2}"
[ "$t1" = "2" ] || fail_g "TotalCount ${t1:-absent}, expected 2 (shared, hostedonly)"
[ "$p1" = "dtfpub.hostedonly" ] && [ "$p2" = "dtfpub.shared" ] || fail_g "pages are '${p1}' / '${p2}', expected one extension each, in id order"
finish_case "hosted gallery paging"

begin_test "FIX #3956: a quarantined version is left out of the gallery listing"
reset_case
aid="$(artifact_id "$H" dtfpub.shared 2.0.0)"
qc="000"
[ -n "$aid" ] && qc="$(curl -s -o "$W/q.o" -w '%{http_code}' -X POST "$BASE/api/v1/quarantine/${aid}/quarantine" -H "$(auth)" \
  -H 'Content-Type: application/json' -d '{"reason":"dtf vscode-gallery-protocol"}' || true)"
code="$(gq "$H" "$(q_name dtfpub.shared "$F_ALL")" "$W/hq2.o")"
vers="$(jq -r '[.results[0].extensions[0].versions[]?.version] | join(",")' "$W/hq2.o" 2>/dev/null || true)"
note "artifact ${aid:-?}; quarantine HTTP ${qc}; listing (${code}) versions ${vers}"
case "$qc" in 2*) ;; *) fail_g "quarantining shared 2.0.0 answered ${qc}: $(head -c 160 "$W/q.o" 2>/dev/null)";; esac
[ "$code" = "200" ] || fail_g "hosted extensionquery answered ${code}"
[ "$vers" = "1.0.0" ] || fail_g "listing after quarantine shows '${vers}', expected 1.0.0 only"
finish_case "a quarantined version is still offered"

# =============================================================================
# FIX #3962: virtual aggregation.
# =============================================================================
begin_test "FIX #3962: a virtual gallery merges hosted and remote members, and the hosted member shadows the same extension"
reset_case
code="$(gq "$V" "$(q_search dtfpub "$F_SEARCH" 1 10)" "$W/vq.o")"
ids="$(ids_of "$W/vq.o")"
shared_n="$(jq '[.results[0].extensions[]? | select(.extensionName=="shared")] | length' "$W/vq.o" 2>/dev/null || true)"
shared_desc="$(jq -r '.results[0].extensions[]? | select(.extensionName=="shared") | .shortDescription' "$W/vq.o" 2>/dev/null || true)"
ro_src="$(jq -r '.results[0].extensions[]? | select(.extensionName=="remoteonly") | .versions[0].files[0].source' "$W/vq.o" 2>/dev/null || true)"
sh_src="$(jq -r '.results[0].extensions[]? | select(.extensionName=="shared") | .versions[0].files[0].source' "$W/vq.o" 2>/dev/null || true)"
note "HTTP ${code}; ids ${ids}; shared x${shared_n} '${shared_desc}'"
note "remoteonly source ${ro_src:-<none>}; shared source ${sh_src:-<none>}"
[ "$code" = "200" ] || fail_g "virtual extensionquery answered ${code} (1.10.0: 501)"
[ "$ids" = "dtfpub.hostedonly,dtfpub.remoteonly,dtfpub.shared" ] || fail_g "virtual lists '${ids}', expected hostedonly, remoteonly and shared"
[ "$shared_n" = "1" ] || fail_g "dtfpub.shared appears ${shared_n:-?} times"
case "$shared_desc" in "hosted shared"*) ;; *) fail_g "dtfpub.shared is described by '${shared_desc}', not the hosted member (shadowing)";; esac
case "$ro_src" in "${BASE}/vscode/${R}/"*) ;; *) fail_g "remoteonly's package is not routed through the remote member ${R}";; esac
case "$sh_src" in "${BASE}/vscode/${H}/extensions/dtfpub/shared/"*) ;; *) fail_g "shared's package is not routed through the hosted member ${H}";; esac
finish_case "virtual gallery aggregation"

begin_test "FIX #3962: a failing remote member is skipped and the hosted page is still served; vspackage on a virtual is 501"
reset_case
mock_put "/vscode/gallery/extensionquery" "$W/remote-page.json" application/json 500 >/dev/null
code="$(gq "$V" "$(q_search dtfpub "$F_SEARCH" 1 10)" "$W/vq2.o")"
ids="$(ids_of "$W/vq2.o")"
vp="$(curl -s -o /dev/null -w '%{http_code}' "$BASE/vscode/${V}/gallery/publishers/dtfpub/vsextensions/shared/1.0.0/vspackage" || true)"
mock_put "/vscode/gallery/extensionquery" "$W/remote-page.json" application/json 200 >/dev/null
note "upstream 500: virtual HTTP ${code}, ids ${ids}; virtual vspackage HTTP ${vp}"
[ "$code" = "200" ] || fail_g "virtual extensionquery answered ${code} with the remote member failing"
[ "$ids" = "dtfpub.hostedonly,dtfpub.shared" ] || fail_g "with the remote failing the virtual lists '${ids}', expected the hosted page only"
[ "$vp" = "501" ] || fail_g "vspackage on a virtual answered ${vp}, expected 501 (no byte route of its own)"
finish_case "virtual gallery failure handling"

# =============================================================================
# FIX #4099
# =============================================================================
begin_test "FIX #4099: /api/v1/formats reports scan_on_proxy=enforced for vscode, and the legacy Remote download is scanned"
reset_case
sop="$(curl -s -H "$(auth)" "$BASE/api/v1/formats" | jq -r '(if type=="array" then . else (.items // .formats // []) end)[] | select(.format_key=="vscode") | .scan_on_proxy // "absent"' 2>/dev/null || true)"
code="$(curl -s -D "$W/ls.h" -o "$W/ls.o" -w '%{http_code}' "$BASE/vscode/${RS}/extensions/${P}/legacyscan/1.0.0/download" || true)"
xs="$(hdr_of "$W/ls.h" x-ak-scan)"
digest="$(sha_of "$W/legacyscan.vsix")"
verdict="$(psql_q "SELECT verdict FROM proxy_scan_results WHERE checksum_sha256 = '${digest}' LIMIT 1")"
note "formats vscode scan_on_proxy=${sop:-?}; legacy scanned download HTTP ${code}, X-AK-Scan '${xs:-<absent>}', verdict row '${verdict:-<none>}'"
[ "$sop" = "enforced" ] || fail_g "/api/v1/formats vscode scan_on_proxy is '${sop:-?}', expected enforced"
[ "$code" = "200" ] && [ "$(sha_of "$W/ls.o")" = "$digest" ] || fail_g "the scanned legacy download answered ${code} or other bytes"
[ -n "$xs" ] || fail_g "the legacy route served a scan-on-proxy Remote's VSIX with no X-AK-Scan verdict (1.10.0: the route bypassed the scan)"
[ -n "$verdict" ] || fail_g "no proxy_scan_results row for the VSIX digest"
finish_case "the legacy VS Code download bypasses scan-on-proxy"

end_suite
