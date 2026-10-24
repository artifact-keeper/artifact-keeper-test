#!/usr/bin/env bash
# =============================================================================
# tiers/scan-on-proxy-cocoapods-swift/oracle.sh - the scan-on-proxy gate on
# proxied CocoaPods pod archives and Swift source archives, Remote and Virtual
# =============================================================================
# artifact-keeper 1.12.0: #4109 (CocoaPods), #4110 (Swift), epic #4097.
# Before them both download handlers streamed a Remote's archive straight
# through even with scan_on_proxy=true, and `GET /api/v1/formats` reported
# them `accepted`. They now go through proxy_helpers::serve_scanned_proxy_file:
#   * CocoaPods: the pod's own {name}.podspec.json must declare the requested
#     name and version.
#   * Swift: the archive must be a zip with a top-level Package.swift.
# Both are graded on their contents: the bundled Grype has no CocoaPods or
# Swift advisory data, so the vulnerable fixtures vendor a Gemfile.lock
# pinning rack 2.0.7.
#
# run.sh has stood up `storage.filesystem upstreams.mock-scan-formats` and
# exported BASE_URL, ADMIN_PASS, RUN_ID, DTF_SLOT, TRIVY_PORT (the mock's
# control port), DB_CONTAINER, COMMON_SH. Verdicts come from the backend
# image's bundled Grype and its pre-seeded DB; nothing leaves the host.
#
# Green: an image carrying #4109-#4110. Red: ak-backend:1.11.5 (every FIX
# case; every control passes on both).
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DB_CONTAINER:?}"; : "${TRIVY_PORT:?}"
: "${RUN_ID:?}"; : "${DTF_SLOT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every probe below is an assignment or a test, so
# a failed grep or curl must never end the run before end_suite.

begin_suite "scan-on-proxy-cocoapods-swift"
auth_admin
setup_workdir

MOCK="http://127.0.0.1:${TRIVY_PORT}"
UP="http://172.16.${DTF_SLOT}.72"
SUF="${DTF_SLOT}x${RUN_ID##*-}"

POD="sopc-pod-${SUF}"         # CocoaPods Remote, fail_closed
POD_OFF="sopc-podoff-${SUF}"  # CocoaPods Remote, no scanning (control)
POD_M="sopc-podm-${SUF}"      # CocoaPods Remote member of POD_V, fail_closed
POD_V="sopc-podv-${SUF}"      # CocoaPods Virtual over POD_M
SW="sopc-sw-${SUF}"           # Swift Remote, fail_closed
SW_RO="sopc-swro-${SUF}"      # Swift Remote, record_only
SW_OFF="sopc-swoff-${SUF}"    # Swift Remote, no scanning (control)
SW_M="sopc-swm-${SUF}"        # Swift Remote member of SW_V, fail_closed
SW_V="sopc-swv-${SUF}"        # Swift Virtual over SW_M

POD_VULN="pods/DtfVulnPod-1.0.0.tar.gz"
POD_CLEAN="pods/DtfCleanPod-1.0.0.tar.gz"
POD_LIAR="pods/DtfLiarPod-2.0.0.tar.gz"
SW_VULN="dtf/vulnpkg/1.0.0.zip"
SW_CLEAN="dtf/cleanpkg/1.0.0.zip"
SW_LIAR="dtf/liarpkg/1.0.0.zip"

cleanup() {
  local k
  for k in "$POD_V" "$SW_V" "$POD_M" "$SW_M" "$POD" "$POD_OFF" "$SW" "$SW_RO" "$SW_OFF"; do
    api_delete "/api/v1/repositories/${k}" >/dev/null 2>&1 || true
  done
}
add_exit_handler "cleanup"

psql_q() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]'; }
golden_sha() { curl -s --max-time 10 "${MOCK}/__sha256/$1" || true; }
hits() { curl -s --max-time 10 "${MOCK}/__hits?prefix=$1" | jq -r '.count // empty' 2>/dev/null; }

BODY="${WORK_DIR}/body"
HDR="${WORK_DIR}/hdr"
pull() {
  ST=$(curl -s -D "$HDR" -o "$BODY" -w '%{http_code}' --max-time 120 "$1" 2>/dev/null) || ST="000"
  SCAN=$(hdr x-ak-scan)
  BSHA=$(sha256sum "$BODY" 2>/dev/null | cut -d' ' -f1)
}
hdr() { grep -i "^$1:" "$HDR" 2>/dev/null | tr -d '\r' | sed 's/^[^:]*:[[:space:]]*//' | head -1 || true; }
body_err() { jq -r '.error // .code // empty' "$BODY" 2>/dev/null || true; }
body_file() { jq -r '.file // empty' "$BODY" 2>/dev/null || true; }
snippet() { head -c 200 "$BODY" | tr -c '[:print:]' '.'; }
verdict_of() { psql_q "SELECT verdict FROM proxy_scan_results WHERE checksum_sha256='$1' ORDER BY scanned_at DESC LIMIT 1"; }
verdict_rows() { psql_q "SELECT count(*) FROM proxy_scan_results WHERE checksum_sha256='$1'"; }
scan_cfg() { # key action -> echoes the persisted proxy_scan_action
  api_put "/api/v1/repositories/$1/security" \
    "{\"scan_enabled\":true,\"scan_on_proxy\":true,\"proxy_scan_action\":\"$2\"}" 2>/dev/null \
    | jq -r '.proxy_scan_action // empty' 2>/dev/null
}

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
begin_test "Setup: mock upstream reachable and the CocoaPods and Swift fixtures present"
if [ -n "$(golden_sha "cocoapods/${POD_VULN}")" ] && [ -n "$(golden_sha "swift/${SW_VULN}")" ]; then
  pass
else
  fail "mock control endpoint ${MOCK} did not answer (or this mock predates the CocoaPods/Swift fixtures)"
fi

begin_test "Setup: Remotes (fail_closed, record_only, unscanned) and a Virtual per format"
ok=1
for k in "$POD" "$POD_OFF" "$POD_M"; do create_repo "$k" cocoapods remote "${UP}/cocoapods" || ok=0; done
for k in "$SW" "$SW_RO" "$SW_OFF" "$SW_M"; do create_repo "$k" swift remote "${UP}/swift" || ok=0; done
create_repo "$POD_V" cocoapods virtual || ok=0
create_repo "$SW_V" swift virtual || ok=0
api_post "/api/v1/repositories/${POD_V}/members" "{\"member_key\":\"${POD_M}\"}" >/dev/null 2>&1 || ok=0
api_post "/api/v1/repositories/${SW_V}/members" "{\"member_key\":\"${SW_M}\"}" >/dev/null 2>&1 || ok=0
a="$(scan_cfg "$POD" fail_closed) $(scan_cfg "$POD_M" fail_closed)"
a="$a $(scan_cfg "$SW" fail_closed) $(scan_cfg "$SW_RO" record_only) $(scan_cfg "$SW_M" fail_closed)"
if [ "$ok" = 1 ] && [ "$a" = "fail_closed fail_closed fail_closed record_only fail_closed" ]; then
  pass
else
  fail "repo setup failed (ok=${ok}) or actions not persisted: '${a}'"
fi

CP="${BASE_URL}/cocoapods"
S="${BASE_URL}/swift"

# ---------------------------------------------------------------------------
# Controls (pass on every image)
# ---------------------------------------------------------------------------
begin_test "control: Remotes WITHOUT scan_on_proxy stream the vulnerable pod and Swift archives unchanged, no X-AK-Scan"
pull "${CP}/${POD_OFF}/${POD_VULN}"; s1="$ST/$SCAN"; ok1=$([ "$BSHA" = "$(golden_sha "cocoapods/${POD_VULN}")" ] && echo y)
pull "${S}/${SW_OFF}/${SW_VULN}"; s2="$ST/$SCAN"; ok2=$([ "$BSHA" = "$(golden_sha "swift/${SW_VULN}")" ] && echo y)
if [ "$s1 $s2" = "200/ 200/" ] && [ "$ok1$ok2" = "yy" ]; then
  pass
else
  fail "cocoapods=${s1} swift=${s2} bytes-match='${ok1}${ok2}'"
fi

begin_test "control: GET /api/v1/formats lists the cocoapods and swift handlers"
FMT="${WORK_DIR}/formats.json"
api_get "/api/v1/formats" > "$FMT" 2>/dev/null || true
fmt_field() { jq -r --arg k "$1" --arg f "$2" '[(if type == "array" then . else .items end)[] | select(.format_key==$k)][0][$f] // empty' "$FMT" 2>/dev/null || true; }
if [ "$(fmt_field cocoapods format_key) $(fmt_field swift format_key)" = "cocoapods swift" ]; then
  pass
else
  fail "formats: $(head -c 200 "$FMT")"
fi

# ---------------------------------------------------------------------------
# The formats capability
# ---------------------------------------------------------------------------
begin_test "FIX #4109/#4110: /api/v1/formats reports cocoapods and swift scan_on_proxy=enforced"
got="$(fmt_field cocoapods scan_on_proxy) $(fmt_field swift scan_on_proxy)"
if [ "$got" = "enforced enforced" ]; then
  pass
else
  fail "cocoapods swift = '${got}' (1.11.x: accepted accepted)"
fi

# ---------------------------------------------------------------------------
# #4109 CocoaPods
# ---------------------------------------------------------------------------
begin_test "FIX #4109: fail_closed pull of a pod vendoring rack 2.0.7 is 403 scan_blocked with a 'vulnerable' verdict"
pull "${CP}/${POD}/${POD_VULN}"
d=$(golden_sha "cocoapods/${POD_VULN}")
if [ "$ST" = "403" ] && [ "$(body_err)" = "scan_blocked" ] && [ "$(body_file)" = "DtfVulnPod-1.0.0.tar.gz" ] \
   && [ "$(verdict_of "$d")" = "vulnerable" ]; then
  pass
else
  fail "status=${ST} scan='${SCAN}' body=$(snippet) verdict='$(verdict_of "$d")'"
fi

begin_test "FIX #4109: a pod with no vulnerable content is 200 clean, and the second pull reuses verdict and cache"
pull "${CP}/${POD}/${POD_CLEAN}"
s1="$ST/$SCAN"; b1="$BSHA"
d=$(golden_sha "cocoapods/${POD_CLEAN}")
h1=$(hits "/cocoapods/${POD_CLEAN}")
pull "${CP}/${POD}/${POD_CLEAN}"
h2=$(hits "/cocoapods/${POD_CLEAN}")
if [ "$s1" = "200/clean" ] && [ "$b1" = "$d" ] && [ "$ST/$SCAN" = "200/clean" ] && [ "$(verdict_rows "$d")" = "1" ] && [ "$h1" = "$h2" ]; then
  pass
else
  fail "first=${s1} second=${ST}/${SCAN} rows=$(verdict_rows "$d") upstream GETs ${h1:-?} -> ${h2:-?}"
fi

begin_test "FIX #4109: a pod whose podspec declares another version is withheld under fail_closed (423, no verdict row)"
pull "${CP}/${POD}/${POD_LIAR}"
d=$(golden_sha "cocoapods/${POD_LIAR}")
if [ "$ST" = "423" ] && [ "$(body_err)" = "scan_pending" ] && [ -z "$(verdict_of "$d")" ]; then
  pass
else
  fail "status=${ST} body=$(snippet) verdict='$(verdict_of "$d")'"
fi

begin_test "FIX #4109: through a Virtual whose Remote member scans, the vulnerable pod is 403 scan_blocked"
pull "${CP}/${POD_V}/${POD_VULN}"
if [ "$ST" = "403" ] && [ "$(body_err)" = "scan_blocked" ]; then
  pass
else
  fail "status=${ST} scan='${SCAN}' body=$(snippet)"
fi

# ---------------------------------------------------------------------------
# #4110 Swift
# ---------------------------------------------------------------------------
begin_test "FIX #4110: fail_closed pull of a source archive vendoring rack 2.0.7 is 403 scan_blocked"
pull "${S}/${SW}/${SW_VULN}"
d=$(golden_sha "swift/${SW_VULN}")
if [ "$ST" = "403" ] && [ "$(body_err)" = "scan_blocked" ] && [ "$(body_file)" = "vulnpkg-1.0.0.zip" ] \
   && [ "$(verdict_of "$d")" = "vulnerable" ]; then
  pass
else
  fail "status=${ST} scan='${SCAN}' body=$(snippet) verdict='$(verdict_of "$d")'"
fi

begin_test "FIX #4110: a source archive with no vulnerable content is 200 X-AK-Scan: clean"
pull "${S}/${SW}/${SW_CLEAN}"
d=$(golden_sha "swift/${SW_CLEAN}")
if [ "$ST/$SCAN" = "200/clean" ] && [ "$BSHA" = "$d" ] && [ "$(verdict_of "$d")" = "clean" ]; then
  pass
else
  fail "status=${ST} scan='${SCAN}' verdict='$(verdict_of "$d")' body=$(snippet)"
fi

begin_test "FIX #4110: an archive with no Package.swift is withheld under fail_closed (423, no verdict row)"
pull "${S}/${SW}/${SW_LIAR}"
d=$(golden_sha "swift/${SW_LIAR}")
if [ "$ST" = "423" ] && [ "$(body_err)" = "scan_pending" ] && [ -z "$(verdict_of "$d")" ]; then
  pass
else
  fail "status=${ST} body=$(snippet) verdict='$(verdict_of "$d")'"
fi

begin_test "FIX #4110: record_only serves the vulnerable archive with X-AK-Scan: recorded"
pull "${S}/${SW_RO}/${SW_VULN}"
if [ "$ST" = "200" ] && [ "$SCAN" = "recorded" ] && [ "$BSHA" = "$(golden_sha "swift/${SW_VULN}")" ]; then
  pass
else
  fail "status=${ST} scan='${SCAN}' body=$(snippet)"
fi

begin_test "FIX #4110: through a Virtual whose Remote member scans, the vulnerable archive is 403 scan_blocked"
pull "${S}/${SW_V}/${SW_VULN}"
if [ "$ST" = "403" ] && [ "$(body_err)" = "scan_blocked" ]; then
  pass
else
  fail "status=${ST} scan='${SCAN}' body=$(snippet)"
fi

end_suite
