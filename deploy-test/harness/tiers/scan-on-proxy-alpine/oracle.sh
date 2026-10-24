#!/usr/bin/env bash
# =============================================================================
# tiers/scan-on-proxy-alpine/oracle.sh - the scan-on-proxy gate on proxied
# Alpine packages, Remote and Virtual
# =============================================================================
# artifact-keeper 1.12.0: #4113, epic #4097.
#
# run.sh has stood up `storage.filesystem upstreams.mock-scan-formats` and
# exported BASE_URL, ADMIN_PASS, RUN_ID, DTF_SLOT, TRIVY_PORT (the mock's
# control port), DB_CONTAINER, COMMON_SH.
#
# Fixtures (scan-on-proxy-maven-nuget/fixtures/mock_scan_upstream.py):
#   v3.19/main/x86_64: busybox 1.36.1-r15 (vulnerable on Alpine 3.19),
#     dtf-scanclean 1.0-r0, dtf-scanliar 2.0-r0 (.PKGINFO says 1.0-r0)
#   latest-stable/main/x86_64: dtf-scanclean 1.0-r0 (the branch names no
#     fixed release)
#
# Green: an image carrying #4113. Red: ak-backend:1.11.5.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DB_CONTAINER:?}"; : "${TRIVY_PORT:?}"
: "${RUN_ID:?}"; : "${DTF_SLOT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

begin_suite "scan-on-proxy-alpine"
auth_admin
setup_workdir

MOCK="http://127.0.0.1:${TRIVY_PORT}"
UP="http://172.16.${DTF_SLOT}.72"
SUF="${DTF_SLOT}x${RUN_ID##*-}"

APK="sopa-apk-${SUF}"         # Alpine Remote, fail_closed
APK_FO="sopa-apkfo-${SUF}"    # Alpine Remote, fail_open
APK_OFF="sopa-apkoff-${SUF}"  # Alpine Remote, no scanning (control)
APK_M="sopa-apkm-${SUF}"      # Alpine Remote member of APK_V, fail_closed
APK_V="sopa-apkv-${SUF}"      # Alpine Virtual over APK_M

DIR="v3.19/main/x86_64"
APK_VULN="${DIR}/busybox-1.36.1-r15.apk"
APK_CLEAN="${DIR}/dtf-scanclean-1.0-r0.apk"
APK_LIAR="${DIR}/dtf-scanliar-2.0-r0.apk"
APK_LATEST="latest-stable/main/x86_64/dtf-scanclean-1.0-r0.apk"

cleanup() {
  local k
  for k in "$APK_V" "$APK_M" "$APK" "$APK_FO" "$APK_OFF"; do
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
cataloged_of() { psql_q "SELECT components_cataloged FROM proxy_scan_results WHERE checksum_sha256='$1' ORDER BY scanned_at DESC LIMIT 1"; }
scan_cfg() {
  api_put "/api/v1/repositories/$1/security" \
    "{\"scan_enabled\":true,\"scan_on_proxy\":true,\"proxy_scan_action\":\"$2\"}" 2>/dev/null \
    | jq -r '.proxy_scan_action // empty' 2>/dev/null
}

begin_test "Setup: mock upstream reachable and the Alpine fixtures present"
if [ -n "$(golden_sha "alpine/${APK_VULN}")" ] && [ -n "$(golden_sha "alpine/${APK_LATEST}")" ]; then
  pass
else
  fail "mock control endpoint ${MOCK} did not answer (or this mock predates the Alpine fixtures)"
fi

begin_test "Setup: Remotes (fail_closed, fail_open, unscanned) and a Virtual"
ok=1
for k in "$APK" "$APK_FO" "$APK_OFF" "$APK_M"; do create_repo "$k" alpine remote "${UP}/alpine" || ok=0; done
create_repo "$APK_V" alpine virtual || ok=0
api_post "/api/v1/repositories/${APK_V}/members" "{\"member_key\":\"${APK_M}\"}" >/dev/null 2>&1 || ok=0
a="$(scan_cfg "$APK" fail_closed) $(scan_cfg "$APK_FO" fail_open) $(scan_cfg "$APK_M" fail_closed)"
if [ "$ok" = 1 ] && [ "$a" = "fail_closed fail_open fail_closed" ]; then
  pass
else
  fail "repo setup failed (ok=${ok}) or actions not persisted: '${a}'"
fi

A="${BASE_URL}/alpine"

begin_test "control: a Remote WITHOUT scan_on_proxy streams the vulnerable .apk unchanged, no X-AK-Scan"
pull "${A}/${APK_OFF}/${APK_VULN}"
if [ "$ST/$SCAN" = "200/" ] && [ "$BSHA" = "$(golden_sha "alpine/${APK_VULN}")" ]; then
  pass
else
  fail "status=${ST} scan='${SCAN}'"
fi

begin_test "control: GET /api/v1/formats lists the alpine handler"
FMT="${WORK_DIR}/formats.json"
api_get "/api/v1/formats" > "$FMT" 2>/dev/null || true
fmt_field() { jq -r --arg k "$1" --arg f "$2" '[(if type == "array" then . else .items end)[] | select(.format_key==$k)][0][$f] // empty' "$FMT" 2>/dev/null || true; }
if [ "$(fmt_field alpine format_key)" = "alpine" ]; then
  pass
else
  fail "formats: $(head -c 200 "$FMT")"
fi

begin_test "FIX #4113: /api/v1/formats reports alpine scan_on_proxy=enforced (helm stays accepted)"
got="$(fmt_field alpine scan_on_proxy) $(fmt_field helm scan_on_proxy)"
if [ "$got" = "enforced accepted" ]; then
  pass
else
  fail "alpine helm = '${got}' (1.11.x: accepted accepted)"
fi

begin_test "FIX #4113: fail_closed pull of busybox 1.36.1-r15 is 403 scan_blocked (graded on Alpine 3.19)"
pull "${A}/${APK}/${APK_VULN}"
d=$(golden_sha "alpine/${APK_VULN}")
if [ "$ST" = "403" ] && [ "$(body_err)" = "scan_blocked" ] && [ "$(body_file)" = "busybox-1.36.1-r15.apk" ] \
   && [ "$(verdict_of "$d")" = "vulnerable" ]; then
  pass
else
  fail "status=${ST} scan='${SCAN}' body=$(snippet) verdict='$(verdict_of "$d")'"
fi

begin_test "FIX #4113: a package no advisory names is graded as itself, 200 clean, and the second pull reuses the verdict and cache"
pull "${A}/${APK}/${APK_CLEAN}"
s1="$ST/$SCAN"; b1="$BSHA"
d=$(golden_sha "alpine/${APK_CLEAN}")
c=$(cataloged_of "$d")
h1=$(hits "/alpine/${APK_CLEAN}")
pull "${A}/${APK}/${APK_CLEAN}"
h2=$(hits "/alpine/${APK_CLEAN}")
if [ "$s1" = "200/clean" ] && [ "$b1" = "$d" ] && [ "$ST/$SCAN" = "200/clean" ] && [ "${c:-0}" -ge 1 ] 2>/dev/null \
   && [ "$(verdict_rows "$d")" = "1" ] && [ "$h1" = "$h2" ]; then
  pass
else
  fail "first=${s1} second=${ST}/${SCAN} cataloged='${c}' rows=$(verdict_rows "$d") upstream GETs ${h1:-?} -> ${h2:-?}"
fi

begin_test "FIX #4113: an .apk whose .PKGINFO declares another version, or requested through latest-stable, is withheld (423, no verdict row)"
pull "${A}/${APK}/${APK_LIAR}"; s1="$ST/$(body_err)"; v1=$(verdict_of "$(golden_sha "alpine/${APK_LIAR}")")
pull "${A}/${APK}/${APK_LATEST}"; s2="$ST/$(body_err)"; v2=$(verdict_of "$(golden_sha "alpine/${APK_LATEST}")")
if [ "$s1 $s2" = "423/scan_pending 423/scan_pending" ] && [ -z "$v1$v2" ]; then
  pass
else
  fail "liar=${s1} latest-stable=${s2} scan='${SCAN}' verdicts='${v1}' '${v2}'"
fi

begin_test "FIX #4113: fail_open first pull of the vulnerable .apk is 200 X-AK-Scan: pending (no-store), then 403 once the verdict lands"
psql_q "DELETE FROM proxy_scan_results WHERE checksum_sha256='$(golden_sha "alpine/${APK_VULN}")'" >/dev/null
pull "${A}/${APK_FO}/${APK_VULN}"
s1="$ST/$SCAN"; cc=$(hdr cache-control)
d=$(golden_sha "alpine/${APK_VULN}")
apk_vulnerable() { [ "$(verdict_of "$d")" = "vulnerable" ]; }
wait_until "vulnerable verdict for the fail_open .apk" 60 apk_vulnerable || true
pull "${A}/${APK_FO}/${APK_VULN}"
if [ "$s1" = "200/pending" ] && [ "$cc" = "no-store" ] && [ "$ST" = "403" ] && [ "$(body_err)" = "scan_blocked" ]; then
  pass
else
  fail "first=${s1} cache-control='${cc}' second=${ST} body=$(snippet) verdict='$(verdict_of "$d")'"
fi

begin_test "FIX #4113: through a Virtual whose Remote member scans, the vulnerable .apk is 403 and the clean one 200 clean"
pull "${A}/${APK_V}/${APK_VULN}"; s1="$ST/$(body_err)"
pull "${A}/${APK_V}/${APK_CLEAN}"
if [ "$s1" = "403/scan_blocked" ] && [ "$ST/$SCAN" = "200/clean" ] && [ "$BSHA" = "$(golden_sha "alpine/${APK_CLEAN}")" ]; then
  pass
else
  fail "vulnerable=${s1} clean=${ST}/${SCAN}"
fi

begin_test "FIX #4113: an ambiguous file name on an Alpine Remote is 400 before any upstream request"
h1=$(hits "/alpine/${DIR}/")
pull "${A}/${APK}/${DIR}/busybox-1.36.1-r15%3F.apk"
h2=$(hits "/alpine/${DIR}/")
if [ "$ST" = "400" ] && [ "$h1" = "$h2" ]; then
  pass
else
  fail "status=${ST} body=$(snippet) upstream GETs ${h1:-?} -> ${h2:-?}"
fi

end_suite
