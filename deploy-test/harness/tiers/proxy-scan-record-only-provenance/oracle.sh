#!/usr/bin/env bash
# =============================================================================
# tiers/proxy-scan-record-only-provenance/oracle.sh - record-only proxy
# scanning, scan-config audit, finding_class and vulnerability-DB provenance
# =============================================================================
# artifact-keeper 1.11.0:
#   #3645 / #3868  proxy_scan_action = record_only: scan and record every
#                  proxied pull, never withhold one. X-AK-Scan: pending on the
#                  first pull, `recorded` once a vulnerable verdict exists.
#                  Only the underscore tokens are accepted (400 otherwise).
#                  Record-only yields to any enforcing side of a Virtual.
#                  Every scan-config change writes a REPOSITORY_UPDATED audit
#                  row with scan_config, previous_scan_config and
#                  scan_config_changed; a no-op write writes none.
#   #3013          findings carry finding_class (vulnerability / malicious /
#                  policy); ?finding_class= filters (typo -> 400); a MAL-* id
#                  is malicious and graded critical.
#   #3014          scan results carry vuln_db_version / vuln_db_published_at.
#
# run.sh has stood up `storage.filesystem upstreams.mock-scan-formats` and
# exported BASE_URL, ADMIN_PASS, RUN_ID, DTF_SLOT, TRIVY_PORT (the mock's
# control port), DB_CONTAINER, COMMON_SH. Grype (bundled, pre-seeded DB) does
# the grading; the malicious finding is ingested, so nothing leaves the host.
#
# Green: ak-backend:1.11.0 and newer. Red: ak-backend:1.10.0.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DB_CONTAINER:?}"; : "${TRIVY_PORT:?}"
: "${RUN_ID:?}"; : "${DTF_SLOT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every probe below is an assignment or a test, so
# a failed grep or curl must never end the run before end_suite.

begin_suite "proxy-scan-record-only-provenance"
auth_admin
setup_workdir

MOCK="http://127.0.0.1:${TRIVY_PORT}"
UP="http://172.16.${DTF_SLOT}.72/maven2"
SUF="${DTF_SLOT}x${RUN_ID##*-}"

RO="psro-ro-${SUF}"     # Remote, scan_on_proxy, record_only
RO_M="psro-rom-${SUF}"  # Remote member, record_only
VIRT="psro-v-${SUF}"    # Virtual over RO_M, itself fail_closed
OFF="psro-off-${SUF}"   # Remote, no scanning (control)
HOSTED="psro-h-${SUF}"  # hosted Maven for the scan-result checks

TEXT="org/apache/commons/commons-text/1.9/commons-text-1.9.jar"
LOG4J="org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.jar"
MAL_ID="MAL-2026-${DTF_SLOT}${RUN_ID##*-}"

cleanup() {
  local k
  for k in "$VIRT" "$RO_M" "$RO" "$OFF" "$HOSTED"; do
    api_delete "/api/v1/repositories/${k}" >/dev/null 2>&1 || true
  done
}
add_exit_handler "cleanup"

psql_q() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null; }
golden_sha() { curl -s --max-time 10 "${MOCK}/__sha256/maven2/$1" || true; }

BODY="${WORK_DIR}/body"
HDR="${WORK_DIR}/hdr"
pull() {
  ST=$(curl -s -D "$HDR" -o "$BODY" -w '%{http_code}' --max-time 120 "$1" 2>/dev/null) || ST="000"
  SCAN=$(grep -i '^x-ak-scan:' "$HDR" 2>/dev/null | tr -d '\r' | sed 's/^[^:]*:[[:space:]]*//' | head -1) || true
  BSHA=$(sha256sum "$BODY" 2>/dev/null | cut -d' ' -f1)
}
body_err() { jq -r '.error // .code // empty' "$BODY" 2>/dev/null || true; }
snippet() { head -c 200 "$BODY" | tr -c '[:print:]' '.'; }
verdict_of() { psql_q "SELECT verdict FROM proxy_scan_results WHERE checksum_sha256='$1' ORDER BY scanned_at DESC LIMIT 1" | tr -d '[:space:]'; }
# put_security KEY JSON -> sets PST (status) and writes the body to $BODY.
put_security() {
  PST=$(curl -s -o "$BODY" -w '%{http_code}' --max-time 30 -X PUT -H "$(auth_header)" \
    -H 'Content-Type: application/json' -d "$2" "${BASE_URL}/api/v1/repositories/$1/security" 2>/dev/null) || PST="000"
}
repo_id() { api_get "/api/v1/repositories/$1" 2>/dev/null | jq -r '.id // empty' 2>/dev/null || true; }
audit_rows() { # repo_id -> count of REPOSITORY_UPDATED rows carrying a scan_config
  psql_q "SELECT count(*) FROM audit_log WHERE action='REPOSITORY_UPDATED' AND resource_id::text='$1' AND details ? 'scan_config'" | tr -d '[:space:]'
}

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
begin_test "Setup: Maven Remotes (record_only, unscanned), a Virtual over a record_only member, a hosted Maven repo"
ok=1
for k in "$RO" "$RO_M" "$OFF"; do create_repo "$k" maven remote "$UP" || ok=0; done
create_repo "$VIRT" maven virtual || ok=0
api_post "/api/v1/repositories/${VIRT}/members" "{\"member_key\":\"${RO_M}\"}" >/dev/null 2>&1 || ok=0
create_repo "$HOSTED" maven local || ok=0
RO_ID=$(repo_id "$RO")
if [ "$ok" = 1 ] && [ -n "$RO_ID" ] && [ -n "$(golden_sha "$TEXT")" ]; then
  pass
else
  fail "repo setup failed (ok=${ok} ro_id=${RO_ID:-none}) or mock ${MOCK} not answering"
fi

# ---------------------------------------------------------------------------
# Controls (pass on every image)
# ---------------------------------------------------------------------------
begin_test "control: PUT security with proxy_scan_action=fail_closed persists (Virtual)"
put_security "$VIRT" '{"scan_enabled":true,"scan_on_proxy":true,"proxy_scan_action":"fail_closed"}'
if [ "$PST" = "200" ] && [ "$(jq -r '.proxy_scan_action' "$BODY" 2>/dev/null)" = "fail_closed" ]; then
  pass
else
  fail "HTTP ${PST} $(snippet)"
fi

begin_test "control: a Remote WITHOUT scanning streams commons-text-1.9.jar unchanged, no X-AK-Scan"
pull "${BASE_URL}/maven/${OFF}/${TEXT}"
if [ "$ST" = "200" ] && [ "$BSHA" = "$(golden_sha "$TEXT")" ] && [ -z "$SCAN" ]; then
  pass
else
  fail "status=${ST} scan='${SCAN}' body=$(snippet)"
fi

begin_test "control: log4j-core-2.14.1.jar uploads to the hosted repo and a triggered scan completes with Grype findings"
JAR="${WORK_DIR}/log4j.jar"
curl -s --max-time 10 -o "$JAR" "${MOCK}/__golden/maven2/${LOG4J}" || true
up=$(curl -s -o /dev/null -w '%{http_code}' --max-time 60 -X PUT -H "$(auth_header)" \
  --data-binary "@${JAR}" "${BASE_URL}/maven/${HOSTED}/${LOG4J}" 2>/dev/null) || up="000"
ART_ID=$(api_get "/api/v1/repositories/${HOSTED}/artifacts?per_page=20" 2>/dev/null \
  | jq -r '[(.items // .)[] | select(.path | endswith(".jar"))][0].id // empty' 2>/dev/null || true)
GRYPE_SCAN=""
if [ -n "$ART_ID" ]; then
  trigger_and_wait_scan "$ART_ID" 180 grype >/dev/null 2>&1 || true
  SCANS="${WORK_DIR}/scans.json"
  api_get "/api/v1/security/scans?artifact_id=${ART_ID}&per_page=20" > "$SCANS" 2>/dev/null || true
  GRYPE_SCAN=$(jq -r '[(.items // .)[] | select(.scan_type=="grype" and .status=="completed")][0].id // empty' "$SCANS" 2>/dev/null || true)
  GRYPE_N=$(jq -r '[(.items // .)[] | select(.scan_type=="grype")][0].findings_count // 0' "$SCANS" 2>/dev/null || echo 0)
fi
if [[ "$up" =~ ^20[01]$ ]] && [ -n "$GRYPE_SCAN" ] && [ "${GRYPE_N:-0}" -gt 0 ] 2>/dev/null; then
  pass
else
  fail "upload HTTP ${up}, artifact ${ART_ID:-none}, grype scan ${GRYPE_SCAN:-none} findings ${GRYPE_N:-?}"
fi

begin_test "control: POST /api/v1/security/findings/external ingests a MAL-* and a CVE finding (200, 2 ingested)"
EXT="${WORK_DIR}/ext.json"
ecode=$(curl -s -o "$EXT" -w '%{http_code}' --max-time 30 -X POST -H "$(auth_header)" \
  -H 'Content-Type: application/json' "${BASE_URL}/api/v1/security/findings/external" \
  -d "$(jq -cn --arg a "${ART_ID:-}" --arg m "$MAL_ID" '{artifact_id:$a, scanner:"dtf-psro",
        findings:[{severity:"low", title:"malicious package", cve_id:$m},
                  {severity:"low", title:"old bug", cve_id:"CVE-2020-11111"}]}')" 2>/dev/null) || ecode="000"
EXT_SCAN=$(jq -r '.scan_id // empty' "$EXT" 2>/dev/null || true)
if [ "$ecode" = "200" ] && [ "$(jq -r '.findings_ingested' "$EXT" 2>/dev/null)" = "2" ] && [ -n "$EXT_SCAN" ]; then
  pass
else
  fail "HTTP ${ecode} $(head -c 200 "$EXT")"
fi

# ---------------------------------------------------------------------------
# #3645 / #3868: record_only
# ---------------------------------------------------------------------------
begin_test "FIX #3645: PUT security proxy_scan_action=record_only persists (response and GET)"
put_security "$RO" '{"scan_enabled":true,"scan_on_proxy":true,"proxy_scan_action":"record_only"}'
p1="$PST"; a1=$(jq -r '.proxy_scan_action // empty' "$BODY" 2>/dev/null || true)
a2=$(api_get "/api/v1/repositories/${RO}/security" 2>/dev/null | jq -r '(.config // .).proxy_scan_action // empty' 2>/dev/null || true)
put_security "$RO_M" '{"scan_enabled":true,"scan_on_proxy":true,"proxy_scan_action":"record_only"}'
if [ "$p1" = "200" ] && [ "$a1" = "record_only" ] && [ "$a2" = "record_only" ] && [ "$PST" = "200" ]; then
  pass
else
  fail "PUT HTTP ${p1} -> '${a1}', GET -> '${a2}', member PUT HTTP ${PST}"
fi

begin_test "FIX #3868: 'record-only' and 'fail-closed' are refused 400 naming the accepted tokens; the stored action is unchanged"
put_security "$RO" '{"scan_enabled":true,"scan_on_proxy":true,"proxy_scan_action":"record-only"}'
s1="$PST"; m1=$(jq -r '.message // empty' "$BODY" 2>/dev/null || true)
put_security "$RO" '{"scan_enabled":true,"scan_on_proxy":true,"proxy_scan_action":"fail-closed"}'
s2="$PST"
a3=$(api_get "/api/v1/repositories/${RO}/security" 2>/dev/null | jq -r '(.config // .).proxy_scan_action // empty' 2>/dev/null || true)
if [ "$s1" = "400" ] && [ "$s2" = "400" ] && [[ "$m1" == *record_only* ]] && [ "$a3" = "record_only" ]; then
  pass
else
  fail "record-only HTTP ${s1} (${m1}), fail-closed HTTP ${s2}, stored '${a3}'"
fi

begin_test "FIX #3645: the scan-config change is audited as REPOSITORY_UPDATED with before/after and changed fields; a no-op PUT adds no row"
n1=$(audit_rows "$RO_ID")
put_security "$RO" '{"scan_enabled":true,"scan_on_proxy":true,"proxy_scan_action":"record_only"}'
n2=$(audit_rows "$RO_ID")
row=$(psql_q "SELECT details::text FROM audit_log WHERE action='REPOSITORY_UPDATED' AND resource_id::text='${RO_ID}' AND details ? 'scan_config' ORDER BY created_at DESC LIMIT 1")
chg=$(jq -c '.scan_config_changed | sort' <<<"$row" 2>/dev/null || true)
if [ "$n1" = "1" ] && [ "$n2" = "1" ] \
   && [ "$(jq -r '.scan_config.proxy_scan_action' <<<"$row" 2>/dev/null)" = "record_only" ] \
   && [ "$(jq -r '.previous_scan_config.proxy_scan_action' <<<"$row" 2>/dev/null)" = "fail_open" ] \
   && [ "$chg" = '["proxy_scan_action","scan_enabled","scan_on_proxy"]' ]; then
  pass
else
  fail "rows before/after no-op: ${n1:-?}/${n2:-?}; changed=${chg:-none}; row=${row:0:300}"
fi

begin_test "FIX #3645: first pull of commons-text-1.9.jar through the record_only Remote is 200 X-AK-Scan: pending"
pull "${BASE_URL}/maven/${RO}/${TEXT}"
if [ "$ST" = "200" ] && [ "$SCAN" = "pending" ] && [ "$BSHA" = "$(golden_sha "$TEXT")" ]; then
  pass
else
  fail "status=${ST} scan='${SCAN}' body=$(snippet)"
fi

begin_test "FIX #3645: the async scan records a 'vulnerable' verdict (max critical) for the jar's digest"
D_TEXT=$(golden_sha "$TEXT")
text_vulnerable() { [ "$(verdict_of "$D_TEXT")" = "vulnerable" ]; }
wait_until "vulnerable verdict for commons-text-1.9.jar" 60 text_vulnerable || true
sev=$(psql_q "SELECT max_severity FROM proxy_scan_results WHERE checksum_sha256='${D_TEXT}' ORDER BY scanned_at DESC LIMIT 1" | tr -d '[:space:]')
if [ "$(verdict_of "$D_TEXT")" = "vulnerable" ] && [ "$sev" = "critical" ]; then
  pass
else
  fail "digest ${D_TEXT}: verdict='$(verdict_of "$D_TEXT")' max_severity='${sev}'"
fi

begin_test "FIX #3645: the next pull is still served (200, same bytes) and marked X-AK-Scan: recorded"
pull "${BASE_URL}/maven/${RO}/${TEXT}"
if [ "$ST" = "200" ] && [ "$SCAN" = "recorded" ] && [ "$BSHA" = "$D_TEXT" ]; then
  pass
else
  fail "status=${ST} scan='${SCAN}' body=$(snippet) (a fail_open repo would 403 here)"
fi

begin_test "FIX #3645: the proxy-scans report shows record_only and the jar as vulnerable"
PS="${WORK_DIR}/ps.json"
api_get "/api/v1/repositories/${RO}/security/proxy-scans" > "$PS" 2>/dev/null || true
st=$(jq -r --arg d "$D_TEXT" '[.items[]? | select(.digest==$d)][0].state // empty' "$PS" 2>/dev/null || true)
if [ "$(jq -r '.proxy_scan_action // empty' "$PS" 2>/dev/null)" = "record_only" ] && [ "$st" = "vulnerable" ]; then
  pass
else
  fail "report: $(head -c 300 "$PS")"
fi

begin_test "FIX #3645: a fail_closed Virtual over a record_only member enforces the stricter policy (403 scan_blocked)"
pull "${BASE_URL}/maven/${VIRT}/${TEXT}"
if [ "$ST" = "403" ] && [ "$(body_err)" = "scan_blocked" ]; then
  pass
else
  fail "status=${ST} scan='${SCAN}' body=$(snippet)"
fi

# ---------------------------------------------------------------------------
# #3014: vulnerability-DB provenance on scan results
# ---------------------------------------------------------------------------
begin_test "FIX #3014: the Grype scan result carries vuln_db_version grype-db-v* and a vuln_db_published_at timestamp"
row=$(jq -c '[(.items // .)[] | select(.scan_type=="grype")][0]' "$SCANS" 2>/dev/null || true)
vv=$(jq -r '.vuln_db_version // empty' <<<"$row" 2>/dev/null || true)
vp=$(jq -r '.vuln_db_published_at // empty' <<<"$row" 2>/dev/null || true)
if [[ "$vv" =~ ^grype-db-v[0-9] ]] && [[ "$vp" =~ ^20[0-9][0-9]-[01][0-9]-[0-3][0-9]T ]]; then
  pass
else
  fail "vuln_db_version='${vv}' vuln_db_published_at='${vp}'"
fi

begin_test "FIX #3014: the dependency scan result carries vuln_db_version live:osv*; the external scan carries none"
dv=$(jq -r '[(.items // .)[] | select(.scan_type=="dependency")][0].vuln_db_version // empty' "$SCANS" 2>/dev/null || true)
api_get "/api/v1/security/scans?artifact_id=${ART_ID:-x}&per_page=20" > "$SCANS.2" 2>/dev/null || true
ev=$(jq -r --arg s "${EXT_SCAN:-x}" '[(.items // .)[] | select(.id==$s)][0] | if . == null then "missing" else (.vuln_db_version // "null") end' "$SCANS.2" 2>/dev/null || true)
has=$(jq -r '[(.items // .)[] | has("vuln_db_version")] | all' "$SCANS.2" 2>/dev/null || true)
if [[ "$dv" == live:osv* ]] && [ "$ev" = "null" ] && [ "$has" = "true" ]; then
  pass
else
  fail "dependency='${dv}' external='${ev}' field-present-on-all='${has}'"
fi

# ---------------------------------------------------------------------------
# #3013: finding_class
# ---------------------------------------------------------------------------
FJ="${WORK_DIR}/f.json"
findings() { # scan_id [query] -> body in $FJ, status in FST (no subshell)
  FST=$(curl -s -o "$FJ" -w '%{http_code}' --max-time 30 -H "$(auth_header)" \
    "${BASE_URL}/api/v1/security/scans/$1/findings${2:-}" 2>/dev/null) || FST="000"
}

begin_test "FIX #3013: every Grype finding carries finding_class=vulnerability"
findings "${GRYPE_SCAN:-x}" "?per_page=100"
all=$(jq -r '[.items[]?.finding_class] | (length > 0 and all(. == "vulnerability"))' "$FJ" 2>/dev/null || true)
if [ "$FST" = "200" ] && [ "$all" = "true" ]; then
  pass
else
  fail "HTTP ${FST} classes: $(jq -c '[.items[]?.finding_class] | unique' "$FJ" 2>/dev/null)"
fi

begin_test "FIX #3013: ?finding_class=malicious on the Grype scan returns nothing, ?finding_class=vulnerability returns every finding"
findings "${GRYPE_SCAN:-x}" "?finding_class=malicious"
mal=$(jq -r '.total // empty' "$FJ" 2>/dev/null || true); s_m="$FST"
findings "${GRYPE_SCAN:-x}" "?finding_class=vulnerability"
vul=$(jq -r '.total // empty' "$FJ" 2>/dev/null || true); s_v="$FST"
if [ "$s_m" = "200" ] && [ "$mal" = "0" ] && [ "$s_v" = "200" ] && [ "$vul" = "${GRYPE_N:-x}" ]; then
  pass
else
  fail "malicious: HTTP ${s_m} total=${mal}; vulnerability: HTTP ${s_v} total=${vul} (findings_count ${GRYPE_N:-?}); pre-1.11.0 ignores the filter"
fi

begin_test "FIX #3013: an unknown finding_class is refused 400 naming the vocabulary"
findings "${GRYPE_SCAN:-x}" "?finding_class=malware"
msg=$(jq -r '.message // empty' "$FJ" 2>/dev/null || true)
if [ "$FST" = "400" ] && [[ "$msg" == *malicious* ]]; then
  pass
else
  fail "HTTP ${FST} ${msg}"
fi

begin_test "FIX #3013: the ingested ${MAL_ID} is classed malicious and graded critical (reported low); the CVE stays a vulnerability"
findings "${EXT_SCAN:-x}" "?finding_class=malicious"
mrow=$(jq -c '.items' "$FJ" 2>/dev/null || true)
findings "${EXT_SCAN:-x}" "?finding_class=vulnerability"
vrow=$(jq -c '[.items[]? | {cve_id, severity}]' "$FJ" 2>/dev/null || true)
if [ "$(jq -r 'length' <<<"$mrow" 2>/dev/null)" = "1" ] \
   && [ "$(jq -r '.[0].cve_id' <<<"$mrow" 2>/dev/null)" = "$MAL_ID" ] \
   && [ "$(jq -r '.[0].severity' <<<"$mrow" 2>/dev/null)" = "critical" ] \
   && [ "$(jq -r '.[0].finding_class' <<<"$mrow" 2>/dev/null)" = "malicious" ] \
   && [ "$vrow" = '[{"cve_id":"CVE-2020-11111","severity":"low"}]' ]; then
  pass
else
  fail "malicious: ${mrow:0:300} vulnerability: ${vrow:0:200}"
fi

end_suite
