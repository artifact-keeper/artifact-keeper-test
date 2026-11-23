#!/usr/bin/env bash
# =============================================================================
# tiers/scan-vuln-db-age/oracle.sh: an old vulnerability database is reported
#   with its age, flagged stale in the API and the metrics, and logged
#   (artifact-keeper#5177)
# =============================================================================
# run.sh has stood up storage.filesystem + scanners.mock-vulndb and exported
# BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID, RELEASE_GATE=1,
# JUNIT_OUTPUT_DIR, COMMON_SH. See the manifest for the gap, the fix and each
# assertion.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
set +e

PREFIX="${DB_CONTAINER%-db}"
BACKEND_CTR="${PREFIX}-backend"
MOCK_CTR="${PREFIX}-mock-vulndb"
ROUTE="/api/v1/admin/security/vuln-db"
WORK="$(mktemp -d -t dtf-vdb-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

DAY=86400
get() { curl -s -m 30 -H "$(auth_header)" -o "$2" -w '%{http_code}' "${BASE_URL}$1" 2>/dev/null || echo 000; }
mock_hits() {
  docker exec "$MOCK_CTR" python3 -c "import urllib.request;print(urllib.request.urlopen('http://127.0.0.1/__hits',timeout=3).read().decode())" 2>/dev/null \
    | jq -r '.vulndb // -1' 2>/dev/null || echo -1
}
trivy() { jq -r --arg f "$1" '[.engines[]? | select(.engine=="trivy")][0][$f] | tostring' "${WORK}/report.json" 2>/dev/null; }

begin_suite "scan-vuln-db-age (#5177)"
auth_admin

begin_test "FIX #5177: the API reports the Trivy DB's age, source and stale state"
code=$(get "$ROUTE" "${WORK}/report.json")
age=$(trivy age_seconds)
summary="state=$(trivy state) source=$(trivy source) offline=$(trivy offline) version=$(trivy version)"
limit=$(jq -r '.max_age_seconds // empty' "${WORK}/report.json" 2>/dev/null)
verdicts=$(jq -r '.affects_verdicts | tostring' "${WORK}/report.json" 2>/dev/null)
any=$(jq -r '.any_stale | tostring' "${WORK}/report.json" 2>/dev/null)
echo "    HTTP ${code} ${summary} age_seconds=${age} max_age_seconds=${limit}"
if [ "$code" = "200" ] \
  && [ "$summary" = "state=stale source=adapter offline=true version=trivy-db-v2" ] \
  && [ "$age" -ge $((29 * DAY)) ] 2>/dev/null && [ "$age" -le $((31 * DAY)) ] 2>/dev/null \
  && [ "$limit" = "604800" ] && [ "$verdicts" = "false" ] && [ "$any" = "true" ]; then
  pass
else
  fail "HTTP ${code} ${summary} age=${age} limit=${limit} affects_verdicts=${verdicts} any_stale=${any}" \
    "$(head -c 400 "${WORK}/report.json")"
fi

begin_test "FIX #5177: the metrics carry the Trivy DB's age and the stale warning"
curl -s -m 15 -H "$(auth_header)" "${BASE_URL}/api/v1/admin/metrics" -o "${WORK}/metrics.txt" 2>/dev/null
metric() { grep -E "^$1\\{engine=\"trivy\"\\}" "${WORK}/metrics.txt" | awk '{print $NF}' | head -1; }
stale=$(metric ak_scanner_vuln_db_stale)
mage=$(metric ak_scanner_vuln_db_age_seconds)
warns=$(metric ak_scanner_vuln_db_stale_warnings_total)
echo "    ak_scanner_vuln_db_stale=${stale} ak_scanner_vuln_db_age_seconds=${mage} stale_warnings_total=${warns}"
if [ "$stale" = "1" ] && awk -v a="${mage:-0}" -v d="$DAY" 'BEGIN{exit !(a >= 29*d && a <= 31*d)}' \
  && awk -v w="${warns:-0}" 'BEGIN{exit !(w >= 1)}'; then
  pass
else
  fail "stale=${stale:-absent} age=${mage:-absent} warnings=${warns:-absent}" \
    "$(grep -E '^ak_scanner_vuln_db' "${WORK}/metrics.txt" | head -8)"
fi

begin_test "FIX #5177: the backend logs that the Trivy DB is stale"
if docker logs "$BACKEND_CTR" 2>&1 | grep -q 'vulnerability database is older than SCAN_VULN_DB_MAX_AGE_HOURS'; then
  pass
else
  fail "no stale-database warning in the backend log" "$(docker logs --tail 20 "$BACKEND_CTR" 2>&1 | tail -5)"
fi

begin_test "FIX #5177: 10 back-to-back reads of the report cost at most one adapter probe"
before=$(mock_hits)
codes=""
for _ in $(seq 1 10); do codes+="$(get "$ROUTE" "${WORK}/again.json") "; done
after=$(mock_hits)
probes=$((after - before))
echo "    adapter probes for 10 reads: ${probes} (codes: ${codes})"
if [ "$before" -ge 0 ] 2>/dev/null && [ "$probes" -le 1 ] && [ "${codes//200 /}" = "" ]; then
  pass
else
  fail "probes=${probes} (before=${before} after=${after}) codes=${codes}"
fi

end_suite
