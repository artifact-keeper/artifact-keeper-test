#!/usr/bin/env bash
# =============================================================================
# tiers/severity-counts-agree/oracle.sh
#   #4338 severity counts agree across the security dashboard, the repository
#         scores and the Overview CVE summary: one vulnerability per
#         (artifact, advisory) at its highest reported severity, open ones in
#         the severity counts, and acknowledging recomputes the repository score
# See the manifest for the fix and the gates.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# TRIVY_PORT (the mock OSV's published control port), RELEASE_GATE=1,
# JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"
: "${DTF_SLOT:?}"; : "${TRIVY_PORT:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

BASE="$BASE_URL"
MOCK="http://127.0.0.1:${TRIVY_PORT}"
SCAN_WAIT=150
SHARED_CVE="CVE-2019-10906"      # Grype reports it for jinja2 2.10 (high)
ACK_CVE="CVE-2024-34064"         # Grype-only, medium: the one acknowledged

setup_workdir
W="$WORK_DIR"

jqr(){ jq -r "$1" 2>/dev/null || true; }
psqlq(){ docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null || true; }

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }
eq(){ [ "$2" = "$3" ] || fail_g "$1 = '$2', expected '$3'"; }

api(){ # <METHOD> <path> [json] -> HTTP code; body in $W/api.body
  local code
  code="$(curl -s --max-time 60 -o "$W/api.body" -w '%{http_code}' -X "$1" "$BASE$2" \
    -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' ${3:+-d "$3"})" || true
  echo "${code:-000}"
}
abody(){ cat "$W/api.body" 2>/dev/null || true; }

# The oracle's own reading of the data, straight from Postgres, with the
# definition #4338 documents: for every live artifact the latest completed
# scan of each scan type; one vulnerability per (artifact, advisory = CVE id
# or title) at the highest severity any of those scans reported; acknowledged
# only when every row behind it is. Prints "open critical high medium low ack".
expected(){
  psqlq "WITH latest AS (
           SELECT DISTINCT ON (artifact_id, scan_type) id FROM scan_results
           WHERE status='completed' ORDER BY artifact_id, scan_type, completed_at DESC NULLS LAST),
         v AS (
           SELECT f.artifact_id, COALESCE(NULLIF(UPPER(BTRIM(f.cve_id)),''), f.title) AS k,
                  max(CASE lower(f.severity) WHEN 'critical' THEN 4 WHEN 'high' THEN 3
                      WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END) AS r,
                  bool_and(f.is_acknowledged) AS ack
           FROM scan_findings f JOIN latest l ON l.id=f.scan_result_id
           JOIN artifacts a ON a.id=f.artifact_id AND NOT a.is_deleted
           GROUP BY 1, 2)
         SELECT count(*) FILTER (WHERE NOT ack)||' '||count(*) FILTER (WHERE NOT ack AND r=4)||' '||
                count(*) FILTER (WHERE NOT ack AND r=3)||' '||count(*) FILTER (WHERE NOT ack AND r=2)||' '||
                count(*) FILTER (WHERE NOT ack AND r=1)||' '||count(*) FILTER (WHERE ack)
         FROM v"
}
# surfaces: fetch the three read models into $W/{dash,score,trends}.json
surfaces(){
  api GET /api/v1/security/dashboard >/dev/null; abody > "$W/dash.json"
  api GET "/api/v1/repositories/${REPO}/security" >/dev/null; abody | jq '.score // {}' > "$W/score.json" 2>/dev/null
  api GET /api/v1/sbom/cve/trends >/dev/null; abody > "$W/trends.json"
  note "dashboard: $(jq -c '{total_findings,critical_findings,high_findings}' "$W/dash.json" 2>/dev/null)"
  note "repo score: $(jq -c '{total_findings,critical_count,high_count,medium_count,low_count,acknowledged_count}' "$W/score.json" 2>/dev/null)"
  note "cve trends: $(jq -c '{open_cves,acknowledged_cves,critical_count,high_count,medium_count,low_count}' "$W/trends.json" 2>/dev/null)"
}
j(){ jq -r "$2 // \"\"" "$W/$1.json" 2>/dev/null || true; }

# =============================================================================
begin_suite "severity-counts-agree"

begin_test "setup: one manifest whose CVE is reported by two scanners (Grype on jinja2, the dependency scanner on a second package)"
TOK="$(curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"${ADMIN_PASS}\"}" | jqr '.access_token // .token // empty')"
if [ -z "$TOK" ]; then infra_fail "admin login failed at $BASE"; end_suite; fi
if [ "$(curl -s --max-time 5 "${MOCK}/__readyz" || true)" != "ok" ]; then
  infra_fail "mock OSV not reachable on ${MOCK} (profiles/upstreams.mock-osv.yml)"; end_suite
fi
SFX="$(printf '%s' "${RUN_ID##*-}$$" | tr -cd '0-9')"
PKG="dtf-shared-${SFX}"
# The mock answers PKG with an advisory whose id IS the CVE: every image then
# stores cve_id=${SHARED_CVE} on the dependency finding (an id starting with
# CVE- is its own CVE), so the artifact holds the same advisory twice, from
# two scanners, on two components.
ADV="$(jq -nc --arg p "$PKG" --arg c "$SHARED_CVE" '{rules:[{ecosystem:"PyPI",name:$p,version:"1.0.0",ids:[$c]}],
  records:{($c):{id:$c,modified:"2026-01-01T00:00:00Z",summary:"DTF shared advisory",
    database_specific:{severity:"CRITICAL"},
    affected:[{package:{ecosystem:"PyPI",name:$p},ranges:[{type:"ECOSYSTEM",events:[{introduced:"0"},{fixed:"1.0.1"}]}]}]}}}')"
reg="$(curl -s --max-time 5 -X PUT --data "$ADV" "${MOCK}/__advisories" | jqr '.records // empty')"
curl -s --max-time 5 -X PUT --data ok "${MOCK}/__mode" >/dev/null || true
REPO="sev-${SFX}"
c1="$(api POST /api/v1/repositories "$(jq -nc --arg k "$REPO" '{key:$k,name:$k,format:"generic",repo_type:"local",is_public:false}')")"
# PKG first: on images before #4081 the dependency finding names deps.first().
printf '%s==1.0.0\njinja2==2.10\n' "$PKG" > "$W/req.txt"
A="$(curl -s --max-time 30 -X PUT -H "Authorization: Bearer $TOK" --data-binary "@$W/req.txt" \
  "$BASE/api/v1/repositories/${REPO}/artifacts/app/requirements.txt" | jqr '.id // empty')"
t="$(api POST /api/v1/security/scan "{\"artifact_id\":\"${A}\"}")"
w=0
while [ "$w" -lt "$SCAN_WAIT" ]; do
  [ "$(psqlq "SELECT count(*) FROM scan_results WHERE artifact_id='${A}' AND status='completed' AND scan_type IN ('grype','dependency')")" = "2" ] \
    && [ "$(psqlq "SELECT count(*) FROM scan_results WHERE artifact_id='${A}' AND status IN ('pending','running')")" = "0" ] && break
  sleep 2; w=$((w+2))
done
note "advisories ${reg}; repo ${c1}; artifact ${A}; scan ${t}; settled after ${w}s"
if [ "$reg" = "1" ] && [[ "$c1" =~ ^20[01]$ ]] && [ -n "$A" ] && [[ "$t" =~ ^2 ]] && [ "$w" -lt "$SCAN_WAIT" ]; then
  pass
else
  infra_fail "setup: $(printf '%s' "$DETAIL" | tr '\n' ' ')"; end_suite
fi

begin_test "CONTROL: the artifact holds ${SHARED_CVE} from both scanners and five more Grype-only jinja2 CVEs"
reset_case
psqlq "SELECT sr.scan_type||'|'||COALESCE(f.affected_component,'')||'|'||UPPER(COALESCE(f.cve_id,''))||'|'||f.severity
       FROM scan_findings f JOIN scan_results sr ON sr.id=f.scan_result_id
       WHERE f.artifact_id='${A}' ORDER BY 1" > "$W/rows"
note "finding rows: $(tr '\n' ';' < "$W/rows")"
grep -q "^grype|jinja2|${SHARED_CVE}|" "$W/rows" || fail_g "Grype did not report ${SHARED_CVE} for jinja2 2.10"
grep -q "^dependency|${PKG}|${SHARED_CVE}|" "$W/rows" || fail_g "the dependency scanner did not report ${SHARED_CVE} for ${PKG}"
[ "$(cut -d'|' -f3 "$W/rows" | sort -u | grep -c .)" -ge 6 ] || fail_g "fewer than 6 distinct CVEs on the artifact"
grep -q "|${ACK_CVE}|" "$W/rows" || fail_g "Grype did not report ${ACK_CVE} (the acknowledge case needs it)"
finish_case "the fixture does not hold a cross-scanner duplicate"

read -r E_OPEN E_CRIT E_HIGH E_MED E_LOW E_ACK <<<"$(expected)"
note_exp="open=${E_OPEN} critical=${E_CRIT} high=${E_HIGH} medium=${E_MED} low=${E_LOW} acknowledged=${E_ACK}"

begin_test "CONTROL: the Overview CVE summary counts one vulnerability per (artifact, CVE)"
reset_case
surfaces
note "expected (one per advisory, highest severity): ${note_exp}"
eq "trends.open_cves" "$(j trends .open_cves)" "$E_OPEN"
finish_case "Overview CVE summary"

begin_test "FIX #4338: the security dashboard counts each advisory once, at its highest severity"
reset_case
note "expected: ${note_exp}"
eq "dashboard.total_findings" "$(j dash .total_findings)" "$E_OPEN"
eq "dashboard.critical_findings" "$(j dash .critical_findings)" "$E_CRIT"
eq "dashboard.high_findings" "$(j dash .high_findings)" "$E_HIGH"
finish_case "dashboard counts finding rows"

begin_test "FIX #4338: the repository score counts each advisory once, at its highest severity"
reset_case
note "expected: ${note_exp}"
eq "score.total_findings" "$(j score .total_findings)" "$E_OPEN"
eq "score.critical_count" "$(j score .critical_count)" "$E_CRIT"
eq "score.high_count" "$(j score .high_count)" "$E_HIGH"
eq "score.medium_count" "$(j score .medium_count)" "$E_MED"
finish_case "repository score counts finding rows"

begin_test "FIX #4338: dashboard, repository score and Overview agree on every severity"
reset_case
eq "dashboard.critical_findings vs trends.critical_count" "$(j dash .critical_findings)" "$(j trends .critical_count)"
eq "dashboard.high_findings vs trends.high_count" "$(j dash .high_findings)" "$(j trends .high_count)"
eq "score.medium_count vs trends.medium_count" "$(j score .medium_count)" "$(j trends .medium_count)"
eq "score.total_findings vs trends.open_cves" "$(j score .total_findings)" "$(j trends .open_cves)"
eq "dashboard.total_findings vs score.total_findings" "$(j dash .total_findings)" "$(j score .total_findings)"
finish_case "surfaces disagree"

# -----------------------------------------------------------------------------
begin_test "CONTROL: acknowledging a Grype-only ${ACK_CVE} finding is accepted and moves it out of the Overview open count"
reset_case
FID="$(psqlq "SELECT id FROM scan_findings WHERE artifact_id='${A}' AND UPPER(cve_id)='${ACK_CVE}' LIMIT 1")"
before_score="$(j score .total_findings)"
code="$(api POST "/api/v1/security/findings/${FID}/acknowledge" '{"reason":"dtf: accepted risk"}')"
note "acknowledge ${FID} -> ${code}: $(abody | jq -c '{is_acknowledged,acknowledged_reason}' 2>/dev/null)"
read -r E_OPEN E_CRIT E_HIGH E_MED E_LOW E_ACK <<<"$(expected)"
note_exp="open=${E_OPEN} critical=${E_CRIT} high=${E_HIGH} medium=${E_MED} low=${E_LOW} acknowledged=${E_ACK}"
surfaces
note "expected after acknowledge: ${note_exp}"
[ "$code" = "200" ] || fail_g "acknowledge -> ${code}"
eq "trends.open_cves" "$(j trends .open_cves)" "$E_OPEN"
eq "trends.acknowledged_cves" "$(j trends .acknowledged_cves)" "$E_ACK"
finish_case "acknowledge"

begin_test "FIX #4338: acknowledging recomputes the repository score without a rescan"
reset_case
note "score.total_findings before ${before_score}, after $(j score .total_findings)"
eq "score.total_findings" "$(j score .total_findings)" "$E_OPEN"
eq "score.medium_count" "$(j score .medium_count)" "$E_MED"
eq "score.acknowledged_count" "$(j score .acknowledged_count)" "$E_ACK"
eq "dashboard.total_findings" "$(j dash .total_findings)" "$E_OPEN"
finish_case "repository score stale after acknowledge"

end_suite
