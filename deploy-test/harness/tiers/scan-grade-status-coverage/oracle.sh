#!/usr/bin/env bash
# =============================================================================
# tiers/scan-grade-status-coverage/oracle.sh: grade status and coverage
# instead of the F floor (artifact-keeper#4336)
# =============================================================================
# run.sh has stood up `storage.filesystem upstreams.mock-scan-formats` and
# exported BASE_URL, ADMIN_PASS, RUN_ID, DTF_SLOT, TRIVY_PORT (the mock's
# control port, used only to fetch the clean Maven jar fixture), DB_CONTAINER,
# COMMON_SH. See the manifest for the gates.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DB_CONTAINER:?}"; : "${TRIVY_PORT:?}"
: "${RUN_ID:?}"; : "${DTF_SLOT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every probe below is an assignment or a test.

begin_suite "scan-grade-status-coverage-4336"
auth_admin
setup_workdir
require_cmd python3

MOCK="http://127.0.0.1:${TRIVY_PORT}"
SUF="${DTF_SLOT}x${RUN_ID##*-}"
REPO="dtf-gsc-${SUF}"
JAR_PATH="lib/dtf-clean-1.0.0.jar"
WHL_PATH="wheels/dtfgsc${DTF_SLOT}-1.0-py3-none-any.whl"

cleanup() { api_delete "/api/v1/repositories/${REPO}" >/dev/null 2>&1 || true; }
add_exit_handler "cleanup"

psql_q() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]' || true; }
put() { # FILE URL -> HTTP status
  curl -s -o "${WORK_DIR}/put.out" -w '%{http_code}' --max-time 60 -X PUT -H "$(auth_header)" \
    -H "Content-Type: application/octet-stream" --data-binary "@$1" "$2" 2>/dev/null || echo 000
}
completed_scans() { # PATH_SUFFIX -> completed scan rows of that artifact
  psql_q "SELECT count(*) FROM scan_results s JOIN artifacts a ON a.id = s.artifact_id
          JOIN repositories r ON r.id = a.repository_id
          WHERE r.key = '${REPO}' AND s.status = 'completed' AND a.path LIKE '%$1' AND NOT a.is_deleted"
}
both_scanned() { [ "$(completed_scans ".jar")" -ge 1 ] 2>/dev/null && [ "$(completed_scans ".whl")" -ge 1 ] 2>/dev/null; }
security() { api_get "/api/v1/repositories/${REPO}/security" 2>/dev/null > "${WORK_DIR}/sec.json" || true; }
# summary -> "grade|status|scanned|cataloged|uncataloged|failed" ("none" for absent)
summary() {
  security
  jq -r '(.score // {}) | "\(.grade // "none")|\(.grade_status // "none")|\(.coverage.scanned // "none")|\(.coverage.cataloged // "none")|\(.coverage.uncataloged // "none")|\(.coverage.failed // "none")"' \
    "${WORK_DIR}/sec.json" 2>/dev/null || echo "none|none|none|none|none|none"
}
status_is() { [ "$(summary | cut -d'|' -f2)" = "$1" ]; }
field() { echo "$1" | cut -d'|' -f"$2"; }

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
begin_test "Setup: fixtures, a generic repository with scan_enabled + scan_on_upload"
curl -s --max-time 10 -o "${WORK_DIR}/clean.jar" \
  "${MOCK}/__golden/maven2/com/example/dtfscan/dtf-clean/1.0.0/dtf-clean-1.0.0.jar" || true
# A "wheel" that is a zip of one text file: nothing for a scanner to catalog.
python3 -I -c "import io,sys,zipfile; b=io.BytesIO(); z=zipfile.ZipFile(b,'w'); z.writestr('notes.txt','not a wheel ${SUF}\n'); z.close(); open(sys.argv[1],'wb').write(b.getvalue())" \
  "${WORK_DIR}/fake.whl" 2>/dev/null || true
ok=1
create_repo "$REPO" generic local || ok=0
[ "$(api_put "/api/v1/repositories/${REPO}/security" '{"scan_enabled":true,"scan_on_upload":true}' 2>/dev/null \
    | jq -r '.scan_on_upload' 2>/dev/null || true)" = "true" ] || ok=0
if [ "$ok" = 1 ] && [ -s "${WORK_DIR}/clean.jar" ] && [ -s "${WORK_DIR}/fake.whl" ]; then pass
else fail "setup ok=${ok} jar=$(wc -c < "${WORK_DIR}/clean.jar" 2>/dev/null) whl=$(wc -c < "${WORK_DIR}/fake.whl" 2>/dev/null)"; end_suite; fi

begin_test "CONTROL: both uploads are accepted and scanned on upload"
s1=$(put "${WORK_DIR}/clean.jar" "${BASE_URL}/api/v1/repositories/${REPO}/artifacts/${JAR_PATH}")
s2=$(put "${WORK_DIR}/fake.whl" "${BASE_URL}/api/v1/repositories/${REPO}/artifacts/${WHL_PATH}")
wait_until "both scans" 120 both_scanned || true
if [[ "$s1" =~ ^20[01]$ && "$s2" =~ ^20[01]$ ]] && both_scanned; then pass
else fail "jar=${s1} whl=${s2}; completed rows jar=$(completed_scans .jar) whl=$(completed_scans .whl)"; end_suite; fi

begin_test "CONTROL: the .whl's scan is not_cataloged with a reason and the repository is flagged"
whl_grype_row() {
  docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc \
    "SELECT coalesce(s.scan_completeness,'') || '|' || coalesce(s.scan_completeness_reason,'')
     FROM scan_results s JOIN artifacts a ON a.id = s.artifact_id JOIN repositories r ON r.id = a.repository_id
     WHERE r.key = '${REPO}' AND a.path LIKE '%.whl' AND s.scan_type = 'grype' AND s.status = 'completed'
     ORDER BY s.completed_at DESC LIMIT 1" 2>/dev/null | head -1 || true
}
whl_grype_done() { [ -n "$(whl_grype_row)" ]; }
wait_until "whl grype row" 120 whl_grype_done || true
row=$(whl_grype_row)
flag_ok() { security; [ "$(jq -r '.score.has_uncataloged_scan // false' "${WORK_DIR}/sec.json" 2>/dev/null)" = "true" ]; }
wait_until "uncataloged flag" 30 flag_ok || true
if [ "${row%%|*}" = "not_cataloged" ] && [ -n "${row#*|}" ] && flag_ok; then pass
else fail "grype row '${row}', score $(head -c 300 "${WORK_DIR}/sec.json" 2>/dev/null)"; fi

# ---------------------------------------------------------------------------
# One scannable jar + one uncataloged archive: incomplete, 1 of 2, no F
# ---------------------------------------------------------------------------
wait_until "incomplete status" 30 status_is incomplete || true
sum=$(summary)
begin_test "FIX #4336: jar + uncataloged archive is incomplete with coverage 1 of 2 and no F"
if [ "$(field "$sum" 2)" = "incomplete" ] && [ "$(field "$sum" 3)" = "2" ] && [ "$(field "$sum" 4)" = "1" ] \
   && [ "$(field "$sum" 5)" = "1" ] && [ "$(field "$sum" 6)" = "0" ] && [ "$(field "$sum" 1)" != "F" ] \
   && [ "$(field "$sum" 1)" != "none" ]; then pass
else fail "#4336: grade|status|scanned|cataloged|uncataloged|failed = ${sum} (pre-fix: F|none|...)" \
  "$(head -c 600 "${WORK_DIR}/sec.json" 2>/dev/null)"; fi
REAL_GRADE="$(field "$sum" 1)"

begin_test "FIX #4336: scan rows carry grade_status: the .whl unrated with a reason, the jar rated"
api_get "/api/v1/repositories/${REPO}/security/scans?per_page=100" 2>/dev/null > "${WORK_DIR}/scans.json" || true
whl_row=$(jq -r --arg p "$WHL_PATH" '[.items[]? | select((.artifact_name // "") | test("whl$")) | select(.scan_type == "grype")][0] | "\(.grade_status // "none")|\(.grade_status_reason // "none")"' "${WORK_DIR}/scans.json" 2>/dev/null || echo "none|none")
jar_rated=$(jq -r '[.items[]? | select((.artifact_name // "") | test("jar$")) | select(.status == "completed") | .grade_status] | index("rated") != null' "${WORK_DIR}/scans.json" 2>/dev/null || echo false)
if [ "${whl_row%%|*}" = "unrated" ] && [ "${whl_row#*|}" != "none" ] && [ "$jar_rated" = "true" ]; then pass
else fail "#4336: whl row ${whl_row}, jar rated=${jar_rated}" "$(head -c 800 "${WORK_DIR}/scans.json" 2>/dev/null)"; fi

begin_test "FIX #4336: the security dashboard counts repositories by grade status"
api_get "/api/v1/security/dashboard" 2>/dev/null > "${WORK_DIR}/dash.json" || true
inc=$(jq -r '.repos_incomplete // "none"' "${WORK_DIR}/dash.json" 2>/dev/null || echo none)
if [ "$inc" != "none" ] && [ "$inc" -ge 1 ] 2>/dev/null \
   && [ "$(jq -r 'has("repos_rated") and has("repos_unrated")' "${WORK_DIR}/dash.json" 2>/dev/null)" = "true" ]; then pass
else fail "#4336: dashboard repos_incomplete=${inc}" "$(head -c 400 "${WORK_DIR}/dash.json" 2>/dev/null)"; fi

# ---------------------------------------------------------------------------
# Delete the archive: rated with the real letter
# ---------------------------------------------------------------------------
begin_test "FIX #4336: after the archive is deleted the repository is rated with its real grade"
d1=$(curl -s -o /dev/null -w '%{http_code}' --max-time 30 -X DELETE -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${REPO}/artifacts/${WHL_PATH}" 2>/dev/null || echo 000)
wait_until "rated status" 30 status_is rated || true
sum=$(summary)
if [[ "$d1" =~ ^20[04]$ ]] && [ "$(field "$sum" 2)" = "rated" ] && [ "$(field "$sum" 1)" = "$REAL_GRADE" ] \
   && [ "$(field "$sum" 3)" = "1" ] && [ "$(field "$sum" 4)" = "1" ] && [ "$(field "$sum" 5)" = "0" ]; then pass
else fail "#4336: delete HTTP ${d1}; grade|status|scanned|cataloged|uncataloged|failed = ${sum} (want ${REAL_GRADE}|rated|1|1|0|0)" \
  "$(head -c 600 "${WORK_DIR}/sec.json" 2>/dev/null)"; fi

# ---------------------------------------------------------------------------
# Delete the jar too: no scans left, unrated
# ---------------------------------------------------------------------------
begin_test "FIX #4336: with no scans left the repository is unrated with no grade letter"
d2=$(curl -s -o /dev/null -w '%{http_code}' --max-time 30 -X DELETE -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${REPO}/artifacts/${JAR_PATH}" 2>/dev/null || echo 000)
wait_until "unrated status" 30 status_is unrated || true
sum=$(summary)
if [[ "$d2" =~ ^20[04]$ ]] && [ "$(field "$sum" 2)" = "unrated" ] && [ "$(field "$sum" 1)" = "none" ] \
   && [ "$(field "$sum" 3)" = "0" ]; then pass
else fail "#4336: delete HTTP ${d2}; grade|status|scanned|... = ${sum} (want none|unrated|0|...)" \
  "$(head -c 600 "${WORK_DIR}/sec.json" 2>/dev/null)"; fi

end_suite
