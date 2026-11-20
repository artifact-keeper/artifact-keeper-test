#!/usr/bin/env bash
# =============================================================================
# tiers/proxy-scan-db-update-grace/oracle.sh - a vulnerability-DB update does
# not re-scan every cached package on its next pull (artifact-keeper#6300)
# =============================================================================
# run.sh has stood up `storage.filesystem upstreams.mock-scan-formats` and
# exported BASE_URL, ADMIN_PASS, RUN_ID, DTF_SLOT, TRIVY_PORT (the mock's
# control port), DB_CONTAINER, COMMON_SH.
#
# Fixtures (mock_scan_upstream.py, shared with scan-on-proxy-maven-nuget):
# log4j-core 2.14.1 (critical, graded vulnerable by every Grype DB the images
# ship) and com.example.dtfscan:dtf-clean 1.0.0 (no advisory), through a Maven
# Remote with scan_on_proxy and fail_closed.
#
# The DB bump is simulated from the stored side (see the manifest): an older
# build of the live Grype binary is recorded as first seen a day ago, a still
# older one two days ago, and the stored verdicts are rewritten to the older
# build, the log4j one `clean`. Whether a pull scanned on the request path is
# read race-free from the row: a scan the pull waited for left it graded by
# the live build with `scanned_at` BEFORE the response was received; a
# background re-grade leaves it as it was or writes it after.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DB_CONTAINER:?}"; : "${TRIVY_PORT:?}"
: "${RUN_ID:?}"; : "${DTF_SLOT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

begin_suite "proxy-scan-db-update-grace"
auth_admin
setup_workdir

MOCK="http://127.0.0.1:${TRIVY_PORT}"
UP="http://172.16.${DTF_SLOT}.72"
SUF="${DTF_SLOT}x${RUN_ID##*-}"
MVN="psdg-mvn-${SUF}"
BACKEND_CONTAINER="${DB_CONTAINER%-db}-backend"

LOG4J="org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.jar"
CLEAN="com/example/dtfscan/dtf-clean/1.0.0/dtf-clean-1.0.0.jar"

cleanup() {
  api_delete "/api/v1/repositories/${MVN}" >/dev/null 2>&1 || true
}
add_exit_handler "cleanup"

psql_q() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]'; }
golden_sha() { curl -s --max-time 10 "${MOCK}/__sha256/$1" || true; }
row_of() { psql_q "SELECT verdict || '|' || coalesce(scanner_version,'<null>') FROM proxy_scan_results WHERE checksum_sha256='$1' AND scan_type='grype'"; }
# Did the pull answered at $2 wait for a scan of $1? Only a scan it waited for
# leaves the row graded by the live build AND written before the response; a
# background re-grade leaves it untouched or writes it after. "t" or "f".
scanned_inline() {
  psql_q "SELECT scanner_version = '${LIVE}' AND scanned_at <= to_timestamp($2) FROM proxy_scan_results WHERE checksum_sha256='$1' AND scan_type='grype'"
}
# Make a row look graded by $2, optionally clean.
age_row() { # <digest> <scanner_version> [clean]
  local set_clean=""
  [ "${3:-}" = "clean" ] && set_clean="verdict='clean', findings_count=0, critical_count=0, high_count=0, medium_count=0, low_count=0, max_severity=NULL,"
  psql_q "UPDATE proxy_scan_results SET ${set_clean} scanner_version='$2' WHERE checksum_sha256='$1' AND scan_type='grype'" >/dev/null
}

BODY="${WORK_DIR}/body"
pull() { # <path> -> sets ST, SCAN, AT (epoch seconds when the response was in)
  local hdr="${WORK_DIR}/hdr"
  ST=$(curl -s -D "$hdr" -o "$BODY" -w '%{http_code}' --max-time 120 "${BASE_URL}/maven/${MVN}/$1" 2>/dev/null) || ST="000"
  AT=$(date +%s.%N)
  SCAN=$(grep -i '^x-ak-scan:' "$hdr" 2>/dev/null | tr -d '\r' | sed 's/^[^:]*:[[:space:]]*//' | head -1) || true
}

begin_test "SETUP: mock reachable; Maven Remote with scan_on_proxy fail_closed; live Grype version"
ok=1
L4_D=$(golden_sha "maven2/${LOG4J}")
CL_D=$(golden_sha "maven2/${CLEAN}")
[ -n "$L4_D" ] && [ -n "$CL_D" ] || ok=0
create_repo "$MVN" maven remote "${UP}/maven2" || ok=0
act=$(api_put "/api/v1/repositories/${MVN}/security" \
  '{"scan_enabled":true,"scan_on_proxy":true,"proxy_scan_action":"fail_closed"}' 2>/dev/null \
  | jq -r '.proxy_scan_action // empty' 2>/dev/null)
RAW_VER="$(docker exec "$BACKEND_CONTAINER" /usr/local/bin/grype --version 2>/dev/null | head -1 | tr -d '\r')"
TOK1="$(printf '%s' "$RAW_VER" | awk '{print $1}')"
case "$TOK1" in
  grype|Grype|Version:) LIVE_NUM="$(printf '%s' "$RAW_VER" | awk '{print $2}')" ;;
  *)                    LIVE_NUM="$TOK1" ;;
esac
CLI="grype-${LIVE_NUM#v}"
PREV="${CLI}+db-2000-01-02"
TWO_BEHIND="${CLI}+db-2000-01-01"
if [ "$ok" = 1 ] && [ "$act" = "fail_closed" ] && [ -n "$LIVE_NUM" ]; then
  pass
else
  infra_fail "setup failed (ok=${ok} action='${act}' grype='${RAW_VER}')"
  end_suite
fi

# Before any pull reuses a stored verdict, which is when the backend records
# the live version and reads the version seen before it. On a build without
# the table this fails harmlessly: there is nothing to record.
psql_q "INSERT INTO proxy_scan_db_versions (scanner_version, first_seen_at) VALUES
          ('${TWO_BEHIND}', now() - interval '2 days'), ('${PREV}', now() - interval '1 day')
        ON CONFLICT (scanner_version) DO NOTHING" >/dev/null || true

begin_test "SETUP: first pulls grade both jars against the live DB build (dtf-clean 200, log4j-core 403)"
pull "$CLEAN"; c_st="$ST"
pull "$LOG4J"; l_st="$ST"
LIVE="$(row_of "$CL_D")"; LIVE="${LIVE#*|}"
case "$LIVE" in
  "${CLI}+db-"*) live_ok=1 ;;
  *) live_ok=0 ;;
esac
if [ "$c_st" = "200" ] && [ "$l_st" = "403" ] && [ "$live_ok" = 1 ] \
   && [ "$(row_of "$L4_D")" = "vulnerable|${LIVE}" ]; then
  pass
else
  infra_fail "first pulls: dtf-clean=${c_st} log4j=${l_st} rows clean='$(row_of "$CL_D")' log4j='$(row_of "$L4_D")' (want ${CLI}+db-*)"
  end_suite
fi

# The DB update: both verdicts were graded by the previous build, which did
# not know the log4j advisory yet.
age_row "$CL_D" "$PREV"
age_row "$L4_D" "$PREV" clean

begin_test "FIX #6300: after a DB update, a fail_closed pull of a cached clean jar is answered without a scan on the request path"
pull "$CLEAN"; c_at="$AT"; c_st="$ST"; c_scan="$SCAN"
c_row="$(row_of "$CL_D")"
if [ "$c_st" = "200" ] && [ "$c_scan" = "clean" ] && [ "$(scanned_inline "$CL_D" "$c_at")" = "f" ]; then
  pass
else
  fail "the pull re-scanned the jar before answering (every DB update re-scans every cached package on its next pull)" \
    "status=${c_st} X-AK-Scan='${c_scan}' row-after-response='${c_row}' scanned-inline=$(scanned_inline "$CL_D" "$c_at")"
fi

begin_test "FIX #6300: the cached log4j-core jar, graded clean by the previous build, is not blocked or scanned synchronously either"
pull "$LOG4J"; l_at="$AT"; l_st="$ST"
l_row="$(row_of "$L4_D")"
if [ "$l_st" = "200" ] && [ "$(scanned_inline "$L4_D" "$l_at")" = "f" ]; then
  pass
else
  fail "the pull waited for an inline re-scan" \
    "status=${l_st} X-AK-Scan='${SCAN}' row-after-response='${l_row}' scanned-inline=$(scanned_inline "$L4_D" "$l_at")"
fi

begin_test "CONTROL: both jars are re-graded against the live build, and log4j-core is blocked once re-graded (403)"
for _ in $(seq 1 90); do
  [ "$(row_of "$CL_D")" = "clean|${LIVE}" ] && [ "$(row_of "$L4_D")" = "vulnerable|${LIVE}" ] && break
  sleep 1
done
pull "$LOG4J"; l_st="$ST"
pull "$CLEAN"; c_st="$ST"
if [ "$(row_of "$CL_D")" = "clean|${LIVE}" ] && [ "$(row_of "$L4_D")" = "vulnerable|${LIVE}" ] \
   && [ "$l_st" = "403" ] && [ "$c_st" = "200" ]; then
  pass
else
  fail "not re-graded within 90 s, or the re-graded verdicts are not enforced" \
    "rows clean='$(row_of "$CL_D")' log4j='$(row_of "$L4_D")' (want ${LIVE}); log4j=${l_st} dtf-clean=${c_st}"
fi

begin_test "CONTROL: a verdict from another scanner binary is re-scanned before the pull is answered"
age_row "$CL_D" "grype-0.0.1-dtf+db-2000-01-02"
pull "$CLEAN"
if [ "$ST" = "200" ] && [ "$(scanned_inline "$CL_D" "$AT")" = "t" ]; then
  pass
else
  fail "a binary upgrade must still re-scan on the next pull" \
    "status=${ST} row='$(row_of "$CL_D")' scanned-inline=$(scanned_inline "$CL_D" "$AT")"
fi

begin_test "CONTROL: a verdict two DB builds behind is re-scanned before the pull is answered"
age_row "$L4_D" "$TWO_BEHIND" clean
pull "$LOG4J"
if [ "$ST" = "403" ] && [ "$(scanned_inline "$L4_D" "$AT")" = "t" ] && [ "$(row_of "$L4_D")" = "vulnerable|${LIVE}" ]; then
  pass
else
  fail "a verdict more than one build behind must not be reused" \
    "status=${ST} row='$(row_of "$L4_D")' scanned-inline=$(scanned_inline "$L4_D" "$AT")"
fi

end_suite
