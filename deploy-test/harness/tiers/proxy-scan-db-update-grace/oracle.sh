#!/usr/bin/env bash
# =============================================================================
# tiers/proxy-scan-db-update-grace/oracle.sh - a vulnerability-DB update does
# not re-scan every cached proxy package on its next pull (artifact-keeper#6300)
# =============================================================================
# run.sh has stood up `storage.filesystem upstreams.mock-scan-formats` and
# exported BASE_URL, ADMIN_PASS, RUN_ID, DTF_SLOT, TRIVY_PORT (the mock's
# control port), DB_CONTAINER, COMMON_SH, DTF_DIR and the compose variables.
#
# Fixtures (mock_scan_upstream.py, shared with scan-on-proxy-maven-nuget):
# log4j-core 2.14.1 (critical, graded vulnerable by every Grype DB the images
# ship) and com.example.dtfscan:dtf-clean 1.0.0 (no advisory), through two
# Maven Remotes with scan_on_proxy: one fail_open, one fail_closed. Verdicts
# are per digest, so both Remotes share them.
#
# The DB bump is simulated from the stored side (see the manifest). Recorded
# in proxy_scan_db_versions: an older build of the live Grype binary, first
# seen a day ago (the previous build), and a still older one recorded a minute
# ago (a replica on a stale DB, recorded LATE: it must not become the previous
# build). The stored verdicts are rewritten to the previous build, log4j-core
# `clean`, as a build that did not know the advisory would have graded it.
#
# Phase 1 runs on the defaults: the grace is 6 h for fail_open, off for
# fail_closed. Phase 2 recreates the backend with the fail_closed opt-in
# (fixtures/fail-closed-grace.yml).
#
# Whether a pull scanned on the request path is read race-free from the row:
# a scan the pull waited for left it graded by the live build with
# `scanned_at` BEFORE the response was received; a background re-grade leaves
# it as it was or writes it after.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DB_CONTAINER:?}"; : "${TRIVY_PORT:?}"
: "${RUN_ID:?}"; : "${DTF_SLOT:?}"; : "${DTF_DIR:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

begin_suite "proxy-scan-db-update-grace"
auth_admin
setup_workdir

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT="ak-dtf${DTF_SLOT}"
MOCK="http://127.0.0.1:${TRIVY_PORT}"
UP="http://172.16.${DTF_SLOT}.72"
SUF="${DTF_SLOT}x${RUN_ID##*-}"
FO="psdg-fo-${SUF}"
FC="psdg-fc-${SUF}"
BACKEND_CONTAINER="${DB_CONTAINER%-db}-backend"

LOG4J="org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.jar"
CLEAN="com/example/dtfscan/dtf-clean/1.0.0/dtf-clean-1.0.0.jar"

cleanup() {
  api_delete "/api/v1/repositories/${FO}" >/dev/null 2>&1 || true
  api_delete "/api/v1/repositories/${FC}" >/dev/null 2>&1 || true
}
add_exit_handler "cleanup"

psql_q() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]'; }
golden_sha() { curl -s --max-time 10 "${MOCK}/__sha256/$1" || true; }
row_of() { psql_q "SELECT verdict || '|' || coalesce(scanner_version,'<null>') FROM proxy_scan_results WHERE checksum_sha256='$1' AND scan_type='grype'"; }
# Did the pull answered at $2 wait for a scan of $1? "t" or "f".
scanned_inline() {
  psql_q "SELECT scanner_version = '${LIVE}' AND scanned_at <= to_timestamp($2) FROM proxy_scan_results WHERE checksum_sha256='$1' AND scan_type='grype'"
}
# Make a row look graded by $2, optionally clean.
age_row() { # <digest> <scanner_version> [clean]
  local set_clean=""
  [ "${3:-}" = "clean" ] && set_clean="verdict='clean', findings_count=0, critical_count=0, high_count=0, medium_count=0, low_count=0, max_severity=NULL,"
  psql_q "UPDATE proxy_scan_results SET ${set_clean} scanner_version='$2' WHERE checksum_sha256='$1' AND scan_type='grype'" >/dev/null
}
# Wait (up to 90 s) until both rows carry the live build, log4j vulnerable.
wait_regraded() {
  local _
  for _ in $(seq 1 90); do
    [ "$(row_of "$CL_D")" = "clean|${LIVE}" ] && [ "$(row_of "$L4_D")" = "vulnerable|${LIVE}" ] && return 0
    sleep 1
  done
  return 1
}

BODY="${WORK_DIR}/body"
pull() { # <repo> <path> -> sets ST, SCAN, AT (epoch seconds when the response was in)
  local hdr="${WORK_DIR}/hdr"
  ST=$(curl -s -D "$hdr" -o "$BODY" -w '%{http_code}' --max-time 120 "${BASE_URL}/maven/$1/$2" 2>/dev/null) || ST="000"
  AT=$(date +%s.%N)
  SCAN=$(grep -i '^x-ak-scan:' "$hdr" 2>/dev/null | tr -d '\r' | sed 's/^[^:]*:[[:space:]]*//' | head -1) || true
}
scan_cfg() {
  api_put "/api/v1/repositories/$1/security" \
    "{\"scan_enabled\":true,\"scan_on_proxy\":true,\"proxy_scan_action\":\"$2\"}" 2>/dev/null \
    | jq -r '.proxy_scan_action // empty' 2>/dev/null
}
# The operator's fail_closed opt-in: only the backend is recreated.
recreate_backend_opted_in() {
  docker compose -p "$PROJECT" -f "${DTF_DIR}/compose.base.yml" \
    -f "${DTF_DIR}/profiles/storage.filesystem.yml" \
    -f "${DTF_DIR}/profiles/upstreams.mock-scan-formats.yml" \
    -f "${HERE}/fixtures/fail-closed-grace.yml" \
    up -d --no-deps --force-recreate --wait backend >"${WORK_DIR}/recreate.log" 2>&1 \
    || { tail -20 "${WORK_DIR}/recreate.log"; return 1; }
  wait_until "backend health after recreate" 120 curl -sf --max-time 3 "${BASE_URL}/health" || return 1
  auth_admin >/dev/null 2>&1
}

begin_test "SETUP: mock reachable; fail_open and fail_closed Maven Remotes; live Grype version"
ok=1
L4_D=$(golden_sha "maven2/${LOG4J}")
CL_D=$(golden_sha "maven2/${CLEAN}")
[ -n "$L4_D" ] && [ -n "$CL_D" ] || ok=0
create_repo "$FO" maven remote "${UP}/maven2" || ok=0
create_repo "$FC" maven remote "${UP}/maven2" || ok=0
acts="$(scan_cfg "$FO" fail_open)$(scan_cfg "$FC" fail_closed)"
RAW_VER="$(docker exec "$BACKEND_CONTAINER" /usr/local/bin/grype --version 2>/dev/null | head -1 | tr -d '\r')"
TOK1="$(printf '%s' "$RAW_VER" | awk '{print $1}')"
case "$TOK1" in
  grype|Grype|Version:) LIVE_NUM="$(printf '%s' "$RAW_VER" | awk '{print $2}')" ;;
  *)                    LIVE_NUM="$TOK1" ;;
esac
CLI="grype-${LIVE_NUM#v}"
PREV="${CLI}+db-2000-01-02"
STALE="${CLI}+db-2000-01-01"
# Newer than the live build: one another replica recorded an hour ago, one
# recorded three days ago (a build since rolled back).
NEWER="${CLI}+db-2999-01-01"
ROLLED_BACK="${CLI}+db-2999-01-02"
if [ "$ok" = 1 ] && [ "$acts" = "fail_openfail_closed" ] && [ -n "$LIVE_NUM" ]; then
  pass
else
  infra_fail "setup failed (ok=${ok} actions='${acts}' grype='${RAW_VER}')"
  end_suite
fi

# Before any pull reuses a stored verdict, which is when the backend records
# the live version and reads the build below it. On a build without the table
# this fails harmlessly: there is nothing to record.
psql_q "INSERT INTO proxy_scan_db_versions (scanner_version, first_seen_at) VALUES
          ('${PREV}', now() - interval '1 day'), ('${STALE}', now() - interval '1 minute'),
          ('${NEWER}', now() - interval '1 hour'), ('${ROLLED_BACK}', now() - interval '3 days')
        ON CONFLICT (scanner_version) DO NOTHING" >/dev/null || true

begin_test "SETUP: first fail_closed pulls grade both jars against the live DB build (dtf-clean 200, log4j-core 403)"
pull "$FC" "$CLEAN"; c_st="$ST"
pull "$FC" "$LOG4J"; l_st="$ST"
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

# ---------------------------------------------------------------------------
# Phase 1: defaults. The DB update: both verdicts graded by the previous build,
# which did not know the log4j advisory yet.
# ---------------------------------------------------------------------------
age_row "$CL_D" "$PREV"
age_row "$L4_D" "$PREV" clean

begin_test "CONTROL: by default a fail_closed pull after a DB update is still re-scanned before it is answered (the fail_closed grace is opt-in)"
pull "$FC" "$CLEAN"
if [ "$ST" = "200" ] && [ "$(scanned_inline "$CL_D" "$AT")" = "t" ]; then
  pass
else
  fail "fail_closed must keep re-scanning by default" \
    "status=${ST} row='$(row_of "$CL_D")' scanned-inline=$(scanned_inline "$CL_D" "$AT")"
fi
age_row "$CL_D" "$PREV"

begin_test "FIX #6300: after a DB update, a fail_open pull of a cached jar is decided by the previous build's verdict (X-AK-Scan: clean, not pending) with no scan on the request path"
pull "$FO" "$CLEAN"; c_st="$ST"; c_scan="$SCAN"; c_at="$AT"
pull "$FO" "$LOG4J"; l_st="$ST"; l_scan="$SCAN"; l_at="$AT"
if [ "$c_st" = "200" ] && [ "$c_scan" = "clean" ] && [ "$l_st" = "200" ] && [ "$l_scan" = "clean" ] \
   && [ "$(scanned_inline "$CL_D" "$c_at")" = "f" ] && [ "$(scanned_inline "$L4_D" "$l_at")" = "f" ]; then
  pass
else
  fail "every cached package is treated as unscanned after a DB update (served pending, a scan per pull)" \
    "dtf-clean=${c_st} '${c_scan}' log4j=${l_st} '${l_scan}' rows clean='$(row_of "$CL_D")' log4j='$(row_of "$L4_D")'"
fi

begin_test "CONTROL: fail_open: both jars are re-graded against the live build, and log4j-core is then blocked (403)"
wait_regraded || true
pull "$FO" "$LOG4J"; l_st="$ST"
if [ "$(row_of "$CL_D")" = "clean|${LIVE}" ] && [ "$(row_of "$L4_D")" = "vulnerable|${LIVE}" ] && [ "$l_st" = "403" ]; then
  pass
else
  fail "not re-graded within 90 s, or the re-graded verdict is not enforced" \
    "rows clean='$(row_of "$CL_D")' log4j='$(row_of "$L4_D")' (want ${LIVE}); log4j=${l_st}"
fi

begin_test "FIX #6300: a fail_closed pull of a verdict graded by a NEWER build another replica recorded an hour ago is reused, not re-scanned with the older build"
age_row "$CL_D" "$NEWER"
pull "$FC" "$CLEAN"
if [ "$ST" = "200" ] && [ "$(row_of "$CL_D")" = "clean|${NEWER}" ]; then
  pass
else
  fail "the older replica re-scanned a newer build's verdict (the rolling-upgrade ping-pong)" \
    "status=${ST} row='$(row_of "$CL_D")'"
fi

begin_test "CONTROL: a verdict graded by a NEWER build recorded three days ago (rolled back) is re-scanned before the pull is answered"
age_row "$CL_D" "$ROLLED_BACK"
pull "$FC" "$CLEAN"
if [ "$ST" = "200" ] && [ "$(scanned_inline "$CL_D" "$AT")" = "t" ]; then
  pass
else
  fail "a rolled-back newer build must not keep standing for the TTL" \
    "status=${ST} row='$(row_of "$CL_D")' scanned-inline=$(scanned_inline "$CL_D" "$AT")"
fi

# ---------------------------------------------------------------------------
# Phase 2: the operator opts fail_closed in. The same DB update again.
# ---------------------------------------------------------------------------
begin_test "SETUP: recreate the backend with PROXY_SCAN_DB_GRACE_HOURS_FAIL_CLOSED=6"
if recreate_backend_opted_in; then pass; else infra_fail "backend recreate failed"; end_suite; fi
age_row "$CL_D" "$PREV"
age_row "$L4_D" "$PREV" clean

begin_test "FIX #6300: with the fail_closed opt-in, a pull of a cached clean jar after a DB update is answered without a scan on the request path"
pull "$FC" "$CLEAN"; c_at="$AT"; c_st="$ST"; c_scan="$SCAN"
if [ "$c_st" = "200" ] && [ "$c_scan" = "clean" ] && [ "$(scanned_inline "$CL_D" "$c_at")" = "f" ]; then
  pass
else
  fail "the pull re-scanned the jar before answering" \
    "status=${c_st} X-AK-Scan='${c_scan}' row='$(row_of "$CL_D")' scanned-inline=$(scanned_inline "$CL_D" "$c_at")"
fi

begin_test "FIX #6300: with the opt-in, the cached log4j-core jar graded clean by the previous build is not blocked or scanned synchronously either"
pull "$FC" "$LOG4J"; l_at="$AT"; l_st="$ST"
if [ "$l_st" = "200" ] && [ "$(scanned_inline "$L4_D" "$l_at")" = "f" ]; then
  pass
else
  fail "the pull waited for an inline re-scan" \
    "status=${l_st} X-AK-Scan='${SCAN}' row='$(row_of "$L4_D")' scanned-inline=$(scanned_inline "$L4_D" "$l_at")"
fi

begin_test "CONTROL: both jars are re-graded against the live build, and log4j-core is blocked once re-graded (403)"
wait_regraded || true
pull "$FC" "$LOG4J"; l_st="$ST"
pull "$FC" "$CLEAN"; c_st="$ST"
if [ "$(row_of "$CL_D")" = "clean|${LIVE}" ] && [ "$(row_of "$L4_D")" = "vulnerable|${LIVE}" ] \
   && [ "$l_st" = "403" ] && [ "$c_st" = "200" ]; then
  pass
else
  fail "not re-graded within 90 s, or the re-graded verdicts are not enforced" \
    "rows clean='$(row_of "$CL_D")' log4j='$(row_of "$L4_D")' (want ${LIVE}); log4j=${l_st} dtf-clean=${c_st}"
fi

begin_test "CONTROL: a verdict from another scanner binary is re-scanned before the pull is answered"
age_row "$CL_D" "grype-0.0.1-dtf+db-2000-01-02"
pull "$FC" "$CLEAN"
if [ "$ST" = "200" ] && [ "$(scanned_inline "$CL_D" "$AT")" = "t" ]; then
  pass
else
  fail "a binary upgrade must still re-scan on the next pull" \
    "status=${ST} row='$(row_of "$CL_D")' scanned-inline=$(scanned_inline "$CL_D" "$AT")"
fi

begin_test "CONTROL: a verdict from a build older than the previous one, recorded after it, is re-scanned before the pull is answered"
age_row "$L4_D" "$STALE" clean
pull "$FC" "$LOG4J"
if [ "$ST" = "403" ] && [ "$(scanned_inline "$L4_D" "$AT")" = "t" ] && [ "$(row_of "$L4_D")" = "vulnerable|${LIVE}" ]; then
  pass
else
  fail "a verdict more than one build behind must not be reused" \
    "status=${ST} row='$(row_of "$L4_D")' scanned-inline=$(scanned_inline "$L4_D" "$AT")"
fi

end_suite
