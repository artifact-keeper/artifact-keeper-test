#!/usr/bin/env bash
# =============================================================================
# tiers/db-read-retry-failover/oracle.sh: a read whose database connection is
# terminated mid-statement (a switchover) is replayed once and succeeds; a
# write is not replayed (artifact-keeper#5941)
# =============================================================================
# run.sh has stood up the `filesystem` profile-set with RATE_LIMIT_ENABLED=false
# and exported BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID,
# RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
#
# THE PRIMITIVE. A psql session of the oracle's own takes ACCESS EXCLUSIVE on
# `repositories`; three reads and one write block on it in the middle of a
# statement; the oracle pg_terminate_backend()s exactly those waiting backend
# sessions (57P01, what a switchover delivers), then ends the lock. A second
# window does the same to a GET that writes: a user's first HTTP Basic login
# records last_login_at, so the oracle row-locks that user and terminates the
# GET's blocked UPDATE. See the manifest for the gates.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${ADMIN_USER:?}"; : "${ADMIN_PASS:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

SUF="${RUN_ID##*-}-$$"
SLOT="${DTF_SLOT:-x}"
REPO="dbretry-generic-${SLOT}-${SUF}"
WRITE_REPO="dbretry-write-${SLOT}-${SUF}"
LOCK_APP="ak-dtf-dbretry-lock-${SUF}"
GW_USER="dbretry-gw-${SLOT}-${SUF}"
PROBE_USER="dbretry-probe-${SLOT}-${SUF}"
GW_PASS="Dbretry-${SUF}-Aa1!"
READS=3
WRITES=1

WORK="$(mktemp -d -t dtf-dbretry-XXXXXX)"
LOCK_PID=""
psql_db() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -Atc "$1" 2>&1; }
end_lock() {
  psql_db "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name = '${LOCK_APP}'" >/dev/null || true
  if [ -n "$LOCK_PID" ]; then wait "$LOCK_PID" 2>/dev/null || true; LOCK_PID=""; fi
}
cleanup() {
  end_lock
  jobs -p | xargs -r kill 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

req() {
  local m="$1" url="$2"; shift 2
  : > "${WORK}/body"; : > "${WORK}/hdr"
  curl -s --max-time 30 --connect-timeout 10 -X "$m" -D "${WORK}/hdr" -o "${WORK}/body" \
    -w '%{http_code}' "$@" "$url" 2>/dev/null; true
}
body() { head -c 300 "${WORK}/body" 2>/dev/null; }
metric() { # NAME LABELS -> value or empty, from the last metrics fetch
  awk -v want="$1{$2}" '$1 == want { print $2; exit }' "${WORK}/metrics" 2>/dev/null
}
fetch_metrics() {
  curl -s --max-time 30 -H "$BEARER" -o "${WORK}/metrics" -w '%{http_code}' \
    "${BASE_URL}/api/v1/admin/metrics" 2>/dev/null; true
}
# A background request: status in $WORK/<name>.code, body in $WORK/<name>.body.
bg() {
  local name="$1"; shift
  ( curl -s --max-time 120 -o "${WORK}/${name}.body" -w '%{http_code}' "$@" 2>/dev/null; true ) > "${WORK}/${name}.code" &
}
# The backend sessions THIS tier's requests are blocked in: waiting on the
# oracle's own lock session (pg_blocking_pids), on a statement that started
# after the requests were sent (LAUNCH_TS), that was not already waiting
# before they were sent (PRE_PIDS: a background worker that happened to touch
# repositories), and running one of the tier's own statements on
# repositories. Nothing else is ever terminated.
LAUNCH_TS=""
PRE_PIDS="0"
lock_pid() { psql_db "SELECT pid FROM pg_stat_activity WHERE application_name = '${LOCK_APP}' LIMIT 1"; }
blocked_by_lock() {
  psql_db "SELECT pid FROM pg_stat_activity
           WHERE datname = 'artifact_registry' AND wait_event_type = 'Lock'
             AND $(lock_pid) = ANY(pg_blocking_pids(pid))"
}
# WAIT_RE: the statements the tier's own requests block in.
WAIT_RE='(from|into|update)[[:space:]]+"?repositories"?'
our_waiters() {
  psql_db "SELECT pid FROM pg_stat_activity
           WHERE datname = 'artifact_registry' AND wait_event_type = 'Lock'
             AND $(lock_pid) = ANY(pg_blocking_pids(pid))
             AND pid NOT IN (${PRE_PIDS})
             AND query_start >= '${LAUNCH_TS}'::timestamptz
             AND query ~* '${WAIT_RE}'"
}

LIST_URL="${BASE_URL}/api/v1/repositories?per_page=200"

begin_suite "db-read-retry-failover"

begin_test "setup: admin login, public generic repository"
auth_admin
BEARER="Authorization: Bearer ${ADMIN_TOKEN}"
if ! api_post "/api/v1/repositories" \
  "{\"key\":\"${REPO}\",\"name\":\"${REPO}\",\"format\":\"generic\",\"repo_type\":\"local\",\"is_public\":true}" >/dev/null 2>&1; then
  infra_fail "could not create public generic repo ${REPO}"; end_suite
fi
pass

begin_test "FIX #5941: the backend proved write detection at startup (read retry on)"
BACKEND_CONTAINER="${DB_CONTAINER%-db}-backend"
# Read the log into a variable first: under pipefail, `docker logs | grep -q`
# fails when grep exits at the match and docker logs takes SIGPIPE.
BACKEND_LOG="$(docker logs "$BACKEND_CONTAINER" 2>&1)"
if grep -qF "database read retry on: write detection verified" <<<"$BACKEND_LOG"; then pass
else fail "no 'database read retry on: write detection verified' line in the backend log" \
  "$(grep -iE 'read retry|write detection' <<<"$BACKEND_LOG" | tail -5)"; fi

begin_test "CONTROL before: /readyz 200, admin and anonymous repository lists 200"
C1="$(req GET "${BASE_URL}/readyz")"
C2="$(req GET "$LIST_URL" -H "$BEARER")"
C3="$(req GET "$LIST_URL")"
if [ "$C1" = "200" ] && [ "$C2" = "200" ] && [ "$C3" = "200" ]; then pass
else fail "/readyz ${C1}, admin list ${C2}, anonymous list ${C3} (want 200 / 200 / 200)" "$(body)"; fi

begin_test "setup: lock repositories; ${READS} reads and ${WRITES} write block on it mid-statement"
docker exec -e PGAPPNAME="$LOCK_APP" "$DB_CONTAINER" psql -U registry -d artifact_registry \
  -c "BEGIN" -c "LOCK TABLE repositories IN ACCESS EXCLUSIVE MODE" -c "SELECT pg_sleep(120)" \
  >"${WORK}/lock.log" 2>&1 &
LOCK_PID=$!
locked=0
for _ in $(seq 1 50); do
  if [ "$(psql_db "SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a ON a.pid = l.pid
        WHERE a.application_name = '${LOCK_APP}' AND l.relation = 'repositories'::regclass
          AND l.mode = 'AccessExclusiveLock' AND l.granted")" = "1" ]; then locked=1; break; fi
  sleep 0.2
done
if [ "$locked" != "1" ]; then infra_fail "the lock session never held repositories" "$(cat "${WORK}/lock.log")"; end_suite; fi
PRE_PIDS="$(blocked_by_lock | tr '\n' ',' | sed 's/,$//')"; PRE_PIDS="${PRE_PIDS:-0}"
LAUNCH_TS="$(psql_db "SELECT clock_timestamp()")"
bg read_get -H "$BEARER" "$LIST_URL"
bg read_head -I -H "$BEARER" "$LIST_URL"
bg read_anon "$LIST_URL"
bg write_create -X POST -H "$BEARER" -H 'Content-Type: application/json' \
  -d "{\"key\":\"${WRITE_REPO}\",\"name\":\"${WRITE_REPO}\",\"format\":\"generic\",\"repo_type\":\"local\",\"is_public\":false}" \
  "${BASE_URL}/api/v1/repositories"
want=$(( READS + WRITES ))
waiting=0
for _ in $(seq 1 75); do
  waiting="$(our_waiters | grep -c . || true)"
  [ "${waiting:-0}" -ge "$want" ] 2>/dev/null && break
  sleep 0.2
done
# Let anything else that is about to block settle, then require EXACTLY the
# tier's own sessions: a surplus means a session the tier cannot attribute,
# and the tier refuses to terminate it.
sleep 0.5
waiting="$(our_waiters | grep -c . || true)"
if [ "${waiting:-0}" = "$want" ] 2>/dev/null; then
  echo "  ${waiting} backend sessions blocked mid-statement on the lock"
  pass
else
  infra_fail "${waiting} of this tier's sessions blocked on the lock after 15 s (want exactly ${want}); nothing terminated" \
    "$(psql_db "SELECT application_name, state, wait_event_type, left(query, 80) FROM pg_stat_activity WHERE datname = 'artifact_registry'")"
  end_suite
fi

begin_test "setup: terminate those sessions (57P01, as a switchover does), then end the lock"
PIDS="$(our_waiters | tr '\n' ',' | sed 's/,$//')"
psql_db "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE pid IN (${PIDS})" >/dev/null
for _ in $(seq 1 25); do
  [ "$(psql_db "SELECT count(*) FROM pg_stat_activity WHERE pid IN (${PIDS})")" = "0" ] && break
  sleep 0.1
done
gone="$(psql_db "SELECT count(*) FROM pg_stat_activity WHERE pid IN (${PIDS})")"
end_lock
deadline=$(( $(date +%s) + 60 ))
while [ -n "$(jobs -pr)" ] && [ "$(date +%s)" -lt "$deadline" ]; do sleep 0.2; done
if [ "$gone" = "0" ]; then echo "  terminated sessions: ${PIDS}"; pass
else infra_fail "${gone} of the terminated sessions (${PIDS}) were still present after 2.5 s"; end_suite; fi

code_of() { cat "${WORK}/$1.code" 2>/dev/null; }
read_ev() { printf 'HTTP %s\nbody: %s\n' "$(code_of "$1")" "$(head -c 300 "${WORK}/$1.body" 2>/dev/null)"; }

begin_test "FIX #5941: admin GET repository list whose connection was terminated -> 200 naming the fixture repo"
C="$(code_of read_get)"
if [ "$C" = "200" ] && jq -e --arg k "$REPO" '[.items[]?.key] | index($k) != null' "${WORK}/read_get.body" >/dev/null 2>&1; then pass
else fail "the read answered ${C}; a read that lost its connection must be replayed (main: 503 DATABASE_UNAVAILABLE)" "$(read_ev read_get)"; fi

begin_test "FIX #5941: admin HEAD repository list whose connection was terminated -> 200"
C="$(code_of read_head)"
if [ "$C" = "200" ]; then pass
else fail "the HEAD answered ${C}; a read that lost its connection must be replayed" "$(read_ev read_head)"; fi

begin_test "FIX #5941: anonymous repository list whose connection was terminated -> 200"
C="$(code_of read_anon)"
if [ "$C" = "200" ] && jq -e '.items | type == "array"' "${WORK}/read_anon.body" >/dev/null 2>&1; then pass
else fail "the anonymous read answered ${C}; a read that lost its connection must be replayed" "$(read_ev read_anon)"; fi

begin_test "CONTROL (writes are not replayed): the terminated create answers 5xx and created nothing"
C="$(code_of write_create)"
G="$(req GET "${BASE_URL}/api/v1/repositories/${WRITE_REPO}" -H "$BEARER")"
case "$C" in
  5??) if [ "$G" = "404" ]; then echo "  write ${C}, repository ${WRITE_REPO}: ${G}"; pass
       else fail "the write answered ${C} but GET of ${WRITE_REPO} answered ${G} (want 404)" "$(body)"; fi ;;
  *) fail "the terminated write answered ${C}, want a 5xx (a write must fail fast, never be replayed)" "$(read_ev write_create)" ;;
esac

begin_test "FIX #5941: ak_db_read_retries_total counts the replays (recovered >= ${READS}, none failed)"
MC="$(fetch_metrics)"
REC="$(metric ak_db_read_retries_total 'outcome="recovered"')"
FAILED="$(metric ak_db_read_retries_total 'outcome="failed"')"
if [ "$MC" = "200" ] && [ -n "$REC" ] && awk -v v="$REC" -v n="$READS" 'BEGIN { exit !(v >= n) }' \
   && { [ -z "$FAILED" ] || [ "$FAILED" = "0" ]; }; then
  echo "  recovered=${REC} failed=${FAILED:-0}"
  pass
else
  fail "metrics HTTP ${MC}: recovered='${REC}' failed='${FAILED}' (want recovered >= ${READS}, failed 0)" \
    "$(grep -E '^ak_db_' "${WORK}/metrics" 2>/dev/null | head -10)"
fi

# --- Window 2: a GET that writes --------------------------------------------
# A user's first HTTP Basic login records last_login_at (an UPDATE of its
# users row), so a GET of the repository list with Basic credentials writes.
# The oracle row-locks the user: the GET's reads pass, its UPDATE blocks and is
# terminated. A replay would log in again and set last_login_at.
begin_test "CONTROL (a GET that writes): a Basic-auth GET of the repository list answers 200 and records the login"
PROBE_ID="$(create_test_user_with_retry "$PROBE_USER" "$GW_PASS" "${PROBE_USER}@example.test")"
GW_ID="$(create_test_user_with_retry "$GW_USER" "$GW_PASS" "${GW_USER}@example.test")"
if [ -z "$PROBE_ID" ] || [ -z "$GW_ID" ]; then infra_fail "could not create the Basic-auth users"; end_suite; fi
C="$(req GET "$LIST_URL" -u "${PROBE_USER}:${GW_PASS}")"
PROBE_LOGIN="$(psql_db "SELECT last_login_at IS NOT NULL FROM users WHERE id = '${PROBE_ID}'")"
GW_LOGIN="$(psql_db "SELECT last_login_at IS NULL FROM users WHERE id = '${GW_ID}'")"
if [ "$C" = "200" ] && [ "$PROBE_LOGIN" = "t" ] && [ "$GW_LOGIN" = "t" ]; then pass
else fail "Basic GET ${C}, probe login recorded '${PROBE_LOGIN}', test user still never logged in '${GW_LOGIN}' (want 200 / t / t)" "$(body)"; fi

begin_test "setup: lock the test user's row; its first Basic-auth GET blocks in the login UPDATE"
docker exec -e PGAPPNAME="$LOCK_APP" "$DB_CONTAINER" psql -U registry -d artifact_registry \
  -c "BEGIN" -c "SELECT id FROM users WHERE id = '${GW_ID}' FOR UPDATE" -c "SELECT pg_sleep(120)" \
  >"${WORK}/lock2.log" 2>&1 &
LOCK_PID=$!
for _ in $(seq 1 50); do
  [ "$(psql_db "SELECT count(*) FROM pg_stat_activity WHERE application_name = '${LOCK_APP}' AND query LIKE '%pg_sleep%'")" = "1" ] && break
  sleep 0.2
done
WAIT_RE='update[[:space:]]+"?users"?'
PRE_PIDS="$(blocked_by_lock | tr '\n' ',' | sed 's/,$//')"; PRE_PIDS="${PRE_PIDS:-0}"
LAUNCH_TS="$(psql_db "SELECT clock_timestamp()")"
bg get_write -u "${GW_USER}:${GW_PASS}" "$LIST_URL"
waiting=0
for _ in $(seq 1 75); do
  waiting="$(our_waiters | grep -c . || true)"
  [ "${waiting:-0}" -ge 1 ] 2>/dev/null && break
  sleep 0.2
done
sleep 0.5
waiting="$(our_waiters | grep -c . || true)"
if [ "${waiting:-0}" = "1" ] 2>/dev/null; then pass
else
  infra_fail "${waiting} sessions blocked in the login UPDATE after 15 s (want exactly 1); nothing terminated" \
    "$(psql_db "SELECT application_name, state, wait_event_type, left(query, 80) FROM pg_stat_activity WHERE datname = 'artifact_registry'")"
  end_suite
fi
PIDS="$(our_waiters | tr '\n' ',' | sed 's/,$//')"
psql_db "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE pid IN (${PIDS})" >/dev/null
for _ in $(seq 1 25); do
  [ "$(psql_db "SELECT count(*) FROM pg_stat_activity WHERE pid IN (${PIDS})")" = "0" ] && break
  sleep 0.1
done
end_lock
deadline=$(( $(date +%s) + 60 ))
while [ -n "$(jobs -pr)" ] && [ "$(date +%s)" -lt "$deadline" ]; do sleep 0.2; done

begin_test "CONTROL (a GET that writes is not replayed): the GET whose login UPDATE was terminated answers 5xx and the login is not recorded"
C="$(code_of get_write)"
GW_LOGIN="$(psql_db "SELECT last_login_at IS NULL FROM users WHERE id = '${GW_ID}'")"
case "$C" in
  5??) if [ "$GW_LOGIN" = "t" ]; then echo "  GET ${C}, last_login_at still NULL"; pass
       else fail "the GET answered ${C} but last_login_at was set: it was replayed" "$(read_ev get_write)"; fi ;;
  *) fail "the GET that wrote answered ${C}, want a 5xx (a GET that wrote must not be replayed; a replay answers 200)" "$(read_ev get_write)" ;;
esac

begin_test "FIX #5941: the GET that wrote is counted as not replayed (skipped_wrote >= 1)"
MC="$(fetch_metrics)"
SKIPPED="$(metric ak_db_read_retries_total 'outcome="skipped_wrote"')"
if [ "$MC" = "200" ] && [ -n "$SKIPPED" ] && awk -v v="$SKIPPED" 'BEGIN { exit !(v >= 1) }'; then
  echo "  skipped_wrote=${SKIPPED}"
  pass
else
  fail "metrics HTTP ${MC}: skipped_wrote='${SKIPPED}' (want >= 1)" \
    "$(grep -E '^ak_db_' "${WORK}/metrics" 2>/dev/null | head -10)"
fi

begin_test "CONTROL after: repository lists answer 200 and /readyz is ready"
C1="$(req GET "$LIST_URL" -H "$BEARER")"
C2="$(req GET "$LIST_URL")"
C3="$(req GET "${BASE_URL}/readyz")"
if [ "$C1" = "200" ] && [ "$C2" = "200" ] && [ "$C3" = "200" ]; then pass
else fail "after the window: admin list ${C1}, anonymous list ${C2}, /readyz ${C3} (want 200 / 200 / 200)" "$(body)"; fi

end_suite
