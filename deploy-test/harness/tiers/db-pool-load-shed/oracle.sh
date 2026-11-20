#!/usr/bin/env bash
# =============================================================================
# tiers/db-pool-load-shed/oracle.sh: with every pooled database connection
#                                    held, an overflow request is answered
#                                    503 + Retry-After at once and /readyz
#                                    stays ready (artifact-keeper#4182)
# =============================================================================
# run.sh has stood up `storage.filesystem limits.db-pool` with
# DATABASE_MAX_CONNECTIONS=4, DATABASE_MIN_CONNECTIONS=0 and
# RATE_LIMIT_ENABLED=false, and exported BASE_URL, DB_CONTAINER, ADMIN_USER,
# ADMIN_PASS, RUN_ID, RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
#
# THE PRIMITIVE. A psql session of the oracle's own (in this slot's Postgres
# container, DB_CONTAINER) takes ACCESS EXCLUSIVE on `repositories` and
# sleeps; admin GET /api/v1/repositories requests then each take a pooled
# connection and block on the lock, so the pool (4 connections) is fully held
# until the oracle terminates the session. An EXIT trap terminates it if the
# oracle dies inside the window.
#
# Gates (see the manifest for the full prose):
#   (CONTROL) before / during / after the window, true on BOTH images.
#   (FIX #4182) the overflow request: 503 POOL_EXHAUSTED + Retry-After: 1 in
#             under 2.5 s (main: after the 5 s acquire timeout).
#   (FIX #4182) /readyz during the window: 200 (main: 503 not_ready).
#   (FIX #4182) ak_db_requests_shed_total >= 1 after the window (main: absent).
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${ADMIN_USER:?}"; : "${ADMIN_PASS:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

SUF="${RUN_ID##*-}-$$"
SLOT="${DTF_SLOT:-x}"
REPO="dbshed-generic-${SLOT}-${SUF}"
ART="pkgs/dbshed-1.0.0.tar.bz2"
BYTES="db-pool-load-shed-${SUF}"
LOCK_APP="ak-dtf-dbshed-lock-${SUF}"
POOL_MAX="${DATABASE_MAX_CONNECTIONS:-4}"
SLOW_REQUESTS=6
# The fix sheds after DATABASE_REQUEST_ACQUIRE_WAIT_MS (500 ms); main answers
# only after DATABASE_ACQUIRE_TIMEOUT_SECS (5 s). 2.5 s splits them with room
# for a loaded runner on either side.
FAST_SHED_SECS="2.5"

WORK="$(mktemp -d -t dtf-dbshed-XXXXXX)"
LOCK_PID=""
psql_db() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -Atc "$1" 2>&1; }
end_lock() {
  psql_db "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name = '${LOCK_APP}'" >/dev/null || true
  if [ -n "$LOCK_PID" ]; then wait "$LOCK_PID" 2>/dev/null || true; LOCK_PID=""; fi
}
cleanup() {
  end_lock
  # Reap any slow request still running.
  jobs -p | xargs -r kill 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

# --- curl helpers -----------------------------------------------------------
b64_basic() { printf '%s:%s' "$1" "$2" | base64 | tr -d '\n'; }
# req METHOD URL [CURL ARGS...] -> prints "<status> <seconds>"; the body lands
# in $WORK/body and the response headers in $WORK/hdr.
req() {
  local m="$1" url="$2"; shift 2
  : > "${WORK}/body"; : > "${WORK}/hdr"
  curl -s --max-time 30 --connect-timeout 10 -X "$m" -D "${WORK}/hdr" -o "${WORK}/body" \
    -w '%{http_code} %{time_total}' "$@" "$url" 2>/dev/null || echo "000 30"
}
body() { head -c 300 "${WORK}/body" 2>/dev/null; }
retry_after() { grep -i '^retry-after:' "${WORK}/hdr" 2>/dev/null | head -1 | cut -d: -f2 | tr -d '[:space:]'; }
evidence() { printf 'HTTP %s in %ss  Retry-After=%s\nbody: %s\n' "$1" "$2" "$(retry_after)" "$(body)"; }
lt() { awk -v a="$1" -v b="$2" 'BEGIN { exit !(a < b) }'; }

DL_URL="${BASE_URL}/api/v1/repositories/${REPO}/download/${ART}"
LIST_URL="${BASE_URL}/api/v1/repositories"

begin_suite "db-pool-load-shed"

# =============================================================================
# SETUP (infra_fail on any failure: nothing about the candidate is learned yet)
# =============================================================================
begin_test "setup: admin login, public generic repo + artifact"
auth_admin
BEARER="Authorization: Bearer ${ADMIN_TOKEN}"
if ! api_post "/api/v1/repositories" \
  "{\"key\":\"${REPO}\",\"name\":\"${REPO}\",\"format\":\"generic\",\"repo_type\":\"local\",\"is_public\":true}" >/dev/null 2>&1; then
  infra_fail "could not create public generic repo ${REPO}"; end_suite
fi
read -r C _ <<<"$(req PUT "${BASE_URL}/api/v1/repositories/${REPO}/artifacts/${ART}" -H "$BEARER" \
  -H 'Content-Type: application/octet-stream' --data-binary "$BYTES")"
case "$C" in 200|201) pass ;; *) infra_fail "PUT of the fixture artifact returned ${C}" "$(body)"; end_suite ;; esac

# =============================================================================
# BEFORE THE WINDOW (CONTROL, both images)
# =============================================================================
begin_test "CONTROL before: /readyz -> 200"
read -r C T <<<"$(req GET "${BASE_URL}/readyz")"
if [ "$C" = "200" ]; then pass; else fail "/readyz returned ${C}" "$(evidence "$C" "$T")"; fi

begin_test "CONTROL before: anonymous download of the public artifact -> 200 + bytes"
read -r C T <<<"$(req GET "$DL_URL")"
if [ "$C" = "200" ] && [ "$(cat "${WORK}/body")" = "$BYTES" ]; then pass; else fail "download returned ${C}" "$(evidence "$C" "$T")"; fi

begin_test "CONTROL before: admin repository list -> 200"
read -r C T <<<"$(req GET "$LIST_URL" -H "$BEARER")"
if [ "$C" = "200" ]; then pass; else fail "repository list returned ${C}" "$(evidence "$C" "$T")"; fi

# =============================================================================
# THE WINDOW: every pooled connection held
# =============================================================================
begin_test "setup: lock repositories, ${SLOW_REQUESTS} slow requests hold the ${POOL_MAX}-connection pool"
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
for i in $(seq 1 "$SLOW_REQUESTS"); do
  curl -s --max-time 150 -o /dev/null -w '%{http_code}\n' -H "$BEARER" "$LIST_URL" >"${WORK}/slow.${i}" 2>/dev/null &
  sleep 0.3
done
# Saturated once POOL_MAX pooled connections are busy: the backend sessions
# waiting on the lock, plus the pooled connection the cache-invalidation
# listener keeps checked out (an idle `LISTEN` session). Background work that
# reads repositories only adds to the waiters.
waiting=0
for _ in $(seq 1 75); do
  waiting="$(psql_db "SELECT count(*) FROM pg_stat_activity
      WHERE datname = 'artifact_registry' AND application_name NOT IN ('${LOCK_APP}', 'psql')
        AND (wait_event_type = 'Lock' OR query LIKE 'LISTEN %')")"
  [ "${waiting:-0}" -ge "$POOL_MAX" ] 2>/dev/null && break
  sleep 0.2
done
if [ "${waiting:-0}" -ge "$POOL_MAX" ] 2>/dev/null; then
  echo "  ${waiting} pooled connections busy (lock waiters + listener)"
  pass
else
  infra_fail "only ${waiting} pooled connections busy after 15 s (want ${POOL_MAX})" \
    "$(psql_db "SELECT application_name, state, wait_event_type, left(query, 80) FROM pg_stat_activity WHERE datname = 'artifact_registry'")"
  end_suite
fi

begin_test "FIX #4182: overflow request (anonymous download) -> 503 POOL_EXHAUSTED + Retry-After: 1 in < ${FAST_SHED_SECS}s"
read -r C T <<<"$(req GET "$DL_URL")"
EV="$(evidence "$C" "$T")"
if [ "$C" != "503" ]; then
  fail "overflow download returned ${C}, expected 503" "$EV"
elif [ "$(retry_after)" != "1" ]; then
  fail "503 without Retry-After: 1" "$EV"
elif [ "$(jq -r '.code // empty' "${WORK}/body" 2>/dev/null)" != "POOL_EXHAUSTED" ]; then
  fail "503 body is not {code: POOL_EXHAUSTED}" "$EV"
elif ! lt "$T" "$FAST_SHED_SECS"; then
  fail "503 took ${T}s: the request queued to the pool's acquire timeout instead of being shed" "$EV"
else
  echo "  503 POOL_EXHAUSTED in ${T}s"
  pass
fi

begin_test "FIX #4182: /readyz while the request pool is saturated -> 200 ready"
read -r C T <<<"$(req GET "${BASE_URL}/readyz")"
if [ "$C" = "200" ] && [ "$(jq -r '.checks.database.status // empty' "${WORK}/body" 2>/dev/null)" = "healthy" ]; then
  echo "  ready in ${T}s"
  pass
else
  fail "/readyz returned ${C}: a saturated request pool made a busy replica report not-ready" "$(evidence "$C" "$T")"
fi

begin_test "CONTROL window: an anonymous admin request is never 2xx"
read -r C T <<<"$(req GET "${BASE_URL}/api/v1/admin/metrics")"
case "$C" in 2*) fail "anonymous /api/v1/admin/metrics answered ${C} with the pool saturated" "$(evidence "$C" "$T")" ;; *) echo "  HTTP ${C}"; pass ;; esac

begin_test "CONTROL window: a wrong Basic password is never 2xx"
read -r C T <<<"$(req GET "$LIST_URL" -H "Authorization: Basic $(b64_basic "$ADMIN_USER" "not-the-password-${SUF}")")"
case "$C" in 2*) fail "wrong Basic password answered ${C} with the pool saturated" "$(evidence "$C" "$T")" ;; *) echo "  HTTP ${C}"; pass ;; esac

# =============================================================================
# AFTER THE WINDOW (CONTROL, both images, plus the shed counter)
# =============================================================================
begin_test "CONTROL after: end the lock; the slow requests complete (200 or a 503 shed, nothing else)"
end_lock
wait_deadline=$(( $(date +%s) + 60 ))
while [ -n "$(jobs -pr)" ] && [ "$(date +%s)" -lt "$wait_deadline" ]; do sleep 0.5; done
codes="$(cat "${WORK}"/slow.* 2>/dev/null | tr '\n' ' ')"
ok200="$(cat "${WORK}"/slow.* 2>/dev/null | grep -c '^200$' || true)"
bad="$(cat "${WORK}"/slow.* 2>/dev/null | grep -vcE '^(200|503)$' || true)"
if [ "${ok200:-0}" -ge 1 ] && [ "${bad:-0}" = "0" ]; then
  echo "  slow request codes: ${codes}"
  pass
else
  fail "slow requests answered: ${codes:-<none>} (want at least one 200, only 200 or 503)"
fi

begin_test "CONTROL after: download, repository list and /readyz succeed again"
read -r C1 _ <<<"$(req GET "$DL_URL")"; B1="$(cat "${WORK}/body")"
read -r C2 _ <<<"$(req GET "$LIST_URL" -H "$BEARER")"
read -r C3 _ <<<"$(req GET "${BASE_URL}/readyz")"
if [ "$C1" = "200" ] && [ "$B1" = "$BYTES" ] && [ "$C2" = "200" ] && [ "$C3" = "200" ]; then pass
else fail "after the window: download ${C1}, list ${C2}, /readyz ${C3} (want 200 / 200 / 200)" "$(body)"; fi

begin_test "CONTROL after: 20 parallel anonymous downloads all answer 200"
for i in $(seq 1 20); do
  curl -s --max-time 30 -o /dev/null -w '%{http_code}\n' "$DL_URL" >"${WORK}/par.${i}" 2>/dev/null &
done
wait
par_ok="$(cat "${WORK}"/par.* | grep -c '^200$' || true)"
if [ "$par_ok" = "20" ]; then pass; else fail "${par_ok}/20 parallel downloads answered 200" "$(cat "${WORK}"/par.* | sort | uniq -c)"; fi

begin_test "FIX #4182: ak_db_requests_shed_total counts the shed requests"
read -r C T <<<"$(req GET "${BASE_URL}/api/v1/admin/metrics" -H "$BEARER")"
SHED="$(awk '/^ak_db_requests_shed_total[ {]/ { print $NF; exit }' "${WORK}/body")"
if [ "$C" = "200" ] && [ -n "$SHED" ] && awk -v v="$SHED" 'BEGIN { exit !(v >= 1) }'; then
  echo "  ak_db_requests_shed_total ${SHED}"
  pass
else
  fail "metrics HTTP ${C}, ak_db_requests_shed_total='${SHED}' (want >= 1)" "$(grep -E '^ak_db_' "${WORK}/body" | head -10)"
fi

end_suite
