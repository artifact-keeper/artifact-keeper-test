#!/usr/bin/env bash
# =============================================================================
# tiers/db-pool-fairness/oracle.sh: an anonymous flood holding the admission
#                                   slots on a busy pool does not get an
#                                   authenticated client shed
#                                   (artifact-keeper#6344)
# =============================================================================
# run.sh has stood up `storage.filesystem limits.db-pool` with
# DATABASE_MAX_CONNECTIONS=12, DATABASE_MIN_CONNECTIONS=12,
# DATABASE_REQUEST_CONCURRENCY=8, DATABASE_REQUEST_ACQUIRE_WAIT_MS=500 and
# RATE_LIMIT_ENABLED=false, and exported BASE_URL, DB_CONTAINER, ADMIN_USER,
# ADMIN_PASS, RUN_ID, RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
#
# THE PRIMITIVE (see the manifest). A psql session of the oracle's own takes
# ACCESS EXCLUSIVE on `repositories`; 12 anonymous downloads are then sent
# one by one, and each admitted one blocks on the lock holding a pooled
# connection, until the pool is busy (2 idle). On main they hold all 8
# admission slots; on the fix anonymous requests may take only 6, so the 2
# reserved slots stay free for a credentialed request. An EXIT trap ends the
# lock session.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${ADMIN_USER:?}"; : "${ADMIN_PASS:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

SUF="${RUN_ID##*-}-$$"
SLOT="${DTF_SLOT:-x}"
REPO="dbfair-generic-${SLOT}-${SUF}"
ART="pkgs/dbfair-1.0.0.tar.bz2"
BYTES="db-pool-fairness-${SUF}"
LOCK_APP="ak-dtf-dbfair-lock-${SUF}"
POOL_MAX="${DATABASE_MAX_CONNECTIONS:-12}"
SLOW_REQUESTS=12
AUTH_PROBES=10
AUTH_FLOOR=9
FLOOD_LOOPS=6

WORK="$(mktemp -d -t dtf-dbfair-XXXXXX)"
LOCK_PID=""
FLOOD_PIDS=()
psql_db() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -Atc "$1" 2>&1; }
end_lock() {
  psql_db "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name = '${LOCK_APP}'" >/dev/null || true
  if [ -n "$LOCK_PID" ]; then wait "$LOCK_PID" 2>/dev/null || true; LOCK_PID=""; fi
}
stop_flood() {
  : > "${WORK}/flood.stop"
  local p
  for p in "${FLOOD_PIDS[@]}"; do wait "$p" 2>/dev/null || true; done
  FLOOD_PIDS=()
}
cleanup() {
  [ -d "$WORK" ] && : > "${WORK}/flood.stop"
  end_lock
  jobs -p | xargs -r kill 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

b64_basic() { printf '%s:%s' "$1" "$2" | base64 | tr -d '\n'; }
# req METHOD URL [CURL ARGS...] -> "<status> <seconds>"; body in $WORK/body.
req() {
  local m="$1" url="$2"; shift 2
  : > "${WORK}/body"; : > "${WORK}/hdr"
  curl -s --max-time 20 --connect-timeout 10 -X "$m" -D "${WORK}/hdr" -o "${WORK}/body" \
    -w '%{http_code} %{time_total}' "$@" "$url" 2>/dev/null || echo "000 20"
}
body() { head -c 300 "${WORK}/body" 2>/dev/null; }

DL_URL="${BASE_URL}/api/v1/repositories/${REPO}/download/${ART}"
ME_URL="${BASE_URL}/api/v1/auth/me"
LIST_URL="${BASE_URL}/api/v1/repositories"

begin_suite "db-pool-fairness"

# =============================================================================
# SETUP
# =============================================================================
begin_test "setup: admin login, public generic repo + artifact, ${POOL_MAX} pooled connections open"
auth_admin
BEARER="Authorization: Bearer ${ADMIN_TOKEN}"
if ! api_post "/api/v1/repositories" \
  "{\"key\":\"${REPO}\",\"name\":\"${REPO}\",\"format\":\"generic\",\"repo_type\":\"local\",\"is_public\":true}" >/dev/null 2>&1; then
  infra_fail "could not create public generic repo ${REPO}"; end_suite
fi
read -r C _ <<<"$(req PUT "${BASE_URL}/api/v1/repositories/${REPO}/artifacts/${ART}" -H "$BEARER" \
  -H 'Content-Type: application/octet-stream' --data-binary "$BYTES")"
case "$C" in 200|201) ;; *) infra_fail "PUT of the fixture artifact returned ${C}" "$(body)"; end_suite ;; esac
# DATABASE_MIN_CONNECTIONS=5: wait until the request pool has opened them
# all (plus the probe pool's one), so "busy" is the pool's steady state.
open=0
for _ in $(seq 1 60); do
  open="$(psql_db "SELECT count(*) FROM pg_stat_activity WHERE datname = 'artifact_registry'
      AND backend_type = 'client backend' AND pid <> pg_backend_pid() AND application_name <> 'psql'")"
  [ "${open:-0}" -ge "$POOL_MAX" ] 2>/dev/null && break
  sleep 0.5
done
if [ "${open:-0}" -ge "$POOL_MAX" ] 2>/dev/null; then echo "  ${open} backend connections open"; pass
else infra_fail "only ${open} backend connections open after 30 s (want ${POOL_MAX})"; end_suite; fi

# =============================================================================
# BEFORE THE WINDOW (CONTROL)
# =============================================================================
begin_test "CONTROL before: anonymous download 200 + bytes, /api/v1/auth/me with the admin token 200"
read -r C1 _ <<<"$(req GET "$DL_URL")"; B1="$(cat "${WORK}/body")"
read -r C2 _ <<<"$(req GET "$ME_URL" -H "$BEARER")"
if [ "$C1" = "200" ] && [ "$B1" = "$BYTES" ] && [ "$C2" = "200" ]; then pass
else fail "download ${C1}, /auth/me ${C2} (want 200 / 200)" "$(body)"; fi

# =============================================================================
# THE WINDOW
# =============================================================================
begin_test "setup: lock repositories, up to ${SLOW_REQUESTS} slow anonymous downloads block on it"
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
lock_waiters() {
  psql_db "SELECT count(*) FROM pg_stat_activity WHERE datname = 'artifact_registry'
      AND application_name NOT IN ('${LOCK_APP}', 'psql') AND wait_event_type = 'Lock'"
}
for i in $(seq 1 "$SLOW_REQUESTS"); do
  curl -s --max-time 150 -o /dev/null -w '%{http_code}\n' "$DL_URL" >"${WORK}/slow.${i}" 2>/dev/null &
  # One at a time: an admitted one reaches the lock in milliseconds, a shed
  # one is answered after the 500 ms wait.
  sleep 0.7
done
sleep 1
waiting="$(lock_waiters)"
if [ "${waiting:-0}" -ge 8 ] 2>/dev/null; then
  echo "  ${waiting} backend sessions waiting on the lock"
  pass
else
  infra_fail "only ${waiting} sessions waiting on the lock (want at least 8)" \
    "$(psql_db "SELECT application_name, state, wait_event_type, left(query, 80) FROM pg_stat_activity WHERE datname = 'artifact_registry'")"
  end_suite
fi

flood_loop() { # n: anonymous downloads until told to stop; one status per line
  local n="$1"
  while [ ! -e "${WORK}/flood.stop" ]; do
    curl -s --max-time 10 -o /dev/null -w '%{http_code}\n' "$DL_URL" >>"${WORK}/flood.${n}" 2>/dev/null || echo 000 >>"${WORK}/flood.${n}"
  done
}
for i in $(seq 1 "$FLOOD_LOOPS"); do flood_loop "$i" & FLOOD_PIDS+=("$!"); done
sleep 1

begin_test "FIX #6344: with an anonymous flood holding the slots, ${AUTH_FLOOR}+ of ${AUTH_PROBES} authenticated /api/v1/auth/me answer 200"
ok=0; codes=""
for _ in $(seq 1 "$AUTH_PROBES"); do
  read -r C T <<<"$(req GET "$ME_URL" -H "$BEARER")"
  codes="${codes} ${C}(${T}s)"
  [ "$C" = "200" ] && ok=$((ok + 1))
done
echo "  authenticated:${codes}"
if [ "$ok" -ge "$AUTH_FLOOR" ]; then pass
else fail "${ok}/${AUTH_PROBES} authenticated requests answered 200 while the anonymous flood held the admission slots (want >= ${AUTH_FLOOR})" "last body: $(body)"; fi

begin_test "CONTROL window: a wrong Basic password is never 2xx"
read -r C T <<<"$(req GET "$LIST_URL" -H "Authorization: Basic $(b64_basic "$ADMIN_USER" "not-the-password-${SUF}")")"
case "$C" in 2*) fail "wrong Basic password answered ${C} with the pool saturated" ;; *) echo "  HTTP ${C}"; pass ;; esac

stop_flood
begin_test "CONTROL window: the anonymous flood is shed, never answered 2xx while the lock is held"
FLOOD="$(cat "${WORK}"/flood.* 2>/dev/null | sort | uniq -c | tr -s ' ' | tr '\n' ',')"
f2xx="$(cat "${WORK}"/flood.* 2>/dev/null | grep -c '^2' || true)"
f503="$(cat "${WORK}"/flood.* 2>/dev/null | grep -c '^503$' || true)"
if [ "${f2xx:-0}" = "0" ] && [ "${f503:-0}" -ge 1 ]; then echo "  flood statuses:${FLOOD}"; pass
else fail "flood statuses:${FLOOD} (want only sheds: no 2xx, at least one 503)"; fi

# =============================================================================
# AFTER THE WINDOW
# =============================================================================
begin_test "CONTROL after: end the lock; the slow requests complete (200 or a 503 shed, nothing else)"
end_lock
wait_deadline=$(( $(date +%s) + 60 ))
while [ -n "$(jobs -pr)" ] && [ "$(date +%s)" -lt "$wait_deadline" ]; do sleep 0.5; done
codes="$(cat "${WORK}"/slow.* 2>/dev/null | tr '\n' ' ')"
ok200="$(cat "${WORK}"/slow.* 2>/dev/null | grep -c '^200$' || true)"
bad="$(cat "${WORK}"/slow.* 2>/dev/null | grep -vcE '^(200|503)$' || true)"
if [ "${ok200:-0}" -ge 1 ] && [ "${bad:-0}" = "0" ]; then echo "  slow request codes: ${codes}"; pass
else fail "slow requests answered: ${codes:-<none>} (want at least one 200, only 200 or 503)"; fi

begin_test "CONTROL after: download and /api/v1/auth/me succeed again"
sleep 1
read -r C1 _ <<<"$(req GET "$DL_URL")"; B1="$(cat "${WORK}/body")"
read -r C2 _ <<<"$(req GET "$ME_URL" -H "$BEARER")"
if [ "$C1" = "200" ] && [ "$B1" = "$BYTES" ] && [ "$C2" = "200" ]; then pass
else fail "after the window: download ${C1}, /auth/me ${C2} (want 200 / 200)" "$(body)"; fi

begin_test "FIX #6344: ak_db_admission_sheds_total: the anonymous flood absorbed the sheds, no credentialed request was shed"
read -r C _ <<<"$(req GET "${BASE_URL}/api/v1/admin/metrics" -H "$BEARER")"
# A missing series sums to 0 (no grep may fail the pipeline: the suite runs
# with errexit and pipefail).
series() { { grep -E "^ak_db_admission_sheds_total\{" "${WORK}/body" || true; } | { grep -F "class=\"$1\"" || true; } | awk '{ s += $NF } END { print s + 0 }'; }
ANON="$(series anonymous)"; CRED="$(series credentialed)"
PRESENT="$(grep -c '^ak_db_admission_sheds_total{' "${WORK}/body" || true)"
if [ "$C" = "200" ] && [ "${PRESENT:-0}" -ge 1 ] && awk -v a="$ANON" -v c="$CRED" 'BEGIN { exit !(a >= 1 && c == 0) }'; then
  echo "  anonymous sheds ${ANON}, credentialed sheds ${CRED}"
  pass
else
  fail "metrics HTTP ${C}: anonymous sheds '${ANON}', credentialed sheds '${CRED}', series present ${PRESENT} (want anonymous >= 1, credentialed 0)" \
    "$(grep -E '^ak_db_(admission|requests)_shed' "${WORK}/body" | head -10)"
fi

end_suite
