#!/usr/bin/env bash
# =============================================================================
# tiers/shutdown-drain/oracle.sh: after SIGTERM the backend fails readiness at
# once, keeps serving for SHUTDOWN_DRAIN_SECS, then exits cleanly and releases
# its scheduler leases (artifact-keeper#5921)
# =============================================================================
# run.sh has stood up `filesystem` + `lifecycle.shutdown-drain` with
# SHUTDOWN_DRAIN_SECS=12 and RATE_LIMIT_ENABLED=false, and exported BASE_URL,
# DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID, RELEASE_GATE=1,
# JUNIT_OUTPUT_DIR, COMMON_SH. See the manifest for the gates.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${ADMIN_USER:?}"; : "${ADMIN_PASS:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

SUF="${RUN_ID##*-}-$$"
SLOT="${DTF_SLOT:-x}"
BACKEND_CONTAINER="${DB_CONTAINER%-db}-backend"
DRAIN="${SHUTDOWN_DRAIN_SECS:-12}"
REPO="drain-generic-${SLOT}-${SUF}"
ART="pkgs/drain-1.0.0.bin"
BYTES="shutdown-drain-${SUF}"
LOCK_APP="ak-dtf-drain-lock-${SUF}"
LEASE_WAIT=90
READY_TIMEOUT=120

WORK="$(mktemp -d -t dtf-drain-XXXXXX)"
LOCK_PID=""
psql_db() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -Atc "$1" 2>&1; }
end_lock() {
  psql_db "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name = '${LOCK_APP}'" >/dev/null || true
  if [ -n "$LOCK_PID" ]; then wait "$LOCK_PID" 2>/dev/null || true; LOCK_PID=""; fi
}
backend_running() { [ "$(docker inspect -f '{{.State.Running}}' "$BACKEND_CONTAINER" 2>/dev/null)" = "true" ]; }
cleanup() {
  end_lock
  jobs -p | xargs -r kill 2>/dev/null || true
  # Never leave the slot without its backend: run.sh teardown and --keep both
  # expect a whole stack.
  backend_running || docker start "$BACKEND_CONTAINER" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

code() { # URL [CURL ARGS...] -> status; body in $WORK/body
  local url="$1"; shift
  : > "${WORK}/body"
  curl -s --max-time 5 --connect-timeout 2 -o "${WORK}/body" -w '%{http_code}' "$@" "$url" 2>/dev/null; true
}
body() { head -c 300 "${WORK}/body" 2>/dev/null; }
now_ms() { date +%s%3N; }
live_leases() { # OWNER_PREFIX -> count of live leases it holds
  psql_db "SELECT count(*) FROM scheduler_leases
           WHERE owner_id LIKE '$1:%' AND lease_expires_at > NOW()"
}
wait_ready() {
  local deadline=$(( $(date +%s) + READY_TIMEOUT ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    [ "$(code "${BASE_URL}/readyz")" = "200" ] && return 0
    sleep 1
  done
  return 1
}

DL_URL="${BASE_URL}/api/v1/repositories/${REPO}/download/${ART}"
# The held request reads `users`, which the anonymous downloads probed during
# the drain do not touch.
HELD_URL="${BASE_URL}/api/v1/users"
# The held request is released this long after SIGTERM: after the listeners
# close at DRAIN s, so it is still in flight when they do.
HOLD_MS=$(( (DRAIN + 3) * 1000 ))

begin_suite "shutdown-drain"

begin_test "setup: admin login, public generic repo + artifact"
auth_admin
BEARER="Authorization: Bearer ${ADMIN_TOKEN}"
if ! api_post "/api/v1/repositories" \
  "{\"key\":\"${REPO}\",\"name\":\"${REPO}\",\"format\":\"generic\",\"repo_type\":\"local\",\"is_public\":true}" >/dev/null 2>&1; then
  infra_fail "could not create public generic repo ${REPO}"; end_suite
fi
C="$(curl -s --max-time 30 -o "${WORK}/body" -w '%{http_code}' -X PUT -H "$BEARER" \
  -H 'Content-Type: application/octet-stream' --data-binary "$BYTES" \
  "${BASE_URL}/api/v1/repositories/${REPO}/artifacts/${ART}" 2>/dev/null; true)"
case "$C" in 200|201) pass ;; *) infra_fail "PUT of the fixture artifact returned ${C}" "$(body)"; end_suite ;; esac

begin_test "CONTROL before: /readyz 200, /livez 200, anonymous download 200 + bytes"
C1="$(code "${BASE_URL}/readyz")"
C2="$(code "${BASE_URL}/livez")"
C3="$(code "$DL_URL")"; B3="$(cat "${WORK}/body")"
if [ "$C1" = "200" ] && [ "$C2" = "200" ] && [ "$C3" = "200" ] && [ "$B3" = "$BYTES" ]; then pass
else fail "/readyz ${C1}, /livez ${C2}, download ${C3} (want 200 / 200 / 200 + bytes)" "$(body)"; fi

begin_test "CONTROL before: this backend holds a live scheduler lease (within ${LEASE_WAIT}s of boot)"
HOST="$(docker inspect -f '{{.Config.Hostname}}' "$BACKEND_CONTAINER" 2>/dev/null)"
held=0
deadline=$(( $(date +%s) + LEASE_WAIT ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  held="$(live_leases "$HOST")"
  [ "${held:-0}" -ge 1 ] 2>/dev/null && break
  sleep 2
done
if [ "${held:-0}" -ge 1 ] 2>/dev/null; then
  echo "  ${held} live lease(s) owned by ${HOST}: $(psql_db "SELECT string_agg(job_name, ',') FROM scheduler_leases WHERE owner_id LIKE '${HOST}:%' AND lease_expires_at > NOW()")"
  pass
else
  infra_fail "no live scheduler lease owned by ${HOST} after ${LEASE_WAIT}s" \
    "$(psql_db "SELECT job_name, owner_id, lease_expires_at FROM scheduler_leases")"
  end_suite
fi

begin_test "setup: one request held in flight by a lock on users"
docker exec -e PGAPPNAME="$LOCK_APP" "$DB_CONTAINER" psql -U registry -d artifact_registry \
  -c "BEGIN" -c "LOCK TABLE users IN ACCESS EXCLUSIVE MODE" -c "SELECT pg_sleep(120)" \
  >"${WORK}/lock.log" 2>&1 &
LOCK_PID=$!
for _ in $(seq 1 50); do
  [ "$(psql_db "SELECT count(*) FROM pg_stat_activity WHERE application_name = '${LOCK_APP}' AND query LIKE '%pg_sleep%'")" = "1" ] && break
  sleep 0.2
done
( curl -s --max-time 60 -o "${WORK}/inflight.body" -w '%{http_code}' -H "$BEARER" "$HELD_URL" 2>/dev/null; true ) > "${WORK}/inflight.code" &
INFLIGHT_PID=$!
blocked=0
for _ in $(seq 1 50); do
  blocked="$(psql_db "SELECT count(*) FROM pg_stat_activity WHERE datname = 'artifact_registry'
                      AND wait_event_type = 'Lock' AND application_name NOT IN ('${LOCK_APP}', 'psql')")"
  [ "${blocked:-0}" -ge 1 ] 2>/dev/null && break
  sleep 0.2
done
if [ "${blocked:-0}" -ge 1 ] 2>/dev/null; then pass
else infra_fail "the in-flight request never blocked on the lock" "$(cat "${WORK}/lock.log")"; end_suite; fi

# --- SIGTERM ----------------------------------------------------------------
T0="$(now_ms)"
docker kill -s TERM "$BACKEND_CONTAINER" >/dev/null 2>&1

begin_test "FIX #5921: within 1 s of SIGTERM /readyz answers 503 with shutting_down in failing"
R="000"; RB=""
while [ $(( $(now_ms) - T0 )) -lt 1000 ]; do
  R="$(code "${BASE_URL}/readyz")"; RB="$(cat "${WORK}/body" 2>/dev/null)"
  [ "$R" = "503" ] && break
  sleep 0.1
done
if [ "$R" = "503" ] && printf '%s' "$RB" | jq -e '.failing | index("shutting_down") != null' >/dev/null 2>&1; then
  echo "  /readyz 503 after $(( $(now_ms) - T0 )) ms"
  pass
else
  fail "/readyz answered ${R} within 1 s of SIGTERM (want 503 + shutting_down; main closes the port: 000)" "body: ${RB:0:400}"
fi

begin_test "FIX #5921: /livez answers 200 during the drain"
C="$(code "${BASE_URL}/livez")"
if [ "$C" = "200" ]; then pass; else fail "/livez answered ${C} during the drain (want 200)" "$(body)"; fi

# End the lock 3 s after the drain: the held request is still in flight when
# the listeners close, and must complete after that.
( sleep_until=$(( T0 + HOLD_MS )); while [ "$(now_ms)" -lt "$sleep_until" ]; do sleep 0.1; done
  psql_db "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name = '${LOCK_APP}'" >/dev/null ) &

begin_test "FIX #5921: downloads from 1 s to 6 s after SIGTERM all answer 200 + bytes"
while [ $(( $(now_ms) - T0 )) -lt 1000 ]; do sleep 0.05; done
ok=0; total=0; codes=""
while [ $(( $(now_ms) - T0 )) -lt 6000 ]; do
  C="$(code "$DL_URL")"; total=$(( total + 1 )); codes="${codes} ${C}"
  [ "$C" = "200" ] && [ "$(cat "${WORK}/body")" = "$BYTES" ] && ok=$(( ok + 1 ))
  sleep 0.5
done
if [ "$total" -ge 5 ] && [ "$ok" = "$total" ]; then echo "  ${ok}/${total} downloads 200 during the drain"; pass
else fail "${ok}/${total} downloads answered 200 during the drain (want all; main refuses the connection: 000)" "codes:${codes}"; fi

begin_test "FIX #5921: /livez still answers 200 $(( DRAIN - 1 ))s after SIGTERM (the drain is honoured)"
while [ $(( $(now_ms) - T0 )) -lt $(( (DRAIN - 1) * 1000 )) ]; do sleep 0.05; done
C="$(code "${BASE_URL}/livez")"
if [ "$C" = "200" ]; then pass
else fail "/livez answered ${C} $(( DRAIN - 1 ))s after SIGTERM (want 200; main closed the port at SIGTERM: 000)" "$(body)"; fi

begin_test "CONTROL: $(( DRAIN + 1 ))s after SIGTERM the listener is closed while the held request is still in flight"
while [ $(( $(now_ms) - T0 )) -lt $(( (DRAIN + 1) * 1000 )) ]; do sleep 0.05; done
C="$(code "${BASE_URL}/livez")"
if kill -0 "$INFLIGHT_PID" 2>/dev/null; then HELD="in flight"; else HELD="finished"; fi
if [ "$C" = "000" ] && [ "$HELD" = "in flight" ]; then pass
else fail "/livez answered ${C} and the held request was ${HELD} (want 000 / in flight)" "$(body)"; fi

begin_test "CONTROL: the request in flight at SIGTERM, released after the listener closed, completes 200"
wait "$INFLIGHT_PID" 2>/dev/null || true
T_HELD="$(now_ms)"
LOCK_PID=""
C="$(cat "${WORK}/inflight.code" 2>/dev/null)"
if [ "$C" = "200" ]; then echo "  completed $(( (T_HELD - T0) / 1000 ))s after SIGTERM"; pass
else fail "the in-flight request answered ${C} (want 200)" "$(head -c 300 "${WORK}/inflight.body" 2>/dev/null)"; fi

begin_test "CONTROL: the process exits with status 0"
deadline=$(( $(date +%s) + 40 ))
while backend_running && [ "$(date +%s)" -lt "$deadline" ]; do sleep 0.2; done
T_EXIT="$(now_ms)"
ELAPSED=$(( T_EXIT - T0 ))
STATE="$(docker inspect -f '{{.State.Status}} {{.State.ExitCode}}' "$BACKEND_CONTAINER" 2>/dev/null)"
if [ "$STATE" = "exited 0" ]; then echo "  exited 0, $(( ELAPSED / 1000 )).$(( ELAPSED % 1000 / 100 ))s after SIGTERM"; pass
else fail "backend state '${STATE}' 40 s after SIGTERM (want 'exited 0')"; fi

begin_test "CONTROL: the process exits after the held request completed, and within 30 s of SIGTERM"
if [ "$T_EXIT" -ge "$T_HELD" ] && [ "$ELAPSED" -le 30000 ]; then pass
else fail "the process exited ${ELAPSED} ms after SIGTERM, $(( T_EXIT - T_HELD )) ms after the held request completed (want >= 0 and <= 30000 ms)"; fi

begin_test "FIX #5921: the log names each shutdown phase"
LOG="$(docker logs --since 5m "$BACKEND_CONTAINER" 2>&1 | tail -200)"
missing=""
for phrase in "draining for ${DRAIN}s" "closing the listeners" "shutdown complete"; do
  grep -qF "$phrase" <<<"$LOG" || missing="${missing} '${phrase}'"
done
if [ -z "$missing" ]; then pass
else fail "the shutdown log lacks:${missing}" "$(grep -iE 'shutdown|SIGTERM|drain|shut down' <<<"$LOG" | tail -10)"; fi

begin_test "FIX #5921: no scheduler lease owned by the stopped backend is still live"
LEFT="$(live_leases "$HOST")"
if [ "$LEFT" = "0" ]; then pass
else fail "${LEFT} lease(s) owned by ${HOST} still live after it exited (want 0; main leaves them to lapse at their TTL)" \
  "$(psql_db "SELECT job_name, lease_expires_at FROM scheduler_leases WHERE owner_id LIKE '${HOST}:%'")"; fi

begin_test "CONTROL after: docker start brings the backend back to ready"
docker start "$BACKEND_CONTAINER" >/dev/null 2>&1
if wait_ready; then pass; else fail "/readyz not 200 within ${READY_TIMEOUT}s of docker start" "$(body)"; fi

end_suite
