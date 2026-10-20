#!/usr/bin/env bash
# =============================================================================
# tiers/db-keepalive-startup-retry/oracle.sh - server-side TCP keepalives on
#   every pooled Postgres session, and a startup connect that retries instead
#   of exiting on the first PoolTimedOut (artifact-keeper#4549, 1.11.2)
# =============================================================================
# run.sh has stood up `storage.filesystem db.keepalive-off-peer` with
# RATE_LIMIT_ENABLED=false and exported BASE_URL, DB_CONTAINER, ADMIN_USER,
# ADMIN_PASS, RUN_ID, DTF_SLOT, RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
# See the manifest for the bug, the primitives and the red/green evidence.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every step below inspects its own status and
# records it with fail(), and the outage leg must always reach its unpause.
set +e

SLOT="${DTF_SLOT:-x}"
BACKEND_CTR="ak-dtf${SLOT}-backend"
NOKEEP_CTR="ak-dtf${SLOT}-backend-nokeep"
NETSHOOT_IMAGE="${NETSHOOT_IMAGE:-docker.io/nicolaka/netshoot:v0.13}"
# The Postgres outage at boot. Long enough that the first attempt (bounded by
# the 5 s DATABASE_ACQUIRE_TIMEOUT_SECS default) and the second both time out,
# short enough that the fixed backend's five-attempt budget (~40 s) outlasts it.
PAUSE_SECS="${DB_PAUSE_SECS:-12}"

WORK="$(mktemp -d -t dtf-dbka-XXXXXX)"
# Never leave this slot's Postgres frozen, whatever happens to the oracle.
cleanup() {
  if [ "$(docker inspect -f '{{.State.Paused}}' "$DB_CONTAINER" 2>/dev/null)" = "true" ]; then
    docker unpause "$DB_CONTAINER" >/dev/null 2>&1
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

ctr_ip() { docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$1" 2>/dev/null; }

# pg_sessions PEER_IP -> one keepalive timer per established 5432 session from
# PEER_IP, in seconds (ss in a throwaway container in the Postgres netns).
pg_sessions() {
  docker run --rm --net "container:${DB_CONTAINER}" "$NETSHOOT_IMAGE" \
    ss -Htno state established '( sport = :5432 )' 2>/dev/null \
    | python3 -c '
import re, sys
peer = sys.argv[1]
unit = {"ms": 0.001, "sec": 1, "min": 60, "h": 3600, "d": 86400}
for line in sys.stdin:
    cols = line.split()
    if len(cols) < 4 or cols[3].rsplit(":", 1)[0] != peer:
        continue
    m = re.search(r"timer:\(keepalive,([^,]+),", line)
    if not m:
        print("none"); continue
    secs = sum(float(n) * unit[u] for n, u in re.findall(r"([0-9.]+)(ms|sec|min|h|d)", m.group(1)))
    print(round(secs, 3))
' "$1"
}

# all_timers PEER_IP OP LIMIT -> 0 when there is at least one session and every
# timer satisfies OP (le|ge) LIMIT seconds.
all_timers() {
  local list
  list="$(pg_sessions "$1")"
  [ -n "$list" ] || return 1
  python3 -c '
import sys
op, lim, vals = sys.argv[1], float(sys.argv[2]), sys.argv[3].split()
ok = all(v != "none" and (float(v) <= lim if op == "le" else float(v) >= lim) for v in vals)
sys.exit(0 if ok else 1)' "$2" "$3" "$list"
}

health_code() { curl -s --max-time 5 -o /dev/null -w '%{http_code}' "${BASE_URL}/health" 2>/dev/null || echo 000; }
ctr_state() { docker inspect -f '{{.State.Status}}' "$1" 2>/dev/null; }

# wait_up_or_exit SECS -> "up" once /health is 200, "exited" if the container
# stops first, "timeout" otherwise.
wait_up_or_exit() {
  local deadline=$(( $(date +%s) + $1 ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    [ "$(health_code)" = "200" ] && { echo up; return; }
    case "$(ctr_state "$BACKEND_CTR")" in exited|stopped|dead) echo exited; return ;; esac
    sleep 1
  done
  echo timeout
}

scrape() {
  curl -s --max-time 30 -o "$1" -w '%{http_code}' -H "$(auth_header)" \
    "${BASE_URL}/api/v1/admin/metrics" 2>/dev/null || echo 000
}

begin_suite "dtf-db-keepalive-startup-retry"

# --- setup ------------------------------------------------------------------
begin_test "setup: admin login; both backends have addresses on the dtf network"
auth_admin
B_IP="$(ctr_ip "$BACKEND_CTR")"
N_IP="$(ctr_ip "$NOKEEP_CTR")"
if [ -z "$B_IP" ] || [ -z "$N_IP" ] || [ "$B_IP" = "$N_IP" ]; then
  infra_fail "could not resolve distinct backend addresses (backend=${B_IP:-none} nokeep=${N_IP:-none})"
  end_suite
fi
# One authenticated round trip on each backend so both pools are in use.
api_get "/api/v1/repositories" >/dev/null 2>&1
docker exec "$NOKEEP_CTR" curl -s --max-time 10 -o /dev/null http://127.0.0.1:8080/api/v1/repositories 2>/dev/null
pass

# --- keepalives -------------------------------------------------------------
docker run --rm --net "container:${DB_CONTAINER}" "$NETSHOOT_IMAGE" \
  ss -Htno state established '( sport = :5432 )' > "${WORK}/ss.txt" 2>&1
B_TIMERS="$(pg_sessions "$B_IP" | tr '\n' ' ')"
N_TIMERS="$(pg_sessions "$N_IP" | tr '\n' ' ')"

begin_test "control: both backends hold established Postgres sessions that carry a keepalive timer"
if [ -n "${B_TIMERS// /}" ] && [ -n "${N_TIMERS// /}" ] \
   && ! grep -qw none <<<"${B_TIMERS} ${N_TIMERS}"; then
  pass
else
  fail "backend(${B_IP}) timers: [${B_TIMERS}] nokeep(${N_IP}) timers: [${N_TIMERS}]" "$(cat "${WORK}/ss.txt")"
fi

begin_test "FIX #4549: every Postgres session of the default backend has tcp_keepalives_idle=15 (timer <= 15 s, not the 2 h kernel default)"
if all_timers "$B_IP" le 15; then
  pass
else
  fail "backend(${B_IP}) keepalive timers in seconds: [${B_TIMERS}]" "$(cat "${WORK}/ss.txt")"
fi

begin_test "control: DATABASE_TCP_KEEPALIVES=false leaves the server default (every timer >= 60 min)"
if all_timers "$N_IP" ge 3600; then
  pass
else
  fail "nokeep(${N_IP}) keepalive timers in seconds: [${N_TIMERS}]" "$(cat "${WORK}/ss.txt")"
fi

# --- startup connect retry --------------------------------------------------
# Stop the backend, freeze Postgres (the kernel still accepts the TCP connect,
# the server never answers the startup packet, so each attempt ends in the
# pool's acquire timeout: exactly the PoolTimedOut that crash-looped pods),
# start the backend, thaw Postgres PAUSE_SECS later.
T0="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
docker stop -t 10 "$BACKEND_CTR" >/dev/null 2>&1
docker pause "$DB_CONTAINER" >/dev/null 2>&1
paused="$(docker inspect -f '{{.State.Paused}}' "$DB_CONTAINER" 2>/dev/null)"
docker start "$BACKEND_CTR" >/dev/null 2>&1
sleep "$PAUSE_SECS"
docker unpause "$DB_CONTAINER" >/dev/null 2>&1
OUTCOME="$(wait_up_or_exit 75)"
docker logs --since "$T0" "$BACKEND_CTR" > "${WORK}/boot.log" 2>&1
STATE_AFTER="$(ctr_state "$BACKEND_CTR")"

begin_test "setup: Postgres was frozen during the backend's boot"
if [ "$paused" = "true" ]; then pass; else infra_fail "docker pause ${DB_CONTAINER} did not take (Paused=${paused})"; fi

begin_test "FIX #4549: a backend started while Postgres is unreachable for ${PAUSE_SECS}s retries and comes up by itself"
if [ "$OUTCOME" = "up" ] && [ "$STATE_AFTER" = "running" ]; then
  pass
else
  fail "outcome=${OUTCOME} container=${STATE_AFTER}" \
    "$(grep -iE 'database|PoolTimedOut|pool timed out|error' "${WORK}/boot.log" | tail -5)"
fi

begin_test "FIX #4549: the boot logged 'initial connect attempt 1/5 failed ... retrying'"
if grep -q 'database pool: initial connect attempt 1/5 failed' "${WORK}/boot.log"; then
  pass
else
  fail "no retry line since ${T0}" "$(tail -5 "${WORK}/boot.log")"
fi

# Bring the backend back whatever happened above (the baseline exits), so the
# metric and the control below run on a live process.
if [ "$OUTCOME" != "up" ]; then
  docker start "$BACKEND_CTR" >/dev/null 2>&1
  RECOVERY="$(wait_up_or_exit 90)"
else
  RECOVERY="up"
fi

# KNOWN-RED (artifact-keeper#4828): the startup retry counts each failed
# attempt with metrics::counter!, but main.rs builds the pool (line 194)
# before it installs the Prometheus recorder (line 404), so the increments go
# to the no-op default recorder and the series never appears. Reported, not
# failed, so the retry gates above stay usable; when the series shows up the
# note says so and this pin should become an assertion (>= 1 after the boot).
begin_test "KNOWN-RED pin #4828: ak_db_pool_connection_failures_total{stage=\"startup\"} after the failed boot attempts"
auth_admin >/dev/null 2>&1
mcode="$(scrape "${WORK}/m.txt")"
sv="$(grep -E '^ak_db_pool_connection_failures_total\{stage="startup"\} ' "${WORK}/m.txt" | awk '{print $2}')"
if [ "$RECOVERY" != "up" ] || [ "$mcode" != "200" ]; then
  fail "backend did not recover for the scrape (recovery=${RECOVERY}, metrics HTTP ${mcode})"
elif [ -n "$sv" ] && python3 -c "import sys; sys.exit(0 if float('${sv}') >= 1 else 1)"; then
  echo "   KNOWN-RED (artifact-keeper#4828) NOW PASSES: stage=startup=${sv}. Turn this pin into an assertion."
  pass
else
  echo "   KNOWN-RED (artifact-keeper#4828): stage=startup series ${sv:-absent} although the boot logged failed attempts"
  pass
fi

begin_test "control: with Postgres up, a restarted backend comes up and serves an authenticated request"
docker restart -t 10 "$BACKEND_CTR" >/dev/null 2>&1
r="$(wait_up_or_exit 90)"
auth_admin >/dev/null 2>&1
code="$(curl -s --max-time 30 -o "${WORK}/repos.json" -w '%{http_code}' -H "$(auth_header)" "${BASE_URL}/api/v1/repositories" 2>/dev/null || echo 000)"
if [ "$r" = "up" ] && [ "$code" = "200" ]; then
  pass
else
  fail "after restart: ${r}; GET /api/v1/repositories=${code}"
fi

begin_test "control: the DATABASE_TCP_KEEPALIVES=false peer rode out the outage, still serves, and is still unarmed"
ncode="$(docker exec "$NOKEEP_CTR" curl -s --max-time 10 -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/health 2>/dev/null)"
if [ "$ncode" = "200" ] && all_timers "$N_IP" ge 3600; then
  pass
else
  fail "nokeep /health=${ncode}; timers: [$(pg_sessions "$N_IP" | tr '\n' ' ')]"
fi

end_suite
