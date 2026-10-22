#!/usr/bin/env bash
# =============================================================================
# tiers/metrics-startup-db-retry/oracle.sh - failed startup connect attempts
#   are exported as ak_db_pool_connection_failures_total{stage="startup"}
#   (artifact-keeper#4828)
# =============================================================================
# run.sh has stood up `storage.filesystem metrics.port` with
# RATE_LIMIT_ENABLED=false and exported BASE_URL, DB_CONTAINER, ADMIN_USER,
# ADMIN_PASS, RUN_ID, DTF_SLOT, RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
# See the manifest for the bug, the primitive and the red/green evidence.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every step below checks its own status, and the
# outage must always reach its unpause.
set +e

SLOT="${DTF_SLOT:-x}"
BACKEND_CTR="ak-dtf${SLOT}-backend"
METRICS_URL="http://127.0.0.1:9091/metrics"
# Long enough that the first attempt (5 s DATABASE_ACQUIRE_TIMEOUT_SECS) and
# the second both time out, short enough that the five-attempt startup budget
# (about 40 s) outlasts it.
PAUSE_SECS="${DB_PAUSE_SECS:-12}"

WORK="$(mktemp -d -t dtf-msdr-XXXXXX)"
cleanup() {
  if [ "$(docker inspect -f '{{.State.Paused}}' "$DB_CONTAINER" 2>/dev/null)" = "true" ]; then
    docker unpause "$DB_CONTAINER" >/dev/null 2>&1
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

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

# scrape OUTFILE -> HTTP status of GET /metrics on the METRICS_PORT listener.
scrape() {
  docker exec "$BACKEND_CTR" curl -s --max-time 30 -o - -w '\n%{http_code}' "$METRICS_URL" \
    > "$1.raw" 2>/dev/null
  tail -n 1 "$1.raw"
  sed '$d' "$1.raw" > "$1"
}

begin_suite "dtf-metrics-startup-db-retry"

begin_test "setup: the METRICS_PORT listener serves /metrics before the outage"
code="$(scrape "$WORK/m0.txt")"
if [ "$code" = "200" ]; then
  pass
else
  infra_fail "GET ${METRICS_URL} inside ${BACKEND_CTR} returned ${code:-nothing}" "$(head -c 300 "$WORK/m0.txt" 2>/dev/null)"
  end_suite
fi

# --- the outage at boot -------------------------------------------------------
T0="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
docker stop -t 10 "$BACKEND_CTR" >/dev/null 2>&1
docker pause "$DB_CONTAINER" >/dev/null 2>&1
paused="$(docker inspect -f '{{.State.Paused}}' "$DB_CONTAINER" 2>/dev/null)"
docker start "$BACKEND_CTR" >/dev/null 2>&1
sleep "$PAUSE_SECS"
docker unpause "$DB_CONTAINER" >/dev/null 2>&1
OUTCOME="$(wait_up_or_exit 90)"
docker logs --since "$T0" "$BACKEND_CTR" > "$WORK/boot.log" 2>&1
FAILED_ATTEMPTS="$(grep -c 'database pool: initial connect attempt [0-9]*/[0-9]* failed' "$WORK/boot.log")"

begin_test "setup: Postgres was frozen during the backend's boot"
if [ "$paused" = "true" ]; then
  pass
else
  infra_fail "docker pause ${DB_CONTAINER} did not take (Paused=${paused})"
  end_suite
fi

begin_test "control: the backend retried the initial connect and came up by itself"
if [ "$OUTCOME" = "up" ] && [ "$FAILED_ATTEMPTS" -ge 1 ]; then
  pass
else
  infra_fail "outcome=${OUTCOME}, failed-attempt log lines=${FAILED_ATTEMPTS}" \
    "$(grep -iE 'database|pool timed out|error' "$WORK/boot.log" | tail -5)"
  end_suite
fi
echo "   boot logged ${FAILED_ATTEMPTS} failed initial connect attempt(s)"

begin_test "control: /metrics answers 200 after the boot and renders the recorder (ak_* series)"
code="$(scrape "$WORK/m1.txt")"
if [ "$code" = "200" ] && grep -q '^ak_' "$WORK/m1.txt"; then
  pass
else
  infra_fail "GET ${METRICS_URL}: ${code:-nothing}" "$(head -c 300 "$WORK/m1.txt" 2>/dev/null)"
  end_suite
fi

begin_test "FIX #4828: ak_db_pool_connection_failures_total{stage=\"startup\"} >= 1 after the failed boot attempts"
sv="$(grep -E '^ak_db_pool_connection_failures_total\{stage="startup"\} ' "$WORK/m1.txt" | awk '{print $2}')"
echo "   stage=startup sample: ${sv:-absent} (log: ${FAILED_ATTEMPTS} failed attempt(s))"
if [ -n "$sv" ] && python3 -I -c 'import sys; sys.exit(0 if float(sys.argv[1]) >= 1 else 1)' "$sv"; then
  pass
else
  fail "ak_db_pool_connection_failures_total{stage=\"startup\"} is ${sv:-absent} although the boot logged ${FAILED_ATTEMPTS} failed attempt(s)" \
    "$(grep '^ak_db_pool' "$WORK/m1.txt" | head -8)"
fi

end_suite
