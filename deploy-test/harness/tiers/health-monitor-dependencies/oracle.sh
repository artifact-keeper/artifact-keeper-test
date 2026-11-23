#!/usr/bin/env bash
# =============================================================================
# tiers/health-monitor-dependencies/oracle.sh: the health monitor records a
#   storage outage, a scanner-adapter outage and a Postgres restart, and
#   /readyz answers promptly with the database down (artifact-keeper#5651)
# =============================================================================
# run.sh has stood up storage.s3 (MinIO) + scanners.mock-adapter and exported
# BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID, RELEASE_GATE=1,
# JUNIT_OUTPUT_DIR, COMMON_SH. See the manifest for the bug, the fix and each
# assertion. Every fault is on this slot's own containers; the EXIT trap
# starts any it stopped.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${ADMIN_USER:?}"; : "${ADMIN_PASS:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
set +e

PREFIX="${DB_CONTAINER%-db}"
MINIO_CTR="${PREFIX}-minio"
ADAPTER_CTR="${PREFIX}-mock-adapter"
MON="/api/v1/admin/monitoring"

WORK="$(mktemp -d -t dtf-hmd-XXXXXX)"
MINIO_STOPPED=0
ADAPTER_STOPPED=0
DB_STOPPED=0
cleanup() {
  if [ "$DB_STOPPED" = "1" ]; then docker unpause "$DB_CONTAINER" >/dev/null 2>&1 || true; fi
  if [ "$MINIO_STOPPED" = "1" ]; then docker start "$MINIO_CTR" >/dev/null 2>&1 || true; fi
  if [ "$ADAPTER_STOPPED" = "1" ]; then docker start "$ADAPTER_CTR" >/dev/null 2>&1 || true; fi
  rm -rf "$WORK"
}
trap cleanup EXIT

# run_check LABEL: POST /monitoring/check; the body lands in $WORK/LABEL.json,
# "CODE SECONDS" in $WORK/LABEL.res.
run_check() {
  curl -s -m 60 -X POST -H "$(auth_header)" -o "${WORK}/$1.json" -w '%{http_code} %{time_total}' \
    "${BASE_URL}${MON}/check" > "${WORK}/$1.res" 2>/dev/null || echo "000 60" > "${WORK}/$1.res"
}
code_of() { cut -d' ' -f1 "${WORK}/$1.res"; }
secs_of() { cut -d' ' -f2 "${WORK}/$1.res"; }
# status_in LABEL SERVICE -> the last entry's status for SERVICE ("" if none)
status_in() { jq -r --arg s "$2" '[.[] | select(.service_name == $s)] | last | .status // ""' "${WORK}/$1.json" 2>/dev/null; }
field_in() { jq -r --arg s "$2" --arg f "$3" '[.[] | select(.service_name == $s)] | last | .[$f] // ""' "${WORK}/$1.json" 2>/dev/null; }
services_in() { jq -r '[.[] | "\(.service_name)=\(.status)"] | join(" ")' "${WORK}/$1.json" 2>/dev/null; }
# wait_ready SECS: until /readyz answers 200 (true) or SECS pass (false)
wait_ready() {
  for _ in $(seq 1 "$1"); do
    [ "$(curl -s -m 3 -o /dev/null -w '%{http_code}' "${BASE_URL}/readyz" 2>/dev/null)" = "200" ] && return 0
    sleep 1
  done
  return 1
}
# wait_check_status SERVICE STATUS LABEL TRIES: rerun the check until SERVICE
# reports STATUS (the /health storage cache holds a result for 5 s)
wait_check_status() {
  for _ in $(seq 1 "$4"); do
    run_check "$3"
    [ "$(status_in "$3" "$1")" = "$2" ] && return 0
    sleep 3
  done
  return 1
}

begin_suite "health-monitor-dependencies"

# =============================================================================
# SETUP + CONTROL
# =============================================================================
begin_test "setup: admin login, MinIO and the mock adapter running"
auth_admin
if [ "$(docker inspect -f '{{.State.Running}}' "$MINIO_CTR" 2>/dev/null)" != "true" ] \
   || [ "$(docker inspect -f '{{.State.Running}}' "$ADAPTER_CTR" 2>/dev/null)" != "true" ]; then
  infra_fail "${MINIO_CTR} or ${ADAPTER_CTR} is not running"; end_suite
fi
pass

run_check up
EV_UP="check: HTTP $(code_of up) in $(secs_of up)s: $(services_in up)"
echo "  ${EV_UP}" >&2

begin_test "CONTROL: a monitoring check with every dependency up answers 200 and reports the database healthy"
if [ "$(code_of up)" = "200" ] && [ "$(status_in up database)" = "healthy" ]; then
  pass
else
  fail "the check did not report a healthy database" "$EV_UP"
fi

begin_test "FIX #5651: the check covers storage and the scanner adapter, both healthy"
if [ "$(status_in up storage)" = "healthy" ] && [ "$(status_in up scanner-adapter)" = "healthy" ]; then
  pass
else
  fail "storage / scanner-adapter missing from the monitor (pre-fix behaviour) or not healthy" "$EV_UP"
fi

# =============================================================================
# MinIO outage
# =============================================================================
if ! docker stop -t 5 "$MINIO_CTR" >/dev/null 2>&1; then infra_fail "docker stop ${MINIO_CTR} failed"; end_suite; fi
MINIO_STOPPED=1
wait_check_status storage unhealthy minio_down 5
EV_MD="check: HTTP $(code_of minio_down) in $(secs_of minio_down)s: $(services_in minio_down); storage message: $(field_in minio_down storage message | head -c 200)"
echo "  ${EV_MD}" >&2
curl -s -m 15 -H "$(auth_header)" "${BASE_URL}${MON}/health-log?service=storage&limit=20" -o "${WORK}/log_storage.json" 2>/dev/null
curl -s -m 15 -H "$(auth_header)" "${BASE_URL}${MON}/alerts" -o "${WORK}/alerts.json" 2>/dev/null
curl -s -m 15 -H "$(auth_header)" "${BASE_URL}/api/v1/admin/metrics" -o "${WORK}/metrics_down.txt" 2>/dev/null
UP_STORAGE="$(grep -E '^ak_health_monitor_up\{service="storage"\}' "${WORK}/metrics_down.txt" | awk '{print $NF}' | head -1)"
LOG_UNHEALTHY="$(jq '[.[] | select(.status == "unhealthy")] | length' "${WORK}/log_storage.json" 2>/dev/null || echo 0)"
ALERT_STORAGE="$(jq -r '[.[] | select(.service_name == "storage")] | first | "\(.current_status) failures=\(.consecutive_failures)"' "${WORK}/alerts.json" 2>/dev/null)"

begin_test "FIX #5651: with MinIO stopped the check, the health log and the alert state record storage unhealthy"
if [ "$(status_in minio_down storage)" = "unhealthy" ] && [ "${LOG_UNHEALTHY:-0}" -ge 1 ] \
   && [[ "$ALERT_STORAGE" == unhealthy* ]]; then
  pass
else
  fail "a MinIO outage was not recorded" "${EV_MD}; health-log unhealthy rows=${LOG_UNHEALTHY}; alert=${ALERT_STORAGE}"
fi

begin_test "FIX #5651: with MinIO stopped /api/v1/admin/metrics has ak_health_monitor_up{service=\"storage\"} 0"
if [ "$UP_STORAGE" = "0" ]; then
  pass
else
  fail "no storage up-gauge at 0" "ak_health_monitor_up{service=\"storage\"}=${UP_STORAGE:-absent}"
fi

# The probes are bounded and concurrent: one check with the object store down
# and (next) the adapter down costs about one probe deadline, not the sum.
if ! docker stop -t 2 "$ADAPTER_CTR" >/dev/null 2>&1; then infra_fail "docker stop ${ADAPTER_CTR} failed"; end_suite; fi
ADAPTER_STOPPED=1
sleep 6
run_check both_down
EV_BD="check: HTTP $(code_of both_down) in $(secs_of both_down)s: $(services_in both_down)"
echo "  ${EV_BD}" >&2

begin_test "FIX #5651: with the scanner adapter stopped the check records scanner-adapter unavailable"
if [ "$(status_in both_down scanner-adapter)" = "unavailable" ]; then
  pass
else
  fail "an adapter outage was not recorded" "$EV_BD"
fi

begin_test "CONTROL: with MinIO and the adapter both down one check answers 200 within 8 s"
if [ "$(code_of both_down)" = "200" ] && awk -v t="$(secs_of both_down)" 'BEGIN { exit !(t + 0 < 8.0) }'; then
  pass
else
  fail "the check was slow or failed with two dependencies down" "$EV_BD"
fi

docker start "$MINIO_CTR" >/dev/null 2>&1 && MINIO_STOPPED=0
docker start "$ADAPTER_CTR" >/dev/null 2>&1 && ADAPTER_STOPPED=0
for _ in $(seq 1 30); do
  [ "$(docker inspect -f '{{.State.Health.Status}}' "$MINIO_CTR" 2>/dev/null)" = "healthy" ] \
    && [ "$(docker inspect -f '{{.State.Health.Status}}' "$ADAPTER_CTR" 2>/dev/null)" = "healthy" ] && break
  sleep 2
done
wait_check_status storage healthy recovered 6
# The scheduler's own 60 s monitor tick may record the recovery before this
# check does, so the transition is read from the health log, not from this
# check's previous_status.
curl -s -m 15 -H "$(auth_header)" "${BASE_URL}${MON}/health-log?service=storage&limit=50" -o "${WORK}/log_storage2.json" 2>/dev/null
TRANSITIONS="$(jq '[.[] | select(.status == "healthy" and .previous_status == "unhealthy")] | length' "${WORK}/log_storage2.json" 2>/dev/null || echo 0)"
EV_RC="check: HTTP $(code_of recovered) in $(secs_of recovered)s: $(services_in recovered); storage unhealthy->healthy rows in the log: ${TRANSITIONS}"
echo "  ${EV_RC}" >&2

begin_test "FIX #5651: after MinIO and the adapter return, both are healthy again and the health log records storage's recovery"
if [ "$(status_in recovered storage)" = "healthy" ] && [ "$(status_in recovered scanner-adapter)" = "healthy" ] \
   && [ "${TRANSITIONS:-0}" -ge 1 ]; then
  pass
else
  fail "recovery was not recorded" "$EV_RC"
fi

# =============================================================================
# Postgres restart between two checks
# =============================================================================
run_check before_restart
if ! docker restart -t 5 "$DB_CONTAINER" >/dev/null 2>&1; then infra_fail "docker restart ${DB_CONTAINER} failed"; end_suite; fi
if ! wait_ready 60; then infra_fail "/readyz did not return to 200 within 60 s of the Postgres restart"; end_suite; fi
# The first requests after the restart may meet a pooled connection the
# restart closed; give the check a few tries.
for _ in 1 2 3 4 5; do
  run_check after_restart
  [ "$(code_of after_restart)" = "200" ] && break
  sleep 2
done
curl -s -m 15 -H "$(auth_header)" "${BASE_URL}${MON}/health-log?service=database&limit=10" -o "${WORK}/log_db.json" 2>/dev/null
RESTART_ROWS="$(jq '[.[] | select(.status == "unavailable" and ((.message // "") | startswith("Postgres restarted at")))] | length' "${WORK}/log_db.json" 2>/dev/null || echo 0)"
# A second check (the scheduler may also run one) must not record it again.
run_check after_restart2
curl -s -m 15 -H "$(auth_header)" "${BASE_URL}${MON}/health-log?service=database&limit=10" -o "${WORK}/log_db.json" 2>/dev/null
RESTART_ROWS="$(jq '[.[] | select(.status == "unavailable" and ((.message // "") | startswith("Postgres restarted at")))] | length' "${WORK}/log_db.json" 2>/dev/null || echo 0)"
RESTARTS_METRIC="$(curl -s -m 15 -H "$(auth_header)" "${BASE_URL}/api/v1/admin/metrics" 2>/dev/null | awk '/^ak_health_monitor_postgres_restarts_total/ {print int($NF)}' | head -1)"
EV_PG="restart rows=${RESTART_ROWS}, restarts metric=${RESTARTS_METRIC:-absent}; check after restart: HTTP $(code_of after_restart): $(services_in after_restart); database log: $(jq -c '[.[] | {status, message}] | .[0:3]' "${WORK}/log_db.json" 2>/dev/null | head -c 400)"
echo "  ${EV_PG}" >&2

begin_test "FIX #5651: a Postgres restart between two checks is recorded once as a database 'unavailable' row and counted in ak_health_monitor_postgres_restarts_total"
if [ "${RESTART_ROWS:-0}" = "1" ] && [ "$(status_in after_restart database)" = "healthy" ] \
   && [ "${RESTARTS_METRIC:-0}" -ge 1 ]; then
  pass
else
  fail "the Postgres restart left no trace in the health log (pre-fix behaviour)" "$EV_PG"
fi

# =============================================================================
# /readyz with Postgres hung
# =============================================================================
# `docker pause` freezes Postgres without closing its socket, the way a
# stalled or unreachable database pod looks to a replica: connects and
# queries hang instead of failing fast (a stopped container's name stops
# resolving, which fails in milliseconds and hides the bug).
if ! docker pause "$DB_CONTAINER" >/dev/null 2>&1; then infra_fail "docker pause ${DB_CONTAINER} failed"; end_suite; fi
DB_STOPPED=1
READYZ=""
for _ in 1 2 3; do
  READYZ+="$(curl -s -m 20 -o /dev/null -w '%{http_code}/%{time_total}' "${BASE_URL}/readyz" 2>/dev/null) "
  sleep 1
done
echo "  /readyz with Postgres paused: ${READYZ}" >&2
SLOW="$(tr ' ' '\n' <<<"$READYZ" | awk -F/ 'NF && ($1 != "503" || $2 + 0 >= 2.5)' | wc -l | tr -d ' ')"
docker unpause "$DB_CONTAINER" >/dev/null 2>&1 && DB_STOPPED=0

begin_test "FIX #5651: with Postgres hung /readyz answers 503 within 2.5 s, every time"
if [ "$SLOW" = "0" ]; then
  pass
else
  fail "/readyz was slow or not 503 with the database hung" "$READYZ"
fi

begin_test "CONTROL: /readyz is 200 again after Postgres is resumed"
if wait_ready 60; then pass; else fail "/readyz did not recover within 60 s"; fi

end_suite
