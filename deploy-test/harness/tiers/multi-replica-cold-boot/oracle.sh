#!/usr/bin/env bash
# =============================================================================
# tiers/multi-replica-cold-boot/oracle.sh: three replicas started together on
#   an empty database all come up without a restart (artifact-keeper#5601)
# =============================================================================
# run.sh has stood up filesystem + topology.three-replica-cold and exported
# BASE_URL, DB_CONTAINER, RUN_ID, RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
# See the manifest for the bug and each assertion.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
set +e

PREFIX="${DB_CONTAINER%-db}"
REPLICAS=("${PREFIX}-backend" "${PREFIX}-backend-b" "${PREFIX}-backend-c")
psql_q() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]'; }

begin_suite "multi-replica-cold-boot"

# --- stage the cold first boot ----------------------------------------------
# Stop every replica, replace the database with an empty one, then start the
# three at the same moment: three pods of a fresh install.
for c in "${REPLICAS[@]}"; do docker stop -t 10 "$c" >/dev/null 2>&1 & done
wait
declare -A BEFORE=()
for c in "${REPLICAS[@]}"; do BEFORE[$c]="$(docker inspect -f '{{.RestartCount}}' "$c" 2>/dev/null || echo 0)"; done
if ! docker exec "$DB_CONTAINER" psql -U registry -d postgres -qc "DROP DATABASE IF EXISTS artifact_registry WITH (FORCE)" >/dev/null 2>&1 \
   || ! docker exec "$DB_CONTAINER" psql -U registry -d postgres -qc "CREATE DATABASE artifact_registry OWNER registry" >/dev/null 2>&1; then
  infra_fail "could not recreate an empty artifact_registry database"; end_suite
fi
T0="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
sleep 1
for c in "${REPLICAS[@]}"; do docker start "$c" >/dev/null 2>&1 & done
wait

# Let a replica that lost the race finish its restarts before counting.
for _ in $(seq 1 90); do
  ok=0
  for c in "${REPLICAS[@]}"; do
    [ "$(docker exec "$c" curl -s -m 5 -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/readyz 2>/dev/null)" = "200" ] && ok=$((ok + 1))
  done
  [ "$ok" = "${#REPLICAS[@]}" ] && break
  sleep 2
done
sleep 3

EV=""
RESTARTS=0
DEADLOCKS=0
COMPLETE=0
READY=0
for c in "${REPLICAS[@]}"; do
  now="$(docker inspect -f '{{.RestartCount}}' "$c" 2>/dev/null || echo '?')"
  # Delta over the staged boot (docker start may or may not reset the count).
  r='?'
  if [[ "$now" =~ ^[0-9]+$ ]]; then
    r=$((now - ${BEFORE[$c]:-0})); [ "$r" -lt 0 ] && r="$now"
  fi
  logs="$(docker logs --since "$T0" "$c" 2>&1 | sed 's/\x1b\[[0-9;]*m//g')"
  d="$(grep -c 'deadlock detected' <<<"$logs")"
  m="$(grep -c 'Database migrations complete' <<<"$logs")"
  code="$(docker exec "$c" curl -s -m 5 -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/readyz 2>/dev/null)"
  EV+="${c##*-dtf}: restarts=${r} deadlock_lines=${d} migrations_complete=${m} readyz=${code}; "
  [[ "$r" =~ ^[0-9]+$ ]] && RESTARTS=$((RESTARTS + r)) || RESTARTS=$((RESTARTS + 1000))
  DEADLOCKS=$((DEADLOCKS + d))
  [ "$m" -ge 1 ] && COMPLETE=$((COMPLETE + 1))
  [ "$code" = "200" ] && READY=$((READY + 1))
done
INVALID="$(psql_q "SELECT count(*) FROM pg_index WHERE NOT indisvalid")"
TOTAL="$(psql_q "SELECT count(*) FROM _sqlx_migrations")"
SUCC="$(psql_q "SELECT count(*) FROM _sqlx_migrations WHERE success")"
MAXV="$(psql_q "SELECT max(version) FROM _sqlx_migrations")"
EV+="invalid_indexes=${INVALID}; ledger total=${TOTAL} succeeded=${SUCC} newest=${MAXV}"
echo "  ${EV}" >&2

begin_test "CONTROL: all three replicas answer /readyz 200, each finished migrations, and every ledger row succeeded"
if [ "$READY" = "3" ] && [ "$COMPLETE" = "3" ] && [ -n "$TOTAL" ] && [ "$TOTAL" = "$SUCC" ] && [ "$TOTAL" -gt 0 ]; then
  pass
else
  fail "the three-replica first boot did not converge" "$EV"
fi

begin_test "FIX #5601: no replica restarted and none logged 'deadlock detected' on the first boot"
if [ "$RESTARTS" = "0" ] && [ "$DEADLOCKS" = "0" ]; then
  pass
else
  fail "a replica lost the migration race (1.11.x behaviour)" "$EV"
fi

begin_test "FIX #5601: the first boot left no INVALID index"
if [ "$INVALID" = "0" ]; then pass; else fail "INVALID indexes after the first boot: ${INVALID}" "$EV"; fi

end_suite
