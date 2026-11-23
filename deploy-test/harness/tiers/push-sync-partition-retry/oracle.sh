#!/usr/bin/env bash
# =============================================================================
# tiers/push-sync-partition-retry/oracle.sh
#   #6134 a push written as its peer becomes unreachable is delivered once the
#         peer is back, instead of using up its retries during the outage
# See the manifest for THE BUG, THE PEERS and the gates.
#
# run.sh exported BASE_URL (instance A), DB_CONTAINER (A's postgres),
# ADMIN_USER, ADMIN_PASS, RUN_ID, DTF_SLOT, TRIVY_PORT (instance B's published
# HTTP port, profiles/peer.second-instance.yml), RELEASE_GATE=1, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"
: "${TRIVY_PORT:?}"; : "${ADMIN_PASS:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

# common.sh enables errexit; every probe below guards its own failure so a
# miss records a JUnit case instead of killing the oracle.
set +e

SLOT="${DTF_SLOT}"
SUF="${RUN_ID##*-}-$$"
A="${BASE_URL}"
B="http://127.0.0.1:${TRIVY_PORT}"
B_CTR="ak-dtf${SLOT}-peer-backend"
B_DB="ak-dtf${SLOT}-peer-db"
AUTH="${ADMIN_USER:-admin}:${ADMIN_PASS}"
R_GEN="psepart-${SLOT}-${SUF}"
# Failed transfers of the write to wait for while B is down: the task's
# whole retry budget (SYNC_TASK_MAX_RETRIES default).
DOWN_FAILURES=3

W="$(mktemp -d -t dtf-pushpart-XXXXXX)"
# B is started again on any exit, so a failed run does not leave it down.
trap 'docker start "$B_CTR" >/dev/null 2>&1; rm -rf "$W"' EXIT

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

# --- helpers -----------------------------------------------------------------
psql_a() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -Atc "$1" 2>/dev/null || true; }
psql_b() { docker exec "$B_DB" psql -U registry -d artifact_registry -Atc "$1" 2>/dev/null || true; }
code() { curl -s -o "$W/last" -w '%{http_code}' --max-time 60 "$@" 2>/dev/null || echo 000; }

repo_create() { # base key -> id
  local body
  body="$(jq -nc --arg k "$2" '{key:$k,name:$k,format:"generic",repo_type:"local",is_public:false}')"
  curl -sf --max-time 60 -u "$AUTH" -X POST -H 'Content-Type: application/json' \
    -d "$body" "$1/api/v1/repositories" 2>/dev/null | jq -r '.id // empty' 2>/dev/null || true
}
mint_key() { # base -> token
  curl -s --max-time 30 -u "$AUTH" -X POST -H 'Content-Type: application/json' \
    -d "{\"name\":\"dtf-part-${SUF}-$RANDOM\",\"scopes\":[\"*\"]}" "$1/api/v1/auth/tokens" 2>/dev/null \
    | jq -r '.token // empty' 2>/dev/null || true
}
register_peer() { # base name endpoint key -> id
  curl -s --max-time 60 -u "$AUTH" -X POST -H 'Content-Type: application/json' \
    -d "{\"name\":\"$2\",\"endpoint_url\":\"$3\",\"api_key\":\"$4\"}" \
    "$1/api/v1/peers" 2>/dev/null | tee "$W/peer-$2" | jq -r '.id // empty' 2>/dev/null || true
}
subscribe() { # base peer repo_id -> http code
  code -u "$AUTH" -X POST -H 'Content-Type: application/json' \
    -d "{\"repository_id\":\"$3\",\"sync_enabled\":true,\"replication_mode\":\"push\"}" \
    "$1/api/v1/peers/$2/repositories"
}
put_a() { # path file -> http code
  code -u "$AUTH" -X PUT -H 'Content-Type: application/octet-stream' --data-binary @"$2" \
    "${A}/api/v1/repositories/${R_GEN}/artifacts/$1"
}
sha_b() { psql_b "SELECT a.checksum_sha256 FROM artifacts a JOIN repositories r ON r.id = a.repository_id \
                  WHERE r.key = '${R_GEN}' AND a.path = '$1' AND a.is_deleted = false"; }
# "<status>|<retry_count>/<max_retries>" of the write's push row on A.
task_a() { psql_a "SELECT st.status::text || '|' || st.retry_count || '/' || st.max_retries \
                   FROM sync_tasks st JOIN artifacts a ON a.id = st.artifact_id \
                   JOIN repositories r ON r.id = a.repository_id \
                   WHERE r.key = '${R_GEN}' AND a.path = '$1' AND st.task_type = 'push' \
                     AND st.peer_instance_id = '${PEER_B_ON_A}'"; }
failures_a() { psql_a "SELECT transfer_failures_total FROM peer_instances WHERE id = '${PEER_B_ON_A}'"; }
# A peer whose own heartbeats still arrive: keep A's view of B fresh.
heartbeat() { psql_a "UPDATE peer_instances SET last_heartbeat_at = NOW() WHERE id = '${PEER_B_ON_A}'" >/dev/null; }
wait_sha_b() { # path want secs
  local deadline=$(( $(date +%s) + $3 ))
  while [ "$(sha_b "$1")" != "$2" ] && [ "$(date +%s)" -lt "$deadline" ]; do heartbeat; sleep 3; done
}
sha() { sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }

begin_suite "push-sync-partition-retry"
auth_admin

# =============================================================================
begin_test "SETUP: B up, the same generic repo on A and B, B a push peer of A"
SETUP_ERR=""
curl -sf --max-time 10 "${B}/health" >/dev/null 2>&1 || SETUP_ERR="instance B not healthy at ${B};"
CTL_F="$W/ctl.bin";   head -c 4096 /dev/urandom > "$CTL_F"
WRITE_F="$W/write.bin"; head -c 4096 /dev/urandom > "$WRITE_F"
RID_A="$(repo_create "$A" "$R_GEN")"; RID_B="$(repo_create "$B" "$R_GEN")"
[ -n "$RID_A" ] || SETUP_ERR="${SETUP_ERR} create ${R_GEN} on A failed;"
[ -n "$RID_B" ] || SETUP_ERR="${SETUP_ERR} create ${R_GEN} on B failed;"
B_KEY="$(mint_key "$B")"
[ -n "$B_KEY" ] || SETUP_ERR="${SETUP_ERR} could not mint an API key on B;"
PEER_B_ON_A="$(register_peer "$A" "dtf-part-b-${SLOT}-${SUF}" "http://peer-backend:8080" "$B_KEY")"
if [ -z "$PEER_B_ON_A" ]; then
  SETUP_ERR="${SETUP_ERR} peer registration failed: $(cat "$W"/peer-* 2>/dev/null | tr '\n' ' ' | cut -c1-300);"
else
  psql_a "UPDATE peer_instances SET status = 'online', last_heartbeat_at = NOW(), backoff_until = NULL \
          WHERE id = '${PEER_B_ON_A}'" >/dev/null
  c="$(subscribe "$A" "$PEER_B_ON_A" "${RID_A:-x}")"
  [ "$c" = "200" ] || SETUP_ERR="${SETUP_ERR} subscribe B to ${R_GEN} on A -> ${c};"
fi
if [ -z "$SETUP_ERR" ]; then pass; else
  infra_fail "setup could not complete: ${SETUP_ERR}"; end_suite; exit $?
fi

CTL_P="ctl/ctl-${SUF}.bin"
WRITE_P="part/write-${SUF}.bin"

# =============================================================================
begin_test "CONTROL: a push made while B is up reaches B"
c="$(put_a "$CTL_P" "$CTL_F")"
wait_sha_b "$CTL_P" "$(sha "$CTL_F")" 90
if [[ "$c" == 20? ]] && [ "$(sha_b "$CTL_P")" = "$(sha "$CTL_F")" ]; then
  pass
else
  infra_fail "the peer wiring itself does not deliver: PUT on A -> ${c}, row $(task_a "$CTL_P"), B sha=$(sha_b "$CTL_P")"
  end_suite; exit $?
fi

# =============================================================================
begin_test "CONTROL: B goes down, a write on A right after it fails ${DOWN_FAILURES}+ transfers while B still looks online"
reset_case
base_fail="$(failures_a)"
docker stop -t 10 "$B_CTR" >/dev/null 2>&1 || fail_g "docker stop ${B_CTR} failed"
c="$(put_a "$WRITE_P" "$WRITE_F")"
[[ "$c" == 20? ]] || fail_g "the write on A answered ${c}"
want=$(( ${base_fail:-0} + DOWN_FAILURES ))
deadline=$(( $(date +%s) + 120 ))
while [ "$(failures_a)" -lt "$want" ] 2>/dev/null && [ "$(date +%s)" -lt "$deadline" ]; do
  heartbeat; sleep 2
done
# One more worker tick, so the fixed image has retried once past the budget.
for _ in 1 2 3 4 5 6; do heartbeat; sleep 2; done
DOWN_ROW="$(task_a "$WRITE_P")"
note "failed transfers to B while it was down: $(( $(failures_a) - ${base_fail:-0} )); the write's row: ${DOWN_ROW}"
note "peer on A: $(psql_a "SELECT status::text || ' failures=' || consecutive_failures FROM peer_instances WHERE id = '${PEER_B_ON_A}'")"
note "last error: $(psql_a "SELECT coalesce(st.error_message,'') FROM sync_tasks st JOIN artifacts a ON a.id = st.artifact_id \
  WHERE a.path = '${WRITE_P}' AND st.peer_instance_id = '${PEER_B_ON_A}'" | head -c 300)"
[ "$(failures_a)" -ge "$want" ] 2>/dev/null || fail_g "fewer than ${DOWN_FAILURES} failed transfers while B was down: the outage window was not exercised"
finish_case "the outage window"
if [ "$FAILS" -ne 0 ]; then end_suite; exit $?; fi

# =============================================================================
begin_test "FIX #6134: once B is back the write made during the outage reaches it"
reset_case
docker start "$B_CTR" >/dev/null 2>&1 || fail_g "docker start ${B_CTR} failed"
up=0
for _ in $(seq 1 90); do curl -sf --max-time 5 "${B}/health" >/dev/null 2>&1 && { up=1; break; }; heartbeat; sleep 1; done
[ "$up" = 1 ] || fail_g "B did not come back healthy within 90 s"
wait_sha_b "$WRITE_P" "$(sha "$WRITE_F")" 90
row="$(task_a "$WRITE_P")"
note "after the heal: B sha=$(sha_b "$WRITE_P"), A row ${row} (during the outage ${DOWN_ROW})"
[ "$(sha_b "$WRITE_P")" = "$(sha "$WRITE_F")" ] \
  || fail_g "B never got the write made during the outage (row on A: ${row}; during the outage ${DOWN_ROW})"
[[ "$row" == completed\|* ]] || fail_g "the write's push row on A is '${row}', not completed"
finish_case "the write made as B became unreachable was lost"

end_suite
