#!/usr/bin/env bash
# =============================================================================
# tiers/replication-delete-restore/oracle.sh
#   Peer deletes, labels and restores of 1.12.0 against a real push peer:
#   a label write keeps a manually subscribed peer's copy (#5625), a restore
#   cancels the queued peer delete (#5505) and its re-push of identical
#   bytes is applied (#5627), and a purged predecessor's delete survives a
#   restore at its path (#5699). See the manifest.
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
# common.sh turns on errexit; every probe here records its outcome instead.
set +e

SLOT="${DTF_SLOT}"
SUF="${RUN_ID##*-}-$$"
A="${BASE_URL}"
B="http://127.0.0.1:${TRIVY_PORT}"
B_DB="ak-dtf${SLOT}-peer-db"
AUTH="${ADMIN_USER:-admin}:${ADMIN_PASS}"
REPO="l6-rdr-${SLOT}-${SUF}"
NIL="00000000-0000-0000-0000-000000000000"
setup_workdir
W="$WORK_DIR"

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
# code ARGS...: HTTP code; the body goes to $W/last.
code() { curl -s -o "$W/last" -w '%{http_code}' --max-time 60 "$@" 2>/dev/null || echo 000; }
sha() { sha256sum "$1" | cut -d' ' -f1; }

put_a() { code -u "$AUTH" -X PUT --data-binary @"$2" "${A}/api/v1/repositories/${REPO}/artifacts/$1"; }
del_a() { code -u "$AUTH" -X DELETE "${A}/api/v1/repositories/${REPO}/artifacts/$1"; }
# id_a PATH [deleted]: the newest row's id at PATH on A (live, or soft-deleted).
id_a() {
  local live="false"; [ "${2:-}" = "deleted" ] && live="true"
  psql_a "SELECT a.id FROM artifacts a JOIN repositories r ON r.id = a.repository_id \
          WHERE r.key = '${REPO}' AND a.path = '$1' AND a.is_deleted = ${live} \
          ORDER BY a.created_at DESC LIMIT 1"
}
# served_b PATH: "<http>:<sha256 of the body>" of B's download.
served_b() {
  local c
  c="$(curl -s -o "$W/servedb" -w '%{http_code}' --max-time 60 -u "$AUTH" \
    "${B}/api/v1/repositories/${REPO}/download/$1" 2>/dev/null || echo 000)"
  if [ "$c" = "200" ]; then echo "${c}:$(sha "$W/servedb")"; else echo "${c}:-"; fi
}
# await_b PATH WANT SECS: wait until served_b PATH equals WANT.
await_b() {
  local end=$(( $(date +%s) + $3 ))
  while [ "$(served_b "$1")" != "$2" ] && [ "$(date +%s)" -lt "$end" ]; do sleep 3; done
  [ "$(served_b "$1")" = "$2" ]
}
# tasks ARTIFACT_ID TYPE: "status:retry_count" of A's tasks of TYPE for B and
# that artifact, comma-joined ("" when none).
tasks() {
  psql_a "SELECT string_agg(status::text || ':' || retry_count, ',' ORDER BY created_at) FROM sync_tasks \
          WHERE peer_instance_id = '${PEER_ID:-$NIL}' AND artifact_id = '${1:-$NIL}' AND task_type = '$2'"
}
task_errors() {
  psql_a "SELECT string_agg(left(coalesce(error_message, ''), 160), ' | ') FROM sync_tasks \
          WHERE peer_instance_id = '${PEER_ID:-$NIL}' AND artifact_id = '${1:-$NIL}' AND coalesce(error_message, '') <> ''"
}
backoff() { # on | off
  if [ "$1" = on ]; then
    psql_a "UPDATE peer_instances SET backoff_until = NOW() + INTERVAL '1 hour' WHERE id = '${PEER_ID}'" >/dev/null
  else
    psql_a "UPDATE peer_instances SET status = 'online', backoff_until = NULL, last_heartbeat_at = NOW() WHERE id = '${PEER_ID}'" >/dev/null
  fi
}
# drain SECS: wait until A holds no pending or in-progress task for B.
drain() {
  local end=$(( $(date +%s) + $1 )) n
  while :; do
    n="$(psql_a "SELECT count(*) FROM sync_tasks WHERE peer_instance_id = '${PEER_ID}' AND status::text IN ('pending','in_progress')")"
    [ "${n:-1}" = "0" ] && return 0
    [ "$(date +%s)" -ge "$end" ] && return 1
    sleep 3
  done
}

begin_suite "replication-delete-restore"
auth_admin

# =============================================================================
# SETUP: the same generic repo on A and B, B a push peer of A (manual
# subscription)
# =============================================================================
begin_test "SETUP: instance B is up, the same generic repository on A and B, B subscribed on A as a push peer"
SETUP_ERR=""
curl -sf --max-time 10 "${B}/health" >/dev/null 2>&1 || SETUP_ERR="instance B not healthy at ${B};"
body="$(jq -nc --arg k "$REPO" '{key:$k,name:$k,format:"generic",repo_type:"local",is_public:false}')"
RID="$(curl -s --max-time 60 -u "$AUTH" -X POST -H 'Content-Type: application/json' -d "$body" "${A}/api/v1/repositories" | jq -r '.id // empty' 2>/dev/null)"
[ -n "$RID" ] || SETUP_ERR="${SETUP_ERR} create ${REPO} on A failed;"
[ -n "$(curl -s --max-time 60 -u "$AUTH" -X POST -H 'Content-Type: application/json' -d "$body" "${B}/api/v1/repositories" | jq -r '.id // empty' 2>/dev/null)" ] \
  || SETUP_ERR="${SETUP_ERR} create ${REPO} on B failed;"
B_KEY="$(curl -s --max-time 30 -u "$AUTH" -X POST -H 'Content-Type: application/json' \
  -d "{\"name\":\"l6-peer-a-${SUF}\",\"scopes\":[\"*\"]}" "${B}/api/v1/auth/tokens" 2>/dev/null | jq -r '.token // empty' 2>/dev/null)"
[ -n "$B_KEY" ] || SETUP_ERR="${SETUP_ERR} could not mint an API key on B;"
PEER_ID="$(curl -s --max-time 60 -u "$AUTH" -X POST -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg n "l6-peer-b-${SLOT}-${SUF}" --arg k "$B_KEY" '{name:$n,endpoint_url:"http://peer-backend:8080",api_key:$k}')" \
  "${A}/api/v1/peers" 2>/dev/null | jq -r '.id // empty' 2>/dev/null)"
if [ -z "$PEER_ID" ]; then
  SETUP_ERR="${SETUP_ERR} peer registration on A failed;"
else
  backoff off
  c="$(code -u "$AUTH" -X POST -H 'Content-Type: application/json' \
    -d "{\"repository_id\":\"${RID:-x}\",\"sync_enabled\":true,\"replication_mode\":\"push\"}" \
    "${A}/api/v1/peers/${PEER_ID}/repositories")"
  [ "$c" = "200" ] || SETUP_ERR="${SETUP_ERR} subscribe ${REPO} -> ${c} $(head -c 200 "$W/last");"
fi
if [ -n "$SETUP_ERR" ]; then infra_fail "setup could not complete: ${SETUP_ERR}"; end_suite; exit $?; fi
echo "-- repository ${REPO}, peer ${PEER_ID}"
pass

# Five artifacts, each for one case.
P_CTL="ctl/c0.bin"; P_DEL="del/d0.bin"; P_LAB="lab/l0.bin"; P_RES="res/r0.bin"; P_PUR="pur/p.bin"
for f in ctl del lab res x1 x2; do printf 'l6 %s %s %s\n' "$f" "$SUF" "$(head -c 24 /dev/urandom | base64)" > "$W/$f"; done
S_CTL="$(sha "$W/ctl")"; S_DEL="$(sha "$W/del")"; S_LAB="$(sha "$W/lab")"; S_RES="$(sha "$W/res")"
S_X1="$(sha "$W/x1")"; S_X2="$(sha "$W/x2")"

begin_test "CONTROL: five generic uploads on A reach B (row, sha256, served bytes)"
reset_case
for spec in "$P_CTL:ctl" "$P_DEL:del" "$P_LAB:lab" "$P_RES:res" "$P_PUR:x1"; do
  c="$(put_a "${spec%%:*}" "$W/${spec##*:}")"
  [[ "$c" == 20? ]] || fail_g "PUT ${spec%%:*} on A answered ${c}: $(head -c 160 "$W/last")"
done
for spec in "$P_CTL:$S_CTL" "$P_DEL:$S_DEL" "$P_LAB:$S_LAB" "$P_RES:$S_RES" "$P_PUR:$S_X1"; do
  if await_b "${spec%%:*}" "200:${spec##*:}" 120; then note "${spec%%:*} on B: 200"; else
    fail_g "${spec%%:*} never reached B within 120 s (B serves $(served_b "${spec%%:*}"))"
  fi
done
X1_ID="$(id_a "$P_PUR")"
if [ "$FAILS" -ne 0 ]; then
  infra_fail "the push peer does not receive uploads; nothing below can be evaluated" "$DETAIL"; end_suite; exit $?
fi
pass

# =============================================================================
# Online peer: a label write, and a delete with no restore
# =============================================================================
LAB_ID="$(id_a "$P_LAB")"
lc="$(code -u "$AUTH" -X POST -H 'Content-Type: application/json' -d '{"value":"l6"}' \
  "${A}/api/v1/artifacts/${LAB_ID:-x}/labels/l6-tier")"
dc="$(del_a "$P_DEL")"
LAB_DELETES_AT_ONCE="$(psql_a "SELECT count(*) FROM sync_tasks WHERE peer_instance_id = '${PEER_ID}' AND artifact_id = '${LAB_ID:-$NIL}' AND task_type = 'delete'")"
sleep 30

begin_test "CONTROL: a delete on A with no restore reaches B (404)"
reset_case
note "DELETE ${P_DEL} on A: ${dc}"
[[ "$dc" == 20? ]] || fail_g "DELETE ${P_DEL} answered ${dc}"
if await_b "$P_DEL" "404:-" 60; then note "B: 404"; else fail_g "B still serves ${P_DEL} ($(served_b "$P_DEL")) 90 s after the delete"; fi
finish_case "deletes do not reach the push peer"

begin_test "FIX #5625: adding a label to an artifact replicated through a manual subscription queues no peer delete, and B keeps it"
reset_case
note "POST /api/v1/artifacts/{id}/labels/l6-tier on A: ${lc}; delete tasks for B right after: ${LAB_DELETES_AT_ONCE}; 30 s later: $(tasks "$LAB_ID" delete)"
[[ "$lc" == 20? ]] || fail_g "the label write answered ${lc}: $(head -c 160 "$W/last")"
nd="$(psql_a "SELECT count(*) FROM sync_tasks WHERE peer_instance_id = '${PEER_ID}' AND artifact_id = '${LAB_ID:-$NIL}' AND task_type = 'delete'")"
[ "${nd:-0}" = "0" ] || fail_g "the label write queued ${nd} delete task(s) for B ($(tasks "$LAB_ID" delete))"
got="$(served_b "$P_LAB")"
note "B serves ${P_LAB}: ${got}"
[ "$got" = "200:${S_LAB}" ] || fail_g "B no longer serves ${P_LAB} 30 s after the label write (${got}); A still has it"
finish_case "a label write deletes the artifact from a manually subscribed peer"

# =============================================================================
# Peer in backoff: delete + restore (#5505, #5627); purge + put + delete +
# restore at one path (#5699). Then the peer returns.
# =============================================================================
backoff on
RES_ID="$(id_a "$P_RES")"
rd="$(del_a "$P_RES")"
RES_DEL_QUEUED="$(tasks "$RES_ID" delete)"
rr="$(code -u "$AUTH" -X POST "${A}/api/v1/admin/trash/${RES_ID:-x}/restore")"
RES_RESTORE_BODY="$(head -c 160 "$W/last")"

pd="$(del_a "$P_PUR")"
pp="$(code -u "$AUTH" -X DELETE "${A}/api/v1/admin/trash/${X1_ID:-x}")"
PURGE_BODY="$(head -c 160 "$W/last")"
px="$(put_a "$P_PUR" "$W/x2")"
X2_ID="$(id_a "$P_PUR")"
pd2="$(del_a "$P_PUR")"
pr="$(code -u "$AUTH" -X POST "${A}/api/v1/admin/trash/${X2_ID:-x}/restore")"
PUR_RESTORE_BODY="$(head -c 160 "$W/last")"
PATH_DELETES="$(psql_a "SELECT string_agg(status::text, ',') FROM sync_tasks WHERE peer_instance_id = '${PEER_ID}' AND task_type = 'delete' \
  AND (artifact_id IN ('${X1_ID:-$NIL}', '${X2_ID:-$NIL}') OR artifact_id IS NULL)")"

begin_test "CONTROL: a delete made while B is in backoff is queued for B"
reset_case
note "DELETE ${P_RES}: ${rd}; delete tasks for B: ${RES_DEL_QUEUED:-none}"
[[ "$rd" == 20? ]] || fail_g "DELETE ${P_RES} answered ${rd}"
[[ "$RES_DEL_QUEUED" == pending:* ]] || fail_g "the delete queued '${RES_DEL_QUEUED:-none}' for B, expected one pending task"
finish_case "deletes are not queued for a peer in backoff"

backoff off
DRAIN_START="$(date +%s)"
drain 150; drained=$?
sleep 15
DRAIN_SECS=$(( $(date +%s) - DRAIN_START ))
echo "-- peer back; drain ${drained} (0 = no pending tasks) after ${DRAIN_SECS} s"

begin_test "FIX #5505: an artifact deleted while B was in backoff and restored before B returned is still served by B"
reset_case
note "restore ${P_RES}: ${rr} ${RES_RESTORE_BODY}"
[[ "$rr" == 20? ]] || fail_g "the restore answered ${rr}"
note "delete tasks for B now: $(tasks "$RES_ID" delete); push tasks: $(tasks "$RES_ID" push)"
got="$(served_b "$P_RES")"
note "B serves ${P_RES}: ${got}"
[ "$got" = "200:${S_RES}" ] || fail_g "B serves ${P_RES} as ${got} after the worker drained, expected the restored bytes: the restore left the delete queued"
finish_case "a restore does not cancel the queued peer delete"

begin_test "FIX #5627: the restore's re-push to B, which never applied the delete, ends completed and leaves no failed task"
reset_case
pt="$(tasks "$RES_ID" push)"
note "push tasks for ${P_RES}: ${pt:-none}; errors: $(task_errors "$RES_ID")"
case ",${pt}," in *",failed:"*) fail_g "a push task for the restored artifact ended failed (${pt})" ;; esac
last="${pt##*,}"
[[ "$last" == completed:* ]] || fail_g "the newest push task for the restored artifact is '${last:-none}', expected completed"
finish_case "a restore's re-push of identical bytes fails on the peer's 409"

begin_test "FIX #5699: after X1 is purged and X2 is put, deleted and restored at the same path, B serves X2 or 404, never the purged X1"
reset_case
note "DELETE X1 ${pd}, purge ${pp} ${PURGE_BODY}; PUT X2 ${px}; DELETE X2 ${pd2}; restore X2 ${pr} ${PUR_RESTORE_BODY}"
note "delete tasks at the path right after the restore: ${PATH_DELETES:-none}"
{ [[ "$pd" == 20? ]] && [[ "$pp" == 20? ]] && [[ "$px" == 20? ]] && [[ "$pd2" == 20? ]] && [[ "$pr" == 20? ]]; } \
  || fail_g "a step of the purge / put / delete / restore sequence did not answer 2xx"
got="$(served_b "$P_PUR")"
note "B serves ${P_PUR}: ${got} (X1 ${S_X1:0:12}, X2 ${S_X2:0:12})"
case "$got" in
  "200:${S_X1}") fail_g "B still serves the purged X1 bytes at ${P_PUR}" ;;
  "200:${S_X2}"|"404:-") ;;
  *) fail_g "B answers ${got} at ${P_PUR}, expected X2's bytes or 404" ;;
esac
finish_case "a restore at a purged path leaves the purged bytes on the peer"

end_suite
