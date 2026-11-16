#!/usr/bin/env bash
# test-schedule-mirror-pass.sh - a mirror subscription's replication_schedule
# fires, and an unscheduled one does not (artifact-keeper/artifact-keeper#6120)
#
# Product contract (backend services/peer_instance_service.rs, #5342): the
# sync worker checks `mirror` schedules on its first tick and every 6 ticks
# (60 s). A `mirror` subscription with a cron `replication_schedule` gets a
# whole-repository pass when it has never had one, or when an occurrence has
# passed since `last_replicated_at`. The pass queues a task for every artifact
# the peer has none for and stamps `last_replicated_at`. Assigning a
# subscription queues nothing by itself, and the upload hook only covers
# artifacts uploaded AFTER the subscription exists.
#
# So, with the artifacts uploaded BEFORE the subscriptions exist:
#   * R_SCHED (mirror, "* * * * *"): its artifact reaches the peer only
#     through a scheduled pass, and `last_replicated_at` is set;
#   * R_PLAIN (mirror, no schedule): its artifact must NOT reach the peer;
#   * the schedule recurs: `last_replicated_at` moves forward again.
# The gate's tests/mesh/test-replication-schedule.sh accepts any sync task
# created after its upload as evidence, which the upload hook alone already
# produces. This script is the stronger check, run beside it.
#
# Requires: MAIN_URL (hub) and PEER1_URL.

source "$(dirname "$0")/../lib/common.sh"
source "$(dirname "$0")/../lib/mesh.sh"

HUB="${MAIN_URL:-}"
PEER="${PEER1_URL:-}"
export BASE_URL="${HUB:-$BASE_URL}"

begin_suite "mesh-schedule-mirror-pass"
setup_workdir

if [ -z "$HUB" ] || [ -z "$PEER" ]; then
  skip_suite "MAIN_URL and PEER1_URL are required: multi-instance mesh only"
fi

FIRST_WAIT="${SCHEDULE_FIRST_WAIT:-150}"   # first mirror tick (<=60 s) + transfer
RECUR_WAIT="${SCHEDULE_RECUR_WAIT:-150}"   # next cron minute + next mirror tick
QUIET_WAIT="${SCHEDULE_QUIET_WAIT:-20}"
require_wait_budget $(( FIRST_WAIT + RECUR_WAIT + QUIET_WAIT )) "first pass, recurrence and quiet-period waits"

mesh_init "$HUB" "$PEER"

SUFFIX=$(mesh_tag)
R_SCHED="mesh-sched-${SUFFIX}"
R_PLAIN="mesh-plain-${SUFFIX}"
P="sched/payload.bin"

begin_test "Create both repos on hub and peer"
ok=true
for u in "$HUB" "$PEER"; do
  for r in "$R_SCHED" "$R_PLAIN"; do
    mesh_on "$u" create_local_repo "$r" generic || ok=false
  done
done
if $ok; then pass; else fail_fatal "repo creation failed"; fi

begin_test "Upload one artifact to each repo on the hub BEFORE any subscription exists"
dd if=/dev/urandom bs=1024 count=4 of="${WORK_DIR}/s.bin" 2>/dev/null
dd if=/dev/urandom bs=1024 count=4 of="${WORK_DIR}/p.bin" 2>/dev/null
S_SHA=$(sha256sum "${WORK_DIR}/s.bin" | awk '{print $1}')
if mesh_upload "$HUB" "$R_SCHED" "$P" "${WORK_DIR}/s.bin" && \
   mesh_upload "$HUB" "$R_PLAIN" "$P" "${WORK_DIR}/p.bin"; then
  pass
else
  fail_fatal "upload failed"
fi

begin_test "Subscribe the peer: ${R_SCHED} mirror with '* * * * *', ${R_PLAIN} mirror without a schedule"
PEER_ID=$(mesh_link "$HUB" "$PEER" "sched-${SUFFIX}") || PEER_ID=""
if [ -n "$PEER_ID" ] && \
   RID_SCHED=$(mesh_subscribe "$HUB" "$PEER_ID" "$R_SCHED" mirror '* * * * *') && \
   RID_PLAIN=$(mesh_subscribe "$HUB" "$PEER_ID" "$R_PLAIN" mirror); then
  pass
else
  fail_fatal "peer link or subscription failed"
fi

last_replicated() {
  { mesh_on "$HUB" api_get "/api/v1/peers/${PEER_ID}/repositories/$1" 2>/dev/null \
    | jq -r '.last_replicated_at // empty'; } || true
}

begin_test "The scheduled pass replicates the pre-existing artifact within ${FIRST_WAIT}s"
if mesh_wait_artifact "$PEER" "$R_SCHED" "$P" "$FIRST_WAIT"; then
  if [ "$(mesh_download_sha "$PEER" "$R_SCHED" "$P")" = "$S_SHA" ]; then
    pass
  else
    fail "scheduled artifact reached the peer with different bytes"
  fi
else
  fail "no scheduled mirror pass delivered the pre-existing artifact within ${FIRST_WAIT}s"
fi

begin_test "The scheduled subscription records its pass (last_replicated_at set)"
T1=$(last_replicated "$RID_SCHED") || T1=""
if [ -n "$T1" ]; then
  echo "  last_replicated_at=${T1}"
  pass
else
  fail "last_replicated_at is still null after the artifact arrived"
fi

begin_test "The unscheduled mirror subscription runs no pass (artifact stays on the hub only)"
sleep "$QUIET_WAIT"
T_PLAIN=$(last_replicated "$RID_PLAIN") || T_PLAIN=""
plain_state=$(mesh_artifact_state "$PEER" "$R_PLAIN" "$P")
if [ "$plain_state" = present ]; then
  fail "the unscheduled repo's pre-existing artifact reached the peer: something other than the schedule queued a whole-repo pass"
elif [ "$plain_state" != absent ]; then
  fail "could not read the unscheduled repo on the peer (${plain_state})"
elif [ -n "$T_PLAIN" ]; then
  fail "the unscheduled subscription has last_replicated_at=${T_PLAIN}"
else
  pass
fi

begin_test "The schedule recurs: last_replicated_at advances within ${RECUR_WAIT}s"
if [ -z "$T1" ]; then
  skip "no first pass to compare against (failure recorded above)"
else
  deadline=$(( $(date +%s) + RECUR_WAIT )); T2="$T1"; advanced=false
  while [ "$(date +%s)" -lt "$deadline" ]; do
    T2=$(last_replicated "$RID_SCHED") || T2=""
    if [ -n "$T2" ] && [ "$T2" != "$T1" ] && \
       [ "$(date -d "$T2" +%s 2>/dev/null || echo 0)" -gt "$(date -d "$T1" +%s 2>/dev/null || echo 0)" ]; then
      advanced=true
      break
    fi
    sleep 5
  done
  if $advanced; then
    echo "  ${T1} -> ${T2}"
    pass
  else
    fail "last_replicated_at stayed at ${T1} for ${RECUR_WAIT}s with a '* * * * *' schedule"
  fi
fi

end_suite
