#!/usr/bin/env bash
# test-partition-heal.sh - partition the hub from one peer, change the hub's
# repo while partitioned, heal, and require the peer to converge
# (artifact-keeper/artifact-keeper#6120)
#
# The partition is real packet loss in the hub pod's network namespace,
# injected by an EPHEMERAL netadmin debug container (tests/lib/netfault.sh).
# The backend container keeps its own spec and capabilities (drop ALL). The
# second peer is the control: it stays connected throughout, so the test
# shows that the fault cut exactly one link.
#
# Steps:
#   1. baseline: hub pushes one artifact to peer1 and peer2;
#   2. partition hub <-> peer1 (Service ClusterIP and pod IP, both ways), and
#      check from inside the hub's netns that peer1 is unreachable and peer2
#      is not;
#   3. while partitioned, upload two artifacts and delete the baseline one on
#      the hub: peer2 converges, peer1 does not, and the hub marks peer1
#      offline (stale detection, compressed by values-nightly-mesh.yaml);
#   4. heal: the hub probes peer1 back online, and peer1 converges on both
#      uploads (same bytes) AND the delete, with no manual sync call.
# SYNC_TASK_MAX_RETRIES is the product default (3), so step 4 also checks
# that a partition does not exhaust the retry budget of the work queued
# during it.
#
# Requires: MAIN_URL, PEER1_URL, PEER2_URL, MESH_NAMESPACE, and kubectl access
# to that namespace (pods/ephemeralcontainers patch, pods/exec create).
# HUB_RELEASE / PEER1_RELEASE default to ak-hub / ak-peer1.

source "$(dirname "$0")/../lib/common.sh"
source "$(dirname "$0")/../lib/mesh.sh"
source "$(dirname "$0")/../lib/netfault.sh"

HUB="${MAIN_URL:-}"
P1="${PEER1_URL:-}"
P2="${PEER2_URL:-}"
NS="${MESH_NAMESPACE:-}"
HUB_RELEASE="${HUB_RELEASE:-ak-hub}"
PEER1_RELEASE="${PEER1_RELEASE:-ak-peer1}"
PEER2_RELEASE="${PEER2_RELEASE:-ak-peer2}"
export BASE_URL="${HUB:-$BASE_URL}"

begin_suite "mesh-partition-heal"
setup_workdir

if [ -z "$HUB" ] || [ -z "$P1" ] || [ -z "$P2" ] || [ -z "$NS" ]; then
  skip_suite "MAIN_URL, PEER1_URL, PEER2_URL and MESH_NAMESPACE are required: multi-instance mesh only"
fi

SYNC_WAIT="${SYNC_WAIT:-60}"
OFFLINE_WAIT="${PARTITION_OFFLINE_WAIT:-120}"  # stale threshold 60 s + 20 s check cadence + margin
ONLINE_WAIT="${HEAL_ONLINE_WAIT:-45}"          # 10 s heartbeat probe
CONVERGE_WAIT="${HEAL_CONVERGE_WAIT:-150}"     # 30 s max backoff + retry reset + transfers
require_wait_budget $(( 2 * SYNC_WAIT + OFFLINE_WAIT + ONLINE_WAIT + CONVERGE_WAIT + NETFAULT_START_TIMEOUT )) \
  "baseline, control, offline, online and converge waits plus fault-container start (NETFAULT_START_TIMEOUT)"

begin_test "Fault injection is available (ephemeral containers + exec in ${NS})"
if netfault_preflight "$NS"; then
  pass
else
  infra_fail "runner cannot add ephemeral debug containers in ${NS}; the partition cannot be injected"
  end_suite
fi

pod_of() {
  kubectl -n "$NS" get pods -l "app.kubernetes.io/instance=$1,app.kubernetes.io/component=backend" \
    --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}'
}

begin_test "Resolve the hub pod and peer1's addresses"
HUB_POD=$(pod_of "$HUB_RELEASE" 2>/dev/null || true)
P1_POD=$(pod_of "$PEER1_RELEASE" 2>/dev/null || true)
P1_POD_IP=$(kubectl -n "$NS" get pod "$P1_POD" -o jsonpath='{.status.podIP}' 2>/dev/null || true)
P1_SVC_IP=$(kubectl -n "$NS" get svc "${PEER1_RELEASE}-backend" -o jsonpath='{.spec.clusterIP}' 2>/dev/null || true)
P1_HOST="${PEER1_RELEASE}-backend.${NS}.svc.cluster.local"
P2_HOST="${PEER2_RELEASE}-backend.${NS}.svc.cluster.local"
echo "  hub pod=${HUB_POD} peer1 pod=${P1_POD} podIP=${P1_POD_IP} svcIP=${P1_SVC_IP}"
if [ -n "$HUB_POD" ] && [ -n "$P1_POD_IP" ] && [ -n "$P1_SVC_IP" ]; then
  pass
else
  infra_fail "could not resolve the hub pod or peer1's pod/Service IP in ${NS}"
  end_suite
fi

mesh_init "$HUB" "$P1" "$P2"

SUFFIX=$(mesh_tag)
REPO="mesh-part-${SUFFIX}"
BASE="part/baseline.bin"
D1="part/during-1.bin"
D2="part/during-2.bin"
FAULT="netfault-$(date +%s)"
HEALED=false

# A cancelled or failing run must not leave the partition in place for the
# rest of the job (the debug container's watchdog also flushes it).
heal_on_exit() {
  if ! $HEALED && [ -n "${HUB_POD:-}" ]; then
    netfault_heal "$NS" "$HUB_POD" "$FAULT" >/dev/null 2>&1 || true
  fi
}
add_exit_handler heal_on_exit

begin_test "Create ${REPO} on hub, peer1 and peer2; link both peers on the hub (push)"
ok=true
for u in "$HUB" "$P1" "$P2"; do
  mesh_on "$u" create_local_repo "$REPO" generic || ok=false
done
ID1=$(mesh_link "$HUB" "$P1" "part1-${SUFFIX}") || ok=false
ID2=$(mesh_link "$HUB" "$P2" "part2-${SUFFIX}") || ok=false
if $ok; then
  mesh_subscribe "$HUB" "$ID1" "$REPO" push >/dev/null || ok=false
  mesh_subscribe "$HUB" "$ID2" "$REPO" push >/dev/null || ok=false
fi
if $ok; then pass; else fail_fatal "setup failed"; fi

for f in baseline d1 d2; do
  dd if=/dev/urandom bs=1024 count=8 of="${WORK_DIR}/${f}.bin" 2>/dev/null
done
D1_SHA=$(sha256sum "${WORK_DIR}/d1.bin" | awk '{print $1}')
D2_SHA=$(sha256sum "${WORK_DIR}/d2.bin" | awk '{print $1}')

begin_test "Baseline: an upload on the hub reaches both peers"
mesh_upload "$HUB" "$REPO" "$BASE" "${WORK_DIR}/baseline.bin" || true
if mesh_wait_all "$SYNC_WAIT" present "$REPO" "$BASE" "$P1" "$P2"; then
  pass
else
  fail_fatal "baseline replication failed; a partition test on a mesh that does not replicate proves nothing"
fi

begin_test "Partition hub <-> peer1 from an ephemeral netadmin container"
if netfault_partition "$NS" "$HUB_POD" backend "$FAULT" "$P1_POD_IP" "$P1_SVC_IP"; then
  PART_START=$(date +%s)
  pass
else
  infra_fail "could not start the fault container" \
    "$(kubectl -n "$NS" describe pod "$HUB_POD" 2>&1 | sed -n '/Ephemeral Containers/,/Conditions/p' | head -40)"
  end_suite
fi

begin_test "The fault is real and targeted: peer1 unreachable, peer2 reachable from the hub's netns"
if netfault_probe "$NS" "$HUB_POD" "$FAULT" "$P1_HOST" 8080; then
  fail_fatal "hub can still open TCP to peer1 (${P1_HOST}:8080) with the partition in place"
elif ! netfault_probe "$NS" "$HUB_POD" "$FAULT" "$P2_HOST" 8080; then
  fail_fatal "hub cannot reach peer2 either: the fault is not targeted (or peer2 is down)"
else
  pass
fi

begin_test "The hub detects the partition: peer1 goes offline within ${OFFLINE_WAIT}s"
if mesh_wait_peer_status "$HUB" "$ID1" offline "$OFFLINE_WAIT"; then
  echo "  offline $(( $(date +%s) - PART_START ))s after the partition started"
  pass
else
  fail "hub never marked peer1 offline (status: $(mesh_peer_status "$HUB" "$ID1"))"
fi

begin_test "While partitioned: upload two artifacts and delete the baseline on the hub"
if mesh_upload "$HUB" "$REPO" "$D1" "${WORK_DIR}/d1.bin" && \
   mesh_upload "$HUB" "$REPO" "$D2" "${WORK_DIR}/d2.bin" && \
   mesh_on "$HUB" api_delete "/api/v1/repositories/${REPO}/artifacts/${BASE}" >/dev/null; then
  pass
else
  fail_fatal "hub writes failed during the partition (the hub itself must stay writable)"
fi

begin_test "Control: peer2 converges during the partition"
ctl_deadline=$(( $(date +%s) + SYNC_WAIT ))
ctl_left() { local l=$(( ctl_deadline - $(date +%s) )); [ "$l" -lt 1 ] && l=1; echo "$l"; }
if mesh_wait_artifact "$P2" "$REPO" "$D1" "$(ctl_left)" && \
   mesh_wait_artifact "$P2" "$REPO" "$D2" "$(ctl_left)" && \
   mesh_wait_artifact "$P2" "$REPO" "$BASE" "$(ctl_left)" absent; then
  pass
else
  fail "peer2 (not partitioned) did not converge: the fault leaked beyond peer1, or replication is broken"
fi

begin_test "peer1 has not converged while partitioned"
s1=$(mesh_artifact_state "$P1" "$REPO" "$D1"); s2=$(mesh_artifact_state "$P1" "$REPO" "$D2")
sb=$(mesh_artifact_state "$P1" "$REPO" "$BASE")
if [ "$s1" = present ] || [ "$s2" = present ]; then
  fail "an upload made during the partition reached peer1: the partition is not effective"
elif [ "$sb" = absent ]; then
  fail "the delete made during the partition reached peer1: the partition is not effective"
elif [ "$s1" != absent ] || [ "$s2" != absent ] || [ "$sb" != present ]; then
  fail "could not read peer1 directly (${s1} ${s2} ${sb}); the runner reaches it without going through the hub"
else
  pass
fi

begin_test "Heal the partition"
if netfault_heal "$NS" "$HUB_POD" "$FAULT"; then
  HEALED=true
  HEAL_AT=$(date +%s)
  echo "  partition lasted $(( HEAL_AT - PART_START ))s"
  if netfault_probe "$NS" "$HUB_POD" "$FAULT" "$P1_HOST" 8080; then
    pass
  else
    fail_fatal "peer1 still unreachable from the hub after the heal"
  fi
else
  fail_fatal "could not flush the fault rules"
fi

begin_test "The hub brings peer1 back online within ${ONLINE_WAIT}s (its own heartbeat probe)"
if mesh_wait_peer_status "$HUB" "$ID1" online "$ONLINE_WAIT"; then
  echo "  online $(( $(date +%s) - HEAL_AT ))s after the heal"
  pass
else
  fail "peer1 is '$(mesh_peer_status "$HUB" "$ID1")' ${ONLINE_WAIT}s after the heal"
fi

begin_test "peer1 converges after the heal: both uploads (same bytes) and the delete, no manual sync"
ok=true
conv_deadline=$(( $(date +%s) + CONVERGE_WAIT ))
left() { local l=$(( conv_deadline - $(date +%s) )); [ "$l" -lt 1 ] && l=1; echo "$l"; }
mesh_wait_artifact "$P1" "$REPO" "$D1" "$(left)" || { ok=false; echo "  ${D1} never reached peer1"; }
mesh_wait_artifact "$P1" "$REPO" "$D2" "$(left)" || { ok=false; echo "  ${D2} never reached peer1"; }
mesh_wait_artifact "$P1" "$REPO" "$BASE" "$(left)" absent || { ok=false; echo "  ${BASE} still on peer1 (delete not applied)"; }
if $ok; then
  [ "$(mesh_download_sha "$P1" "$REPO" "$D1")" = "$D1_SHA" ] || { ok=false; echo "  ${D1}: checksum mismatch"; }
  [ "$(mesh_download_sha "$P1" "$REPO" "$D2")" = "$D2_SHA" ] || { ok=false; echo "  ${D2}: checksum mismatch"; }
fi
if $ok; then
  echo "  converged $(( $(date +%s) - HEAL_AT ))s after the heal"
  pass
else
  fail "peer1 did not converge within ${CONVERGE_WAIT}s of the heal" \
    "$(kubectl -n "$NS" logs "$HUB_POD" -c backend --since=10m 2>&1 | grep -iE 'sync task|peer|retry|backoff' | tail -40)"
fi

end_suite
