#!/usr/bin/env bash
# test-packet-loss.sh - Verify operations tolerate moderate packet loss
#
# Drops 10% of the packets the backend pod receives, proves the loss is in
# effect (ping loss from the pod, the drop rule's packet counter), runs
# several upload/download operations and asserts that most succeed, then
# removes the loss and proves it is gone.
#
# The backend image has no iptables, so the rule is applied from the
# fault-net container that tests/lib/k8s.sh attaches to the backend pod
# (same network namespace; artifact-keeper-test#842). Loss uses iptables
# `-m statistic` on ingress, which needs no sch_netem on the node. A loss
# that cannot be applied or measured is INFRA (exit 11), never a skip.
#
# Requires: kubectl, NAMESPACE

source "$(dirname "$0")/../../lib/common.sh"
source "$(dirname "$0")/../../lib/k8s.sh"

begin_suite "network-packet-loss"
require_cmd kubectl
setup_workdir

NAMESPACE="${NAMESPACE:-ak-test-${RUN_ID}}"
REPO_KEY="net-pktloss-${RUN_ID}"
LOSS_PCT=10

# ---------------------------------------------------------------------------
# Fault injector
# ---------------------------------------------------------------------------

begin_test "Attach fault injector to the backend pod"
k8s_fault_injector_attach BACKEND_POD
IFACE=$(k8s_fault_net_iface "$BACKEND_POD" 2>/dev/null || true)
GATEWAY=$(k8s_fault_net_gateway "$BACKEND_POD" 2>/dev/null || true)
if [ -z "$IFACE" ] || [ -z "$GATEWAY" ]; then
  _k8s_fault_abort "could not read the backend pod's default route (iface='${IFACE}', gateway='${GATEWAY}')" \
    "$(k8s_fault_net "$BACKEND_POD" ip route 2>&1)"
fi
echo "  Interface ${IFACE}, gateway ${GATEWAY}"
pass

auth_admin

add_exit_handler 'k8s_fault_cleanup_loss "$BACKEND_POD"'

# ---------------------------------------------------------------------------
# Baseline uploads
# ---------------------------------------------------------------------------

begin_test "Create generic repository"
if create_local_repo "$REPO_KEY" "generic"; then
  pass
else
  fail "could not create generic repo"
fi

begin_test "Upload baseline artifacts"
baseline_ok=true
for i in $(seq 1 3); do
  dd if=/dev/urandom bs=1024 count=4 of="${WORK_DIR}/base-${i}.bin" 2>/dev/null
  if ! api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/files/v1/base-${i}.bin" \
      "${WORK_DIR}/base-${i}.bin" "application/octet-stream" > /dev/null; then
    fail "baseline upload ${i} failed"
    baseline_ok=false
    break
  fi
done
[ "$baseline_ok" = true ] && pass

begin_test "Measure baseline loss"
if ! k8s_fault_ping "$BACKEND_POD" "$GATEWAY" 50 0.05; then
  _k8s_fault_abort "could not ping the gateway ${GATEWAY} from the backend pod, so loss could not be measured"
fi
BASE_LOSS="$K8S_PING_LOSS"
echo "  Baseline loss: ${BASE_LOSS}%"
if [ "$BASE_LOSS" -gt 2 ]; then
  _k8s_fault_abort "the pod network already loses ${BASE_LOSS}% of pings without any fault; an injected loss would not be distinguishable"
fi
pass

# ---------------------------------------------------------------------------
# Inject packet loss
# ---------------------------------------------------------------------------

begin_test "Inject ${LOSS_PCT}% packet loss"
if ! loss_out=$(k8s_fault_net_loss_add "$BACKEND_POD" "$IFACE" "$LOSS_PCT" 2>&1); then
  _k8s_fault_abort "iptables could not add the loss rule in the backend pod" "$loss_out"
fi
echo "  iptables -S INPUT:"
k8s_fault_net "$BACKEND_POD" iptables -w -S INPUT 2>&1 | sed 's/^/    /'
pass

begin_test "Verify the loss is in effect"
k8s_fault_ping "$BACKEND_POD" "$GATEWAY" 200 0.02 || true
LOSSY="${K8S_PING_LOSS:-0}"
echo "  Measured loss: ${LOSSY}% (injected ${LOSS_PCT}%)"
# 200 pings at p=0.10: P(<2%) and P(>30%) are both below 1e-5.
if [ "$LOSSY" -lt 2 ] || [ "$LOSSY" -gt 30 ]; then
  _k8s_fault_abort "the loss rule is installed but the measured loss is ${LOSSY}%, not about ${LOSS_PCT}%" \
    "$(k8s_fault_net "$BACKEND_POD" iptables -w -L INPUT -v -n -x 2>&1)"
fi
pass

# ---------------------------------------------------------------------------
# Run operations under packet loss
# ---------------------------------------------------------------------------

begin_test "Upload operations under ${LOSS_PCT}% packet loss"
DROPS_BEFORE=$(k8s_fault_net_rule_packets "$BACKEND_POD" INPUT ak-fault-loss)
upload_success=0
upload_fail=0
TOTAL_ATTEMPTS=10
for i in $(seq 1 "$TOTAL_ATTEMPTS"); do
  dd if=/dev/urandom bs=1024 count=64 of="${WORK_DIR}/lossy-${i}.bin" 2>/dev/null
  if api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/files/v1/lossy-${i}.bin" \
      "${WORK_DIR}/lossy-${i}.bin" "application/octet-stream" > /dev/null 2>&1; then
    upload_success=$(( upload_success + 1 ))
  else
    upload_fail=$(( upload_fail + 1 ))
  fi
done
echo "  Uploads: ${upload_success} success, ${upload_fail} failed out of ${TOTAL_ATTEMPTS}"
if [ "$upload_success" -gt $(( TOTAL_ATTEMPTS / 2 )) ]; then
  pass
else
  fail "success rate too low: ${upload_success}/${TOTAL_ATTEMPTS}"
fi

begin_test "Download operations under ${LOSS_PCT}% packet loss"
dl_success=0
for i in $(seq 1 3); do
  want=$(shasum -a 256 "${WORK_DIR}/base-${i}.bin" | awk '{print $1}')
  if curl -sf $CURL_TIMEOUT -H "$(auth_header)" \
      -o "${WORK_DIR}/dl-base-${i}.bin" \
      "${BASE_URL}/api/v1/repositories/${REPO_KEY}/download/files/v1/base-${i}.bin" 2>/dev/null \
     && [ "$(shasum -a 256 "${WORK_DIR}/dl-base-${i}.bin" | awk '{print $1}')" = "$want" ]; then
    dl_success=$(( dl_success + 1 ))
  fi
done
echo "  Downloads with a matching checksum: ${dl_success} of 3"
if [ "$dl_success" -ge 2 ]; then
  pass
else
  fail "only ${dl_success}/3 downloads succeeded intact under packet loss"
fi

begin_test "Backend traffic was actually dropped during the operations"
DROPS_AFTER=$(k8s_fault_net_rule_packets "$BACKEND_POD" INPUT ak-fault-loss)
echo "  Packets dropped by the loss rule during the operations: $(( DROPS_AFTER - DROPS_BEFORE ))"
if [ "$DROPS_AFTER" -gt "$DROPS_BEFORE" ]; then
  pass
else
  _k8s_fault_abort "the loss rule dropped no packets while the operations ran, so they were not exercised under loss" \
    "$(k8s_fault_net "$BACKEND_POD" iptables -w -L INPUT -v -n -x 2>&1)"
fi

# ---------------------------------------------------------------------------
# Remove packet loss and verify recovery
# ---------------------------------------------------------------------------

begin_test "Remove packet loss injection"
k8s_fault_net_loss_del "$BACKEND_POD" >/dev/null 2>&1 || true
if k8s_fault_net "$BACKEND_POD" iptables -w -S INPUT 2>&1 | grep -q 'ak-fault-loss'; then
  _k8s_fault_abort "the loss rule is still installed after removal" \
    "$(k8s_fault_net "$BACKEND_POD" iptables -w -S INPUT 2>&1)"
fi
k8s_fault_ping "$BACKEND_POD" "$GATEWAY" 50 0.05 || true
echo "  Loss after removal: ${K8S_PING_LOSS:-?}%"
if [ "${K8S_PING_LOSS:-100}" -le 2 ]; then
  pass
else
  fail "loss did not clear after removing the rule (${K8S_PING_LOSS:-?}%)"
fi

begin_test "Verify normal operation after cleanup"
dd if=/dev/urandom bs=1024 count=4 of="${WORK_DIR}/verify.bin" 2>/dev/null
if api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/files/v1/verify.bin" \
    "${WORK_DIR}/verify.bin" "application/octet-stream" > /dev/null; then
  pass
else
  fail "upload after removing packet loss failed"
fi

end_suite
