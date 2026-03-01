#!/usr/bin/env bash
# test-packet-loss.sh - Verify operations tolerate moderate packet loss
#
# Injects 10% packet loss on the backend pod using tc/netem, runs multiple
# upload/download operations, and asserts that more than half succeed.
# Cleans up netem rules afterward.
#
# Requires: kubectl, NAMESPACE
# Note: Backend pod needs iproute2 and NET_ADMIN capability.

source "$(dirname "$0")/../../lib/common.sh"

begin_suite "network-packet-loss"
require_cmd kubectl
auth_admin
setup_workdir

NAMESPACE="${NAMESPACE:-ak-test-${RUN_ID}}"
REPO_KEY="net-pktloss-${RUN_ID}"

# ---------------------------------------------------------------------------
# Identify backend pod
# ---------------------------------------------------------------------------

BACKEND_POD=$(kubectl get pods -l app=artifact-keeper-backend \
  -n "${NAMESPACE}" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
if [ -z "$BACKEND_POD" ]; then
  echo "SKIP: could not find backend pod"
  exit 0
fi

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
for i in $(seq 1 3); do
  dd if=/dev/urandom bs=1024 count=4 of="${WORK_DIR}/base-${i}.bin" 2>/dev/null
  if ! api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/files/v1/base-${i}.bin" \
      "${WORK_DIR}/base-${i}.bin" "application/octet-stream" > /dev/null; then
    fail "baseline upload ${i} failed"
    break
  fi
done
if [ "$_FAIL_COUNT" -eq 0 ]; then
  pass
fi

# ---------------------------------------------------------------------------
# Inject packet loss
# ---------------------------------------------------------------------------

begin_test "Inject 10% packet loss via tc netem"
tc_output=$(kubectl exec "$BACKEND_POD" -n "${NAMESPACE}" -- \
  tc qdisc add dev eth0 root netem loss 10% 2>&1) || true
if echo "$tc_output" | grep -qi "not found\|no such file\|operation not permitted"; then
  skip "tc/netem not available in backend pod (need iproute2 and NET_ADMIN capability)"
else
  echo "  Packet loss injection applied (10%)"
  pass
fi

# ---------------------------------------------------------------------------
# Run operations under packet loss
# ---------------------------------------------------------------------------

begin_test "Upload operations under 10% packet loss"
upload_success=0
upload_fail=0
TOTAL_ATTEMPTS=10
for i in $(seq 1 "$TOTAL_ATTEMPTS"); do
  dd if=/dev/urandom bs=1024 count=4 of="${WORK_DIR}/lossy-${i}.bin" 2>/dev/null
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

begin_test "Download operations under 10% packet loss"
dl_success=0
dl_fail=0
for i in $(seq 1 3); do
  if curl -sf -H "$(auth_header)" \
      -o "${WORK_DIR}/dl-base-${i}.bin" \
      "${BASE_URL}/api/v1/repositories/${REPO_KEY}/download/files/v1/base-${i}.bin" 2>/dev/null; then
    dl_success=$(( dl_success + 1 ))
  else
    dl_fail=$(( dl_fail + 1 ))
  fi
done
echo "  Downloads: ${dl_success} success, ${dl_fail} failed out of 3"
if [ "$dl_success" -gt 0 ]; then
  pass
else
  fail "no downloads succeeded under packet loss"
fi

# ---------------------------------------------------------------------------
# Clean up netem rules
# ---------------------------------------------------------------------------

begin_test "Remove packet loss injection"
kubectl exec "$BACKEND_POD" -n "${NAMESPACE}" -- \
  tc qdisc del dev eth0 root netem 2>&1 || true
echo "  Packet loss removed"
pass

# ---------------------------------------------------------------------------
# Verify normal operation
# ---------------------------------------------------------------------------

begin_test "Verify normal operation after cleanup"
dd if=/dev/urandom bs=1024 count=4 of="${WORK_DIR}/verify.bin" 2>/dev/null
if api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/files/v1/verify.bin" \
    "${WORK_DIR}/verify.bin" "application/octet-stream" > /dev/null; then
  pass
else
  fail "upload after removing packet loss failed"
fi

end_suite
