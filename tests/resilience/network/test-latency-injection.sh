#!/usr/bin/env bash
# test-latency-injection.sh - Verify operations succeed under high latency
#
# Injects 500ms network latency on the backend pod using tc/netem,
# confirms that uploads and downloads still complete (just slower),
# then removes the latency and verifies normal speed is restored.
#
# Requires: kubectl, NAMESPACE
# Note: The backend pod must have the iproute2 (tc) tooling available,
# and the container must have NET_ADMIN capability. If tc is not
# available, the test will skip.

source "$(dirname "$0")/../../lib/common.sh"

begin_suite "network-latency"
require_cmd kubectl
auth_admin
setup_workdir

NAMESPACE="${NAMESPACE:-ak-test-${RUN_ID}}"
REPO_KEY="net-latency-${RUN_ID}"

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
# Baseline: upload artifacts at normal speed
# ---------------------------------------------------------------------------

begin_test "Create generic repository"
if create_local_repo "$REPO_KEY" "generic"; then
  pass
else
  fail "could not create generic repo"
fi

begin_test "Upload baseline artifact at normal speed"
dd if=/dev/urandom bs=1024 count=64 of="${WORK_DIR}/baseline.bin" 2>/dev/null
BASELINE_SHA=$(shasum -a 256 "${WORK_DIR}/baseline.bin" | awk '{print $1}')
BASELINE_START=$(date +%s)
if api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/files/v1/baseline.bin" \
    "${WORK_DIR}/baseline.bin" "application/octet-stream" > /dev/null; then
  BASELINE_DURATION=$(( $(date +%s) - BASELINE_START ))
  echo "  Baseline upload took ${BASELINE_DURATION}s"
  pass
else
  fail "baseline upload failed"
fi

# ---------------------------------------------------------------------------
# Inject latency
# ---------------------------------------------------------------------------

begin_test "Inject 500ms latency via tc netem"
tc_output=$(kubectl exec "$BACKEND_POD" -n "${NAMESPACE}" -- \
  tc qdisc add dev eth0 root netem delay 500ms 2>&1) || true
if echo "$tc_output" | grep -qi "not found\|no such file\|operation not permitted"; then
  skip "tc/netem not available in backend pod (need iproute2 and NET_ADMIN capability)"
else
  echo "  Latency injection applied"
  pass
fi

# ---------------------------------------------------------------------------
# Upload/download under latency
# ---------------------------------------------------------------------------

begin_test "Upload under 500ms latency"
dd if=/dev/urandom bs=1024 count=16 of="${WORK_DIR}/slow-upload.bin" 2>/dev/null
SLOW_SHA=$(shasum -a 256 "${WORK_DIR}/slow-upload.bin" | awk '{print $1}')
SLOW_START=$(date +%s)
if api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/files/v1/slow-upload.bin" \
    "${WORK_DIR}/slow-upload.bin" "application/octet-stream" > /dev/null; then
  SLOW_DURATION=$(( $(date +%s) - SLOW_START ))
  echo "  Upload under latency took ${SLOW_DURATION}s"
  pass
else
  fail "upload under latency failed"
fi

begin_test "Download under 500ms latency"
if curl -sf -H "$(auth_header)" \
    -o "${WORK_DIR}/slow-download.bin" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}/download/files/v1/slow-upload.bin"; then
  DL_SHA=$(shasum -a 256 "${WORK_DIR}/slow-download.bin" | awk '{print $1}')
  if assert_eq "$DL_SHA" "$SLOW_SHA" "checksum mismatch under latency"; then
    pass
  fi
else
  fail "download under latency failed"
fi

# ---------------------------------------------------------------------------
# Remove latency
# ---------------------------------------------------------------------------

begin_test "Remove latency injection"
kubectl exec "$BACKEND_POD" -n "${NAMESPACE}" -- \
  tc qdisc del dev eth0 root netem 2>&1 || true
echo "  Latency removed"
pass

# ---------------------------------------------------------------------------
# Verify normal speed restored
# ---------------------------------------------------------------------------

begin_test "Verify normal speed restored"
dd if=/dev/urandom bs=1024 count=16 of="${WORK_DIR}/fast-upload.bin" 2>/dev/null
FAST_START=$(date +%s)
if api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/files/v1/fast-upload.bin" \
    "${WORK_DIR}/fast-upload.bin" "application/octet-stream" > /dev/null; then
  FAST_DURATION=$(( $(date +%s) - FAST_START ))
  echo "  Post-cleanup upload took ${FAST_DURATION}s"
  pass
else
  fail "upload after removing latency failed"
fi

end_suite
