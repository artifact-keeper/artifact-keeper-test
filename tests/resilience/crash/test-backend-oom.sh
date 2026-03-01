#!/usr/bin/env bash
# test-backend-oom.sh - Verify backend recovers from OOM-induced restarts
#
# Checks that the backend pod restarts after memory pressure and that
# data remains intact. Note: this test relies on the backend deployment
# having a low memory limit set (e.g., via Helm values:
#   backend.resources.limits.memory=64Mi). If the current limit is too
# generous to trigger OOM, the test will skip the kill-verification step.
#
# Requires: kubectl, NAMESPACE

source "$(dirname "$0")/../../lib/common.sh"

begin_suite "crash-backend-oom"
require_cmd kubectl
auth_admin
setup_workdir

NAMESPACE="${NAMESPACE:-ak-test-${RUN_ID}}"
REPO_KEY="crash-oom-${RUN_ID}"

# ---------------------------------------------------------------------------
# Create repository and upload baseline data
# ---------------------------------------------------------------------------

begin_test "Create generic repository"
if create_local_repo "$REPO_KEY" "generic"; then
  pass
else
  fail "could not create generic repo"
fi

begin_test "Upload baseline artifacts"
for i in $(seq 1 3); do
  dd if=/dev/urandom bs=1024 count=4 of="${WORK_DIR}/baseline-${i}.bin" 2>/dev/null
  if ! api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/files/v1/baseline-${i}.bin" \
      "${WORK_DIR}/baseline-${i}.bin" "application/octet-stream" > /dev/null; then
    fail "upload of baseline-${i} failed"
    break
  fi
done
if [ "$_FAIL_COUNT" -eq 0 ]; then
  pass
fi

# ---------------------------------------------------------------------------
# Record restart count before memory pressure
# ---------------------------------------------------------------------------

begin_test "Record pod restart count"
RESTARTS_BEFORE=$(kubectl get pods -l app=artifact-keeper-backend \
  -n "${NAMESPACE}" -o jsonpath='{.items[0].status.containerStatuses[0].restartCount}' 2>/dev/null || echo "0")
echo "  Restarts before: ${RESTARTS_BEFORE}"
pass

# ---------------------------------------------------------------------------
# Attempt to trigger memory pressure via large uploads
# ---------------------------------------------------------------------------

begin_test "Upload large payloads to trigger memory pressure"
# Generate a 10MB file and upload several copies in rapid succession
dd if=/dev/urandom bs=1048576 count=10 of="${WORK_DIR}/bigfile.bin" 2>/dev/null
upload_ok=true
for i in $(seq 1 5); do
  if ! api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/files/v1/big-${i}.bin" \
      "${WORK_DIR}/bigfile.bin" "application/octet-stream" > /dev/null 2>&1; then
    echo "  Upload ${i} failed (possibly OOM), continuing"
  fi
done
pass

# Give the pod time to be OOM-killed and restart
sleep 10

# ---------------------------------------------------------------------------
# Check for restarts
# ---------------------------------------------------------------------------

begin_test "Check if pod restarted"
RESTARTS_AFTER=$(kubectl get pods -l app=artifact-keeper-backend \
  -n "${NAMESPACE}" -o jsonpath='{.items[0].status.containerStatuses[0].restartCount}' 2>/dev/null || echo "0")
echo "  Restarts after: ${RESTARTS_AFTER}"
if [ "$RESTARTS_AFTER" -gt "$RESTARTS_BEFORE" ] 2>/dev/null; then
  echo "  Pod was restarted (OOM triggered as expected)"
  pass
else
  echo "  No OOM restart detected. Memory limit may be too generous for this test."
  echo "  Set backend.resources.limits.memory to a low value (e.g., 64Mi) to test OOM."
  skip "no OOM restart detected (memory limit may be too high)"
fi

# ---------------------------------------------------------------------------
# Wait for recovery
# ---------------------------------------------------------------------------

begin_test "Wait for backend to recover"
elapsed=0
health_ok=false
while [ "$elapsed" -lt 60 ]; do
  if curl -sf -o /dev/null "${BASE_URL}/health" 2>/dev/null; then
    health_ok=true
    break
  fi
  sleep 3
  elapsed=$(( elapsed + 3 ))
done
if [ "$health_ok" = true ]; then
  echo "  Backend healthy after ${elapsed}s"
  pass
else
  fail "backend did not recover within 60s"
fi

# ---------------------------------------------------------------------------
# Verify data integrity
# ---------------------------------------------------------------------------

begin_test "Re-authenticate and verify baseline data"
if auth_admin 2>/dev/null; then
  if resp=$(api_get "/api/v1/repositories/${REPO_KEY}/artifacts"); then
    if assert_contains "$resp" "baseline-1.bin" "should still contain baseline-1"; then
      pass
    fi
  else
    fail "could not list artifacts after recovery"
  fi
else
  fail "re-authentication failed after recovery"
fi

end_suite
