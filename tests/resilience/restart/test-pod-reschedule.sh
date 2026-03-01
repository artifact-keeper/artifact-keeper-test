#!/usr/bin/env bash
# test-pod-reschedule.sh - Verify data survives pod deletion and reschedule
#
# Uploads artifacts with known checksums, deletes the specific pod (graceful),
# waits for Kubernetes to schedule a replacement, then downloads artifacts
# and verifies checksums match.
#
# Requires: kubectl, NAMESPACE

source "$(dirname "$0")/../../lib/common.sh"

begin_suite "restart-pod-reschedule"
require_cmd kubectl
auth_admin
setup_workdir

NAMESPACE="${NAMESPACE:-ak-test-${RUN_ID}}"
REPO_KEY="restart-resched-${RUN_ID}"

# ---------------------------------------------------------------------------
# Upload artifacts and record checksums
# ---------------------------------------------------------------------------

begin_test "Create generic repository"
if create_local_repo "$REPO_KEY" "generic"; then
  pass
else
  fail "could not create generic repo"
fi

begin_test "Upload artifacts and record checksums"
declare -a CHECKSUMS
for i in $(seq 1 3); do
  dd if=/dev/urandom bs=1024 count=4 of="${WORK_DIR}/file-${i}.bin" 2>/dev/null
  CHECKSUMS[$i]=$(shasum -a 256 "${WORK_DIR}/file-${i}.bin" | awk '{print $1}')
  if ! api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/files/v1/file-${i}.bin" \
      "${WORK_DIR}/file-${i}.bin" "application/octet-stream" > /dev/null; then
    fail "upload of file-${i} failed"
    break
  fi
done
if [ "$_FAIL_COUNT" -eq 0 ]; then
  echo "  Uploaded 3 artifacts with recorded SHA256 checksums"
  pass
fi

# ---------------------------------------------------------------------------
# Delete the specific pod (graceful)
# ---------------------------------------------------------------------------

begin_test "Delete specific backend pod"
POD_NAME=$(kubectl get pods -l app=artifact-keeper-backend \
  -n "${NAMESPACE}" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
if [ -z "$POD_NAME" ]; then
  fail "could not find backend pod"
else
  echo "  Deleting pod: ${POD_NAME}"
  if kubectl delete pod "$POD_NAME" -n "${NAMESPACE}" 2>&1; then
    pass
  else
    fail "kubectl delete pod failed"
  fi
fi

# ---------------------------------------------------------------------------
# Wait for new pod to be scheduled and ready
# ---------------------------------------------------------------------------

begin_test "Wait for replacement pod"
elapsed=0
pod_ready=false
while [ "$elapsed" -lt 60 ]; do
  ready=$(kubectl get pods -l app=artifact-keeper-backend \
    -n "${NAMESPACE}" -o jsonpath='{.items[*].status.containerStatuses[0].ready}' 2>/dev/null || true)
  if [ "$ready" = "true" ]; then
    NEW_POD=$(kubectl get pods -l app=artifact-keeper-backend \
      -n "${NAMESPACE}" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
    echo "  New pod: ${NEW_POD}"
    pod_ready=true
    break
  fi
  sleep 3
  elapsed=$(( elapsed + 3 ))
done
if [ "$pod_ready" = true ]; then
  echo "  Pod ready after ${elapsed}s"
  pass
else
  fail "replacement pod did not become ready within 60s"
fi

begin_test "Wait for health endpoint"
elapsed=0
health_ok=false
while [ "$elapsed" -lt 30 ]; do
  if curl -sf -o /dev/null "${BASE_URL}/health" 2>/dev/null; then
    health_ok=true
    break
  fi
  sleep 2
  elapsed=$(( elapsed + 2 ))
done
if [ "$health_ok" = true ]; then
  pass
else
  fail "health endpoint did not respond within 30s"
fi

# ---------------------------------------------------------------------------
# Re-auth, download, and verify checksums
# ---------------------------------------------------------------------------

begin_test "Re-authenticate after reschedule"
if auth_admin 2>/dev/null; then
  pass
else
  fail "re-authentication failed"
fi

begin_test "Download artifacts and verify checksums"
all_match=true
for i in $(seq 1 3); do
  if curl -sf -H "$(auth_header)" \
      -o "${WORK_DIR}/dl-file-${i}.bin" \
      "${BASE_URL}/api/v1/repositories/${REPO_KEY}/download/files/v1/file-${i}.bin"; then
    DL_SHA=$(shasum -a 256 "${WORK_DIR}/dl-file-${i}.bin" | awk '{print $1}')
    if [ "$DL_SHA" != "${CHECKSUMS[$i]}" ]; then
      fail "checksum mismatch for file-${i}: expected ${CHECKSUMS[$i]}, got ${DL_SHA}"
      all_match=false
      break
    fi
  else
    fail "could not download file-${i} after reschedule"
    all_match=false
    break
  fi
done
if [ "$all_match" = true ] && [ "$_FAIL_COUNT" -eq 0 ]; then
  pass
fi

end_suite
