#!/usr/bin/env bash
# test-pvc-remount.sh - Verify data survives PVC detach/reattach cycle
#
# Uploads artifacts with known checksums, restarts the backend pod (which
# triggers a PVC unmount/remount), then downloads and verifies all
# artifacts still have correct checksums.
#
# Requires: kubectl, NAMESPACE

source "$(dirname "$0")/../../lib/common.sh"

begin_suite "storage-pvc-remount"
require_cmd kubectl
auth_admin
setup_workdir

NAMESPACE="${NAMESPACE:-ak-test-${RUN_ID}}"
REPO_KEY="store-pvc-${RUN_ID}"

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
ARTIFACT_COUNT=4
for i in $(seq 1 "$ARTIFACT_COUNT"); do
  dd if=/dev/urandom bs=1024 count=8 of="${WORK_DIR}/pvc-${i}.bin" 2>/dev/null
  CHECKSUMS[$i]=$(shasum -a 256 "${WORK_DIR}/pvc-${i}.bin" | awk '{print $1}')
  if ! api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/files/v1/pvc-${i}.bin" \
      "${WORK_DIR}/pvc-${i}.bin" "application/octet-stream" > /dev/null; then
    fail "upload of pvc-${i} failed"
    break
  fi
done
if [ "$_FAIL_COUNT" -eq 0 ]; then
  echo "  Uploaded ${ARTIFACT_COUNT} artifacts"
  pass
fi

# ---------------------------------------------------------------------------
# Restart pod to trigger PVC detach/reattach
# ---------------------------------------------------------------------------

begin_test "Delete backend pod to trigger PVC remount"
POD_BEFORE=$(kubectl get pods -l app=artifact-keeper-backend \
  -n "${NAMESPACE}" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
echo "  Deleting pod: ${POD_BEFORE}"
if kubectl delete pod "$POD_BEFORE" -n "${NAMESPACE}" 2>&1; then
  pass
else
  fail "pod deletion failed"
fi

# ---------------------------------------------------------------------------
# Wait for new pod with PVC mounted
# ---------------------------------------------------------------------------

begin_test "Wait for new pod with PVC attached"
elapsed=0
pod_ready=false
while [ "$elapsed" -lt 90 ]; do
  ready=$(kubectl get pods -l app=artifact-keeper-backend \
    -n "${NAMESPACE}" -o jsonpath='{.items[*].status.containerStatuses[0].ready}' 2>/dev/null || true)
  if [ "$ready" = "true" ]; then
    POD_AFTER=$(kubectl get pods -l app=artifact-keeper-backend \
      -n "${NAMESPACE}" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
    echo "  New pod: ${POD_AFTER}"
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
  fail "new pod did not become ready within 90s (PVC may be stuck)"
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
# Verify all artifacts accessible with correct checksums
# ---------------------------------------------------------------------------

begin_test "Re-authenticate after PVC remount"
if auth_admin 2>/dev/null; then
  pass
else
  fail "re-authentication failed"
fi

begin_test "Verify artifact checksums after PVC remount"
all_match=true
for i in $(seq 1 "$ARTIFACT_COUNT"); do
  if curl -sf -H "$(auth_header)" \
      -o "${WORK_DIR}/dl-pvc-${i}.bin" \
      "${BASE_URL}/api/v1/repositories/${REPO_KEY}/download/files/v1/pvc-${i}.bin"; then
    DL_SHA=$(shasum -a 256 "${WORK_DIR}/dl-pvc-${i}.bin" | awk '{print $1}')
    if [ "$DL_SHA" != "${CHECKSUMS[$i]}" ]; then
      fail "checksum mismatch for pvc-${i}: expected ${CHECKSUMS[$i]}, got ${DL_SHA}"
      all_match=false
      break
    fi
  else
    fail "could not download pvc-${i} after PVC remount"
    all_match=false
    break
  fi
done
if [ "$all_match" = true ] && [ "$_FAIL_COUNT" -eq 0 ]; then
  echo "  All ${ARTIFACT_COUNT} checksums verified"
  pass
fi

end_suite
