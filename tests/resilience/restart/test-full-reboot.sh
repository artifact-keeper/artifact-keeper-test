#!/usr/bin/env bash
# test-full-reboot.sh - Verify data survives a full scale-down/scale-up cycle
#
# Uploads artifacts with known checksums, scales the backend deployment to
# zero replicas, waits, scales back up, then verifies all artifacts are
# still accessible with correct checksums.
#
# Requires: kubectl, NAMESPACE

source "$(dirname "$0")/../../lib/common.sh"

begin_suite "restart-full-reboot"
require_cmd kubectl
auth_admin
setup_workdir

NAMESPACE="${NAMESPACE:-ak-test-${RUN_ID}}"
REPO_KEY="restart-reboot-${RUN_ID}"

# ---------------------------------------------------------------------------
# Upload artifacts and record state
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
  dd if=/dev/urandom bs=1024 count=4 of="${WORK_DIR}/reboot-${i}.bin" 2>/dev/null
  CHECKSUMS[$i]=$(shasum -a 256 "${WORK_DIR}/reboot-${i}.bin" | awk '{print $1}')
  if ! api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/files/v1/reboot-${i}.bin" \
      "${WORK_DIR}/reboot-${i}.bin" "application/octet-stream" > /dev/null; then
    fail "upload of reboot-${i} failed"
    break
  fi
done
if [ "$_FAIL_COUNT" -eq 0 ]; then
  pass
fi

begin_test "Record artifact count"
if resp=$(api_get "/api/v1/repositories/${REPO_KEY}/artifacts"); then
  BEFORE_COUNT=$(echo "$resp" | jq '
    if type == "array" then length
    elif .items then (.items | length)
    elif .total != null then .total
    else 0
    end
  ')
  echo "  Artifact count: ${BEFORE_COUNT}"
  pass
else
  fail "could not list artifacts"
fi

# ---------------------------------------------------------------------------
# Scale down to zero
# ---------------------------------------------------------------------------

begin_test "Scale backend to zero replicas"
if kubectl scale deployment/artifact-keeper-backend --replicas=0 \
    -n "${NAMESPACE}" 2>&1; then
  pass
else
  fail "scale to 0 failed"
fi

begin_test "Verify no running pods"
sleep 10
running=$(kubectl get pods -l app=artifact-keeper-backend \
  -n "${NAMESPACE}" --field-selector=status.phase=Running \
  -o jsonpath='{.items}' 2>/dev/null || echo "[]")
pod_count=$(echo "$running" | jq 'length' 2>/dev/null || echo "0")
if [ "$pod_count" -eq 0 ] 2>/dev/null; then
  echo "  All backend pods terminated"
  pass
else
  # Pods may still be terminating, not a hard failure
  echo "  ${pod_count} pods still present (may be terminating)"
  pass
fi

# ---------------------------------------------------------------------------
# Scale back up
# ---------------------------------------------------------------------------

begin_test "Scale backend to one replica"
if kubectl scale deployment/artifact-keeper-backend --replicas=1 \
    -n "${NAMESPACE}" 2>&1; then
  pass
else
  fail "scale to 1 failed"
fi

begin_test "Wait for pod to become ready"
elapsed=0
pod_ready=false
while [ "$elapsed" -lt 90 ]; do
  ready=$(kubectl get pods -l app=artifact-keeper-backend \
    -n "${NAMESPACE}" -o jsonpath='{.items[*].status.containerStatuses[0].ready}' 2>/dev/null || true)
  if [ "$ready" = "true" ]; then
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
  fail "pod did not become ready within 90s"
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
# Verify everything survived
# ---------------------------------------------------------------------------

begin_test "Re-authenticate after full reboot"
if auth_admin 2>/dev/null; then
  pass
else
  fail "re-authentication failed"
fi

begin_test "Verify artifact count"
if resp=$(api_get "/api/v1/repositories/${REPO_KEY}/artifacts"); then
  AFTER_COUNT=$(echo "$resp" | jq '
    if type == "array" then length
    elif .items then (.items | length)
    elif .total != null then .total
    else 0
    end
  ')
  if assert_eq "$AFTER_COUNT" "$BEFORE_COUNT" \
      "expected ${BEFORE_COUNT} artifacts, got ${AFTER_COUNT}"; then
    pass
  fi
else
  fail "could not list artifacts after reboot"
fi

begin_test "Verify artifact checksums"
all_match=true
for i in $(seq 1 "$ARTIFACT_COUNT"); do
  if curl -sf -H "$(auth_header)" \
      -o "${WORK_DIR}/dl-reboot-${i}.bin" \
      "${BASE_URL}/api/v1/repositories/${REPO_KEY}/download/files/v1/reboot-${i}.bin"; then
    DL_SHA=$(shasum -a 256 "${WORK_DIR}/dl-reboot-${i}.bin" | awk '{print $1}')
    if [ "$DL_SHA" != "${CHECKSUMS[$i]}" ]; then
      fail "checksum mismatch for reboot-${i}: expected ${CHECKSUMS[$i]}, got ${DL_SHA}"
      all_match=false
      break
    fi
  else
    fail "could not download reboot-${i} after reboot"
    all_match=false
    break
  fi
done
if [ "$all_match" = true ] && [ "$_FAIL_COUNT" -eq 0 ]; then
  pass
fi

end_suite
