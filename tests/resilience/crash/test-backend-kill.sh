#!/usr/bin/env bash
# test-backend-kill.sh - Verify data survives a forced backend pod kill
#
# Uploads artifacts, force-kills the backend pod, waits for recovery,
# then verifies all previously uploaded data is still accessible and
# that new writes succeed.
#
# Requires: kubectl, NAMESPACE

source "$(dirname "$0")/../../lib/common.sh"

begin_suite "crash-backend-kill"
require_cmd kubectl
auth_admin
setup_workdir

NAMESPACE="${NAMESPACE:-ak-test-${RUN_ID}}"
REPO_KEY="crash-kill-${RUN_ID}"

# ---------------------------------------------------------------------------
# Create repository and upload baseline artifacts
# ---------------------------------------------------------------------------

begin_test "Create generic repository"
if create_local_repo "$REPO_KEY" "generic"; then
  pass
else
  fail "could not create generic repo"
fi

begin_test "Upload baseline artifacts"
ARTIFACT_COUNT=3
for i in $(seq 1 "$ARTIFACT_COUNT"); do
  dd if=/dev/urandom bs=1024 count=2 of="${WORK_DIR}/artifact-${i}.bin" 2>/dev/null
  if ! api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/files/v1/artifact-${i}.bin" \
      "${WORK_DIR}/artifact-${i}.bin" "application/octet-stream" > /dev/null; then
    fail "upload of artifact-${i} failed"
    break
  fi
done
if [ "$_FAIL_COUNT" -eq 0 ]; then
  pass
fi

begin_test "Record artifact count before kill"
if resp=$(api_get "/api/v1/repositories/${REPO_KEY}/artifacts"); then
  BEFORE_COUNT=$(echo "$resp" | jq '
    if type == "array" then length
    elif .items then (.items | length)
    elif .total != null then .total
    else 0
    end
  ')
  echo "  Artifact count before kill: ${BEFORE_COUNT}"
  pass
else
  fail "could not list artifacts"
fi

# ---------------------------------------------------------------------------
# Force-kill the backend pod
# ---------------------------------------------------------------------------

begin_test "Force-kill backend pod"
if kubectl delete pod -l app=artifact-keeper-backend \
    --force --grace-period=0 -n "${NAMESPACE}" 2>&1; then
  pass
else
  fail "kubectl delete pod failed"
fi

# ---------------------------------------------------------------------------
# Wait for pod to come back
# ---------------------------------------------------------------------------

begin_test "Wait for backend pod to become ready"
elapsed=0
pod_ready=false
while [ "$elapsed" -lt 60 ]; do
  ready_count=$(kubectl get pods -l app=artifact-keeper-backend \
    -n "${NAMESPACE}" -o jsonpath='{.items[*].status.containerStatuses[0].ready}' 2>/dev/null || true)
  if [ "$ready_count" = "true" ]; then
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
  fail "backend pod did not become ready within 60s"
fi

# ---------------------------------------------------------------------------
# Wait for health endpoint
# ---------------------------------------------------------------------------

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
  echo "  Health endpoint responded after ${elapsed}s"
  pass
else
  fail "health endpoint did not respond within 30s"
fi

# ---------------------------------------------------------------------------
# Re-auth and verify data
# ---------------------------------------------------------------------------

begin_test "Re-authenticate after restart"
if auth_admin 2>/dev/null; then
  pass
else
  fail "re-authentication failed"
fi

begin_test "Verify artifact count matches"
if resp=$(api_get "/api/v1/repositories/${REPO_KEY}/artifacts"); then
  AFTER_COUNT=$(echo "$resp" | jq '
    if type == "array" then length
    elif .items then (.items | length)
    elif .total != null then .total
    else 0
    end
  ')
  if assert_eq "$AFTER_COUNT" "$BEFORE_COUNT" \
      "expected ${BEFORE_COUNT} artifacts after kill, got ${AFTER_COUNT}"; then
    pass
  fi
else
  fail "could not list artifacts after kill"
fi

# ---------------------------------------------------------------------------
# Verify writes still work
# ---------------------------------------------------------------------------

begin_test "Upload new artifact after recovery"
dd if=/dev/urandom bs=1024 count=2 of="${WORK_DIR}/post-kill.bin" 2>/dev/null
if api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/files/v1/post-kill.bin" \
    "${WORK_DIR}/post-kill.bin" "application/octet-stream" > /dev/null; then
  pass
else
  fail "write after recovery failed"
fi

end_suite
