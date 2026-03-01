#!/usr/bin/env bash
# test-rolling-restart.sh - Verify data survives a rolling restart
#
# Uploads artifacts, triggers a rolling restart via kubectl, attempts
# reads during the rollout, and verifies that all data is intact and
# writes work after the rollout completes.
#
# Requires: kubectl, NAMESPACE

source "$(dirname "$0")/../../lib/common.sh"

begin_suite "restart-rolling"
require_cmd kubectl
auth_admin
setup_workdir

NAMESPACE="${NAMESPACE:-ak-test-${RUN_ID}}"
REPO_KEY="restart-rolling-${RUN_ID}"

# ---------------------------------------------------------------------------
# Upload baseline data
# ---------------------------------------------------------------------------

begin_test "Create generic repository"
if create_local_repo "$REPO_KEY" "generic"; then
  pass
else
  fail "could not create generic repo"
fi

begin_test "Upload baseline artifacts"
ARTIFACT_COUNT=5
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
# Trigger rolling restart
# ---------------------------------------------------------------------------

begin_test "Trigger rolling restart"
if kubectl rollout restart deployment/artifact-keeper-backend -n "${NAMESPACE}" 2>&1; then
  pass
else
  fail "kubectl rollout restart failed"
fi

# ---------------------------------------------------------------------------
# Attempt reads during rollout
# ---------------------------------------------------------------------------

begin_test "Read availability during rollout"
read_success=0
read_fail=0
for attempt in $(seq 1 10); do
  status=$(curl -s -o /dev/null -w '%{http_code}' \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts" 2>/dev/null || echo "000")
  if [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then
    read_success=$(( read_success + 1 ))
  else
    read_fail=$(( read_fail + 1 ))
  fi
  sleep 2
done
echo "  Reads during rollout: ${read_success} success, ${read_fail} failed"
# During a rolling restart, most reads should succeed (zero-downtime goal)
if [ "$read_success" -gt 0 ]; then
  pass
else
  fail "no reads succeeded during the rolling restart"
fi

# ---------------------------------------------------------------------------
# Wait for rollout to complete
# ---------------------------------------------------------------------------

begin_test "Wait for rollout to complete"
if kubectl rollout status deployment/artifact-keeper-backend \
    -n "${NAMESPACE}" --timeout=120s 2>&1; then
  pass
else
  fail "rollout did not complete within 120s"
fi

# ---------------------------------------------------------------------------
# Wait for health
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
  pass
else
  fail "health endpoint did not respond within 30s"
fi

# ---------------------------------------------------------------------------
# Verify data after rollout
# ---------------------------------------------------------------------------

begin_test "Re-authenticate after rolling restart"
if auth_admin 2>/dev/null; then
  pass
else
  fail "re-authentication failed"
fi

begin_test "Verify artifact count after rolling restart"
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
  fail "could not list artifacts after rolling restart"
fi

begin_test "Upload new artifact after rolling restart"
dd if=/dev/urandom bs=1024 count=2 of="${WORK_DIR}/post-restart.bin" 2>/dev/null
if api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/files/v1/post-restart.bin" \
    "${WORK_DIR}/post-restart.bin" "application/octet-stream" > /dev/null; then
  pass
else
  fail "write after rolling restart failed"
fi

end_suite
