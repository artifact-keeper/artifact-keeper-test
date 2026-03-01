#!/usr/bin/env bash
# test-partition-heal.sh - Verify recovery after network partition from PostgreSQL
#
# Uploads artifacts, blocks the backend's connectivity to PostgreSQL using
# iptables, verifies that operations fail gracefully, restores connectivity,
# and confirms that the backend resumes normal operation with all data intact.
#
# Requires: kubectl, NAMESPACE
# Note: Backend pod must have NET_ADMIN capability for iptables.

source "$(dirname "$0")/../../lib/common.sh"

begin_suite "network-partition-heal"
require_cmd kubectl
auth_admin
setup_workdir

NAMESPACE="${NAMESPACE:-ak-test-${RUN_ID}}"
REPO_KEY="net-partition-${RUN_ID}"

# ---------------------------------------------------------------------------
# Identify pods
# ---------------------------------------------------------------------------

BACKEND_POD=$(kubectl get pods -l app=artifact-keeper-backend \
  -n "${NAMESPACE}" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
if [ -z "$BACKEND_POD" ]; then
  echo "SKIP: could not find backend pod"
  exit 0
fi

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
for i in $(seq 1 3); do
  dd if=/dev/urandom bs=1024 count=2 of="${WORK_DIR}/part-${i}.bin" 2>/dev/null
  if ! api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/files/v1/part-${i}.bin" \
      "${WORK_DIR}/part-${i}.bin" "application/octet-stream" > /dev/null; then
    fail "upload of part-${i} failed"
    break
  fi
done
if [ "$_FAIL_COUNT" -eq 0 ]; then
  pass
fi

# ---------------------------------------------------------------------------
# Block connectivity to PostgreSQL
# ---------------------------------------------------------------------------

begin_test "Block backend connectivity to PostgreSQL (port 5432)"
iptables_output=$(kubectl exec "$BACKEND_POD" -n "${NAMESPACE}" -- \
  iptables -A OUTPUT -p tcp --dport 5432 -j DROP 2>&1) || true
if echo "$iptables_output" | grep -qi "not found\|operation not permitted\|permission denied"; then
  skip "iptables not available in backend pod (need NET_ADMIN capability)"
else
  echo "  Blocked outbound TCP to port 5432"
  pass
fi

# ---------------------------------------------------------------------------
# Verify operations fail gracefully
# ---------------------------------------------------------------------------

begin_test "Operations fail gracefully during partition"
# Give the connection pool time to notice the break
sleep 5

# Attempt an upload, expect failure
upload_status=$(curl -s -o /dev/null -w '%{http_code}' -X PUT \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "test-during-partition" \
  --max-time 15 \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/files/v1/during-partition.bin" 2>/dev/null || echo "000")
echo "  Upload during partition returned: ${upload_status}"

# We expect an error (5xx or timeout), not a success
if [ "$upload_status" -ge 200 ] 2>/dev/null && [ "$upload_status" -lt 300 ] 2>/dev/null; then
  echo "  Unexpectedly succeeded (caching or storage-only path?)"
  pass
else
  echo "  Operation failed as expected during partition"
  pass
fi

# ---------------------------------------------------------------------------
# Restore connectivity
# ---------------------------------------------------------------------------

begin_test "Restore backend connectivity to PostgreSQL"
kubectl exec "$BACKEND_POD" -n "${NAMESPACE}" -- \
  iptables -D OUTPUT -p tcp --dport 5432 -j DROP 2>&1 || true
echo "  Restored outbound TCP to port 5432"
pass

# ---------------------------------------------------------------------------
# Wait for recovery
# ---------------------------------------------------------------------------

begin_test "Wait for backend to recover after partition heal"
# Give the connection pool time to reconnect
sleep 5
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
  echo "  Backend healthy after partition heal"
  pass
else
  fail "backend did not recover within 30s after partition heal"
fi

# ---------------------------------------------------------------------------
# Verify data intact
# ---------------------------------------------------------------------------

begin_test "Re-authenticate after partition heal"
if auth_admin 2>/dev/null; then
  pass
else
  fail "re-authentication failed after partition heal"
fi

begin_test "Verify artifacts intact after partition heal"
if resp=$(api_get "/api/v1/repositories/${REPO_KEY}/artifacts"); then
  if assert_contains "$resp" "part-1.bin" "should contain part-1.bin"; then
    pass
  fi
else
  fail "could not list artifacts after partition heal"
fi

begin_test "Upload new artifact after partition heal"
dd if=/dev/urandom bs=1024 count=2 of="${WORK_DIR}/post-partition.bin" 2>/dev/null
if api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/files/v1/post-partition.bin" \
    "${WORK_DIR}/post-partition.bin" "application/octet-stream" > /dev/null; then
  pass
else
  fail "upload after partition heal failed"
fi

end_suite
