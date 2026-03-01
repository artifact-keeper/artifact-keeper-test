#!/usr/bin/env bash
# test-storage-readonly.sh - Verify clean error handling with read-only storage
#
# Makes the storage directory read-only inside the backend pod, verifies
# uploads fail with clean error messages, restores write permissions,
# and verifies uploads work again.
#
# Requires: kubectl, NAMESPACE
# Note: Backend pod must be running as root or have permissions to chmod /data.

source "$(dirname "$0")/../../lib/common.sh"

begin_suite "storage-readonly"
require_cmd kubectl
auth_admin
setup_workdir

NAMESPACE="${NAMESPACE:-ak-test-${RUN_ID}}"
REPO_KEY="store-ro-${RUN_ID}"

BACKEND_POD=$(kubectl get pods -l app=artifact-keeper-backend \
  -n "${NAMESPACE}" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
if [ -z "$BACKEND_POD" ]; then
  echo "SKIP: could not find backend pod"
  exit 0
fi

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

begin_test "Create generic repository"
if create_local_repo "$REPO_KEY" "generic"; then
  pass
else
  fail "could not create generic repo"
fi

begin_test "Upload artifact before making storage read-only"
dd if=/dev/urandom bs=1024 count=4 of="${WORK_DIR}/before-ro.bin" 2>/dev/null
BEFORE_SHA=$(shasum -a 256 "${WORK_DIR}/before-ro.bin" | awk '{print $1}')
if api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/files/v1/before-ro.bin" \
    "${WORK_DIR}/before-ro.bin" "application/octet-stream" > /dev/null; then
  pass
else
  fail "pre-readonly upload failed"
fi

# ---------------------------------------------------------------------------
# Make storage read-only
# ---------------------------------------------------------------------------

begin_test "Make storage directory read-only"
chmod_result=$(kubectl exec "$BACKEND_POD" -n "${NAMESPACE}" -- \
  chmod 444 /data 2>&1) || true
if echo "$chmod_result" | grep -qi "operation not permitted\|permission denied"; then
  skip "cannot chmod /data (insufficient permissions in container)"
else
  echo "  /data set to read-only (444)"
  pass
fi

# ---------------------------------------------------------------------------
# Attempt uploads (should fail cleanly)
# ---------------------------------------------------------------------------

begin_test "Upload fails cleanly with read-only storage"
dd if=/dev/urandom bs=1024 count=4 of="${WORK_DIR}/ro-test.bin" 2>/dev/null
ro_status=$(curl -s -o "${WORK_DIR}/ro-response.txt" -w '%{http_code}' -X PUT \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@${WORK_DIR}/ro-test.bin" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/files/v1/ro-test.bin" 2>/dev/null || echo "000")
echo "  Upload status with read-only storage: ${ro_status}"

if [ "$ro_status" -ge 200 ] 2>/dev/null && [ "$ro_status" -lt 300 ] 2>/dev/null; then
  echo "  Upload unexpectedly succeeded (storage may not actually be read-only)"
  skip "chmod did not prevent writes"
else
  # Check for clean error (no panic, no stack trace)
  if [ -f "${WORK_DIR}/ro-response.txt" ]; then
    error_body=$(cat "${WORK_DIR}/ro-response.txt")
    if assert_not_contains "$error_body" "panic" "response should not contain panic"; then
      if assert_not_contains "$error_body" "RUST_BACKTRACE" "response should not expose backtrace env"; then
        pass
      fi
    fi
  else
    pass
  fi
fi

# Verify the server is still running
begin_test "Server still healthy after read-only error"
health_status=$(curl -s -o /dev/null -w '%{http_code}' "${BASE_URL}/health" 2>/dev/null || echo "000")
if [ "$health_status" -ge 200 ] 2>/dev/null && [ "$health_status" -lt 300 ] 2>/dev/null; then
  pass
else
  fail "server not responding after read-only error (status: ${health_status})"
fi

# ---------------------------------------------------------------------------
# Restore permissions
# ---------------------------------------------------------------------------

begin_test "Restore storage directory permissions"
kubectl exec "$BACKEND_POD" -n "${NAMESPACE}" -- chmod 755 /data 2>&1 || true
echo "  /data restored to 755"
pass

# ---------------------------------------------------------------------------
# Verify uploads work again
# ---------------------------------------------------------------------------

begin_test "Upload works after restoring permissions"
dd if=/dev/urandom bs=1024 count=4 of="${WORK_DIR}/after-ro.bin" 2>/dev/null
if api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/files/v1/after-ro.bin" \
    "${WORK_DIR}/after-ro.bin" "application/octet-stream" > /dev/null; then
  pass
else
  fail "upload after restoring permissions failed"
fi

# Verify pre-existing artifact still downloadable
begin_test "Verify pre-existing artifact still accessible"
if curl -sf -H "$(auth_header)" \
    -o "${WORK_DIR}/dl-before-ro.bin" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}/download/files/v1/before-ro.bin"; then
  DL_SHA=$(shasum -a 256 "${WORK_DIR}/dl-before-ro.bin" | awk '{print $1}')
  if assert_eq "$DL_SHA" "$BEFORE_SHA" "pre-readonly artifact checksum mismatch"; then
    pass
  fi
else
  fail "could not download pre-readonly artifact"
fi

end_suite
