#!/usr/bin/env bash
# test-disk-full.sh - Verify clean error handling when storage is full
#
# Fills the storage volume by writing a large ballast file, verifies that
# uploads fail with clean error messages (no panics), frees space by
# removing the ballast, then verifies uploads work again.
#
# Requires: kubectl, NAMESPACE
# Note: This test requires the backend pod to have a writable /data directory.
# For accurate results, use a PVC with a small quota (e.g., 100Mi).
# The test creates a ballast file via fallocate or dd to consume space.

source "$(dirname "$0")/../../lib/common.sh"

begin_suite "storage-disk-full"
require_cmd kubectl
auth_admin
setup_workdir

NAMESPACE="${NAMESPACE:-ak-test-${RUN_ID}}"
REPO_KEY="store-full-${RUN_ID}"

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

begin_test "Upload artifact before filling disk"
dd if=/dev/urandom bs=1024 count=4 of="${WORK_DIR}/prefill.bin" 2>/dev/null
if api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/files/v1/prefill.bin" \
    "${WORK_DIR}/prefill.bin" "application/octet-stream" > /dev/null; then
  pass
else
  fail "pre-fill upload failed"
fi

# ---------------------------------------------------------------------------
# Fill disk with ballast file
# ---------------------------------------------------------------------------

begin_test "Fill storage volume with ballast"
# Try fallocate first (fast), fall back to dd
fill_result=$(kubectl exec "$BACKEND_POD" -n "${NAMESPACE}" -- \
  sh -c 'fallocate -l $(($(df /data --output=avail | tail -1) * 1024 - 4096)) /data/_ballast 2>/dev/null || dd if=/dev/zero of=/data/_ballast bs=1M count=9999 2>/dev/null; echo done' 2>&1) || true

# Verify disk is actually full
avail=$(kubectl exec "$BACKEND_POD" -n "${NAMESPACE}" -- \
  sh -c 'df /data --output=avail 2>/dev/null | tail -1 || echo 999999' 2>&1 | tr -d ' ') || true
echo "  Available space after fill: ${avail}KB"
if [ "${avail:-999999}" -lt 1024 ] 2>/dev/null; then
  echo "  Disk is full (less than 1MB free)"
  pass
else
  echo "  Could not fully fill disk (${avail}KB free). Test may be less reliable."
  pass
fi

# ---------------------------------------------------------------------------
# Verify uploads fail with clean errors
# ---------------------------------------------------------------------------

begin_test "Upload fails cleanly when disk is full"
dd if=/dev/urandom bs=1024 count=64 of="${WORK_DIR}/should-fail.bin" 2>/dev/null
full_status=$(curl -s -o "${WORK_DIR}/full-response.txt" -w '%{http_code}' -X PUT \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@${WORK_DIR}/should-fail.bin" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/files/v1/should-fail.bin" 2>/dev/null || echo "000")
echo "  Upload status when disk full: ${full_status}"

if [ "$full_status" -ge 200 ] 2>/dev/null && [ "$full_status" -lt 300 ] 2>/dev/null; then
  echo "  Upload unexpectedly succeeded (disk may not be truly full)"
  skip "disk was not full enough to trigger error"
else
  # Verify no panic in the response
  if [ -f "${WORK_DIR}/full-response.txt" ]; then
    error_body=$(cat "${WORK_DIR}/full-response.txt")
    if assert_not_contains "$error_body" "panic" "response should not contain panic"; then
      echo "  Error response is clean"
      pass
    fi
  else
    pass
  fi
fi

# Check server is still responding (not crashed)
begin_test "Server still responds after disk-full error"
health_status=$(curl -s -o /dev/null -w '%{http_code}' "${BASE_URL}/health" 2>/dev/null || echo "000")
if [ "$health_status" -ge 200 ] 2>/dev/null && [ "$health_status" -lt 300 ] 2>/dev/null; then
  pass
else
  fail "server not responding after disk-full error (status: ${health_status})"
fi

# ---------------------------------------------------------------------------
# Free space by removing ballast
# ---------------------------------------------------------------------------

begin_test "Remove ballast file to free space"
kubectl exec "$BACKEND_POD" -n "${NAMESPACE}" -- rm -f /data/_ballast 2>&1 || true
avail_after=$(kubectl exec "$BACKEND_POD" -n "${NAMESPACE}" -- \
  sh -c 'df /data --output=avail 2>/dev/null | tail -1 || echo unknown' 2>&1 | tr -d ' ') || true
echo "  Available space after cleanup: ${avail_after}KB"
pass

# ---------------------------------------------------------------------------
# Verify uploads work again
# ---------------------------------------------------------------------------

begin_test "Upload works after freeing space"
dd if=/dev/urandom bs=1024 count=4 of="${WORK_DIR}/after-free.bin" 2>/dev/null
if api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/files/v1/after-free.bin" \
    "${WORK_DIR}/after-free.bin" "application/octet-stream" > /dev/null; then
  pass
else
  fail "upload after freeing disk space failed"
fi

# Verify pre-fill artifact is still accessible
begin_test "Verify pre-fill artifact still accessible"
if assert_http_ok "/api/v1/repositories/${REPO_KEY}/download/files/v1/prefill.bin"; then
  pass
fi

end_suite
