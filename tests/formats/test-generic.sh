#!/usr/bin/env bash
# test-generic.sh - Generic format E2E test
# Tests upload/download of binary blobs via the management API at /api/v1/repositories/{key}/.
source "$(dirname "$0")/../lib/common.sh"

begin_suite "generic"
auth_admin
setup_workdir

REPO_KEY="test-generic-${RUN_ID}"

# ---------------------------------------------------------------------------
# Create repository
# ---------------------------------------------------------------------------

begin_test "Create generic local repository"
if create_local_repo "$REPO_KEY" "generic"; then
  pass
else
  fail "could not create generic repo"
fi

# ---------------------------------------------------------------------------
# Upload binary blob
# ---------------------------------------------------------------------------

begin_test "Upload binary blob"
dd if=/dev/urandom bs=1024 count=4 of="${WORK_DIR}/blob.bin" 2>/dev/null
ORIG_SHA256=$(shasum -a 256 "${WORK_DIR}/blob.bin" | awk '{print $1}')

if api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/tools/v1/blob.bin" \
    "${WORK_DIR}/blob.bin" "application/octet-stream" > /dev/null; then
  pass
else
  fail "upload returned non-2xx"
fi

# ---------------------------------------------------------------------------
# Download and verify checksum
# ---------------------------------------------------------------------------

begin_test "Download and verify checksum"
if curl -sf -H "$(auth_header)" \
    -o "${WORK_DIR}/downloaded.bin" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}/download/tools/v1/blob.bin"; then
  DL_SHA256=$(shasum -a 256 "${WORK_DIR}/downloaded.bin" | awk '{print $1}')
  if assert_eq "$DL_SHA256" "$ORIG_SHA256" "SHA256 mismatch after round-trip"; then
    pass
  fi
else
  fail "download returned non-2xx"
fi

# ---------------------------------------------------------------------------
# Upload second blob
# ---------------------------------------------------------------------------

begin_test "Upload second artifact"
echo "second file content" > "${WORK_DIR}/readme.txt"
if api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/docs/readme.txt" \
    "${WORK_DIR}/readme.txt" "text/plain" > /dev/null; then
  pass
else
  fail "second upload failed"
fi

# ---------------------------------------------------------------------------
# Delete artifact
# ---------------------------------------------------------------------------

begin_test "Delete artifact"
if api_delete "/api/v1/repositories/${REPO_KEY}/artifacts/docs/readme.txt" > /dev/null 2>&1; then
  pass
else
  fail "delete returned non-2xx"
fi

# ---------------------------------------------------------------------------
# Verify deletion
# ---------------------------------------------------------------------------

begin_test "Verify deleted artifact returns 404"
if assert_http_status "/api/v1/repositories/${REPO_KEY}/download/docs/readme.txt" "404"; then
  pass
fi

# ---------------------------------------------------------------------------
# List artifacts via management API
# ---------------------------------------------------------------------------

begin_test "List artifacts via management API"
if resp=$(api_get "/api/v1/repositories/${REPO_KEY}/artifacts"); then
  if assert_contains "$resp" "blob.bin" "artifact list should contain blob.bin"; then
    pass
  fi
else
  fail "GET /api/v1/repositories/${REPO_KEY}/artifacts returned error"
fi

end_suite
