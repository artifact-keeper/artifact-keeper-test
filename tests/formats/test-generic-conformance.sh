#!/usr/bin/env bash
# test-generic-conformance.sh - Generic repository (raw file storage) conformance tests
#
# Validates that the generic repository handles file uploads, downloads,
# nested paths, content integrity, 404 for missing files, and overwrites.
#
# Endpoints: ${BASE_URL}/api/v1/repositories/{repo_key}/ (management API)
#
# The generic format has no format-native handler. All operations use the
# standard artifact management API for upload and download.
#
# Requires: jq, shasum
source "$(dirname "$0")/../lib/common.sh"

begin_suite "generic-conformance"
auth_admin
setup_workdir

REPO_KEY="test-generic-conf-${RUN_ID}"

# ---------------------------------------------------------------------------
# Create repository
# ---------------------------------------------------------------------------

begin_test "Create generic local repository"
if create_local_repo "$REPO_KEY" "generic"; then
  pass
else
  fail "could not create generic repository"
fi

# ---------------------------------------------------------------------------
# 1. PUT /{path} uploads a file
# ---------------------------------------------------------------------------

begin_test "Upload file via PUT"
echo "generic conformance test content" > "${WORK_DIR}/testfile.txt"
ORIG_SHA256=$(shasum -a 256 "${WORK_DIR}/testfile.txt" | awk '{print $1}')

if api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/tools/v1/testfile.txt" \
    "${WORK_DIR}/testfile.txt" "text/plain" > /dev/null; then
  pass
else
  fail "file upload returned non-2xx"
fi

# ---------------------------------------------------------------------------
# 2. GET /{path} downloads the file
# ---------------------------------------------------------------------------

begin_test "Download file via GET"
if curl -sf $CURL_TIMEOUT \
    -H "$(auth_header)" \
    -o "${WORK_DIR}/downloaded.txt" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}/download/tools/v1/testfile.txt"; then
  if [ -s "${WORK_DIR}/downloaded.txt" ]; then
    pass
  else
    fail "downloaded file is empty"
  fi
else
  fail "file download returned non-2xx"
fi

# ---------------------------------------------------------------------------
# 3. PUT with nested path (foo/bar/baz.txt)
# ---------------------------------------------------------------------------

begin_test "Upload file with deeply nested path"
echo "deeply nested content for conformance test" > "${WORK_DIR}/nested.txt"

if api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/foo/bar/baz/nested.txt" \
    "${WORK_DIR}/nested.txt" "text/plain" > /dev/null; then
  # Verify it can be downloaded
  if curl -sf $CURL_TIMEOUT \
      -H "$(auth_header)" \
      -o "${WORK_DIR}/nested-dl.txt" \
      "${BASE_URL}/api/v1/repositories/${REPO_KEY}/download/foo/bar/baz/nested.txt"; then
    if [ -s "${WORK_DIR}/nested-dl.txt" ]; then
      pass
    else
      fail "downloaded nested file is empty"
    fi
  else
    fail "nested file download returned non-2xx"
  fi
else
  fail "nested path upload returned non-2xx"
fi

# ---------------------------------------------------------------------------
# 4. Download integrity matches upload
# ---------------------------------------------------------------------------

begin_test "Download integrity matches upload (SHA256)"
if [ -s "${WORK_DIR}/downloaded.txt" ]; then
  DL_SHA256=$(shasum -a 256 "${WORK_DIR}/downloaded.txt" | awk '{print $1}')
  if assert_eq "$DL_SHA256" "$ORIG_SHA256" "SHA256 mismatch after round-trip: expected ${ORIG_SHA256}, got ${DL_SHA256}"; then
    pass
  fi
else
  skip "no downloaded file to verify"
fi

# ---------------------------------------------------------------------------
# 5. 404 for nonexistent path
# ---------------------------------------------------------------------------

begin_test "404 for nonexistent path"
status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/download/does/not/exist.bin") || true
if assert_eq "$status" "404" "expected 404 for nonexistent path, got ${status}"; then
  pass
fi

# ---------------------------------------------------------------------------
# 6. Overwrite: PUT same path replaces the file
# ---------------------------------------------------------------------------

begin_test "Overwrite replaces file content"
echo "original content for overwrite test" > "${WORK_DIR}/overwrite.txt"
ORIG_OVERWRITE_SHA=$(shasum -a 256 "${WORK_DIR}/overwrite.txt" | awk '{print $1}')

# Upload the original
api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/overwrite-test/data.txt" \
    "${WORK_DIR}/overwrite.txt" "text/plain" > /dev/null 2>&1 || true

# Upload a replacement with different content
echo "replaced content for overwrite test -- different bytes" > "${WORK_DIR}/overwrite-v2.txt"
NEW_SHA=$(shasum -a 256 "${WORK_DIR}/overwrite-v2.txt" | awk '{print $1}')

if api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/overwrite-test/data.txt" \
    "${WORK_DIR}/overwrite-v2.txt" "text/plain" > /dev/null; then
  # Download and verify the new content is served
  if curl -sf $CURL_TIMEOUT \
      -H "$(auth_header)" \
      -o "${WORK_DIR}/overwrite-dl.txt" \
      "${BASE_URL}/api/v1/repositories/${REPO_KEY}/download/overwrite-test/data.txt"; then
    DL_SHA=$(shasum -a 256 "${WORK_DIR}/overwrite-dl.txt" | awk '{print $1}')
    if assert_eq "$DL_SHA" "$NEW_SHA" "overwritten file should have new content SHA256"; then
      pass
    fi
  else
    fail "download after overwrite returned non-2xx"
  fi
else
  fail "overwrite upload returned non-2xx"
fi

end_suite
