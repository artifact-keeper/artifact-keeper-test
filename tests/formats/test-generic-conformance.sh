#!/usr/bin/env bash
# test-generic-conformance.sh - Generic repository (raw file storage) conformance tests
#
# Validates that the generic repository handles file uploads, downloads,
# nested paths, content integrity, 404 for missing files, and refused overwrites.
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
# 6. Immutability: a second PUT to an occupied path is refused and the first
#    upload keeps being served. The upload route documents this 409 (#1941).
#    Replacing bytes takes a delete first, or versioning on the repository.
# ---------------------------------------------------------------------------

begin_test "Second PUT to the same path is 409 and leaves the file unchanged"
echo "original content for overwrite test" > "${WORK_DIR}/overwrite.txt"
ORIG_OVERWRITE_SHA=$(shasum -a 256 "${WORK_DIR}/overwrite.txt" | awk '{print $1}')
echo "replaced content for overwrite test -- different bytes" > "${WORK_DIR}/overwrite-v2.txt"

if ! api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/overwrite-test/data.txt" \
    "${WORK_DIR}/overwrite.txt" "text/plain" > /dev/null; then
  fail "first upload to overwrite-test/data.txt returned non-2xx"
else
  second_status=$(curl -s -o "${WORK_DIR}/overwrite-resp.json" -w '%{http_code}' $CURL_TIMEOUT -X PUT \
    -H "$(auth_header)" \
    -H "Content-Type: text/plain" \
    --data-binary "@${WORK_DIR}/overwrite-v2.txt" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/overwrite-test/data.txt") || second_status="000"
  second_code=$(jq -r '.code // empty' "${WORK_DIR}/overwrite-resp.json" 2>/dev/null) || second_code=""

  if [ "$second_status" != "409" ] || [ "$second_code" != "CONFLICT" ]; then
    fail "second upload returned HTTP ${second_status} code '${second_code}', expected 409 CONFLICT"
  elif ! curl -sf $CURL_TIMEOUT \
      -H "$(auth_header)" \
      -o "${WORK_DIR}/overwrite-dl.txt" \
      "${BASE_URL}/api/v1/repositories/${REPO_KEY}/download/overwrite-test/data.txt"; then
    fail "download after refused overwrite returned non-2xx"
  else
    DL_SHA=$(shasum -a 256 "${WORK_DIR}/overwrite-dl.txt" | awk '{print $1}')
    if assert_eq "$DL_SHA" "$ORIG_OVERWRITE_SHA" "refused overwrite changed the stored file"; then
      pass
    fi
  fi
fi

end_suite
