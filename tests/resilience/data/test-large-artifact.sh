#!/usr/bin/env bash
# test-large-artifact.sh - Verify upload/download of a large artifact
#
# Generates a 100MB file, uploads it via streaming, downloads it, and
# verifies the SHA256 checksum and file size match. Kept at 100MB (not
# multi-GB) so CI pipelines finish in reasonable time.
#
# Requires: kubectl, NAMESPACE

source "$(dirname "$0")/../../lib/common.sh"

begin_suite "data-large-artifact"
require_cmd kubectl
auth_admin
setup_workdir

NAMESPACE="${NAMESPACE:-ak-test-${RUN_ID}}"
REPO_KEY="data-large-${RUN_ID}"
LARGE_SIZE_MB=100

# ---------------------------------------------------------------------------
# Create repository
# ---------------------------------------------------------------------------

begin_test "Create generic repository"
if create_local_repo "$REPO_KEY" "generic"; then
  pass
else
  fail "could not create generic repo"
fi

# ---------------------------------------------------------------------------
# Generate large file
# ---------------------------------------------------------------------------

begin_test "Generate ${LARGE_SIZE_MB}MB test file"
dd if=/dev/urandom bs=1048576 count="$LARGE_SIZE_MB" \
  of="${WORK_DIR}/large.bin" 2>/dev/null
ORIG_SHA=$(shasum -a 256 "${WORK_DIR}/large.bin" | awk '{print $1}')
ORIG_SIZE=$(wc -c < "${WORK_DIR}/large.bin" | tr -d ' ')
echo "  File size: ${ORIG_SIZE} bytes"
echo "  SHA256: ${ORIG_SHA}"
if [ "$ORIG_SIZE" -gt 0 ] 2>/dev/null; then
  pass
else
  fail "could not generate large file"
fi

# ---------------------------------------------------------------------------
# Upload via streaming
# ---------------------------------------------------------------------------

begin_test "Upload ${LARGE_SIZE_MB}MB file via streaming"
UPLOAD_START=$(date +%s)
upload_status=$(curl -s -o /dev/null -w '%{http_code}' -X PUT \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@${WORK_DIR}/large.bin" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/files/v1/large.bin" 2>/dev/null || echo "000")
UPLOAD_DURATION=$(( $(date +%s) - UPLOAD_START ))
echo "  Upload status: ${upload_status}"
echo "  Upload duration: ${UPLOAD_DURATION}s"

if [ "$upload_status" -ge 200 ] 2>/dev/null && [ "$upload_status" -lt 300 ] 2>/dev/null; then
  pass
else
  fail "large file upload failed with status ${upload_status}"
fi

# ---------------------------------------------------------------------------
# Download and verify checksum
# ---------------------------------------------------------------------------

begin_test "Download large file and verify SHA256"
DOWNLOAD_START=$(date +%s)
if curl -sf -H "$(auth_header)" \
    -o "${WORK_DIR}/large-dl.bin" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}/download/files/v1/large.bin"; then
  DOWNLOAD_DURATION=$(( $(date +%s) - DOWNLOAD_START ))
  echo "  Download duration: ${DOWNLOAD_DURATION}s"

  DL_SHA=$(shasum -a 256 "${WORK_DIR}/large-dl.bin" | awk '{print $1}')
  if assert_eq "$DL_SHA" "$ORIG_SHA" "SHA256 mismatch on ${LARGE_SIZE_MB}MB file round-trip"; then
    pass
  fi
else
  fail "large file download failed"
fi

# ---------------------------------------------------------------------------
# Verify file size
# ---------------------------------------------------------------------------

begin_test "Verify downloaded file size matches"
if [ -f "${WORK_DIR}/large-dl.bin" ]; then
  DL_SIZE=$(wc -c < "${WORK_DIR}/large-dl.bin" | tr -d ' ')
  if assert_eq "$DL_SIZE" "$ORIG_SIZE" \
      "file size mismatch: expected ${ORIG_SIZE}, got ${DL_SIZE}"; then
    echo "  Downloaded size: ${DL_SIZE} bytes"
    pass
  fi
else
  fail "downloaded file does not exist"
fi

# ---------------------------------------------------------------------------
# Verify artifact appears in management API
# ---------------------------------------------------------------------------

begin_test "Verify large artifact listed in management API"
if resp=$(api_get "/api/v1/repositories/${REPO_KEY}/artifacts"); then
  if assert_contains "$resp" "large.bin" "artifact list should contain large.bin"; then
    pass
  fi
else
  fail "could not list artifacts"
fi

end_suite
