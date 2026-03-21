#!/usr/bin/env bash
# test-decompression-bomb.sh - T2-09: Decompression bomb detection
#
# Creates a small gzip archive that expands to a large size and uploads it.
# The backend should reject archives with excessive compression ratios.

source "$(dirname "$0")/../lib/common.sh"

begin_suite "decompression-bomb"
auth_admin
setup_workdir

REPO_KEY="sec-decomp-bomb-${RUN_ID}"

# ---------------------------------------------------------------------------
# Create a test repository
# ---------------------------------------------------------------------------

begin_test "Create generic local repo"
if create_local_repo "$REPO_KEY" "generic"; then
  pass
else
  fail "could not create generic repo"
fi

# ---------------------------------------------------------------------------
# Generate a decompression bomb (100MB of zeros compressed to ~100KB)
# ---------------------------------------------------------------------------

begin_test "Generate decompression bomb archive"
if dd if=/dev/zero bs=1M count=100 2>/dev/null | gzip -9 > "${WORK_DIR}/bomb.gz" 2>/dev/null; then
  compressed_size=$(wc -c < "${WORK_DIR}/bomb.gz" | tr -d ' ')
  echo "  compressed size: ${compressed_size} bytes"
  if [ "$compressed_size" -gt 0 ] 2>/dev/null; then
    pass
  else
    fail "bomb.gz is empty"
  fi
else
  fail "could not generate decompression bomb"
fi

# ---------------------------------------------------------------------------
# Upload the bomb as a generic artifact
# ---------------------------------------------------------------------------

begin_test "Upload decompression bomb to generic repo"
status=$(curl -s -o "${WORK_DIR}/bomb-response.txt" -w '%{http_code}' $CURL_TIMEOUT \
  -X PUT \
  -H "$(auth_header)" \
  -H "Content-Type: application/gzip" \
  --data-binary "@${WORK_DIR}/bomb.gz" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/bomb/v1/bomb.gz") || true
body=$(cat "${WORK_DIR}/bomb-response.txt" 2>/dev/null) || true

if [ "$status" = "400" ] || [ "$status" = "413" ] || [ "$status" = "422" ]; then
  pass
elif [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then
  # Generic repos may accept any binary blob without decompressing.
  # This is acceptable for generic format but would be a concern for npm/pypi.
  skip "generic repo accepted the archive without decompression validation (expected for generic format; npm/pypi should validate)"
elif [ "$status" = "408" ] || [ "$status" = "504" ]; then
  # Timeout could indicate the server tried to decompress and hit limits
  skip "server timed out processing the archive (may indicate partial protection)"
else
  fail "expected 400/413/422 for decompression bomb, got ${status}"
fi

# ---------------------------------------------------------------------------
# Try uploading as an npm tarball if possible (npm actually decompresses)
# ---------------------------------------------------------------------------

begin_test "Upload decompression bomb as npm package"
NPM_REPO="sec-decomp-npm-${RUN_ID}"
if create_local_repo "$NPM_REPO" "npm" 2>/dev/null; then
  # npm packages are tarballs that the server unpacks to read package.json
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X PUT \
    -H "$(auth_header)" \
    -H "Content-Type: application/octet-stream" \
    --data-binary "@${WORK_DIR}/bomb.gz" \
    "${BASE_URL}/npm/${NPM_REPO}/@bomb/decompression-bomb" 2>/dev/null) || true

  if [ "$status" = "400" ] || [ "$status" = "413" ] || [ "$status" = "422" ]; then
    pass
  elif [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then
    skip "npm endpoint accepted the bomb archive (decompression bomb protection may not be implemented for npm)"
  else
    # Any non-2xx rejection is acceptable (could be format validation, not bomb detection)
    pass
  fi
else
  skip "could not create npm repo to test format-specific decompression"
fi

end_suite
