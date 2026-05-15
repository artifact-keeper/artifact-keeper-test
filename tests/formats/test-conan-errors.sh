#!/usr/bin/env bash
# test-conan-errors.sh - Conan v2 error handling and edge case E2E tests
#
# Validates that the Conan v2 REST API returns correct error responses for
# invalid requests, non-existent resources, idempotent re-uploads, content
# type headers, and boundary conditions.

source "$(dirname "$0")/../lib/common.sh"

begin_suite "conan-errors"
auth_admin
setup_workdir

REPO_KEY="test-conan-err-${RUN_ID}"
BOGUS_REPO="test-conan-bogus-${RUN_ID}"
PKG_NAME="errlib"
PKG_VER="1.0.0"
REV="$(echo -n 'error-test-rev-content' | md5sum | cut -d' ' -f1)"
CONAN_BASE="${BASE_URL}/conan/${REPO_KEY}/v2/conans"

# Helper: upload a file to a specific recipe revision
conan_upload_file() {
  local name="$1" ver="$2" user="$3" channel="$4" rev="$5" filename="$6" filepath="$7"
  curl -s -o /dev/null -w '%{http_code}' -X PUT \
    -H "$(format_auth_header)" \
    -H "Content-Type: application/octet-stream" \
    --data-binary "@${filepath}" \
    $CURL_TIMEOUT \
    "${CONAN_BASE}/${name}/${ver}/${user}/${channel}/revisions/${rev}/files/${filename}"
}

# ---------------------------------------------------------------------------
# 1. Create local Conan repository
# ---------------------------------------------------------------------------
begin_test "Create local Conan repository"
if create_local_repo "$REPO_KEY" "conan"; then
  pass
else
  fail "could not create conan repository"
fi

# ---------------------------------------------------------------------------
# 2. GET latest for non-existent recipe returns 404
# ---------------------------------------------------------------------------
begin_test "GET latest for non-existent recipe returns 404"

status=$(curl -s -o /dev/null -w '%{http_code}' \
  -H "$(format_auth_header)" \
  $CURL_TIMEOUT \
  "${CONAN_BASE}/nosuchpkg/9.9.9/_/_/latest") || true

if assert_eq "$status" "404" "expected 404 for non-existent recipe latest, got ${status}"; then
  pass
fi

# ---------------------------------------------------------------------------
# 3. GET recipe file for non-existent revision returns 404
# ---------------------------------------------------------------------------
begin_test "GET recipe file for non-existent revision returns 404"

fake_rev="00000000000000000000000000000000"
status=$(curl -s -o /dev/null -w '%{http_code}' \
  -H "$(format_auth_header)" \
  $CURL_TIMEOUT \
  "${CONAN_BASE}/${PKG_NAME}/${PKG_VER}/_/_/revisions/${fake_rev}/files/conanfile.py") || true

if assert_eq "$status" "404" "expected 404 for non-existent revision file, got ${status}"; then
  pass
fi

# ---------------------------------------------------------------------------
# 4. GET package file for non-existent package_id returns 404
# ---------------------------------------------------------------------------
begin_test "GET package file for non-existent package_id returns 404"

fake_pkg_id="0000000000000000000000000000000000000000"
fake_pkg_rev="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
status=$(curl -s -o /dev/null -w '%{http_code}' \
  -H "$(format_auth_header)" \
  $CURL_TIMEOUT \
  "${CONAN_BASE}/${PKG_NAME}/${PKG_VER}/_/_/revisions/${REV}/packages/${fake_pkg_id}/revisions/${fake_pkg_rev}/files/conaninfo.txt") || true

if assert_eq "$status" "404" "expected 404 for non-existent package file, got ${status}"; then
  pass
fi

# ---------------------------------------------------------------------------
# 5. List revisions for non-existent recipe returns 404 or empty list
# ---------------------------------------------------------------------------
begin_test "List revisions for non-existent recipe returns 404 or empty"

resp=$(curl -s -w '\n%{http_code}' \
  -H "$(format_auth_header)" \
  $CURL_TIMEOUT \
  "${CONAN_BASE}/nopkg/0.0.1/_/_/revisions") || true

body=$(echo "$resp" | head -n -1)
status=$(echo "$resp" | tail -n 1)

if [ "$status" = "404" ]; then
  pass
elif [ "$status" = "200" ]; then
  # Some implementations return an empty revisions list instead of 404
  rev_count=$(echo "$body" | jq '.revisions | length // 0' 2>/dev/null) || rev_count=""
  if [ "$rev_count" = "0" ]; then
    pass
  else
    fail "expected 404 or empty revisions list for non-existent recipe, got ${rev_count} revisions"
  fi
else
  fail "expected 404 or 200 with empty list, got HTTP ${status}"
fi

# ---------------------------------------------------------------------------
# 6. Search on non-existent repo returns 404
# ---------------------------------------------------------------------------
begin_test "Search on non-existent repo returns 404"

status=$(curl -s -o /dev/null -w '%{http_code}' \
  -H "$(format_auth_header)" \
  $CURL_TIMEOUT \
  "${BASE_URL}/conan/${BOGUS_REPO}/v2/conans/search?q=anything") || true

if assert_eq "$status" "404" "expected 404 for search on non-existent repo, got ${status}"; then
  pass
fi

# ---------------------------------------------------------------------------
# 7. Upload to non-existent repo returns 404
# ---------------------------------------------------------------------------
begin_test "Upload to non-existent repo returns 404"
# v1.1.x backend dispatches to the format handler before validating repo
# existence, so PUT to an unknown repo returns 500. Targeted at v1.1.10.
if ! require_feature "conan_error_correctness"; then
  :  # require_feature already emitted skip; continue to next test
else

echo "dummy content" > "${WORK_DIR}/dummy.py"
status=$(curl -s -o /dev/null -w '%{http_code}' -X PUT \
  -H "$(format_auth_header)" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@${WORK_DIR}/dummy.py" \
  $CURL_TIMEOUT \
  "${BASE_URL}/conan/${BOGUS_REPO}/v2/conans/pkg/1.0.0/_/_/revisions/${REV}/files/conanfile.py") || true

if assert_eq "$status" "404" "expected 404 for upload to non-existent repo, got ${status}"; then
  pass
fi

fi  # require_feature "conan_error_correctness"

# ---------------------------------------------------------------------------
# Upload a real recipe so subsequent tests have data to work with
# ---------------------------------------------------------------------------
cat > "${WORK_DIR}/conanfile.py" <<'PYEOF'
from conan import ConanFile

class ErrLibConan(ConanFile):
    name = "errlib"
    version = "1.0.0"
    license = "MIT"
    description = "Library for error-case testing"
    settings = "os", "compiler", "build_type", "arch"
PYEOF

seed_status=$(conan_upload_file "$PKG_NAME" "$PKG_VER" "_" "_" "$REV" "conanfile.py" "${WORK_DIR}/conanfile.py") || true
if [ "$seed_status" -lt 200 ] 2>/dev/null || [ "$seed_status" -ge 300 ] 2>/dev/null; then
  echo "  Warning: seed upload returned HTTP ${seed_status}, some tests may skip"
fi

# Also upload a .tgz for content-type tests
echo "1713000000
conanfile.py: d41d8cd98f00b204e9800998ecf8427e" > "${WORK_DIR}/conanmanifest.txt"
tar czf "${WORK_DIR}/conan_export.tgz" -C "${WORK_DIR}" conanmanifest.txt

tgz_status=$(conan_upload_file "$PKG_NAME" "$PKG_VER" "_" "_" "$REV" "conan_export.tgz" "${WORK_DIR}/conan_export.tgz") || true
if [ "$tgz_status" -lt 200 ] 2>/dev/null || [ "$tgz_status" -ge 300 ] 2>/dev/null; then
  echo "  Warning: tgz seed upload returned HTTP ${tgz_status}"
fi

# ---------------------------------------------------------------------------
# 8. Re-upload same file to same revision is idempotent (200 or 201)
# ---------------------------------------------------------------------------
begin_test "Re-upload same file to same revision is idempotent"

status=$(conan_upload_file "$PKG_NAME" "$PKG_VER" "_" "_" "$REV" "conanfile.py" "${WORK_DIR}/conanfile.py") || true

if [ "$status" = "200" ] || [ "$status" = "201" ]; then
  pass
else
  fail "expected 200 or 201 for idempotent re-upload, got HTTP ${status}"
fi

# ---------------------------------------------------------------------------
# 9. Upload same revision with different content (replace or conflict)
# ---------------------------------------------------------------------------
begin_test "Upload same revision with different content handled gracefully"

cat > "${WORK_DIR}/conanfile_alt.py" <<'PYEOF'
from conan import ConanFile

class ErrLibConan(ConanFile):
    name = "errlib"
    version = "1.0.0"
    license = "MIT"
    description = "This is DIFFERENT content for the same revision hash"
    settings = "os", "compiler", "build_type", "arch"
    requires = "zlib/1.3.1"
PYEOF

status=$(conan_upload_file "$PKG_NAME" "$PKG_VER" "_" "_" "$REV" "conanfile.py" "${WORK_DIR}/conanfile_alt.py") || true

# The server should either accept the replacement (200/201) or reject with a conflict (409).
# Both behaviors are valid. A 500 would be a bug.
if [ "$status" = "200" ] || [ "$status" = "201" ] || [ "$status" = "409" ]; then
  pass
else
  fail "expected 200, 201, or 409 for same-revision different-content upload, got HTTP ${status}"
fi

# ---------------------------------------------------------------------------
# 10. Download .py file has correct Content-Type (text/plain or similar)
# ---------------------------------------------------------------------------
begin_test "Download .py file has correct Content-Type"

headers=$(curl -sI \
  -H "$(format_auth_header)" \
  $CURL_TIMEOUT \
  "${CONAN_BASE}/${PKG_NAME}/${PKG_VER}/_/_/revisions/${REV}/files/conanfile.py") || true

if [ -z "$headers" ]; then
  fail "could not fetch headers for conanfile.py"
else
  # Normalize to lowercase for case-insensitive matching
  ct=$(echo "$headers" | tr '[:upper:]' '[:lower:]' | grep '^content-type:' | head -1 | tr -d '\r')
  if [ -z "$ct" ]; then
    fail "no Content-Type header in response"
  else
    # For .py files, expect text/plain, text/x-python, or application/octet-stream
    if echo "$ct" | grep -qE '(text/plain|text/x-python|application/octet-stream)'; then
      pass
    else
      fail "unexpected Content-Type for .py file: ${ct}"
    fi
  fi
fi

# ---------------------------------------------------------------------------
# 11. Download .tgz file has correct Content-Type
# ---------------------------------------------------------------------------
begin_test "Download .tgz file has correct Content-Type"

headers=$(curl -sI \
  -H "$(format_auth_header)" \
  $CURL_TIMEOUT \
  "${CONAN_BASE}/${PKG_NAME}/${PKG_VER}/_/_/revisions/${REV}/files/conan_export.tgz") || true

if [ -z "$headers" ]; then
  fail "could not fetch headers for conan_export.tgz"
else
  ct=$(echo "$headers" | tr '[:upper:]' '[:lower:]' | grep '^content-type:' | head -1 | tr -d '\r')
  if [ -z "$ct" ]; then
    fail "no Content-Type header in response"
  else
    if echo "$ct" | grep -qE '(application/gzip|application/x-gzip|application/octet-stream|application/x-tar)'; then
      pass
    else
      fail "unexpected Content-Type for .tgz file: ${ct}"
    fi
  fi
fi

# ---------------------------------------------------------------------------
# 12. Ping on non-existent repo returns 404
# ---------------------------------------------------------------------------
begin_test "Ping on non-existent repo returns 404"
# v1.1.x /v2/ping handler short-circuits before repo lookup and returns 200
# regardless of repo existence. Targeted at v1.1.10.
if ! require_feature "conan_error_correctness"; then
  :  # require_feature already emitted skip; continue to next test
else

status=$(curl -s -o /dev/null -w '%{http_code}' \
  -H "$(format_auth_header)" \
  $CURL_TIMEOUT \
  "${BASE_URL}/conan/${BOGUS_REPO}/v2/ping") || true

if assert_eq "$status" "404" "expected 404 for ping on non-existent repo, got ${status}"; then
  pass
fi

fi  # require_feature "conan_error_correctness"

# ---------------------------------------------------------------------------
# 13. PUT with empty body (zero-length file)
# ---------------------------------------------------------------------------
begin_test "PUT with empty body uploads zero-length file"

: > "${WORK_DIR}/empty_file"

status=$(curl -s -o /dev/null -w '%{http_code}' -X PUT \
  -H "$(format_auth_header)" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@${WORK_DIR}/empty_file" \
  $CURL_TIMEOUT \
  "${CONAN_BASE}/${PKG_NAME}/${PKG_VER}/_/_/revisions/${REV}/files/empty_marker.txt") || true

# Zero-length uploads may be accepted (200/201) or rejected (400/422).
# Both are reasonable. A crash (500) would be a bug.
if [ "$status" = "200" ] || [ "$status" = "201" ] || [ "$status" = "400" ] || [ "$status" = "422" ]; then
  pass
else
  fail "expected 200, 201, 400, or 422 for zero-length upload, got HTTP ${status}"
fi

# ---------------------------------------------------------------------------
# 14. Recipe file download includes checksum header
# ---------------------------------------------------------------------------
begin_test "Recipe file download includes checksum or content-length header"

headers=$(curl -sI \
  -H "$(format_auth_header)" \
  $CURL_TIMEOUT \
  "${CONAN_BASE}/${PKG_NAME}/${PKG_VER}/_/_/revisions/${REV}/files/conanfile.py") || true

if [ -z "$headers" ]; then
  fail "could not fetch headers for conanfile.py"
else
  headers_lower=$(echo "$headers" | tr '[:upper:]' '[:lower:]')
  # Check for any checksum header (x-checksum-sha256, x-checksum-md5, digest)
  # or at minimum a content-length header for integrity verification
  has_checksum=$(echo "$headers_lower" | grep -cE '(x-checksum|digest|etag|content-md5)' || true)
  has_content_length=$(echo "$headers_lower" | grep -c 'content-length' || true)
  if [ "$has_checksum" -gt 0 ]; then
    pass
  elif [ "$has_content_length" -gt 0 ]; then
    # Content-Length is acceptable as a minimal integrity signal
    pass
  else
    fail "response has no checksum header and no content-length"
  fi
fi

# ---------------------------------------------------------------------------
# 15. Upload with extremely long name/version path segments
# ---------------------------------------------------------------------------
begin_test "Upload with extremely long path segments returns error"
# v1.1.x file-upload handler returns 500 on >255-char path segments instead
# of a structured client error. Targeted at v1.1.10.
if ! require_feature "conan_error_correctness"; then
  :  # require_feature already emitted skip; continue to next test
else

# Generate a 300-character package name
long_name=$(printf 'a%.0s' $(seq 1 300))

status=$(curl -s -o /dev/null -w '%{http_code}' -X PUT \
  -H "$(format_auth_header)" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@${WORK_DIR}/conanfile.py" \
  $CURL_TIMEOUT \
  "${CONAN_BASE}/${long_name}/1.0.0/_/_/revisions/${REV}/files/conanfile.py") || true

# The server should reject with 400, 414 (URI Too Long), 422, or 404.
# Accepting it (200/201) is also fine if the server has no length limits.
# A 500 would indicate an unhandled edge case.
if [ "$status" = "400" ] || [ "$status" = "414" ] || [ "$status" = "422" ] || [ "$status" = "404" ] || \
   [ "$status" = "200" ] || [ "$status" = "201" ]; then
  pass
else
  fail "expected a graceful response for extremely long path, got HTTP ${status}"
fi

fi  # require_feature "conan_error_correctness"

# ---------------------------------------------------------------------------
# Cleanup: delete the test repository
# ---------------------------------------------------------------------------
if api_delete "/api/v1/repositories/${REPO_KEY}" > /dev/null 2>&1; then
  echo "  Cleaned up repository ${REPO_KEY}"
else
  echo "  Warning: could not delete repository ${REPO_KEY}"
fi

end_suite
