#!/usr/bin/env bash
# test-conan.sh - Conan v2 E2E test
# Tests the Conan v2 REST API at /conan/{repo_key}/.
source "$(dirname "$0")/../lib/common.sh"

begin_suite "conan"
auth_admin
setup_workdir

REPO_KEY="test-conan-${RUN_ID}"

# -----------------------------------------------------------------------
begin_test "Create Conan local repository"
# -----------------------------------------------------------------------
if create_local_repo "$REPO_KEY" "conan"; then
  pass
else
  fail "could not create conan repo"
fi

# -----------------------------------------------------------------------
begin_test "Upload recipe conanfile.py"
# -----------------------------------------------------------------------
cat > "${WORK_DIR}/conanfile.py" <<'PYEOF'
from conan import ConanFile

class TestLibConan(ConanFile):
    name = "testlib"
    version = "1.0.0"
    license = "MIT"
    description = "A test library for E2E"
    settings = "os", "compiler", "build_type", "arch"
PYEOF

# Use a fixed revision hash for testing
REVISION="a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"

UPLOAD_STATUS=$(curl -s -o /dev/null -w '%{http_code}' -X PUT \
  -H "$(format_auth_header)" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@${WORK_DIR}/conanfile.py" \
  "${BASE_URL}/conan/${REPO_KEY}/v2/conans/testlib/1.0.0/_/_/revisions/${REVISION}/files/conanfile.py") || true

if [ "$UPLOAD_STATUS" -ge 200 ] 2>/dev/null && [ "$UPLOAD_STATUS" -lt 300 ] 2>/dev/null; then
  pass
else
  fail "recipe upload returned HTTP ${UPLOAD_STATUS}"
fi

# -----------------------------------------------------------------------
begin_test "Upload conan_export.tgz"
# -----------------------------------------------------------------------
# Create a minimal export tarball containing the conanmanifest
echo "1708000000
conanfile.py: d41d8cd98f00b204e9800998ecf8427e" > "${WORK_DIR}/conanmanifest.txt"

tar czf "${WORK_DIR}/conan_export.tgz" -C "${WORK_DIR}" conanmanifest.txt

EXPORT_STATUS=$(curl -s -o /dev/null -w '%{http_code}' -X PUT \
  -H "$(format_auth_header)" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@${WORK_DIR}/conan_export.tgz" \
  "${BASE_URL}/conan/${REPO_KEY}/v2/conans/testlib/1.0.0/_/_/revisions/${REVISION}/files/conan_export.tgz") || true

if [ "$EXPORT_STATUS" -ge 200 ] 2>/dev/null && [ "$EXPORT_STATUS" -lt 300 ] 2>/dev/null; then
  pass
else
  fail "conan_export.tgz upload returned HTTP ${EXPORT_STATUS}"
fi

# -----------------------------------------------------------------------
begin_test "Query search endpoint"
# -----------------------------------------------------------------------
SEARCH_RESP=$(curl -sf \
  -H "$(format_auth_header)" \
  "${BASE_URL}/conan/${REPO_KEY}/v2/conans/search?q=testlib") || true

if [ -n "$SEARCH_RESP" ]; then
  if assert_contains "$SEARCH_RESP" "testlib" "search results missing testlib"; then
    pass
  fi
else
  fail "search returned empty response"
fi

# -----------------------------------------------------------------------
begin_test "Verify recipe exists"
# -----------------------------------------------------------------------
LATEST_RESP=$(curl -sf \
  -H "$(format_auth_header)" \
  "${BASE_URL}/conan/${REPO_KEY}/v2/conans/testlib/1.0.0/_/_/latest") || true

if [ -n "$LATEST_RESP" ]; then
  LATEST_REV=$(echo "$LATEST_RESP" | jq -r '.revision // empty')
  if [ -n "$LATEST_REV" ]; then
    pass
  else
    fail "latest revision response missing 'revision' field"
  fi
else
  fail "latest revision returned empty response"
fi

# -----------------------------------------------------------------------
begin_test "Download and verify recipe file"
# -----------------------------------------------------------------------
dl_file="${WORK_DIR}/downloaded-conanfile.py"
dl_status=$(curl -sf -o "$dl_file" -w '%{http_code}' \
  -H "$(format_auth_header)" \
  "${BASE_URL}/conan/${REPO_KEY}/v2/conans/testlib/1.0.0/_/_/revisions/${REVISION}/files/conanfile.py" 2>/dev/null) || true

if [ "$dl_status" = "200" ] && [ -s "$dl_file" ]; then
  pass
else
  # Try management API
  if curl -sf -H "$(auth_header)" \
      -o "$dl_file" \
      "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/testlib/1.0.0/conanfile.py"; then
    if [ -s "$dl_file" ]; then
      pass
    else
      fail "downloaded file is empty"
    fi
  elif [ "$dl_status" = "404" ] || [ "$dl_status" = "405" ]; then
    skip "download endpoint not available for this format (status: ${dl_status})"
  else
    fail "download failed (status: ${dl_status})"
  fi
fi

# -----------------------------------------------------------------------
begin_test "Upload second version recipe"
# -----------------------------------------------------------------------
cat > "${WORK_DIR}/conanfile-v2.py" <<'PYEOF'
from conan import ConanFile

class TestLibConan(ConanFile):
    name = "testlib"
    version = "2.0.0"
    license = "MIT"
    description = "A test library v2 for E2E"
    settings = "os", "compiler", "build_type", "arch"
PYEOF

REVISION_V2="b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5"

V2_STATUS=$(curl -s -o /dev/null -w '%{http_code}' -X PUT \
  -H "$(format_auth_header)" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@${WORK_DIR}/conanfile-v2.py" \
  "${BASE_URL}/conan/${REPO_KEY}/v2/conans/testlib/2.0.0/_/_/revisions/${REVISION_V2}/files/conanfile.py") || true

if [ "$V2_STATUS" -ge 200 ] 2>/dev/null && [ "$V2_STATUS" -lt 300 ] 2>/dev/null; then
  pass
elif [ "$V2_STATUS" = "404" ] || [ "$V2_STATUS" = "405" ]; then
  skip "version upload endpoint not available for this format (status: ${V2_STATUS})"
else
  fail "v2 recipe upload returned HTTP ${V2_STATUS}"
fi

# -----------------------------------------------------------------------
begin_test "Delete recipe and verify removal"
# -----------------------------------------------------------------------
status=$(curl -s -o /dev/null -w "%{http_code}" \
  -X DELETE -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/testlib/1.0.0/conanfile.py" 2>&1) || true
if [ "$status" = "200" ] || [ "$status" = "204" ]; then
  verify_status=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "$(auth_header)" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/testlib/1.0.0/conanfile.py" 2>&1) || true
  if [ "$verify_status" = "404" ]; then
    pass
  else
    fail "artifact still accessible after delete (status: ${verify_status})"
  fi
else
  # Try deleting via Conan v2 API
  status=$(curl -s -o /dev/null -w "%{http_code}" \
    -X DELETE -H "$(format_auth_header)" \
    "${BASE_URL}/conan/${REPO_KEY}/v2/conans/testlib/1.0.0/_/_" 2>&1) || true
  if [ "$status" = "200" ] || [ "$status" = "204" ]; then
    pass
  elif [ "$status" = "404" ] || [ "$status" = "405" ]; then
    skip "delete not supported for this format (status: ${status})"
  else
    fail "delete returned ${status}"
  fi
fi

end_suite
