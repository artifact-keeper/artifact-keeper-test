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

end_suite
