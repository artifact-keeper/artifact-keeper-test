#!/usr/bin/env bash
# test-conan-auth.sh - Conan v2 authentication and authorization E2E tests
#
# Validates the Conan v2 auth endpoints: ping, authenticate, check_credentials,
# and verifies that upload/download operations respect auth requirements.
#
# Endpoints tested:
#   GET  /conan/{repo}/v2/ping
#   GET  /conan/{repo}/v2/users/authenticate
#   GET  /conan/{repo}/v2/users/check_credentials
#   PUT  /conan/{repo}/v2/conans/{name}/{ver}/_/_/revisions/{rev}/files/{file}
#
# Requires: curl, base64

source "$(dirname "$0")/../lib/common.sh"

begin_suite "conan-auth"
auth_admin
setup_workdir

REPO_KEY="test-conan-auth-${RUN_ID}"
CONAN_BASE="/conan/${REPO_KEY}/v2"

# -----------------------------------------------------------------------
# Test 1: Create a local Conan repository
# -----------------------------------------------------------------------
begin_test "Create Conan local repository"
if create_local_repo "$REPO_KEY" "conan"; then
  pass
else
  fail "could not create conan repo"
fi

# -----------------------------------------------------------------------
# Test 2: Ping returns 200 with X-Conan-Server-Capabilities header
# -----------------------------------------------------------------------
begin_test "Ping returns 200 with X-Conan-Server-Capabilities header"
ping_headers=$(curl -s -D - -o /dev/null $CURL_TIMEOUT \
  "${BASE_URL}${CONAN_BASE}/ping") || true
ping_status=$(echo "$ping_headers" | head -1 | grep -oE '[0-9]{3}' | head -1)

if [ "$ping_status" = "200" ]; then
  if echo "$ping_headers" | grep -qi "X-Conan-Server-Capabilities"; then
    pass
  else
    fail "ping response missing X-Conan-Server-Capabilities header"
  fi
else
  fail "ping returned HTTP ${ping_status}, expected 200"
fi

# -----------------------------------------------------------------------
# Test 3: Ping capabilities include "revisions"
# -----------------------------------------------------------------------
begin_test "Ping capabilities include revisions"
caps_value=$(echo "$ping_headers" | grep -i "X-Conan-Server-Capabilities" | sed 's/^[^:]*: *//' | tr -d '\r\n')

if [ -n "$caps_value" ]; then
  if assert_contains "$caps_value" "revisions" "capabilities should include 'revisions'"; then
    pass
  fi
else
  fail "X-Conan-Server-Capabilities header value is empty"
fi

# -----------------------------------------------------------------------
# Test 4: Authenticate with valid credentials returns 200 and a token
# -----------------------------------------------------------------------
begin_test "Authenticate with valid credentials returns token"
auth_resp=$(curl -s -w "\n%{http_code}" $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  "${BASE_URL}${CONAN_BASE}/users/authenticate") || true
auth_body=$(echo "$auth_resp" | sed '$d')
auth_status=$(echo "$auth_resp" | tail -1)

if [ "$auth_status" = "200" ]; then
  if [ -n "$auth_body" ]; then
    CONAN_TOKEN="$auth_body"
    pass
  else
    fail "authenticate returned 200 but response body is empty"
  fi
else
  fail "authenticate returned HTTP ${auth_status}, expected 200"
fi

# -----------------------------------------------------------------------
# Test 5: Authenticate with invalid credentials returns 401
# -----------------------------------------------------------------------
begin_test "Authenticate with invalid credentials returns 401"
bad_auth="Authorization: Basic $(printf '%s:%s' "$ADMIN_USER" "wrong-password-xyz" | base64)"
bad_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -H "$bad_auth" \
  "${BASE_URL}${CONAN_BASE}/users/authenticate") || true

if assert_eq "$bad_status" "401" "invalid credentials should return 401, got ${bad_status}"; then
  pass
fi

# -----------------------------------------------------------------------
# Test 6: Check credentials with valid auth returns 200
# -----------------------------------------------------------------------
begin_test "Check credentials with valid auth returns 200"
check_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  "${BASE_URL}${CONAN_BASE}/users/check_credentials") || true

if assert_eq "$check_status" "200" "check_credentials with valid auth should return 200, got ${check_status}"; then
  pass
fi

# -----------------------------------------------------------------------
# Test 7: Check credentials with no auth returns 401
# -----------------------------------------------------------------------
begin_test "Check credentials with no auth returns 401"
noauth_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  "${BASE_URL}${CONAN_BASE}/users/check_credentials") || true

if assert_eq "$noauth_status" "401" "check_credentials without auth should return 401, got ${noauth_status}"; then
  pass
fi

# -----------------------------------------------------------------------
# Test 8: Upload recipe file with valid auth succeeds
# -----------------------------------------------------------------------
begin_test "Upload recipe with valid auth succeeds"
cat > "${WORK_DIR}/conanfile.py" <<'PYEOF'
from conan import ConanFile

class AuthTestConan(ConanFile):
    name = "authtest"
    version = "1.0.0"
    license = "MIT"
    description = "Auth test package"
PYEOF

REVISION="f1e2d3c4b5a6f1e2d3c4b5a6f1e2d3c4"

upload_status=$(curl -s -o /dev/null -w '%{http_code}' -X PUT \
  -H "$(format_auth_header)" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@${WORK_DIR}/conanfile.py" \
  $CURL_TIMEOUT \
  "${BASE_URL}${CONAN_BASE}/conans/authtest/1.0.0/_/_/revisions/${REVISION}/files/conanfile.py") || true

if [ "$upload_status" -ge 200 ] 2>/dev/null && [ "$upload_status" -lt 300 ] 2>/dev/null; then
  pass
else
  fail "upload with valid auth returned HTTP ${upload_status}"
fi

# -----------------------------------------------------------------------
# Test 9: Upload without auth fails with 401
# -----------------------------------------------------------------------
begin_test "Upload without auth fails with 401"
noauth_upload=$(curl -s -o /dev/null -w '%{http_code}' -X PUT \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@${WORK_DIR}/conanfile.py" \
  $CURL_TIMEOUT \
  "${BASE_URL}${CONAN_BASE}/conans/authtest/1.0.0/_/_/revisions/${REVISION}/files/conanfile.py") || true

if [ "$noauth_upload" = "401" ] || [ "$noauth_upload" = "403" ]; then
  pass
else
  fail "upload without auth returned HTTP ${noauth_upload}, expected 401 or 403"
fi

# -----------------------------------------------------------------------
# Test 10: Download recipe with valid auth succeeds
# -----------------------------------------------------------------------
begin_test "Download recipe with valid auth succeeds"
dl_file="${WORK_DIR}/downloaded-conanfile.py"
dl_status=$(curl -s -o "$dl_file" -w '%{http_code}' \
  -H "$(format_auth_header)" \
  $CURL_TIMEOUT \
  "${BASE_URL}${CONAN_BASE}/conans/authtest/1.0.0/_/_/revisions/${REVISION}/files/conanfile.py") || true

if [ "$dl_status" = "200" ] && [ -s "$dl_file" ]; then
  if assert_contains "$(cat "$dl_file")" "AuthTestConan" "downloaded recipe should contain class name"; then
    pass
  fi
else
  fail "download with valid auth returned HTTP ${dl_status} or file was empty"
fi

# -----------------------------------------------------------------------
# Test 11: Download without auth on a local repo
# -----------------------------------------------------------------------
begin_test "Download without auth on local repo"
noauth_dl_status=$(curl -s -o /dev/null -w '%{http_code}' \
  $CURL_TIMEOUT \
  "${BASE_URL}${CONAN_BASE}/conans/authtest/1.0.0/_/_/revisions/${REVISION}/files/conanfile.py") || true

# Local repos may allow anonymous reads (public) or deny them (private).
# The repo was created with is_public=true, so 200 is expected. If the server
# requires auth regardless, 401 is also acceptable.
if [ "$noauth_dl_status" = "200" ]; then
  echo "  anonymous download allowed (repo is public)"
  pass
elif [ "$noauth_dl_status" = "401" ]; then
  echo "  anonymous download denied (server requires auth for all Conan reads)"
  pass
else
  fail "download without auth returned HTTP ${noauth_dl_status}, expected 200 or 401"
fi

# -----------------------------------------------------------------------
# Test 12: Authenticate response Content-Type is text/plain
# -----------------------------------------------------------------------
begin_test "Authenticate response Content-Type is text/plain"
ct_headers=$(curl -s -D - -o /dev/null $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  "${BASE_URL}${CONAN_BASE}/users/authenticate") || true
content_type=$(echo "$ct_headers" | grep -i "^Content-Type:" | sed 's/^[^:]*: *//' | tr -d '\r\n')

if [ -n "$content_type" ]; then
  if assert_contains "$content_type" "text/plain" "Content-Type should be text/plain, got ${content_type}"; then
    pass
  fi
else
  fail "authenticate response missing Content-Type header"
fi

# -----------------------------------------------------------------------
# Cleanup: delete the test repository
# -----------------------------------------------------------------------
api_delete "/api/v1/repositories/${REPO_KEY}" > /dev/null 2>&1 || true

end_suite
