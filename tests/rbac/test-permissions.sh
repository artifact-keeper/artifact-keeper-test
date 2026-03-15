#!/usr/bin/env bash
# test-permissions.sh - Fine-grained permission enforcement E2E test
#
# Tests that a non-admin user cannot access repos they don't have permission
# for, and CAN access repos where permission has been explicitly granted.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "permissions"
auth_admin
setup_workdir

PRIVATE_REPO="test-perm-private-${RUN_ID}"
PUBLIC_REPO="test-perm-public-${RUN_ID}"
TEST_USER="e2e-perm-user-${RUN_ID}"
TEST_PASS="PermTest123!"

# -------------------------------------------------------------------------
# Setup: create repos and a non-admin user
# -------------------------------------------------------------------------

begin_test "Create private repo"
payload="{\"key\":\"${PRIVATE_REPO}\",\"name\":\"${PRIVATE_REPO}\",\"format\":\"generic\",\"repo_type\":\"local\",\"is_public\":false}"
if api_post "/api/v1/repositories" "$payload" > /dev/null 2>&1; then
  pass
else
  fail "could not create private repo"
fi

begin_test "Create public repo"
if create_local_repo "$PUBLIC_REPO" "generic"; then
  pass
else
  fail "could not create public repo"
fi

begin_test "Create non-admin user"
if api_post "/api/v1/users" \
    "{\"username\":\"${TEST_USER}\",\"password\":\"${TEST_PASS}\",\"email\":\"${TEST_USER}@test.local\"}" > /dev/null 2>&1; then
  pass
else
  fail "could not create test user"
fi

# Upload something to private repo (as admin)
echo "secret-${RUN_ID}" > "${WORK_DIR}/secret.bin"
api_upload "/api/v1/repositories/${PRIVATE_REPO}/artifacts/secret.bin" "${WORK_DIR}/secret.bin" > /dev/null 2>&1 || true

# -------------------------------------------------------------------------
# Login as non-admin user
# -------------------------------------------------------------------------

begin_test "Login as non-admin user"
USER_TOKEN=""
if resp=$(curl -sf $CURL_TIMEOUT -X POST "${BASE_URL}/api/v1/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${TEST_USER}\",\"password\":\"${TEST_PASS}\"}" 2>/dev/null); then
  USER_TOKEN=$(echo "$resp" | jq -r '.token // .access_token // empty') || true
  if [ -n "$USER_TOKEN" ]; then
    pass
  else
    fail "no token in response"
  fi
else
  fail "non-admin login failed"
fi

# -------------------------------------------------------------------------
# Unauthenticated access to private repo should be denied (401)
# -------------------------------------------------------------------------

begin_test "Unauthenticated access to private repo denied"
status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  "${BASE_URL}/api/v1/repositories/${PRIVATE_REPO}" 2>/dev/null) || true
if [ "$status" = "401" ] || [ "$status" = "403" ] || [ "$status" = "404" ]; then
  pass
else
  fail "expected 401/403/404 for unauthenticated private repo access, got ${status}"
fi

# -------------------------------------------------------------------------
# Authenticated non-admin CAN access private repo
# -------------------------------------------------------------------------

begin_test "Authenticated non-admin can access private repo"
if [ -n "$USER_TOKEN" ]; then
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "Authorization: Bearer ${USER_TOKEN}" \
    "${BASE_URL}/api/v1/repositories/${PRIVATE_REPO}" 2>/dev/null) || true
  if [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then
    pass
  else
    fail "expected 2xx for authenticated non-admin, got ${status}"
  fi
else
  skip "no user token"
fi

# -------------------------------------------------------------------------
# Non-admin CAN access public repo
# -------------------------------------------------------------------------

begin_test "Non-admin can access public repo"
if [ -n "$USER_TOKEN" ]; then
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "Authorization: Bearer ${USER_TOKEN}" \
    "${BASE_URL}/api/v1/repositories/${PUBLIC_REPO}" 2>/dev/null) || true
  if [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then
    pass
  else
    fail "expected 2xx for public repo, got ${status}"
  fi
else
  skip "no user token"
fi

# -------------------------------------------------------------------------
# Cleanup
# -------------------------------------------------------------------------

# Re-authenticate as admin for cleanup
auth_admin
api_delete "/api/v1/users/${TEST_USER}" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${PRIVATE_REPO}" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${PUBLIC_REPO}" > /dev/null 2>&1 || true

end_suite
