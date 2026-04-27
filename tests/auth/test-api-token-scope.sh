#!/usr/bin/env bash
# test-api-token-scope.sh - API token scope enforcement (Epic 11.8, #76)
#
# Verifies:
#   1. A non-admin user can create an API token for themselves with "read" scope
#   2. That read-only token authenticates GET requests (200)
#   3. That same read-only token is rejected (403) on write operations
#   4. A non-admin user cannot create a token with the "admin" scope
#      (auth.rs:359-363 explicitly blocks this for non-admins)
#   5. An admin CAN create a token with the "admin" scope
#
# Backend reference:
#   - POST /api/v1/auth/tokens          (auth.rs:354)
#   - require_scope("write") gate       (middleware/auth.rs:79)
#   - non-admin admin-scope block       (auth.rs:359-363)
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "auth-api-token-scope"
auth_admin
setup_workdir

NONADMIN_USER="e2e-scope-${RUN_ID}"
NONADMIN_PASS="ScopeTest_Pass123!"
NONADMIN_EMAIL="e2e-scope-${RUN_ID}@test.local"
USER_ID=""
USER_TOKEN=""
READ_TOKEN=""
READ_TOKEN_ID=""
ADMIN_SCOPE_TOKEN=""

# -------------------------------------------------------------------------
# Create a non-admin user
# -------------------------------------------------------------------------

begin_test "Create non-admin test user"
if resp=$(api_post "/api/v1/users" \
    "{\"username\":\"${NONADMIN_USER}\",\"password\":\"${NONADMIN_PASS}\",\"email\":\"${NONADMIN_EMAIL}\",\"display_name\":\"Scope Test\"}" 2>/dev/null); then
  USER_ID=$(echo "$resp" | jq -r '.user.id // .id // empty')
  if [ -n "$USER_ID" ] && [ "$USER_ID" != "null" ]; then
    pass
  else
    fail "user created but no ID in response: ${resp:0:200}"
  fi
else
  fail "could not create non-admin user"
fi

# -------------------------------------------------------------------------
# Login as the non-admin user (need their own session to create tokens)
# -------------------------------------------------------------------------

begin_test "Login as non-admin user"
if [ -z "${USER_ID:-}" ] || [ "$USER_ID" = "null" ]; then
  skip "no user ID from creation"
else
  USER_TOKEN=$(login_as "${NONADMIN_USER}" "${NONADMIN_PASS}") || true
  if [ -n "$USER_TOKEN" ]; then
    pass
  else
    fail "non-admin login returned no token"
  fi
fi

# -------------------------------------------------------------------------
# Create a read-only API token (non-admin acting on themselves)
# -------------------------------------------------------------------------

begin_test "Non-admin creates read-only API token"
if [ -z "${USER_TOKEN:-}" ]; then
  skip "no user JWT"
else
  resp=$(curl -sf $CURL_TIMEOUT -X POST \
    -H "Authorization: Bearer ${USER_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"name":"e2e-readonly","scopes":["read"]}' \
    "${BASE_URL}/api/v1/auth/tokens" 2>/dev/null) || true
  READ_TOKEN=$(echo "$resp" | jq -r '.token // empty')
  READ_TOKEN_ID=$(echo "$resp" | jq -r '.id // empty')
  if [ -n "$READ_TOKEN" ] && [ "$READ_TOKEN" != "null" ]; then
    pass
  else
    fail "read-only token creation failed: ${resp:0:200}"
  fi
fi

# -------------------------------------------------------------------------
# Read-only token allows GET on /repositories (read scope satisfied)
# -------------------------------------------------------------------------

begin_test "Read-only token allows GET /repositories"
if [ -z "${READ_TOKEN:-}" ] || [ "$READ_TOKEN" = "null" ]; then
  skip "no read-only token"
else
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "Authorization: Bearer ${READ_TOKEN}" \
    "${BASE_URL}/api/v1/repositories" 2>/dev/null || echo 000)
  if [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then
    pass
  else
    fail "expected 2xx for GET with read scope, got HTTP ${status}"
  fi
fi

# -------------------------------------------------------------------------
# Read-only token rejected on write operation (create repo requires write)
# -------------------------------------------------------------------------

begin_test "Read-only token rejected on POST /repositories (write scope required)"
if [ -z "${READ_TOKEN:-}" ] || [ "$READ_TOKEN" = "null" ]; then
  skip "no read-only token"
else
  payload="{\"key\":\"e2e-scope-deny-${RUN_ID}\",\"name\":\"deny\",\"format\":\"generic\",\"repo_type\":\"local\",\"is_public\":true}"
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X POST \
    -H "Authorization: Bearer ${READ_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "$payload" \
    "${BASE_URL}/api/v1/repositories" 2>/dev/null || echo 000)
  # 403 is the contract: authenticated but missing scope. 401 would mean
  # the token wasn't recognized at all. Accept 403 strictly.
  if [ "$status" = "403" ]; then
    pass
  else
    fail "expected 403 for write op with read-only token, got HTTP ${status}"
  fi
fi

# -------------------------------------------------------------------------
# Non-admin cannot create a token with "admin" scope
#
# Backend rejects this with 403 in auth.rs:359-363 before storing anything.
# -------------------------------------------------------------------------

begin_test "Non-admin cannot create token with admin scope"
if [ -z "${USER_TOKEN:-}" ]; then
  skip "no user JWT"
else
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X POST \
    -H "Authorization: Bearer ${USER_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"name":"e2e-tries-admin","scopes":["admin"]}' \
    "${BASE_URL}/api/v1/auth/tokens" 2>/dev/null || echo 000)
  if [ "$status" = "403" ]; then
    pass
  else
    fail "expected 403 (Authorization) for non-admin requesting admin scope, got HTTP ${status}"
  fi
fi

# -------------------------------------------------------------------------
# Admin CAN create a token with admin scope (sanity check the inverse)
# -------------------------------------------------------------------------

begin_test "Admin can create token with admin scope"
resp=$(curl -sf $CURL_TIMEOUT -X POST \
  -H "$(auth_header)" \
  -H "Content-Type: application/json" \
  -d "{\"name\":\"e2e-admin-scope-${RUN_ID}\",\"scopes\":[\"admin\"]}" \
  "${BASE_URL}/api/v1/auth/tokens" 2>/dev/null) || true
ADMIN_SCOPE_TOKEN=$(echo "$resp" | jq -r '.token // empty')
ADMIN_SCOPE_TOKEN_ID=$(echo "$resp" | jq -r '.id // empty')
if [ -n "$ADMIN_SCOPE_TOKEN" ] && [ "$ADMIN_SCOPE_TOKEN" != "null" ]; then
  pass
else
  fail "admin could not create admin-scope token: ${resp:0:200}"
fi

# -------------------------------------------------------------------------
# Cleanup
# -------------------------------------------------------------------------

if [ -n "${READ_TOKEN_ID:-}" ] && [ "$READ_TOKEN_ID" != "null" ] && [ -n "${USER_TOKEN:-}" ]; then
  curl -sf $CURL_TIMEOUT -X DELETE \
    -H "Authorization: Bearer ${USER_TOKEN}" \
    "${BASE_URL}/api/v1/auth/tokens/${READ_TOKEN_ID}" > /dev/null 2>&1 || true
fi
if [ -n "${ADMIN_SCOPE_TOKEN_ID:-}" ] && [ "$ADMIN_SCOPE_TOKEN_ID" != "null" ]; then
  api_delete "/api/v1/auth/tokens/${ADMIN_SCOPE_TOKEN_ID}" > /dev/null 2>&1 || true
fi
if [ -n "${USER_ID:-}" ] && [ "$USER_ID" != "null" ]; then
  api_delete "/api/v1/users/${USER_ID}" > /dev/null 2>&1 || true
fi

# EXPECT_FAILURE=1 inverts the suite's exit code so this script can be used
# as a fixture to validate the gate (a "broken" gate is a passing self-test).
enable_expect_failure_trap

end_suite
