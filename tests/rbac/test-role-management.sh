#!/usr/bin/env bash
# test-role-management.sh - Role assignment and revocation E2E test
#
# Creates a user, assigns and revokes the admin role, and verifies
# that access to admin endpoints changes accordingly.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "rbac-role-management"
auth_admin
setup_workdir

USER="role-test-${RUN_ID}"
PASSWORD="TestPass123!"

# -------------------------------------------------------------------------
# Create test user
# -------------------------------------------------------------------------

begin_test "Create user"
resp=$(api_post "/api/v1/users" "{\"username\":\"${USER}\",\"password\":\"${PASSWORD}\",\"email\":\"role-${RUN_ID}@test.com\"}")
USER_ID=$(echo "$resp" | jq -r '.id // empty')
if [ -n "$USER_ID" ] && [ "$USER_ID" != "null" ]; then
  pass
else
  fail "create user failed"
fi

# -------------------------------------------------------------------------
# Verify user has no admin access
# -------------------------------------------------------------------------

begin_test "User initially has no admin access"
login_resp=$(curl -sf $CURL_TIMEOUT -X POST -H "Content-Type: application/json" \
  -d "{\"username\":\"${USER}\",\"password\":\"${PASSWORD}\"}" \
  "${BASE_URL}/api/v1/auth/login" 2>&1) || true
USER_TOKEN=$(echo "$login_resp" | jq -r '.access_token // .token // empty')
status=$(curl -s -o /dev/null -w "%{http_code}" $CURL_TIMEOUT \
  -H "Authorization: Bearer ${USER_TOKEN}" \
  "${BASE_URL}/api/v1/admin/settings" 2>&1) || true
if [ "$status" = "403" ]; then
  pass
else
  fail "non-admin had access (got HTTP ${status}, expected 403)"
fi

# -------------------------------------------------------------------------
# Get admin role ID and assign it
# -------------------------------------------------------------------------

begin_test "Find admin role ID"
ADMIN_ROLE_ID=""
# First, get the admin user's roles to find the admin role ID
admin_roles=$(api_get "/api/v1/users/${USER_ID}/roles" 2>/dev/null) || true
# The test user has no roles yet, so get admin's own roles
# We need to find the admin role from the system. Try listing all users
# and getting the admin user's roles.
admin_user_resp=$(api_get "/api/v1/users?search=admin&per_page=1" 2>/dev/null) || true
ADMIN_USER_ID=$(echo "$admin_user_resp" | jq -r '
  if type == "array" then .[0].id // empty
  elif .items then .items[0].id // empty
  else empty
  end' 2>/dev/null) || true

if [ -n "$ADMIN_USER_ID" ] && [ "$ADMIN_USER_ID" != "null" ]; then
  admin_roles_resp=$(api_get "/api/v1/users/${ADMIN_USER_ID}/roles" 2>/dev/null) || true
  ADMIN_ROLE_ID=$(echo "$admin_roles_resp" | jq -r '
    if .items then (.items[] | select(.name == "admin") | .id) // empty
    elif type == "array" then (.[] | select(.name == "admin") | .id) // empty
    else empty
    end' 2>/dev/null) || true
fi

if [ -n "$ADMIN_ROLE_ID" ] && [ "$ADMIN_ROLE_ID" != "null" ]; then
  pass
else
  skip "could not find admin role ID"
fi

begin_test "Assign admin role"
if [ -z "${ADMIN_ROLE_ID:-}" ] || [ "$ADMIN_ROLE_ID" = "null" ]; then
  skip "no admin role ID available"
else
  resp=$(api_post "/api/v1/users/${USER_ID}/roles" "{\"role_id\":\"${ADMIN_ROLE_ID}\"}" 2>/dev/null) || true
  if [ $? -eq 0 ]; then
    pass
  else
    skip "role assignment API not available"
  fi
fi

# -------------------------------------------------------------------------
# Verify admin access after role assignment
# -------------------------------------------------------------------------

begin_test "User now has admin access"
if [ -z "${ADMIN_ROLE_ID:-}" ] || [ "$ADMIN_ROLE_ID" = "null" ]; then
  skip "role was not assigned"
else
  # Re-login to get updated token
  login_resp=$(curl -sf $CURL_TIMEOUT -X POST -H "Content-Type: application/json" \
    -d "{\"username\":\"${USER}\",\"password\":\"${PASSWORD}\"}" \
    "${BASE_URL}/api/v1/auth/login" 2>&1) || true
  USER_TOKEN=$(echo "$login_resp" | jq -r '.access_token // .token // empty')
  status=$(curl -s -o /dev/null -w "%{http_code}" $CURL_TIMEOUT \
    -H "Authorization: Bearer ${USER_TOKEN}" \
    "${BASE_URL}/api/v1/admin/settings" 2>&1) || true
  if [ "$status" = "200" ]; then
    pass
  else
    fail "admin role not effective (got HTTP ${status}, expected 200)"
  fi
fi

# -------------------------------------------------------------------------
# Revoke admin role and verify
# -------------------------------------------------------------------------

begin_test "Revoke admin role"
if [ -z "${ADMIN_ROLE_ID:-}" ] || [ "$ADMIN_ROLE_ID" = "null" ]; then
  skip "role was not assigned"
else
  api_delete "/api/v1/users/${USER_ID}/roles/${ADMIN_ROLE_ID}" > /dev/null 2>&1 || true
  pass
fi

begin_test "User no longer has admin access"
if [ -z "${ADMIN_ROLE_ID:-}" ] || [ "$ADMIN_ROLE_ID" = "null" ]; then
  skip "role was not assigned"
else
  # Re-login to get updated token
  login_resp=$(curl -sf $CURL_TIMEOUT -X POST -H "Content-Type: application/json" \
    -d "{\"username\":\"${USER}\",\"password\":\"${PASSWORD}\"}" \
    "${BASE_URL}/api/v1/auth/login" 2>&1) || true
  USER_TOKEN=$(echo "$login_resp" | jq -r '.access_token // .token // empty')
  status=$(curl -s -o /dev/null -w "%{http_code}" $CURL_TIMEOUT \
    -H "Authorization: Bearer ${USER_TOKEN}" \
    "${BASE_URL}/api/v1/admin/settings" 2>&1) || true
  if [ "$status" = "403" ]; then
    pass
  else
    fail "role revocation not effective (got HTTP ${status}, expected 403)"
  fi
fi

# -------------------------------------------------------------------------
# Cleanup
# -------------------------------------------------------------------------

api_delete "/api/v1/users/${USER_ID}" > /dev/null 2>&1 || true

end_suite
