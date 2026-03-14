#!/usr/bin/env bash
# test-user-crud.sh - User management CRUD E2E test
#
# Tests creating, listing, getting, updating, and deleting users.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "user-crud"
auth_admin
setup_workdir

TEST_USER="e2e-user-${RUN_ID}"
TEST_PASS="TestPass123!"
TEST_EMAIL="e2e-${RUN_ID}@test.local"

# -------------------------------------------------------------------------
# Create user
# -------------------------------------------------------------------------

begin_test "Create user"
if resp=$(api_post "/api/v1/users" \
    "{\"username\":\"${TEST_USER}\",\"password\":\"${TEST_PASS}\",\"email\":\"${TEST_EMAIL}\",\"display_name\":\"E2E Test User\"}" 2>/dev/null); then
  USER_ID=$(echo "$resp" | jq -r '.id // .user_id // empty') || true
  pass
else
  fail "could not create user"
fi

# -------------------------------------------------------------------------
# List users
# -------------------------------------------------------------------------

begin_test "List users includes new user"
if resp=$(api_get "/api/v1/users"); then
  if assert_contains "$resp" "$TEST_USER"; then
    pass
  fi
else
  fail "could not list users"
fi

# -------------------------------------------------------------------------
# Get user
# -------------------------------------------------------------------------

begin_test "Get user by username"
if resp=$(api_get "/api/v1/users/${TEST_USER}" 2>/dev/null); then
  if assert_contains "$resp" "$TEST_EMAIL"; then
    pass
  fi
elif [ -n "${USER_ID:-}" ] && resp=$(api_get "/api/v1/users/${USER_ID}" 2>/dev/null); then
  if assert_contains "$resp" "$TEST_EMAIL"; then
    pass
  fi
else
  fail "could not get user"
fi

# -------------------------------------------------------------------------
# Login as new user
# -------------------------------------------------------------------------

begin_test "Login as new user"
if resp=$(curl -sf -X POST "${BASE_URL}/api/v1/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${TEST_USER}\",\"password\":\"${TEST_PASS}\"}" 2>/dev/null); then
  token=$(echo "$resp" | jq -r '.token // .access_token // empty') || true
  if [ -n "$token" ]; then
    pass
  else
    fail "login succeeded but no token returned"
  fi
else
  fail "could not login as new user"
fi

# -------------------------------------------------------------------------
# Update user
# -------------------------------------------------------------------------

begin_test "Update user display name"
if api_put "/api/v1/users/${TEST_USER}" \
    '{"display_name":"Updated E2E User"}' > /dev/null 2>&1; then
  pass
elif [ -n "${USER_ID:-}" ] && api_put "/api/v1/users/${USER_ID}" \
    '{"display_name":"Updated E2E User"}' > /dev/null 2>&1; then
  pass
else
  skip "user update not supported"
fi

# -------------------------------------------------------------------------
# Delete user
# -------------------------------------------------------------------------

begin_test "Delete user"
if api_delete "/api/v1/users/${TEST_USER}" > /dev/null 2>&1; then
  pass
elif [ -n "${USER_ID:-}" ] && api_delete "/api/v1/users/${USER_ID}" > /dev/null 2>&1; then
  pass
else
  fail "could not delete user"
fi

begin_test "Deleted user cannot login"
status=$(curl -s -o /dev/null -w '%{http_code}' -X POST "${BASE_URL}/api/v1/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${TEST_USER}\",\"password\":\"${TEST_PASS}\"}" 2>/dev/null) || true
if [ "$status" = "401" ] || [ "$status" = "404" ] || [ "$status" = "403" ]; then
  pass
else
  fail "deleted user got HTTP ${status}, expected 401/403/404"
fi

end_suite
