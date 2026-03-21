#!/usr/bin/env bash
# test-privilege-escalation.sh - Privilege escalation prevention E2E test
#
# Verifies that a non-admin user cannot elevate their own privileges,
# create new users, or access admin-only endpoints.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "privilege-escalation"
auth_admin
setup_workdir

TEST_USER="e2e-privesc-${RUN_ID}"
TEST_PASS="PrivEsc123!"

# -------------------------------------------------------------------------
# Setup: create a non-admin user
# -------------------------------------------------------------------------

begin_test "Create non-admin user"
USER_ID=""
if resp=$(api_post "/api/v1/users" \
    "{\"username\":\"${TEST_USER}\",\"password\":\"${TEST_PASS}\",\"email\":\"${TEST_USER}@test.local\"}" 2>/dev/null); then
  USER_ID=$(echo "$resp" | jq -r '.user.id // .id // .user_id // empty') || true
  if [ -n "$USER_ID" ] && [ "$USER_ID" != "null" ]; then
    pass
  else
    fail "user created but no ID returned"
  fi
else
  fail "could not create non-admin user"
fi

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
    fail "no token in login response"
  fi
else
  fail "login failed"
fi

# -------------------------------------------------------------------------
# Self-escalation: try to set is_admin on own profile
# -------------------------------------------------------------------------

begin_test "Cannot self-escalate to admin via PATCH"
if [ -n "$USER_TOKEN" ] && [ -n "$USER_ID" ] && [ "$USER_ID" != "null" ]; then
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X PATCH \
    -H "Authorization: Bearer ${USER_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"is_admin":true}' \
    "${BASE_URL}/api/v1/users/${USER_ID}" 2>/dev/null) || true
  # Accept 403 (rejected) or 200 if the field is silently ignored.
  # If 200, we verify is_admin is still false in the next test.
  if [ "$status" = "403" ] || [ "$status" = "200" ]; then
    pass
  else
    fail "expected 403 or 200 (field ignored) for self-escalation, got ${status}"
  fi
else
  skip "missing user token or user ID"
fi

begin_test "Verify is_admin still false after escalation attempt"
if [ -n "$USER_ID" ] && [ "$USER_ID" != "null" ]; then
  if resp=$(api_get "/api/v1/users/${USER_ID}" 2>/dev/null); then
    is_admin=$(echo "$resp" | jq -r '.is_admin // .admin // .user.is_admin // "false"') || true
    if [ "$is_admin" = "false" ] || [ "$is_admin" = "null" ]; then
      pass
    else
      fail "is_admin is '${is_admin}' after self-escalation attempt, expected false"
    fi
  else
    fail "could not fetch user to verify admin status"
  fi
else
  skip "no user ID"
fi

# -------------------------------------------------------------------------
# Non-admin cannot create users
# -------------------------------------------------------------------------

begin_test "Non-admin cannot create users"
if [ -n "$USER_TOKEN" ]; then
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X POST \
    -H "Authorization: Bearer ${USER_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"e2e-smuggled-${RUN_ID}\",\"password\":\"Smuggle123!\",\"email\":\"smuggled-${RUN_ID}@test.local\",\"is_admin\":true}" \
    "${BASE_URL}/api/v1/users" 2>/dev/null) || true
  if [ "$status" = "403" ]; then
    pass
  else
    fail "expected 403 for non-admin user creation, got ${status}"
    # Clean up the smuggled user if it was somehow created
    auth_admin
    api_delete "/api/v1/users/e2e-smuggled-${RUN_ID}" > /dev/null 2>&1 || true
  fi
else
  skip "no user token"
fi

# -------------------------------------------------------------------------
# Non-admin cannot access admin settings
# -------------------------------------------------------------------------

begin_test "Non-admin cannot access admin settings"
if [ -n "$USER_TOKEN" ]; then
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "Authorization: Bearer ${USER_TOKEN}" \
    "${BASE_URL}/api/v1/admin/settings" 2>/dev/null) || true
  if [ "$status" = "403" ]; then
    pass
  else
    fail "expected 403 for admin settings access, got ${status}"
  fi
else
  skip "no user token"
fi

# -------------------------------------------------------------------------
# Non-admin cannot set is_admin via PUT (full replace)
# -------------------------------------------------------------------------

begin_test "Cannot escalate via PUT with is_admin field"
if [ -n "$USER_TOKEN" ] && [ -n "$USER_ID" ] && [ "$USER_ID" != "null" ]; then
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X PUT \
    -H "Authorization: Bearer ${USER_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${TEST_USER}\",\"email\":\"${TEST_USER}@test.local\",\"is_admin\":true}" \
    "${BASE_URL}/api/v1/users/${USER_ID}" 2>/dev/null) || true
  # 403 (rejected), 405 (method not allowed), or 200 if field is ignored
  if [ "$status" = "403" ] || [ "$status" = "405" ] || [ "$status" = "200" ]; then
    pass
  else
    fail "expected 403, 405, or 200 for PUT escalation, got ${status}"
  fi
else
  skip "missing user token or user ID"
fi

begin_test "Verify is_admin still false after PUT escalation attempt"
if [ -n "$USER_ID" ] && [ "$USER_ID" != "null" ]; then
  if resp=$(api_get "/api/v1/users/${USER_ID}" 2>/dev/null); then
    is_admin=$(echo "$resp" | jq -r '.is_admin // .admin // .user.is_admin // "false"') || true
    if [ "$is_admin" = "false" ] || [ "$is_admin" = "null" ]; then
      pass
    else
      fail "is_admin is '${is_admin}' after PUT escalation attempt, expected false"
    fi
  else
    fail "could not fetch user to verify admin status"
  fi
else
  skip "no user ID"
fi

# -------------------------------------------------------------------------
# Cleanup
# -------------------------------------------------------------------------

auth_admin
api_delete "/api/v1/users/${USER_ID}" > /dev/null 2>&1 || true

end_suite
