#!/usr/bin/env bash
# test-idor.sh - IDOR (Insecure Direct Object Reference) E2E test
#
# Verifies that User A cannot access or modify User B's resources.
# Each user should only be able to manage their own account; cross-user
# operations must be rejected with 403.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "idor"
auth_admin
setup_workdir

USER_A="e2e-idor-a-${RUN_ID}"
USER_B="e2e-idor-b-${RUN_ID}"
USER_PASS="IdorTest123!"

# -------------------------------------------------------------------------
# Setup: create two non-admin users
# -------------------------------------------------------------------------

begin_test "Create User A"
USER_A_ID=""
# Include both "username" and "name" fields plus "display_name" to match
# whichever field the backend requires (the user-crud test showed display_name
# is accepted; some backend versions require "name" instead of "username").
if resp=$(api_post "/api/v1/users" \
    "{\"username\":\"${USER_A}\",\"name\":\"${USER_A}\",\"password\":\"${USER_PASS}\",\"email\":\"${USER_A}@test.local\",\"display_name\":\"IDOR User A\"}" 2>/dev/null); then
  USER_A_ID=$(echo "$resp" | jq -r '.user.id // .id // .user_id // empty') || true
  if [ -n "$USER_A_ID" ] && [ "$USER_A_ID" != "null" ]; then
    pass
  else
    fail "user created but no ID returned"
  fi
else
  fail "could not create User A"
fi

begin_test "Create User B"
USER_B_ID=""
if resp=$(api_post "/api/v1/users" \
    "{\"username\":\"${USER_B}\",\"name\":\"${USER_B}\",\"password\":\"${USER_PASS}\",\"email\":\"${USER_B}@test.local\",\"display_name\":\"IDOR User B\"}" 2>/dev/null); then
  USER_B_ID=$(echo "$resp" | jq -r '.user.id // .id // .user_id // empty') || true
  if [ -n "$USER_B_ID" ] && [ "$USER_B_ID" != "null" ]; then
    pass
  else
    fail "user created but no ID returned"
  fi
else
  fail "could not create User B"
fi

# -------------------------------------------------------------------------
# Login as User A
# -------------------------------------------------------------------------

begin_test "Login as User A"
USER_A_TOKEN=""
if resp=$(curl -sf $CURL_TIMEOUT -X POST "${BASE_URL}/api/v1/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${USER_A}\",\"password\":\"${USER_PASS}\"}" 2>/dev/null); then
  USER_A_TOKEN=$(echo "$resp" | jq -r '.token // .access_token // empty') || true
  if [ -n "$USER_A_TOKEN" ]; then
    pass
  else
    fail "no token in login response"
  fi
else
  fail "login as User A failed"
fi

# -------------------------------------------------------------------------
# IDOR: User A tries to read User B's tokens
# -------------------------------------------------------------------------

begin_test "User A cannot list User B tokens"
if [ -n "$USER_A_TOKEN" ] && [ -n "$USER_B_ID" ] && [ "$USER_B_ID" != "null" ]; then
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "Authorization: Bearer ${USER_A_TOKEN}" \
    "${BASE_URL}/api/v1/users/${USER_B_ID}/tokens" 2>/dev/null) || true
  if [ "$status" = "403" ]; then
    pass
  else
    fail "expected 403 for cross-user token listing, got ${status}"
  fi
else
  skip "missing user token or User B ID"
fi

# -------------------------------------------------------------------------
# IDOR: User A tries to modify User B's profile
# -------------------------------------------------------------------------

begin_test "User A cannot modify User B profile"
if [ -n "$USER_A_TOKEN" ] && [ -n "$USER_B_ID" ] && [ "$USER_B_ID" != "null" ]; then
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X PATCH \
    -H "Authorization: Bearer ${USER_A_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"email":"hacked@evil.com"}' \
    "${BASE_URL}/api/v1/users/${USER_B_ID}" 2>/dev/null) || true
  if [ "$status" = "403" ]; then
    pass
  else
    fail "expected 403 for cross-user profile update, got ${status}"
  fi
else
  skip "missing user token or User B ID"
fi

# -------------------------------------------------------------------------
# IDOR: User A tries to delete User B
# -------------------------------------------------------------------------

begin_test "User A cannot delete User B"
if [ -n "$USER_A_TOKEN" ] && [ -n "$USER_B_ID" ] && [ "$USER_B_ID" != "null" ]; then
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X DELETE \
    -H "Authorization: Bearer ${USER_A_TOKEN}" \
    "${BASE_URL}/api/v1/users/${USER_B_ID}" 2>/dev/null) || true
  if [ "$status" = "403" ]; then
    pass
  else
    fail "expected 403 for cross-user delete, got ${status}"
  fi
else
  skip "missing user token or User B ID"
fi

# -------------------------------------------------------------------------
# Verify User B still exists (not deleted by User A)
# -------------------------------------------------------------------------

begin_test "User B still exists after IDOR attempts"
if [ -n "$USER_B_ID" ] && [ "$USER_B_ID" != "null" ]; then
  if resp=$(api_get "/api/v1/users/${USER_B_ID}" 2>/dev/null); then
    if assert_contains "$resp" "$USER_B"; then
      pass
    fi
  else
    fail "User B no longer exists (IDOR delete may have succeeded)"
  fi
else
  skip "no User B ID"
fi

# -------------------------------------------------------------------------
# Verify User B email was not changed
# -------------------------------------------------------------------------

begin_test "User B email unchanged after IDOR attempts"
if [ -n "$USER_B_ID" ] && [ "$USER_B_ID" != "null" ]; then
  if resp=$(api_get "/api/v1/users/${USER_B_ID}" 2>/dev/null); then
    if assert_not_contains "$resp" "hacked@evil.com"; then
      pass
    fi
  else
    fail "could not fetch User B to verify email"
  fi
else
  skip "no User B ID"
fi

# -------------------------------------------------------------------------
# Cleanup
# -------------------------------------------------------------------------

auth_admin
api_delete "/api/v1/users/${USER_A_ID}" > /dev/null 2>&1 || true
api_delete "/api/v1/users/${USER_B_ID}" > /dev/null 2>&1 || true

end_suite
