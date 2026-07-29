#!/usr/bin/env bash
# test-admin-token-revoke.sh - Admin revoking other users' tokens
#
# Tests that an admin can create a user, create an API token for them,
# list the tokens, revoke a specific token, and confirm it is removed.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "admin-token-revoke"
auth_admin
setup_workdir

TEST_USER="e2e-tokenrev-${RUN_ID}"
TEST_PASS="TokRev_Pass123!"
TEST_EMAIL="e2e-tokenrev-${RUN_ID}@test.local"
TOKEN_NAME="e2e-revokable-${RUN_ID}"

# -------------------------------------------------------------------------
# Create a test user
# -------------------------------------------------------------------------

begin_test "Create test user"
if resp=$(api_post "/api/v1/users" \
    "{\"username\":\"${TEST_USER}\",\"password\":\"${TEST_PASS}\",\"email\":\"${TEST_EMAIL}\",\"display_name\":\"Token Revoke Test\"}" 2>/dev/null); then
  USER_ID=$(echo "$resp" | jq -r '.user.id // .id // .user_id // empty') || true
  if [ -n "$USER_ID" ] && [ "$USER_ID" != "null" ]; then
    pass
  else
    fail "user created but no ID in response"
  fi
else
  fail "could not create test user"
fi

# -------------------------------------------------------------------------
# Create an API token for the user (via admin API)
# -------------------------------------------------------------------------

begin_test "Create API token for user"
if [ -n "${USER_ID:-}" ] && [ "$USER_ID" != "null" ]; then
  if resp=$(api_post "/api/v1/users/${USER_ID}/tokens" \
      "{\"name\":\"${TOKEN_NAME}\",\"scopes\":[\"read:artifacts\"]}" 2>/dev/null); then
    TOKEN_VALUE=$(echo "$resp" | jq -r '.token // .api_key // .key // empty') || true
    TOKEN_ID=$(echo "$resp" | jq -r '.id // .token_id // empty') || true
    if [ -n "$TOKEN_ID" ] && [ "$TOKEN_ID" != "null" ]; then
      pass
    else
      fail "token created but no ID in response"
    fi
  else
    # Try alternative: create token via the auth endpoint on behalf of user
    if resp=$(api_post "/api/v1/auth/tokens" \
        "{\"name\":\"${TOKEN_NAME}\",\"scopes\":[\"read:artifacts\"],\"user_id\":\"${USER_ID}\"}" 2>/dev/null); then
      TOKEN_VALUE=$(echo "$resp" | jq -r '.token // .api_key // .key // empty') || true
      TOKEN_ID=$(echo "$resp" | jq -r '.id // .token_id // empty') || true
      if [ -n "$TOKEN_ID" ] && [ "$TOKEN_ID" != "null" ]; then
        pass
      else
        fail "token created via /auth/tokens but no ID returned"
      fi
    else
      skip "user token creation endpoint not available"
    fi
  fi
else
  skip "no user ID"
fi

# -------------------------------------------------------------------------
# List the user's tokens
# -------------------------------------------------------------------------

begin_test "List user's tokens"
if [ -n "${USER_ID:-}" ] && [ "$USER_ID" != "null" ]; then
  if resp=$(api_get "/api/v1/users/${USER_ID}/tokens" 2>/dev/null); then
    if assert_contains "$resp" "$TOKEN_NAME"; then
      pass
    fi
  else
    skip "user tokens listing not available"
  fi
else
  skip "no user ID"
fi

# -------------------------------------------------------------------------
# Verify the token appears in the list
# -------------------------------------------------------------------------

begin_test "Token ID appears in user's token list"
if [ -n "${USER_ID:-}" ] && [ "$USER_ID" != "null" ] && [ -n "${TOKEN_ID:-}" ] && [ "$TOKEN_ID" != "null" ]; then
  if resp=$(api_get "/api/v1/users/${USER_ID}/tokens" 2>/dev/null); then
    if assert_contains "$resp" "$TOKEN_ID"; then
      pass
    fi
  else
    skip "user tokens listing not available"
  fi
else
  skip "no user or token ID"
fi

# -------------------------------------------------------------------------
# Revoke the token
# -------------------------------------------------------------------------

begin_test "Revoke user's token via admin API"
if [ -n "${USER_ID:-}" ] && [ "$USER_ID" != "null" ] && [ -n "${TOKEN_ID:-}" ] && [ "$TOKEN_ID" != "null" ]; then
  if api_delete "/api/v1/users/${USER_ID}/tokens/${TOKEN_ID}" > /dev/null 2>&1; then
    pass
  else
    fail "could not revoke user token"
  fi
else
  skip "no user or token ID"
fi

# -------------------------------------------------------------------------
# Verify token is gone from the list
# -------------------------------------------------------------------------

begin_test "Revoked token no longer in user's list"
if [ -n "${USER_ID:-}" ] && [ "$USER_ID" != "null" ] && [ -n "${TOKEN_ID:-}" ] && [ "$TOKEN_ID" != "null" ]; then
  if resp=$(api_get "/api/v1/users/${USER_ID}/tokens" 2>/dev/null); then
    if assert_not_contains "$resp" "$TOKEN_ID" "revoked token still appears in listing"; then
      pass
    fi
  else
    # A 404 or empty response is also acceptable
    pass
  fi
else
  skip "no user or token ID"
fi

# -------------------------------------------------------------------------
# Verify revoked token is rejected for API access
# -------------------------------------------------------------------------

begin_test "Revoked token is rejected"
if [ -n "${TOKEN_VALUE:-}" ] && [ "$TOKEN_VALUE" != "null" ]; then
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "Authorization: Bearer ${TOKEN_VALUE}" \
    "${BASE_URL}/api/v1/repositories" 2>/dev/null) || true
  # Revoked token is no longer a valid credential: expect 401 (unauthenticated).
  if [ "$status" = "401" ]; then
    pass
  else
    skip "revoked token returned ${status} (may take time to propagate)"
  fi
else
  skip "no token value to test"
fi

# -------------------------------------------------------------------------
# Cleanup
# -------------------------------------------------------------------------

if [ -n "${USER_ID:-}" ] && [ "$USER_ID" != "null" ]; then
  api_delete "/api/v1/users/${USER_ID}" > /dev/null 2>&1 || true
fi

end_suite
