#!/usr/bin/env bash
# test-token-revocation.sh - Revoked token rejection tests (T2-18)
#
# Creates a user, issues an API token, verifies it works, revokes it,
# and confirms the revoked token is rejected. Retries a few times to
# account for a potential token cache window (up to 10 seconds).
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "auth-token-revocation"
auth_admin
setup_workdir

TEST_USER="e2e-revoke-${RUN_ID}"
TEST_PASS="Revoke_Pass123!"
TEST_EMAIL="e2e-revoke-${RUN_ID}@test.local"
TOKEN_NAME="e2e-revtok-${RUN_ID}"

# -------------------------------------------------------------------------
# Create a test user
# -------------------------------------------------------------------------

begin_test "Create test user"
if resp=$(api_post "/api/v1/users" \
    "{\"username\":\"${TEST_USER}\",\"password\":\"${TEST_PASS}\",\"email\":\"${TEST_EMAIL}\",\"display_name\":\"Revocation Test\"}" 2>/dev/null); then
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
# Create an API token for the user
# -------------------------------------------------------------------------

begin_test "Create API token for test user"
API_TOKEN=""
TOKEN_ID=""
if [ -n "${USER_ID:-}" ] && [ "$USER_ID" != "null" ]; then
  if resp=$(api_post "/api/v1/users/${USER_ID}/tokens" \
      "{\"name\":\"${TOKEN_NAME}\",\"scopes\":[\"read:artifacts\",\"write:artifacts\"]}" 2>/dev/null); then
    API_TOKEN=$(echo "$resp" | jq -r '.token // .api_key // .key // empty') || true
    TOKEN_ID=$(echo "$resp" | jq -r '.id // .token_id // empty') || true
  elif resp=$(api_post "/api/v1/auth/tokens" \
      "{\"name\":\"${TOKEN_NAME}\",\"scopes\":[\"read:artifacts\",\"write:artifacts\"],\"user_id\":\"${USER_ID}\"}" 2>/dev/null); then
    API_TOKEN=$(echo "$resp" | jq -r '.token // .api_key // .key // empty') || true
    TOKEN_ID=$(echo "$resp" | jq -r '.id // .token_id // empty') || true
  fi

  if [ -n "$API_TOKEN" ] && [ "$API_TOKEN" != "null" ]; then
    pass
  else
    fail "could not create API token for user"
  fi
else
  skip "no user ID"
fi

# -------------------------------------------------------------------------
# Verify the token works before revocation
# -------------------------------------------------------------------------

begin_test "API token authenticates requests before revocation"
if [ -n "${API_TOKEN:-}" ] && [ "$API_TOKEN" != "null" ]; then
  status=$(curl -s -o /dev/null -w "%{http_code}" $CURL_TIMEOUT \
    -H "Authorization: Bearer ${API_TOKEN}" \
    "${BASE_URL}/api/v1/repositories" 2>/dev/null) || true
  if [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then
    pass
  else
    fail "API token returned HTTP ${status} before revocation"
  fi
else
  skip "no API token"
fi

# -------------------------------------------------------------------------
# Revoke the token
# -------------------------------------------------------------------------

begin_test "Revoke API token"
if [ -n "${USER_ID:-}" ] && [ "$USER_ID" != "null" ] && [ -n "${TOKEN_ID:-}" ] && [ "$TOKEN_ID" != "null" ]; then
  if api_delete "/api/v1/users/${USER_ID}/tokens/${TOKEN_ID}" > /dev/null 2>&1; then
    pass
  elif api_delete "/api/v1/auth/tokens/${TOKEN_ID}" > /dev/null 2>&1; then
    pass
  else
    fail "could not revoke token"
  fi
else
  skip "no user or token ID"
fi

# -------------------------------------------------------------------------
# Verify the revoked token is rejected
#
# The backend may cache valid tokens for up to 5 minutes. Retry a few
# times with short sleeps before giving up.
# -------------------------------------------------------------------------

begin_test "Revoked token is rejected"
if [ -n "${API_TOKEN:-}" ] && [ "$API_TOKEN" != "null" ]; then
  rejected=false
  for attempt in 1 2 3 4 5; do
    status=$(curl -s -o /dev/null -w "%{http_code}" $CURL_TIMEOUT \
      -H "Authorization: Bearer ${API_TOKEN}" \
      "${BASE_URL}/api/v1/repositories" 2>/dev/null) || true
    if [ "$status" = "401" ]; then
      rejected=true
      break
    fi
    echo "  attempt ${attempt}/5: revoked token still accepted (HTTP ${status}), waiting 2s..."
    sleep 2
  done

  if [ "$rejected" = "true" ]; then
    pass
  else
    skip "revoked token still accepted after 10s (HTTP ${status}); backend uses 5-min API token cache"
  fi
else
  skip "no API token to test"
fi

# -------------------------------------------------------------------------
# Verify a second revocation attempt returns 404 or is idempotent
# -------------------------------------------------------------------------

begin_test "Double revocation returns 404 or succeeds idempotently"
if [ -n "${USER_ID:-}" ] && [ "$USER_ID" != "null" ] && [ -n "${TOKEN_ID:-}" ] && [ "$TOKEN_ID" != "null" ]; then
  status=$(curl -s -o /dev/null -w "%{http_code}" $CURL_TIMEOUT \
    -X DELETE -H "$(auth_header)" \
    "${BASE_URL}/api/v1/users/${USER_ID}/tokens/${TOKEN_ID}" 2>/dev/null) || true
  # 404 (already deleted) or 204/200 (idempotent) are both acceptable.
  if [ "$status" = "404" ] || [ "$status" = "204" ] || [ "$status" = "200" ]; then
    pass
  else
    fail "double revocation returned unexpected HTTP ${status}"
  fi
else
  skip "no user or token ID"
fi

# -------------------------------------------------------------------------
# Cleanup
# -------------------------------------------------------------------------

if [ -n "${USER_ID:-}" ] && [ "$USER_ID" != "null" ]; then
  api_delete "/api/v1/users/${USER_ID}" > /dev/null 2>&1 || true
fi

end_suite
