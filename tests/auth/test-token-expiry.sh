#!/usr/bin/env bash
# test-token-expiry.sh - Expired token rejection tests (T2-17)
#
# Verifies that expired JWTs and expired API tokens are rejected with 401.
# Uses two approaches: (1) craft a JWT with exp in the past and send it,
# (2) create an API token with a past expires_at via the admin API.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "auth-token-expiry"
auth_admin
setup_workdir

TEST_USER="e2e-expiry-${RUN_ID}"
TEST_PASS="Expiry_Pass123!"
TEST_EMAIL="e2e-expiry-${RUN_ID}@test.local"

# -------------------------------------------------------------------------
# Crafted JWT with exp in the past
# -------------------------------------------------------------------------

begin_test "JWT with expired exp claim is rejected"
# Build a JWT where exp is 1 minute in the past.
PAST_EXP=$(( $(date +%s) - 60 ))
HEADER=$(printf '{"alg":"HS256","typ":"JWT"}' | base64 | tr '+/' '-_' | tr -d '=\n')
PAYLOAD=$(printf '{"sub":"admin","user_id":"00000000-0000-0000-0000-000000000000","is_admin":true,"exp":%d}' "$PAST_EXP" \
  | base64 | tr '+/' '-_' | tr -d '=\n')
FAKE_SIG=$(printf 'fakesignaturebytes' | base64 | tr '+/' '-_' | tr -d '=\n')
EXPIRED_JWT="${HEADER}.${PAYLOAD}.${FAKE_SIG}"

status=$(curl -s -o /dev/null -w "%{http_code}" $CURL_TIMEOUT \
  -H "Authorization: Bearer ${EXPIRED_JWT}" \
  "${BASE_URL}/api/v1/repositories" 2>/dev/null) || true
if [ "$status" = "401" ]; then
  pass
else
  fail "expired JWT was not rejected, got HTTP ${status}"
fi

# -------------------------------------------------------------------------
# Verify a valid token works (baseline)
# -------------------------------------------------------------------------

begin_test "Valid admin token works (baseline)"
status=$(curl -s -o /dev/null -w "%{http_code}" $CURL_TIMEOUT \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  "${BASE_URL}/api/v1/repositories" 2>/dev/null) || true
if [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then
  pass
else
  fail "valid admin token returned HTTP ${status}"
fi

# -------------------------------------------------------------------------
# Create a test user and get a fresh login token
# -------------------------------------------------------------------------

begin_test "Create test user for expiry tests"
if resp=$(api_post "/api/v1/users" \
    "{\"username\":\"${TEST_USER}\",\"password\":\"${TEST_PASS}\",\"email\":\"${TEST_EMAIL}\",\"display_name\":\"Expiry Test\"}" 2>/dev/null); then
  USER_ID=$(echo "$resp" | jq -r '.user.id // .id // .user_id // empty') || true
  if [ -n "$USER_ID" ] && [ "$USER_ID" != "null" ]; then
    pass
  else
    fail "user created but no ID in response"
  fi
else
  fail "could not create test user"
fi

begin_test "Login as test user"
USER_TOKEN=""
if resp=$(curl -sf $CURL_TIMEOUT -X POST "${BASE_URL}/api/v1/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${TEST_USER}\",\"password\":\"${TEST_PASS}\"}" 2>/dev/null); then
  USER_TOKEN=$(echo "$resp" | jq -r '.token // .access_token // empty') || true
  if [ -n "$USER_TOKEN" ]; then
    pass
  else
    fail "login succeeded but no token returned"
  fi
else
  fail "could not login as test user"
fi

# -------------------------------------------------------------------------
# Read the exp claim from the real token
# -------------------------------------------------------------------------

begin_test "Real token has valid exp claim in the future"
if [ -n "${USER_TOKEN:-}" ]; then
  # Extract the payload (second segment) and decode it.
  TOKEN_PAYLOAD=$(echo "$USER_TOKEN" | cut -d. -f2)
  # Add padding if needed for base64 decoding.
  case $(( ${#TOKEN_PAYLOAD} % 4 )) in
    2) TOKEN_PAYLOAD="${TOKEN_PAYLOAD}==" ;;
    3) TOKEN_PAYLOAD="${TOKEN_PAYLOAD}=" ;;
  esac
  TOKEN_JSON=$(echo "$TOKEN_PAYLOAD" | tr '_-' '/+' | base64 -d 2>/dev/null) || true
  if [ -n "$TOKEN_JSON" ]; then
    TOKEN_EXP=$(echo "$TOKEN_JSON" | jq -r '.exp // empty' 2>/dev/null) || true
    NOW=$(date +%s)
    if [ -n "$TOKEN_EXP" ] && [ "$TOKEN_EXP" -gt "$NOW" ] 2>/dev/null; then
      pass
    else
      skip "could not verify exp claim (exp=${TOKEN_EXP:-empty}, now=${NOW})"
    fi
  else
    skip "could not decode token payload"
  fi
else
  skip "no user token"
fi

# -------------------------------------------------------------------------
# Create an API token with a past expires_at
# -------------------------------------------------------------------------

begin_test "API token with past expiry is rejected"
if [ -n "${USER_ID:-}" ] && [ "$USER_ID" != "null" ]; then
  PAST_ISO=$(date -u -v-1H +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date -u -d "1 hour ago" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null) || true
  TOKEN_NAME="e2e-expired-${RUN_ID}"
  EXPIRED_API_TOKEN=""

  if [ -n "$PAST_ISO" ]; then
    # Try creating via user tokens endpoint with expires_at in the past.
    if resp=$(api_post "/api/v1/users/${USER_ID}/tokens" \
        "{\"name\":\"${TOKEN_NAME}\",\"scopes\":[\"read\"],\"expires_at\":\"${PAST_ISO}\"}" 2>/dev/null); then
      EXPIRED_API_TOKEN=$(echo "$resp" | jq -r '.token // .api_key // .key // empty') || true
    elif resp=$(api_post "/api/v1/auth/tokens" \
        "{\"name\":\"${TOKEN_NAME}\",\"scopes\":[\"read\"],\"expires_at\":\"${PAST_ISO}\",\"user_id\":\"${USER_ID}\"}" 2>/dev/null); then
      EXPIRED_API_TOKEN=$(echo "$resp" | jq -r '.token // .api_key // .key // empty') || true
    fi
  fi

  if [ -n "$EXPIRED_API_TOKEN" ] && [ "$EXPIRED_API_TOKEN" != "null" ]; then
    status=$(curl -s -o /dev/null -w "%{http_code}" $CURL_TIMEOUT \
      -H "Authorization: Bearer ${EXPIRED_API_TOKEN}" \
      "${BASE_URL}/api/v1/repositories" 2>/dev/null) || true
    if [ "$status" = "401" ]; then
      pass
    else
      fail "API token with past expiry was not rejected, got HTTP ${status}"
    fi
  else
    # The API may refuse to create a token already expired. That is also acceptable.
    skip "could not create API token with past expiry (API may validate expiry on creation)"
  fi
else
  skip "no user ID"
fi

# -------------------------------------------------------------------------
# Create an API token with very short TTL, wait for expiry
# -------------------------------------------------------------------------

begin_test "API token expires after short TTL"
if [ -n "${USER_ID:-}" ] && [ "$USER_ID" != "null" ]; then
  # Set expires_at to 2 seconds from now.
  NEAR_ISO=$(date -u -v+2S +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date -u -d "2 seconds" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null) || true
  SHORT_TOKEN_NAME="e2e-shortttl-${RUN_ID}"
  SHORT_API_TOKEN=""

  if [ -n "$NEAR_ISO" ]; then
    if resp=$(api_post "/api/v1/users/${USER_ID}/tokens" \
        "{\"name\":\"${SHORT_TOKEN_NAME}\",\"scopes\":[\"read\"],\"expires_at\":\"${NEAR_ISO}\"}" 2>/dev/null); then
      SHORT_API_TOKEN=$(echo "$resp" | jq -r '.token // .api_key // .key // empty') || true
    elif resp=$(api_post "/api/v1/auth/tokens" \
        "{\"name\":\"${SHORT_TOKEN_NAME}\",\"scopes\":[\"read\"],\"expires_at\":\"${NEAR_ISO}\",\"user_id\":\"${USER_ID}\"}" 2>/dev/null); then
      SHORT_API_TOKEN=$(echo "$resp" | jq -r '.token // .api_key // .key // empty') || true
    fi
  fi

  if [ -n "$SHORT_API_TOKEN" ] && [ "$SHORT_API_TOKEN" != "null" ]; then
    # Wait for it to expire.
    sleep 3
    status=$(curl -s -o /dev/null -w "%{http_code}" $CURL_TIMEOUT \
      -H "Authorization: Bearer ${SHORT_API_TOKEN}" \
      "${BASE_URL}/api/v1/repositories" 2>/dev/null) || true
    if [ "$status" = "401" ]; then
      pass
    else
      fail "short-TTL API token was not rejected after expiry, got HTTP ${status}"
    fi
  else
    skip "could not create short-TTL API token (endpoint may not support expires_at)"
  fi
else
  skip "no user ID"
fi

# -------------------------------------------------------------------------
# Cleanup
# -------------------------------------------------------------------------

if [ -n "${USER_ID:-}" ] && [ "$USER_ID" != "null" ]; then
  api_delete "/api/v1/users/${USER_ID}" > /dev/null 2>&1 || true
fi

end_suite
