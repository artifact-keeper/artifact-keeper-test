#!/usr/bin/env bash
# test-refresh-token-rotation.sh - Refresh token TTL and rotation (Epic 11.13, #76)
#
# Verifies:
#   1. Login returns access_token + refresh_token + expires_in
#   2. Access TTL (expires_in) is shorter than refresh TTL
#      (refresh expiry observable by decoding the JWT exp claim)
#   3. POST /auth/refresh with the refresh_token returns a new pair
#   4. Re-using the OLD refresh_token after rotation is rejected (401)
#      -- if rotation is enforced. v1.1.x's refresh_tokens just calls
#      generate_tokens without invalidating the old refresh, so the test
#      treats reuse-rejection as a desirable feature and SKIPs (with a
#      precise reason) if the backend still accepts the old token.
#
# Backend reference:
#   - auth_service::refresh_tokens (auth_service.rs:290) decodes the refresh,
#     fetches the user, and generates a brand-new pair. There is no
#     family_id / used_at table in v1.1.x, so reuse-rejection is a
#     known gap tracked under Epic 11.
#   - jwt_access_token_expiry_minutes default = 30, jwt_refresh_token_expiry_days
#     default = 7 (auth_service.rs:1232-1233)
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "auth-refresh-rotation"
auth_admin
setup_workdir

REFRESH_USER="e2e-refresh-${RUN_ID}"
REFRESH_PASS="RefreshPass_123!"
REFRESH_EMAIL="e2e-refresh-${RUN_ID}@test.local"
USER_ID=""
ACCESS_TOKEN=""
REFRESH_TOKEN=""
EXPIRES_IN=""
NEW_ACCESS=""
NEW_REFRESH=""

# -------------------------------------------------------------------------
# Helper: base64url decode the JWT payload (no signature check) and print exp.
# Returns empty string if it cannot decode.
# -------------------------------------------------------------------------

jwt_exp() {
  local jwt="$1"
  local payload="${jwt#*.}"
  payload="${payload%%.*}"
  # base64url -> base64
  payload="${payload//-/+}"
  payload="${payload//_/\/}"
  # pad
  local mod=$(( ${#payload} % 4 ))
  if [ "$mod" -eq 2 ]; then payload="${payload}=="; fi
  if [ "$mod" -eq 3 ]; then payload="${payload}="; fi
  echo "$payload" | base64 -d 2>/dev/null | jq -r '.exp // empty' 2>/dev/null || true
}

# -------------------------------------------------------------------------
# Setup user (we use a fresh user so admin's session doesn't affect anything)
# -------------------------------------------------------------------------

begin_test "Create test user"
USER_ID=$(create_test_user "${REFRESH_USER}" "${REFRESH_PASS}" "${REFRESH_EMAIL}") || true
if [ -n "$USER_ID" ]; then
  pass
else
  fail "could not create user"
fi

# -------------------------------------------------------------------------
# Login -> capture access + refresh + expires_in
# -------------------------------------------------------------------------

begin_test "Login returns access_token, refresh_token, expires_in"
if [ -z "${USER_ID:-}" ] || [ "$USER_ID" = "null" ]; then
  skip "no user"
else
  resp=$(curl -sf $CURL_TIMEOUT -X POST \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${REFRESH_USER}\",\"password\":\"${REFRESH_PASS}\"}" \
    "${BASE_URL}/api/v1/auth/login" 2>/dev/null) || true
  ACCESS_TOKEN=$(echo "$resp" | jq -r '.access_token // .token // empty')
  REFRESH_TOKEN=$(echo "$resp" | jq -r '.refresh_token // empty')
  EXPIRES_IN=$(echo "$resp" | jq -r '.expires_in // empty')
  if [ -n "$ACCESS_TOKEN" ] && [ -n "$REFRESH_TOKEN" ] && [ "$REFRESH_TOKEN" != "null" ] \
       && [[ "$EXPIRES_IN" =~ ^[0-9]+$ ]]; then
    pass
  else
    fail "login response missing fields: access='${ACCESS_TOKEN:0:8}…' refresh='${REFRESH_TOKEN:0:8}…' expires_in='${EXPIRES_IN}'"
  fi
fi

# -------------------------------------------------------------------------
# Access TTL is shorter than refresh TTL
#
# We compare:
#   - login response expires_in (access TTL in seconds)
#   - refresh JWT exp - now (refresh TTL in seconds)
# -------------------------------------------------------------------------

begin_test "Access token TTL is shorter than refresh token TTL"
if [ -z "${REFRESH_TOKEN:-}" ] || [ "$REFRESH_TOKEN" = "null" ] || [ -z "${EXPIRES_IN:-}" ]; then
  skip "no tokens to compare"
else
  refresh_exp=$(jwt_exp "$REFRESH_TOKEN")
  if ! [[ "$refresh_exp" =~ ^[0-9]+$ ]]; then
    skip "could not decode refresh token exp claim"
  else
    now=$(date +%s)
    refresh_ttl=$(( refresh_exp - now ))
    if [ "$refresh_ttl" -gt "$EXPIRES_IN" ]; then
      pass
    else
      fail "refresh TTL (${refresh_ttl}s) not greater than access TTL (${EXPIRES_IN}s)"
    fi
  fi
fi

# -------------------------------------------------------------------------
# Use refresh -> get new pair
# -------------------------------------------------------------------------

begin_test "Refresh returns a new access + refresh pair"
if [ -z "${REFRESH_TOKEN:-}" ] || [ "$REFRESH_TOKEN" = "null" ]; then
  skip "no refresh token"
else
  # Sleep 1s so JWT iat differs and the rotated token is observably distinct.
  sleep 1
  resp=$(curl -sf $CURL_TIMEOUT -X POST \
    -H "Content-Type: application/json" \
    -d "{\"refresh_token\":\"${REFRESH_TOKEN}\"}" \
    "${BASE_URL}/api/v1/auth/refresh" 2>/dev/null) || true
  NEW_ACCESS=$(echo "$resp" | jq -r '.access_token // .token // empty')
  NEW_REFRESH=$(echo "$resp" | jq -r '.refresh_token // empty')
  if [ -n "$NEW_ACCESS" ] && [ "$NEW_ACCESS" != "null" ]; then
    pass
  else
    fail "refresh did not return new access token: ${resp:0:200}"
  fi
fi

# -------------------------------------------------------------------------
# New access token actually authenticates
# -------------------------------------------------------------------------

begin_test "New access token authenticates /auth/me"
if [ -z "${NEW_ACCESS:-}" ] || [ "$NEW_ACCESS" = "null" ]; then
  skip "no rotated access token"
else
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "Authorization: Bearer ${NEW_ACCESS}" \
    "${BASE_URL}/api/v1/auth/me" 2>/dev/null) || true
  status="${status:-000}"
  if [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then
    pass
  else
    fail "new access token returned HTTP ${status}"
  fi
fi

# -------------------------------------------------------------------------
# OLD refresh token reuse should be rejected (rotation invariant).
#
# v1.1.x's refresh_tokens implementation does NOT mark the old refresh as
# used; it just generates a fresh pair. So this test SKIPs in 1.1.x and
# will start passing automatically when refresh-token rotation lands.
# -------------------------------------------------------------------------

begin_test "Re-using the old refresh token after rotation is rejected"
if [ -z "${REFRESH_TOKEN:-}" ] || [ "$REFRESH_TOKEN" = "null" ]; then
  skip "no original refresh token"
elif require_feature "refresh_token_rotation"; then
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X POST \
    -H "Content-Type: application/json" \
    -d "{\"refresh_token\":\"${REFRESH_TOKEN}\"}" \
    "${BASE_URL}/api/v1/auth/refresh" 2>/dev/null) || true
  status="${status:-000}"
  if [ "$status" = "401" ]; then
    pass
  else
    fail "expected 401 for old refresh token reuse, got HTTP ${status}"
  fi
fi

# -------------------------------------------------------------------------
# A clearly invalid refresh token is rejected
# -------------------------------------------------------------------------

begin_test "Garbage refresh token returns 401"
status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"not-a-real-jwt"}' \
  "${BASE_URL}/api/v1/auth/refresh" 2>/dev/null) || true
status="${status:-000}"
if [ "$status" = "401" ]; then
  pass
else
  fail "expected 401 for garbage refresh token, got HTTP ${status}"
fi

# -------------------------------------------------------------------------
# An access token cannot be used as a refresh token (token_type check)
# -------------------------------------------------------------------------

begin_test "Access token is rejected when used as refresh"
if [ -z "${ACCESS_TOKEN:-}" ] || [ "$ACCESS_TOKEN" = "null" ]; then
  skip "no access token"
else
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X POST \
    -H "Content-Type: application/json" \
    -d "{\"refresh_token\":\"${ACCESS_TOKEN}\"}" \
    "${BASE_URL}/api/v1/auth/refresh" 2>/dev/null) || true
  status="${status:-000}"
  if [ "$status" = "401" ]; then
    pass
  else
    fail "expected 401 when using access token as refresh, got HTTP ${status}"
  fi
fi

# -------------------------------------------------------------------------
# Cleanup
# -------------------------------------------------------------------------

if [ -n "${USER_ID:-}" ] && [ "$USER_ID" != "null" ]; then
  api_delete "/api/v1/users/${USER_ID}" > /dev/null 2>&1 || true
fi

# EXPECT_FAILURE=1 inverts the suite's exit code so this script can be used
# as a fixture to validate the gate (a "broken" gate is a passing self-test).
enable_expect_failure_trap

end_suite
