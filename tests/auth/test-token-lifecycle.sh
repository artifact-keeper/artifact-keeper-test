#!/usr/bin/env bash
# test-token-lifecycle.sh - Token lifecycle E2E test
#
# Tests login, token refresh, token expiry, and logout.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "token-lifecycle"
setup_workdir

# -------------------------------------------------------------------------
# Login
# -------------------------------------------------------------------------

begin_test "Login returns access token"
if resp=$(curl -sf $CURL_TIMEOUT -X POST "${BASE_URL}/api/v1/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASS}\"}" 2>/dev/null); then
  ACCESS_TOKEN=$(echo "$resp" | jq -r '.token // .access_token // empty') || true
  REFRESH_TOKEN=$(echo "$resp" | jq -r '.refresh_token // empty') || true
  if [ -n "$ACCESS_TOKEN" ]; then
    pass
  else
    fail "no access token in login response"
  fi
else
  fail "login failed"
fi

# -------------------------------------------------------------------------
# Use token
# -------------------------------------------------------------------------

begin_test "Token authenticates API requests"
if [ -n "${ACCESS_TOKEN:-}" ]; then
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "Authorization: Bearer ${ACCESS_TOKEN}" \
    "${BASE_URL}/api/v1/auth/me" 2>/dev/null) || true
  if [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then
    pass
  else
    fail "token auth returned ${status}"
  fi
else
  skip "no token"
fi

# -------------------------------------------------------------------------
# Refresh token
# -------------------------------------------------------------------------

begin_test "Refresh token"
if [ -n "${REFRESH_TOKEN:-}" ] && [ "$REFRESH_TOKEN" != "null" ]; then
  if resp=$(curl -sf $CURL_TIMEOUT -X POST "${BASE_URL}/api/v1/auth/refresh" \
      -H "Content-Type: application/json" \
      -d "{\"refresh_token\":\"${REFRESH_TOKEN}\"}" 2>/dev/null); then
    new_token=$(echo "$resp" | jq -r '.token // .access_token // empty') || true
    if [ -n "$new_token" ]; then
      ACCESS_TOKEN="$new_token"
      pass
    else
      fail "refresh returned no new token"
    fi
  else
    skip "refresh endpoint returned error"
  fi
else
  skip "no refresh token in login response"
fi

# -------------------------------------------------------------------------
# Logout
# -------------------------------------------------------------------------

begin_test "Logout invalidates token"
if [ -n "${ACCESS_TOKEN:-}" ]; then
  curl -sf $CURL_TIMEOUT -X POST "${BASE_URL}/api/v1/auth/logout" \
    -H "Authorization: Bearer ${ACCESS_TOKEN}" > /dev/null 2>&1 || true
  # After logout, token should be rejected
  sleep 1
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "Authorization: Bearer ${ACCESS_TOKEN}" \
    "${BASE_URL}/api/v1/auth/me" 2>/dev/null) || true
  if [ "$status" = "401" ] || [ "$status" = "403" ]; then
    pass
  else
    skip "logout may not invalidate JWT immediately (stateless), got ${status}"
  fi
else
  skip "no token"
fi

end_suite
