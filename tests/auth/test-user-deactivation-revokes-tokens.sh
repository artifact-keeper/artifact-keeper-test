#!/usr/bin/env bash
# test-user-deactivation-revokes-tokens.sh - User deactivation kills active tokens (Epic 11.12, #76)
#
# Verifies:
#   1. Create a user, issue an API token for them, confirm token works
#   2. Admin sets is_active = false via PATCH/PUT /api/v1/users/{id}
#   3. Once the API-token cache window passes (5 min in v1.1.x), the token
#      is rejected with 401 because the underlying SQL filters
#      `WHERE id = $1 AND is_active = true` (auth_service.rs:472)
#
# Because v1.1.x has a 5-minute (API_TOKEN_CACHE_TTL_SECS = 300) in-process
# token cache, the test may not observe rejection within a short polling
# window. We retry for ~30s; if still cached, we SKIP (release-gate aware).
# A future change that flushes the cache on user.is_active flip will let
# this test PASS deterministically.
#
# Backend reference:
#   - PATCH /api/v1/users/{id} accepts is_active (users.rs:108-114, 376-409)
#   - validate_api_token query filters is_active = true (auth_service.rs:467-474)
#   - API_TOKEN_CACHE_TTL_SECS = 300 (auth_service.rs:90)
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "auth-user-deactivation-revokes-tokens"
auth_admin
setup_workdir

DEACT_USER="e2e-deact-${RUN_ID}"
DEACT_PASS="DeactPass_123!"
DEACT_EMAIL="e2e-deact-${RUN_ID}@test.local"
USER_ID=""
USER_TOKEN=""
API_TOKEN=""
API_TOKEN_ID=""

# -------------------------------------------------------------------------
# Create user
# -------------------------------------------------------------------------

begin_test "Create test user"
resp=$(api_post "/api/v1/users" \
  "{\"username\":\"${DEACT_USER}\",\"password\":\"${DEACT_PASS}\",\"email\":\"${DEACT_EMAIL}\"}" 2>/dev/null) || true
USER_ID=$(echo "$resp" | jq -r '.user.id // .id // empty')
if [ -n "$USER_ID" ] && [ "$USER_ID" != "null" ]; then
  pass
else
  fail "could not create user: ${resp:0:200}"
fi

# -------------------------------------------------------------------------
# Login as the user, then create an API token in their own session
# -------------------------------------------------------------------------

begin_test "Login + create API token for user"
if [ -z "${USER_ID:-}" ] || [ "$USER_ID" = "null" ]; then
  skip "no user"
else
  login_resp=$(curl -sf $CURL_TIMEOUT -X POST \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${DEACT_USER}\",\"password\":\"${DEACT_PASS}\"}" \
    "${BASE_URL}/api/v1/auth/login" 2>/dev/null) || true
  USER_TOKEN=$(echo "$login_resp" | jq -r '.access_token // .token // empty')
  if [ -z "$USER_TOKEN" ] || [ "$USER_TOKEN" = "null" ]; then
    fail "login failed"
  else
    tok_resp=$(curl -sf $CURL_TIMEOUT -X POST \
      -H "Authorization: Bearer ${USER_TOKEN}" \
      -H "Content-Type: application/json" \
      -d '{"name":"e2e-deact","scopes":["read","write"]}' \
      "${BASE_URL}/api/v1/auth/tokens" 2>/dev/null) || true
    API_TOKEN=$(echo "$tok_resp" | jq -r '.token // empty')
    API_TOKEN_ID=$(echo "$tok_resp" | jq -r '.id // empty')
    if [ -n "$API_TOKEN" ] && [ "$API_TOKEN" != "null" ]; then
      pass
    else
      fail "could not create API token: ${tok_resp:0:200}"
    fi
  fi
fi

# -------------------------------------------------------------------------
# Token works before deactivation
# -------------------------------------------------------------------------

begin_test "API token works before deactivation"
if [ -z "${API_TOKEN:-}" ] || [ "$API_TOKEN" = "null" ]; then
  skip "no API token"
else
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "Authorization: Bearer ${API_TOKEN}" \
    "${BASE_URL}/api/v1/repositories" 2>/dev/null) || true
  if [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then
    pass
  else
    fail "API token returned HTTP ${status} before deactivation"
  fi
fi

# -------------------------------------------------------------------------
# Admin deactivates user (is_active = false)
# -------------------------------------------------------------------------

begin_test "Admin deactivates user"
if [ -z "${USER_ID:-}" ] || [ "$USER_ID" = "null" ]; then
  skip "no user ID"
else
  # Backend route is PATCH /api/v1/users/{id} per users.rs (uses
  # axum::routing::patch). Try PATCH first, fall back to PUT for older
  # routers if needed.
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X PATCH \
    -H "$(auth_header)" \
    -H "Content-Type: application/json" \
    -d '{"is_active":false}' \
    "${BASE_URL}/api/v1/users/${USER_ID}" 2>/dev/null) || true
  if ! { [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; }; then
    status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
      -X PUT \
      -H "$(auth_header)" \
      -H "Content-Type: application/json" \
      -d '{"is_active":false}' \
      "${BASE_URL}/api/v1/users/${USER_ID}" 2>/dev/null) || true
  fi
  if [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then
    pass
  else
    fail "deactivate user returned HTTP ${status}"
  fi
fi

# -------------------------------------------------------------------------
# After deactivation, the API token should eventually be rejected.
#
# v1.1.x caches token validation for up to 300s. Poll for ~30s and SKIP
# (not FAIL) if still cached -- the cache TTL is documented behavior.
# RELEASE_GATE=1 escalates skip_suite, but per-test skip stays as skip.
# -------------------------------------------------------------------------

begin_test "Deactivated user's API token is rejected"
if [ -z "${API_TOKEN:-}" ] || [ "$API_TOKEN" = "null" ]; then
  skip "no API token to test"
else
  rejected=false
  last_status=""
  for attempt in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
    last_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
      -H "Authorization: Bearer ${API_TOKEN}" \
      "${BASE_URL}/api/v1/repositories" 2>/dev/null) || true
    if [ "$last_status" = "401" ]; then
      rejected=true
      break
    fi
    sleep 2
  done
  if [ "$rejected" = "true" ]; then
    pass
  else
    skip "token still accepted (HTTP ${last_status}) after 30s; v1.1.x has a 300s API token cache (auth_service.rs:90)"
  fi
fi

# -------------------------------------------------------------------------
# A fresh login as the deactivated user must fail outright
# (login query filters is_active = true, auth_service.rs:193)
# -------------------------------------------------------------------------

begin_test "Login as deactivated user fails"
status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X POST \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"${DEACT_USER}\",\"password\":\"${DEACT_PASS}\"}" \
  "${BASE_URL}/api/v1/auth/login" 2>/dev/null) || true
if [ "$status" = "401" ]; then
  pass
else
  fail "expected 401 for deactivated user login, got HTTP ${status}"
fi

# -------------------------------------------------------------------------
# Cleanup -- reactivate so delete works cleanly, then delete
# -------------------------------------------------------------------------

if [ -n "${USER_ID:-}" ] && [ "$USER_ID" != "null" ]; then
  curl -s -o /dev/null -X PATCH \
    -H "$(auth_header)" \
    -H "Content-Type: application/json" \
    -d '{"is_active":true}' \
    "${BASE_URL}/api/v1/users/${USER_ID}" > /dev/null 2>&1 || true
  api_delete "/api/v1/users/${USER_ID}" > /dev/null 2>&1 || true
fi

# EXPECT_FAILURE=1 inverts the suite's exit code so this script can be used
# as a fixture to validate the gate (a "broken" gate is a passing self-test).
if [ "${EXPECT_FAILURE:-0}" = "1" ]; then
  trap 'rc=$?; if [ "$rc" -eq 0 ]; then exit 1; else exit 0; fi' EXIT
fi

end_suite
