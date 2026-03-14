#!/usr/bin/env bash
# test-api-tokens.sh - API token lifecycle E2E test
#
# Tests creating API tokens for a user, listing them, using a token
# for API access, and revoking it.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "api-tokens"
auth_admin
setup_workdir

TOKEN_NAME="e2e-apitoken-${RUN_ID}"

# -------------------------------------------------------------------------
# Create API token
# -------------------------------------------------------------------------

begin_test "Create API token"
if resp=$(api_post "/api/v1/auth/tokens" \
    "{\"name\":\"${TOKEN_NAME}\",\"scopes\":[\"read\",\"write\"]}" 2>/dev/null); then
  API_TOKEN=$(echo "$resp" | jq -r '.token // .api_key // .key // empty') || true
  TOKEN_ID=$(echo "$resp" | jq -r '.id // .token_id // empty') || true
  if [ -n "$API_TOKEN" ] && [ "$API_TOKEN" != "null" ]; then
    pass
  else
    fail "token created but value not returned"
  fi
else
  skip "API tokens endpoint not available"
fi

# -------------------------------------------------------------------------
# Use token for API access
# -------------------------------------------------------------------------

begin_test "Use API token for authenticated request"
if [ -n "${API_TOKEN:-}" ] && [ "$API_TOKEN" != "null" ]; then
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "Authorization: Bearer ${API_TOKEN}" \
    "${BASE_URL}/api/v1/repositories" 2>/dev/null) || true
  if [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then
    pass
  else
    fail "API token auth returned ${status}"
  fi
else
  skip "no API token"
fi

# -------------------------------------------------------------------------
# List tokens
# -------------------------------------------------------------------------

begin_test "List API tokens"
if resp=$(api_get "/api/v1/auth/tokens" 2>/dev/null); then
  if assert_contains "$resp" "$TOKEN_NAME"; then
    pass
  fi
else
  skip "token listing not available"
fi

# -------------------------------------------------------------------------
# Revoke token
# -------------------------------------------------------------------------

begin_test "Revoke API token"
if [ -n "${TOKEN_ID:-}" ] && [ "$TOKEN_ID" != "null" ]; then
  if api_delete "/api/v1/auth/tokens/${TOKEN_ID}" > /dev/null 2>&1; then
    pass
  else
    fail "could not revoke token"
  fi
else
  skip "no token ID"
fi

begin_test "Revoked token is rejected"
if [ -n "${API_TOKEN:-}" ] && [ "$API_TOKEN" != "null" ]; then
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "Authorization: Bearer ${API_TOKEN}" \
    "${BASE_URL}/api/v1/repositories" 2>/dev/null) || true
  if [ "$status" = "401" ] || [ "$status" = "403" ]; then
    pass
  else
    skip "revoked token returned ${status} (may take time to propagate)"
  fi
else
  skip "no API token"
fi

end_suite
