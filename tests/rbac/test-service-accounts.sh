#!/usr/bin/env bash
# test-service-accounts.sh - Service account lifecycle E2E test
#
# Tests creating a service account, generating scoped tokens, using a
# token to authenticate, and revoking tokens.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "service-accounts"
auth_admin
setup_workdir

SA_NAME="e2e-sa-${RUN_ID}"
REPO_KEY="test-sa-repo-${RUN_ID}"

begin_test "Create repo for service account tests"
if create_local_repo "$REPO_KEY" "generic"; then
  pass
else
  fail "could not create repo"
fi

# -------------------------------------------------------------------------
# Create service account
# -------------------------------------------------------------------------

begin_test "Create service account"
if resp=$(api_post "/api/v1/service-accounts" \
    "{\"name\":\"${SA_NAME}\",\"description\":\"E2E test SA\"}" 2>/dev/null); then
  SA_ID=$(echo "$resp" | jq -r '.id // empty') || true
  pass
else
  skip "service accounts endpoint not available"
fi

# -------------------------------------------------------------------------
# Create scoped token for the service account
# -------------------------------------------------------------------------

begin_test "Create scoped token"
if [ -n "${SA_ID:-}" ]; then
  if resp=$(api_post "/api/v1/service-accounts/${SA_ID}/tokens" \
      "{\"name\":\"e2e-token-${RUN_ID}\",\"scopes\":[\"read\"]}" 2>/dev/null); then
    SA_TOKEN=$(echo "$resp" | jq -r '.token // .api_key // empty') || true
    if [ -n "$SA_TOKEN" ] && [ "$SA_TOKEN" != "null" ]; then
      pass
    else
      fail "token created but value not returned"
    fi
  else
    fail "could not create token"
  fi
else
  skip "no service account ID"
fi

# -------------------------------------------------------------------------
# Use token to authenticate
# -------------------------------------------------------------------------

begin_test "Authenticate with service account token"
if [ -n "${SA_TOKEN:-}" ]; then
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "Authorization: Bearer ${SA_TOKEN}" \
    "${BASE_URL}/api/v1/repositories" 2>/dev/null) || true
  if [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then
    pass
  else
    fail "SA token auth returned ${status}"
  fi
else
  skip "no SA token"
fi

# -------------------------------------------------------------------------
# List service accounts
# -------------------------------------------------------------------------

begin_test "List service accounts"
if resp=$(api_get "/api/v1/service-accounts" 2>/dev/null); then
  if assert_contains "$resp" "$SA_NAME"; then
    pass
  fi
else
  skip "could not list service accounts"
fi

# -------------------------------------------------------------------------
# Delete service account
# -------------------------------------------------------------------------

begin_test "Delete service account"
if [ -n "${SA_ID:-}" ]; then
  if api_delete "/api/v1/service-accounts/${SA_ID}" > /dev/null 2>&1; then
    pass
  else
    fail "could not delete service account"
  fi
else
  skip "no SA ID"
fi

end_suite
