#!/usr/bin/env bash
# test-proxy-config.sh - Proxy configuration sanity check
#
# Lightweight test that verifies the backend is running and healthy.
# Proxy configuration detection is internal to the backend and not
# directly observable via API, so this test confirms the health
# endpoint works and checks for any proxy-related fields in the
# system info response.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "proxy-config"
auth_admin

# -------------------------------------------------------------------------
# Backend health check
# -------------------------------------------------------------------------

begin_test "Backend health endpoint responds"
status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    "${BASE_URL}/api/v1/system/health" 2>/dev/null) || true
if [ "$status" = "200" ]; then
  pass
else
  # Try alternate health endpoints
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
      "${BASE_URL}/health" 2>/dev/null) || true
  if [ "$status" = "200" ]; then
    pass
  elif status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
      "${BASE_URL}/readyz" 2>/dev/null) && [ "$status" = "200" ]; then
    pass
  else
    fail "no health endpoint responded with 200"
  fi
fi

# -------------------------------------------------------------------------
# System info or config endpoint (may expose proxy settings)
# -------------------------------------------------------------------------

begin_test "Check system info for proxy configuration"
resp=""
if resp=$(api_get "/api/v1/system/info" 2>/dev/null); then
  : # got response
elif resp=$(api_get "/api/v1/admin/system/info" 2>/dev/null); then
  : # got response from admin endpoint
elif resp=$(api_get "/api/v1/admin/settings" 2>/dev/null); then
  : # got response from settings endpoint
fi

if [ -n "$resp" ] && echo "$resp" | jq -e '.' > /dev/null 2>&1; then
  # Check if the response mentions proxy configuration
  if echo "$resp" | jq -e '.proxy // .proxy_config // .http_proxy' > /dev/null 2>&1; then
    pass
  else
    skip "system info available but does not expose proxy configuration"
  fi
else
  skip "system info endpoint not available, proxy config not observable via API"
fi

# -------------------------------------------------------------------------
# Verify remote repos can be created (proxy path is functional)
# -------------------------------------------------------------------------

begin_test "Remote repository creation works"
REPO_KEY="test-proxy-sanity-${RUN_ID}"
if create_remote_repo "$REPO_KEY" "generic" "https://example.com/upstream"; then
  pass
  api_delete "/api/v1/repositories/${REPO_KEY}" > /dev/null 2>&1 || true
else
  fail "could not create remote repository"
fi

end_suite
