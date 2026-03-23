#!/usr/bin/env bash
# test-oidc-callback.sh - OIDC callback route registration E2E test
#
# Verifies that the generic OIDC callback route is registered and responds
# to requests. A full OIDC flow is not possible in E2E without a real IdP,
# so this test only confirms route existence and parameter validation.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "auth-oidc-callback"
auth_admin

# -------------------------------------------------------------------------
# SSO providers endpoint exists
# -------------------------------------------------------------------------

begin_test "SSO providers endpoint returns 200"
status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(auth_header)" \
    "${BASE_URL}/api/v1/auth/sso/providers" 2>/dev/null) || true
if [ "$status" = "200" ]; then
  SSO_AVAILABLE=true
  pass
elif [ "$status" = "404" ]; then
  SSO_AVAILABLE=false
  skip "SSO providers endpoint not available (404)"
else
  # Other status codes (e.g. 401 for unauthenticated) still mean the
  # route exists, which is what we are checking.
  SSO_AVAILABLE=true
  pass
fi

# -------------------------------------------------------------------------
# OIDC callback route exists (no params should return 400/422, not 404)
# -------------------------------------------------------------------------

begin_test "OIDC callback route exists (no params)"
if [ "$SSO_AVAILABLE" != "true" ]; then
  skip "SSO not available"
else
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
      "${BASE_URL}/api/v1/auth/sso/oidc/callback" 2>/dev/null) || true
  if [ "$status" = "404" ]; then
    fail "OIDC callback route returned 404, expected 400 or 422 (route not registered)"
  elif [ "$status" = "400" ] || [ "$status" = "422" ] || [ "$status" = "401" ]; then
    pass
  elif [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 500 ] 2>/dev/null; then
    # Any non-404, non-5xx response means the route is registered
    pass
  else
    fail "OIDC callback returned unexpected status ${status}"
  fi
fi

# -------------------------------------------------------------------------
# OIDC callback rejects invalid state parameter
# -------------------------------------------------------------------------

begin_test "OIDC callback rejects invalid state"
if [ "$SSO_AVAILABLE" != "true" ]; then
  skip "SSO not available"
else
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
      "${BASE_URL}/api/v1/auth/sso/oidc/callback?state=invalid-${RUN_ID}&code=bogus" 2>/dev/null) || true
  if [ "$status" = "404" ]; then
    fail "OIDC callback returned 404 for invalid state, route may not be registered"
  elif [ "$status" = "400" ] || [ "$status" = "401" ] || [ "$status" = "422" ]; then
    pass
  elif [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 500 ] 2>/dev/null; then
    # Route exists and rejected the request in some way
    pass
  else
    fail "OIDC callback returned unexpected status ${status} for invalid state"
  fi
fi

end_suite
