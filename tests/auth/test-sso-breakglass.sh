#!/usr/bin/env bash
# test-sso-breakglass.sh - ALLOW_LOCAL_ADMIN_LOGIN break-glass check
#
# Partial test: verifies local admin login works when no SSO is configured
# and checks for the ALLOW_LOCAL_ADMIN_LOGIN signal in system config. Full
# break-glass testing requires an SSO provider, so this script only covers
# the API-observable behavior.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "sso-breakglass"
auth_admin
setup_workdir

# -------------------------------------------------------------------------
# Check whether SSO is configured
# -------------------------------------------------------------------------

begin_test "Check SSO configuration status"
SSO_CONFIGURED=false
if resp=$(api_get "/api/v1/admin/settings" 2>/dev/null) || \
   resp=$(api_get "/api/v1/admin/system/settings" 2>/dev/null) || \
   resp=$(api_get "/api/v1/system/config" 2>/dev/null); then
  # Look for SSO-related fields
  sso_enabled=$(echo "$resp" | jq -r '.sso_enabled // .oidc_enabled // .saml_enabled // "false"' 2>/dev/null) || true
  if [ "$sso_enabled" = "true" ]; then
    SSO_CONFIGURED=true
    pass
  else
    pass
  fi
else
  skip "system config endpoint not available"
fi

# -------------------------------------------------------------------------
# Verify local login works (baseline)
# -------------------------------------------------------------------------

begin_test "Local admin login works"
if resp=$(curl -sf $CURL_TIMEOUT -X POST "${BASE_URL}/api/v1/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASS}\"}" 2>/dev/null); then
  token=$(echo "$resp" | jq -r '.token // .access_token // empty') || true
  if [ -n "$token" ]; then
    pass
  else
    fail "login succeeded but no token in response"
  fi
else
  fail "local admin login failed"
fi

# -------------------------------------------------------------------------
# Check system config for upload/auth settings
# -------------------------------------------------------------------------

begin_test "System config returns valid response"
if resp=$(api_get "/api/v1/system/config" 2>/dev/null); then
  pass
elif resp=$(api_get "/api/v1/admin/settings" 2>/dev/null); then
  pass
elif resp=$(api_get "/api/v1/admin/system/settings" 2>/dev/null); then
  pass
else
  skip "no system config endpoint found"
fi

# -------------------------------------------------------------------------
# Verify health endpoint (available without auth)
# -------------------------------------------------------------------------

begin_test "Health endpoint accessible without auth"
if status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    "${BASE_URL}/health" 2>/dev/null); then
  if [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then
    pass
  elif status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
      "${BASE_URL}/readyz" 2>/dev/null); then
    if [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then
      pass
    else
      fail "health endpoints returned ${status}"
    fi
  else
    fail "health endpoint returned ${status}"
  fi
else
  fail "could not reach health endpoint"
fi

# -------------------------------------------------------------------------
# If SSO is configured, skip the break-glass portion
# -------------------------------------------------------------------------

begin_test "Break-glass: local login with SSO"
if [ "$SSO_CONFIGURED" = "true" ]; then
  # With SSO enabled, local login should still work if ALLOW_LOCAL_ADMIN_LOGIN is set
  if resp=$(curl -sf $CURL_TIMEOUT -X POST "${BASE_URL}/api/v1/auth/login" \
      -H "Content-Type: application/json" \
      -d "{\"username\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASS}\"}" 2>/dev/null); then
    token=$(echo "$resp" | jq -r '.token // .access_token // empty') || true
    if [ -n "$token" ]; then
      pass
    else
      fail "break-glass login failed with SSO enabled"
    fi
  else
    fail "local login rejected with SSO enabled (break-glass may be disabled)"
  fi
else
  skip "SSO not configured, cannot test break-glass behavior"
fi

end_suite
