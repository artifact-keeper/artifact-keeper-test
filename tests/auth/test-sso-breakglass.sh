#!/usr/bin/env bash
# test-sso-breakglass.sh - ALLOW_LOCAL_ADMIN_LOGIN break-glass check
#
# Verifies the break-glass contract that holds in EITHER SSO posture: the
# verified local admin can always log in with local credentials (issue #443;
# only SSO_DISABLE_ADMIN_BREAK_GLASS, which the gate does not set, removes it).
# With no SSO provider enabled that is ordinary local login; with one enabled
# it is the break-glass path (auth.rs local_login_gate).
#
# Why no posture branch (artifact-keeper-test#365): whether ANY SSO provider
# is enabled is instance-global state that a sibling suite flips mid-run
# (security/test-saml-signature.sh enables an ephemeral SAML provider for a
# few seconds). This suite used to sample that posture once and skip the
# break-glass check unless it happened to sample inside the sibling's window,
# so its verdict depended on timing, not on the product. The posture is now
# sampled around the login and reported, never branched on. Enabling a
# provider here to force the SSO posture would itself disable local login for
# every non-admin user on the shared instance, so this suite does not.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "sso-breakglass"
auth_admin
setup_workdir

# -------------------------------------------------------------------------
# Check whether SSO is configured
# -------------------------------------------------------------------------

# sso_posture -> "enabled (N provider(s))", "none enabled", or "unknown".
# Informational only: read from the public providers endpoint (enabled
# providers), and never used to choose what to assert.
sso_posture() {
  local body n
  body=$(curl -sf $CURL_TIMEOUT "${BASE_URL}/api/v1/auth/sso/providers" 2>/dev/null) || { echo "unknown"; return 0; }
  n=$(echo "$body" | jq -r 'if type == "array" then length
      elif (.providers | type) == "array" then (.providers | length)
      elif (.data | type) == "array" then (.data | length)
      else "?" end' 2>/dev/null) || n="?"
  case "$n" in
    0) echo "none enabled" ;;
    ''|'?') echo "unknown" ;;
    *) echo "enabled (${n} provider(s))" ;;
  esac
}

# Informational only, not a test case: a guaranteed pass here would keep the
# zero-pass floor from ever tripping for this suite.
echo "  SSO posture at start: $(sso_posture) (informational; a sibling suite may change it)"

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
# The admin's local login is accepted, whatever the SSO posture. Asserted
# unconditionally; the posture on each side of the login is only reported, so
# a sibling flipping it mid-run cannot change what this check means. The
# SSO-on branch is asserted deterministically inside the provider window of
# tests/security/test-saml-signature.sh.
# -------------------------------------------------------------------------

begin_test "Local admin login accepted (SSO posture reported)"
posture_before=$(sso_posture)
bg_status=$(curl -s -o "${WORK_DIR}/breakglass.json" -w '%{http_code}' $CURL_TIMEOUT \
  -X POST "${BASE_URL}/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASS}\"}" 2>/dev/null) || bg_status="000"
posture_after=$(sso_posture)
echo "  SSO posture around the login: before=${posture_before}, after=${posture_after}"
token=$(jq -r '.token // .access_token // empty' "${WORK_DIR}/breakglass.json" 2>/dev/null) || token=""
if [ "$bg_status" = "200" ] && [ -n "$token" ]; then
  pass
else
  fail "local admin login was not accepted (HTTP ${bg_status}, token present: $([ -n "$token" ] && echo yes || echo no)); the verified-admin break-glass must hold whether or not an SSO provider is enabled (SSO posture before=${posture_before}, after=${posture_after})" \
    "$(head -c 300 "${WORK_DIR}/breakglass.json" 2>/dev/null)"
fi

end_suite
