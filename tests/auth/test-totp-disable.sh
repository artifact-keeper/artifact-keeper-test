#!/usr/bin/env bash
# test-totp-disable.sh - TOTP disable requires both password and TOTP code (Epic 11.11, #76)
#
# Verifies:
#   1. /auth/totp/disable rejects a wrong password (401)
#   2. /auth/totp/disable rejects a wrong TOTP code (401)
#   3. /auth/totp/disable succeeds with both correct (200)
#   4. After disable, the user record reports totp_enabled = false
#
# Backend reference:
#   - totp.rs:371-423 disable_totp
#   - both bcrypt::verify(password) AND totp.check_current(code) must pass;
#     either failure returns AppError::Authentication -> 401
#
# Requires: curl, jq, oathtool
source "$(dirname "$0")/../lib/common.sh"

begin_suite "auth-totp-disable"

if ! command -v oathtool > /dev/null 2>&1; then
  skip_suite "oathtool not installed; required to compute live TOTP codes"
fi

auth_admin
setup_workdir

TOTP_USER="totp-dis-${RUN_ID}"
TOTP_PASS="TotpDisPass123!"
TOTP_EMAIL="totp-dis-${RUN_ID}@test.local"
USER_ID=""
USER_TOKEN=""
TOTP_SECRET=""

# -------------------------------------------------------------------------
# Setup user, login, enable TOTP
# -------------------------------------------------------------------------

begin_test "Create test user"
resp=$(api_post "/api/v1/users" \
  "{\"username\":\"${TOTP_USER}\",\"password\":\"${TOTP_PASS}\",\"email\":\"${TOTP_EMAIL}\"}" 2>/dev/null) || true
USER_ID=$(echo "$resp" | jq -r '.user.id // .id // empty')
if [ -n "$USER_ID" ] && [ "$USER_ID" != "null" ]; then
  pass
else
  fail "could not create user: ${resp:0:200}"
fi

begin_test "Login as test user"
if [ -z "${USER_ID:-}" ] || [ "$USER_ID" = "null" ]; then
  skip "no user"
else
  login_resp=$(curl -sf $CURL_TIMEOUT -X POST \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${TOTP_USER}\",\"password\":\"${TOTP_PASS}\"}" \
    "${BASE_URL}/api/v1/auth/login" 2>/dev/null) || true
  USER_TOKEN=$(echo "$login_resp" | jq -r '.access_token // .token // empty')
  if [ -n "$USER_TOKEN" ] && [ "$USER_TOKEN" != "null" ]; then
    pass
  else
    fail "login failed"
  fi
fi

begin_test "Enable TOTP (setup + enable)"
if [ -z "${USER_TOKEN:-}" ]; then
  skip "no user token"
else
  setup_resp=$(curl -sf $CURL_TIMEOUT -X POST \
    -H "Authorization: Bearer ${USER_TOKEN}" \
    "${BASE_URL}/api/v1/auth/totp/setup" 2>/dev/null) || true
  TOTP_SECRET=$(echo "$setup_resp" | jq -r '.secret // empty')
  if [ -z "$TOTP_SECRET" ] || [ "$TOTP_SECRET" = "null" ]; then
    fail "TOTP setup did not return a secret: ${setup_resp:0:200}"
  else
    CODE=$(oathtool --totp -b "$TOTP_SECRET" 2>/dev/null) || true
    enable_resp=$(curl -sf $CURL_TIMEOUT -X POST \
      -H "Authorization: Bearer ${USER_TOKEN}" \
      -H "Content-Type: application/json" \
      -d "{\"code\":\"${CODE}\"}" \
      "${BASE_URL}/api/v1/auth/totp/enable" 2>/dev/null) || true
    backup_count=$(echo "$enable_resp" | jq '.backup_codes | length // 0' 2>/dev/null)
    if [ "$backup_count" -ge 1 ]; then
      pass
    else
      fail "TOTP enable did not return backup_codes: ${enable_resp:0:200}"
    fi
  fi
fi

# -------------------------------------------------------------------------
# Disable with WRONG password rejected
# -------------------------------------------------------------------------

begin_test "Disable rejects wrong password"
if [ -z "${USER_TOKEN:-}" ] || [ -z "${TOTP_SECRET:-}" ]; then
  skip "TOTP not enabled"
else
  CODE=$(oathtool --totp -b "$TOTP_SECRET" 2>/dev/null) || true
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X POST \
    -H "Authorization: Bearer ${USER_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{\"password\":\"WrongPassword!1\",\"code\":\"${CODE}\"}" \
    "${BASE_URL}/api/v1/auth/totp/disable" 2>/dev/null) || true
  if [ "$status" = "401" ]; then
    pass
  else
    fail "expected 401 for wrong password on disable, got HTTP ${status}"
  fi
fi

# -------------------------------------------------------------------------
# Disable with WRONG TOTP code rejected
# -------------------------------------------------------------------------

begin_test "Disable rejects wrong TOTP code"
if [ -z "${USER_TOKEN:-}" ] || [ -z "${TOTP_SECRET:-}" ]; then
  skip "TOTP not enabled"
else
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X POST \
    -H "Authorization: Bearer ${USER_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{\"password\":\"${TOTP_PASS}\",\"code\":\"000000\"}" \
    "${BASE_URL}/api/v1/auth/totp/disable" 2>/dev/null) || true
  if [ "$status" = "401" ]; then
    pass
  else
    fail "expected 401 for wrong TOTP code on disable, got HTTP ${status}"
  fi
fi

# -------------------------------------------------------------------------
# Disable with both correct succeeds
# -------------------------------------------------------------------------

begin_test "Disable succeeds with correct password and TOTP code"
if [ -z "${USER_TOKEN:-}" ] || [ -z "${TOTP_SECRET:-}" ]; then
  skip "TOTP not enabled"
else
  CODE=$(oathtool --totp -b "$TOTP_SECRET" 2>/dev/null) || true
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X POST \
    -H "Authorization: Bearer ${USER_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{\"password\":\"${TOTP_PASS}\",\"code\":\"${CODE}\"}" \
    "${BASE_URL}/api/v1/auth/totp/disable" 2>/dev/null) || true
  if [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then
    pass
  else
    fail "expected 2xx for correct disable, got HTTP ${status}"
  fi
fi

# -------------------------------------------------------------------------
# After disable, /auth/me reports totp_enabled = false
# -------------------------------------------------------------------------

begin_test "User profile shows totp_enabled = false after disable"
if [ -z "${USER_TOKEN:-}" ]; then
  skip "no user token"
else
  me_resp=$(curl -sf $CURL_TIMEOUT \
    -H "Authorization: Bearer ${USER_TOKEN}" \
    "${BASE_URL}/api/v1/auth/me" 2>/dev/null) || true
  totp_state=$(echo "$me_resp" | jq -r '.totp_enabled // empty')
  if [ "$totp_state" = "false" ]; then
    pass
  else
    fail "expected totp_enabled=false, got '${totp_state}': ${me_resp:0:200}"
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
if [ "${EXPECT_FAILURE:-0}" = "1" ]; then
  trap 'rc=$?; if [ "$rc" -eq 0 ]; then exit 1; else exit 0; fi' EXIT
fi

end_suite
