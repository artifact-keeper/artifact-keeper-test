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
# Requires: curl, jq, python3 (for TOTP code generation via totp_code helper)
source "$(dirname "$0")/../lib/common.sh"

begin_suite "auth-totp-disable"

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
USER_ID=$(create_test_user "${TOTP_USER}" "${TOTP_PASS}" "${TOTP_EMAIL}") || true
if [ -n "$USER_ID" ]; then
  pass
else
  fail "could not create user"
fi

begin_test "Login as test user"
if [ -z "${USER_ID:-}" ]; then
  skip "no user"
else
  USER_TOKEN=$(login_as "${TOTP_USER}" "${TOTP_PASS}") || true
  if [ -n "$USER_TOKEN" ]; then
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
    CODE=$(totp_code "$TOTP_SECRET") || true
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
  # Use 'wait' mode so we don't reuse the same code as the prior /enable call,
  # which the backend would reject as a replay within the 30s window.
  CODE=$(totp_code "$TOTP_SECRET" wait) || true
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X POST \
    -H "Authorization: Bearer ${USER_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{\"password\":\"WrongPassword!1\",\"code\":\"${CODE}\"}" \
    "${BASE_URL}/api/v1/auth/totp/disable" 2>/dev/null || echo 000)
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
    "${BASE_URL}/api/v1/auth/totp/disable" 2>/dev/null || echo 000)
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
  # 'wait' again — the prior wrong-password attempt may have used this code,
  # and the wrong-totp-code branch consumed window time.
  CODE=$(totp_code "$TOTP_SECRET" wait) || true
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X POST \
    -H "Authorization: Bearer ${USER_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{\"password\":\"${TOTP_PASS}\",\"code\":\"${CODE}\"}" \
    "${BASE_URL}/api/v1/auth/totp/disable" 2>/dev/null || echo 000)
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
enable_expect_failure_trap

end_suite
