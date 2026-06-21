#!/usr/bin/env bash
# test-admin-password-recovery.sh - Admin password recovery regression test
#
# Regression test for bug #815: admin.password file creation and recovery.
# The bug caused the admin.password file to fail on first boot, or if the
# file was deleted while the DB still had the hash, the server could not
# recover. The fix added pg_advisory_xact_lock and write-before-DB ordering.
#
# Since E2E tests cannot directly verify filesystem operations, this suite
# validates the observable behavior: an admin user's auth works, the password
# can be changed and restored, the old password is rejected, and the system
# stays stable under rapid auth load.
#
# RELEASE-GATE SAFETY (shared-admin credential poisoning fix):
#   This suite used to mutate the SHARED global admin (ADMIN_USER) -- resolve
#   its user id, change its password, then reset it. Under the gate's ~25-way
#   concurrency that poisons every other suite: changing the shared admin's
#   password trips the backend credential-invalidation map and invalidates the
#   global admin JWT process-wide, so all concurrent suites' ADMIN_TOKEN start
#   returning 401. The "intent" of this regression test is the password
#   change -> rapid-login -> reset cycle on an *admin* identity, not on the
#   *shared* one. So we now mint a DEDICATED throwaway admin
#   (create_dedicated_admin) and run the entire cycle against it. The global
#   admin token is used only to create/delete the throwaway user and is never
#   mutated, so concurrent suites are unaffected.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "admin-password-recovery"
auth_admin

# -------------------------------------------------------------------------
# Mint a dedicated throwaway admin. ALL password mutations below target THIS
# user, never the shared ADMIN_USER. Credentials are unique per run.
# -------------------------------------------------------------------------

DED_USER="e2e-pwrec-${RUN_ID}-$$"
ORIGINAL_PASS="DedPwRec_${RUN_ID:0:8}_Aa1!"
TEST_PASS="DedPwRec_${RUN_ID:0:8}_Bb2!"
ADMIN_ID=""
PASSWORD_MUTATED=false

# Cleanup: delete the throwaway admin. add_exit_handler re-auths as the global
# admin first, so cleanup works even though we rotate the dedicated admin's
# password mid-suite. The global admin token is never touched here.
add_exit_handler "cleanup_dedicated_admin \"\${ADMIN_ID:-}\""

# Best-effort restore of the DEDICATED admin's password if the suite is
# interrupted between the password change and the explicit reset step. This is
# now purely cosmetic (the user is deleted on exit anyway), but it keeps the
# dedicated admin loginable with ORIGINAL_PASS for any in-suite
# assertions. It NEVER touches the shared admin.
restore_dedicated_password() {
  if [ "$PASSWORD_MUTATED" != "true" ]; then
    return 0
  fi
  if [ -z "${ADMIN_ID:-}" ] || [ "$ADMIN_ID" = "null" ]; then
    return 0
  fi
  local _tok=""
  for _candidate in "$TEST_PASS" "$ORIGINAL_PASS"; do
    local _login
    _login=$(curl -sf --max-time 10 -X POST "${BASE_URL}/api/v1/auth/login" \
      -H "Content-Type: application/json" \
      -d "{\"username\":\"${DED_USER}\",\"password\":\"${_candidate}\"}" 2>/dev/null) || true
    if [ -n "$_login" ]; then
      _tok=$(echo "$_login" | jq -r '.token // .access_token // empty' 2>/dev/null) || true
      if [ -n "$_tok" ] && [ "$_tok" != "null" ]; then
        if [ "$_candidate" = "$ORIGINAL_PASS" ]; then
          return 0
        fi
        curl -sf --max-time 10 -X POST \
          -H "Authorization: Bearer ${_tok}" \
          -H "Content-Type: application/json" \
          -d "{\"current_password\":\"${TEST_PASS}\",\"new_password\":\"${ORIGINAL_PASS}\"}" \
          "${BASE_URL}/api/v1/users/${ADMIN_ID}/password" >/dev/null 2>&1 || true
        return 0
      fi
    fi
  done
}
add_exit_handler restore_dedicated_password

# -------------------------------------------------------------------------
# Create the dedicated admin (needed for the password-change endpoint, which
# is keyed on user id).
# -------------------------------------------------------------------------

begin_test "Create dedicated admin user"
ADMIN_ID=$(create_dedicated_admin "$DED_USER" "$ORIGINAL_PASS") || ADMIN_ID=""
if [ -n "$ADMIN_ID" ] && [ "$ADMIN_ID" != "null" ]; then
  pass
else
  fail "could not create dedicated admin user"
fi

# -------------------------------------------------------------------------
# 1. Dedicated admin login works (basic health check for auth)
# -------------------------------------------------------------------------

begin_test "Dedicated admin login works"
if [ -z "$ADMIN_ID" ] || [ "$ADMIN_ID" = "null" ]; then
  skip "dedicated admin not created"
else
  login_resp=$(curl -sf $CURL_TIMEOUT -X POST "${BASE_URL}/api/v1/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${DED_USER}\",\"password\":\"${ORIGINAL_PASS}\"}" 2>/dev/null) || true
  if [ -n "$login_resp" ]; then
    token=$(echo "$login_resp" | jq -r '.token // .access_token // empty')
    if [ -n "$token" ] && [ "$token" != "null" ]; then
      DED_TOKEN="$token"
      pass
    else
      fail "login response did not contain a token"
    fi
  else
    fail "login request returned empty response"
  fi
fi

# -------------------------------------------------------------------------
# 2. Health endpoint returns version
# -------------------------------------------------------------------------

begin_test "Health endpoint returns version"
health_resp=$(curl -sf $CURL_TIMEOUT "${BASE_URL}/health" 2>/dev/null) || true
if [ -n "$health_resp" ]; then
  version=$(echo "$health_resp" | jq -r '.version // empty')
  if [ -n "$version" ] && [ "$version" != "null" ]; then
    echo "  Server version: ${version}"
    pass
  else
    fail "health response missing version field"
  fi
else
  fail "health endpoint returned empty response"
fi

# -------------------------------------------------------------------------
# 3. Dedicated admin can change its own password
# -------------------------------------------------------------------------

begin_test "Dedicated admin can change password"
if [ -z "$ADMIN_ID" ] || [ "$ADMIN_ID" = "null" ] || [ -z "${DED_TOKEN:-}" ]; then
  skip "dedicated admin not available"
else
  # Send exactly one request. The change_password handler invalidates the
  # caller's existing JWT after a successful change (backend
  # auth_service::invalidate_user_tokens), so a second call with the same
  # DED_TOKEN would get 401 and look like a backend failure. Crucially this
  # is the DEDICATED admin's token -- the GLOBAL admin token is untouched.
  change_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X POST \
    -H "Authorization: Bearer ${DED_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{\"current_password\":\"${ORIGINAL_PASS}\",\"new_password\":\"${TEST_PASS}\"}" \
    "${BASE_URL}/api/v1/users/${ADMIN_ID}/password") || true

  if [ "$change_status" -ge 200 ] 2>/dev/null && [ "$change_status" -lt 300 ] 2>/dev/null; then
    PASSWORD_MUTATED=true
    pass
  else
    fail "password change returned HTTP ${change_status}"
  fi
fi

# -------------------------------------------------------------------------
# 4. Login with new password works
# -------------------------------------------------------------------------

begin_test "Login with new password works"
if [ "$PASSWORD_MUTATED" != "true" ]; then
  skip "password was not changed"
else
  new_login_resp=$(curl -sf $CURL_TIMEOUT -X POST "${BASE_URL}/api/v1/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${DED_USER}\",\"password\":\"${TEST_PASS}\"}" 2>/dev/null) || true
  if [ -n "$new_login_resp" ]; then
    new_token=$(echo "$new_login_resp" | jq -r '.token // .access_token // empty')
    if [ -n "$new_token" ] && [ "$new_token" != "null" ]; then
      DED_TOKEN="$new_token"
      pass
    else
      fail "login with new password did not return a token"
    fi
  else
    fail "login with new password returned empty response"
  fi
fi

# -------------------------------------------------------------------------
# 5. Login with old password fails (returns 401)
# -------------------------------------------------------------------------

begin_test "Login with old password fails"
if [ "$PASSWORD_MUTATED" != "true" ]; then
  skip "password was not changed"
else
  old_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X POST \
    "${BASE_URL}/api/v1/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${DED_USER}\",\"password\":\"${ORIGINAL_PASS}\"}" 2>/dev/null) || true
  if [ "$old_status" = "401" ]; then
    pass
  else
    fail "expected HTTP 401 for old password, got ${old_status}"
  fi
fi

# -------------------------------------------------------------------------
# 6. Reset back to original password
# -------------------------------------------------------------------------

begin_test "Reset back to original password"
if [ "$PASSWORD_MUTATED" != "true" ] || [ -z "${DED_TOKEN:-}" ]; then
  skip "nothing to reset"
else
  reset_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X POST \
    -H "Authorization: Bearer ${DED_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{\"current_password\":\"${TEST_PASS}\",\"new_password\":\"${ORIGINAL_PASS}\"}" \
    "${BASE_URL}/api/v1/users/${ADMIN_ID}/password") || true

  if [ "$reset_status" -ge 200 ] 2>/dev/null && [ "$reset_status" -lt 300 ] 2>/dev/null; then
    # Verify we can log in with the original password again
    verify_resp=$(curl -sf $CURL_TIMEOUT -X POST "${BASE_URL}/api/v1/auth/login" \
      -H "Content-Type: application/json" \
      -d "{\"username\":\"${DED_USER}\",\"password\":\"${ORIGINAL_PASS}\"}" 2>/dev/null) || true
    if [ -n "$verify_resp" ]; then
      restored_token=$(echo "$verify_resp" | jq -r '.token // .access_token // empty')
      if [ -n "$restored_token" ] && [ "$restored_token" != "null" ]; then
        DED_TOKEN="$restored_token"
        PASSWORD_MUTATED=false
        pass
      else
        fail "login with restored password did not return a token"
      fi
    else
      fail "login with restored password returned empty response"
    fi
  else
    fail "password reset returned HTTP ${reset_status}"
  fi
fi

# -------------------------------------------------------------------------
# 7. System config endpoint accessible
# -------------------------------------------------------------------------

begin_test "System config endpoint returns valid JSON"
config_resp=$(curl -sf $CURL_TIMEOUT "${BASE_URL}/system/config" 2>/dev/null) || true
if [ -n "$config_resp" ]; then
  if echo "$config_resp" | jq -e '.' >/dev/null 2>&1; then
    pass
  else
    fail "system config response is not valid JSON"
  fi
else
  # Try the /api/v1 prefixed path as a fallback
  config_resp=$(curl -sf $CURL_TIMEOUT "${BASE_URL}/api/v1/system/config" 2>/dev/null) || true
  if [ -n "$config_resp" ] && echo "$config_resp" | jq -e '.' >/dev/null 2>&1; then
    pass
  else
    skip "system config endpoint not available"
  fi
fi

# -------------------------------------------------------------------------
# 8. Multiple rapid login attempts (for the dedicated admin) do not error
# -------------------------------------------------------------------------

begin_test "Rapid sequential login attempts stay stable"
if [ -z "$ADMIN_ID" ] || [ "$ADMIN_ID" = "null" ]; then
  skip "dedicated admin not available"
else
  success_count=0
  error_count=0
  for i in $(seq 1 10); do
    rapid_resp=$(curl -sf $CURL_TIMEOUT -X POST "${BASE_URL}/api/v1/auth/login" \
      -H "Content-Type: application/json" \
      -d "{\"username\":\"${DED_USER}\",\"password\":\"${ORIGINAL_PASS}\"}" 2>/dev/null) || true
    if [ -n "$rapid_resp" ]; then
      rapid_token=$(echo "$rapid_resp" | jq -r '.token // .access_token // empty')
      if [ -n "$rapid_token" ] && [ "$rapid_token" != "null" ]; then
        success_count=$(( success_count + 1 ))
      else
        error_count=$(( error_count + 1 ))
      fi
    else
      error_count=$(( error_count + 1 ))
    fi
  done
  echo "  ${success_count}/10 logins succeeded, ${error_count}/10 failed"
  # Allow up to 2 failures (rate limiting may kick in) but most should succeed
  if [ "$success_count" -ge 8 ]; then
    pass
  else
    fail "only ${success_count}/10 rapid login attempts succeeded"
  fi
fi

end_suite
