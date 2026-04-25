#!/usr/bin/env bash
# test-admin-password-recovery.sh - Admin password recovery regression test
#
# Regression test for bug #815: admin.password file creation and recovery.
# The bug caused the admin.password file to fail on first boot, or if the
# file was deleted while the DB still had the hash, the server could not
# recover. The fix added pg_advisory_xact_lock and write-before-DB ordering.
#
# Since E2E tests cannot directly verify filesystem operations, this suite
# validates the observable behavior: admin auth works, password can be
# changed and restored, and the system stays stable under rapid auth load.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "admin-password-recovery"
auth_admin

ORIGINAL_PASS="$ADMIN_PASS"
TEST_PASS="N3wP@ssw0rd!Zxq"
PASSWORD_MUTATED=false

# Best-effort restore of the admin password if the suite is interrupted or
# any test fails between the password change and the explicit reset step.
# Without this, a partial run leaves the admin user locked to TEST_PASS,
# which breaks every subsequent suite's auth_admin call in the namespace.
restore_admin_password() {
  if [ "$PASSWORD_MUTATED" != "true" ]; then
    return 0
  fi
  if [ -z "${ADMIN_ID:-}" ] || [ "$ADMIN_ID" = "null" ]; then
    return 0
  fi
  # Re-login with whatever password is currently active (TEST_PASS first).
  local _tok=""
  for _candidate in "$TEST_PASS" "$ORIGINAL_PASS"; do
    local _login
    _login=$(curl -sf --max-time 10 -X POST "${BASE_URL}/api/v1/auth/login" \
      -H "Content-Type: application/json" \
      -d "{\"username\":\"${ADMIN_USER}\",\"password\":\"${_candidate}\"}" 2>/dev/null) || true
    if [ -n "$_login" ]; then
      _tok=$(echo "$_login" | jq -r '.token // .access_token // empty' 2>/dev/null) || true
      if [ -n "$_tok" ] && [ "$_tok" != "null" ]; then
        # If we got in with the original, nothing to restore.
        if [ "$_candidate" = "$ORIGINAL_PASS" ]; then
          return 0
        fi
        # Got in with TEST_PASS, push original back.
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
trap restore_admin_password EXIT

# -------------------------------------------------------------------------
# Resolve admin user ID (needed for password change endpoint)
# -------------------------------------------------------------------------

ADMIN_ID=""
resolve_admin_id() {
  local resp
  resp=$(api_get "/api/v1/users?username=${ADMIN_USER}" 2>/dev/null) || true
  if [ -n "$resp" ]; then
    ADMIN_ID=$(echo "$resp" | jq -r '
      if type == "array" then .[0].id
      elif .items then .items[0].id
      elif .users then .users[0].id
      elif .id then .id
      else empty
      end // empty
    ')
  fi
  # Fallback: list all users and find admin by username
  if [ -z "$ADMIN_ID" ] || [ "$ADMIN_ID" = "null" ]; then
    resp=$(api_get "/api/v1/users" 2>/dev/null) || true
    if [ -n "$resp" ]; then
      ADMIN_ID=$(echo "$resp" | jq -r --arg u "$ADMIN_USER" '
        if type == "array" then (.[] | select(.username == $u) | .id)
        elif .items then (.items[] | select(.username == $u) | .id)
        elif .users then (.users[] | select(.username == $u) | .id)
        else empty
        end // empty
      ')
    fi
  fi
}

resolve_admin_id

# -------------------------------------------------------------------------
# 1. Admin login works (basic health check for auth)
# -------------------------------------------------------------------------

begin_test "Admin login works"
login_resp=$(curl -sf $CURL_TIMEOUT -X POST "${BASE_URL}/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"${ADMIN_USER}\",\"password\":\"${ORIGINAL_PASS}\"}" 2>/dev/null) || true
if [ -n "$login_resp" ]; then
  token=$(echo "$login_resp" | jq -r '.token // .access_token // empty')
  if [ -n "$token" ] && [ "$token" != "null" ]; then
    pass
  else
    fail "login response did not contain a token"
  fi
else
  fail "login request returned empty response"
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
# 3. Admin can change password
# -------------------------------------------------------------------------

begin_test "Admin can change password"
if [ -z "$ADMIN_ID" ] || [ "$ADMIN_ID" = "null" ]; then
  skip "could not resolve admin user ID"
else
  # Send exactly one request. The change_password handler invalidates the
  # caller's existing JWT after a successful change (backend
  # auth_service::invalidate_user_tokens), so a second call with the same
  # ADMIN_TOKEN would get 401 and look like a backend failure.
  change_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X POST \
    -H "$(auth_header)" \
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
if [ -z "$ADMIN_ID" ] || [ "$ADMIN_ID" = "null" ]; then
  skip "admin ID not resolved, password was not changed"
else
  new_login_resp=$(curl -sf $CURL_TIMEOUT -X POST "${BASE_URL}/api/v1/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${ADMIN_USER}\",\"password\":\"${TEST_PASS}\"}" 2>/dev/null) || true
  if [ -n "$new_login_resp" ]; then
    new_token=$(echo "$new_login_resp" | jq -r '.token // .access_token // empty')
    if [ -n "$new_token" ] && [ "$new_token" != "null" ]; then
      # Update the token for subsequent API calls
      ADMIN_TOKEN="$new_token"
      export ADMIN_TOKEN
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
if [ -z "$ADMIN_ID" ] || [ "$ADMIN_ID" = "null" ]; then
  skip "admin ID not resolved, password was not changed"
else
  old_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X POST \
    "${BASE_URL}/api/v1/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${ADMIN_USER}\",\"password\":\"${ORIGINAL_PASS}\"}" 2>/dev/null) || true
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
if [ -z "$ADMIN_ID" ] || [ "$ADMIN_ID" = "null" ]; then
  skip "admin ID not resolved, nothing to reset"
else
  reset_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X POST \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{\"current_password\":\"${TEST_PASS}\",\"new_password\":\"${ORIGINAL_PASS}\"}" \
    "${BASE_URL}/api/v1/users/${ADMIN_ID}/password") || true

  if [ "$reset_status" -ge 200 ] 2>/dev/null && [ "$reset_status" -lt 300 ] 2>/dev/null; then
    # Verify we can log in with the original password again
    verify_resp=$(curl -sf $CURL_TIMEOUT -X POST "${BASE_URL}/api/v1/auth/login" \
      -H "Content-Type: application/json" \
      -d "{\"username\":\"${ADMIN_USER}\",\"password\":\"${ORIGINAL_PASS}\"}" 2>/dev/null) || true
    if [ -n "$verify_resp" ]; then
      restored_token=$(echo "$verify_resp" | jq -r '.token // .access_token // empty')
      if [ -n "$restored_token" ] && [ "$restored_token" != "null" ]; then
        ADMIN_TOKEN="$restored_token"
        export ADMIN_TOKEN
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
# 8. Multiple rapid login attempts do not cause errors
# -------------------------------------------------------------------------

begin_test "Rapid sequential login attempts stay stable"
success_count=0
error_count=0
for i in $(seq 1 10); do
  rapid_resp=$(curl -sf $CURL_TIMEOUT -X POST "${BASE_URL}/api/v1/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${ADMIN_USER}\",\"password\":\"${ORIGINAL_PASS}\"}" 2>/dev/null) || true
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

end_suite
