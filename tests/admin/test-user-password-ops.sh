#!/usr/bin/env bash
# test-user-password-ops.sh - User password change + admin reset (Epic 10.11, 10.12, #77)
#
# Covers two endpoints with their full happy-path semantics, not just
# status codes:
#
#   POST /api/v1/users/{id}/password         (10.12 self-service change)
#     body: { current_password, new_password }
#     load-bearing assertion: AFTER the change, login with new_password
#     returns a token AND login with current_password returns 401.
#
#   POST /api/v1/users/{id}/password/reset   (10.11 admin reset)
#     no body; response contains { temporary_password: "..." }
#     load-bearing assertion: AFTER the reset, login with the
#     temporary_password returns a token AND login with the previously
#     valid password returns 401.
#
# Safety:
#   - Operates ONLY on a throwaway user created with RUN_ID in the
#     username; never touches the global admin password.
#   - Cleanup deletes the user via add_exit_handler so an interrupted
#     run leaves no dangling test users.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "admin-user-password-ops"
auth_admin

TEST_USERNAME="e2e-pwd-${RUN_ID}"
TEST_EMAIL="${TEST_USERNAME}@e2e.local"
# Two distinct fixture passwords generated at runtime. Secret scanners
# heuristically flag literal-looking password strings even when they are
# fixtures, so we build the fixtures from /dev/urandom + RUN_ID rather
# than embedding string literals. Each must satisfy the backend's
# documented min-length/complexity policy (>=12 chars + mixed case +
# digit + symbol).
_rand_alnum() { LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 12; }
PASS_INITIAL="$(_rand_alnum)_${RUN_ID:0:8}_Aa1!"
PASS_CHANGED="$(_rand_alnum)_${RUN_ID:0:8}_Bb2!"
TEST_USER_ID=""

_pwd_cleanup() {
  if [ -n "${TEST_USER_ID:-}" ] && [ "$TEST_USER_ID" != "null" ]; then
    auth_admin > /dev/null 2>&1 || true
    api_delete "/api/v1/users/${TEST_USER_ID}" > /dev/null 2>&1 || true
  fi
}
add_exit_handler _pwd_cleanup

# Helper: attempt a login and echo the HTTP status. Does NOT retain the token.
# We use this both as the positive assertion (200 + token in body) and the
# negative assertion (401 / 403 / empty body).
_try_login() {
  local username="$1"
  local password="$2"
  local tmp
  tmp=$(mktemp)
  local s
  s=$(curl -s -o "$tmp" -w '%{http_code}' $CURL_TIMEOUT \
    -X POST \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${username}\",\"password\":\"${password}\"}" \
    "${BASE_URL}/api/v1/auth/login" 2>/dev/null) || s=000
  local b
  b=$(cat "$tmp"); rm -f "$tmp"
  # Echo "STATUS|BODY" so caller can split. Body is bounded by curl's response.
  echo "${s}|${b}"
}

begin_test "Create throwaway user for password ops"
resp=""
status=$(curl -s -o /tmp/_pwd_create.$$ -w '%{http_code}' $CURL_TIMEOUT \
  -X POST \
  -H "$(auth_header)" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"${TEST_USERNAME}\",\"password\":\"${PASS_INITIAL}\",\"email\":\"${TEST_EMAIL}\",\"display_name\":\"E2E Password Ops\"}" \
  "${BASE_URL}/api/v1/users" 2>/dev/null) || status=000
resp=$(cat /tmp/_pwd_create.$$ 2>/dev/null || true)
rm -f /tmp/_pwd_create.$$

if [ "$status" = "200" ] || [ "$status" = "201" ]; then
  TEST_USER_ID=$(echo "$resp" | jq -r '.user.id // .id // empty')
  if [ -n "$TEST_USER_ID" ] && [ "$TEST_USER_ID" != "null" ]; then
    pass
  else
    fail "user create returned ${status} but no id" "${resp:0:300}"
  fi
elif [ "$status" = "404" ] || [ "$status" = "501" ]; then
  skip "POST /users not mounted (HTTP ${status})"
else
  fail "user create returned HTTP ${status}" "${resp:0:300}"
fi

begin_test "Initial login with PASS_INITIAL works"
if [ -z "${TEST_USER_ID:-}" ]; then
  skip "no user id"
else
  out=$(_try_login "$TEST_USERNAME" "$PASS_INITIAL")
  s="${out%%|*}"
  b="${out#*|}"
  if [ "$s" = "200" ] && echo "$b" | jq -e '.access_token // .token' > /dev/null 2>&1; then
    pass
  else
    fail "initial login expected 200+token, got HTTP ${s}" "${b:0:200}"
  fi
fi

# -------------------------------------------------------------------------
# 10.12: self-service password change. The user logs in themselves and
# POSTs to /users/{id}/password with their own current+new password.
# -------------------------------------------------------------------------

begin_test "Self-service POST /users/{id}/password changes password"
if [ -z "${TEST_USER_ID:-}" ]; then
  skip "no user id"
else
  USER_TOKEN=$(login_as "$TEST_USERNAME" "$PASS_INITIAL") || USER_TOKEN=""
  if [ -z "$USER_TOKEN" ]; then
    fail "could not log in as throwaway user before change_password"
  else
    tmp=$(mktemp)
    change_status=$(curl -s -o "$tmp" -w '%{http_code}' $CURL_TIMEOUT \
      -X POST \
      -H "Authorization: Bearer ${USER_TOKEN}" \
      -H "Content-Type: application/json" \
      -d "{\"current_password\":\"${PASS_INITIAL}\",\"new_password\":\"${PASS_CHANGED}\"}" \
      "${BASE_URL}/api/v1/users/${TEST_USER_ID}/password" 2>/dev/null) || change_status=000
    body=$(cat "$tmp"); rm -f "$tmp"
    if [ "$change_status" = "200" ] || [ "$change_status" = "204" ]; then
      pass
    elif [ "$change_status" = "404" ] || [ "$change_status" = "501" ]; then
      skip "POST /users/{id}/password not mounted (HTTP ${change_status})"
    else
      fail "change_password returned HTTP ${change_status}" "${body:0:300}"
    fi
  fi
fi

# Load-bearing assertion #1: NEW password authenticates.
begin_test "After change_password, PASS_CHANGED authenticates"
if [ -z "${TEST_USER_ID:-}" ]; then
  skip "no user id"
else
  out=$(_try_login "$TEST_USERNAME" "$PASS_CHANGED")
  s="${out%%|*}"
  b="${out#*|}"
  if [ "$s" = "200" ] && echo "$b" | jq -e '.access_token // .token' > /dev/null 2>&1; then
    pass
  else
    fail "expected 200+token for new password, got HTTP ${s}" "${b:0:200}"
  fi
fi

# Load-bearing assertion #2: OLD password no longer authenticates.
# This is the assertion that distinguishes a real password change from a
# silent no-op that returned 200.
begin_test "After change_password, PASS_INITIAL is rejected (HTTP 401)"
if [ -z "${TEST_USER_ID:-}" ]; then
  skip "no user id"
else
  out=$(_try_login "$TEST_USERNAME" "$PASS_INITIAL")
  s="${out%%|*}"
  if [ "$s" = "401" ]; then
    pass
  else
    # 403 would imply auth happened but user is now blocked (unexpected).
    # 200 is the silent-success class we are guarding against.
    fail "expected 401 for old password, got HTTP ${s}"
  fi
fi

# -------------------------------------------------------------------------
# 10.11: admin-initiated password reset. The ADMIN POSTs to
# /users/{id}/password/reset and receives a temporary_password in the
# response body. The user must then be able to log in with that temp pwd.
# -------------------------------------------------------------------------

TEMP_PASSWORD=""

begin_test "Admin POST /users/{id}/password/reset returns temporary_password"
if [ -z "${TEST_USER_ID:-}" ]; then
  skip "no user id"
else
  tmp=$(mktemp)
  reset_status=$(curl -s -o "$tmp" -w '%{http_code}' $CURL_TIMEOUT \
    -X POST \
    -H "$(auth_header)" \
    "${BASE_URL}/api/v1/users/${TEST_USER_ID}/password/reset" 2>/dev/null) || reset_status=000
  body=$(cat "$tmp"); rm -f "$tmp"
  if [ "$reset_status" = "404" ] || [ "$reset_status" = "501" ]; then
    skip "POST /users/{id}/password/reset not mounted (HTTP ${reset_status})"
  elif [ "$reset_status" = "200" ]; then
    TEMP_PASSWORD=$(echo "$body" | jq -r '.temporary_password // empty')
    if [ -n "$TEMP_PASSWORD" ] && [ "$TEMP_PASSWORD" != "null" ]; then
      # Do not print the actual password (CI logs are retained). Just
      # confirm we got a non-empty string of plausible length.
      echo "  received temporary_password (length=${#TEMP_PASSWORD})"
      pass
    else
      fail "reset response did not contain temporary_password" "${body:0:300}"
    fi
  else
    fail "reset returned HTTP ${reset_status}" "${body:0:300}"
  fi
fi

# Load-bearing assertion #3: the temporary_password actually works for login.
# This is what catches the bug class where reset issues a token-shaped
# string that does not match the bcrypt hash written to users.password_hash.
begin_test "Login with temporary_password succeeds"
if [ -z "${TEMP_PASSWORD:-}" ]; then
  skip "no temporary_password"
else
  out=$(_try_login "$TEST_USERNAME" "$TEMP_PASSWORD")
  s="${out%%|*}"
  b="${out#*|}"
  if [ "$s" = "200" ] && echo "$b" | jq -e '.access_token // .token' > /dev/null 2>&1; then
    pass
  else
    fail "login with temp password returned HTTP ${s}" "${b:0:200}"
  fi
fi

# Load-bearing assertion #4: pre-reset password no longer works.
begin_test "After reset, PASS_CHANGED is rejected (HTTP 401)"
if [ -z "${TEMP_PASSWORD:-}" ]; then
  skip "reset did not run"
else
  out=$(_try_login "$TEST_USERNAME" "$PASS_CHANGED")
  s="${out%%|*}"
  if [ "$s" = "401" ]; then
    pass
  else
    fail "expected 401 for pre-reset password, got HTTP ${s}"
  fi
fi

# -------------------------------------------------------------------------
# Negative path: a non-admin user cannot reset another user's password.
# -------------------------------------------------------------------------

begin_test "Non-admin POST /users/{id}/password/reset on another user returns 403"
if [ -z "${TEST_USER_ID:-}" ] || [ -z "${TEMP_PASSWORD:-}" ]; then
  skip "fixtures unavailable"
else
  # Log the test user in (they are non-admin) and attempt to reset their
  # OWN account through the admin reset endpoint. Per openapi spec, only
  # admins can call this endpoint, so a non-admin caller must get 403.
  USER_TOKEN=$(login_as "$TEST_USERNAME" "$TEMP_PASSWORD") || USER_TOKEN=""
  if [ -z "$USER_TOKEN" ]; then
    skip "could not log in as non-admin to test 403"
  else
    s=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
      -X POST \
      -H "Authorization: Bearer ${USER_TOKEN}" \
      "${BASE_URL}/api/v1/users/${TEST_USER_ID}/password/reset" 2>/dev/null) || s=000
    # Per openapi.yaml:9581-9584, the documented responses are only
    # 403 (Forbidden), 404 (Not found), and 422 (Validation error). 401
    # is NOT in that set: a 401 means the bearer token itself was
    # rejected, i.e. auth broke, not that authz correctly denied a
    # non-admin caller. We freshly logged in as TEST_USERNAME above, so
    # the token must be valid here; treat 401 as a hard failure rather
    # than silently tolerating it.
    if [ "$s" = "403" ]; then
      pass
    elif [ "$s" = "200" ] || [ "$s" = "204" ]; then
      fail "non-admin was allowed to reset password (HTTP ${s}) -- this is a privilege-escalation regression"
    elif [ "$s" = "401" ]; then
      fail "got HTTP 401 -- bearer token for non-admin was rejected by AUTH, not denied by AUTHZ; expected 403 per openapi.yaml:9581-9584"
    else
      fail "expected 403, got HTTP ${s}"
    fi
  fi
fi

end_suite
