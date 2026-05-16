#!/usr/bin/env bash
# test-jwt-after-password-change.sh - JWT invalidation on password change (Epic 11, #76)
#
# Verifies the CREDENTIAL_INVALIDATIONS map shipped in PR #931: when a user
# changes their password, every JWT issued before the change MUST be rejected
# with 401 on the next request. Tokens issued AFTER the change continue to
# work.
#
# Failure mode this guards against: a leaked JWT remains valid until its
# exp claim, even after the user rotates their password. Pre-#931, the
# password-change endpoint did not push the user_id into the invalidation
# map, so cached JWTs survived the rotation.
#
# Backend reference: services/auth/credential_invalidations.rs
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "auth-jwt-after-password-change"
auth_admin
setup_workdir

TEST_USER="e2e-pwchange-${RUN_ID}"
TEST_PASS_OLD="OldPass_Pass123!"
TEST_PASS_NEW="NewPass_Pass456!"
TEST_EMAIL="${TEST_USER}@test.local"
USER_ID=""
OLD_JWT=""
NEW_JWT=""

begin_test "Create test user"
if resp=$(api_post "/api/v1/users" \
    "{\"username\":\"${TEST_USER}\",\"password\":\"${TEST_PASS_OLD}\",\"email\":\"${TEST_EMAIL}\",\"display_name\":\"PW Change Test\"}" 2>/dev/null); then
  USER_ID=$(echo "$resp" | jq -r '.user.id // .id // empty')
  if [ -n "$USER_ID" ] && [ "$USER_ID" != "null" ]; then
    pass
  else
    fail "no user id in response: ${resp:0:200}"
  fi
else
  fail "could not create user"
fi

begin_test "Login with old password (capture OLD_JWT)"
if [ -z "${USER_ID:-}" ] || [ "$USER_ID" = "null" ]; then
  skip "no user"
else
  OLD_JWT=$(login_as "${TEST_USER}" "${TEST_PASS_OLD}") || true
  if [ -n "$OLD_JWT" ]; then
    pass
  else
    fail "login with old password returned empty token"
  fi
fi

begin_test "OLD_JWT works on /auth/me (baseline)"
if [ -z "${OLD_JWT:-}" ]; then
  skip "no OLD_JWT"
else
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "Authorization: Bearer ${OLD_JWT}" \
    "${BASE_URL}/api/v1/auth/me" 2>/dev/null) || status=000
  if [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then
    pass
  else
    fail "OLD_JWT failed baseline check, got ${status}"
  fi
fi

begin_test "Change password via user self-service endpoint"
if [ -z "${USER_ID:-}" ] || [ "$USER_ID" = "null" ] || [ -z "${OLD_JWT:-}" ]; then
  skip "no user/jwt"
else
  # Use the user's own JWT to change their password (self-service path).
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X POST \
    -H "Authorization: Bearer ${OLD_JWT}" \
    -H "Content-Type: application/json" \
    -d "{\"current_password\":\"${TEST_PASS_OLD}\",\"new_password\":\"${TEST_PASS_NEW}\"}" \
    "${BASE_URL}/api/v1/users/${USER_ID}/password" 2>/dev/null) || status=000
  if [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then
    pass
  else
    fail "password change returned ${status}"
  fi
fi

begin_test "OLD_JWT is rejected (401) after password change"
if [ -z "${OLD_JWT:-}" ]; then
  skip "no OLD_JWT"
else
  # Small grace window in case the invalidation map is written async.
  # The CREDENTIAL_INVALIDATIONS map is in-process and synchronous in
  # 1.1.x, so this should be immediate; we sleep 1s to absorb any future
  # async-cache work without making the test brittle.
  sleep 1
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "Authorization: Bearer ${OLD_JWT}" \
    "${BASE_URL}/api/v1/auth/me" 2>/dev/null) || status=000
  if [ "$status" = "401" ]; then
    pass
  else
    fail "OLD_JWT should be rejected after password change, got HTTP ${status} (regression of PR #931)"
  fi
fi

begin_test "Login with new password yields a fresh, working JWT"
# Get NEW_JWT first. This is needed for the causation check below: if the
# whole signing key has rotated (or the session table has been flushed by
# something unrelated), NEW_JWT obtained AFTER the password change would
# also fail, and the OLD_JWT 401 above would not actually prove the
# CREDENTIAL_INVALIDATIONS map was the cause.
NEW_JWT=$(login_as "${TEST_USER}" "${TEST_PASS_NEW}") || true
if [ -z "$NEW_JWT" ]; then
  fail "login with new password failed"
else
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "Authorization: Bearer ${NEW_JWT}" \
    "${BASE_URL}/api/v1/auth/me" 2>/dev/null) || status=000
  if [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then
    pass
  else
    fail "NEW_JWT failed: HTTP ${status}"
  fi
fi

# Causation pin: NEW_JWT works (verified above) AND OLD_JWT still fails.
# Rules out the "all JWTs are 401" scenarios (signing key rotation,
# session table flush, audience claim change, JWKS endpoint failure)
# that would also produce a 401 on OLD_JWT but for the wrong reason.
# The CREDENTIAL_INVALIDATIONS map is per-user, so a NEW_JWT minted for
# the same user AFTER the invalidation entry was written MUST pass while
# OLD_JWT (minted BEFORE) MUST still fail. That asymmetric pair is the
# behavior #931 actually shipped, and what this test should pin.
begin_test "CREDENTIAL_INVALIDATIONS causation: NEW_JWT works, OLD_JWT still fails"
if [ -z "${OLD_JWT:-}" ] || [ -z "${NEW_JWT:-}" ]; then
  skip "missing OLD_JWT or NEW_JWT for causation check"
else
  new_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "Authorization: Bearer ${NEW_JWT}" \
    "${BASE_URL}/api/v1/auth/me" 2>/dev/null) || new_status=000
  old_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "Authorization: Bearer ${OLD_JWT}" \
    "${BASE_URL}/api/v1/auth/me" 2>/dev/null) || old_status=000

  new_ok=0
  if [[ "$new_status" =~ ^[0-9]+$ ]] && [ "$new_status" -ge 200 ] && [ "$new_status" -lt 300 ]; then
    new_ok=1
  fi

  if [ "$new_ok" = "1" ] && [ "$old_status" = "401" ]; then
    pass
  elif [ "$new_ok" != "1" ] && [ "$old_status" = "401" ]; then
    fail "both JWTs fail (NEW=${new_status}, OLD=${old_status}). OLD_JWT 401 is not actually caused by CREDENTIAL_INVALIDATIONS; could be signing-key rotation, session flush, or audience-claim change."
  elif [ "$new_ok" = "1" ] && [ "$old_status" != "401" ]; then
    fail "NEW_JWT works (${new_status}) but OLD_JWT no longer rejected (${old_status}). CREDENTIAL_INVALIDATIONS map appears to no longer block pre-rotation tokens (regression of PR #931)."
  else
    fail "unexpected NEW=${new_status} OLD=${old_status}"
  fi
fi

# Cleanup
auth_admin
if [ -n "${USER_ID:-}" ] && [ "$USER_ID" != "null" ]; then
  api_delete "/api/v1/users/${USER_ID}" > /dev/null 2>&1 || true
fi

end_suite
