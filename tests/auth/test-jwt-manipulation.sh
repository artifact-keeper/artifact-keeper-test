#!/usr/bin/env bash
# test-jwt-manipulation.sh - JWT algorithm confusion and malformed token tests (T2-06)
#
# Verifies that the backend rejects JWTs crafted with alg=none, empty
# signatures, garbage payloads, and other manipulation attempts.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "auth-jwt-manipulation"
auth_admin
setup_workdir

# Build a base64url-encoded payload once; reused across tests.
PAYLOAD=$(printf '{"sub":"admin","user_id":"00000000-0000-0000-0000-000000000000","is_admin":true,"exp":9999999999}' \
  | base64 | tr '+/' '-_' | tr -d '=\n')

# -------------------------------------------------------------------------
# alg=none attack
# -------------------------------------------------------------------------

begin_test "JWT with alg=none is rejected"
HEADER_NONE=$(printf '{"alg":"none","typ":"JWT"}' | base64 | tr '+/' '-_' | tr -d '=\n')
FAKE_JWT="${HEADER_NONE}.${PAYLOAD}."

status=$(curl -s -o /dev/null -w "%{http_code}" $CURL_TIMEOUT \
  -H "Authorization: Bearer ${FAKE_JWT}" \
  "${BASE_URL}/api/v1/auth/me" 2>/dev/null) || true
if [ "$status" = "401" ]; then
  pass
else
  fail "JWT with alg=none was not rejected, got HTTP ${status}"
fi

# -------------------------------------------------------------------------
# HS256 header with empty signature
# -------------------------------------------------------------------------

begin_test "JWT with HS256 header but empty signature is rejected"
HEADER_HS256=$(printf '{"alg":"HS256","typ":"JWT"}' | base64 | tr '+/' '-_' | tr -d '=\n')
FAKE_JWT2="${HEADER_HS256}.${PAYLOAD}."

status=$(curl -s -o /dev/null -w "%{http_code}" $CURL_TIMEOUT \
  -H "Authorization: Bearer ${FAKE_JWT2}" \
  "${BASE_URL}/api/v1/auth/me" 2>/dev/null) || true
if [ "$status" = "401" ]; then
  pass
else
  fail "JWT with empty signature was not rejected, got HTTP ${status}"
fi

# -------------------------------------------------------------------------
# HS256 header with garbage signature
# -------------------------------------------------------------------------

begin_test "JWT with garbage signature is rejected"
FAKE_SIG=$(printf 'this-is-not-a-real-signature' | base64 | tr '+/' '-_' | tr -d '=\n')
FAKE_JWT3="${HEADER_HS256}.${PAYLOAD}.${FAKE_SIG}"

status=$(curl -s -o /dev/null -w "%{http_code}" $CURL_TIMEOUT \
  -H "Authorization: Bearer ${FAKE_JWT3}" \
  "${BASE_URL}/api/v1/auth/me" 2>/dev/null) || true
if [ "$status" = "401" ]; then
  pass
else
  fail "JWT with garbage signature was not rejected, got HTTP ${status}"
fi

# -------------------------------------------------------------------------
# Completely invalid bearer value
# -------------------------------------------------------------------------

begin_test "Completely invalid JWT string is rejected"
status=$(curl -s -o /dev/null -w "%{http_code}" $CURL_TIMEOUT \
  -H "Authorization: Bearer not.a.jwt.at.all" \
  "${BASE_URL}/api/v1/auth/me" 2>/dev/null) || true
if [ "$status" = "401" ]; then
  pass
else
  fail "invalid JWT string was not rejected, got HTTP ${status}"
fi

# -------------------------------------------------------------------------
# Single-segment bearer value
# -------------------------------------------------------------------------

begin_test "Single-segment bearer token is rejected"
status=$(curl -s -o /dev/null -w "%{http_code}" $CURL_TIMEOUT \
  -H "Authorization: Bearer totallynotavalidtoken" \
  "${BASE_URL}/api/v1/auth/me" 2>/dev/null) || true
if [ "$status" = "401" ]; then
  pass
else
  fail "single-segment bearer was not rejected, got HTTP ${status}"
fi

# -------------------------------------------------------------------------
# Empty Authorization header
# -------------------------------------------------------------------------

begin_test "Empty bearer value is rejected"
status=$(curl -s -o /dev/null -w "%{http_code}" $CURL_TIMEOUT \
  -H "Authorization: Bearer " \
  "${BASE_URL}/api/v1/auth/me" 2>/dev/null) || true
if [ "$status" = "401" ]; then
  pass
else
  fail "empty bearer value was not rejected, got HTTP ${status}"
fi

# -------------------------------------------------------------------------
# alg=none with "none" signature string
# -------------------------------------------------------------------------

begin_test "JWT with alg=none and dummy signature is rejected"
FAKE_JWT4="${HEADER_NONE}.${PAYLOAD}.dummysig"

status=$(curl -s -o /dev/null -w "%{http_code}" $CURL_TIMEOUT \
  -H "Authorization: Bearer ${FAKE_JWT4}" \
  "${BASE_URL}/api/v1/auth/me" 2>/dev/null) || true
if [ "$status" = "401" ]; then
  pass
else
  fail "JWT with alg=none and dummy sig was not rejected, got HTTP ${status}"
fi

end_suite
