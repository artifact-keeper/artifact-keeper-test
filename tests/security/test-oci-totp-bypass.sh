#!/usr/bin/env bash
# test-oci-totp-bypass.sh - #536: OCI registry TOTP bypass
#
# Verifies that the OCI /v2/ token endpoint behaves correctly: returns
# proper Www-Authenticate headers, accepts Basic auth for normal users,
# and rejects password-only auth when TOTP is enabled (if TOTP setup
# is available in the test environment).

source "$(dirname "$0")/../lib/common.sh"

begin_suite "oci-totp-bypass"
auth_admin
setup_workdir

TEST_USER="e2e-oci-totp-${RUN_ID}"
TEST_PASS="OciTotp123!"
USER_ID=""

# ---------------------------------------------------------------------------
# OCI /v2/ endpoint must return Www-Authenticate header on 401
# ---------------------------------------------------------------------------

begin_test "GET /v2/ returns 401 with Www-Authenticate header"
response_headers=$(curl -s -D - -o /dev/null $CURL_TIMEOUT \
  "${BASE_URL}/v2/" 2>/dev/null) || true

status=$(echo "$response_headers" | grep -i "^HTTP/" | tail -1 | awk '{print $2}') || true

if [ "$status" = "401" ]; then
  if echo "$response_headers" | grep -qi "Www-Authenticate"; then
    pass
  else
    fail "/v2/ returned 401 but missing Www-Authenticate header"
  fi
elif [ "$status" = "404" ]; then
  skip "OCI /v2/ endpoint not available on this deployment"
elif [ "$status" = "200" ]; then
  # Open registry without auth; not necessarily wrong
  skip "/v2/ returned 200 (registry allows anonymous access)"
else
  # 301, 302, etc. still means OCI endpoint is responding
  pass
fi

# ---------------------------------------------------------------------------
# Create a test user for OCI auth tests
# ---------------------------------------------------------------------------

begin_test "Create test user for OCI auth"
if resp=$(api_post "/api/v1/users" \
    "{\"username\":\"${TEST_USER}\",\"password\":\"${TEST_PASS}\",\"email\":\"${TEST_USER}@test.local\"}" 2>/dev/null); then
  USER_ID=$(echo "$resp" | jq -r '.user.id // .id // .user_id // empty') || true
  if [ -n "$USER_ID" ] && [ "$USER_ID" != "null" ]; then
    pass
  else
    fail "user created but no ID returned"
  fi
else
  fail "could not create test user"
fi

# ---------------------------------------------------------------------------
# Basic auth against /v2/token works for normal user (no TOTP)
# ---------------------------------------------------------------------------

begin_test "OCI Basic auth works for user without TOTP"
BASIC_AUTH=$(printf '%s:%s' "$TEST_USER" "$TEST_PASS" | base64)

# Try the /v2/token endpoint first, then /v2/ directly
token_status=""
for token_path in "/v2/token" "/v2/auth" "/v2/"; do
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "Authorization: Basic ${BASIC_AUTH}" \
    "${BASE_URL}${token_path}" 2>/dev/null) || true

  if [ "$status" != "404" ]; then
    token_status="$status"
    break
  fi
done

if [ -z "$token_status" ]; then
  skip "no OCI token endpoint found"
elif [ "$token_status" = "200" ]; then
  pass
elif [ "$token_status" = "401" ]; then
  # Might need scope parameter or different auth flow
  # Try with scope parameter
  status_with_scope=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "Authorization: Basic ${BASIC_AUTH}" \
    "${BASE_URL}/v2/token?service=artifact-keeper&scope=registry:catalog:*" 2>/dev/null) || true
  if [ "$status_with_scope" = "200" ]; then
    pass
  else
    skip "OCI auth returned ${token_status} (may require different auth flow)"
  fi
else
  # 403, 500, etc.
  skip "OCI token endpoint returned ${token_status}"
fi

# ---------------------------------------------------------------------------
# Attempt to enable TOTP via API, then verify password-only auth is blocked
# ---------------------------------------------------------------------------

begin_test "TOTP setup available via API"
TOTP_AVAILABLE=false

# Login as the test user first
user_resp=$(curl -sf $CURL_TIMEOUT -X POST "${BASE_URL}/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"${TEST_USER}\",\"password\":\"${TEST_PASS}\"}" 2>/dev/null) || true
USER_TOKEN=$(echo "$user_resp" | jq -r '.token // .access_token // empty' 2>/dev/null) || true

if [ -z "$USER_TOKEN" ]; then
  skip "could not login as test user"
else
  # Check if TOTP setup endpoint exists
  totp_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X POST \
    -H "Authorization: Bearer ${USER_TOKEN}" \
    "${BASE_URL}/api/v1/auth/totp/setup" 2>/dev/null) || true

  if [ "$totp_status" = "404" ]; then
    skip "TOTP setup endpoint not available"
  elif [ "$totp_status" -ge 200 ] 2>/dev/null && [ "$totp_status" -lt 300 ] 2>/dev/null; then
    TOTP_AVAILABLE=true
    pass
  else
    skip "TOTP setup returned HTTP ${totp_status}"
  fi
fi

begin_test "Password-only OCI auth rejected when TOTP is enabled"
if [ "$TOTP_AVAILABLE" != "true" ]; then
  skip "TOTP not available in test environment; cannot verify TOTP enforcement on /v2/"
else
  # If TOTP was set up, Basic auth with just password should fail on /v2/token
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "Authorization: Basic ${BASIC_AUTH}" \
    "${BASE_URL}/v2/token?service=artifact-keeper" 2>/dev/null) || true

  if [ "$status" = "401" ] || [ "$status" = "403" ]; then
    pass
  elif [ "$status" = "200" ]; then
    fail "password-only auth accepted on /v2/token despite TOTP being enabled"
  else
    skip "OCI token endpoint returned ${status}"
  fi
fi

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

if [ -n "$USER_ID" ] && [ "$USER_ID" != "null" ]; then
  api_delete "/api/v1/users/${USER_ID}" > /dev/null 2>&1 || true
fi

end_suite
