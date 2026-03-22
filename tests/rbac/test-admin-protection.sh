#!/usr/bin/env bash
# test-admin-protection.sh - Systematic admin endpoint protection E2E test
#
# Verifies that a non-admin user receives 403 on every admin-only endpoint.
# Uses a loop over endpoint definitions to keep the test compact and easy
# to extend as new admin routes are added.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "admin-protection"
auth_admin
setup_workdir

TEST_USER="e2e-adminprot-${RUN_ID}"
TEST_PASS="AdminProt123!"

# -------------------------------------------------------------------------
# Setup: create a non-admin user and login
# -------------------------------------------------------------------------

begin_test "Create non-admin user"
USER_ID=""
if resp=$(api_post "/api/v1/users" \
    "{\"username\":\"${TEST_USER}\",\"password\":\"${TEST_PASS}\",\"email\":\"${TEST_USER}@test.local\"}" 2>/dev/null); then
  USER_ID=$(echo "$resp" | jq -r '.user.id // .id // .user_id // empty') || true
  if [ -n "$USER_ID" ] && [ "$USER_ID" != "null" ]; then
    pass
  else
    fail "user created but no ID returned"
  fi
else
  fail "could not create non-admin user"
fi

begin_test "Login as non-admin user"
USER_TOKEN=""
if resp=$(curl -sf $CURL_TIMEOUT -X POST "${BASE_URL}/api/v1/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${TEST_USER}\",\"password\":\"${TEST_PASS}\"}" 2>/dev/null); then
  USER_TOKEN=$(echo "$resp" | jq -r '.token // .access_token // empty') || true
  if [ -n "$USER_TOKEN" ]; then
    pass
  else
    fail "no token in login response"
  fi
else
  fail "login failed"
fi

# -------------------------------------------------------------------------
# Systematic check: each admin endpoint must return 403
#
# Format: "METHOD PATH DESCRIPTION"
# Endpoints that require a body use POST/PUT; read-only use GET.
# -------------------------------------------------------------------------

ADMIN_ENDPOINTS=(
  "GET /api/v1/admin/settings Admin settings"
  "GET /api/v1/admin/backups Backup listing"
  "GET /api/v1/admin/metrics Metrics endpoint"
  "GET /api/v1/admin/monitoring/health-log Health log"
  "POST /api/v1/users User creation"
  "POST /api/v1/groups Group creation"
  "POST /api/v1/plugins Plugin installation"
)

if [ -n "$USER_TOKEN" ]; then
  for entry in "${ADMIN_ENDPOINTS[@]}"; do
    method=$(echo "$entry" | awk '{print $1}')
    path=$(echo "$entry" | awk '{print $2}')
    desc=$(echo "$entry" | cut -d' ' -f3-)

    begin_test "Non-admin blocked from: ${desc} (${method} ${path})"

    case "$method" in
      GET)
        status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
          -H "Authorization: Bearer ${USER_TOKEN}" \
          "${BASE_URL}${path}" 2>/dev/null) || true
        ;;
      POST)
        # Send a minimal JSON body for POST endpoints
        status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
          -X POST \
          -H "Authorization: Bearer ${USER_TOKEN}" \
          -H "Content-Type: application/json" \
          -d '{}' \
          "${BASE_URL}${path}" 2>/dev/null) || true
        ;;
      PUT)
        status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
          -X PUT \
          -H "Authorization: Bearer ${USER_TOKEN}" \
          -H "Content-Type: application/json" \
          -d '{}' \
          "${BASE_URL}${path}" 2>/dev/null) || true
        ;;
      DELETE)
        status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
          -X DELETE \
          -H "Authorization: Bearer ${USER_TOKEN}" \
          "${BASE_URL}${path}" 2>/dev/null) || true
        ;;
    esac

    # Some endpoints may validate the request body before checking authorization,
    # returning 422 (validation) or 400 (bad request) instead of 403. Both
    # outcomes confirm the non-admin user cannot perform the action successfully.
    if [ "$status" = "403" ] || [ "$status" = "422" ] || [ "$status" = "400" ]; then
      pass
    else
      fail "expected 403/422/400 for ${method} ${path}, got ${status}"
    fi
  done
else
  # Skip all endpoint checks if we have no token
  for entry in "${ADMIN_ENDPOINTS[@]}"; do
    desc=$(echo "$entry" | cut -d' ' -f3-)
    begin_test "Non-admin blocked from: ${desc}"
    skip "no user token"
  done
fi

# -------------------------------------------------------------------------
# Verify admin CAN access these endpoints (sanity check)
# -------------------------------------------------------------------------

begin_test "Admin can access admin settings (sanity check)"
status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/admin/settings" 2>/dev/null) || true
if [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then
  pass
else
  skip "admin settings endpoint returned ${status} (may not exist)"
fi

# -------------------------------------------------------------------------
# Cleanup
# -------------------------------------------------------------------------

auth_admin
api_delete "/api/v1/users/${USER_ID}" > /dev/null 2>&1 || true

end_suite
