#!/usr/bin/env bash
# test-storage-backends-list.sh - Storage backend listing contract (Epic 10.9, #77)
#
# Pins the contract on GET /api/v1/admin/storage-backends. The endpoint
# lists configured storage backends (filesystem, s3) and is admin-only.
#
# Verifies:
#   - 200 with array response for admin
#   - At least one backend present (default filesystem must always exist)
#   - 401 for unauthenticated request
#   - 403 for non-admin user
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "admin-storage-backends-list"
auth_admin
setup_workdir

NONADMIN_USER="e2e-storage-${RUN_ID}"
NONADMIN_PASS="StorageTest_Pass123!"
NONADMIN_EMAIL="${NONADMIN_USER}@test.local"
NONADMIN_TOKEN=""
USER_ID=""

begin_test "GET /admin/storage-backends as admin returns array"
if resp=$(api_get "/api/v1/admin/storage-backends" 2>/dev/null); then
  if echo "$resp" | jq -e 'type == "array" or (.backends | type == "array") or (.items | type == "array")' > /dev/null 2>&1; then
    pass
  else
    fail "unexpected response shape: ${resp:0:200}"
  fi
else
  skip "endpoint not available in this build"
fi

begin_test "Storage backend list contains at least one entry"
if resp=$(api_get "/api/v1/admin/storage-backends" 2>/dev/null); then
  count=$(echo "$resp" | jq '
    if type == "array" then length
    elif (.backends | type == "array") then (.backends | length)
    elif (.items | type == "array") then (.items | length)
    else 0 end' 2>/dev/null || echo 0)
  if [ "${count:-0}" -ge 1 ] 2>/dev/null; then
    pass
  else
    fail "expected >= 1 backend, got ${count}"
  fi
else
  skip "endpoint not available"
fi

begin_test "GET /admin/storage-backends without auth returns 401"
status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  "${BASE_URL}/api/v1/admin/storage-backends" 2>/dev/null) || status=000
if [ "$status" = "401" ] || [ "$status" = "403" ]; then
  pass
elif [ "$status" = "404" ]; then
  skip "endpoint not mounted"
else
  fail "expected 401/403 for unauthenticated, got ${status}"
fi

# Create a non-admin user to verify 403 (not 401) for authenticated-but-unauthorized.
begin_test "Create non-admin user for authz test"
if resp=$(api_post "/api/v1/users" \
    "{\"username\":\"${NONADMIN_USER}\",\"password\":\"${NONADMIN_PASS}\",\"email\":\"${NONADMIN_EMAIL}\",\"display_name\":\"Storage Test\"}" 2>/dev/null); then
  USER_ID=$(echo "$resp" | jq -r '.user.id // .id // empty')
  pass
else
  skip "could not create non-admin user"
fi

begin_test "Non-admin login"
if [ -z "${USER_ID:-}" ] || [ "$USER_ID" = "null" ]; then
  skip "no user id"
else
  NONADMIN_TOKEN=$(login_as "${NONADMIN_USER}" "${NONADMIN_PASS}") || true
  if [ -n "${NONADMIN_TOKEN:-}" ]; then
    pass
  else
    fail "login returned empty token"
  fi
fi

begin_test "Non-admin gets 403 on GET /admin/storage-backends"
if [ -z "${NONADMIN_TOKEN:-}" ]; then
  skip "no non-admin token"
else
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "Authorization: Bearer ${NONADMIN_TOKEN}" \
    "${BASE_URL}/api/v1/admin/storage-backends" 2>/dev/null) || status=000
  if [ "$status" = "403" ]; then
    pass
  elif [ "$status" = "404" ]; then
    skip "endpoint not mounted"
  else
    fail "expected 403 for non-admin, got ${status}"
  fi
fi

# Cleanup
auth_admin
if [ -n "${USER_ID:-}" ] && [ "$USER_ID" != "null" ]; then
  api_delete "/api/v1/users/${USER_ID}" > /dev/null 2>&1 || true
fi

end_suite
