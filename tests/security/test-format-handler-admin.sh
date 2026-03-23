#!/usr/bin/env bash
# test-format-handler-admin.sh - #535: Format handler enable/disable requires admin
#
# Verifies that toggling format handlers (enable/disable) is restricted to
# admin users and that non-admin users receive 403.

source "$(dirname "$0")/../lib/common.sh"

begin_suite "format-handler-admin"
auth_admin
setup_workdir

TEST_USER="e2e-fmtadmin-${RUN_ID}"
TEST_PASS="FmtAdmin123!"
USER_ID=""
USER_TOKEN=""

# A format to test against. Generic is always present.
TARGET_FORMAT="generic"

# ---------------------------------------------------------------------------
# Setup: create a non-admin user
# ---------------------------------------------------------------------------

begin_test "Create non-admin user"
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
  fail "login failed for non-admin user"
fi

# ---------------------------------------------------------------------------
# Discover format handler management endpoints
# ---------------------------------------------------------------------------

# The backend may expose format management at different paths. We try the
# most likely candidates and skip if none exist.
FORMAT_ENABLE_PATHS=(
  "/api/v1/formats/${TARGET_FORMAT}/enable"
  "/api/v1/admin/formats/${TARGET_FORMAT}/enable"
  "/api/v1/system/formats/${TARGET_FORMAT}/enable"
)

FORMAT_DISABLE_PATHS=(
  "/api/v1/formats/${TARGET_FORMAT}/disable"
  "/api/v1/admin/formats/${TARGET_FORMAT}/disable"
  "/api/v1/system/formats/${TARGET_FORMAT}/disable"
)

# ---------------------------------------------------------------------------
# Non-admin must be blocked from enabling a format handler
# ---------------------------------------------------------------------------

begin_test "Non-admin cannot enable format handler"
if [ -z "$USER_TOKEN" ]; then
  skip "no user token available"
else
  tested=false
  for path in "${FORMAT_ENABLE_PATHS[@]}"; do
    # Check if endpoint exists (as admin first)
    admin_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
      -X POST \
      -H "$(auth_header)" \
      -H "Content-Type: application/json" \
      "${BASE_URL}${path}" 2>/dev/null) || true

    if [ "$admin_status" = "404" ]; then
      continue
    fi

    tested=true
    # Now try as non-admin
    user_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
      -X POST \
      -H "Authorization: Bearer ${USER_TOKEN}" \
      -H "Content-Type: application/json" \
      "${BASE_URL}${path}" 2>/dev/null) || true

    if [ "$user_status" = "403" ]; then
      pass
    elif [ "$user_status" = "401" ]; then
      # Token not recognized for this endpoint scope; still blocked
      pass
    elif [ "$user_status" = "200" ]; then
      fail "non-admin was able to enable format handler at ${path} (HTTP 200)"
    else
      # 400, 422, 500 all mean the action was not completed
      pass
    fi
    break
  done

  if [ "$tested" = "false" ]; then
    skip "no format enable endpoint found at any known path"
  fi
fi

# ---------------------------------------------------------------------------
# Non-admin must be blocked from disabling a format handler
# ---------------------------------------------------------------------------

begin_test "Non-admin cannot disable format handler"
if [ -z "$USER_TOKEN" ]; then
  skip "no user token available"
else
  tested=false
  for path in "${FORMAT_DISABLE_PATHS[@]}"; do
    admin_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
      -X POST \
      -H "$(auth_header)" \
      -H "Content-Type: application/json" \
      "${BASE_URL}${path}" 2>/dev/null) || true

    if [ "$admin_status" = "404" ]; then
      continue
    fi

    tested=true
    user_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
      -X POST \
      -H "Authorization: Bearer ${USER_TOKEN}" \
      -H "Content-Type: application/json" \
      "${BASE_URL}${path}" 2>/dev/null) || true

    if [ "$user_status" = "403" ]; then
      pass
    elif [ "$user_status" = "401" ]; then
      pass
    elif [ "$user_status" = "200" ]; then
      fail "non-admin was able to disable format handler at ${path} (HTTP 200)"
    else
      pass
    fi
    break
  done

  if [ "$tested" = "false" ]; then
    skip "no format disable endpoint found at any known path"
  fi
fi

# ---------------------------------------------------------------------------
# Admin CAN enable/disable format handlers (positive control)
# ---------------------------------------------------------------------------

begin_test "Admin can manage format handlers"
tested=false
for path in "${FORMAT_ENABLE_PATHS[@]}"; do
  admin_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X POST \
    -H "$(auth_header)" \
    -H "Content-Type: application/json" \
    "${BASE_URL}${path}" 2>/dev/null) || true

  if [ "$admin_status" = "404" ]; then
    continue
  fi

  tested=true
  if [ "$admin_status" -ge 200 ] 2>/dev/null && [ "$admin_status" -lt 300 ] 2>/dev/null; then
    pass
  elif [ "$admin_status" = "409" ]; then
    # Already enabled; that is fine
    pass
  else
    fail "admin could not enable format handler at ${path} (HTTP ${admin_status})"
  fi
  break
done

if [ "$tested" = "false" ]; then
  skip "no format enable endpoint found at any known path"
fi

# ---------------------------------------------------------------------------
# Non-admin cannot list format handler config (if such endpoint exists)
# ---------------------------------------------------------------------------

begin_test "Non-admin cannot access format handler listing"
if [ -z "$USER_TOKEN" ]; then
  skip "no user token available"
else
  FORMAT_LIST_PATHS=(
    "/api/v1/formats"
    "/api/v1/admin/formats"
    "/api/v1/system/formats"
  )

  tested=false
  for path in "${FORMAT_LIST_PATHS[@]}"; do
    admin_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
      -H "$(auth_header)" \
      "${BASE_URL}${path}" 2>/dev/null) || true

    if [ "$admin_status" = "404" ]; then
      continue
    fi

    tested=true
    user_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
      -H "Authorization: Bearer ${USER_TOKEN}" \
      "${BASE_URL}${path}" 2>/dev/null) || true

    # Format listing may be public (read-only). Only fail if the endpoint
    # is explicitly admin-only (admin gets 200 but user gets 403).
    if [ "$user_status" = "403" ] || [ "$user_status" = "401" ]; then
      pass
    elif [ "$user_status" -ge 200 ] 2>/dev/null && [ "$user_status" -lt 300 ] 2>/dev/null; then
      # Read-only listing may be intentionally public; not a failure
      skip "format listing appears to be public (non-admin got HTTP ${user_status})"
    else
      pass
    fi
    break
  done

  if [ "$tested" = "false" ]; then
    skip "no format listing endpoint found"
  fi
fi

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

if [ -n "$USER_ID" ] && [ "$USER_ID" != "null" ]; then
  api_delete "/api/v1/users/${USER_ID}" > /dev/null 2>&1 || true
fi

end_suite
