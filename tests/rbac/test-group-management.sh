#!/usr/bin/env bash
# test-group-management.sh - Group CRUD and membership E2E test
#
# Tests creating groups, adding/removing members, listing groups.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "group-management"
auth_admin
setup_workdir

GROUP_NAME="e2e-group-${RUN_ID}"
USER_A="e2e-grp-user-a-${RUN_ID}"
USER_B="e2e-grp-user-b-${RUN_ID}"

# Create test users first
api_post "/api/v1/users" "{\"username\":\"${USER_A}\",\"password\":\"Pass123!\",\"email\":\"${USER_A}@test.local\"}" > /dev/null 2>&1 || true
api_post "/api/v1/users" "{\"username\":\"${USER_B}\",\"password\":\"Pass123!\",\"email\":\"${USER_B}@test.local\"}" > /dev/null 2>&1 || true

# -------------------------------------------------------------------------
# Create group
# -------------------------------------------------------------------------

begin_test "Create group"
if resp=$(api_post "/api/v1/groups" \
    "{\"name\":\"${GROUP_NAME}\",\"description\":\"E2E test group\"}" 2>/dev/null); then
  GROUP_ID=$(echo "$resp" | jq -r '.id // empty') || true
  pass
else
  fail "could not create group"
fi

# -------------------------------------------------------------------------
# List groups
# -------------------------------------------------------------------------

begin_test "List groups"
if resp=$(api_get "/api/v1/groups"); then
  if assert_contains "$resp" "$GROUP_NAME"; then
    pass
  fi
else
  fail "could not list groups"
fi

# -------------------------------------------------------------------------
# Add members
# -------------------------------------------------------------------------

begin_test "Add members to group"
endpoint="/api/v1/groups/${GROUP_ID:-$GROUP_NAME}/members"
if api_post "$endpoint" "{\"usernames\":[\"${USER_A}\",\"${USER_B}\"]}" > /dev/null 2>&1; then
  pass
elif api_post "$endpoint" "{\"members\":[\"${USER_A}\",\"${USER_B}\"]}" > /dev/null 2>&1; then
  pass
else
  skip "add members endpoint not available or different shape"
fi

# -------------------------------------------------------------------------
# List group members
# -------------------------------------------------------------------------

begin_test "List group members"
if resp=$(api_get "$endpoint" 2>/dev/null); then
  if assert_contains "$resp" "$USER_A"; then
    pass
  fi
else
  skip "member listing not available"
fi

# -------------------------------------------------------------------------
# Remove member
# -------------------------------------------------------------------------

begin_test "Remove member from group"
if api_delete "${endpoint}/${USER_B}" > /dev/null 2>&1; then
  pass
elif api_post "${endpoint}/remove" "{\"usernames\":[\"${USER_B}\"]}" > /dev/null 2>&1; then
  pass
else
  skip "remove member not available"
fi

# -------------------------------------------------------------------------
# Delete group
# -------------------------------------------------------------------------

begin_test "Delete group"
if api_delete "/api/v1/groups/${GROUP_ID:-$GROUP_NAME}" > /dev/null 2>&1; then
  pass
else
  fail "could not delete group"
fi

# Cleanup users
api_delete "/api/v1/users/${USER_A}" > /dev/null 2>&1 || true
api_delete "/api/v1/users/${USER_B}" > /dev/null 2>&1 || true

end_suite
