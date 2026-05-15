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
  if [ -n "$GROUP_ID" ]; then
    pass
  else
    fail "create group response did not include an id"
  fi
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
# Backend MembersRequest is { user_ids: Vec<Uuid> }; add_group_members resolves
# usernames to UUIDs and posts the correct payload.
if add_group_members "$GROUP_ID" "$USER_A" "$USER_B" > /dev/null 2>&1; then
  pass
else
  fail "could not add members to group"
fi

# -------------------------------------------------------------------------
# List group members
# -------------------------------------------------------------------------

begin_test "List group members"
# Group detail returns members inline, not via a separate /members GET.
if resp=$(api_get "/api/v1/groups/${GROUP_ID}" 2>/dev/null); then
  if assert_contains "$resp" "$USER_A"; then
    pass
  fi
else
  fail "could not fetch group detail"
fi

# -------------------------------------------------------------------------
# Remove member
# -------------------------------------------------------------------------

begin_test "Remove member from group"
# Backend remove_members takes the same { user_ids: [...] } body via DELETE.
if remove_group_members "$GROUP_ID" "$USER_B" > /dev/null 2>&1; then
  pass
else
  fail "could not remove member from group"
fi

# -------------------------------------------------------------------------
# Delete group
# -------------------------------------------------------------------------

begin_test "Delete group"
if api_delete "/api/v1/groups/${GROUP_ID}" > /dev/null 2>&1; then
  pass
else
  fail "could not delete group"
fi

# Cleanup users
api_delete "/api/v1/users/${USER_A}" > /dev/null 2>&1 || true
api_delete "/api/v1/users/${USER_B}" > /dev/null 2>&1 || true

end_suite
