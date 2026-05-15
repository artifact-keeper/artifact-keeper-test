#!/usr/bin/env bash
# test-group-detail-members.sh - Regression test for bug #813
#
# The GET /api/v1/groups/{id} endpoint previously did not return group members
# at all. After the fix, it returns members with pagination support via
# member_limit and member_offset query params, plus a members_total field.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "group-detail-members"
auth_admin
setup_workdir

GROUP_NAME="e2e-detail-grp-${RUN_ID}"
USER_A="e2e-dtl-a-${RUN_ID}"
USER_B="e2e-dtl-b-${RUN_ID}"
USER_C="e2e-dtl-c-${RUN_ID}"

GROUP_ID=""

# -------------------------------------------------------------------------
# 1. Create a group
# -------------------------------------------------------------------------

begin_test "Create group for member detail tests"
if resp=$(api_post "/api/v1/groups" \
    "{\"name\":\"${GROUP_NAME}\",\"description\":\"Regression test for bug 813\"}" 2>/dev/null); then
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
# 2. Create 3 test users
# -------------------------------------------------------------------------

begin_test "Create 3 test users"
fail_count=0
for user in "$USER_A" "$USER_B" "$USER_C"; do
  if ! api_post "/api/v1/users" \
      "{\"username\":\"${user}\",\"password\":\"Pass813!\",\"email\":\"${user}@test.local\"}" > /dev/null 2>&1; then
    fail_count=$(( fail_count + 1 ))
  fi
done
if [ "$fail_count" -eq 0 ]; then
  pass
else
  fail "failed to create ${fail_count} of 3 test users"
fi

# -------------------------------------------------------------------------
# 3. Add all 3 users to the group
# -------------------------------------------------------------------------

begin_test "Add 3 users to the group"
# The backend expects { "user_ids": [<uuid>, ...] } at POST /api/v1/groups/{id}/members
# (see backend MembersRequest). add_group_members resolves usernames to UUIDs first.
if add_group_members "$GROUP_ID" "$USER_A" "$USER_B" "$USER_C" > /dev/null 2>&1; then
  pass
else
  fail "could not add members to group"
fi

# -------------------------------------------------------------------------
# 4. Get group detail and verify members array exists (the original bug)
# -------------------------------------------------------------------------

begin_test "Group detail response contains members array"
if resp=$(api_get "/api/v1/groups/${GROUP_ID}" 2>/dev/null); then
  has_members=$(echo "$resp" | jq 'has("members")')
  if assert_eq "$has_members" "true" "members field missing from group detail response (bug #813)"; then
    pass
  fi
else
  fail "could not fetch group detail"
fi

# -------------------------------------------------------------------------
# 5. Verify members array contains all 3 users
# -------------------------------------------------------------------------

begin_test "Members array contains all 3 users"
if resp=$(api_get "/api/v1/groups/${GROUP_ID}" 2>/dev/null); then
  members_json=$(echo "$resp" | jq -r '[.members[].username // .members[].name // empty] | sort | join(",")')
  expected=$(printf '%s\n' "$USER_A" "$USER_B" "$USER_C" | sort | paste -sd ',' -)
  all_found=true
  for user in "$USER_A" "$USER_B" "$USER_C"; do
    if ! echo "$resp" | jq -e --arg u "$user" '.members[] | select(.username == $u or .name == $u)' > /dev/null 2>&1; then
      fail "member ${user} not found in members array"
      all_found=false
      break
    fi
  done
  if $all_found; then
    pass
  fi
else
  fail "could not fetch group detail"
fi

# -------------------------------------------------------------------------
# 6. Verify members_total field equals 3
# -------------------------------------------------------------------------

begin_test "members_total field equals 3"
if resp=$(api_get "/api/v1/groups/${GROUP_ID}" 2>/dev/null); then
  members_total=$(echo "$resp" | jq -r '.members_total // empty')
  if [ -z "$members_total" ]; then
    fail "members_total field missing from group detail response"
  elif assert_eq "$members_total" "3" "expected members_total=3, got ${members_total}"; then
    pass
  fi
else
  fail "could not fetch group detail"
fi

# -------------------------------------------------------------------------
# 7. Pagination: member_limit=1 returns 1 member but members_total=3
# -------------------------------------------------------------------------

begin_test "Pagination: member_limit=1 returns 1 member with members_total=3"
if resp=$(api_get "/api/v1/groups/${GROUP_ID}?member_limit=1" 2>/dev/null); then
  count=$(echo "$resp" | jq '.members | length')
  total=$(echo "$resp" | jq -r '.members_total // empty')
  if ! assert_eq "$count" "1" "expected 1 member with limit=1, got ${count}"; then
    :
  elif [ -z "$total" ]; then
    fail "members_total field missing when using member_limit"
  elif ! assert_eq "$total" "3" "expected members_total=3, got ${total}"; then
    :
  else
    pass
  fi
else
  fail "could not fetch group detail with member_limit=1"
fi

# -------------------------------------------------------------------------
# 8. Pagination: member_limit=2&member_offset=1 returns correct slice
# -------------------------------------------------------------------------

begin_test "Pagination: member_limit=2 member_offset=1 returns 2 members"
if resp=$(api_get "/api/v1/groups/${GROUP_ID}?member_limit=2&member_offset=1" 2>/dev/null); then
  count=$(echo "$resp" | jq '.members | length')
  total=$(echo "$resp" | jq -r '.members_total // empty')
  if ! assert_eq "$count" "2" "expected 2 members with limit=2,offset=1, got ${count}"; then
    :
  elif ! assert_eq "$total" "3" "expected members_total=3, got ${total}"; then
    :
  else
    pass
  fi
else
  fail "could not fetch group detail with member_limit=2&member_offset=1"
fi

# -------------------------------------------------------------------------
# 9. Default pagination returns all members (no explicit limit/offset)
# -------------------------------------------------------------------------

begin_test "Default pagination returns all members without explicit params"
if resp=$(api_get "/api/v1/groups/${GROUP_ID}" 2>/dev/null); then
  count=$(echo "$resp" | jq '.members | length')
  if [ "$count" -ge 3 ]; then
    pass
  else
    fail "expected at least 3 members with default pagination, got ${count}"
  fi
else
  fail "could not fetch group detail for default pagination check"
fi

# -------------------------------------------------------------------------
# 10. Pagination: offset beyond total returns empty members array
# -------------------------------------------------------------------------

begin_test "Pagination: offset beyond total returns empty members"
if resp=$(api_get "/api/v1/groups/${GROUP_ID}?member_limit=10&member_offset=100" 2>/dev/null); then
  count=$(echo "$resp" | jq '.members | length')
  total=$(echo "$resp" | jq -r '.members_total // empty')
  if ! assert_eq "$count" "0" "expected 0 members with offset=100, got ${count}"; then
    :
  elif ! assert_eq "$total" "3" "expected members_total=3 even with high offset, got ${total}"; then
    :
  else
    pass
  fi
else
  fail "could not fetch group detail with high offset"
fi

# -------------------------------------------------------------------------
# Cleanup
# -------------------------------------------------------------------------

api_delete "/api/v1/groups/${GROUP_ID}" > /dev/null 2>&1 || true
api_delete "/api/v1/users/${USER_A}" > /dev/null 2>&1 || true
api_delete "/api/v1/users/${USER_B}" > /dev/null 2>&1 || true
api_delete "/api/v1/users/${USER_C}" > /dev/null 2>&1 || true

end_suite
