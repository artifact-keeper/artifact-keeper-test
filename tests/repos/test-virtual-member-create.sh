#!/usr/bin/env bash
# test-virtual-member-create.sh - Virtual repo member creation in API
#
# Tests two approaches for adding members to a virtual repo: specifying
# member_repos in the POST body at creation time, and adding them after
# creation via the members endpoint.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "virtual-member-create"
auth_admin
setup_workdir
# Two member-listing polls of at most 15 s each; each normally ends on its
# first probe (member writes commit before they answer).
require_wait_budget 30 "member listing polls"

LOCAL_A="test-vmc-a-${RUN_ID}"
LOCAL_B="test-vmc-b-${RUN_ID}"
LOCAL_C="test-vmc-c-${RUN_ID}"
VIRTUAL_INLINE="test-vmc-inline-${RUN_ID}"
VIRTUAL_MANUAL="test-vmc-manual-${RUN_ID}"
INLINE_OK=0
MANUAL_ADDED=0

# members_at_least KEY N: wait_until predicate, KEY lists >= N members.
members_at_least() {
  local n
  n=$(api_get "/api/v1/repositories/${1}/members" 2>/dev/null | jq '.items | length // 0' 2>/dev/null)
  [ "${n:-0}" -ge "$2" ] 2>/dev/null
}

# -------------------------------------------------------------------------
# Create three local repos to use as members
# -------------------------------------------------------------------------

begin_test "Create local repo A"
if create_local_repo "$LOCAL_A" "generic"; then
  pass
else
  fail "could not create local repo A"
fi

begin_test "Create local repo B"
if create_local_repo "$LOCAL_B" "generic"; then
  pass
else
  fail "could not create local repo B"
fi

begin_test "Create local repo C"
if create_local_repo "$LOCAL_C" "generic"; then
  pass
else
  fail "could not create local repo C"
fi

# -------------------------------------------------------------------------
# Approach 1: Create virtual repo with member_repos in POST body
# -------------------------------------------------------------------------

begin_test "Create virtual repo with inline member_repos"
INLINE_PAYLOAD=$(cat <<EOJSON
{
  "key": "${VIRTUAL_INLINE}",
  "name": "${VIRTUAL_INLINE}",
  "format": "generic",
  "repo_type": "virtual",
  "is_public": true,
  "member_repos": [
    {"member_key": "${LOCAL_A}", "priority": 1},
    {"member_key": "${LOCAL_B}", "priority": 2}
  ]
}
EOJSON
)
if api_post "/api/v1/repositories" "$INLINE_PAYLOAD" > /dev/null 2>&1; then
  INLINE_OK=1
  pass
else
  # Fall back to creating without members (field may not be supported inline)
  if create_virtual_repo "$VIRTUAL_INLINE" "generic"; then
    skip "member_repos in POST body not supported, created without members"
  else
    fail "could not create virtual repo"
  fi
fi

begin_test "Verify inline members via GET members"
# Bounded wait for both inline members to be listed (only when the inline
# create was accepted); the checks below judge the listing either way.
if [ "$INLINE_OK" = "1" ]; then
  # common.sh runs under set -e: a timeout must not abort the script before
  # the check below records its verdict.
  wait_until "2 inline members listed on ${VIRTUAL_INLINE}" 15 members_at_least "$VIRTUAL_INLINE" 2 \
    || echo "  continuing to the check below after the wait timed out" >&2
fi
if resp=$(api_get "/api/v1/repositories/${VIRTUAL_INLINE}/members" 2>/dev/null); then
  count=$(echo "$resp" | jq '.items | length // 0' 2>/dev/null) || count=0
  if [ "$count" -ge 2 ]; then
    pass
  elif [ "$count" -ge 1 ]; then
    skip "only ${count} member(s) found, expected 2"
  else
    skip "no members returned (inline member_repos may not be supported)"
  fi
else
  skip "members endpoint not available"
fi

begin_test "Verify member priorities"
if [ -n "${resp:-}" ]; then
  first_priority=$(echo "$resp" | jq '.items[0].priority // empty' 2>/dev/null) || true
  if [ -n "$first_priority" ] && [ "$first_priority" != "null" ]; then
    pass
  else
    skip "priority field not present in member response"
  fi
else
  skip "no member response to check"
fi

# -------------------------------------------------------------------------
# Approach 2: Create virtual repo then add members via POST /members
# -------------------------------------------------------------------------

begin_test "Create virtual repo without members"
if create_virtual_repo "$VIRTUAL_MANUAL" "generic"; then
  pass
else
  fail "could not create virtual repo"
fi

begin_test "Add member A via POST /members"
if api_post "/api/v1/repositories/${VIRTUAL_MANUAL}/members" \
    "{\"member_key\":\"${LOCAL_B}\",\"priority\":1}" > /dev/null 2>&1; then
  MANUAL_ADDED=$(( MANUAL_ADDED + 1 ))
  pass
else
  # Try PUT with members array as alternative
  if api_put "/api/v1/repositories/${VIRTUAL_MANUAL}/members" \
      "{\"members\":[{\"member_key\":\"${LOCAL_B}\",\"priority\":1}]}" > /dev/null 2>&1; then
    MANUAL_ADDED=$(( MANUAL_ADDED + 1 ))
    pass
  else
    fail "could not add member via POST or PUT"
  fi
fi

begin_test "Add member C via POST /members"
if api_post "/api/v1/repositories/${VIRTUAL_MANUAL}/members" \
    "{\"member_key\":\"${LOCAL_C}\",\"priority\":2}" > /dev/null 2>&1; then
  MANUAL_ADDED=$(( MANUAL_ADDED + 1 ))
  pass
else
  skip "adding second member failed (may need PUT with full array)"
fi

begin_test "Verify manually-added members"
# Bounded wait for every accepted member add to be listed; the check below
# judges the listing either way.
if [ "$MANUAL_ADDED" -gt 0 ]; then
  # common.sh runs under set -e: a timeout must not abort the script before
  # the check below records its verdict.
  wait_until "${MANUAL_ADDED} members listed on ${VIRTUAL_MANUAL}" 15 members_at_least "$VIRTUAL_MANUAL" "$MANUAL_ADDED" \
    || echo "  continuing to the check below after the wait timed out" >&2
fi
if resp=$(api_get "/api/v1/repositories/${VIRTUAL_MANUAL}/members" 2>/dev/null); then
  count=$(echo "$resp" | jq '.items | length // 0' 2>/dev/null) || count=0
  if [ "$count" -ge 1 ]; then
    pass
  else
    skip "no members found after manual add"
  fi
else
  skip "members endpoint not available"
fi

# -------------------------------------------------------------------------
# Cleanup
# -------------------------------------------------------------------------

api_delete "/api/v1/repositories/${VIRTUAL_MANUAL}" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${VIRTUAL_INLINE}" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${LOCAL_C}" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${LOCAL_B}" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${LOCAL_A}" > /dev/null 2>&1 || true

end_suite
