#!/usr/bin/env bash
# test-virtual-repo-member-remove.sh - Virtual repo single-member removal
#
# Covers Epic 6 sub-task 6.1 (artifact-keeper-test#70):
#   DELETE /api/v1/repositories/:key/members/:member_key
#
# Scenario:
#   1. Create local repos A and B.
#   2. Create virtual repo V with members [A, B].
#   3. DELETE /V/members/A -> expect 2xx.
#   4. GET /V/members -> assert only B remains (member count == 1, key == B).
#   5. DELETE /V/members/<nonexistent> -> assert 404 from get_by_key on the
#      member resolution (the handler resolves member_key to a repo before
#      removing).
#
# Response shape (from backend repositories.rs / VirtualMembersListResponse):
#   { "members": [ { "id", "member_repo_id", "member_repo_key",
#                    "member_repo_name", "member_repo_type", "priority",
#                    "created_at" }, ... ] }
#
# EXPECT_FAILURE=1 inverts the suite exit code (used by negative-path harness
# runs that want to confirm the suite would have failed under regression).
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "virtual-repo-member-remove"
auth_admin
setup_workdir

LOCAL_A="test-vmr-a-${RUN_ID}"
LOCAL_B="test-vmr-b-${RUN_ID}"
VIRTUAL_KEY="test-vmr-virt-${RUN_ID}"
GHOST_KEY="test-vmr-ghost-${RUN_ID}"

# -------------------------------------------------------------------------
# Setup: two local member repos plus the virtual repo wrapping them.
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

begin_test "Create virtual repo V with members A,B"
if create_virtual_repo "$VIRTUAL_KEY" "generic" "${LOCAL_A},${LOCAL_B}"; then
  pass
else
  fail "could not create virtual repo with members"
fi

# Settle briefly: create_virtual_repo POSTs members in sequence; allow the
# database transaction to commit before the next read.
sleep 1

begin_test "Confirm V has 2 members before removal"
INIT_RESP=""
if INIT_RESP=$(api_get "/api/v1/repositories/${VIRTUAL_KEY}/members" 2>/dev/null); then
  init_count=$(echo "$INIT_RESP" | jq '.members | length // 0' 2>/dev/null) || init_count=0
  if [ "$init_count" -eq 2 ]; then
    pass
  else
    fail "expected 2 members, got ${init_count} (response: ${INIT_RESP:0:200})"
  fi
else
  fail "could not list members before removal"
fi

# -------------------------------------------------------------------------
# 6.1.a: DELETE single member by key.
# -------------------------------------------------------------------------

begin_test "DELETE /V/members/A succeeds"
DEL_STATUS=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X DELETE -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${VIRTUAL_KEY}/members/${LOCAL_A}") || DEL_STATUS="000"
if assert_http_2xx "$DEL_STATUS" "DELETE member A returned non-2xx"; then
  pass
fi

begin_test "After delete, only B remains in V"
sleep 1
if AFTER_RESP=$(api_get "/api/v1/repositories/${VIRTUAL_KEY}/members" 2>/dev/null); then
  after_count=$(echo "$AFTER_RESP" | jq '.members | length // 0' 2>/dev/null) || after_count=0
  remaining_key=$(echo "$AFTER_RESP" | jq -r '.members[0].member_repo_key // empty' 2>/dev/null)
  if [ "$after_count" -eq 1 ] && [ "$remaining_key" = "$LOCAL_B" ]; then
    pass
  else
    fail "expected 1 member (${LOCAL_B}), got count=${after_count} key='${remaining_key}'"
  fi
else
  fail "could not list members after removal"
fi

# -------------------------------------------------------------------------
# 6.1.b: DELETE non-existent member -> 404.
#
# remove_virtual_member calls service.get_by_key(&member_key) before any
# delete query, which returns AppError::NotFound -> HTTP 404.
# -------------------------------------------------------------------------

begin_test "DELETE non-existent member returns 404"
GHOST_STATUS=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X DELETE -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${VIRTUAL_KEY}/members/${GHOST_KEY}") || GHOST_STATUS="000"
assert_eq "$GHOST_STATUS" "404" "expected 404 for non-existent member, got ${GHOST_STATUS}" && pass

# -------------------------------------------------------------------------
# 6.1.c: DELETE on a non-virtual repo (member of a virtual is fine, but
# calling /<local>/members/<x> should not delete from a real virtual).
# remove_virtual_member returns 400 (Validation) when the parent isn't
# virtual.
# -------------------------------------------------------------------------

begin_test "DELETE member on non-virtual parent returns 400"
NV_STATUS=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X DELETE -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${LOCAL_B}/members/${LOCAL_A}") || NV_STATUS="000"
# Backend uses AppError::Validation -> 400. Some older builds returned 422
# from the same code path; accept either deterministic 4xx but flag the
# exact code so a regression to 500 fails loudly.
case "$NV_STATUS" in
  400|422) pass ;;
  *) fail "expected 400/422 on non-virtual parent, got ${NV_STATUS}" ;;
esac

# -------------------------------------------------------------------------
# Cleanup
# -------------------------------------------------------------------------

api_delete "/api/v1/repositories/${VIRTUAL_KEY}" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${LOCAL_B}" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${LOCAL_A}" > /dev/null 2>&1 || true

# -------------------------------------------------------------------------
# EXPECT_FAILURE handling: invert the suite exit so a known-broken backend
# can run this script and confirm the failure is the one we expect.
# -------------------------------------------------------------------------

if [ "${EXPECT_FAILURE:-0}" = "1" ]; then
  # end_suite calls exit; capture by running it in a subshell and inverting.
  if ( end_suite ); then
    echo "EXPECT_FAILURE=1 but suite passed; inverting to fail"
    exit 1
  else
    echo "EXPECT_FAILURE=1 and suite failed as expected; inverting to pass"
    exit 0
  fi
fi

end_suite
