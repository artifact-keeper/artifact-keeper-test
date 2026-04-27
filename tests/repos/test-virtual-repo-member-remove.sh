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

# Settle: create_virtual_repo POSTs members in sequence; poll until both
# rows are visible (10s budget) instead of a fixed sleep.
deadline=$(( $(date +%s) + 10 ))
until [ "$(api_get "/api/v1/repositories/${VIRTUAL_KEY}/members" 2>/dev/null | jq '.members | length // 0')" = "2" ] || [ "$(date +%s)" -ge "$deadline" ]; do
  sleep 0.2
done

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
assert_http_2xx "$DEL_STATUS" "DELETE member A returned non-2xx" && pass

begin_test "After delete, only B remains in V"
# Poll for the delete to be visible to subsequent reads.
deadline=$(( $(date +%s) + 10 ))
until [ "$(api_get "/api/v1/repositories/${VIRTUAL_KEY}/members" 2>/dev/null | jq '.members | length // 0')" = "1" ] || [ "$(date +%s)" -ge "$deadline" ]; do
  sleep 0.2
done
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
# Backend uses AppError::Validation -> 400 deterministically (see
# backend/src/error.rs:91). The HTTP Status Code Guide in tests/lib/common.sh
# explicitly forbids OR-ing codes; assert exact 400.
assert_eq "$NV_STATUS" "400" "expected 400 (Validation) on non-virtual parent, got $NV_STATUS" && pass

# -------------------------------------------------------------------------
# 6.1.d: Cascade on local-repo delete (closes ak-wlib).
#
# Migration backend/migrations/003_repositories.sql defines:
#   member_repo_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE
# Deleting a local repo must therefore cascade-remove its rows in
# virtual_repo_members. User-visible failure mode if it doesn't:
# revoking a local repo silently degrades unrelated virtual aggregates.
#
# Uses a fresh set of repos (suffixed -casc-) to avoid colliding with
# the LOCAL_A/LOCAL_B/VIRTUAL_KEY state mutated by 6.1.a/b/c above.
# -------------------------------------------------------------------------

LOCAL_C="test-vmr-cascade-c-${RUN_ID}"
LOCAL_D="test-vmr-cascade-d-${RUN_ID}"
VIRTUAL_W="test-vmr-cascade-w-${RUN_ID}"

begin_test "Cascade setup: create local repo C"
if create_local_repo "$LOCAL_C" "generic"; then
  pass
else
  fail "could not create local repo C"
fi

begin_test "Cascade setup: create local repo D"
if create_local_repo "$LOCAL_D" "generic"; then
  pass
else
  fail "could not create local repo D"
fi

begin_test "Cascade setup: create virtual repo W with members C,D"
if create_virtual_repo "$VIRTUAL_W" "generic" "${LOCAL_C},${LOCAL_D}"; then
  pass
else
  fail "could not create virtual repo W with members"
fi

# Settle: poll for both members to be visible (same pattern as 6.1.a setup).
deadline=$(( $(date +%s) + 10 ))
until [ "$(api_get "/api/v1/repositories/${VIRTUAL_W}/members" 2>/dev/null | jq '.members | length // 0')" = "2" ] || [ "$(date +%s)" -ge "$deadline" ]; do
  sleep 0.2
done

begin_test "Cascade precondition: W has 2 members"
if W_PRE=$(api_get "/api/v1/repositories/${VIRTUAL_W}/members" 2>/dev/null); then
  w_pre_count=$(echo "$W_PRE" | jq '.members | length // 0' 2>/dev/null) || w_pre_count=0
  if [ "$w_pre_count" -eq 2 ]; then
    pass
  else
    fail "expected 2 members in W, got ${w_pre_count} (response: ${W_PRE:0:200})"
  fi
else
  fail "could not list W members before cascade delete"
fi

# Delete the local repo C directly (NOT via /W/members/C). The FK cascade
# should remove the row from virtual_repo_members on its own.
begin_test "DELETE /api/v1/repositories/C succeeds"
DEL_C_STATUS=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X DELETE -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${LOCAL_C}") || DEL_C_STATUS="000"
assert_http_2xx "$DEL_C_STATUS" "DELETE local repo C returned non-2xx" && pass

begin_test "After cascade, W has 1 member (D)"
# Poll for the cascade to be visible to subsequent reads.
deadline=$(( $(date +%s) + 10 ))
until [ "$(api_get "/api/v1/repositories/${VIRTUAL_W}/members" 2>/dev/null | jq '.members | length // 0')" = "1" ] || [ "$(date +%s)" -ge "$deadline" ]; do
  sleep 0.2
done
if W_POST=$(api_get "/api/v1/repositories/${VIRTUAL_W}/members" 2>/dev/null); then
  w_post_count=$(echo "$W_POST" | jq '.members | length // 0' 2>/dev/null) || w_post_count=0
  remaining_w_key=$(echo "$W_POST" | jq -r '.members[0].member_repo_key // empty' 2>/dev/null)
  if [ "$w_post_count" -eq 1 ] && [ "$remaining_w_key" = "$LOCAL_D" ]; then
    pass
  else
    fail "expected 1 member (${LOCAL_D}) after cascade, got count=${w_post_count} key='${remaining_w_key}'"
  fi
else
  fail "could not list W members after cascade delete"
fi

# -------------------------------------------------------------------------
# Cleanup
# -------------------------------------------------------------------------

api_delete "/api/v1/repositories/${VIRTUAL_W}" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${LOCAL_D}" > /dev/null 2>&1 || true
# LOCAL_C already deleted by the cascade test above; tolerate 404 here.
api_delete "/api/v1/repositories/${LOCAL_C}" > /dev/null 2>&1 || true
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
