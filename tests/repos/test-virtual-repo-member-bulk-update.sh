#!/usr/bin/env bash
# test-virtual-repo-member-bulk-update.sh - Bulk priority update on virtual repos
#
# Covers Epic 6 sub-task 6.2 (artifact-keeper-test#70):
#   PUT /api/v1/repositories/:key/members
#   body: { "members": [ { "member_key": "...", "priority": N }, ... ] }
#
# IMPORTANT BACKEND BEHAVIOR (from backend/src/api/handlers/repositories.rs
# `update_virtual_members` -> `set_virtual_members`):
#
#   The PUT handler applies FULL-SET REPLACE semantics. The request body is
#   the complete desired member list: members absent from the body are
#   REMOVED, members present are inserted if new or have their priority
#   updated if existing. Introduced by artifact-keeper/artifact-keeper#2795
#   and ratified as the intended contract in
#   artifact-keeper/artifact-keeper#2899.
#
#   DELETE /:key/members/:member_key remains the single-member removal path
#   (covered by test-virtual-repo-member-remove.sh), but it is no longer the
#   ONLY way to remove a member.
#
#   Replace semantics is asserted directly in
#   test-virtual-members-concurrent-put.sh. This suite deliberately stays
#   scoped to bulk REORDER, and every PUT below sends the complete member set,
#   so its assertions hold identically under either contract: create V with
#   members [A(p=1), B(p=2)], PUT a body that swaps priorities to
#   [A(p=10), B(p=5)], then GET /members and assert ordering reflects the
#   new priorities (members are returned ORDER BY priority ascending, so B
#   should now precede A).
#
# We additionally test that PUT with a member_key that resolves to no
# repository returns 404: the handler resolves every key in the body with
# get_by_key before mutating, so an unknown key fails the whole request and
# leaves membership untouched. Note that under replace semantics a KNOWN but
# non-member key no longer no-ops -- it is inserted as a new member -- which
# is why the unknown-key case below uses a deliberately non-existent key.
#
# Response shape for PUT (mirrors GET): VirtualMembersListResponse
#   { "members": [ { ..., "priority": N, "member_repo_key": "..." }, ... ] }
#
# EXPECT_FAILURE=1 inverts the suite exit code.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "virtual-repo-member-bulk-update"
auth_admin

LOCAL_A="test-vmb-a-${RUN_ID}"
LOCAL_B="test-vmb-b-${RUN_ID}"
VIRTUAL_KEY="test-vmb-virt-${RUN_ID}"
GHOST_KEY="test-vmb-ghost-${RUN_ID}"

# -------------------------------------------------------------------------
# Setup
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

begin_test "Create virtual repo V with members A(p=1), B(p=2)"
# create_virtual_repo adds members via POST without explicit priorities,
# so each gets max+1. To get deterministic starting priorities we add
# A then B in order. The helper uses an explicit POST per member, so
# A ends up at priority 1 and B at priority 2 (matches backend
# add_virtual_member: priority = MAX(existing) + 1, starting from 0).
if create_virtual_repo "$VIRTUAL_KEY" "generic" "${LOCAL_A},${LOCAL_B}"; then
  pass
else
  fail "could not create virtual repo with members"
fi

# Poll until both members are visible (10s budget).
deadline=$(( $(date +%s) + 10 ))
until [ "$(api_get "/api/v1/repositories/${VIRTUAL_KEY}/members" 2>/dev/null | jq '.members | length // 0')" = "2" ] || [ "$(date +%s)" -ge "$deadline" ]; do
  sleep 0.2
done

# -------------------------------------------------------------------------
# 6.2.a: Confirm initial state (A before B by priority).
# -------------------------------------------------------------------------

begin_test "Initial member ordering: A then B"
if BEFORE_RESP=$(api_get "/api/v1/repositories/${VIRTUAL_KEY}/members" 2>/dev/null); then
  count=$(echo "$BEFORE_RESP" | jq '.members | length // 0') || count=0
  first_key=$(echo "$BEFORE_RESP" | jq -r '.members[0].member_repo_key // empty')
  second_key=$(echo "$BEFORE_RESP" | jq -r '.members[1].member_repo_key // empty')
  if [ "$count" -eq 2 ] && [ "$first_key" = "$LOCAL_A" ] && [ "$second_key" = "$LOCAL_B" ]; then
    pass
  else
    fail "expected [A,B] ordering; got count=${count} first='${first_key}' second='${second_key}'"
  fi
else
  fail "could not list members"
fi

# -------------------------------------------------------------------------
# 6.2.b: PUT new priorities that flip the order. Backend orders ascending,
# so giving B a lower priority than A should put B first.
# -------------------------------------------------------------------------

begin_test "PUT bulk update: A=10, B=5 (swap order)"
SWAP_PAYLOAD=$(jq -n \
  --arg a "$LOCAL_A" \
  --arg b "$LOCAL_B" \
  '{members: [
     {member_key: $a, priority: 10},
     {member_key: $b, priority: 5}
   ]}')
if api_put "/api/v1/repositories/${VIRTUAL_KEY}/members" "$SWAP_PAYLOAD" > /dev/null 2>&1; then
  pass
else
  fail "PUT bulk update failed"
fi

begin_test "After swap, ordering is B then A"
# Poll until the swap is reflected: B (lower priority) becomes first row.
deadline=$(( $(date +%s) + 10 ))
until [ "$(api_get "/api/v1/repositories/${VIRTUAL_KEY}/members" 2>/dev/null | jq -r '.members[0].member_repo_key // empty')" = "$LOCAL_B" ] || [ "$(date +%s)" -ge "$deadline" ]; do
  sleep 0.2
done
if AFTER_RESP=$(api_get "/api/v1/repositories/${VIRTUAL_KEY}/members" 2>/dev/null); then
  count=$(echo "$AFTER_RESP" | jq '.members | length // 0') || count=0
  first_key=$(echo "$AFTER_RESP" | jq -r '.members[0].member_repo_key // empty')
  first_pri=$(echo "$AFTER_RESP" | jq -r '.members[0].priority // empty')
  second_key=$(echo "$AFTER_RESP" | jq -r '.members[1].member_repo_key // empty')
  second_pri=$(echo "$AFTER_RESP" | jq -r '.members[1].priority // empty')
  if [ "$count" -eq 2 ] \
      && [ "$first_key" = "$LOCAL_B" ] && [ "$first_pri" = "5" ] \
      && [ "$second_key" = "$LOCAL_A" ] && [ "$second_pri" = "10" ]; then
    pass
  else
    fail "expected B(p=5) then A(p=10); got first=${first_key}(${first_pri}) second=${second_key}(${second_pri})"
  fi
else
  fail "could not list members after PUT"
fi

# -------------------------------------------------------------------------
# 6.2.c: PUT response body itself (the handler returns the refreshed list).
# -------------------------------------------------------------------------

begin_test "PUT response returns updated member list"
NORMALIZE_PAYLOAD=$(jq -n \
  --arg a "$LOCAL_A" \
  --arg b "$LOCAL_B" \
  '{members: [
     {member_key: $a, priority: 1},
     {member_key: $b, priority: 2}
   ]}')
if RESP=$(api_put "/api/v1/repositories/${VIRTUAL_KEY}/members" "$NORMALIZE_PAYLOAD" 2>/dev/null); then
  count=$(echo "$RESP" | jq '.members | length // 0') || count=0
  first_key=$(echo "$RESP" | jq -r '.members[0].member_repo_key // empty')
  first_pri=$(echo "$RESP" | jq -r '.members[0].priority // empty')
  second_key=$(echo "$RESP" | jq -r '.members[1].member_repo_key // empty')
  second_pri=$(echo "$RESP" | jq -r '.members[1].priority // empty')
  if [ "$count" -eq 2 ] \
      && [ "$first_key" = "$LOCAL_A" ] && [ "$first_pri" = "1" ] \
      && [ "$second_key" = "$LOCAL_B" ] && [ "$second_pri" = "2" ]; then
    pass
  else
    fail "PUT response missing refreshed list (count=${count} first=${first_key}(${first_pri}) second=${second_key}(${second_pri}))"
  fi
else
  fail "PUT did not return a body"
fi

# -------------------------------------------------------------------------
# 6.2.f: Strict-shape assertion on PUT /members response.
#
# Issue artifact-keeper-test#92: the test above asserts content (key+priority)
# but not the JSON shape itself. A regression that renamed a field, dropped
# one, or changed nesting would slip past content-only checks. The handler
# returns VirtualMembersListResponse; its element fields (per
# backend/src/api/handlers/repositories.rs:2185-2221) include id (UUID),
# member_repo_key (string), priority (number). This assertion pins those
# names and types so a silent rename breaks the gate loudly.
#
# Reuses RESP from the previous test to avoid a duplicate PUT.
# Gated to v1.2.0 via require_feature so 1.1.9 release-gate runs
# don't pick up this assertion.
# -------------------------------------------------------------------------

begin_test "PUT response body matches VirtualMembersListResponse shape"
if require_feature "virtual_member_strict_contract"; then
  if [ -z "${RESP:-}" ]; then
    fail "RESP not populated by previous PUT-response test"
  else
    members_is_array=$(echo "$RESP" | jq '.members | type == "array"')
    all_keys_string=$(echo "$RESP" | jq '[.members[].member_repo_key | type == "string"] | all')
    all_priorities_number=$(echo "$RESP" | jq '[.members[].priority | type == "number"] | all')
    # UUID v4-ish: 8-4-4-4-12 hex blocks. Tolerant of any v1-v5 hyphenated form.
    uuid_re='^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
    all_ids_uuid=true
    while IFS= read -r id_val; do
      if ! [[ "$id_val" =~ $uuid_re ]]; then
        all_ids_uuid=false
        break
      fi
    done < <(echo "$RESP" | jq -r '.members[].id // empty')
    if [ "$members_is_array" = "true" ] \
        && [ "$all_keys_string" = "true" ] \
        && [ "$all_priorities_number" = "true" ] \
        && [ "$all_ids_uuid" = "true" ]; then
      pass
    else
      fail "shape mismatch: members_array=${members_is_array} keys_string=${all_keys_string} priorities_number=${all_priorities_number} ids_uuid=${all_ids_uuid} (resp head: ${RESP:0:200})"
    fi
  fi
fi

# -------------------------------------------------------------------------
# 6.2.d: PUT with an unknown member_key -> 404 (resolution failure).
#
# update_virtual_members iterates payload.members and calls get_by_key for
# each; an unknown key surfaces as AppError::NotFound -> 404.
# -------------------------------------------------------------------------

begin_test "PUT with unknown member_key returns 404"
BAD_PAYLOAD=$(jq -n \
  --arg ghost "$GHOST_KEY" \
  '{members: [{member_key: $ghost, priority: 1}]}')
BAD_STATUS=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X PUT -H "$(auth_header)" \
  -H "Content-Type: application/json" \
  -d "$BAD_PAYLOAD" \
  "${BASE_URL}/api/v1/repositories/${VIRTUAL_KEY}/members") || BAD_STATUS="000"
assert_eq "$BAD_STATUS" "404" "expected 404 for unknown member_key, got ${BAD_STATUS}" && pass

# -------------------------------------------------------------------------
# 6.2.e: PUT against a non-virtual parent -> 400 (Validation).
# -------------------------------------------------------------------------

begin_test "PUT on non-virtual parent returns 400"
NV_PAYLOAD=$(jq -n \
  --arg a "$LOCAL_A" \
  '{members: [{member_key: $a, priority: 1}]}')
NV_STATUS=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X PUT -H "$(auth_header)" \
  -H "Content-Type: application/json" \
  -d "$NV_PAYLOAD" \
  "${BASE_URL}/api/v1/repositories/${LOCAL_B}/members") || NV_STATUS="000"
# Backend uses AppError::Validation -> 400 deterministically (see
# backend/src/error.rs:91). The HTTP Status Code Guide in tests/lib/common.sh
# explicitly forbids OR-ing codes; assert exact 400.
assert_eq "$NV_STATUS" "400" "expected 400 (Validation) on non-virtual parent, got $NV_STATUS" && pass

# -------------------------------------------------------------------------
# Cleanup
# -------------------------------------------------------------------------

api_delete "/api/v1/repositories/${VIRTUAL_KEY}" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${LOCAL_B}" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${LOCAL_A}" > /dev/null 2>&1 || true

if [ "${EXPECT_FAILURE:-0}" = "1" ]; then
  if ( end_suite ); then
    echo "EXPECT_FAILURE=1 but suite passed; inverting to fail"
    exit 1
  else
    echo "EXPECT_FAILURE=1 and suite failed as expected; inverting to pass"
    exit 0
  fi
fi

end_suite
