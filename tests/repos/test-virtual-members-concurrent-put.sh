#!/usr/bin/env bash
# test-virtual-members-concurrent-put.sh - Race test for update_virtual_members
#
# Covers artifact-keeper-test#96.
#
# RACE UNDER TEST
# ---------------
# Backend handler `update_virtual_members` (artifact-keeper/backend/src/api/
# handlers/repositories.rs:2238) loops over the payload's members and issues
# a separate `UPDATE virtual_repo_members SET priority = ...` per row. The
# loop is NOT wrapped in a transaction, and each row's resolution
# (`service.get_by_key(...)`) is also outside any shared transactional
# boundary.
#
# That means two concurrent PUTs against the same virtual repo can interleave
# their UPDATE statements at the row level. The contract the handler tries
# to expose ("set members to this list with these priorities") therefore
# doesn't hold atomically: with overlapping member sets, intermediate
# priorities from one writer can be observed and overwritten by the other
# in non-deterministic order.
#
# Note that backend PR #1222 added transaction wrappers to
# `add_virtual_member` (single-row add path). The bulk PUT path
# (`update_virtual_members`) was not modified by that PR and remains the
# subject of this test.
#
# WHAT THIS TEST EXERCISES
# ------------------------
# 1. Create virtual repo V with three existing members A, B, C. The PUT
#    handler ONLY updates priorities on existing members (see
#    test-virtual-repo-member-bulk-update.sh for the contract note), so we
#    pre-add all three before racing.
# 2. Fire two PUT /api/v1/repositories/V/members calls in parallel:
#       Writer 1: A=10,  B=20
#       Writer 2: B=200, C=300
#    Row B is the contested row; rows A and C are touched by exactly one
#    writer each.
# 3. Wait for both to finish.
#
# ASSERTIONS
# ----------
# We assert the WEAK contract that the current handler does provide:
#
#   a. Neither call returns 5xx. A 500 here would indicate the race
#      corrupted handler state (panic, broken connection pool entry, etc.),
#      which is what the bead is most worried about.
#   b. Both calls return 200. The handler holds no locks, so both should
#      independently succeed.
#   c. After both finish, V still has exactly 3 members (no row was lost).
#      The PUT path does not delete rows, so this is a hard invariant
#      regardless of interleaving.
#   d. Row A's final priority is 10 (only writer 1 touched it).
#   e. Row C's final priority is 300 (only writer 2 touched it).
#   f. Row B's final priority is one of {20, 200}. With the current
#      non-transactional handler this is a "last writer wins per row"
#      observation, NOT a stronger atomicity guarantee. We document this
#      as a known gap below.
#
# KNOWN GAP / FUTURE WORK
# -----------------------
# Once the backend wraps the loop in a single transaction, a stronger
# assertion becomes meaningful: the final state should match exactly one
# of the two writers' payloads for the contested rows (i.e., (B=20) and
# (B=200) wouldn't both be observable across rows in mixed combinations).
# Today the handler can produce per-row interleaving because each UPDATE
# is its own implicit transaction. This test deliberately stops short of
# asserting full payload atomicity to avoid flaking; tightening the
# assertion is gated on the backend transaction fix.
#
# EXPECT_FAILURE=1 inverts the suite exit code (used by self-tests).
#
# Requires: curl, jq

source "$(dirname "$0")/../lib/common.sh"

begin_suite "virtual-members-concurrent-put"
auth_admin
setup_workdir

LOCAL_A="test-vmcp-a-${RUN_ID}"
LOCAL_B="test-vmcp-b-${RUN_ID}"
LOCAL_C="test-vmcp-c-${RUN_ID}"
VIRTUAL_KEY="test-vmcp-virt-${RUN_ID}"

# ---------------------------------------------------------------------------
# Setup: three local members + virtual repo containing all three.
# ---------------------------------------------------------------------------

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

begin_test "Create virtual repo V with members A, B, C"
if create_virtual_repo "$VIRTUAL_KEY" "generic" "${LOCAL_A},${LOCAL_B},${LOCAL_C}"; then
  pass
else
  fail "could not create virtual repo with members"
fi

# Poll until all three members are visible (10s budget). Tests that follow
# assume V already has A, B, C as existing members.
deadline=$(( $(date +%s) + 10 ))
until [ "$(api_get "/api/v1/repositories/${VIRTUAL_KEY}/members" 2>/dev/null | jq '.members | length // 0')" = "3" ] || [ "$(date +%s)" -ge "$deadline" ]; do
  sleep 0.2
done

begin_test "Pre-race: V has 3 members"
if PRE_RESP=$(api_get "/api/v1/repositories/${VIRTUAL_KEY}/members" 2>/dev/null); then
  pre_count=$(echo "$PRE_RESP" | jq '.members | length // 0') || pre_count=0
  if [ "$pre_count" -eq 3 ]; then
    pass
  else
    fail "expected 3 members before race, got ${pre_count}"
  fi
else
  fail "could not list members before race"
fi

# ---------------------------------------------------------------------------
# Race: two concurrent PUTs. Writer 1 targets {A=10, B=20},
# writer 2 targets {B=200, C=300}. Row B is contested.
# ---------------------------------------------------------------------------

PAYLOAD_1=$(jq -n \
  --arg a "$LOCAL_A" \
  --arg b "$LOCAL_B" \
  '{members: [
     {member_key: $a, priority: 10},
     {member_key: $b, priority: 20}
   ]}')

PAYLOAD_2=$(jq -n \
  --arg b "$LOCAL_B" \
  --arg c "$LOCAL_C" \
  '{members: [
     {member_key: $b, priority: 200},
     {member_key: $c, priority: 300}
   ]}')

OUT_1="${WORK_DIR:-/tmp}/vmcp-writer1-${RUN_ID}.out"
OUT_2="${WORK_DIR:-/tmp}/vmcp-writer2-${RUN_ID}.out"
STATUS_1_FILE="${WORK_DIR:-/tmp}/vmcp-writer1-${RUN_ID}.status"
STATUS_2_FILE="${WORK_DIR:-/tmp}/vmcp-writer2-${RUN_ID}.status"

# We use raw curl (not api_put / api_post) so we can capture the HTTP status
# code for each concurrent call independently. api_put uses `curl -sf` which
# discards the body on non-2xx and only returns a shell exit code, which
# would hide a 500 vs a non-200 distinction we care about here.
run_writer() {
  local payload="$1"
  local body_out="$2"
  local status_out="$3"
  local status
  status=$(curl -s -o "$body_out" -w '%{http_code}' $CURL_TIMEOUT \
    -X PUT \
    -H "$(auth_header)" \
    -H "Content-Type: application/json" \
    -d "$payload" \
    "${BASE_URL}/api/v1/repositories/${VIRTUAL_KEY}/members" 2>/dev/null) || status="000"
  printf '%s' "$status" > "$status_out"
}

begin_test "Fire two concurrent PUTs against /members"
run_writer "$PAYLOAD_1" "$OUT_1" "$STATUS_1_FILE" &
PID_1=$!
run_writer "$PAYLOAD_2" "$OUT_2" "$STATUS_2_FILE" &
PID_2=$!

wait "$PID_1"; rc_1=$?
wait "$PID_2"; rc_2=$?

if [ "$rc_1" -eq 0 ] && [ "$rc_2" -eq 0 ]; then
  pass
else
  fail "concurrent writers exited non-zero (rc1=${rc_1} rc2=${rc_2})"
fi

STATUS_1=$(cat "$STATUS_1_FILE" 2>/dev/null || echo "000")
STATUS_2=$(cat "$STATUS_2_FILE" 2>/dev/null || echo "000")

# ---------------------------------------------------------------------------
# Assertion (a): neither call returned a 5xx.
# ---------------------------------------------------------------------------

begin_test "Writer 1 did not return 5xx"
if [ "$STATUS_1" -lt 500 ] 2>/dev/null && [ "$STATUS_1" -ge 100 ] 2>/dev/null; then
  pass
else
  fail "writer 1 status was ${STATUS_1} (body: $(head -c 200 "$OUT_1" 2>/dev/null))"
fi

begin_test "Writer 2 did not return 5xx"
if [ "$STATUS_2" -lt 500 ] 2>/dev/null && [ "$STATUS_2" -ge 100 ] 2>/dev/null; then
  pass
else
  fail "writer 2 status was ${STATUS_2} (body: $(head -c 200 "$OUT_2" 2>/dev/null))"
fi

# ---------------------------------------------------------------------------
# Assertion (b): both calls returned 200.
# ---------------------------------------------------------------------------

begin_test "Writer 1 returned 200"
assert_eq "$STATUS_1" "200" "expected writer 1 -> 200, got ${STATUS_1}" && pass

begin_test "Writer 2 returned 200"
assert_eq "$STATUS_2" "200" "expected writer 2 -> 200, got ${STATUS_2}" && pass

# ---------------------------------------------------------------------------
# Assertion (c): V still has all 3 members after the race.
# ---------------------------------------------------------------------------

begin_test "Post-race: V still has 3 members (no lost rows)"
# Small settle window: each writer's UPDATEs auto-commit per row, so by the
# time both curl calls return their bodies the rows should be visible. We
# still poll briefly to absorb any replication lag in non-trivial setups.
deadline=$(( $(date +%s) + 5 ))
until [ "$(api_get "/api/v1/repositories/${VIRTUAL_KEY}/members" 2>/dev/null | jq '.members | length // 0')" = "3" ] || [ "$(date +%s)" -ge "$deadline" ]; do
  sleep 0.2
done
if POST_RESP=$(api_get "/api/v1/repositories/${VIRTUAL_KEY}/members" 2>/dev/null); then
  post_count=$(echo "$POST_RESP" | jq '.members | length // 0') || post_count=0
  if [ "$post_count" -eq 3 ]; then
    pass
  else
    fail "expected 3 members after race, got ${post_count}; body: $(echo "$POST_RESP" | head -c 300)"
  fi
else
  fail "could not list members after race"
fi

# ---------------------------------------------------------------------------
# Assertions (d), (e): uncontested rows have the writer's priority.
# Row A is only written by writer 1 (-> 10). Row C is only written by
# writer 2 (-> 300).
# ---------------------------------------------------------------------------

begin_test "Row A has final priority 10 (uncontested, writer 1 only)"
a_pri=$(echo "${POST_RESP:-{}}" | jq -r --arg k "$LOCAL_A" '.members[] | select(.member_repo_key == $k) | .priority // empty')
if [ "$a_pri" = "10" ]; then
  pass
else
  fail "expected A.priority=10, got '${a_pri}'"
fi

begin_test "Row C has final priority 300 (uncontested, writer 2 only)"
c_pri=$(echo "${POST_RESP:-{}}" | jq -r --arg k "$LOCAL_C" '.members[] | select(.member_repo_key == $k) | .priority // empty')
if [ "$c_pri" = "300" ]; then
  pass
else
  fail "expected C.priority=300, got '${c_pri}'"
fi

# ---------------------------------------------------------------------------
# Assertion (f): row B (contested) has a priority from one of the two
# writers. We do NOT assert which one wins; that is the documented
# non-determinism the bead calls out.
# ---------------------------------------------------------------------------

begin_test "Row B has priority 20 or 200 (contested, last-writer-wins per row)"
b_pri=$(echo "${POST_RESP:-{}}" | jq -r --arg k "$LOCAL_B" '.members[] | select(.member_repo_key == $k) | .priority // empty')
if [ "$b_pri" = "20" ] || [ "$b_pri" = "200" ]; then
  pass
  echo "  observed B.priority=${b_pri} (either value is acceptable under current backend)"
else
  fail "expected B.priority in {20,200}, got '${b_pri}' (race may have corrupted row)"
fi

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

api_delete "/api/v1/repositories/${VIRTUAL_KEY}" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${LOCAL_C}" > /dev/null 2>&1 || true
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
