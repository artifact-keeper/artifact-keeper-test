#!/usr/bin/env bash
# test-virtual-members-concurrent-put.sh - Race test for update_virtual_members
#
# Covers artifact-keeper-test#96.
#
# RACE UNDER TEST
# ---------------
# Backend handler `update_virtual_members` (artifact-keeper/backend/src/api/
# handlers/repositories.rs:2185) loops over the payload's members and issues
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
# Postgres row-level locking on individual UPDATE statements guarantees the
# committed value of any single row is one of the bound literals from one
# of the two writers; no torn writes are possible. Hence the exhaustive
# assertion for the contested row B is `B in {20, 200}` given the current
# non-transactional handler. Mixed-row combinations across writers are
# possible today (e.g. A from writer 1, B from writer 1, C from writer 2
# OR A from writer 1, B from writer 2, C from writer 2) which is the
# precise gap a transaction would close.
#
# WHAT THIS TEST EXERCISES
# ------------------------
# 1. Create virtual repo V with three existing members A, B, C. The PUT
#    handler ONLY updates priorities on existing members (see
#    test-virtual-repo-member-bulk-update.sh for the contract note), so we
#    pre-add all three before racing.
# 2. For each of N iterations:
#    a. Reset row B to a known starting sentinel via a setup PUT.
#    b. Use a shell barrier so curl/TLS setup cost is paid before the
#       race window opens.
#    c. Fire two PUT /api/v1/repositories/V/members calls in parallel:
#          Writer 1: A=10,  B=20
#          Writer 2: B=200, C=300
#       Row B is the contested row; rows A and C are touched by exactly
#       one writer each.
#    d. Wait for both to finish and assert.
# 3. The cumulative race window across iterations widens the probability
#    of observable interleaving on a fast localhost backend, where a
#    single PUT completes in single-digit milliseconds.
#
# ASSERTIONS (per iteration)
# --------------------------
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
#      observation, NOT a stronger atomicity guarantee.
#
# KNOWN GAP / TRACKING ISSUE
# --------------------------
# CONTRACT SUPERSEDED: everything below assumes the pre-#2795 partial-update
# PUT semantics. Backend PR artifact-keeper#2795 changed PUT /:key/members to
# full-set replace, which invalidates these invariants (see the contract gate
# near begin_suite). The suite is gated off on current backends pending the
# replace-semantics decision in artifact-keeper#2899; the notes below are
# retained as the historical rationale for the partial-update assertions.
#
# Once the backend wraps the loop in a single transaction, a stronger
# assertion becomes meaningful: the final state across A, B, C should
# match exactly one writer's payload semantics for the contested rows.
# This test deliberately stops short of asserting full payload atomicity
# to avoid flaking; tightening the assertion is gated on the backend
# transaction fix tracked at:
#
#   artifact-keeper/artifact-keeper#1233
#   "Wrap update_virtual_members loop in transaction (#96 follow-up)"
#
# When that lands, ratchet assertion (f) to a per-writer atomicity check.
#
# EXPECT_FAILURE=1 inverts the suite exit code (used by self-tests).
#
# Requires: curl, jq

source "$(dirname "$0")/../lib/common.sh"

begin_suite "virtual-members-concurrent-put"
auth_admin
setup_workdir

# ---------------------------------------------------------------------------
# Contract gate (artifact-keeper#2899).
#
# This suite was written against the PRE-#2795 PARTIAL-UPDATE PUT semantics:
# PUT /:key/members updated priorities on the listed existing members and left
# unlisted members untouched. That is what makes the race meaningful (two
# writers touch an overlapping member set) and what every invariant below
# assumes: V keeps all 3 members, the uncontested rows A=10 and C=300 survive,
# and the per-iteration reset PUT sets only row B without dropping A and C.
#
# Backend PR artifact-keeper#2795 changed PUT /:key/members to FULL-SET REPLACE:
# the request body becomes the complete member set. Under replace, writer 1's
# {A,B} body drops C, writer 2's {B,C} body drops A, and the reset-B-only setup
# PUT would drop A and C entirely, so none of these invariants hold and the race
# harness itself is invalid. The correct replace-semantics assertions (and
# whether the update loop should be atomic at all) are the subject of the
# semantics decision tracked in artifact-keeper#2899.
#
# Gate the whole suite behind virtual_member_partial_update_contract, a flag
# that is enabled ONLY for 1.1.x / 1.2.x-era backends (see feature-flags.sh:
# it lives in the 1.1.x and 1.2.x bundles, NOT main). The release-gate workflow
# derives AK_BACKEND_BRANCH from the backend tag: a 1.1.x tag maps to
# release/1.1.x, a 1.2.x tag to release/1.2.x, and EVERYTHING ELSE (every 1.3+
# tag, including 1.6.3) maps to 'main'. main-bundle backends already have the
# #2795 replace semantics, so the flag is absent there and this suite auto-skips
# on all current gates, running only against 1.1.x / 1.2.x-era backends where
# the partial-update contract actually held.
#
# (virtual_member_strict_contract, used by the sibling shape-assertion test, is
# the WRONG flag here: it is additive/present-from-1.2.0-onward, so it is
# enabled on main and would let this suite run its obsolete assertions and fail.)
#
# The 5xx / non-200 checks are not cleanly separable from the partial-update
# reset+race harness, so the entire suite is gated rather than a subset of it.
# The replacement assertions for replace semantics are pending
# artifact-keeper#2899.
begin_test "Backend supports the partial-update virtual-member contract"
if require_feature "virtual_member_partial_update_contract"; then
  pass
else
  end_suite
  exit 0
fi

LOCAL_A="test-vmcp-a-${RUN_ID}"
LOCAL_B="test-vmcp-b-${RUN_ID}"
LOCAL_C="test-vmcp-c-${RUN_ID}"
VIRTUAL_KEY="test-vmcp-virt-${RUN_ID}"

# Number of race iterations. 50 iterations at ~50ms each is ~2.5s for the
# race phase, well under the 90s total budget. Tune up if local timing
# leaves the race phase narrow.
RACE_ITERATIONS="${RACE_ITERATIONS:-50}"

# ---------------------------------------------------------------------------
# Setup: three local members + virtual repo containing all three.
# Cleanup for each repo is registered with add_exit_handler immediately
# after creation so an assertion failure mid-test does not leak repos.
# ---------------------------------------------------------------------------

begin_test "Create local repo A"
if create_local_repo "$LOCAL_A" "generic"; then
  add_exit_handler "api_delete \"/api/v1/repositories/${LOCAL_A}\" >/dev/null 2>&1 || true"
  pass
else
  fail "could not create local repo A"
fi

begin_test "Create local repo B"
if create_local_repo "$LOCAL_B" "generic"; then
  add_exit_handler "api_delete \"/api/v1/repositories/${LOCAL_B}\" >/dev/null 2>&1 || true"
  pass
else
  fail "could not create local repo B"
fi

begin_test "Create local repo C"
if create_local_repo "$LOCAL_C" "generic"; then
  add_exit_handler "api_delete \"/api/v1/repositories/${LOCAL_C}\" >/dev/null 2>&1 || true"
  pass
else
  fail "could not create local repo C"
fi

begin_test "Create virtual repo V with members A, B, C"
if create_virtual_repo "$VIRTUAL_KEY" "generic" "${LOCAL_A},${LOCAL_B},${LOCAL_C}"; then
  add_exit_handler "api_delete \"/api/v1/repositories/${VIRTUAL_KEY}\" >/dev/null 2>&1 || true"
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
# Race payloads. Writer 1 targets {A=10, B=20}, writer 2 targets
# {B=200, C=300}. Row B is contested. Row B is reset to a sentinel
# priority of 1 between iterations so we observe a true race each time
# rather than measuring whatever residue the previous iteration left.
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

RESET_PAYLOAD=$(jq -n \
  --arg b "$LOCAL_B" \
  '{members: [
     {member_key: $b, priority: 1}
   ]}')

# We use raw curl (not api_put / api_post) so we can capture the HTTP status
# code for each concurrent call independently. api_put uses `curl -sf` which
# discards the body on non-2xx and only returns a shell exit code, which
# would hide a 500 vs a non-200 distinction we care about here.
#
# Barrier mechanism: each iteration creates a named pipe (FIFO). Each
# writer opens the FIFO for reading and blocks on `read` until the
# parent writes a release byte. This pays the fork + bash startup cost
# before the race window opens; the two curl invocations then leave
# the starting line within microseconds of each other.
run_writer() {
  local payload="$1"
  local body_out="$2"
  local status_out="$3"
  local barrier="$4"
  local status
  # Block until the parent writes the release byte to the FIFO.
  read -r _barrier_byte < "$barrier" || true
  status=$(curl -s -o "$body_out" -w '%{http_code}' $CURL_TIMEOUT \
    -X PUT \
    -H "$(auth_header)" \
    -H "Content-Type: application/json" \
    -d "$payload" \
    "${BASE_URL}/api/v1/repositories/${VIRTUAL_KEY}/members" 2>/dev/null) || status="000"
  printf '%s' "$status" > "$status_out"
}

# Aggregated outcomes across iterations. We assert at the end so the
# suite reports per-aspect pass/fail (rather than one pass per iteration
# which would dominate the test count).
total_iters=0
race_writer_nonzero_rc=0
race_5xx=0
race_non200=0
race_lost_rows=0
race_a_wrong=0
race_c_wrong=0
race_b_out_of_set=0
race_b_observed_20=0
race_b_observed_200=0
last_failure_detail=""

iter=1
while [ "$iter" -le "$RACE_ITERATIONS" ]; do
  total_iters=$iter

  # Reset row B to sentinel via a setup PUT. This setup PUT is sequential
  # and is NOT part of the race. If the reset itself fails we record it
  # and skip the iteration's race rather than asserting on stale state.
  reset_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X PUT \
    -H "$(auth_header)" \
    -H "Content-Type: application/json" \
    -d "$RESET_PAYLOAD" \
    "${BASE_URL}/api/v1/repositories/${VIRTUAL_KEY}/members" 2>/dev/null) || reset_status="000"
  if [ "$reset_status" != "200" ]; then
    last_failure_detail="iter ${iter}: reset PUT returned ${reset_status}"
    race_writer_nonzero_rc=$((race_writer_nonzero_rc + 1))
    iter=$((iter + 1))
    continue
  fi

  OUT_1="${WORK_DIR:-/tmp}/vmcp-writer1-${RUN_ID}-${iter}.out"
  OUT_2="${WORK_DIR:-/tmp}/vmcp-writer2-${RUN_ID}-${iter}.out"
  STATUS_1_FILE="${WORK_DIR:-/tmp}/vmcp-writer1-${RUN_ID}-${iter}.status"
  STATUS_2_FILE="${WORK_DIR:-/tmp}/vmcp-writer2-${RUN_ID}-${iter}.status"
  BARRIER_FIFO="${WORK_DIR:-/tmp}/vmcp-barrier-${RUN_ID}-${iter}.fifo"

  # Create a fresh FIFO for the iteration's barrier. Remove first in
  # case a previous aborted iteration left one behind.
  rm -f "$BARRIER_FIFO"
  if ! mkfifo "$BARRIER_FIFO" 2>/dev/null; then
    last_failure_detail="iter ${iter}: mkfifo failed"
    race_writer_nonzero_rc=$((race_writer_nonzero_rc + 1))
    iter=$((iter + 1))
    continue
  fi

  # Hold the FIFO open on fd 8 in the parent. We MUST open it read-write
  # (`<>`), not write-only (`>`).
  #
  # A write-only open of a FIFO blocks until a reader attaches (POSIX
  # O_WRONLY semantics, observed on both Linux ARC runners and macOS). The
  # two reader children are forked AFTER this line, so a write-only open
  # here deadlocks: the parent waits for a reader that can never be created
  # because the parent never reaches the fork. That is the exit-124 hang
  # this suite was tripping in release-gate (cycle-1's backend advisory lock
  # did not and could not fix it; the hang is entirely client-side -- no
  # PUT is ever issued, the backend sees zero traffic for the iteration).
  #
  # Opening read-write never blocks (there is always a reader: ourselves),
  # so the parent proceeds to fork the writers immediately. Because fd 8
  # keeps a read end open, closing the write end does NOT produce EOF, so
  # we release the writers by WRITING one byte per writer instead of
  # relying on EOF.
  exec 8<>"$BARRIER_FIFO"

  run_writer "$PAYLOAD_1" "$OUT_1" "$STATUS_1_FILE" "$BARRIER_FIFO" &
  PID_1=$!
  run_writer "$PAYLOAD_2" "$OUT_2" "$STATUS_2_FILE" "$BARRIER_FIFO" &
  PID_2=$!

  # Give the two writers a moment to fork, exec bash, and reach their
  # `read < $BARRIER_FIFO` barrier. 50ms is generous: bash startup is
  # typically ~5ms.
  sleep 0.05

  # Release the barrier: write exactly one byte per blocked reader. Both
  # children's `read` return near-simultaneously and proceed to issue their
  # PUT. Then close fd 8 (drops both the read and write ends we hold).
  printf 'g\ng\n' >&8
  exec 8>&-

  wait "$PID_1"; rc_1=$?
  wait "$PID_2"; rc_2=$?
  rm -f "$BARRIER_FIFO"

  if [ "$rc_1" -ne 0 ] || [ "$rc_2" -ne 0 ]; then
    race_writer_nonzero_rc=$((race_writer_nonzero_rc + 1))
    last_failure_detail="iter ${iter}: writer rc1=${rc_1} rc2=${rc_2}"
    iter=$((iter + 1))
    continue
  fi

  STATUS_1=$(cat "$STATUS_1_FILE" 2>/dev/null || echo "000")
  STATUS_2=$(cat "$STATUS_2_FILE" 2>/dev/null || echo "000")

  # Check 5xx.
  if [ "$STATUS_1" -ge 500 ] 2>/dev/null || [ "$STATUS_2" -ge 500 ] 2>/dev/null; then
    race_5xx=$((race_5xx + 1))
    last_failure_detail="iter ${iter}: 5xx status w1=${STATUS_1} w2=${STATUS_2}"
  fi
  # Check non-200.
  if [ "$STATUS_1" != "200" ] || [ "$STATUS_2" != "200" ]; then
    race_non200=$((race_non200 + 1))
    last_failure_detail="iter ${iter}: non-200 status w1=${STATUS_1} w2=${STATUS_2}"
  fi

  # Per-iteration post check. Short settle window because each UPDATE
  # auto-commits per row.
  post_resp=$(api_get "/api/v1/repositories/${VIRTUAL_KEY}/members" 2>/dev/null || echo "{}")
  post_count=$(echo "$post_resp" | jq '.members | length // 0' 2>/dev/null || echo "0")
  if [ "$post_count" != "3" ]; then
    race_lost_rows=$((race_lost_rows + 1))
    last_failure_detail="iter ${iter}: expected 3 members, got ${post_count}"
  fi
  a_pri=$(echo "$post_resp" | jq -r --arg k "$LOCAL_A" '.members[] | select(.member_repo_key == $k) | .priority // empty' 2>/dev/null || echo "")
  c_pri=$(echo "$post_resp" | jq -r --arg k "$LOCAL_C" '.members[] | select(.member_repo_key == $k) | .priority // empty' 2>/dev/null || echo "")
  b_pri=$(echo "$post_resp" | jq -r --arg k "$LOCAL_B" '.members[] | select(.member_repo_key == $k) | .priority // empty' 2>/dev/null || echo "")
  if [ "$a_pri" != "10" ]; then
    race_a_wrong=$((race_a_wrong + 1))
    last_failure_detail="iter ${iter}: A.priority=${a_pri} (want 10)"
  fi
  if [ "$c_pri" != "300" ]; then
    race_c_wrong=$((race_c_wrong + 1))
    last_failure_detail="iter ${iter}: C.priority=${c_pri} (want 300)"
  fi
  case "$b_pri" in
    "20")  race_b_observed_20=$((race_b_observed_20 + 1)) ;;
    "200") race_b_observed_200=$((race_b_observed_200 + 1)) ;;
    *)
      race_b_out_of_set=$((race_b_out_of_set + 1))
      last_failure_detail="iter ${iter}: B.priority='${b_pri}' (want 20 or 200)"
      ;;
  esac

  # Drop per-iteration temp files immediately so we don't accumulate
  # 200+ files for a 50-iter run.
  rm -f "$OUT_1" "$OUT_2" "$STATUS_1_FILE" "$STATUS_2_FILE"

  iter=$((iter + 1))
done

# ---------------------------------------------------------------------------
# Aggregated assertions across all iterations.
# ---------------------------------------------------------------------------

begin_test "All race iterations completed (${RACE_ITERATIONS} runs)"
if [ "$total_iters" -eq "$RACE_ITERATIONS" ] && [ "$race_writer_nonzero_rc" -eq 0 ]; then
  pass
else
  fail "completed ${total_iters}/${RACE_ITERATIONS}, ${race_writer_nonzero_rc} writer-rc failures (last: ${last_failure_detail})"
fi

begin_test "No iteration produced a 5xx response"
if [ "$race_5xx" -eq 0 ]; then
  pass
else
  fail "${race_5xx}/${RACE_ITERATIONS} iterations produced a 5xx (last: ${last_failure_detail})"
fi

begin_test "Every iteration returned 200 for both writers"
if [ "$race_non200" -eq 0 ]; then
  pass
else
  fail "${race_non200}/${RACE_ITERATIONS} iterations had a non-200 status (last: ${last_failure_detail})"
fi

begin_test "Every iteration left V with 3 members"
if [ "$race_lost_rows" -eq 0 ]; then
  pass
else
  fail "${race_lost_rows}/${RACE_ITERATIONS} iterations lost rows (last: ${last_failure_detail})"
fi

begin_test "Row A always ended at priority 10 (uncontested)"
if [ "$race_a_wrong" -eq 0 ]; then
  pass
else
  fail "${race_a_wrong}/${RACE_ITERATIONS} iterations had wrong A priority (last: ${last_failure_detail})"
fi

begin_test "Row C always ended at priority 300 (uncontested)"
if [ "$race_c_wrong" -eq 0 ]; then
  pass
else
  fail "${race_c_wrong}/${RACE_ITERATIONS} iterations had wrong C priority (last: ${last_failure_detail})"
fi

begin_test "Row B always ended in {20, 200} (contested, no torn writes)"
if [ "$race_b_out_of_set" -eq 0 ]; then
  pass
  echo "  observed B=20: ${race_b_observed_20}, B=200: ${race_b_observed_200} across ${RACE_ITERATIONS} iters"
else
  fail "${race_b_out_of_set}/${RACE_ITERATIONS} iterations had B priority outside {20,200} (last: ${last_failure_detail})"
fi

# ---------------------------------------------------------------------------
# Cleanup is registered with add_exit_handler at creation time, so the
# trap will tear down the four repos regardless of how this script exits.
# ---------------------------------------------------------------------------

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
