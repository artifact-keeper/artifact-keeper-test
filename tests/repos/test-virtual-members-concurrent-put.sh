#!/usr/bin/env bash
# test-virtual-members-concurrent-put.sh - Full-set replace semantics for
# PUT /api/v1/repositories/:key/members, including the concurrent case.
#
# Covers artifact-keeper-test#96.
#
# RATIFIED CONTRACT (artifact-keeper#2899, introduced by artifact-keeper#2795)
# ---------------------------------------------------------------------------
# PUT /api/v1/repositories/{key}/members has FULL-SET REPLACE semantics. The
# request body is the COMPLETE desired member list:
#
#   * members listed in the body are inserted if absent, or have their
#     priority refreshed if already present;
#   * members ABSENT from the body are REMOVED;
#   * an empty member list removes every member.
#
# artifact-keeper#2795 introduced this (it replaced a priorities-only update
# that returned 404 for any member not already present, which made "add a
# member through the edit form" impossible). artifact-keeper#2899 ratified it
# as the intended API semantics rather than reverting to a non-destructive
# update.
#
# LAST-WRITER-WINS IS THE CORRECT BEHAVIOR, NOT A BUG
# ---------------------------------------------------
# This suite previously asserted a non-destructive partial-update contract and
# treated "complementary lost members across two overlapping PUTs" as a race
# defect. Under the ratified replace semantics that fingerprint is exactly what
# a correct implementation produces: each writer submits a complete desired set,
# so the writer that commits last owns the whole membership. The old assertions
# reported a false regression on every 1.6.1+ backend and are gone.
#
# What replace semantics DOES still guarantee under concurrency is atomicity of
# the whole set. `RepositoryService::set_virtual_members` performs the
# remove-absent DELETE and the upsert INSERT inside ONE transaction guarded by
# the process-wide member-graph advisory lock (pg_advisory_xact_lock), so two
# overlapping PUTs serialize. The observable end state must therefore be
# EXACTLY one of the two submitted sets. It must never be:
#
#   * a merge of both bodies (that would be the old partial-update behavior);
#   * a partially-applied mixture (some rows from one writer, some from the
#     other), which is what a non-transactional per-row loop would produce.
#
# WHAT THIS TEST EXERCISES
# ------------------------
# 1. Sequential replace: a PUT with the full member list yields exactly that
#    set, with the priorities as sent, including members the PUT INSERTS.
# 2. Sequential removal: a PUT that omits an existing member REMOVES it. This
#    is asserted positively, as ratified behavior, not as a defect.
# 3. Sequential clear: a PUT with an empty member list removes every member.
# 4. Concurrent overlapping PUTs converge to last-writer-wins:
#       Writer 1: {A=11, B=21}
#       Writer 2: {B=22, C=33}
#    B is the shared member, A is unique to writer 1, C is unique to writer 2.
#    The final set must equal EXACTLY one of those two sets. We do NOT assert
#    WHICH writer wins: commit ordering is nondeterministic and either outcome
#    is correct. We assert the end state is internally consistent, and
#    separately that no torn state exists (A and C can never coexist, since no
#    submitted set contains both).
#
# ASSERTION NOTE ON THE PUT RESPONSE BODY
# ---------------------------------------
# The handler returns the refreshed member list by calling list_virtual_members
# AFTER its own transaction commits. That read is not inside the advisory lock,
# so under concurrency a writer's own response body may legitimately show the
# OTHER writer's set (if that writer committed in between). We therefore assert
# that each concurrent response body is one of the two submitted sets (a single
# SELECT sees exactly one committed state, so a torn body is a real defect) but
# NOT that a writer's body echoes its own payload. The sequential sections do
# assert the response echoes the submitted set, because no contention exists
# there.
#
# EXPECT_FAILURE=1 inverts the suite exit code (used by self-tests).
#
# Requires: curl, jq

source "$(dirname "$0")/../lib/common.sh"

begin_suite "virtual-members-concurrent-put"
auth_admin
setup_workdir

# ---------------------------------------------------------------------------
# Contract gate.
#
# Full-set replace shipped with artifact-keeper#2795, which merged after v1.6.0
# and is contained in v1.6.1 (the first tag carrying commit 2120b3b2). Backends
# older than that still have the pre-#2795 priorities-only update, where every
# assertion in this suite is wrong by construction: writer 1's {A,B} body would
# not drop C, and the empty-list PUT would be a no-op instead of a clear.
#
# virtual_member_replace_contract is registered in BOTH flag layers:
#   * tests/lib/common.sh   _feature_min_version -> 1.6.1 (backend-probe path,
#     which is what the repos suite actually uses: the repo-tests job in
#     release-gate.yml does not set AK_BACKEND_BRANCH, so AK_FEATURES is unset
#     and require_feature falls through to the version probe);
#   * tests/lib/feature-flags.sh AK_BACKEND_BRANCH_MAIN (branch-aware path, for
#     jobs that do set AK_BACKEND_BRANCH). It is deliberately absent from the
#     1.1.x and 1.2.x bundles, which pre-date replace semantics.
# ---------------------------------------------------------------------------
begin_test "Backend implements full-set replace virtual-member semantics"
if require_feature "virtual_member_replace_contract"; then
  pass
else
  end_suite
  exit 0
fi

LOCAL_A="test-vmcp-a-${RUN_ID}"
LOCAL_B="test-vmcp-b-${RUN_ID}"
LOCAL_C="test-vmcp-c-${RUN_ID}"
VIRTUAL_KEY="test-vmcp-virt-${RUN_ID}"
MEMBERS_PATH="/api/v1/repositories/${VIRTUAL_KEY}/members"

# Number of race iterations. Each iteration is 2 concurrent PUTs plus one GET
# plus a 50ms barrier settle, so ~0.2s worst case on a loaded gate runner. 20
# iterations keeps the race phase to a few seconds, well inside run-suite.sh's
# 120s per-script budget (setup creates four repos first). Tune up locally if
# the race window feels narrow.
RACE_ITERATIONS="${RACE_ITERATIONS:-20}"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# canonical_members RESPONSE_JSON
# Render a VirtualMembersListResponse as a stable, order-independent string:
#   "<member_repo_key>=<priority>,<member_repo_key>=<priority>,..."
# sorted lexicographically. Two member sets are equal iff their canonical
# strings are equal, so a whole-set comparison is a single string compare and
# the failure message shows the full observed state.
canonical_members() {
  echo "${1:-}" | jq -r '[.members[]? | "\(.member_repo_key)=\(.priority)"] | sort | join(",")' 2>/dev/null || echo "<unparseable>"
}

# canonical_payload REQUEST_JSON
# Same rendering for an UpdateVirtualMembersRequest body, so a submitted set
# and an observed set are directly comparable. The request uses member_key
# where the response uses member_repo_key; both produce "key=priority" tokens.
canonical_payload() {
  echo "${1:-}" | jq -r '[.members[]? | "\(.member_key)=\(.priority)"] | sort | join(",")' 2>/dev/null || echo "<unparseable>"
}

# put_members PAYLOAD BODY_OUT
# Issue the PUT with raw curl so the HTTP status is observable independently of
# the body. api_put uses `curl -sf`, which discards the body on non-2xx and
# collapses every failure into one shell exit code, hiding a 500 vs a 404.
# Echoes the HTTP status on stdout; writes the response body to BODY_OUT.
put_members() {
  local payload="$1"
  local body_out="${2:-/dev/null}"
  local status
  status=$(curl -s -o "$body_out" -w '%{http_code}' $CURL_TIMEOUT \
    -X PUT \
    -H "$(auth_header)" \
    -H "Content-Type: application/json" \
    -d "$payload" \
    "${BASE_URL}${MEMBERS_PATH}" 2>/dev/null) || status="000"
  echo "$status"
}

# ---------------------------------------------------------------------------
# Setup: three local members plus a virtual repo seeded with A only.
#
# Seeding with A alone (not all three) means the first replace PUT has to
# INSERT B and C, which is the half of replace semantics the pre-#2795 handler
# could not do. Cleanup for each repo is registered with add_exit_handler right
# after creation so a failure mid-suite does not leak repos.
#
# Setup failures use infra_fail, not fail: the harness could not build the
# fixture, so nothing has been learned about the candidate's member semantics.
# ---------------------------------------------------------------------------

begin_test "Create local repo A"
if create_local_repo "$LOCAL_A" "generic"; then
  add_exit_handler "api_delete \"/api/v1/repositories/${LOCAL_A}\" >/dev/null 2>&1 || true"
  pass
else
  infra_fail "could not create local repo A"
fi

begin_test "Create local repo B"
if create_local_repo "$LOCAL_B" "generic"; then
  add_exit_handler "api_delete \"/api/v1/repositories/${LOCAL_B}\" >/dev/null 2>&1 || true"
  pass
else
  infra_fail "could not create local repo B"
fi

begin_test "Create local repo C"
if create_local_repo "$LOCAL_C" "generic"; then
  add_exit_handler "api_delete \"/api/v1/repositories/${LOCAL_C}\" >/dev/null 2>&1 || true"
  pass
else
  infra_fail "could not create local repo C"
fi

begin_test "Create virtual repo V seeded with member A"
if create_virtual_repo "$VIRTUAL_KEY" "generic" "${LOCAL_A}"; then
  add_exit_handler "api_delete \"/api/v1/repositories/${VIRTUAL_KEY}\" >/dev/null 2>&1 || true"
  pass
else
  infra_fail "could not create virtual repo with member A"
fi

# Poll until the seed member is visible (10s budget).
deadline=$(( $(date +%s) + 10 ))
until [ "$(api_get "${MEMBERS_PATH}" 2>/dev/null | jq '.members | length // 0' 2>/dev/null || echo 0)" = "1" ] || [ "$(date +%s)" -ge "$deadline" ]; do
  sleep 0.2
done

begin_test "Pre-condition: V has exactly member A"
if PRE_RESP=$(api_get "${MEMBERS_PATH}" 2>/dev/null); then
  # Assert membership only, not the seed priority: the POST add path assigns
  # MAX(existing)+1 and its base has moved between releases. Nothing below
  # depends on the seed priority, because every subsequent PUT states the
  # priority it wants explicitly.
  pre_count=$(echo "$PRE_RESP" | jq '.members | length // 0' 2>/dev/null) || pre_count=0
  pre_key=$(echo "$PRE_RESP" | jq -r '.members[0].member_repo_key // empty' 2>/dev/null) || pre_key=""
  if [ "$pre_count" = "1" ] && [ "$pre_key" = "$LOCAL_A" ]; then
    pass
  else
    infra_fail "expected V to hold only member A after seeding, got '$(canonical_members "$PRE_RESP")'"
  fi
else
  infra_fail "could not list members before the replace tests"
fi

# ---------------------------------------------------------------------------
# 1. Full-set replace: the body IS the desired set.
#
# V currently holds {A}. PUT {A=10, B=20, C=30} must yield exactly that set:
# A's priority refreshed, B and C inserted.
# ---------------------------------------------------------------------------

SET_ABC=$(jq -n \
  --arg a "$LOCAL_A" \
  --arg b "$LOCAL_B" \
  --arg c "$LOCAL_C" \
  '{members: [
     {member_key: $a, priority: 10},
     {member_key: $b, priority: 20},
     {member_key: $c, priority: 30}
   ]}')
EXPECT_ABC=$(canonical_payload "$SET_ABC")

begin_test "PUT with a full member list sets exactly that set (inserts absent members)"
ABC_BODY="${WORK_DIR}/put-abc.json"
ABC_STATUS=$(put_members "$SET_ABC" "$ABC_BODY")
if [ "$ABC_STATUS" != "200" ]; then
  fail "replace PUT returned HTTP ${ABC_STATUS}, want 200" "$(head -c 400 "$ABC_BODY" 2>/dev/null || true)"
else
  abc_resp=$(cat "$ABC_BODY" 2>/dev/null || echo "{}")
  abc_resp_canon=$(canonical_members "$abc_resp")
  abc_get_canon=$(canonical_members "$(api_get "${MEMBERS_PATH}" 2>/dev/null || echo '{}')")
  if [ "$abc_resp_canon" = "$EXPECT_ABC" ] && [ "$abc_get_canon" = "$EXPECT_ABC" ]; then
    pass
  else
    fail "replace PUT did not set the submitted member set" \
      "submitted: ${EXPECT_ABC}
PUT response: ${abc_resp_canon}
GET response: ${abc_get_canon}"
  fi
fi

# ---------------------------------------------------------------------------
# 2. Omitting a member REMOVES it.
#
# This is the ratified behavior from artifact-keeper#2899, asserted positively.
# V holds {A,B,C}; PUT {A=10, C=30} must leave exactly {A,C}. B must be gone,
# not merely reordered or left at its old priority.
# ---------------------------------------------------------------------------

SET_AC=$(jq -n \
  --arg a "$LOCAL_A" \
  --arg c "$LOCAL_C" \
  '{members: [
     {member_key: $a, priority: 10},
     {member_key: $c, priority: 30}
   ]}')
EXPECT_AC=$(canonical_payload "$SET_AC")

begin_test "PUT omitting an existing member removes that member (ratified replace semantics)"
AC_BODY="${WORK_DIR}/put-ac.json"
AC_STATUS=$(put_members "$SET_AC" "$AC_BODY")
if [ "$AC_STATUS" != "200" ]; then
  fail "omitting-member PUT returned HTTP ${AC_STATUS}, want 200" "$(head -c 400 "$AC_BODY" 2>/dev/null || true)"
else
  ac_get=$(api_get "${MEMBERS_PATH}" 2>/dev/null || echo "{}")
  ac_get_canon=$(canonical_members "$ac_get")
  ac_count=$(echo "$ac_get" | jq '.members | length // 0' 2>/dev/null) || ac_count=0
  b_present=$(echo "$ac_get" | jq --arg k "$LOCAL_B" '[.members[]? | select(.member_repo_key == $k)] | length' 2>/dev/null) || b_present="?"
  if [ "$ac_get_canon" = "$EXPECT_AC" ] && [ "$ac_count" = "2" ] && [ "$b_present" = "0" ]; then
    pass
  else
    fail "member omitted from the PUT body was not removed" \
      "submitted: ${EXPECT_AC}
observed:  ${ac_get_canon}
member count: ${ac_count} (want 2), occurrences of omitted member ${LOCAL_B}: ${b_present} (want 0)"
  fi
fi

# ---------------------------------------------------------------------------
# 3. An empty member list clears the membership.
#
# The degenerate case of replace semantics: set_virtual_members' remove-absent
# DELETE uses `member_repo_id <> ALL($2)`, which is TRUE for every row when the
# desired array is empty. Under the old partial-update contract this PUT was a
# no-op, so it is the sharpest single discriminator between the two contracts.
# ---------------------------------------------------------------------------

SET_EMPTY='{"members": []}'

begin_test "PUT with an empty member list removes every member"
EMPTY_BODY="${WORK_DIR}/put-empty.json"
EMPTY_STATUS=$(put_members "$SET_EMPTY" "$EMPTY_BODY")
if [ "$EMPTY_STATUS" != "200" ]; then
  fail "empty-list PUT returned HTTP ${EMPTY_STATUS}, want 200" "$(head -c 400 "$EMPTY_BODY" 2>/dev/null || true)"
elif ! empty_get=$(api_get "${MEMBERS_PATH}" 2>/dev/null); then
  infra_fail "could not list members after the empty-list PUT"
else
  # Require a real members ARRAY, not just a zero count. `{} | .members |
  # length // 0` is also 0, so a malformed or error body would otherwise look
  # identical to a correctly cleared membership and pass this assertion.
  empty_is_array=$(echo "$empty_get" | jq '.members | type == "array"' 2>/dev/null) || empty_is_array="false"
  empty_count=$(echo "$empty_get" | jq '.members | length // 0' 2>/dev/null) || empty_count="?"
  if [ "$empty_is_array" = "true" ] && [ "$empty_count" = "0" ]; then
    pass
  else
    fail "empty-list PUT did not clear the membership (members array present: ${empty_is_array}, count: ${empty_count}, want true/0)" \
      "observed: $(canonical_members "$empty_get")"
  fi
fi

# ---------------------------------------------------------------------------
# 4. Concurrent overlapping PUTs: last-writer-wins over the WHOLE set.
#
#   Writer 1: {A=11, B=21}   A is unique to writer 1
#   Writer 2: {B=22, C=33}   C is unique to writer 2
#
# B is shared, and carries a DIFFERENT priority in each body, so a final state
# that keeps writer 1's rows but writer 2's B (or vice versa) is detectable as
# a partially-applied mixture rather than looking like a valid outcome.
#
# No per-iteration reset is needed: each writer submits a complete set, so the
# previous iteration's residue is irrelevant by construction. That is itself a
# property of replace semantics (the old partial-update harness needed a reset
# PUT precisely because a partial body could not define the whole state).
# ---------------------------------------------------------------------------

PAYLOAD_1=$(jq -n \
  --arg a "$LOCAL_A" \
  --arg b "$LOCAL_B" \
  '{members: [
     {member_key: $a, priority: 11},
     {member_key: $b, priority: 21}
   ]}')
PAYLOAD_2=$(jq -n \
  --arg b "$LOCAL_B" \
  --arg c "$LOCAL_C" \
  '{members: [
     {member_key: $b, priority: 22},
     {member_key: $c, priority: 33}
   ]}')
EXPECT_W1=$(canonical_payload "$PAYLOAD_1")
EXPECT_W2=$(canonical_payload "$PAYLOAD_2")

# Barrier mechanism: each iteration creates a named pipe (FIFO). Each writer
# opens the FIFO for reading and blocks on `read` until the parent writes a
# release byte. This pays the fork + bash startup + TLS setup cost before the
# race window opens, so the two curl invocations leave the starting line within
# microseconds of each other.
run_writer() {
  local payload="$1"
  local body_out="$2"
  local status_out="$3"
  local barrier="$4"
  local status
  # Block until the parent writes the release byte to the FIFO.
  read -r _barrier_byte < "$barrier" || true
  status=$(put_members "$payload" "$body_out")
  printf '%s' "$status" > "$status_out"
}

# Aggregated outcomes across iterations. We assert once at the end so the suite
# reports per-aspect pass/fail rather than one testcase per iteration.
total_iters=0
race_writer_nonzero_rc=0
race_5xx=0
race_non200=0
race_final_not_a_submitted_set=0
race_torn_state=0
race_duplicate_member=0
race_body_not_a_submitted_set=0
race_won_by_w1=0
race_won_by_w2=0
last_failure_detail=""
last_infra_detail=""

iter=1
while [ "$iter" -le "$RACE_ITERATIONS" ]; do
  total_iters=$iter

  OUT_1="${WORK_DIR}/vmcp-writer1-${RUN_ID}-${iter}.out"
  OUT_2="${WORK_DIR}/vmcp-writer2-${RUN_ID}-${iter}.out"
  STATUS_1_FILE="${WORK_DIR}/vmcp-writer1-${RUN_ID}-${iter}.status"
  STATUS_2_FILE="${WORK_DIR}/vmcp-writer2-${RUN_ID}-${iter}.status"
  BARRIER_FIFO="${WORK_DIR}/vmcp-barrier-${RUN_ID}-${iter}.fifo"

  # Create a fresh FIFO for the iteration's barrier. Remove first in case a
  # previous aborted iteration left one behind.
  rm -f "$BARRIER_FIFO"
  if ! mkfifo "$BARRIER_FIFO" 2>/dev/null; then
    last_infra_detail="iter ${iter}: mkfifo failed"
    race_writer_nonzero_rc=$((race_writer_nonzero_rc + 1))
    iter=$((iter + 1))
    continue
  fi

  # Hold the FIFO open on fd 8 in the parent. We MUST open it read-write
  # (`<>`), not write-only (`>`).
  #
  # A write-only open of a FIFO blocks until a reader attaches (POSIX O_WRONLY
  # semantics, observed on both Linux ARC runners and macOS). The two reader
  # children are forked AFTER this line, so a write-only open here deadlocks:
  # the parent waits for a reader that can never be created because the parent
  # never reaches the fork. That is the exit-124 hang this suite tripped in
  # release-gate; the hang is entirely client-side (no PUT is ever issued).
  #
  # Opening read-write never blocks (there is always a reader: ourselves), so
  # the parent proceeds to fork the writers immediately. Because fd 8 keeps a
  # read end open, closing the write end does NOT produce EOF, so we release
  # the writers by WRITING one byte per writer instead of relying on EOF.
  exec 8<>"$BARRIER_FIFO"

  run_writer "$PAYLOAD_1" "$OUT_1" "$STATUS_1_FILE" "$BARRIER_FIFO" &
  PID_1=$!
  run_writer "$PAYLOAD_2" "$OUT_2" "$STATUS_2_FILE" "$BARRIER_FIFO" &
  PID_2=$!

  # Give the two writers a moment to fork, exec bash, and reach their
  # `read < $BARRIER_FIFO` barrier. 50ms is generous: bash startup is ~5ms.
  sleep 0.05

  # Release the barrier: write exactly one byte per blocked reader. Both
  # children's `read` return near-simultaneously and proceed to issue their
  # PUT. Then close fd 8 (drops both the read and write ends we hold).
  printf 'g\ng\n' >&8
  exec 8>&-

  rc_1=0; wait "$PID_1" || rc_1=$?
  rc_2=0; wait "$PID_2" || rc_2=$?
  rm -f "$BARRIER_FIFO"

  if [ "$rc_1" -ne 0 ] || [ "$rc_2" -ne 0 ]; then
    race_writer_nonzero_rc=$((race_writer_nonzero_rc + 1))
    last_infra_detail="iter ${iter}: writer rc1=${rc_1} rc2=${rc_2}"
    iter=$((iter + 1))
    continue
  fi

  STATUS_1=$(cat "$STATUS_1_FILE" 2>/dev/null || echo "000")
  STATUS_2=$(cat "$STATUS_2_FILE" 2>/dev/null || echo "000")

  # A 5xx means the concurrent path corrupted handler state (panic, poisoned
  # pool entry). Under an advisory-locked transaction both writers must simply
  # serialize and succeed.
  if [ "$STATUS_1" -ge 500 ] 2>/dev/null || [ "$STATUS_2" -ge 500 ] 2>/dev/null; then
    race_5xx=$((race_5xx + 1))
    last_failure_detail="iter ${iter}: 5xx status w1=${STATUS_1} w2=${STATUS_2}"
  fi
  if [ "$STATUS_1" != "200" ] || [ "$STATUS_2" != "200" ]; then
    race_non200=$((race_non200 + 1))
    last_failure_detail="iter ${iter}: non-200 status w1=${STATUS_1} w2=${STATUS_2}"
  fi

  # Each writer's own response body is a single SELECT taken after its own
  # transaction committed, so it observes exactly one committed state: either
  # its own set or the other writer's. A body that is neither is a torn read.
  # We deliberately do NOT require a writer's body to echo its OWN payload:
  # the list read happens outside the advisory lock, so the other writer may
  # legitimately have committed in between.
  body_1_canon=$(canonical_members "$(cat "$OUT_1" 2>/dev/null || echo '{}')")
  body_2_canon=$(canonical_members "$(cat "$OUT_2" 2>/dev/null || echo '{}')")
  for body_canon in "$body_1_canon" "$body_2_canon"; do
    if [ "$body_canon" != "$EXPECT_W1" ] && [ "$body_canon" != "$EXPECT_W2" ]; then
      race_body_not_a_submitted_set=$((race_body_not_a_submitted_set + 1))
      last_failure_detail="iter ${iter}: PUT response body '${body_canon}' is neither '${EXPECT_W1}' nor '${EXPECT_W2}'"
    fi
  done

  # Final observed state. Both transactions committed before their HTTP
  # responses returned, so no settle window is required.
  post_resp=$(api_get "${MEMBERS_PATH}" 2>/dev/null || echo "{}")
  post_canon=$(canonical_members "$post_resp")

  # (a) Convergence: the end state equals EXACTLY one submitted set. Which one
  #     wins is nondeterministic and both answers are correct, so we only count
  #     the split for the diagnostic line.
  case "$post_canon" in
    "$EXPECT_W1") race_won_by_w1=$((race_won_by_w1 + 1)) ;;
    "$EXPECT_W2") race_won_by_w2=$((race_won_by_w2 + 1)) ;;
    *)
      race_final_not_a_submitted_set=$((race_final_not_a_submitted_set + 1))
      last_failure_detail="iter ${iter}: final set '${post_canon}' is neither '${EXPECT_W1}' nor '${EXPECT_W2}'"
      ;;
  esac

  # (b) No torn/partial state: A is unique to writer 1 and C is unique to
  #     writer 2, so no submitted set contains both. Their coexistence proves
  #     a merge or a partially-applied mixture regardless of priorities.
  a_count=$(echo "$post_resp" | jq --arg k "$LOCAL_A" '[.members[]? | select(.member_repo_key == $k)] | length' 2>/dev/null) || a_count=0
  c_count=$(echo "$post_resp" | jq --arg k "$LOCAL_C" '[.members[]? | select(.member_repo_key == $k)] | length' 2>/dev/null) || c_count=0
  if [ "$a_count" != "0" ] && [ "$c_count" != "0" ]; then
    race_torn_state=$((race_torn_state + 1))
    last_failure_detail="iter ${iter}: torn state, member unique to writer 1 (${LOCAL_A}) coexists with member unique to writer 2 (${LOCAL_C}): '${post_canon}'"
  fi

  # (c) No duplicate rows for the same member repo. The upsert is keyed on
  #     (virtual_repo_id, member_repo_id), so a duplicate would mean the
  #     conflict target stopped matching.
  member_total=$(echo "$post_resp" | jq '.members | length // 0' 2>/dev/null) || member_total=0
  member_distinct=$(echo "$post_resp" | jq '[.members[]?.member_repo_key] | unique | length' 2>/dev/null) || member_distinct=0
  if [ "$member_total" != "$member_distinct" ]; then
    race_duplicate_member=$((race_duplicate_member + 1))
    last_failure_detail="iter ${iter}: ${member_total} member rows but only ${member_distinct} distinct keys: '${post_canon}'"
  fi

  # Drop per-iteration temp files immediately so a long run does not
  # accumulate hundreds of files under WORK_DIR.
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
  # A writer subprocess that never issued its PUT is a harness problem, not a
  # verdict on the backend's member semantics.
  infra_fail "completed ${total_iters}/${RACE_ITERATIONS}, ${race_writer_nonzero_rc} writer-process failures" \
    "last: ${last_infra_detail}"
fi

begin_test "No iteration produced a 5xx response"
if [ "$race_5xx" -eq 0 ]; then
  pass
else
  fail "${race_5xx}/${RACE_ITERATIONS} iterations produced a 5xx" "last: ${last_failure_detail}"
fi

begin_test "Every iteration returned 200 for both writers"
if [ "$race_non200" -eq 0 ]; then
  pass
else
  fail "${race_non200}/${RACE_ITERATIONS} iterations had a non-200 status" "last: ${last_failure_detail}"
fi

begin_test "Final member set equals exactly one submitted set (last-writer-wins)"
if [ "$race_final_not_a_submitted_set" -eq 0 ]; then
  pass
  echo "  won by writer 1: ${race_won_by_w1}, won by writer 2: ${race_won_by_w2} across ${RACE_ITERATIONS} iters"
  echo "  (both outcomes are correct under replace semantics; the split is informational)"
else
  fail "${race_final_not_a_submitted_set}/${RACE_ITERATIONS} iterations ended in a set that was neither writer's submitted set" \
    "writer 1 submitted: ${EXPECT_W1}
writer 2 submitted: ${EXPECT_W2}
last: ${last_failure_detail}"
fi

begin_test "No torn state: members unique to different writers never coexist"
if [ "$race_torn_state" -eq 0 ]; then
  pass
else
  fail "${race_torn_state}/${RACE_ITERATIONS} iterations produced a merged or partially-applied member set" \
    "last: ${last_failure_detail}"
fi

begin_test "No duplicate member rows after concurrent replace"
if [ "$race_duplicate_member" -eq 0 ]; then
  pass
else
  fail "${race_duplicate_member}/${RACE_ITERATIONS} iterations returned duplicate member rows" \
    "last: ${last_failure_detail}"
fi

begin_test "Each PUT response body reflects one committed member set"
if [ "$race_body_not_a_submitted_set" -eq 0 ]; then
  pass
else
  fail "${race_body_not_a_submitted_set} PUT response bodies were neither submitted set" \
    "writer 1 submitted: ${EXPECT_W1}
writer 2 submitted: ${EXPECT_W2}
last: ${last_failure_detail}"
fi

# ---------------------------------------------------------------------------
# Cleanup is registered with add_exit_handler at creation time, so the trap
# tears down the four repos regardless of how this script exits.
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
