#!/usr/bin/env bash
# test-webhook-retry-recover.sh
#
# Webhooks v2 wire contract (artifact-keeper#919, E5): exercise the webhook
# delivery retry engine end-to-end.
#
# Full v2 retry schedule (jittered +/-20%):
#   30s, 1m, 2m, 5m, 10m, 30m, 1h, 2h, 4h, 8h, 16h, 24h
#   = 12 attempts; total walltime ~65h.
#
# Smoke profile: this test caps observation at the first 3 attempts so the
# release-gate stays under WEBHOOK_RETRY_TIMEOUT (default 330s). The first
# three intervals (30s, 60s, 120s base) plus +/-20% jitter give acceptable
# windows of:
#   attempt 1 ->  24-36s   backoff
#   attempt 2 ->  48-72s   backoff
#   attempt 3 ->  96-144s  backoff
# The full 12-attempt schedule is exercised in the dead-letter test.
#
# IMPORTANT: what we actually measure, and the scheduler-tick quantization
# that the (now fixed) windows MUST account for:
#
# The backend does NOT fire a retry at the exact instant next_retry_at
# elapses. A background scheduler tick runs every 30s
# (services/scheduler_service.rs: interval(Duration::from_secs(30))) and
# only then drains rows whose next_retry_at <= NOW(). So the *observed* gap
# between two consecutive POSTs at the receiver is:
#
#     observed_gap = backoff(attempt)  +  [0 .. 30s tick latency]  +  dial
#
# i.e. the backoff rounded UP to the next 30s scheduler tick. The previous
# version of this test asserted the raw backoff window (24-36s etc.) and
# IGNORED tick quantization, so a perfectly healthy backend whose 30s base
# delay landed mid-tick was measured as e.g. a 55s gap and reported
# "outside 24-36". The windows below add a +30s (one full tick) upper
# allowance and a small floor.
#
# Note also: this test must KEEP the receiver FAILING through attempt 3.
# If the mock recovers (returns 200) after the first failure the delivery
# row is marked success/next_retry_at=NULL and NO further POSTs occur, so you
# can never observe a 2nd or 3rd retry interval. WEBHOOK_FAIL_FIRST_N is
# therefore defaulted to EXPECT_ATTEMPTS so the receiver rejects attempts
# 1..3 (producing the 3 spaced retry POSTs we measure) and accepts the 4th,
# proving the recover path.
#
# Delivery isolation: the webhook is scoped to this test's own repository and
# subscribes to artifact_uploaded, so no sibling suite's event can reach this
# receiver or queue on this endpoint (test#317; see "Delivery isolation" below).
#
# Receiver discovery / isolation:
#   WEBHOOK_RECEIVER_PORT  - port the local mock listens on. Defaults to a
#                            per-PID port so concurrent webhook suites in the
#                            same gate run do NOT share one receiver. A shared
#                            receiver was the root cause of the "all deltas=0s"
#                            flake: a second suite's deliveries drained in the
#                            same 30s scheduler tick landed as near-simultaneous
#                            POSTs in this suite's log, so every measured gap
#                            collapsed to 0s.
#   WEBHOOK_RECEIVER_URL   - URL the backend POSTs to. Defaults to the
#                            local mock; override in environments where
#                            the backend cannot reach loopback.
#   WEBHOOK_FAIL_FIRST_N   - how many POSTs the mock should reject with
#                            500 before flipping to 200. Defaults to 3 so we
#                            observe THREE spaced retries then recover on the
#                            4th. (Must be >= EXPECT_ATTEMPTS.)
#   WEBHOOK_RETRY_TIMEOUT  - seconds to wait for the retry POST(s) after the
#                            initial one (default 330; see the note at its
#                            assignment below).
#   INITIAL_POST_TIMEOUT   - seconds to wait for the initial POST after the
#                            upload (default 60).
#
# Companion backend PR: artifact-keeper#1140. Producer feature flag is
# WEBHOOKS_V2_PRODUCER_ENABLED; harness sets it to 1.
#
# Requires: curl, jq, python3

source "$(dirname "$0")/../lib/common.sh"

begin_suite "webhook-retry-recover"

# Per-PID default port so concurrent webhook suites never share a receiver
# (shared-receiver simultaneous drains were the "all deltas=0s" root cause).
WEBHOOK_RECEIVER_PORT="${WEBHOOK_RECEIVER_PORT:-$(( 18700 + $$ % 200 ))}"
WEBHOOK_RECEIVER_URL="${WEBHOOK_RECEIVER_URL:-http://$(webhook_receiver_host):${WEBHOOK_RECEIVER_PORT}/hook}"
# Number of spaced retry intervals we observe. Default 1: reject attempt 1,
# recover on attempt 2. This proves the retry-AND-recover behavior with real
# backoff spacing inside the webhook job's TEST_TIMEOUT (420s). Observing all 3
# intervals needs ~330s of retry polling (30+60+120 backoff + 30s ticks +
# jitter) on top of setup and the initial-POST poll, which overruns it, so we
# validate the first interval (the backoff base) rather than time out. Set EXPECT_ATTEMPTS=3 + a larger
# WEBHOOK_RETRY_TIMEOUT/TEST_TIMEOUT to exercise the full ladder when desired.
EXPECT_ATTEMPTS="${EXPECT_ATTEMPTS:-1}"
# Reject the first N POSTs, then recover on the (N+1)th. MUST be >= EXPECT_ATTEMPTS.
WEBHOOK_FAIL_FIRST_N="${WEBHOOK_FAIL_FIRST_N:-${EXPECT_ATTEMPTS}}"
# attempt-1 backoff ~30s base + up to one 30s tick + jitter + scheduler warmup +
# producer latency => ~120s worst case for EXPECT_ATTEMPTS=1. Widened 240s -> 360s
# (artifact-keeper-test#309): under full-suite congestion this failed once in nine
# gate attempts when the first delivery landed ~23s late and the retry slid just
# past the old 240s window; the scheduler itself is proven by the other eight
# runs. 360s absorbed that congestion tail. Lowered to 330s (test#317) to pay
# for a 60s initial-POST poll inside the same run-suite budget: with a
# repository-scoped webhook nothing else queues on this endpoint, so the
# retry needs the ~30s backoff plus at most one 30s pass, far inside 330s.
WEBHOOK_RETRY_TIMEOUT="${WEBHOOK_RETRY_TIMEOUT:-330}"
WEBHOOK_RECEIVER_LOG="${WEBHOOK_RECEIVER_LOG:-/tmp/mock-webhook-receiver-${RUN_ID}.log}"
RECEIVER_PID=""

REPO_KEY="retry-recover-repo-${RUN_ID}"
WEBHOOK_ID=""

cleanup_and_finalize() {
  local code=$?
  if [ -n "${WEBHOOK_ID}" ] && [ "${WEBHOOK_ID}" != "null" ]; then
    api_delete "/api/v1/webhooks/${WEBHOOK_ID}" >/dev/null 2>&1 || true
  fi
  api_delete "/api/v1/repositories/${REPO_KEY}" >/dev/null 2>&1 || true
  if [ -n "${RECEIVER_PID}" ] && kill -0 "${RECEIVER_PID}" 2>/dev/null; then
    kill "${RECEIVER_PID}" 2>/dev/null || true
    wait "${RECEIVER_PID}" 2>/dev/null || true
  fi
  rm -f "${WEBHOOK_RECEIVER_LOG}"
  exit "$code"
}
trap cleanup_and_finalize EXIT

# -------------------------------------------------------------------------
# Delivery isolation (test#317).
#
# Every delivery this receiver sees must be this test's own. The webhook is
# therefore REPOSITORY-SCOPED: it is created after this test's repository,
# with repository_id set to it, and subscribes to artifact_uploaded. The
# backend's producer only enqueues a delivery for a scoped webhook when the
# event's repository_id matches (services/webhook_producer.rs
# enqueue_for_event), and nothing else uploads into this repository, so the
# one artifact this test uploads yields exactly one delivery row.
#
# The earlier design subscribed a GLOBAL webhook to repository_created. The
# backend fanned every sibling suite's repository.created event out to it,
# and with per-entity forced failures (test#853) every one of those deliveries
# also failed once and was retried. All deliveries, first attempts included,
# are drained by the same 30 s scheduler pass (at most 50 rows), and since
# artifact-keeper#5661 a pass stops sending to an endpoint at its first
# failure and defers that endpoint's remaining due rows to the next pass. So
# under a full gate this endpoint processed about one sibling failure per
# pass while siblings kept creating repositories, and this test's retry sat
# behind that backlog past WEBHOOK_RETRY_TIMEOUT (nightly 44080626761). The
# scheduler was behaving as designed; the test was measuring the wrong queue.
#
# The receiver still runs with WEBHOOK_FAIL_PER_ENTITY=1 (the entity is now
# the artifact's UUID), so the forced 500 can only ever land on this
# artifact's own first delivery. The measurement side selects this
# artifact's POSTs, and the step after the initial POST checks the receiver
# really answered that first delivery with a 500.
# -------------------------------------------------------------------------

# Worst case: the initial-POST poll plus the WEBHOOK_RETRY_TIMEOUT poll. The
# initial poll is longer than one scheduler tick because first attempts are
# drained by the same 30 s pass as retries, so an upload that lands just after
# a pass waits a full tick before its first dial.
INITIAL_POST_TIMEOUT="${INITIAL_POST_TIMEOUT:-60}"
require_wait_budget "$(( WEBHOOK_RETRY_TIMEOUT + INITIAL_POST_TIMEOUT ))" "initial-POST and retry polls"

auth_admin

# -------------------------------------------------------------------------
# Start mock receiver.
# -------------------------------------------------------------------------

begin_test "Start mock webhook receiver"
if ! command -v python3 >/dev/null 2>&1; then
  SUITE_BLOCKED=true
  require_or_fail "python3 not available to run the mock webhook receiver"
else
  # NOTE: #316 passed WEBHOOK_FAIL_MATCH="$REPO_KEY" here. That was wrong: the
  # delivery body carries entity_id = the entity's UUID, not a key, so the
  # match never fired and every delivery was answered 200. Per-entity
  # counting (WEBHOOK_FAIL_PER_ENTITY=1) scopes the forced failures to each
  # delivery's own entity without needing the UUID up front. See test#317.
  WEBHOOK_RECEIVER_PORT="$WEBHOOK_RECEIVER_PORT" \
    WEBHOOK_FAIL_FIRST_N="$WEBHOOK_FAIL_FIRST_N" \
    WEBHOOK_FAIL_PER_ENTITY=1 \
    WEBHOOK_RECEIVER_LOG="$WEBHOOK_RECEIVER_LOG" \
    python3 "$(dirname "$0")/../lib/mock-webhook-receiver.py" \
    >/tmp/mock-webhook-receiver-${RUN_ID}.stderr 2>&1 &
  RECEIVER_PID=$!

  ready=false
  for _ in $(seq 1 25); do
    if curl -sf --max-time 1 "http://127.0.0.1:${WEBHOOK_RECEIVER_PORT}/__health" >/dev/null 2>&1; then
      ready=true
      break
    fi
    sleep 0.2
  done
  if [ "$ready" = true ]; then
    # Reset any stale state if the port happened to be reused by a prior run.
    curl -sf --max-time 2 "http://127.0.0.1:${WEBHOOK_RECEIVER_PORT}/__reset" >/dev/null 2>&1 || true
    pass
  else
    fail "mock receiver did not come up on 127.0.0.1:${WEBHOOK_RECEIVER_PORT}"
  fi
fi

SUITE_BLOCKED="${SUITE_BLOCKED:-false}"

# -------------------------------------------------------------------------
# Create this test's repository first: the webhook is scoped to its id.
# -------------------------------------------------------------------------

REPO_ID=""

begin_test "Create this test's repository"
if [ "$ready" != "true" ]; then
  skip "receiver not running"
else
  REPO_CREATE_PAYLOAD=$(jq -nc --arg k "$REPO_KEY" \
    '{key:$k, name:$k, format:"generic", repo_type:"local", is_public:true}')
  if repo_resp=$(api_post "/api/v1/repositories" "$REPO_CREATE_PAYLOAD" 2>/dev/null); then
    REPO_ID=$(echo "$repo_resp" | jq -r '.id // empty' 2>/dev/null) || REPO_ID=""
    if [ -n "$REPO_ID" ] && [ "$REPO_ID" != "null" ]; then
      pass
    else
      SUITE_BLOCKED=true
      fail "repo create returned no id; cannot scope the webhook to this repository"
    fi
  else
    SUITE_BLOCKED=true
    require_or_fail "repo create failed for ${REPO_KEY}"
  fi
fi

# -------------------------------------------------------------------------
# Create a repository-scoped webhook pointing at the mock receiver.
# -------------------------------------------------------------------------

WEBHOOK_NAME="retry-recover-${RUN_ID}"

begin_test "Create repository-scoped webhook targeting mock receiver"
if [ "$ready" != "true" ] || [ "$SUITE_BLOCKED" = "true" ]; then
  skip "receiver not running or no repository id"
else
  PAYLOAD=$(jq -n \
    --arg name "$WEBHOOK_NAME" \
    --arg url "$WEBHOOK_RECEIVER_URL" \
    --arg rid "$REPO_ID" \
    '{name: $name, url: $url, events: ["artifact_uploaded"], repository_id: $rid}')
  if resp=$(api_post "/api/v1/webhooks" "$PAYLOAD" 2>/dev/null); then
    WEBHOOK_ID=$(echo "$resp" | jq -r '.id // empty' 2>/dev/null) || WEBHOOK_ID=""
    scoped_to=$(echo "$resp" | jq -r '.repository_id // empty' 2>/dev/null) || scoped_to=""
    if [ -z "$WEBHOOK_ID" ] || [ "$WEBHOOK_ID" = "null" ]; then
      fail "webhook create returned no id"
    elif [ "$scoped_to" != "$REPO_ID" ]; then
      # A global webhook would bring back the sibling fan-out this design
      # exists to avoid (test#317).
      SUITE_BLOCKED=true
      fail "webhook was not scoped to repository ${REPO_ID} (response repository_id='${scoped_to}')"
    else
      pass
    fi
  else
    SUITE_BLOCKED=true
    # Under RELEASE_GATE=1 the gate configures the receiver to be reachable;
    # a rejected create leaves every retry assertion below unchecked.
    require_or_fail "webhook create rejected (URL '${WEBHOOK_RECEIVER_URL}' likely blocked by SSRF allow-list)"
  fi
fi

# -------------------------------------------------------------------------
# Trigger the initial delivery via a REAL event. POST /webhooks/{id}/test
# does NOT insert a webhook_deliveries row (it does a single synchronous
# POST and mints a throwaway id), so the retry scheduler would have nothing
# to retry. The retry engine only acts on real producer-enqueued rows, so we
# upload an artifact into the repository (-> artifact.uploaded, emitted for
# the repository -> the producer inserts one delivery row for this webhook).
# The mock rejects the first WEBHOOK_FAIL_FIRST_N POSTs for that artifact
# with 500, which drives the retry-then-recover path we assert on below.
#
# Selection: every delivery payload carries entity_id = the artifact's UUID
# (services/webhook_producer.rs build_event_payload). We take the artifact id
# from the upload response, or failing that from the first artifact_uploaded
# POST this receiver saw (the webhook is scoped, so that POST is ours), and
# select only that entity's artifact_uploaded POSTs from then on.
# -------------------------------------------------------------------------

ARTIFACT_ID=""
ARTIFACT_PATH="retry/${RUN_ID}.txt"

# Echo, oldest-first, the full JSON record of every receiver-log POST for
# this test's artifact (one compact JSON object per line). Before ARTIFACT_ID
# is known it matches any artifact_uploaded POST, which on this scoped
# webhook can only come from this test's repository.
select_repo_records() {
  jq -c --arg aid "$ARTIFACT_ID" '
    select((.body | fromjson? | .event) == "artifact_uploaded")
    | select($aid == "" or (.body | fromjson? | .entity_id) == $aid)' \
    "$WEBHOOK_RECEIVER_LOG" 2>/dev/null
}

# Echo, oldest-first, the .ts of every receiver-log POST for this artifact.
select_repo_posts() {
  select_repo_records | jq -r '.ts' 2>/dev/null
}

begin_test "Trigger delivery via artifact upload and observe initial POST at receiver"
if [ "$SUITE_BLOCKED" = "true" ] || [ -z "$WEBHOOK_ID" ]; then
  skip "no webhook id"
else
  upload_file="/tmp/retry-recover-${RUN_ID}.txt"
  echo "retry-recover-${RUN_ID}" > "$upload_file"
  if upload_resp=$(api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/${ARTIFACT_PATH}" \
      "$upload_file" "text/plain" 2>/dev/null); then
    rm -f "$upload_file"
    ARTIFACT_ID=$(echo "$upload_resp" | jq -r '.id // empty' 2>/dev/null) || ARTIFACT_ID=""
    [ "$ARTIFACT_ID" = "null" ] && ARTIFACT_ID=""
    seen=0
    # The first attempt is rejected (500) by the mock but still lands as a
    # POST. First attempts are drained by the 30 s scheduler pass, so allow
    # up to INITIAL_POST_TIMEOUT for the producer enqueue plus the first dial.
    for _ in $(seq 1 "$INITIAL_POST_TIMEOUT"); do
      # awk 'END{print NR}' always prints exactly one line (0 on empty) and
      # exits 0, unlike `grep -c . || echo 0` which emitted "0" AND echoed a
      # second "0" on no matches, producing a two-line value that tripped the
      # `[: 0` test warnings (artifact-keeper-test#309). Assignment-level `|| =0`
      # keeps it single-valued if the jq pipeline itself fails under pipefail.
      seen=$(select_repo_posts | awk 'END{print NR}') || seen=0
      [ "$seen" -gt 0 ] && break
      sleep 1  # sleep-ok: poll interval of the bounded initial-POST poll
    done
    if [ "$seen" -ge 1 ]; then
      if [ -z "$ARTIFACT_ID" ]; then
        # The upload response carried no id: pin the entity of the first POST
        # so a later stray delivery cannot be counted as a retry.
        ARTIFACT_ID=$(select_repo_records | head -n 1 \
          | jq -r '.body | fromjson? | .entity_id // empty' 2>/dev/null) || ARTIFACT_ID=""
      fi
      if [ -n "$ARTIFACT_ID" ]; then
        pass
      else
        SUITE_BLOCKED=true
        fail "initial POST for ${REPO_KEY}/${ARTIFACT_PATH} carried no entity_id; cannot scope the retry to this artifact"
      fi
    else
      # Nothing to retry: skip the retry poll instead of waiting it out.
      SUITE_BLOCKED=true
      fail "receiver saw 0 artifact_uploaded POSTs for ${REPO_KEY}/${ARTIFACT_PATH} within ${INITIAL_POST_TIMEOUT}s"
    fi
  else
    rm -f "$upload_file"
    SUITE_BLOCKED=true
    require_or_fail "artifact upload (event trigger) failed for ${REPO_KEY}/${ARTIFACT_PATH}"
  fi
fi

# The retry assertions below are only meaningful if the forced failure landed
# on OUR delivery (test#317). The receiver records the status it returned.
begin_test "Receiver answered this artifact's first delivery with the forced 500"
if [ "$SUITE_BLOCKED" = "true" ] || [ -z "$WEBHOOK_ID" ]; then
  skip "no webhook id"
elif [ -z "$ARTIFACT_ID" ]; then
  # Without the id the selection would match any artifact_uploaded POST.
  SUITE_BLOCKED=true
  fail "no artifact id for ${REPO_KEY}/${ARTIFACT_PATH}; cannot scope the forced failure to this artifact"
else
  first_status=$(select_repo_records | head -n 1 | jq -r '.status // empty' 2>/dev/null) || first_status=""
  if [ -z "$first_status" ]; then
    fail "no receiver record for ${REPO_KEY}/${ARTIFACT_PATH} (entity_id ${ARTIFACT_ID})"
  elif [ "$first_status" = "500" ] || [ "$WEBHOOK_FAIL_FIRST_N" -eq 0 ]; then
    pass
  else
    fail "first delivery for ${REPO_KEY}/${ARTIFACT_PATH} was answered ${first_status}, not the forced 500 (FAIL_FIRST_N=${WEBHOOK_FAIL_FIRST_N})"
  fi
fi

# -------------------------------------------------------------------------
# Retry windows. We observe the wall-clock timestamps of consecutive POSTs
# at the receiver and assert each gap is within window. The window is the
# jittered backoff PLUS the scheduler-tick quantization (a retry only fires
# on the next 30s tick after next_retry_at elapses):
#
#   observed_gap(attempt) in [ backoff_min , backoff_max + 30s_tick + slack ]
#
#   attempt 1: backoff 24..36   -> window 20..72   (36 + 30 tick + 6 slack)
#   attempt 2: backoff 48..72   -> window 40..108  (72 + 30 tick + 6 slack)
#   attempt 3: backoff 96..144  -> window 84..180  (144 + 30 tick + 6 slack)
#
# The lower bound is set slightly below backoff_min to tolerate a POST that
# lands a hair early on a fast tick / clock skew, but stays WELL above 0 so a
# collapsed/simultaneous-drain run (the original flake) still FAILS loudly:
# this remains a meaningful assertion that retries ARE spaced by backoff.
# -------------------------------------------------------------------------

RETRY_MIN=(20 40 84)
RETRY_MAX=(72 108 180)

begin_test "Retry intervals for attempts 1..3 fall within v2 schedule (+/-20% jitter)"
if [ "$SUITE_BLOCKED" = "true" ] || [ -z "$WEBHOOK_ID" ]; then
  skip "no webhook id"
else
  # We need EXPECT_ATTEMPTS+1 POSTs for our repo: the initial failing dial
  # plus one POST per observed retry (attempts 1..N), where the (N+1)th POST
  # is the one whose preceding gap closes attempt N. With FAIL_FIRST_N >=
  # EXPECT_ATTEMPTS the receiver keeps rejecting through attempt N, so all N
  # spaced retries materialize.
  expected_entries=$(( EXPECT_ATTEMPTS + 1 ))

  # Poll on the count of OUR repo's POSTs (entity_id filtered), and require it
  # to be STABLE for one extra poll before measuring -- this guards against
  # reading mid-write (a half-written final line) and against a retry POST
  # that is in-flight when we snapshot. Bail at WEBHOOK_RETRY_TIMEOUT.
  elapsed=0
  poll=5
  prev_seen=-1
  stable=0
  observed=0
  while [ "$elapsed" -lt "$WEBHOOK_RETRY_TIMEOUT" ]; do
    # Single-line-robust count (see the seen= site above, #309).
    observed=$(select_repo_posts | awk 'END{print NR}') || observed=0
    if [ "$observed" -ge "$expected_entries" ]; then
      if [ "$observed" -eq "$prev_seen" ]; then
        stable=$(( stable + 1 ))
        [ "$stable" -ge 1 ] && break
      else
        stable=0
      fi
    fi
    prev_seen="$observed"
    sleep "$poll"
    elapsed=$(( elapsed + poll ))
  done

  if [ "$observed" -lt "$expected_entries" ]; then
    fail "only ${observed} POST(s) for repo ${REPO_KEY} observed within ${WEBHOOK_RETRY_TIMEOUT}s (need ${expected_entries}); the retry scheduler did not deliver the expected attempts (FAIL_FIRST_N=${WEBHOOK_FAIL_FIRST_N})"
  else
    # Pull the FIRST `expected_entries` timestamps for our repo, oldest-first.
    # (Oldest-first is the genuine attempt order; taking the tail could splice
    # in a stray late POST.)
    mapfile -t ts_lines < <(select_repo_posts | head -n "$expected_entries")
    if [ "${#ts_lines[@]}" -lt "$expected_entries" ]; then
      fail "could not parse ${expected_entries} timestamps for repo ${REPO_KEY} from receiver log"
    else
      bad=""
      deltas=""
      for i in $(seq 1 "$EXPECT_ATTEMPTS"); do
        prev="${ts_lines[$((i-1))]}"
        curr="${ts_lines[$i]}"
        # Integer delta (sec). awk handles the float subtraction.
        delta=$(awk -v a="$curr" -v b="$prev" 'BEGIN { printf "%d", (a - b) }')
        deltas="${deltas} a${i}=${delta}s"
        min="${RETRY_MIN[$((i-1))]}"
        max="${RETRY_MAX[$((i-1))]}"
        if [ "$delta" -lt "$min" ] || [ "$delta" -gt "$max" ]; then
          bad="${bad} attempt${i}_delta=${delta}s(expected_${min}-${max})"
        fi
      done
      if [ -z "$bad" ]; then
        echo "    observed retry gaps:${deltas}"
        pass
      else
        fail "retry interval(s) outside v2 backoff+tick window:${bad}" \
             "observed gaps:${deltas}; windows attempt1=${RETRY_MIN[0]}-${RETRY_MAX[0]} attempt2=${RETRY_MIN[1]}-${RETRY_MAX[1]} attempt3=${RETRY_MIN[2]}-${RETRY_MAX[2]}. delta=0 across the board => simultaneous drain (receiver contamination) not real backoff."
      fi
    fi
  fi
fi

# -------------------------------------------------------------------------
# X-ArtifactKeeper-Retry-Attempt numbers the attempt being sent. Producer rows
# are only ever sent by the retry path (webhooks.rs deliver_one_claimed_webhook
# sets retry_attempt = attempts + 1), so the initial POST carries 1 and the
# first retry 2. Assert the second POST's counter is exactly one more than the
# first's: a bare ">= 1" would also pass on a first attempt. The retry must
# also be a re-send of the SAME delivery row (same X-ArtifactKeeper-Delivery
# id), not a second event.
# -------------------------------------------------------------------------

begin_test "X-ArtifactKeeper-Retry-Attempt header present on retry deliveries"
if [ "$SUITE_BLOCKED" = "true" ] || [ ! -s "$WEBHOOK_RECEIVER_LOG" ]; then
  skip "no receiver log"
else
  # Compare the FIRST and SECOND POSTs for OUR artifact (entity_id filtered):
  # the initial delivery and its first retry.
  # Single-line-robust count (see the seen= site above, #309).
  repo_post_count=$(select_repo_records | awk 'END{print NR}') || repo_post_count=0
  if [ "$repo_post_count" -lt 2 ]; then
    fail "only ${repo_post_count} delivery POST(s) for repo ${REPO_KEY}; cannot check retry header (expected the first retry to have fired)"
  else
    # Case-insensitive header lookups: the receiver logs names as sent
    # (reqwest sends them lowercase). One "<attempt> <delivery>" line per POST.
    attempt_lines=$(select_repo_records | sed -n '1,2p' | jq -r '
      .headers | to_entries
      | (map(select((.key | ascii_downcase) == "x-artifactkeeper-retry-attempt")) | .[0].value // "-")
        + " "
        + (map(select((.key | ascii_downcase) == "x-artifactkeeper-delivery")) | .[0].value // "-")' \
      2>/dev/null) || attempt_lines=""
    read -r first_attempt first_delivery <<< "$(echo "$attempt_lines" | sed -n '1p')" || true
    read -r retry_attempt second_delivery <<< "$(echo "$attempt_lines" | sed -n '2p')" || true
    if ! [[ "${first_attempt:-}" =~ ^[0-9]+$ && "${retry_attempt:-}" =~ ^[0-9]+$ ]]; then
      fail "expected numeric X-ArtifactKeeper-Retry-Attempt on both POSTs, got '${first_attempt:-}' then '${retry_attempt:-}'"
    elif [ "$retry_attempt" -lt 2 ] || [ "$retry_attempt" -ne $(( first_attempt + 1 )) ]; then
      fail "retry POST's X-ArtifactKeeper-Retry-Attempt is ${retry_attempt}, expected $(( first_attempt + 1 )) (initial POST carried ${first_attempt})"
    elif [ "${first_delivery:--}" = "-" ] || [ "$first_delivery" != "${second_delivery:-}" ]; then
      fail "second POST is not a retry of the first delivery: X-ArtifactKeeper-Delivery '${first_delivery:-}' then '${second_delivery:-}'"
    else
      pass
    fi
  fi
fi

# -------------------------------------------------------------------------
# Cleanup.
# -------------------------------------------------------------------------

if [ -n "$WEBHOOK_ID" ] && [ "$WEBHOOK_ID" != "null" ]; then
  api_delete "/api/v1/webhooks/${WEBHOOK_ID}" >/dev/null 2>&1 || true
fi

end_suite
