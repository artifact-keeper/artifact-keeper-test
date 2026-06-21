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
# release-gate stays under WEBHOOK_RETRY_TIMEOUT (default 360s). The first
# three intervals (30s, 60s, 120s base) plus +/-20% jitter give acceptable
# windows of:
#   attempt 1 ->  24-36s   backoff
#   attempt 2 ->  48-72s   backoff
#   attempt 3 ->  96-144s  backoff
# The full 12-attempt schedule is exercised in the dead-letter test.
#
# IMPORTANT — what we actually measure, and the scheduler-tick quantization
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
# row is marked success/next_retry_at=NULL and NO further POSTs occur — you
# can never observe a 2nd or 3rd retry interval. WEBHOOK_FAIL_FIRST_N is
# therefore defaulted to EXPECT_ATTEMPTS so the receiver rejects attempts
# 1..3 (producing the 3 spaced retry POSTs we measure) and accepts the 4th,
# proving the recover path.
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
#   WEBHOOK_RETRY_TIMEOUT  - seconds to wait for the full attempt-3 round-trip
#                            (default 480 to cover backoff 30+60+120s plus up
#                            to three 30s scheduler ticks plus jitter headroom).
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
WEBHOOK_RECEIVER_URL="${WEBHOOK_RECEIVER_URL:-http://${WEBHOOK_RECEIVER_HOST:-127.0.0.1}:${WEBHOOK_RECEIVER_PORT}/hook}"
# Number of attempts we observe a spaced retry for (attempt 1, 2, 3).
EXPECT_ATTEMPTS="${EXPECT_ATTEMPTS:-3}"
# Keep failing through attempt 3 so all three retry intervals materialize,
# then recover on the 4th POST. MUST be >= EXPECT_ATTEMPTS.
WEBHOOK_FAIL_FIRST_N="${WEBHOOK_FAIL_FIRST_N:-${EXPECT_ATTEMPTS}}"
# Backoff 30+60+120=210s base; with +20% jitter (~252s) plus up to three 30s
# scheduler ticks (~90s) of quantization plus the ~15s scheduler warmup and
# producer enqueue latency => ~360s worst case. 480s gives load headroom.
WEBHOOK_RETRY_TIMEOUT="${WEBHOOK_RETRY_TIMEOUT:-480}"
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

auth_admin

# -------------------------------------------------------------------------
# Start mock receiver.
# -------------------------------------------------------------------------

begin_test "Start mock webhook receiver"
if ! command -v python3 >/dev/null 2>&1; then
  skip "python3 not available"
else
  WEBHOOK_RECEIVER_PORT="$WEBHOOK_RECEIVER_PORT" \
    WEBHOOK_FAIL_FIRST_N="$WEBHOOK_FAIL_FIRST_N" \
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

# -------------------------------------------------------------------------
# Create a webhook pointing at the mock receiver.
# -------------------------------------------------------------------------

WEBHOOK_NAME="retry-recover-${RUN_ID}"
SUITE_BLOCKED=false

begin_test "Create webhook targeting mock receiver"
if [ "$ready" != "true" ]; then
  skip "receiver not running"
else
  PAYLOAD=$(jq -n \
    --arg name "$WEBHOOK_NAME" \
    --arg url "$WEBHOOK_RECEIVER_URL" \
    '{name: $name, url: $url, events: ["repository_created"], enabled: true}')
  if resp=$(api_post "/api/v1/webhooks" "$PAYLOAD" 2>/dev/null); then
    WEBHOOK_ID=$(echo "$resp" | jq -r '.id // empty')
    if [ -z "$WEBHOOK_ID" ] || [ "$WEBHOOK_ID" = "null" ]; then
      fail "webhook create returned no id"
    else
      pass
    fi
  else
    SUITE_BLOCKED=true
    skip "webhook create rejected (URL '${WEBHOOK_RECEIVER_URL}' likely blocked by SSRF allow-list)"
  fi
fi

# -------------------------------------------------------------------------
# Trigger the initial delivery via a REAL event. POST /webhooks/{id}/test
# does NOT insert a webhook_deliveries row (it does a single synchronous
# POST and mints a throwaway id), so the retry scheduler would have nothing
# to retry. The retry engine only acts on real producer-enqueued rows, so we
# create a repository (-> repository.created -> producer inserts a delivery
# row). The mock rejects the first WEBHOOK_FAIL_FIRST_N POSTs with 500, which
# drives the retry-then-recover path we assert on below.
#
# Isolation against sibling deliveries: this webhook is global (repository_id
# NULL), so the producer also enqueues a delivery for it on repository.created
# events fired by OTHER suites running concurrently. Those sibling deliveries
# would land as extra POSTs in this receiver's log and, because they drain in
# the same 30s scheduler tick, collapse the measured retry gaps to 0s -- the
# original flake. We defend against that by capturing THIS repository's id and
# filtering the receiver log down to only the POSTs whose payload .entity_id
# matches it (see select_repo_posts below). Every delivery payload carries
# entity_id = the created repo's UUID (services/webhook_producer.rs
# build_event_payload), so the filter isolates our own retry sequence exactly.
# -------------------------------------------------------------------------

REPO_ID=""

# Echo, oldest-first, the .ts of every receiver-log POST whose payload
# .entity_id matches our repo (falls back to all POSTs if entity_id could not
# be determined, e.g. an older producer that omitted it).
select_repo_posts() {
  if [ -n "$REPO_ID" ]; then
    jq -r --arg rid "$REPO_ID" \
      'select((.body | fromjson? | .entity_id) == $rid) | .ts' \
      "$WEBHOOK_RECEIVER_LOG" 2>/dev/null
  else
    jq -r '.ts' "$WEBHOOK_RECEIVER_LOG" 2>/dev/null
  fi
}

# Echo, oldest-first, the full JSON record of every receiver-log POST whose
# payload .entity_id matches our repo (one compact JSON object per line).
select_repo_records() {
  if [ -n "$REPO_ID" ]; then
    jq -c --arg rid "$REPO_ID" \
      'select((.body | fromjson? | .entity_id) == $rid)' \
      "$WEBHOOK_RECEIVER_LOG" 2>/dev/null
  else
    jq -c '.' "$WEBHOOK_RECEIVER_LOG" 2>/dev/null
  fi
}

begin_test "Trigger delivery via repository.created and observe initial POST at receiver"
if [ "$SUITE_BLOCKED" = "true" ] || [ -z "$WEBHOOK_ID" ]; then
  skip "no webhook id"
else
  REPO_CREATE_PAYLOAD="{\"key\":\"${REPO_KEY}\",\"name\":\"${REPO_KEY}\",\"format\":\"generic\",\"repo_type\":\"local\",\"is_public\":true}"
  if repo_resp=$(api_post "/api/v1/repositories" "$REPO_CREATE_PAYLOAD" 2>/dev/null); then
    REPO_ID=$(echo "$repo_resp" | jq -r '.id // empty')
    seen=0
    # First attempt is rejected (500) by the mock but still lands as a POST;
    # allow generous headroom for the producer's async enqueue + first dial.
    # Count only POSTs that belong to OUR repo so a sibling suite's delivery
    # cannot satisfy this gate.
    for _ in $(seq 1 30); do
      seen=$(select_repo_posts | grep -c . 2>/dev/null || echo 0)
      [ "$seen" -gt 0 ] && break
      sleep 1
    done
    if [ "$seen" -ge 1 ]; then
      pass
    else
      fail "receiver saw 0 POSTs for repo ${REPO_KEY} after repository.created event"
    fi
  else
    SUITE_BLOCKED=true
    skip "repo create (event trigger) failed"
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
    observed=$(select_repo_posts | grep -c . 2>/dev/null || echo 0)
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
# X-ArtifactKeeper-Retry-Attempt is emitted ONLY on retry deliveries
# (per the v2 wire contract). The first delivery has no retry header;
# subsequent deliveries carry attempt counters >= 1.
# -------------------------------------------------------------------------

begin_test "X-ArtifactKeeper-Retry-Attempt header present on retry deliveries"
if [ "$SUITE_BLOCKED" = "true" ] || [ ! -s "$WEBHOOK_RECEIVER_LOG" ]; then
  skip "no receiver log"
else
  # Use the SECOND POST for OUR repo (entity_id filtered): the first POST is
  # the initial delivery (no retry header), the second is retry attempt 1.
  repo_post_count=$(select_repo_records | grep -c . 2>/dev/null || echo 0)
  if [ "$repo_post_count" -lt 2 ]; then
    fail "only ${repo_post_count} delivery POST(s) for repo ${REPO_KEY}; cannot check retry header (expected the first retry to have fired)"
  else
    second_headers=$(select_repo_records | sed -n '2p' | jq -r '.headers')
    retry_attempt=$(echo "$second_headers" | jq -r '
      (.["X-ArtifactKeeper-Retry-Attempt"] //
       .["x-artifactkeeper-retry-attempt"] //
       .["X-ARTIFACTKEEPER-RETRY-ATTEMPT"] // empty)
    ')
    if [ -n "$retry_attempt" ] && [ "$retry_attempt" != "null" ] && \
       [[ "$retry_attempt" =~ ^[0-9]+$ ]] && [ "$retry_attempt" -ge 1 ]; then
      pass
    else
      fail "expected retry-attempt header >= 1 on second delivery, got '${retry_attempt}'"
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
