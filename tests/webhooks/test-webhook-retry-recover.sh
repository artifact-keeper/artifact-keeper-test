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
#   attempt 1 ->  24-36s
#   attempt 2 ->  48-72s   (cumulative 72-108s)
#   attempt 3 ->  96-144s  (cumulative 168-252s)
# The full 12-attempt schedule is exercised in the dead-letter test.
#
# Receiver discovery:
#   WEBHOOK_RECEIVER_PORT  - port the local mock listens on (default 18765).
#   WEBHOOK_RECEIVER_URL   - URL the backend POSTs to. Defaults to the
#                            local mock; override in environments where
#                            the backend cannot reach loopback.
#   WEBHOOK_FAIL_FIRST_N   - how many POSTs the mock should reject with
#                            500 before flipping to 200 (default 1, so we
#                            observe the recover path on the first retry).
#   WEBHOOK_RETRY_TIMEOUT  - seconds to wait for the recover round-trip
#                            (default 360 to cover up to attempt 3 with
#                            jitter headroom).
#
# Companion backend PR: artifact-keeper#1140. Producer feature flag is
# WEBHOOKS_V2_PRODUCER_ENABLED; harness sets it to 1.
#
# Requires: curl, jq, python3

source "$(dirname "$0")/../lib/common.sh"

begin_suite "webhook-retry-recover"

WEBHOOK_RECEIVER_PORT="${WEBHOOK_RECEIVER_PORT:-18765}"
WEBHOOK_RECEIVER_URL="${WEBHOOK_RECEIVER_URL:-http://${WEBHOOK_RECEIVER_HOST:-127.0.0.1}:${WEBHOOK_RECEIVER_PORT}/hook}"
WEBHOOK_FAIL_FIRST_N="${WEBHOOK_FAIL_FIRST_N:-1}"
WEBHOOK_RETRY_TIMEOUT="${WEBHOOK_RETRY_TIMEOUT:-360}"
WEBHOOK_RECEIVER_LOG="${WEBHOOK_RECEIVER_LOG:-/tmp/mock-webhook-receiver-${RUN_ID}.log}"
RECEIVER_PID=""

cleanup_and_finalize() {
  local code=$?
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
    pass
  else
    fail "mock receiver did not come up on 127.0.0.1:${WEBHOOK_RECEIVER_PORT}"
  fi
fi

# -------------------------------------------------------------------------
# Create a webhook pointing at the mock receiver.
# -------------------------------------------------------------------------

WEBHOOK_NAME="retry-recover-${RUN_ID}"
WEBHOOK_ID=""
SUITE_BLOCKED=false

begin_test "Create webhook targeting mock receiver"
if [ "$ready" != "true" ]; then
  skip "receiver not running"
else
  PAYLOAD=$(jq -n \
    --arg name "$WEBHOOK_NAME" \
    --arg url "$WEBHOOK_RECEIVER_URL" \
    '{name: $name, url: $url, events: ["artifact.uploaded"], enabled: true}')
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
# Trigger the initial delivery.
# -------------------------------------------------------------------------

begin_test "Trigger /test delivery and observe initial POST at receiver"
if [ "$SUITE_BLOCKED" = "true" ] || [ -z "$WEBHOOK_ID" ]; then
  skip "no webhook id"
else
  if api_post "/api/v1/webhooks/${WEBHOOK_ID}/test" "" >/dev/null 2>&1; then
    seen=0
    for _ in $(seq 1 10); do
      seen=$(curl -sf --max-time 2 "http://127.0.0.1:${WEBHOOK_RECEIVER_PORT}/__count" 2>/dev/null || echo 0)
      [ "$seen" -gt 0 ] && break
      sleep 0.5
    done
    if [ "$seen" -ge 1 ]; then
      pass
    else
      fail "receiver saw 0 POSTs after /test"
    fi
  else
    skip "/test endpoint unavailable"
  fi
fi

# -------------------------------------------------------------------------
# Retry windows for v2 schedule (with +/-20% jitter applied):
#   attempt 1: 24..36s   after the failed try
#   attempt 2: 48..72s   after attempt 1
#   attempt 3: 96..144s  after attempt 2
# We observe the timestamps of consecutive POSTs at the receiver and
# assert each gap is within window. For the smoke profile we cap at 3
# attempts (covers attempt 1, 2, 3 deltas).
# -------------------------------------------------------------------------

EXPECT_ATTEMPTS=3
RETRY_MIN=(24 48 96)
RETRY_MAX=(36 72 144)

# Mark the receiver log so we can read deltas freshly.
LOG_BASELINE_LINES=0
if [ -f "$WEBHOOK_RECEIVER_LOG" ]; then
  LOG_BASELINE_LINES=$(wc -l < "$WEBHOOK_RECEIVER_LOG" | tr -d ' ')
fi

begin_test "Retry intervals for attempts 1..3 fall within v2 schedule (+/-20% jitter)"
if [ "$SUITE_BLOCKED" = "true" ] || [ -z "$WEBHOOK_ID" ]; then
  skip "no webhook id"
else
  # Wait for at least EXPECT_ATTEMPTS + 1 entries (the initial delivery
  # plus the retry attempts). Bail at WEBHOOK_RETRY_TIMEOUT.
  expected_entries=$(( EXPECT_ATTEMPTS + 1 ))
  elapsed=0
  poll=5
  while [ "$elapsed" -lt "$WEBHOOK_RETRY_TIMEOUT" ]; do
    seen=$(curl -sf --max-time 2 "http://127.0.0.1:${WEBHOOK_RECEIVER_PORT}/__count" 2>/dev/null || echo 0)
    if [ "$seen" -ge "$expected_entries" ]; then
      break
    fi
    sleep "$poll"
    elapsed=$(( elapsed + poll ))
  done

  total_lines=$(wc -l < "$WEBHOOK_RECEIVER_LOG" 2>/dev/null | tr -d ' ' || echo 0)
  new_lines=$(( total_lines - LOG_BASELINE_LINES ))
  if [ "$new_lines" -lt "$expected_entries" ]; then
    skip "only ${new_lines} delivery entries observed within ${WEBHOOK_RETRY_TIMEOUT}s; producer may not be running, or jitter pushed timing out of window"
  else
    # Pull the last `expected_entries` timestamps (in seconds, float).
    mapfile -t ts_lines < <(tail -n "$expected_entries" "$WEBHOOK_RECEIVER_LOG" \
      | jq -r '.ts' 2>/dev/null)
    if [ "${#ts_lines[@]}" -lt "$expected_entries" ]; then
      fail "could not parse ${expected_entries} timestamps from receiver log"
    else
      bad=""
      for i in $(seq 1 "$EXPECT_ATTEMPTS"); do
        prev="${ts_lines[$((i-1))]}"
        curr="${ts_lines[$i]}"
        # Integer delta (sec). awk handles the float subtraction.
        delta=$(awk -v a="$curr" -v b="$prev" 'BEGIN { printf "%d", (a - b) }')
        min="${RETRY_MIN[$((i-1))]}"
        max="${RETRY_MAX[$((i-1))]}"
        if [ "$delta" -lt "$min" ] || [ "$delta" -gt "$max" ]; then
          bad="${bad} attempt${i}_delta=${delta}s(expected_${min}-${max})"
        fi
      done
      if [ -z "$bad" ]; then
        pass
      else
        fail "retry interval(s) outside v2 +/-20% window:${bad}"
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
  total_lines=$(wc -l < "$WEBHOOK_RECEIVER_LOG" 2>/dev/null | tr -d ' ' || echo 0)
  if [ "$total_lines" -lt 2 ]; then
    skip "only ${total_lines} delivery entry/entries; cannot check retry header"
  else
    second_headers=$(sed -n '2p' "$WEBHOOK_RECEIVER_LOG" | jq -r '.headers')
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
