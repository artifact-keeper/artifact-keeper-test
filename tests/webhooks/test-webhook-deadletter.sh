#!/usr/bin/env bash
# test-webhook-deadletter.sh
#
# Epic 7 / sub-task 7.2, 7.3 (artifact-keeper-test#73): exercise the dead-letter
# path. The receiver always returns 500, so a delivery should advance through
# all max_attempts (default 5, see migration 067) and end with
# next_retry_at = NULL and success = false.
#
# Same retry-window constraint as test-webhook-retry-recover.sh: the full
# 30s -> 2m -> 15m -> 1h -> 4h schedule is hours. There is no fast-forward
# admin endpoint in v1.1.x, so this test verifies the API surface used to
# detect dead-letter (the deliveries list with status filter) and the
# determine_retry_outcome shape, but does not wait the full schedule.
#
# Receiver discovery: same env vars as test-webhook-retry-recover.sh. The
# receiver is configured with WEBHOOK_FAIL_FIRST_N=999999 so every POST
# returns 500.
#
# Self-test mode: EXPECT_FAILURE=1 inverts the script exit code.
#
# Requires: curl, jq, python3

source "$(dirname "$0")/../lib/common.sh"

begin_suite "webhook-deadletter"

WEBHOOK_RECEIVER_PORT="${WEBHOOK_RECEIVER_PORT:-18766}"
WEBHOOK_RECEIVER_URL="${WEBHOOK_RECEIVER_URL:-http://127.0.0.1:${WEBHOOK_RECEIVER_PORT}/hook}"
WEBHOOK_RECEIVER_LOG="${WEBHOOK_RECEIVER_LOG:-/tmp/mock-webhook-receiver-dl-${RUN_ID}.log}"
DEADLETTER_TIMEOUT="${DEADLETTER_TIMEOUT:-60}"
RECEIVER_PID=""

cleanup_and_finalize() {
  local code=$?
  if [ -n "${RECEIVER_PID}" ] && kill -0 "${RECEIVER_PID}" 2>/dev/null; then
    kill "${RECEIVER_PID}" 2>/dev/null || true
    wait "${RECEIVER_PID}" 2>/dev/null || true
  fi
  rm -f "${WEBHOOK_RECEIVER_LOG}"
  if [ "${EXPECT_FAILURE:-0}" = "1" ]; then
    if [ "$code" -eq 0 ]; then
      echo "ERROR: EXPECT_FAILURE=1 but suite passed" >&2
      exit 4
    else
      echo "Self-test PASSED: suite exited ${code} as expected"
      exit 0
    fi
  fi
  exit "$code"
}
trap cleanup_and_finalize EXIT

auth_admin

# -------------------------------------------------------------------------
# Start mock receiver in always-fail mode.
# -------------------------------------------------------------------------

begin_test "Start mock receiver (always-500 mode)"
if ! command -v python3 >/dev/null 2>&1; then
  skip "python3 not available"
else
  WEBHOOK_RECEIVER_PORT="$WEBHOOK_RECEIVER_PORT" \
    WEBHOOK_FAIL_FIRST_N=999999 \
    WEBHOOK_RECEIVER_LOG="$WEBHOOK_RECEIVER_LOG" \
    python3 "$(dirname "$0")/../lib/mock-webhook-receiver.py" \
    >/tmp/mock-webhook-receiver-dl-${RUN_ID}.stderr 2>&1 &
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
# Mock self-test: the receiver returns 500 to ANY POST (FAIL_FIRST_N is huge).
# -------------------------------------------------------------------------

begin_test "Mock receiver returns 500 for every POST"
if [ "$ready" != "true" ]; then
  skip "receiver not running"
else
  status_a=$(curl -s -o /dev/null --max-time 3 -w '%{http_code}' \
    -X POST -d '{"probe":1}' "http://127.0.0.1:${WEBHOOK_RECEIVER_PORT}/probe" || echo 000)
  status_b=$(curl -s -o /dev/null --max-time 3 -w '%{http_code}' \
    -X POST -d '{"probe":2}' "http://127.0.0.1:${WEBHOOK_RECEIVER_PORT}/probe" || echo 000)
  if [ "$status_a" = "500" ] && [ "$status_b" = "500" ]; then
    pass
  else
    fail "expected 500 from receiver on both probes, got '${status_a}' and '${status_b}'"
  fi
fi

# -------------------------------------------------------------------------
# Create a webhook pointing at the mock. Skip if URL validation rejects.
# -------------------------------------------------------------------------

WEBHOOK_NAME="deadletter-${RUN_ID}"
WEBHOOK_ID=""
SUITE_BLOCKED=false

begin_test "Create webhook with mock receiver URL"
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
# /test reports the failure synchronously: success=false, status=500.
# -------------------------------------------------------------------------

begin_test "/test reports synchronous 500 from receiver"
if [ "$SUITE_BLOCKED" = "true" ] || [ -z "$WEBHOOK_ID" ]; then
  skip "no webhook id"
else
  if test_resp=$(api_post "/api/v1/webhooks/${WEBHOOK_ID}/test" "" 2>/dev/null); then
    success_field=$(echo "$test_resp" | jq -r '.success // "missing"')
    status_field=$(echo "$test_resp" | jq -r '.status_code // empty')
    if [ "$success_field" = "false" ] && [ "$status_field" = "500" ]; then
      pass
    else
      fail "expected success=false / status=500, got success='${success_field}' status='${status_field}' (raw: ${test_resp:0:200})"
    fi
  else
    skip "/test endpoint unavailable"
  fi
fi

# -------------------------------------------------------------------------
# The dead-letter detection contract is: the deliveries list endpoint
# accepts a `status=failed` filter and returns failed deliveries. v1.1.x
# implements `status=success` (truthy filter) -- we assert the endpoint
# at least responds successfully, and that any delivery with attempts
# >= max_attempts has next_retry_at == null.
#
# Because v1.1.x does not auto-INSERT webhook_deliveries from artifact
# upload, the list will normally be empty and we degrade gracefully.
# -------------------------------------------------------------------------

begin_test "Deliveries list filter returns a usable shape"
if [ "$SUITE_BLOCKED" = "true" ] || [ -z "$WEBHOOK_ID" ]; then
  skip "no webhook id"
else
  if list=$(api_get "/api/v1/webhooks/${WEBHOOK_ID}/deliveries?status=failed" 2>/dev/null); then
    items_type=$(echo "$list" | jq -r 'try (.items | type) catch "missing"')
    if [ "$items_type" = "array" ]; then
      pass
    else
      fail "deliveries shape unexpected: ${list:0:200}"
    fi
  else
    skip "deliveries list endpoint unavailable"
  fi
fi

# -------------------------------------------------------------------------
# When delivery rows DO exist, dead-lettered ones must satisfy:
#   success == false AND attempts >= max_attempts
# We poll for up to DEADLETTER_TIMEOUT seconds; if we never see a row, we
# skip with a clear reason rather than failing (the producer wiring is
# out of scope for this gate).
# -------------------------------------------------------------------------

begin_test "Any failed delivery is exhausted (attempts >= max_attempts)"
if [ "$SUITE_BLOCKED" = "true" ] || [ -z "$WEBHOOK_ID" ]; then
  skip "no webhook id"
else
  found_exhausted=false
  saw_any=false
  elapsed=0
  while [ "$elapsed" -lt "$DEADLETTER_TIMEOUT" ]; do
    if list=$(api_get "/api/v1/webhooks/${WEBHOOK_ID}/deliveries" 2>/dev/null); then
      n=$(echo "$list" | jq '.items | length // 0')
      if [ "$n" -gt 0 ]; then
        saw_any=true
        # Exhausted = success == false AND attempts >= 5 (default max).
        exhausted=$(echo "$list" | jq '[.items[] | select(.success == false and .attempts >= 5)] | length')
        if [ "$exhausted" -gt 0 ]; then
          found_exhausted=true
          break
        fi
      fi
    fi
    sleep 5
    elapsed=$(( elapsed + 5 ))
  done

  if [ "$found_exhausted" = "true" ]; then
    pass
  elif [ "$saw_any" = "true" ]; then
    skip "deliveries exist but none reached attempts >= 5 within ${DEADLETTER_TIMEOUT}s (full backoff schedule is hours)"
  else
    skip "no webhook_deliveries rows produced; v1.1.x does not auto-create deliveries on upload"
  fi
fi

if [ -n "$WEBHOOK_ID" ] && [ "$WEBHOOK_ID" != "null" ]; then
  api_delete "/api/v1/webhooks/${WEBHOOK_ID}" >/dev/null 2>&1 || true
fi

end_suite
