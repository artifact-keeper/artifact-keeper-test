#!/usr/bin/env bash
# test-webhook-deadletter.sh
#
# Webhooks v2 wire contract (artifact-keeper#919, E5): exercise the dead-
# letter path. The receiver always returns 500, so a delivery should advance
# through all 12 retry attempts and end with the webhook auto-disabled
# (is_enabled = false, disabled_reason non-null).
#
# Retry schedule (jittered +/-20%):
#   30s, 1m, 2m, 5m, 10m, 30m, 1h, 2h, 4h, 8h, 16h, 24h
# Total walltime is ~65h; this test does NOT wait the full schedule. It
# verifies the wire contract, the API surface used to query failed
# deliveries, and the auto-disable shape on rows that have already
# exhausted attempts (if the producer has populated any in the test
# window).
#
# Receiver discovery: WEBHOOK_RECEIVER_PORT (default in 18000-19000 range).
# The receiver runs on the test runner with WEBHOOK_FAIL_FIRST_N=999999 so
# every POST returns 500.
#
# Companion backend PR: artifact-keeper#1140. The producer feature flag is
# WEBHOOKS_V2_PRODUCER_ENABLED; the harness sets it to 1.
#
# Requires: curl, jq, python3

source "$(dirname "$0")/../lib/common.sh"

begin_suite "webhook-deadletter"

WEBHOOK_RECEIVER_PORT="${WEBHOOK_RECEIVER_PORT:-18766}"
WEBHOOK_RECEIVER_URL="${WEBHOOK_RECEIVER_URL:-http://${WEBHOOK_RECEIVER_HOST:-127.0.0.1}:${WEBHOOK_RECEIVER_PORT}/hook}"
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
# Mock self-test: receiver returns 500 to every POST.
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
# Create a webhook pointing at the mock receiver.
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
    # NOTE: do not use `.success // "missing"`. jq's `//` operator treats a
    # boolean `false` as an absent value, so `.success // "missing"` returns
    # "missing" for a correct `{"success": false}` response. The backend
    # returns the right payload (TestWebhookResponse { success: false,
    # status_code: 500, ... }); the old jq path mis-extracted it. Branch on
    # has("success") so a genuine false is read as "false".
    success_field=$(echo "$test_resp" | jq -r 'if has("success") then (.success | tostring) else "missing" end')
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
# Deliveries-list filter shape check.
# -------------------------------------------------------------------------

begin_test "Deliveries list with status=failed returns a usable shape"
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
#   success == false AND attempts >= max_attempts (default 12 in v2).
# -------------------------------------------------------------------------

SAW_EXHAUSTED=false

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
        # In v2 the default budget is 12. Fall back to whatever max_attempts
        # the row carries so older rows (default 5) don't false-fail.
        exhausted=$(echo "$list" | jq '
          [.items[] | select(.success == false and (.attempts >= (.max_attempts // 12)))]
          | length')
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
    SAW_EXHAUSTED=true
    pass
  elif [ "$saw_any" = "true" ]; then
    skip "deliveries exist but none reached max_attempts within ${DEADLETTER_TIMEOUT}s (full v2 schedule is ~65h walltime)"
  else
    skip "no webhook_deliveries rows produced in window"
  fi
fi

# -------------------------------------------------------------------------
# Auto-disable on dead-letter (v2 contract): once max_attempts is exhausted
# the webhook itself is flipped to is_enabled=false with a non-null
# disabled_reason. We assert this on the webhook row only when we observed
# an exhausted delivery in the previous step (otherwise the auto-disable
# branch has not been reached yet and asserting would false-fail).
# -------------------------------------------------------------------------

begin_test "Auto-disable: webhook is_enabled=false and disabled_reason non-null after dead-letter"
if [ "$SUITE_BLOCKED" = "true" ] || [ -z "$WEBHOOK_ID" ]; then
  skip "no webhook id"
elif [ "$SAW_EXHAUSTED" != "true" ]; then
  skip "no exhausted delivery observed in this window; auto-disable branch not exercised"
else
  if hook=$(api_get "/api/v1/webhooks/${WEBHOOK_ID}" 2>/dev/null); then
    enabled=$(echo "$hook" | jq -r '.enabled // .is_enabled // empty')
    reason=$(echo "$hook" | jq -r '.disabled_reason // empty')
    if [ "$enabled" = "false" ] && [ -n "$reason" ] && [ "$reason" != "null" ]; then
      pass
    else
      fail "expected enabled=false and non-null disabled_reason, got enabled='${enabled}' disabled_reason='${reason}' (raw: ${hook:0:200})"
    fi
  else
    fail "could not GET /api/v1/webhooks/${WEBHOOK_ID}"
  fi
fi

if [ -n "$WEBHOOK_ID" ] && [ "$WEBHOOK_ID" != "null" ]; then
  api_delete "/api/v1/webhooks/${WEBHOOK_ID}" >/dev/null 2>&1 || true
fi

end_suite
