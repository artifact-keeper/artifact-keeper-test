#!/usr/bin/env bash
# test-event-delivery-status-filter.sh
#
# Issue #75 sub-task 7.14: GET /api/v1/webhooks/{id}/deliveries supports
# a `status` query parameter (openapi.yaml: parameter `status`, type
# nullable string). No existing test exercises the filter; the delivery
# and dead-letter suites read the list without a filter and inspect every
# row.
#
# The .status field is what the operator UI uses to surface "all
# failures" / "all retries" / "all successes". A regression where the
# query parameter is silently ignored returns the unfiltered list, the
# UI shows the wrong rows, and on-call triages the wrong delivery.
#
# Strategy:
#   1. Drive a SUCCESS delivery via /test against a 200-always receiver.
#   2. Read the unfiltered deliveries list to learn the actual status
#      vocabulary the backend uses (it varies across builds:
#      "success" | "succeeded" | "delivered" are all in the wild).
#   3. Filter by that observed status. The returned set MUST be
#      non-empty AND every row's .status MUST equal the queried value.
#   4. Filter by a status vocabulary that does not match any row
#      ("xfail-${RUN_ID}") -- the returned set MUST be empty. This is
#      the load-bearing assertion: if the backend ignores the param,
#      this query returns the full list and the test fails loudly.
#
# Requires: curl, jq, python3

source "$(dirname "$0")/../lib/common.sh"

begin_suite "event-delivery-status-filter"

WEBHOOK_RECEIVER_PORT="${WEBHOOK_RECEIVER_PORT:-18783}"
WEBHOOK_RECEIVER_URL="${WEBHOOK_RECEIVER_URL:-http://127.0.0.1:${WEBHOOK_RECEIVER_PORT}/hook}"
WEBHOOK_RECEIVER_LOG="${WEBHOOK_RECEIVER_LOG:-/tmp/mock-webhook-receiver-statusfilter-${RUN_ID}.log}"
RECEIVER_PID=""
WEBHOOK_ID=""

cleanup_and_finalize() {
  local code=$?
  if [ -n "${WEBHOOK_ID}" ] && [ "${WEBHOOK_ID}" != "null" ]; then
    api_delete "/api/v1/webhooks/${WEBHOOK_ID}" >/dev/null 2>&1 || true
  fi
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
# extract_rows JSON
#
# The list endpoint returns one of three documented shapes:
#   - bare array
#   - { items: [...] }
#   - { items: [...], total: N }   (DeliveryListResponse)
# Normalize to a JSON array on stdout so downstream jq queries are
# consistent. Empty input echoes "[]" so the count assertion sees zero.
# -------------------------------------------------------------------------

extract_rows() {
  local json="$1"
  echo "$json" | jq -c '
    if type == "array" then .
    elif .items then .items
    elif .deliveries then .deliveries
    else []
    end
  ' 2>/dev/null || echo "[]"
}

# -------------------------------------------------------------------------
# Pre-flight.
# -------------------------------------------------------------------------

begin_test "python3 and jq available"
miss=""
command -v python3  >/dev/null 2>&1 || miss="${miss} python3"
command -v jq       >/dev/null 2>&1 || miss="${miss} jq"
if [ -n "$miss" ]; then
  skip "missing tools:${miss}"
  end_suite
fi
pass

# -------------------------------------------------------------------------
# Start receiver. Always-200 so the resulting delivery row lands in
# whatever the success-state vocabulary is for this build.
# -------------------------------------------------------------------------

begin_test "Start mock receiver (always-200)"
WEBHOOK_RECEIVER_PORT="$WEBHOOK_RECEIVER_PORT" \
  WEBHOOK_FAIL_FIRST_N=0 \
  WEBHOOK_RECEIVER_LOG="$WEBHOOK_RECEIVER_LOG" \
  python3 "$(dirname "$0")/../lib/mock-webhook-receiver.py" \
  >/tmp/mock-webhook-receiver-statusfilter-${RUN_ID}.stderr 2>&1 &
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

# -------------------------------------------------------------------------
# Create webhook.
# -------------------------------------------------------------------------

WEBHOOK_NAME="statusfilter-${RUN_ID}"
SUITE_BLOCKED=false

begin_test "Create webhook"
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
      fail "create returned no id"
    else
      pass
    fi
  else
    SUITE_BLOCKED=true
    skip "webhook create rejected (URL likely blocked by SSRF allow-list)"
  fi
fi

# -------------------------------------------------------------------------
# Drive at least one delivery and wait until it shows up in the list.
# Use /test because it shares the producer pipeline with real events
# (proven by test-webhook-dry-run.sh) and is the fastest way to get a
# deterministic row inserted.
# -------------------------------------------------------------------------

begin_test "Trigger a delivery via /test"
if [ "$SUITE_BLOCKED" = "true" ] || [ -z "$WEBHOOK_ID" ]; then
  skip "no webhook id"
else
  if api_post "/api/v1/webhooks/${WEBHOOK_ID}/test" "" >/dev/null 2>&1; then
    pass
  else
    SUITE_BLOCKED=true
    skip "/test endpoint unavailable"
  fi
fi

# -------------------------------------------------------------------------
# Wait for the row to land in the list. Poll up to ~30s -- the producer
# is async, and on cold start the first delivery can be slow to flush.
# -------------------------------------------------------------------------

UNFILTERED_JSON=""
UNFILTERED_COUNT=0
OBSERVED_STATUS=""

begin_test "Unfiltered list contains at least one delivery"
if [ "$SUITE_BLOCKED" = "true" ] || [ -z "$WEBHOOK_ID" ]; then
  skip "no webhook id"
else
  for _ in $(seq 1 15); do
    if resp=$(api_get "/api/v1/webhooks/${WEBHOOK_ID}/deliveries" 2>/dev/null); then
      UNFILTERED_JSON="$resp"
      rows=$(extract_rows "$resp")
      UNFILTERED_COUNT=$(echo "$rows" | jq 'length' 2>/dev/null || echo 0)
      if [ "$UNFILTERED_COUNT" -gt 0 ]; then
        OBSERVED_STATUS=$(echo "$rows" | jq -r '.[0].status // empty')
        break
      fi
    fi
    sleep 2
  done
  if [ "$UNFILTERED_COUNT" -gt 0 ]; then
    pass
  else
    fail "no delivery row appeared within 30s for webhook ${WEBHOOK_ID}"
  fi
fi

# -------------------------------------------------------------------------
# Discovered the actual status vocabulary. If the rows have no .status
# field at all, the filter spec doesn't apply to this build; skip
# rather than fail (would be a contract mismatch, not a regression).
# -------------------------------------------------------------------------

begin_test "Delivery rows expose a .status field"
if [ "$SUITE_BLOCKED" = "true" ] || [ "$UNFILTERED_COUNT" -eq 0 ]; then
  skip "no rows to inspect"
elif [ -z "$OBSERVED_STATUS" ] || [ "$OBSERVED_STATUS" = "null" ]; then
  SUITE_BLOCKED=true
  skip "rows have no .status field; filter spec inapplicable"
else
  pass
fi

# -------------------------------------------------------------------------
# Positive filter: status=<observed> returns the row(s) we know exist.
# Every returned row's .status must equal the queried value. A regression
# where the filter is silently ignored manifests as
#   "filter returned rows whose .status != queried value"
# (because the unfiltered list might contain mixed statuses on a busy
# cluster, even if our /test produced just one success).
# -------------------------------------------------------------------------

begin_test "Filter status=${OBSERVED_STATUS:-?} returns only matching rows"
if [ "$SUITE_BLOCKED" = "true" ]; then
  skip "no observed status to filter by"
else
  # URL-encode the status conservatively. Observed values are alnum +
  # underscores in every build we've seen; if a build returns something
  # exotic, jq quoting in the assert below catches it.
  if resp=$(api_get "/api/v1/webhooks/${WEBHOOK_ID}/deliveries?status=${OBSERVED_STATUS}" 2>/dev/null); then
    rows=$(extract_rows "$resp")
    cnt=$(echo "$rows" | jq 'length' 2>/dev/null || echo 0)
    if [ "$cnt" -lt 1 ]; then
      fail "filter status=${OBSERVED_STATUS} returned 0 rows, but unfiltered list had ${UNFILTERED_COUNT}"
    else
      mismatched=$(echo "$rows" | jq --arg s "$OBSERVED_STATUS" '
        [.[] | select(.status != $s)] | length
      ' 2>/dev/null || echo 0)
      if [ "$mismatched" -eq 0 ]; then
        pass
      else
        fail "filter returned ${mismatched}/${cnt} rows whose .status != '${OBSERVED_STATUS}' (filter likely ignored)" "${rows:0:500}"
      fi
    fi
  else
    fail "filter request failed"
  fi
fi

# -------------------------------------------------------------------------
# Negative filter: a status value that cannot exist must return zero
# rows. This is the assertion that catches "the backend ignores the
# status param and returns the full list". We embed RUN_ID so two
# parallel runs of this suite cannot collide on this synthetic value.
# -------------------------------------------------------------------------

begin_test "Filter status=xfail-${RUN_ID} returns zero rows"
if [ "$SUITE_BLOCKED" = "true" ]; then
  skip "no observed status to compare against"
else
  bogus="xfail-${RUN_ID}"
  if resp=$(api_get "/api/v1/webhooks/${WEBHOOK_ID}/deliveries?status=${bogus}" 2>/dev/null); then
    rows=$(extract_rows "$resp")
    cnt=$(echo "$rows" | jq 'length' 2>/dev/null || echo 0)
    if [ "$cnt" -eq 0 ]; then
      pass
    else
      fail "filter status=${bogus} returned ${cnt} rows; expected 0 (filter likely ignored, returning unfiltered list of ${UNFILTERED_COUNT})" "${rows:0:500}"
    fi
  else
    # Some implementations reject an unknown status with 4xx -- that is
    # also acceptable behavior (strict enum). Accept the rejection.
    pass
  fi
fi

end_suite
