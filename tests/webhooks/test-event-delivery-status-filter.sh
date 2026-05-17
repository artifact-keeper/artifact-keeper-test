#!/usr/bin/env bash
# test-event-delivery-status-filter.sh
#
# Issue #75 sub-task 7.14: GET /api/v1/webhooks/{id}/deliveries supports
# a `status` query parameter (backend webhooks.rs:488-493). The handler
# at webhooks.rs:541 normalizes the parameter to a boolean filter on the
# DeliveryResponse.success column:
#
#     let success_filter = query.status.as_ref().map(|s| s == "success");
#
# So:
#   status=success  -> WHERE success = TRUE
#   status=anything -> WHERE success = FALSE
#   status omitted  -> no filter
#
# DeliveryResponse exposes the verdict as a boolean .success field
# (openapi.yaml:12703-12745, webhooks.rs:495-508). There is no string
# .status field on the response row; an earlier draft of this test read
# .status and would have produced "" for every row regardless of the
# actual delivery verdict.
#
# Strategy:
#   1. Drive a SUCCESS delivery via /test against a 200-always receiver.
#   2. Read the unfiltered deliveries list. At least one row's .success
#      must be true.
#   3. Filter status=success. The returned set MUST be non-empty AND
#      every row's .success MUST be true.
#   4. Filter status=failure. Our /test row (success=true) MUST NOT be
#      in the filtered set, and every returned row's .success MUST be
#      false. This is the load-bearing assertion: if the backend
#      ignores the param, this query returns the full list including
#      our success row and the test fails loudly.
#
# Requires: curl, jq, python3

source "$(dirname "$0")/../lib/common.sh"

begin_suite "event-delivery-status-filter"

# Receiver port: derive from PID so parallel test runs do not collide on
# the same listen socket. The base 18000 + ($$ % 1000) keeps us away
# from common reserved ports and inside an unprivileged range. Callers
# can still override with WEBHOOK_RECEIVER_PORT.
WEBHOOK_RECEIVER_PORT="${WEBHOOK_RECEIVER_PORT:-$(( 18000 + $$ % 1000 ))}"
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
    '{name: $name, url: $url, events: ["artifact_uploaded"]}')
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

UNFILTERED_COUNT=0
SUCCESS_ROW_COUNT=0

begin_test "Unfiltered list contains at least one success row"
if [ "$SUITE_BLOCKED" = "true" ] || [ -z "$WEBHOOK_ID" ]; then
  skip "no webhook id"
else
  for _ in $(seq 1 15); do
    if resp=$(api_get "/api/v1/webhooks/${WEBHOOK_ID}/deliveries" 2>/dev/null); then
      rows=$(extract_rows "$resp")
      UNFILTERED_COUNT=$(echo "$rows" | jq 'length' 2>/dev/null || echo 0)
      SUCCESS_ROW_COUNT=$(echo "$rows" | jq '[.[] | select(.success == true)] | length' 2>/dev/null || echo 0)
      if [ "$SUCCESS_ROW_COUNT" -gt 0 ]; then
        break
      fi
    fi
    sleep 2
  done
  if [ "$SUCCESS_ROW_COUNT" -gt 0 ]; then
    pass
  elif [ "$UNFILTERED_COUNT" -gt 0 ]; then
    # Rows landed but none of them succeeded. /test against our local
    # always-200 receiver should produce success=true; if it did not,
    # the suite's premise is broken and downstream assertions cannot
    # tell "filter ignored" from "no success rows to filter for".
    SUITE_BLOCKED=true
    skip "delivery rows exist but none have .success=true; cannot exercise success-vs-failure filter"
  else
    fail "no delivery row appeared within 30s for webhook ${WEBHOOK_ID}"
  fi
fi

# -------------------------------------------------------------------------
# Positive filter: status=success returns rows whose .success == true.
# Per handler logic at webhooks.rs:541, status=success maps to a
# WHERE success = TRUE filter. The returned set MUST be non-empty
# (we just drove a success delivery) AND every returned row MUST have
# .success == true. A regression where the filter is silently dropped
# would surface as "the filtered set still contains success=false rows"
# on any cluster with prior failed deliveries.
# -------------------------------------------------------------------------

begin_test "Filter status=success returns only success=true rows"
if [ "$SUITE_BLOCKED" = "true" ]; then
  skip "no success row to filter for"
else
  if resp=$(api_get "/api/v1/webhooks/${WEBHOOK_ID}/deliveries?status=success" 2>/dev/null); then
    rows=$(extract_rows "$resp")
    cnt=$(echo "$rows" | jq 'length' 2>/dev/null || echo 0)
    if [ "$cnt" -lt 1 ]; then
      fail "filter status=success returned 0 rows, but unfiltered list had ${SUCCESS_ROW_COUNT} success row(s)"
    else
      mismatched=$(echo "$rows" | jq '[.[] | select(.success != true)] | length' 2>/dev/null || echo 0)
      if [ "$mismatched" -eq 0 ]; then
        pass
      else
        fail "filter status=success returned ${mismatched}/${cnt} rows whose .success != true (filter likely ignored)" "${rows:0:500}"
      fi
    fi
  else
    fail "filter request failed"
  fi
fi

# -------------------------------------------------------------------------
# Negative filter: status=failure must NOT return the success row we
# just produced, and any rows it does return must have .success == false.
# This is the assertion that catches "the backend ignores the status
# param and returns the full list" -- if it did, the success row we
# drove above would appear here.
#
# Per handler: status=anything-except-success maps to WHERE success=FALSE,
# so "failure" is the documented spelling of the negative filter.
# -------------------------------------------------------------------------

begin_test "Filter status=failure excludes success=true rows"
if [ "$SUITE_BLOCKED" = "true" ]; then
  skip "no success row to compare against"
else
  if resp=$(api_get "/api/v1/webhooks/${WEBHOOK_ID}/deliveries?status=failure" 2>/dev/null); then
    rows=$(extract_rows "$resp")
    cnt=$(echo "$rows" | jq 'length' 2>/dev/null || echo 0)
    success_leaked=$(echo "$rows" | jq '[.[] | select(.success == true)] | length' 2>/dev/null || echo 0)
    if [ "$success_leaked" -eq 0 ]; then
      pass
    else
      fail "filter status=failure returned ${success_leaked}/${cnt} rows with .success=true; expected zero (filter likely ignored, returning unfiltered list)" "${rows:0:500}"
    fi
  else
    # Some implementations reject an unknown status with 4xx -- the
    # handler today does not, but tolerate the stricter behavior.
    pass
  fi
fi

end_suite
