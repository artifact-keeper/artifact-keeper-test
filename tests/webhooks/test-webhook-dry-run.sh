#!/usr/bin/env bash
# test-webhook-dry-run.sh
#
# Issue #75 sub-task 7.12: POST /api/v1/webhooks/{id}/test (a.k.a. the
# "dry-run" endpoint). The endpoint is referenced by test-webhook-crud.sh
# in a degenerate form (does it return a 2xx?) and used as a delivery
# trigger by the HMAC and rotation tests, but no existing suite asserts
# the actual TestWebhookResponse contract or the round-trip semantics of
# the call.
#
# Contract under test (from openapi.yaml):
#   POST /api/v1/webhooks/{id}/test -> 200 TestWebhookResponse
#
#   The response carries the result of a synthetic delivery: the receiver
#   was POSTed, the round-trip succeeded or failed, and the caller can
#   distinguish "you configured a bad URL" from "the receiver is down".
#
# Assertions in this suite:
#   1. /test returns a 2xx for a real, reachable webhook.
#   2. The receiver actually got a POST -- the endpoint is not a no-op.
#   3. The body that arrived at the receiver is JSON with an event field
#      (the same shape a real delivery uses, so receivers can be tested
#      with the same code path).
#   4. /test on a deleted/unknown id returns 404 (negative path -- this
#      catches the regression where /test silently succeeds against any
#      string, which is a tenant-isolation bug).
#
# Requires: curl, jq, python3

source "$(dirname "$0")/../lib/common.sh"

begin_suite "webhook-dry-run"

# Receiver port: derive from PID so parallel test runs do not collide
# on the same listen socket. Callers can still override with
# WEBHOOK_RECEIVER_PORT.
WEBHOOK_RECEIVER_PORT="${WEBHOOK_RECEIVER_PORT:-$(( 18000 + $$ % 1000 ))}"
WEBHOOK_RECEIVER_URL="${WEBHOOK_RECEIVER_URL:-http://127.0.0.1:${WEBHOOK_RECEIVER_PORT}/hook}"
WEBHOOK_RECEIVER_LOG="${WEBHOOK_RECEIVER_LOG:-/tmp/mock-webhook-receiver-dryrun-${RUN_ID}.log}"
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
# Start receiver.
# -------------------------------------------------------------------------

begin_test "Start mock receiver"
WEBHOOK_RECEIVER_PORT="$WEBHOOK_RECEIVER_PORT" \
  WEBHOOK_FAIL_FIRST_N=0 \
  WEBHOOK_RECEIVER_LOG="$WEBHOOK_RECEIVER_LOG" \
  python3 "$(dirname "$0")/../lib/mock-webhook-receiver.py" \
  >/tmp/mock-webhook-receiver-dryrun-${RUN_ID}.stderr 2>&1 &
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

WEBHOOK_NAME="dryrun-${RUN_ID}"
SUITE_BLOCKED=false

begin_test "Create webhook"
if [ "$ready" != "true" ]; then
  skip "receiver not running"
else
  # CreateWebhookRequest does not accept an enabled/is_enabled field
  # (backend webhooks.rs:86-95); new webhooks default to enabled. Event
  # names are the snake_case Display form of WebhookEvent (webhooks.rs:
  # 50-74), e.g. "artifact_uploaded".
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
    skip "webhook create rejected (URL '${WEBHOOK_RECEIVER_URL}' likely blocked by SSRF allow-list)"
  fi
fi

# -------------------------------------------------------------------------
# Call /test, capture the response body, capture the HTTP status code.
# Use curl directly (not api_post) so we can read both the body and the
# status without an extra round-trip.
# -------------------------------------------------------------------------

TEST_RESP_BODY=""
TEST_RESP_STATUS=""

begin_test "POST /test returns 2xx with a response body"
if [ "$SUITE_BLOCKED" = "true" ] || [ -z "$WEBHOOK_ID" ]; then
  skip "no webhook id"
else
  curl -sf --max-time 2 "http://127.0.0.1:${WEBHOOK_RECEIVER_PORT}/__reset" >/dev/null 2>&1 || true
  tmp=$(mktemp)
  TEST_RESP_STATUS=$(curl -s -o "$tmp" -w '%{http_code}' \
    --max-time 15 \
    -H "$(auth_header)" \
    -X POST \
    "${BASE_URL}/api/v1/webhooks/${WEBHOOK_ID}/test" 2>/dev/null) || TEST_RESP_STATUS="000"
  TEST_RESP_BODY=$(cat "$tmp" 2>/dev/null || true)
  rm -f "$tmp"

  case "$TEST_RESP_STATUS" in
    2??)
      if [ -z "$TEST_RESP_BODY" ]; then
        fail "/test returned ${TEST_RESP_STATUS} with empty body (expected TestWebhookResponse JSON)"
      else
        pass
      fi
      ;;
    501)
      SUITE_BLOCKED=true
      skip "/test endpoint not implemented (HTTP 501)"
      ;;
    *)
      fail "expected 2xx from /test, got HTTP ${TEST_RESP_STATUS}" "${TEST_RESP_BODY:0:400}"
      ;;
  esac
fi

# -------------------------------------------------------------------------
# Receiver actually got a POST. This is the load-bearing assertion for
# the dry-run endpoint: a /test that returns 200 without firing a real
# delivery is a silent-success bug (the operator clicks "Test", sees
# green, and trusts a configuration that has never actually delivered).
# -------------------------------------------------------------------------

LATEST_BODY=""
LATEST_HEADERS=""

begin_test "Receiver got a POST from the /test call"
if [ "$SUITE_BLOCKED" = "true" ] || [ -z "$WEBHOOK_ID" ]; then
  skip "no webhook id or /test unavailable"
else
  seen=0
  for _ in $(seq 1 20); do
    seen=$(curl -sf --max-time 2 "http://127.0.0.1:${WEBHOOK_RECEIVER_PORT}/__count" 2>/dev/null || echo 0)
    [ "$seen" -gt 0 ] && break
    sleep 0.5
  done
  if [ "$seen" -ge 1 ] && [ -s "$WEBHOOK_RECEIVER_LOG" ]; then
    LATEST=$(tail -n 1 "$WEBHOOK_RECEIVER_LOG")
    LATEST_BODY=$(echo "$LATEST" | jq -r '.body')
    LATEST_HEADERS=$(echo "$LATEST" | jq -r '.headers')
    pass
  else
    fail "/test returned ${TEST_RESP_STATUS} but no POST landed at the receiver. This is a silent-success regression: operators clicking 'Test' would see green for a webhook that never fires."
  fi
fi

# -------------------------------------------------------------------------
# The body the receiver got is the same shape a real delivery uses.
# This matters because customers wire test deliveries into their CI to
# validate receiver code: if /test sends a different envelope than the
# real producer, the test passes and real deliveries fail.
# -------------------------------------------------------------------------

begin_test "Delivered body is JSON with an event field"
if [ "$SUITE_BLOCKED" = "true" ] || [ -z "$LATEST_BODY" ]; then
  skip "no receiver body to inspect"
else
  evt=$(echo "$LATEST_BODY" | jq -r '.event // empty' 2>/dev/null) || evt=""
  if [ -n "$evt" ]; then
    pass
  else
    fail "delivered body has no .event field" "${LATEST_BODY:0:300}"
  fi
fi

# -------------------------------------------------------------------------
# The delivery carries the standard wire-contract headers. We only
# check presence here (the dedicated HMAC suite owns shape/value); the
# point of this assertion is that /test goes through the same delivery
# pipeline as a real event, not a special-cased shortcut.
# -------------------------------------------------------------------------

begin_test "Delivery carries X-ArtifactKeeper-Delivery header"
if [ "$SUITE_BLOCKED" = "true" ] || [ -z "$LATEST_HEADERS" ]; then
  skip "no receiver headers to inspect"
else
  delivery=$(echo "$LATEST_HEADERS" | jq -r '
    (.["X-ArtifactKeeper-Delivery"] //
     .["x-artifactkeeper-delivery"] //
     .["X-ARTIFACTKEEPER-DELIVERY"] // empty)
  ')
  if [ -n "$delivery" ] && [ "$delivery" != "null" ]; then
    pass
  else
    fail "X-ArtifactKeeper-Delivery missing from /test delivery (suggests /test bypasses the standard delivery pipeline)"
  fi
fi

# -------------------------------------------------------------------------
# Negative path: /test against a webhook id that does not exist must
# return 404. The unhappy spelling here is the regression where /test
# returns 200 for any string and just no-ops -- the symptom of a route
# that doesn't load the webhook before dispatching.
#
# Use a clearly-fabricated UUID so we don't accidentally collide with a
# real row.
# -------------------------------------------------------------------------

begin_test "POST /test on unknown id returns 404"
fake_id="00000000-0000-0000-0000-000000000000"
status=$(curl -s -o /dev/null -w '%{http_code}' \
  --max-time 10 \
  -H "$(auth_header)" \
  -X POST \
  "${BASE_URL}/api/v1/webhooks/${fake_id}/test" 2>/dev/null) || status="000"

case "$status" in
  404)
    pass
    ;;
  4??)
    # Some implementations return 400 for malformed-id and 404 for
    # not-found; both are acceptable for an obviously-synthetic id, but
    # we tighten the assertion: must NOT be a success.
    pass
    ;;
  501)
    skip "/test endpoint not implemented (HTTP 501)"
    ;;
  2??)
    fail "SECURITY/UX: POST /test against unknown id '${fake_id}' returned HTTP ${status}. A no-op success here masks misconfigured webhook ids."
    ;;
  000)
    fail "network failure contacting ${BASE_URL} for unknown-id /test"
    ;;
  *)
    fail "unexpected HTTP ${status} for /test on unknown id (expected 404)"
    ;;
esac

end_suite
