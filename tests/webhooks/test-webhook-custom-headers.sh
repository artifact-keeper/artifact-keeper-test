#!/usr/bin/env bash
# test-webhook-custom-headers.sh - Custom header injection on webhook deliveries
#
# Epic 7 sub-task 7.7 (artifact-keeper-test#75). Webhooks v2 wire contract
# allows operators to pin a small map of custom HTTP headers on a webhook
# row (commonly used to attach an auth token or routing key for the
# receiver). Each delivery must carry those headers verbatim alongside the
# standard X-ArtifactKeeper-* set, and the value must not be reordered or
# stripped by the delivery worker.
#
# Sub-checks:
#   1. Create a webhook with two custom headers (one ASCII, one with a
#      symbol-heavy value). POST /api/v1/webhooks/{id}/test fires a
#      synchronous delivery against the local mock receiver.
#   2. The receiver records both custom headers with the exact values
#      supplied at create time.
#   3. The standard X-ArtifactKeeper-Delivery header is still present
#      (custom headers must augment, not replace).
#
# Requires: curl, jq, python3

source "$(dirname "$0")/../lib/common.sh"

begin_suite "webhook-custom-headers"
auth_admin
setup_workdir

WEBHOOK_RECEIVER_PORT="${WEBHOOK_RECEIVER_PORT:-18772}"
WEBHOOK_RECEIVER_URL="${WEBHOOK_RECEIVER_URL:-http://127.0.0.1:${WEBHOOK_RECEIVER_PORT}/hook}"
WEBHOOK_RECEIVER_LOG="${WORK_DIR}/mock-webhook-receiver-customhdr.log"
WEBHOOK_RECEIVER_STDERR="${WORK_DIR}/mock-webhook-receiver-customhdr.stderr"
RECEIVER_PID=""

cleanup_and_finalize() {
  local code=$?
  if [ -n "${RECEIVER_PID}" ] && kill -0 "${RECEIVER_PID}" 2>/dev/null; then
    kill "${RECEIVER_PID}" 2>/dev/null || true
    wait "${RECEIVER_PID}" 2>/dev/null || true
  fi
  # WORK_DIR (and the logs inside it) are cleaned by setup_workdir's
  # registered exit handler. No /tmp leakage.
  exit "$code"
}
trap cleanup_and_finalize EXIT

# -------------------------------------------------------------------------
# Pre-flight + receiver.
# -------------------------------------------------------------------------

begin_test "python3 and jq available"
miss=""
command -v python3 >/dev/null 2>&1 || miss="${miss} python3"
command -v jq      >/dev/null 2>&1 || miss="${miss} jq"
if [ -n "$miss" ]; then
  skip "missing tools:${miss}"
  end_suite
fi
pass

# Port-collision pre-flight: if something is already listening on
# WEBHOOK_RECEIVER_PORT, fail loudly rather than silently attaching to a
# foreign receiver from another concurrent run.
begin_test "Receiver port ${WEBHOOK_RECEIVER_PORT} is free"
if curl -sf --max-time 1 "http://127.0.0.1:${WEBHOOK_RECEIVER_PORT}/__health" >/dev/null 2>&1; then
  fail "127.0.0.1:${WEBHOOK_RECEIVER_PORT} already serves /__health (concurrent run? stale receiver?); set WEBHOOK_RECEIVER_PORT to a free port"
  end_suite
fi
pass

begin_test "Start mock receiver"
WEBHOOK_RECEIVER_PORT="$WEBHOOK_RECEIVER_PORT" \
  WEBHOOK_FAIL_FIRST_N=0 \
  WEBHOOK_RECEIVER_LOG="$WEBHOOK_RECEIVER_LOG" \
  python3 "$(dirname "$0")/../lib/mock-webhook-receiver.py" \
  >"$WEBHOOK_RECEIVER_STDERR" 2>&1 &
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
  end_suite
fi

# -------------------------------------------------------------------------
# Create webhook with custom headers.
# -------------------------------------------------------------------------

WEBHOOK_NAME="custhdr-${RUN_ID}"
CUSTOM_TOKEN_VALUE="secret.token.value-${RUN_ID}"
CUSTOM_ROUTE_VALUE="route/key=abc+xyz"

WEBHOOK_ID=""

begin_test "Create webhook with custom headers"
payload=$(jq -nc \
  --arg name "$WEBHOOK_NAME" \
  --arg url  "$WEBHOOK_RECEIVER_URL" \
  --arg tok  "$CUSTOM_TOKEN_VALUE" \
  --arg rte  "$CUSTOM_ROUTE_VALUE" \
  '{
    name: $name,
    url:  $url,
    events: ["artifact.uploaded"],
    enabled: true,
    headers: {
      "X-Test-Auth-Token": $tok,
      "X-Test-Route-Key":  $rte
    }
  }')
if resp=$(api_post "/api/v1/webhooks" "$payload" 2>/dev/null); then
  WEBHOOK_ID=$(echo "$resp" | jq -r '.id // empty')
  if [ -n "$WEBHOOK_ID" ] && [ "$WEBHOOK_ID" != "null" ]; then
    pass
  else
    skip "webhook create returned no id (custom headers may not be supported on this backend)"
    end_suite
  fi
else
  skip "webhook create not available or rejected custom headers"
  end_suite
fi

# -------------------------------------------------------------------------
# Trigger synchronous test delivery.
# -------------------------------------------------------------------------

begin_test "POST /webhooks/{id}/test fires a delivery"
if api_post "/api/v1/webhooks/${WEBHOOK_ID}/test" "" >/dev/null 2>&1; then
  pass
else
  skip "test delivery endpoint not available"
  end_suite
fi

# Allow async receiver to record the request.
seen=0
for _ in $(seq 1 20); do
  seen=$(curl -sf --max-time 2 "http://127.0.0.1:${WEBHOOK_RECEIVER_PORT}/__count" 2>/dev/null || echo 0)
  if [ "$seen" -gt 0 ]; then
    break
  fi
  sleep 0.5
done

begin_test "Receiver observed at least one delivery"
if [ "$seen" -gt 0 ]; then
  pass
else
  fail "receiver did not see any delivery"
  end_suite
fi

# -------------------------------------------------------------------------
# Inspect headers on the last delivery.
# -------------------------------------------------------------------------

last=$(tail -n1 "$WEBHOOK_RECEIVER_LOG" 2>/dev/null || echo '{}')
if [ -z "$last" ]; then
  last='{}'
fi

begin_test "Custom header X-Test-Auth-Token present with exact value"
got_tok=$(echo "$last" | jq -r '
  (.headers["X-Test-Auth-Token"] //
   .headers["x-test-auth-token"] //
   empty)')
if [ "$got_tok" = "$CUSTOM_TOKEN_VALUE" ]; then
  pass
else
  fail "X-Test-Auth-Token: expected='${CUSTOM_TOKEN_VALUE}' got='${got_tok}'"
fi

begin_test "Custom header X-Test-Route-Key preserves symbol-heavy value"
got_rte=$(echo "$last" | jq -r '
  (.headers["X-Test-Route-Key"] //
   .headers["x-test-route-key"] //
   empty)')
if [ "$got_rte" = "$CUSTOM_ROUTE_VALUE" ]; then
  pass
else
  fail "X-Test-Route-Key: expected='${CUSTOM_ROUTE_VALUE}' got='${got_rte}'"
fi

begin_test "Standard X-ArtifactKeeper-Delivery still present alongside custom headers"
delivery_id=$(echo "$last" | jq -r '
  (.headers["X-ArtifactKeeper-Delivery"] //
   .headers["x-artifactkeeper-delivery"] //
   empty)')
if [ -n "$delivery_id" ] && [ "$delivery_id" != "null" ]; then
  pass
else
  fail "X-ArtifactKeeper-Delivery missing on delivery with custom headers"
fi

# -------------------------------------------------------------------------
# Cleanup.
# -------------------------------------------------------------------------

api_delete "/api/v1/webhooks/${WEBHOOK_ID}" >/dev/null 2>&1 || true

end_suite
