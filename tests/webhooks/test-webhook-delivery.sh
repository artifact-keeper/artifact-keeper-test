#!/usr/bin/env bash
# test-webhook-delivery.sh - Webhook producer delivery enqueue regression test
#
# Webhooks v2 wire contract (artifact-keeper#919, E3 + E4): subscribing a
# webhook to a real EventBus event must result in:
#   1. a row being inserted into webhook_deliveries when that event fires.
#   2. the resulting POST to the receiver carrying the new
#      X-ArtifactKeeper-Delivery / -Event / -Event-Version headers.
#
# Trigger: repository.created
#   The producer maps EventBus repository.created -> webhook event name
#   "repository_created", entity_id is the repository UUID, and the
#   producer matches on global webhooks (repository_id IS NULL).
#
# Companion backend PR: artifact-keeper#1140. The producer is gated by
# WEBHOOKS_V2_PRODUCER_ENABLED; the harness sets it to 1.
#
# Receiver: the local mock at WEBHOOK_RECEIVER_PORT. The previous version
# of this test used `https://example.invalid` and could only assert the
# database row; with the receiver wired we can also assert the wire
# headers on the actual delivery.
#
# Also serves as the E2E reproducer for artifact-keeper#1367 ("Webhook
# subsystem broken in release-gate deploy"). Closing PR
# artifact-keeper-test#188 fixed the env-var rename
# (WEBHOOK_ALLOW_PRIVATE_IPS -> UPSTREAM_ALLOW_PRIVATE_IPS) that this
# test depends on; without that rename the mock receiver at 127.0.0.1
# is rejected at create time and the steps below all fail at "Create
# webhook subscribed to repository_created". With the rename in place,
# the suite proves the producer task is alive, EventBus is wired, and
# the delivery worker POSTs to a real receiver within 30s of the
# triggering repo creation, which is the regression bar for #1367.
#
# Requires: curl, jq, python3

source "$(dirname "$0")/../lib/common.sh"

begin_suite "webhook-delivery"
auth_admin
setup_workdir

WEBHOOK_RECEIVER_PORT="${WEBHOOK_RECEIVER_PORT:-18768}"
WEBHOOK_RECEIVER_URL="${WEBHOOK_RECEIVER_URL:-http://${WEBHOOK_RECEIVER_HOST:-127.0.0.1}:${WEBHOOK_RECEIVER_PORT}/hook}"
WEBHOOK_RECEIVER_LOG="${WEBHOOK_RECEIVER_LOG:-/tmp/mock-webhook-receiver-delivery-${RUN_ID}.log}"
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

REPO_KEY="test-whk-delivery-${RUN_ID}"
WEBHOOK_NAME="delivery-test-${RUN_ID}"
WEBHOOK_ID=""

# -------------------------------------------------------------------------
# Start mock receiver.
# -------------------------------------------------------------------------

receiver_ready=false
begin_test "Start mock webhook receiver"
if ! command -v python3 >/dev/null 2>&1; then
  skip "python3 not available"
else
  WEBHOOK_RECEIVER_PORT="$WEBHOOK_RECEIVER_PORT" \
    WEBHOOK_FAIL_FIRST_N=0 \
    WEBHOOK_RECEIVER_LOG="$WEBHOOK_RECEIVER_LOG" \
    python3 "$(dirname "$0")/../lib/mock-webhook-receiver.py" \
    >/tmp/mock-webhook-receiver-delivery-${RUN_ID}.stderr 2>&1 &
  RECEIVER_PID=$!

  for _ in $(seq 1 25); do
    if curl -sf --max-time 1 "http://127.0.0.1:${WEBHOOK_RECEIVER_PORT}/__health" >/dev/null 2>&1; then
      receiver_ready=true
      break
    fi
    sleep 0.2
  done
  if [ "$receiver_ready" = true ]; then
    pass
  else
    fail "mock receiver did not come up on 127.0.0.1:${WEBHOOK_RECEIVER_PORT}"
  fi
fi

# -------------------------------------------------------------------------
# Create a global webhook subscribed to repository_created BEFORE the
# repo exists. Ordering matters: the event is fanned out to webhooks
# matching at emit time, so the subscription must be in place first.
# -------------------------------------------------------------------------

begin_test "Create webhook subscribed to repository_created"
if [ "$receiver_ready" != "true" ]; then
  skip "receiver not running"
else
  WEBHOOK_PAYLOAD=$(jq -n \
    --arg name "$WEBHOOK_NAME" \
    --arg url "$WEBHOOK_RECEIVER_URL" \
    '{name: $name, url: $url, events: ["repository_created"], enabled: true}')
  if resp=$(api_post "/api/v1/webhooks" "$WEBHOOK_PAYLOAD" 2>/dev/null); then
    WEBHOOK_ID=$(echo "$resp" | jq -r '.id // empty') || true
    if [ -z "$WEBHOOK_ID" ] || [ "$WEBHOOK_ID" = "null" ]; then
      fail "webhook create returned no id: ${resp:0:200}"
    else
      pass
    fi
  else
    fail "webhook create request failed"
  fi
fi

# -------------------------------------------------------------------------
# Trigger the event by creating a repository.
# -------------------------------------------------------------------------

REPO_ID=""

begin_test "Create repo to trigger repository.created event"
if [ -z "$WEBHOOK_ID" ]; then
  skip "no webhook id"
else
  REPO_CREATE_PAYLOAD="{\"key\":\"${REPO_KEY}\",\"name\":\"${REPO_KEY}\",\"format\":\"generic\",\"repo_type\":\"local\",\"is_public\":true}"
  if resp=$(api_post "/api/v1/repositories" "$REPO_CREATE_PAYLOAD" 2>/dev/null); then
    REPO_ID=$(echo "$resp" | jq -r '.id // empty') || true
    if [ -z "$REPO_ID" ] || [ "$REPO_ID" = "null" ]; then
      fail "repo create returned no id: ${resp:0:200}"
    else
      pass
    fi
  else
    fail "repo create request failed"
  fi
fi

# -------------------------------------------------------------------------
# Strict assertion: a delivery row must exist within 30s.
# -------------------------------------------------------------------------

DELIVERY_RESP=""
delivery_count=0

begin_test "Webhook delivery row inserted within 30s"
if [ -z "$WEBHOOK_ID" ]; then
  fail "no webhook id from earlier step"
else
  for attempt in $(seq 1 15); do
    sleep 2
    if resp=$(api_get "/api/v1/webhooks/${WEBHOOK_ID}/deliveries" 2>/dev/null); then
      DELIVERY_RESP="$resp"
      delivery_count=$(echo "$resp" | jq '
        if type == "array" then length
        elif .items then (.items | length)
        elif .total != null then .total
        else 0
        end' 2>/dev/null) || delivery_count=0
      if [ "$delivery_count" -gt 0 ]; then
        break
      fi
    fi
  done
  if [ "$delivery_count" -gt 0 ]; then
    pass
  else
    fail "no webhook_deliveries row appeared within 30s for webhook ${WEBHOOK_ID} after creating repo ${REPO_ID}; producer may not be running" "${DELIVERY_RESP:0:500}"
  fi
fi

# -------------------------------------------------------------------------
# Confirm the delivery row carries the right event name.
# -------------------------------------------------------------------------

begin_test "Delivery event field is 'repository_created'"
if [ "$delivery_count" -gt 0 ]; then
  event_name=$(echo "$DELIVERY_RESP" | jq -r '
    if type == "array" then .[0].event
    elif .items then .items[0].event
    else empty
    end' 2>/dev/null) || event_name=""
  if [ "$event_name" = "repository_created" ]; then
    pass
  else
    fail "expected event='repository_created', got '${event_name}'" "${DELIVERY_RESP:0:500}"
  fi
else
  fail "no delivery row to inspect"
fi

# -------------------------------------------------------------------------
# Confirm the delivery payload contains the new repo's UUID.
# -------------------------------------------------------------------------

begin_test "Delivery payload contains new repo entity_id"
if [ "$delivery_count" -gt 0 ] && [ -n "$REPO_ID" ]; then
  if assert_contains "$DELIVERY_RESP" "$REPO_ID"; then
    pass
  fi
else
  fail "no delivery row or no repo id to check"
fi

# -------------------------------------------------------------------------
# v2 wire-contract assertion: the actual POST that landed at the receiver
# carries X-ArtifactKeeper-Delivery (UUID), X-ArtifactKeeper-Event, and
# X-ArtifactKeeper-Event-Version headers. Wait briefly for the producer's
# scheduler tick to push the row to the receiver.
# -------------------------------------------------------------------------

LATEST_HEADERS=""

begin_test "Delivery POST reached the mock receiver"
if [ "$receiver_ready" != "true" ] || [ -z "$WEBHOOK_ID" ]; then
  skip "receiver not running or no webhook id"
else
  seen=0
  for _ in $(seq 1 60); do
    seen=$(curl -sf --max-time 2 "http://127.0.0.1:${WEBHOOK_RECEIVER_PORT}/__count" 2>/dev/null || echo 0)
    [ "$seen" -gt 0 ] && break
    sleep 1
  done
  if [ "$seen" -ge 1 ] && [ -s "$WEBHOOK_RECEIVER_LOG" ]; then
    LATEST_HEADERS=$(tail -n 1 "$WEBHOOK_RECEIVER_LOG" | jq -r '.headers')
    pass
  else
    fail "receiver saw 0 POSTs after repo create within 60s"
  fi
fi

begin_test "X-ArtifactKeeper-Delivery is a UUID"
if [ -z "$LATEST_HEADERS" ]; then
  skip "no receiver entry"
else
  delivery=$(echo "$LATEST_HEADERS" | jq -r '
    (.["X-ArtifactKeeper-Delivery"] //
     .["x-artifactkeeper-delivery"] //
     .["X-ARTIFACTKEEPER-DELIVERY"] // empty)
  ')
  if [ -n "$delivery" ] && [ "$delivery" != "null" ] && \
     echo "$delivery" | grep -Eiq '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'; then
    pass
  else
    fail "X-ArtifactKeeper-Delivery missing or not a UUID: '${delivery}'"
  fi
fi

begin_test "X-ArtifactKeeper-Event reflects the event type"
if [ -z "$LATEST_HEADERS" ]; then
  skip "no receiver entry"
else
  evt=$(echo "$LATEST_HEADERS" | jq -r '
    (.["X-ArtifactKeeper-Event"] //
     .["x-artifactkeeper-event"] //
     .["X-ARTIFACTKEEPER-EVENT"] // empty)
  ')
  # The wire event name may use underscores or dots depending on the
  # producer mapping. Accept either form for repository_created.
  case "$evt" in
    repository_created|repository.created) pass ;;
    *) fail "expected event header 'repository_created' or 'repository.created', got '${evt}'" ;;
  esac
fi

begin_test "X-ArtifactKeeper-Event-Version is the default 2026-04-01"
if [ -z "$LATEST_HEADERS" ]; then
  skip "no receiver entry"
else
  ver=$(echo "$LATEST_HEADERS" | jq -r '
    (.["X-ArtifactKeeper-Event-Version"] //
     .["x-artifactkeeper-event-version"] //
     .["X-ARTIFACTKEEPER-EVENT-VERSION"] // empty)
  ')
  if [ "$ver" = "2026-04-01" ]; then
    pass
  else
    fail "expected event-version '2026-04-01', got '${ver}'"
  fi
fi

# Cleanup
api_delete "/api/v1/webhooks/${WEBHOOK_ID}" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${REPO_KEY}" > /dev/null 2>&1 || true

end_suite
