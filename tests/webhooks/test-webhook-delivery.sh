#!/usr/bin/env bash
# test-webhook-delivery.sh - Webhook producer delivery enqueue regression test
#
# This is the regression test for artifact-keeper#909 (webhook v2 event
# producer): subscribing a webhook to a real EventBus event must result in
# a row being inserted into webhook_deliveries when that event fires.
#
# Trigger choice: repository.created
#
#   The previous version of this test used "artifact.uploaded" as the
#   trigger, but no handler on release/1.1.x emits that event type. The
#   only artifact-side event currently emitted is "artifact.created",
#   which has its own scoping problems (entity_id is the artifact UUID,
#   not the repo, so the producer cannot match a repo-scoped webhook on
#   release/1.1.x where DomainEvent has no explicit repository_id field;
#   see FIXME(#948) in webhook_producer.rs).
#
#   repository.created sidesteps that problem: the entity_id IS the
#   repository UUID, and we can match it with a global webhook
#   (repository_id IS NULL), which the producer's matching predicate
#   ("repository_id IS NULL OR repository_id = $2") accepts.
#
#   Until #948 lands proper repo scoping for non-repo events on the
#   1.1.x branch, this test uses repository creation as the trigger.
#   That is enough to prove the producer task is alive, mapping
#   EventBus events to webhook event names, and inserting deliveries.
#
# What we assert (the regression bar for #909):
#   1. A webhook subscribed to "repository_created" (the mapped name)
#      gets a webhook_deliveries row inserted within 30s of repo
#      creation.
#   2. The delivery row has event="repository_created".
#   3. The delivery payload contains the entity_id (the new repo's
#      UUID), proving the producer wired the EventBus payload through.
#
# If the producer task panics, is removed, or stops subscribing to the
# bus, this test fails hard. No silent skip on missing deliveries.
#
# Requires: curl, jq

source "$(dirname "$0")/../lib/common.sh"

begin_suite "webhook-delivery"
auth_admin
setup_workdir

REPO_KEY="test-whk-delivery-${RUN_ID}"
WEBHOOK_NAME="delivery-test-${RUN_ID}"
WEBHOOK_ID=""

# -------------------------------------------------------------------------
# Create a global webhook subscribed to repository_created BEFORE the
# repo exists. Ordering matters: the event is fanned out to webhooks
# matching at emit time, so the subscription must be in place first.
# -------------------------------------------------------------------------

begin_test "Create webhook subscribed to repository_created"
WEBHOOK_PAYLOAD='{
  "name": "'"${WEBHOOK_NAME}"'",
  "url": "https://example.invalid/webhook-sink",
  "events": ["repository_created"],
  "enabled": true
}'
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

# -------------------------------------------------------------------------
# Trigger the event by creating a repository. The backend emits
# "repository.created" via EventBus, the producer maps it to
# "repository_created", matches the global webhook above, and inserts
# a webhook_deliveries row.
# -------------------------------------------------------------------------

REPO_ID=""

begin_test "Create repo to trigger repository.created event"
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

# -------------------------------------------------------------------------
# Strict assertion: a delivery row must exist within 30s. This is the
# regression test for #909. Do NOT skip on empty results.
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
# Confirm the delivery row carries the right event name. This catches
# regressions in webhook_producer::map_event_type.
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
# Confirm the delivery payload contains the new repo's UUID. This
# proves the producer pulled the EventBus entity_id through into the
# enqueued payload (build_event_payload in webhook_producer.rs).
# -------------------------------------------------------------------------

begin_test "Delivery payload contains new repo entity_id"
if [ "$delivery_count" -gt 0 ] && [ -n "$REPO_ID" ]; then
  if assert_contains "$DELIVERY_RESP" "$REPO_ID"; then
    pass
  fi
else
  fail "no delivery row or no repo id to check"
fi

# Cleanup
api_delete "/api/v1/webhooks/${WEBHOOK_ID}" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${REPO_KEY}" > /dev/null 2>&1 || true

end_suite
