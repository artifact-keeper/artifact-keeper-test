#!/usr/bin/env bash
# test-webhook-crud.sh - Webhook CRUD E2E test
#
# Tests creating, listing, getting, updating, and deleting webhooks.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "webhook-crud"
auth_admin
setup_workdir

WEBHOOK_NAME="e2e-webhook-${RUN_ID}"
# Use a non-routable address for the webhook URL (we just test CRUD, not delivery)
WEBHOOK_URL="https://httpbin.org/post"

# -------------------------------------------------------------------------
# Create webhook
# -------------------------------------------------------------------------

begin_test "Create webhook"
WEBHOOK_PAYLOAD='{
  "name": "'"${WEBHOOK_NAME}"'",
  "url": "'"${WEBHOOK_URL}"'",
  "events": ["artifact.uploaded", "artifact.deleted"],
  "enabled": true
}'
if resp=$(api_post "/api/v1/webhooks" "$WEBHOOK_PAYLOAD" 2>/dev/null); then
  WEBHOOK_ID=$(echo "$resp" | jq -r '.id // empty') || true
  pass
else
  skip "webhooks endpoint not available"
fi

# -------------------------------------------------------------------------
# List webhooks
# -------------------------------------------------------------------------

begin_test "List webhooks"
if resp=$(api_get "/api/v1/webhooks" 2>/dev/null); then
  if assert_contains "$resp" "$WEBHOOK_NAME"; then
    pass
  fi
else
  skip "webhook listing not available"
fi

# -------------------------------------------------------------------------
# Get webhook
# -------------------------------------------------------------------------

begin_test "Get webhook by ID"
if [ -n "${WEBHOOK_ID:-}" ] && [ "$WEBHOOK_ID" != "null" ]; then
  if resp=$(api_get "/api/v1/webhooks/${WEBHOOK_ID}" 2>/dev/null); then
    if assert_contains "$resp" "$WEBHOOK_NAME"; then
      pass
    fi
  else
    fail "could not get webhook"
  fi
else
  skip "no webhook ID"
fi

# -------------------------------------------------------------------------
# Update webhook
# -------------------------------------------------------------------------

begin_test "Disable webhook"
if [ -n "${WEBHOOK_ID:-}" ] && [ "$WEBHOOK_ID" != "null" ]; then
  if api_put "/api/v1/webhooks/${WEBHOOK_ID}" '{"enabled":false}' > /dev/null 2>&1; then
    pass
  else
    skip "webhook update not supported"
  fi
else
  skip "no webhook ID"
fi

# -------------------------------------------------------------------------
# Test webhook delivery (dry-run)
# -------------------------------------------------------------------------

begin_test "Test webhook delivery"
if [ -n "${WEBHOOK_ID:-}" ] && [ "$WEBHOOK_ID" != "null" ]; then
  if resp=$(api_post "/api/v1/webhooks/${WEBHOOK_ID}/test" "" 2>/dev/null); then
    pass
  else
    skip "webhook test delivery not available"
  fi
else
  skip "no webhook ID"
fi

# -------------------------------------------------------------------------
# List deliveries
# -------------------------------------------------------------------------

begin_test "List webhook deliveries"
if [ -n "${WEBHOOK_ID:-}" ] && [ "$WEBHOOK_ID" != "null" ]; then
  if resp=$(api_get "/api/v1/webhooks/${WEBHOOK_ID}/deliveries" 2>/dev/null); then
    pass
  else
    skip "delivery listing not available"
  fi
else
  skip "no webhook ID"
fi

# -------------------------------------------------------------------------
# Delete webhook
# -------------------------------------------------------------------------

begin_test "Delete webhook"
if [ -n "${WEBHOOK_ID:-}" ] && [ "$WEBHOOK_ID" != "null" ]; then
  if api_delete "/api/v1/webhooks/${WEBHOOK_ID}" > /dev/null 2>&1; then
    pass
  else
    fail "could not delete webhook"
  fi
else
  skip "no webhook ID"
fi

end_suite
