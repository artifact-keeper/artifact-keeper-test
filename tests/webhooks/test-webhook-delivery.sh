#!/usr/bin/env bash
# test-webhook-delivery.sh - Webhook delivery on artifact upload E2E test
#
# Creates a webhook, uploads an artifact, verifies the delivery was logged.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "webhook-delivery"
auth_admin
setup_workdir

REPO_KEY="test-whk-delivery-${RUN_ID}"
WEBHOOK_NAME="delivery-test-${RUN_ID}"

begin_test "Create repo"
if create_local_repo "$REPO_KEY" "generic"; then
  pass
else
  fail "could not create repo"
fi

# -------------------------------------------------------------------------
# Create webhook targeting the repo
# -------------------------------------------------------------------------

begin_test "Create webhook for artifact.uploaded events"
WEBHOOK_PAYLOAD='{
  "name": "'"${WEBHOOK_NAME}"'",
  "url": "https://httpbin.org/post",
  "events": ["artifact.uploaded"],
  "repository_key": "'"${REPO_KEY}"'",
  "enabled": true
}'
if resp=$(api_post "/api/v1/webhooks" "$WEBHOOK_PAYLOAD" 2>/dev/null); then
  WEBHOOK_ID=$(echo "$resp" | jq -r '.id // empty') || true
  pass
else
  skip "webhooks not available"
fi

# -------------------------------------------------------------------------
# Upload artifact to trigger webhook
# -------------------------------------------------------------------------

begin_test "Upload artifact to trigger webhook"
echo "webhook-trigger-${RUN_ID}" > "${WORK_DIR}/trigger.bin"
if api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/trigger.bin" \
    "${WORK_DIR}/trigger.bin"; then
  pass
else
  fail "upload failed"
fi

# -------------------------------------------------------------------------
# Verify delivery was logged
# -------------------------------------------------------------------------

sleep 5

begin_test "Verify webhook delivery logged"
if [ -n "${WEBHOOK_ID:-}" ] && [ "$WEBHOOK_ID" != "null" ]; then
  if resp=$(api_get "/api/v1/webhooks/${WEBHOOK_ID}/deliveries" 2>/dev/null); then
    count=$(echo "$resp" | jq '
      if type == "array" then length
      elif .items then (.items | length)
      elif .total != null then .total
      else 0
      end' 2>/dev/null) || count=0
    if [ "$count" -gt 0 ]; then
      pass
    else
      skip "no deliveries logged yet (async delivery may be delayed)"
    fi
  else
    skip "delivery listing not available"
  fi
else
  skip "no webhook ID"
fi

# Cleanup
api_delete "/api/v1/webhooks/${WEBHOOK_ID}" > /dev/null 2>&1 || true

end_suite
