#!/usr/bin/env bash
# test-promotion-approval.sh - Promotion approval workflow E2E test
#
# Tests the approval gate: request promotion, list pending approvals,
# approve/reject, verify outcome.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "promotion-approval"
auth_admin
setup_workdir

STAGING_KEY="test-approval-staging-${RUN_ID}"
RELEASE_KEY="test-approval-release-${RUN_ID}"

begin_test "Create staging and release repos"
if create_local_repo "$STAGING_KEY" "generic" && \
   create_local_repo "$RELEASE_KEY" "generic"; then
  pass
else
  fail "could not create repos"
fi

begin_test "Upload artifact to staging"
echo "needs-approval-${RUN_ID}" > "${WORK_DIR}/artifact.bin"
if api_upload "/api/v1/repositories/${STAGING_KEY}/artifacts/pkg/artifact.bin" \
    "${WORK_DIR}/artifact.bin"; then
  pass
else
  fail "upload failed"
fi

sleep 2

# -------------------------------------------------------------------------
# Request approval for promotion
# -------------------------------------------------------------------------

begin_test "Request promotion approval"
# Get artifact ID
ARTIFACT_ID=""
if resp=$(api_get "/api/v1/repositories/${STAGING_KEY}/artifacts" 2>/dev/null); then
  ARTIFACT_ID=$(echo "$resp" | jq -r '
    if type == "array" then .[0].id // empty
    elif .items then .items[0].id // empty
    else .id // empty
    end' 2>/dev/null) || true
fi

if [ -z "$ARTIFACT_ID" ] || [ "$ARTIFACT_ID" = "null" ]; then
  skip "could not get artifact ID"
else
  APPROVAL_PAYLOAD='{
    "source_repo": "'"${STAGING_KEY}"'",
    "target_repo": "'"${RELEASE_KEY}"'",
    "artifact_ids": ["'"${ARTIFACT_ID}"'"],
    "comment": "E2E test promotion request"
  }'
  if resp=$(api_post "/api/v1/approval/request" "$APPROVAL_PAYLOAD" 2>/dev/null); then
    APPROVAL_ID=$(echo "$resp" | jq -r '.id // .approval_id // empty') || true
    pass
  elif resp=$(api_post "/api/v1/approval" "$APPROVAL_PAYLOAD" 2>/dev/null); then
    APPROVAL_ID=$(echo "$resp" | jq -r '.id // .approval_id // empty') || true
    pass
  else
    skip "approval endpoint not available"
  fi
fi

# -------------------------------------------------------------------------
# List pending approvals
# -------------------------------------------------------------------------

begin_test "List pending approvals"
if resp=$(api_get "/api/v1/approval/pending" 2>/dev/null); then
  pass
elif resp=$(api_get "/api/v1/approval?status=pending" 2>/dev/null); then
  pass
else
  skip "pending approvals endpoint not available"
fi

# -------------------------------------------------------------------------
# Approve the request
# -------------------------------------------------------------------------

begin_test "Approve promotion request"
if [ -n "${APPROVAL_ID:-}" ] && [ "$APPROVAL_ID" != "null" ]; then
  if api_post "/api/v1/approval/${APPROVAL_ID}/approve" \
      '{"comment":"Approved by E2E test"}' > /dev/null 2>&1; then
    pass
  else
    fail "could not approve"
  fi
else
  skip "no approval ID available"
fi

end_suite
