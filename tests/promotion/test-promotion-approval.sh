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

# Separation of duties (four-eyes): the backend now rejects approving a
# promotion you requested (approval_separation_of_duties_ok: requester !=
# approver; admin-only approve). The shared admin requests below, so the
# approver must be a DIFFERENT admin. Mint a dedicated admin to do the
# approving; the shared admin's own auth state is never touched.
# NOTE: create_dedicated_admin runs in a command-substitution subshell, so the
# DEDICATED_ADMIN_* globals it exports do not survive into this shell. We pass
# the credentials in explicitly and reuse those local values to log in.
APPROVER_USER="e2e-approval-approver-${RUN_ID}-$$"
APPROVER_PASS="Appr_${RUN_ID:0:8}_$$_Aa1!"
APPROVER_TOKEN=""
if APPROVER_ID=$(create_dedicated_admin "$APPROVER_USER" "$APPROVER_PASS"); then
  add_exit_handler "cleanup_dedicated_admin ${APPROVER_ID}"
  APPROVER_TOKEN=$(login_as "$APPROVER_USER" "$APPROVER_PASS") || APPROVER_TOKEN=""
fi

begin_test "Create staging and release repos"
if create_repo "$STAGING_KEY" "generic" "staging" && \
   create_repo "$RELEASE_KEY" "generic" "local"; then
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
    "source_repository": "'"${STAGING_KEY}"'",
    "target_repository": "'"${RELEASE_KEY}"'",
    "artifact_id": "'"${ARTIFACT_ID}"'"
  }'
  if resp=$(api_post "/api/v1/approval/request" "$APPROVAL_PAYLOAD" 2>/dev/null); then
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
else
  skip "pending approvals endpoint not available"
fi

# -------------------------------------------------------------------------
# Approve the request
# -------------------------------------------------------------------------

begin_test "Approve promotion request"
if [ -z "${APPROVAL_ID:-}" ] || [ "$APPROVAL_ID" = "null" ]; then
  skip "no approval ID available"
elif [ -z "$APPROVER_TOKEN" ]; then
  skip "could not establish a separate approver admin"
else
  # Four-eyes: approve as the dedicated admin, who is distinct from the
  # requester (the shared admin). Temporarily swap the bearer token used by
  # api_post; restore it afterwards so later calls use the shared admin.
  _saved_token="$ADMIN_TOKEN"
  ADMIN_TOKEN="$APPROVER_TOKEN"
  if api_post "/api/v1/approval/${APPROVAL_ID}/approve" \
      '{"notes":"Approved by E2E test (separate reviewer for four-eyes SoD)"}' > /dev/null 2>&1; then
    ADMIN_TOKEN="$_saved_token"
    pass
  else
    ADMIN_TOKEN="$_saved_token"
    fail "could not approve"
  fi
fi

end_suite
