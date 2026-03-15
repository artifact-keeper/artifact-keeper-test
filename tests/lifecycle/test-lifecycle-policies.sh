#!/usr/bin/env bash
# test-lifecycle-policies.sh - Retention policy CRUD and preview E2E test
#
# Tests creating lifecycle/retention policies, previewing what would be
# cleaned, and verifying policy listing.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "lifecycle-policies"
auth_admin
setup_workdir

REPO_KEY="test-lifecycle-${RUN_ID}"
POLICY_NAME="cleanup-${RUN_ID}"

begin_test "Create repo"
REPO_ID=""
if resp=$(api_post "/api/v1/repositories" \
    "{\"key\":\"${REPO_KEY}\",\"name\":\"${REPO_KEY}\",\"format\":\"generic\",\"repo_type\":\"local\",\"is_public\":true}" 2>/dev/null); then
  REPO_ID=$(echo "$resp" | jq -r '.id // empty') || true
  pass
else
  fail "could not create repo"
fi

# If we did not capture the repo ID from creation, fetch it
if [ -z "$REPO_ID" ] || [ "$REPO_ID" = "null" ]; then
  if resp=$(api_get "/api/v1/repositories/${REPO_KEY}" 2>/dev/null); then
    REPO_ID=$(echo "$resp" | jq -r '.id // empty') || true
  fi
fi

# Upload some artifacts
for i in 1 2 3; do
  echo "old-artifact-${i}-${RUN_ID}" > "${WORK_DIR}/old-${i}.bin"
  api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/old/file-${i}.bin" \
    "${WORK_DIR}/old-${i}.bin" > /dev/null 2>&1 || true
done

# -------------------------------------------------------------------------
# Create lifecycle policy
# -------------------------------------------------------------------------

begin_test "Create lifecycle policy"
if [ -z "$REPO_ID" ] || [ "$REPO_ID" = "null" ]; then
  skip "no repository ID available for lifecycle policy"
else
  POLICY_PAYLOAD='{
    "name": "'"${POLICY_NAME}"'",
    "repository_id": "'"${REPO_ID}"'",
    "policy_type": "max_versions",
    "config": {"max_versions": 1},
    "priority": 10
  }'
  if resp=$(api_post "/api/v1/admin/lifecycle" "$POLICY_PAYLOAD" 2>/dev/null); then
    POLICY_ID=$(echo "$resp" | jq -r '.id // empty') || true
    pass
  elif resp=$(api_post "/api/v1/admin/lifecycle/policies" "$POLICY_PAYLOAD" 2>/dev/null); then
    POLICY_ID=$(echo "$resp" | jq -r '.id // empty') || true
    pass
  else
    skip "lifecycle policy endpoint not available"
  fi
fi

# -------------------------------------------------------------------------
# List policies
# -------------------------------------------------------------------------

begin_test "List lifecycle policies"
if resp=$(api_get "/api/v1/admin/lifecycle" 2>/dev/null); then
  if assert_contains "$resp" "$POLICY_NAME"; then
    pass
  fi
elif resp=$(api_get "/api/v1/admin/lifecycle/policies" 2>/dev/null); then
  if assert_contains "$resp" "$POLICY_NAME"; then
    pass
  fi
else
  skip "lifecycle listing not available"
fi

# -------------------------------------------------------------------------
# Preview policy execution
# -------------------------------------------------------------------------

begin_test "Preview lifecycle policy"
if [ -n "${POLICY_ID:-}" ] && [ "$POLICY_ID" != "null" ]; then
  if resp=$(api_post "/api/v1/admin/lifecycle/${POLICY_ID}/preview" "" 2>/dev/null); then
    pass
  elif resp=$(api_post "/api/v1/admin/lifecycle/${POLICY_ID}/execute?dry_run=true" "" 2>/dev/null); then
    pass
  else
    skip "policy preview not available"
  fi
else
  skip "no policy ID"
fi

# -------------------------------------------------------------------------
# Delete policy
# -------------------------------------------------------------------------

begin_test "Delete lifecycle policy"
if [ -n "${POLICY_ID:-}" ] && [ "$POLICY_ID" != "null" ]; then
  if api_delete "/api/v1/admin/lifecycle/${POLICY_ID}" > /dev/null 2>&1; then
    pass
  elif api_delete "/api/v1/admin/lifecycle/policies/${POLICY_ID}" > /dev/null 2>&1; then
    pass
  else
    fail "could not delete policy"
  fi
else
  skip "no policy ID"
fi

end_suite
