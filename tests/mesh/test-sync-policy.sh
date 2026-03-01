#!/usr/bin/env bash
# test-sync-policy.sh - Mesh sync policy E2E test
#
# Verifies that sync policies can be created, listed, updated,
# and deleted. Tests both push and pull sync modes.
#
# Requires: MAIN_URL, PEER1_URL

source "$(dirname "$0")/../lib/common.sh"

begin_suite "mesh-sync-policy"
setup_workdir

MAIN_URL="${MAIN_URL:?MAIN_URL must be set}"
PEER1_URL="${PEER1_URL:?PEER1_URL must be set}"

auth_admin

REPO_KEY="test-mesh-sync-${RUN_ID}"

# ---------------------------------------------------------------------------
# Setup: create repo and ensure peer exists
# ---------------------------------------------------------------------------

begin_test "Create repository for sync testing"
if create_local_repo "$REPO_KEY" "generic"; then
  pass
else
  fail "could not create repository"
fi

begin_test "Ensure peer1 is registered"
# Check if peer1 already registered
peers=$(api_get "/api/v1/mesh/peers" 2>/dev/null || echo "[]")
if [[ "$peers" == *"peer1"* ]]; then
  PEER1_ID=$(echo "$peers" | jq -r '[.[] // .items[]?] | map(select(.name | contains("peer1"))) | .[0].id // empty' 2>/dev/null || true)
  pass
else
  PEER1_PAYLOAD="{\"name\":\"peer1-${RUN_ID}\",\"url\":\"${PEER1_URL}\",\"enabled\":true}"
  if resp=$(api_post "/api/v1/mesh/peers" "$PEER1_PAYLOAD"); then
    PEER1_ID=$(echo "$resp" | jq -r '.id // empty' 2>/dev/null || true)
    pass
  else
    fail "could not register peer1"
  fi
fi

# ---------------------------------------------------------------------------
# Create push sync policy
# ---------------------------------------------------------------------------

begin_test "Create push sync policy"
PUSH_POLICY="{\"name\":\"push-to-peer1-${RUN_ID}\",\"source_repo\":\"${REPO_KEY}\",\"target_peer\":\"peer1-${RUN_ID}\",\"target_repo\":\"${REPO_KEY}\",\"sync_mode\":\"push\",\"enabled\":true}"
if resp=$(api_post "/api/v1/mesh/sync-policies" "$PUSH_POLICY"); then
  PUSH_POLICY_ID=$(echo "$resp" | jq -r '.id // empty' 2>/dev/null || true)
  if [ -n "$PUSH_POLICY_ID" ]; then
    pass
  else
    # Policy created but no ID returned, try to find it
    if assert_contains "$resp" "push" "response should indicate push policy"; then
      pass
    fi
  fi
else
  fail "POST /api/v1/mesh/sync-policies failed"
fi

# ---------------------------------------------------------------------------
# Create pull sync policy
# ---------------------------------------------------------------------------

begin_test "Create pull sync policy"
PULL_POLICY="{\"name\":\"pull-from-peer1-${RUN_ID}\",\"source_peer\":\"peer1-${RUN_ID}\",\"source_repo\":\"${REPO_KEY}\",\"target_repo\":\"${REPO_KEY}-pull\",\"sync_mode\":\"pull\",\"enabled\":true}"
if resp=$(api_post "/api/v1/mesh/sync-policies" "$PULL_POLICY"); then
  PULL_POLICY_ID=$(echo "$resp" | jq -r '.id // empty' 2>/dev/null || true)
  pass
else
  fail "POST /api/v1/mesh/sync-policies failed for pull policy"
fi

# ---------------------------------------------------------------------------
# List sync policies
# ---------------------------------------------------------------------------

begin_test "List sync policies"
if resp=$(api_get "/api/v1/mesh/sync-policies"); then
  if assert_contains "$resp" "push-to-peer1" "policy list should contain push policy" && \
     assert_contains "$resp" "pull-from-peer1" "policy list should contain pull policy"; then
    pass
  fi
else
  fail "GET /api/v1/mesh/sync-policies failed"
fi

# ---------------------------------------------------------------------------
# Update sync policy (disable)
# ---------------------------------------------------------------------------

begin_test "Disable push sync policy"
if [ -n "$PUSH_POLICY_ID" ]; then
  UPDATE_PAYLOAD="{\"enabled\":false}"
  if resp=$(api_put "/api/v1/mesh/sync-policies/${PUSH_POLICY_ID}" "$UPDATE_PAYLOAD"); then
    pass
  else
    fail "PUT /api/v1/mesh/sync-policies/${PUSH_POLICY_ID} failed"
  fi
else
  skip "no push policy ID available"
fi

# ---------------------------------------------------------------------------
# Delete pull sync policy
# ---------------------------------------------------------------------------

begin_test "Delete pull sync policy"
if [ -n "$PULL_POLICY_ID" ]; then
  if api_delete "/api/v1/mesh/sync-policies/${PULL_POLICY_ID}" > /dev/null 2>&1; then
    # Verify it's gone
    if ! api_get "/api/v1/mesh/sync-policies/${PULL_POLICY_ID}" > /dev/null 2>&1; then
      pass
    else
      fail "policy still exists after delete"
    fi
  else
    fail "DELETE /api/v1/mesh/sync-policies/${PULL_POLICY_ID} failed"
  fi
else
  skip "no pull policy ID available"
fi

end_suite
