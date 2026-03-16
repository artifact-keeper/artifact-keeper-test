#!/usr/bin/env bash
# test-artifact-sync.sh - Mesh artifact replication E2E test
#
# Verifies that artifacts uploaded to one instance are replicated
# to peers according to sync policies.
#
# Requires: MAIN_URL, PEER1_URL

source "$(dirname "$0")/../lib/common.sh"

begin_suite "mesh-artifact-sync"
setup_workdir

MAIN_URL="${MAIN_URL:?MAIN_URL must be set}"
PEER1_URL="${PEER1_URL:?PEER1_URL must be set}"

auth_admin

REPO_KEY="test-mesh-artsync-${RUN_ID}"
SYNC_TIMEOUT="${SYNC_TIMEOUT:-60}"

# ---------------------------------------------------------------------------
# Setup: create repos on both instances, register peer, create sync policy
# ---------------------------------------------------------------------------

begin_test "Create repository on main instance"
if create_local_repo "$REPO_KEY" "generic"; then
  pass
else
  fail "could not create repo on main"
fi

begin_test "Create repository on peer1"
ORIG_BASE_URL="$BASE_URL"
ORIG_TOKEN="$ADMIN_TOKEN"
export BASE_URL="$PEER1_URL"
auth_admin
PEER1_TOKEN="$ADMIN_TOKEN"

if create_local_repo "$REPO_KEY" "generic"; then
  pass
else
  fail "could not create repo on peer1"
fi

# Restore main context
export BASE_URL="$ORIG_BASE_URL"
export ADMIN_TOKEN="$ORIG_TOKEN"

begin_test "Register peer and create push sync policy"
# Create an API token on peer1 that the main instance's sync worker
# can use to authenticate when pushing artifacts.
PEER1_API_KEY=""
export BASE_URL="$PEER1_URL"
export ADMIN_TOKEN="$PEER1_TOKEN"
if resp=$(api_post "/api/v1/auth/tokens" \
    "{\"name\":\"sync-key-${RUN_ID}\",\"scopes\":[\"read\",\"write\"]}" 2>/dev/null); then
  PEER1_API_KEY=$(echo "$resp" | jq -r '.token // empty') || true
fi
export BASE_URL="$ORIG_BASE_URL"
export ADMIN_TOKEN="$ORIG_TOKEN"

# Fall back to admin token if token creation didn't return a key
if [ -z "$PEER1_API_KEY" ] || [ "$PEER1_API_KEY" = "null" ]; then
  PEER1_API_KEY="$PEER1_TOKEN"
fi

# Register peer1 with a real auth token
PEER1_PAYLOAD="{\"name\":\"sync-peer1-${RUN_ID}\",\"endpoint_url\":\"${PEER1_URL}\",\"api_key\":\"${PEER1_API_KEY}\"}"
PEER_RESP=$(api_post "/api/v1/peers" "$PEER1_PAYLOAD" 2>/dev/null) || true
PEER1_ID=$(echo "$PEER_RESP" | jq -r '.id // empty' 2>/dev/null) || true

# Send heartbeat to set peer status from 'offline' (default) to 'online'.
# The sync worker only processes peers with status IN ('online', 'syncing').
if [ -n "$PEER1_ID" ] && [ "$PEER1_ID" != "null" ]; then
  api_post "/api/v1/peers/${PEER1_ID}/heartbeat" '{"cache_used_bytes":0}' > /dev/null 2>&1 || true
fi

# Create push sync policy
POLICY="{\"name\":\"sync-artifacts-${RUN_ID}\",\"repo_selector\":{\"match_pattern\":\"${REPO_KEY}\"},\"peer_selector\":{\"all\":true},\"replication_mode\":\"push\",\"enabled\":true}"
if api_post "/api/v1/sync-policies" "$POLICY" > /dev/null 2>&1; then
  # Trigger policy evaluation to create peer_repo_subscriptions
  api_post "/api/v1/sync-policies/evaluate" "" > /dev/null 2>&1 || true
  pass
else
  fail "could not create sync policy"
fi

# ---------------------------------------------------------------------------
# Upload artifact on main
# ---------------------------------------------------------------------------

begin_test "Upload artifact on main instance"
dd if=/dev/urandom bs=1024 count=4 of="${WORK_DIR}/sync-test.bin" 2>/dev/null
ORIG_SHA256=$(shasum -a 256 "${WORK_DIR}/sync-test.bin" | awk '{print $1}')

if api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/sync-test/v1/payload.bin" \
    "${WORK_DIR}/sync-test.bin" "application/octet-stream" > /dev/null; then
  pass
else
  fail "upload to main instance failed"
fi

# ---------------------------------------------------------------------------
# Wait for replication to peer1
# ---------------------------------------------------------------------------

begin_test "Wait for artifact to sync to peer1"
export BASE_URL="$PEER1_URL"
export ADMIN_TOKEN="$PEER1_TOKEN"

elapsed=0
synced=false
while [ "$elapsed" -lt "$SYNC_TIMEOUT" ]; do
  if resp=$(api_get "/api/v1/repositories/${REPO_KEY}/artifacts" 2>/dev/null); then
    if [[ "$resp" == *"payload.bin"* ]]; then
      synced=true
      break
    fi
  fi
  sleep 5
  elapsed=$(( elapsed + 5 ))
  echo "  ...waiting for sync (${elapsed}s)"
done

if $synced; then
  pass
else
  fail "artifact did not sync to peer1 within ${SYNC_TIMEOUT}s"
fi

# ---------------------------------------------------------------------------
# Verify synced artifact integrity
# ---------------------------------------------------------------------------

begin_test "Verify synced artifact checksum"
if curl -sf -H "$(auth_header)" \
    -o "${WORK_DIR}/synced.bin" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}/download/sync-test/v1/payload.bin"; then
  SYNCED_SHA256=$(shasum -a 256 "${WORK_DIR}/synced.bin" | awk '{print $1}')
  if assert_eq "$SYNCED_SHA256" "$ORIG_SHA256" "synced file SHA256 mismatch"; then
    pass
  fi
else
  fail "download from peer1 failed"
fi

# ---------------------------------------------------------------------------
# Upload second artifact and verify sync
# ---------------------------------------------------------------------------

# Restore main context
export BASE_URL="$ORIG_BASE_URL"
export ADMIN_TOKEN="$ORIG_TOKEN"

begin_test "Upload second artifact and verify sync"
echo "second artifact content ${RUN_ID}" > "${WORK_DIR}/second.txt"
if api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/sync-test/v1/second.txt" \
    "${WORK_DIR}/second.txt" "text/plain" > /dev/null; then

  # Wait for sync
  export BASE_URL="$PEER1_URL"
  export ADMIN_TOKEN="$PEER1_TOKEN"

  elapsed=0
  synced=false
  while [ "$elapsed" -lt "$SYNC_TIMEOUT" ]; do
    if resp=$(api_get "/api/v1/repositories/${REPO_KEY}/artifacts" 2>/dev/null); then
      if [[ "$resp" == *"second.txt"* ]]; then
        synced=true
        break
      fi
    fi
    sleep 5
    elapsed=$(( elapsed + 5 ))
  done

  if $synced; then
    pass
  else
    fail "second artifact did not sync within ${SYNC_TIMEOUT}s"
  fi

  # Restore main context
  export BASE_URL="$ORIG_BASE_URL"
  export ADMIN_TOKEN="$ORIG_TOKEN"
else
  fail "upload of second artifact failed"
fi

end_suite
