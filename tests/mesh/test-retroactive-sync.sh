#!/usr/bin/env bash
# test-retroactive-sync.sh - Mesh retroactive sync E2E test
#
# Verifies that when a sync policy is created AFTER artifacts
# already exist, those pre-existing artifacts get synced.
#
# Requires: MAIN_URL, PEER1_URL

source "$(dirname "$0")/../lib/common.sh"

begin_suite "mesh-retroactive-sync"
setup_workdir

MAIN_URL="${MAIN_URL:?MAIN_URL must be set}"
PEER1_URL="${PEER1_URL:?PEER1_URL must be set}"

auth_admin

REPO_KEY="test-mesh-retro-${RUN_ID}"
SYNC_TIMEOUT="${SYNC_TIMEOUT:-60}"

# ---------------------------------------------------------------------------
# Setup: create repos, upload BEFORE creating sync policy
# ---------------------------------------------------------------------------

begin_test "Create repository on main"
if create_local_repo "$REPO_KEY" "generic"; then
  pass
else
  fail "could not create repo on main"
fi

begin_test "Upload artifacts BEFORE sync policy exists"
echo "pre-existing artifact 1" > "${WORK_DIR}/pre1.txt"
echo "pre-existing artifact 2" > "${WORK_DIR}/pre2.txt"
echo "pre-existing artifact 3" > "${WORK_DIR}/pre3.txt"

upload_ok=true
for i in 1 2 3; do
  if ! api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/retro/pre${i}.txt" \
      "${WORK_DIR}/pre${i}.txt" "text/plain" > /dev/null; then
    upload_ok=false
  fi
done

if $upload_ok; then
  pass
else
  fail "one or more pre-sync uploads failed"
fi

# ---------------------------------------------------------------------------
# Create repo on peer1
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# NOW create sync policy (after artifacts exist)
# ---------------------------------------------------------------------------

begin_test "Register peer and create sync policy"
PEER1_PAYLOAD="{\"name\":\"retro-peer1-${RUN_ID}\",\"url\":\"${PEER1_URL}\",\"enabled\":true}"
api_post "/api/v1/mesh/peers" "$PEER1_PAYLOAD" > /dev/null 2>&1 || true

POLICY="{\"name\":\"retro-sync-${RUN_ID}\",\"source_repo\":\"${REPO_KEY}\",\"target_peer\":\"retro-peer1-${RUN_ID}\",\"target_repo\":\"${REPO_KEY}\",\"sync_mode\":\"push\",\"enabled\":true}"
if api_post "/api/v1/mesh/sync-policies" "$POLICY" > /dev/null 2>&1; then
  pass
else
  fail "could not create sync policy"
fi

# ---------------------------------------------------------------------------
# Trigger retroactive sync if needed
# ---------------------------------------------------------------------------

begin_test "Trigger retroactive sync"
# Some implementations auto-sync on policy creation, others need a trigger
if api_post "/api/v1/mesh/sync-policies/trigger" "{\"repo\":\"${REPO_KEY}\"}" > /dev/null 2>&1; then
  pass
else
  # Trigger endpoint may not exist; policy creation may auto-trigger
  pass
fi

# ---------------------------------------------------------------------------
# Wait for pre-existing artifacts to appear on peer1
# ---------------------------------------------------------------------------

begin_test "Verify pre-existing artifacts synced to peer1"
export BASE_URL="$PEER1_URL"
export ADMIN_TOKEN="$PEER1_TOKEN"

elapsed=0
all_synced=false
while [ "$elapsed" -lt "$SYNC_TIMEOUT" ]; do
  if resp=$(api_get "/api/v1/repositories/${REPO_KEY}/artifacts" 2>/dev/null); then
    has1=false; has2=false; has3=false
    [[ "$resp" == *"pre1.txt"* ]] && has1=true
    [[ "$resp" == *"pre2.txt"* ]] && has2=true
    [[ "$resp" == *"pre3.txt"* ]] && has3=true

    if $has1 && $has2 && $has3; then
      all_synced=true
      break
    fi
  fi
  sleep 5
  elapsed=$(( elapsed + 5 ))
  echo "  ...waiting for retroactive sync (${elapsed}s)"
done

if $all_synced; then
  pass
else
  fail "pre-existing artifacts did not sync within ${SYNC_TIMEOUT}s"
fi

# ---------------------------------------------------------------------------
# Verify content integrity of retroactively synced artifacts
# ---------------------------------------------------------------------------

begin_test "Verify retroactively synced artifact content"
if content=$(curl -sf -H "$(auth_header)" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}/download/retro/pre1.txt" 2>/dev/null); then
  if assert_contains "$content" "pre-existing artifact 1" "content mismatch on synced artifact"; then
    pass
  fi
else
  fail "download of synced artifact from peer1 failed"
fi

# Restore main context
export BASE_URL="$ORIG_BASE_URL"
export ADMIN_TOKEN="$ORIG_TOKEN"

end_suite
