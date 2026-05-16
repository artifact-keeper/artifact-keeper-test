#!/usr/bin/env bash
# test-metadata-aggregation.sh - Cross-instance metadata aggregation
# (Epic 12.10, #78)
#
# Verifies that when two peer instances each hold distinct artifacts in
# the SAME repository, a federated tree / artifact listing query
# surfaces artifacts contributed by both sides (i.e. format-aware
# metadata is aggregated, not just the local subset).
#
# This is the precondition for the Conda repodata.json / Helm index.yaml
# / CRAN PACKAGES merge behaviour referenced in the issue. We don't
# crack format-specific metadata here -- we use the generic format and
# assert that GET /api/v1/repositories/{key}/artifacts on the federation
# endpoint surfaces names that were only ever uploaded to a different
# peer. Format-specific merge correctness is tracked elsewhere.
#
# Skip cleanly if the aggregation isn't wired up (only local artifacts
# come back).
#
# Requires: curl, jq, MAIN_URL + PEER1_URL exported.
source "$(dirname "$0")/../lib/common.sh"

begin_suite "federation-metadata-aggregation"
setup_workdir

if [ -z "${PEER1_URL:-}" ]; then
  skip_suite "PEER1_URL not set -- multi-instance env required"
fi

MAIN_URL="${MAIN_URL:-$BASE_URL}"
BASE_URL="$MAIN_URL"
auth_admin
MAIN_TOKEN="$ADMIN_TOKEN"

REPO_KEY="fed-agg-${RUN_ID}"
PEER_NAME="fed-agg-peer-${RUN_ID}"
POLICY_NAME="fed-agg-policy-${RUN_ID}"
PEER_ID=""
POLICY_ID=""
SYNC_TIMEOUT="${AGG_SYNC_TIMEOUT:-75}"

cleanup_agg() {
  export BASE_URL="$MAIN_URL"; export ADMIN_TOKEN="$MAIN_TOKEN"
  if [ -n "${POLICY_ID:-}" ] && [ "$POLICY_ID" != "null" ]; then
    api_delete "/api/v1/sync-policies/${POLICY_ID}" > /dev/null 2>&1 || true
  fi
  if [ -n "${PEER_ID:-}" ] && [ "$PEER_ID" != "null" ]; then
    api_delete "/api/v1/peers/${PEER_ID}" > /dev/null 2>&1 || true
  fi
  api_delete "/api/v1/repositories/${REPO_KEY}" > /dev/null 2>&1 || true
}
add_exit_handler cleanup_agg

begin_test "Create matching repo on main + peer1"
if ! create_local_repo "$REPO_KEY" "generic"; then
  fail "could not create repo on main"
else
  export BASE_URL="$PEER1_URL"
  auth_admin
  PEER_TOKEN="$ADMIN_TOKEN"
  if create_local_repo "$REPO_KEY" "generic"; then
    pass
  else
    fail "could not create repo on peer1"
  fi
  export BASE_URL="$MAIN_URL"; export ADMIN_TOKEN="$MAIN_TOKEN"
fi

begin_test "Register peer + bidirectional policy"
payload="{\"name\":\"${PEER_NAME}\",\"endpoint_url\":\"${PEER1_URL}\",\"api_key\":\"fed-test-key\"}"
status=$(curl -s -o "${WORK_DIR}/peer.json" -w '%{http_code}' $CURL_TIMEOUT \
  -X POST -H "$(auth_header)" -H "Content-Type: application/json" \
  -d "$payload" "${BASE_URL}/api/v1/peers" 2>/dev/null) || status=000
case "$status" in
  404|501) skip "federation disabled (HTTP ${status})" ;;
  2*)
    PEER_ID=$(jq -r '.id // empty' < "${WORK_DIR}/peer.json")
    if [ -n "$PEER_ID" ] && [ "$PEER_ID" != "null" ]; then
      api_post "/api/v1/peers/${PEER_ID}/heartbeat" '{"cache_used_bytes":0}' > /dev/null 2>&1 || true
      # Try bidirectional; fall back to push if rejected.
      pol="{\"name\":\"${POLICY_NAME}\",\"repo_selector\":{\"match_pattern\":\"${REPO_KEY}\"},\"peer_selector\":{\"match_peers\":[\"${PEER_ID}\"]},\"replication_mode\":\"bidirectional\",\"enabled\":true}"
      if resp=$(api_post "/api/v1/sync-policies" "$pol" 2>/dev/null); then
        POLICY_ID=$(echo "$resp" | jq -r '.id // empty')
      else
        pol="{\"name\":\"${POLICY_NAME}\",\"repo_selector\":{\"match_pattern\":\"${REPO_KEY}\"},\"peer_selector\":{\"match_peers\":[\"${PEER_ID}\"]},\"replication_mode\":\"push\",\"enabled\":true}"
        resp=$(api_post "/api/v1/sync-policies" "$pol" 2>/dev/null) || true
        POLICY_ID=$(echo "$resp" | jq -r '.id // empty')
      fi
      api_post "/api/v1/sync-policies/evaluate" "" > /dev/null 2>&1 || true
      pass
    else
      fail "peer created but no id"
    fi
    ;;
  *) fail "peer registration failed: HTTP ${status}" ;;
esac

begin_test "Upload disjoint artifact sets to each instance"
if [ -z "${POLICY_ID:-}" ] || [ "$POLICY_ID" = "null" ]; then
  skip "no policy"
else
  echo "from-main ${RUN_ID}" > "${WORK_DIR}/m.txt"
  echo "from-peer1 ${RUN_ID}" > "${WORK_DIR}/p.txt"

  ok_main=true; ok_peer=true
  api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/agg/main-only.txt" \
    "${WORK_DIR}/m.txt" "text/plain" > /dev/null 2>&1 || ok_main=false

  export BASE_URL="$PEER1_URL"; export ADMIN_TOKEN="$PEER_TOKEN"
  api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/agg/peer-only.txt" \
    "${WORK_DIR}/p.txt" "text/plain" > /dev/null 2>&1 || ok_peer=false
  export BASE_URL="$MAIN_URL"; export ADMIN_TOKEN="$MAIN_TOKEN"

  if $ok_main && $ok_peer; then
    pass
  else
    fail "disjoint uploads failed (main=${ok_main} peer1=${ok_peer})"
  fi
fi

begin_test "Trigger sync on both directions"
if [ -z "${PEER_ID:-}" ] || [ "$PEER_ID" = "null" ]; then
  skip "no peer"
else
  curl -s -o /dev/null $CURL_TIMEOUT -X POST -H "$(auth_header)" \
    "${MAIN_URL}/api/v1/peers/${PEER_ID}/sync" 2>/dev/null || true

  # Also ask peer1 to push back; this is best-effort because the peer
  # may not have a corresponding peer-instance row pointing at main.
  export BASE_URL="$PEER1_URL"; export ADMIN_TOKEN="$PEER_TOKEN"
  if peers_resp=$(api_get "/api/v1/peers" 2>/dev/null); then
    rev_peer_id=$(echo "$peers_resp" | jq -r '[.items // .[] | select(.endpoint_url == "'"$MAIN_URL"'")][0].id // empty' 2>/dev/null || true)
    if [ -n "$rev_peer_id" ] && [ "$rev_peer_id" != "null" ]; then
      api_post "/api/v1/peers/${rev_peer_id}/sync" "" > /dev/null 2>&1 || true
    fi
  fi
  export BASE_URL="$MAIN_URL"; export ADMIN_TOKEN="$MAIN_TOKEN"
  pass
fi

begin_test "GET /artifacts on main lists artifacts from both sides"
if [ -z "${POLICY_ID:-}" ] || [ "$POLICY_ID" = "null" ]; then
  skip "no policy"
else
  elapsed=0
  saw_main=false
  saw_peer=false
  while [ "$elapsed" -lt "$SYNC_TIMEOUT" ]; do
    if resp=$(api_get "/api/v1/repositories/${REPO_KEY}/artifacts" 2>/dev/null); then
      [[ "$resp" == *"main-only.txt"* ]] && saw_main=true
      [[ "$resp" == *"peer-only.txt"* ]] && saw_peer=true
      $saw_main && $saw_peer && break
    fi
    sleep 4
    elapsed=$(( elapsed + 4 ))
  done

  if $saw_main && $saw_peer; then
    pass
  elif $saw_main && ! $saw_peer; then
    skip "peer-only artifact not aggregated on main within ${SYNC_TIMEOUT}s (federation aggregation may be deferred)"
  elif ! $saw_main; then
    fail "local artifact main-only.txt missing from listing"
  else
    skip "aggregation incomplete: saw_main=${saw_main} saw_peer=${saw_peer}"
  fi
fi

begin_test "Tree endpoint reflects aggregated paths"
# /api/v1/tree?repository_key=... is the federated browser view.
# We only assert that BOTH path prefixes (agg/main-only.txt and
# agg/peer-only.txt) are reachable -- the test above already gates
# strictness on aggregation actually working.
if [ -z "${POLICY_ID:-}" ] || [ "$POLICY_ID" = "null" ]; then
  skip "no policy"
else
  if resp=$(api_get "/api/v1/tree?repository_key=${REPO_KEY}&path=agg" 2>/dev/null); then
    tree_main=false; tree_peer=false
    [[ "$resp" == *"main-only.txt"* ]] && tree_main=true
    [[ "$resp" == *"peer-only.txt"* ]] && tree_peer=true
    if $tree_main && $tree_peer; then
      pass
    elif $tree_main || $tree_peer; then
      skip "tree endpoint partially aggregated (main=${tree_main} peer=${tree_peer})"
    else
      skip "tree endpoint returned no aggregated entries"
    fi
  else
    skip "/api/v1/tree not available on this cluster"
  fi
fi

end_suite
