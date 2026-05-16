#!/usr/bin/env bash
# test-sync-filter-application.sh - Sync filter applied on artifact selection (Epic 12.4, #78)
#
# Verifies that when a sync policy has a `filter` glob, only matching
# artifacts are eligible for sync. This test creates a policy with a
# narrow filter ("*.tar.gz") and asserts the API surface reflects it.
#
# Caveat: artifact-keeper-fzj -- the sync worker doesn't queue tasks in
# the ephemeral E2E env (the worker runs in a separate process that isn't
# started in this test harness). We therefore test the API contract for
# the filter field rather than the end-to-end transfer. End-to-end transfer
# coverage lives in tests/mesh/test-artifact-sync.sh and runs only in the
# multi-instance release-gate env.
#
# Requires: curl, jq, MAIN_URL + PEER1_URL exported.
source "$(dirname "$0")/../lib/common.sh"

begin_suite "federation-sync-filter-application"

# Gate: only run if mesh env vars are set. Single-instance dev environments
# don't have a peer to sync to.
if [ -z "${PEER1_URL:-}" ]; then
  skip_suite "PEER1_URL not set -- multi-instance env required"
  end_suite
fi

MAIN_URL="${MAIN_URL:-$BASE_URL}"
BASE_URL="$MAIN_URL"
auth_admin

PEER_NAME="fed-filter-peer-${RUN_ID}"
POLICY_NAME="fed-filter-policy-${RUN_ID}"
REPO_KEY="fed-filter-repo-${RUN_ID}"
PEER_ID=""
POLICY_ID=""

begin_test "Create local repo for filtered sync"
if create_local_repo "$REPO_KEY" "generic"; then
  pass
else
  fail "could not create repo"
fi

begin_test "Register peer"
peer_payload="{\"name\":\"${PEER_NAME}\",\"endpoint_url\":\"${PEER1_URL}\",\"api_key\":\"fed-test-key\"}"
if resp=$(api_post "/api/v1/peers" "$peer_payload" 2>/dev/null); then
  PEER_ID=$(echo "$resp" | jq -r '.id // empty')
  if [ -n "$PEER_ID" ] && [ "$PEER_ID" != "null" ]; then
    pass
  else
    fail "peer registered but no id: ${resp:0:200}"
  fi
else
  fail "peer registration failed"
fi

begin_test "Create sync policy with *.tar.gz filter"
if [ -z "${PEER_ID:-}" ] || [ "$PEER_ID" = "null" ]; then
  skip "no peer"
else
  policy_payload=$(cat <<EOF
{
  "name": "${POLICY_NAME}",
  "peer_id": "${PEER_ID}",
  "repository_key": "${REPO_KEY}",
  "direction": "push",
  "filter": "*.tar.gz",
  "schedule": "manual"
}
EOF
)
  if resp=$(api_post "/api/v1/sync-policies" "$policy_payload" 2>/dev/null); then
    POLICY_ID=$(echo "$resp" | jq -r '.id // empty')
    if [ -n "$POLICY_ID" ] && [ "$POLICY_ID" != "null" ]; then
      pass
    else
      fail "policy created but no id: ${resp:0:200}"
    fi
  else
    fail "sync policy creation failed"
  fi
fi

begin_test "GET sync policy echoes the filter back verbatim"
if [ -z "${POLICY_ID:-}" ] || [ "$POLICY_ID" = "null" ]; then
  skip "no policy"
else
  if resp=$(api_get "/api/v1/sync-policies/${POLICY_ID}" 2>/dev/null); then
    filter=$(echo "$resp" | jq -r '.filter // empty')
    if [ "$filter" = "*.tar.gz" ]; then
      pass
    else
      fail "expected filter='*.tar.gz', got '${filter}'"
    fi
  else
    fail "could not GET sync policy"
  fi
fi

# TODO(#78.4): The end-to-end check (upload .tar.gz + upload .txt, trigger
# sync, assert only .tar.gz appears on peer) needs the sync worker which
# is gated by artifact-keeper-fzj. Re-enable in the mesh release-gate job
# once the worker is started in the test harness.

begin_test "Trigger manual sync run (best-effort)"
if [ -z "${POLICY_ID:-}" ] || [ "$POLICY_ID" = "null" ]; then
  skip "no policy"
else
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X POST \
    -H "$(auth_header)" \
    "${BASE_URL}/api/v1/sync-policies/${POLICY_ID}/run" 2>/dev/null) || status=000
  # 202 ideal. 200 acceptable. 503/501 in ephemeral env (artifact-keeper-fzj).
  if [ "$status" = "202" ] || [ "$status" = "200" ]; then
    pass
  elif [ "$status" = "503" ] || [ "$status" = "501" ]; then
    skip "sync worker not running in this env (artifact-keeper-fzj)"
  else
    fail "expected 200/202 from run-now, got ${status}"
  fi
fi

# Cleanup
if [ -n "${POLICY_ID:-}" ] && [ "$POLICY_ID" != "null" ]; then
  api_delete "/api/v1/sync-policies/${POLICY_ID}" > /dev/null 2>&1 || true
fi
if [ -n "${PEER_ID:-}" ] && [ "$PEER_ID" != "null" ]; then
  api_delete "/api/v1/peers/${PEER_ID}" > /dev/null 2>&1 || true
fi
api_delete "/api/v1/repositories/${REPO_KEY}" > /dev/null 2>&1 || true

end_suite
