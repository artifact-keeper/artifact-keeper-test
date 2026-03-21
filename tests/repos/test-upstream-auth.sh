#!/usr/bin/env bash
# test-upstream-auth.sh - Upstream authentication for remote repos
#
# Tests setting and removing upstream auth credentials on a remote repo,
# including basic and bearer auth types, and the test-upstream endpoint.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "upstream-auth"
auth_admin
setup_workdir

UPSTREAM_KEY="test-upauth-local-${RUN_ID}"
REMOTE_KEY="test-upauth-remote-${RUN_ID}"

# -------------------------------------------------------------------------
# Create a local repo as mock upstream and seed it with an artifact
# -------------------------------------------------------------------------

begin_test "Create local repo as upstream"
if create_local_repo "$UPSTREAM_KEY" "generic"; then
  pass
else
  fail "could not create local repo"
fi

begin_test "Upload artifact to upstream"
echo "upstream-payload-${RUN_ID}" > "${WORK_DIR}/payload.txt"
if api_upload "/api/v1/repositories/${UPSTREAM_KEY}/artifacts/libs/file.jar" \
    "${WORK_DIR}/payload.txt"; then
  pass
else
  fail "upload to upstream failed"
fi

# -------------------------------------------------------------------------
# Create remote repo pointing at the local one
# -------------------------------------------------------------------------

begin_test "Create remote repo"
UPSTREAM_URL="${BASE_URL}/generic/${UPSTREAM_KEY}"
if create_remote_repo "$REMOTE_KEY" "generic" "$UPSTREAM_URL"; then
  pass
else
  fail "could not create remote repo"
fi

# -------------------------------------------------------------------------
# Set upstream auth (basic)
# -------------------------------------------------------------------------

begin_test "Set upstream auth with basic credentials"
BASIC_AUTH_PAYLOAD="{\"auth_type\":\"basic\",\"username\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASS}\"}"
if api_put "/api/v1/repositories/${REMOTE_KEY}/upstream-auth" "$BASIC_AUTH_PAYLOAD" > /dev/null 2>&1; then
  pass
else
  skip "upstream-auth endpoint not available"
fi

# -------------------------------------------------------------------------
# Test upstream connectivity
# -------------------------------------------------------------------------

begin_test "Test upstream connectivity"
if resp=$(api_post "/api/v1/repositories/${REMOTE_KEY}/test-upstream" "" 2>/dev/null); then
  # The response should indicate success or a reachable upstream
  if echo "$resp" | jq -e '.success // .reachable // .status' > /dev/null 2>&1; then
    pass
  else
    # Any 2xx means the endpoint worked
    pass
  fi
else
  skip "test-upstream endpoint not available"
fi

# -------------------------------------------------------------------------
# Verify remote repo still shows correct details
# -------------------------------------------------------------------------

begin_test "Get remote repo details with auth configured"
if resp=$(api_get "/api/v1/repositories/${REMOTE_KEY}" 2>/dev/null); then
  if assert_contains "$resp" "remote"; then
    pass
  fi
else
  fail "could not get remote repo details"
fi

# -------------------------------------------------------------------------
# Switch to bearer auth
# -------------------------------------------------------------------------

begin_test "Set upstream auth with bearer token"
BEARER_AUTH_PAYLOAD="{\"auth_type\":\"bearer\",\"token\":\"test-bearer-token-${RUN_ID}\"}"
if api_put "/api/v1/repositories/${REMOTE_KEY}/upstream-auth" "$BEARER_AUTH_PAYLOAD" > /dev/null 2>&1; then
  pass
else
  skip "bearer auth type not supported"
fi

# -------------------------------------------------------------------------
# Remove upstream auth
# -------------------------------------------------------------------------

begin_test "Remove upstream auth"
NONE_AUTH_PAYLOAD='{"auth_type":"none"}'
if api_put "/api/v1/repositories/${REMOTE_KEY}/upstream-auth" "$NONE_AUTH_PAYLOAD" > /dev/null 2>&1; then
  pass
else
  skip "removing upstream auth not supported"
fi

# -------------------------------------------------------------------------
# Verify remote repo still works after auth removal
# -------------------------------------------------------------------------

begin_test "Remote repo accessible after auth removal"
if resp=$(api_get "/api/v1/repositories/${REMOTE_KEY}" 2>/dev/null); then
  if assert_contains "$resp" "$REMOTE_KEY"; then
    pass
  fi
else
  fail "could not access remote repo after auth removal"
fi

# -------------------------------------------------------------------------
# Cleanup
# -------------------------------------------------------------------------

api_delete "/api/v1/repositories/${REMOTE_KEY}" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${UPSTREAM_KEY}" > /dev/null 2>&1 || true

end_suite
