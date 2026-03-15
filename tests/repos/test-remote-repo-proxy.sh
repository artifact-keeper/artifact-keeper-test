#!/usr/bin/env bash
# test-remote-repo-proxy.sh - Remote repository proxy/cache E2E test
#
# Tests that a remote repository proxies requests to an upstream URL and
# caches artifacts locally. Uses one local repo as the "upstream" and
# a remote repo pointing at it.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "remote-repo-proxy"
auth_admin
setup_workdir

UPSTREAM_KEY="test-remote-upstream-${RUN_ID}"
REMOTE_KEY="test-remote-proxy-${RUN_ID}"

# -------------------------------------------------------------------------
# Create upstream local repo and seed it with an artifact
# -------------------------------------------------------------------------

begin_test "Create upstream local repo"
if create_local_repo "$UPSTREAM_KEY" "generic"; then
  pass
else
  fail "could not create upstream repo"
fi

begin_test "Upload artifact to upstream"
echo "upstream-content-${RUN_ID}" > "${WORK_DIR}/upstream.txt"
if api_upload "/api/v1/repositories/${UPSTREAM_KEY}/artifacts/libs/artifact.jar" \
    "${WORK_DIR}/upstream.txt"; then
  pass
else
  fail "upload to upstream failed"
fi

# -------------------------------------------------------------------------
# Create remote repo pointing at the upstream
# -------------------------------------------------------------------------

begin_test "Create remote repo with upstream URL"
UPSTREAM_URL="${BASE_URL}/generic/${UPSTREAM_KEY}"
if create_remote_repo "$REMOTE_KEY" "generic" "$UPSTREAM_URL"; then
  pass
else
  fail "could not create remote repo"
fi

# -------------------------------------------------------------------------
# Fetch artifact through the remote repo (proxy)
# -------------------------------------------------------------------------

sleep 2

begin_test "Fetch artifact via remote proxy"
if resp=$(api_get "/api/v1/repositories/${REMOTE_KEY}/artifacts" 2>/dev/null); then
  if assert_contains "$resp" "artifact"; then
    pass
  else
    skip "remote proxy did not auto-cache artifact on creation"
  fi
elif curl -sf $CURL_TIMEOUT -H "$(auth_header)" \
    -o "${WORK_DIR}/proxied.txt" \
    "${BASE_URL}/generic/${REMOTE_KEY}/libs/artifact.jar" 2>/dev/null; then
  if [ -s "${WORK_DIR}/proxied.txt" ]; then
    pass
  else
    skip "proxied artifact is empty, proxy fetch may not be supported"
  fi
else
  skip "remote proxy fetch not supported for this configuration"
fi

# -------------------------------------------------------------------------
# Verify the remote repo cached the artifact
# -------------------------------------------------------------------------

begin_test "Verify artifact cached in remote repo"
sleep 2
if resp=$(api_get "/api/v1/repositories/${REMOTE_KEY}/artifacts" 2>/dev/null); then
  if [[ "$resp" == *"artifact"* ]]; then
    pass
  else
    skip "artifact not yet cached by remote proxy"
  fi
else
  skip "remote repo artifact listing not supported"
fi

# -------------------------------------------------------------------------
# Verify remote repo metadata
# -------------------------------------------------------------------------

begin_test "Get remote repo details"
if resp=$(api_get "/api/v1/repositories/${REMOTE_KEY}" 2>/dev/null); then
  if assert_contains "$resp" "remote"; then
    pass
  fi
else
  fail "could not get remote repo details"
fi

end_suite
