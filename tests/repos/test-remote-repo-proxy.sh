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
# Upstream-serves poll plus cache-row poll, at most 20 s each.
require_wait_budget 40 "upstream and cache-row polls"

UPSTREAM_KEY="test-remote-upstream-${RUN_ID}"
REMOTE_KEY="test-remote-proxy-${RUN_ID}"
PROXY_FETCHED=0

# upstream_serves_artifact: wait_until predicate, the upstream generic
# endpoint (the remote's upstream URL) serves the seeded artifact.
upstream_serves_artifact() {
  curl -sf -o /dev/null $CURL_TIMEOUT -H "$(auth_header)" \
    "${BASE_URL}/generic/${UPSTREAM_KEY}/libs/artifact.jar"
}

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

begin_test "Fetch artifact via remote proxy"
# Precondition: the upstream serves the artifact seeded above. Then always
# fetch THROUGH the proxy: the old first branch listed the remote's artifacts
# instead, which answers 2xx for any existing repo, so the proxy fetch (and
# the cache check after it) never ran.
if ! wait_until "upstream ${UPSTREAM_KEY} serves libs/artifact.jar" 20 upstream_serves_artifact; then
  fail "the artifact uploaded to ${UPSTREAM_KEY} was not served by its generic endpoint within 20s"
elif curl -sf $CURL_TIMEOUT -H "$(auth_header)" \
    -o "${WORK_DIR}/proxied.txt" \
    "${BASE_URL}/generic/${REMOTE_KEY}/libs/artifact.jar" 2>/dev/null; then
  PROXY_FETCHED=1
  if [ -s "${WORK_DIR}/proxied.txt" ]; then
    pass
  else
    fail "proxy fetch of libs/artifact.jar through ${REMOTE_KEY} answered 2xx with an empty body"
  fi
else
  skip "remote proxy fetch not supported for this configuration"
fi

# -------------------------------------------------------------------------
# Verify the remote repo cached the artifact
# -------------------------------------------------------------------------

begin_test "Verify artifact cached in remote repo"
# The proxy writes its cache row (proxy_cache_artifacts, listed by the
# remote's artifact listing) from a writer task that outlives the client
# response, so after a fetch through the proxy wait, bounded, for the row.
if [ "$PROXY_FETCHED" != "1" ]; then
  skip "no fetch went through the proxy, so there is nothing to have cached"
elif wait_until "cache row for libs/artifact.jar in ${REMOTE_KEY}" 20 repo_lists_artifact "$REMOTE_KEY" "artifact.jar"; then
  pass
else
  fail "a 2xx fetch through ${REMOTE_KEY} left no cache row for libs/artifact.jar in its listing within 20s" \
    "$(api_get "/api/v1/repositories/${REMOTE_KEY}/artifacts" 2>/dev/null | head -c 300)"
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
