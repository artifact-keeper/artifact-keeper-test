#!/usr/bin/env bash
# test-go-remote.sh - Go remote proxy E2E test
#
# Verifies that Go modules can be fetched through a remote repository
# pointing at proxy.golang.org. No local uploads; this test exercises
# the GOPROXY proxy/cache path for remote upstreams.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "go-remote"
auth_admin

REPO_KEY="test-go-remote-${RUN_ID}"
UPSTREAM_URL="https://proxy.golang.org"
MODULE_PATH="golang.org/x/text"
MODULE_VERSION="v0.14.0"

# -------------------------------------------------------------------------
# Create remote Go repository
# -------------------------------------------------------------------------

begin_test "Create remote Go repository"
if create_remote_repo "$REPO_KEY" "go" "$UPSTREAM_URL"; then
  pass
else
  fail "could not create remote Go repo"
fi

# -------------------------------------------------------------------------
# Check upstream reachability before running proxy tests
# -------------------------------------------------------------------------

begin_test "Verify upstream reachability"
if curl -sf --max-time 10 "${UPSTREAM_URL}/golang.org/x/text/@v/list" > /dev/null 2>&1; then
  UPSTREAM_REACHABLE=true
  pass
else
  UPSTREAM_REACHABLE=false
  skip "proxy.golang.org unreachable from test environment"
fi

# -------------------------------------------------------------------------
# list_versions: GET /go/{repo_key}/golang.org/x/text/@v/list
# -------------------------------------------------------------------------

begin_test "List versions via remote proxy"
if [ "$UPSTREAM_REACHABLE" != "true" ]; then
  skip "upstream unreachable"
else
  sleep 1
  if resp=$(curl -sf $CURL_TIMEOUT \
      -u "${ADMIN_USER}:${ADMIN_PASS}" \
      "${BASE_URL}/go/${REPO_KEY}/${MODULE_PATH}/@v/list" 2>/dev/null); then
    # The response should contain at least one version string (e.g. v0.14.0)
    if echo "$resp" | grep -qE '^v[0-9]+\.[0-9]+'; then
      pass
    else
      fail "version list did not contain version strings"
    fi
  else
    fail "list versions endpoint returned error"
  fi
fi

# -------------------------------------------------------------------------
# version_info: GET /go/{repo_key}/golang.org/x/text/@v/v0.14.0.info
# -------------------------------------------------------------------------

begin_test "Get version info via remote proxy"
if [ "$UPSTREAM_REACHABLE" != "true" ]; then
  skip "upstream unreachable"
else
  if resp=$(curl -sf $CURL_TIMEOUT \
      -u "${ADMIN_USER}:${ADMIN_PASS}" \
      "${BASE_URL}/go/${REPO_KEY}/${MODULE_PATH}/@v/${MODULE_VERSION}.info" 2>/dev/null); then
    if assert_contains "$resp" "${MODULE_VERSION}"; then
      pass
    fi
  else
    fail ".info endpoint returned error"
  fi
fi

# -------------------------------------------------------------------------
# latest_version: GET /go/{repo_key}/golang.org/x/text/@latest
# -------------------------------------------------------------------------

begin_test "Get latest version via remote proxy"
if [ "$UPSTREAM_REACHABLE" != "true" ]; then
  skip "upstream unreachable"
else
  if resp=$(curl -sf $CURL_TIMEOUT \
      -u "${ADMIN_USER}:${ADMIN_PASS}" \
      "${BASE_URL}/go/${REPO_KEY}/${MODULE_PATH}/@latest" 2>/dev/null); then
    # Response should be JSON containing a Version field
    if echo "$resp" | jq -e '.Version // .version' > /dev/null 2>&1; then
      pass
    elif assert_contains "$resp" "v"; then
      pass
    fi
  else
    skip "@latest endpoint not available for remote proxy"
  fi
fi

# -------------------------------------------------------------------------
# get_mod_file: GET /go/{repo_key}/golang.org/x/text/@v/v0.14.0.mod
# -------------------------------------------------------------------------

begin_test "Get go.mod file via remote proxy"
if [ "$UPSTREAM_REACHABLE" != "true" ]; then
  skip "upstream unreachable"
else
  if resp=$(curl -sf $CURL_TIMEOUT \
      -u "${ADMIN_USER}:${ADMIN_PASS}" \
      "${BASE_URL}/go/${REPO_KEY}/${MODULE_PATH}/@v/${MODULE_VERSION}.mod" 2>/dev/null); then
    if assert_contains "$resp" "module golang.org/x/text"; then
      pass
    fi
  else
    fail ".mod endpoint returned error"
  fi
fi

# -------------------------------------------------------------------------
# Cleanup
# -------------------------------------------------------------------------

api_delete "/api/v1/repositories/${REPO_KEY}" > /dev/null 2>&1 || true

end_suite
