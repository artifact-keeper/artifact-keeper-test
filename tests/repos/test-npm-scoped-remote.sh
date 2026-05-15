#!/usr/bin/env bash
# test-npm-scoped-remote.sh - NPM scoped package remote proxy
#
# Verifies that scoped npm packages (@scope/pkg) work correctly through
# remote and virtual npm repositories. The scope separator must be
# URL-encoded (%2F) in upstream requests per the npm registry protocol.
#
# Tests both metadata fetch and tarball download through a remote proxy
# using an AK-to-AK upstream (local repo as the "upstream registry").
#
# Fixes: https://github.com/artifact-keeper/artifact-keeper/issues/616
#
# Requires: npm, curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "npm-scoped-remote"
auth_admin
setup_workdir
require_cmd npm

UPSTREAM_KEY="test-npm-upstream-${RUN_ID}"
REMOTE_KEY="test-npm-remote-${RUN_ID}"
SCOPE="e2escope"
PKG_SHORT="testpkg"
SCOPED_NAME="@${SCOPE}/${PKG_SHORT}"
PKG_VERSION="1.0.$(date +%s)"

# ---------------------------------------------------------------------------
# Create upstream local npm repo
# ---------------------------------------------------------------------------

begin_test "Create local npm repo (upstream)"
if create_local_repo "$UPSTREAM_KEY" "npm"; then
  pass
else
  fail "could not create npm upstream repo"
fi

# ---------------------------------------------------------------------------
# Publish scoped package to upstream
# ---------------------------------------------------------------------------

begin_test "Publish scoped package to upstream"

cd "$WORK_DIR"
mkdir -p scoped-pkg && cd scoped-pkg

cat > package.json <<EOF
{
  "name": "${SCOPED_NAME}",
  "version": "${PKG_VERSION}",
  "description": "E2E test: scoped package for remote proxy",
  "main": "index.js",
  "license": "MIT"
}
EOF

cat > index.js <<EOF
module.exports = { hello: function() { return "Hello from ${SCOPED_NAME}"; } };
EOF

UPSTREAM_REGISTRY="${BASE_URL}/npm/${UPSTREAM_KEY}/"
AUTH_B64=$(printf '%s:%s' "$ADMIN_USER" "$ADMIN_PASS" | base64)

cat > .npmrc <<EOF
//${BASE_URL#http*://}/npm/${UPSTREAM_KEY}/:_auth=${AUTH_B64}
registry=${UPSTREAM_REGISTRY}
EOF

if npm publish --registry "${UPSTREAM_REGISTRY}" 2>/dev/null; then
  pass
else
  fail "npm publish of scoped package failed"
fi

# ---------------------------------------------------------------------------
# Create remote npm repo pointing at upstream
# ---------------------------------------------------------------------------

begin_test "Create remote npm repo"
UPSTREAM_URL="${BASE_URL}/npm/${UPSTREAM_KEY}"
if create_remote_repo "$REMOTE_KEY" "npm" "$UPSTREAM_URL"; then
  pass
else
  fail "could not create remote npm repo"
fi

sleep 2

# ---------------------------------------------------------------------------
# Fetch scoped package metadata through remote (uses %2F encoding)
# ---------------------------------------------------------------------------

begin_test "Fetch scoped metadata via remote proxy"
# The backend must encode @scope/pkg as @scope%2Fpkg when requesting upstream
if resp=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${BASE_URL}/npm/${REMOTE_KEY}/@${SCOPE}/${PKG_SHORT}" 2>/dev/null); then
  if echo "$resp" | jq -e '.name' > /dev/null 2>&1; then
    fetched_name=$(echo "$resp" | jq -r '.name')
    if [ "$fetched_name" = "${SCOPED_NAME}" ]; then
      pass
    else
      fail "metadata name '${fetched_name}' does not match '${SCOPED_NAME}'"
    fi
  else
    fail "metadata response is not valid JSON"
  fi
else
  fail "could not fetch scoped metadata through remote proxy"
fi

# ---------------------------------------------------------------------------
# Fetch metadata using percent-encoded URL (client sends %2F)
# ---------------------------------------------------------------------------

begin_test "Fetch scoped metadata with encoded slash (%2F)"
if resp=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${BASE_URL}/npm/${REMOTE_KEY}/@${SCOPE}%2F${PKG_SHORT}" 2>/dev/null); then
  fetched_name=$(echo "$resp" | jq -r '.name // empty')
  if [ "$fetched_name" = "${SCOPED_NAME}" ]; then
    pass
  else
    fail "encoded-URL metadata name '${fetched_name}' does not match '${SCOPED_NAME}'"
  fi
else
  fail "could not fetch metadata with encoded slash"
fi

# ---------------------------------------------------------------------------
# Download tarball through remote proxy
# ---------------------------------------------------------------------------

begin_test "Download scoped tarball via remote proxy"
# Extract tarball URL from metadata
tarball_filename="${PKG_SHORT}-${PKG_VERSION}.tgz"
download_url="${BASE_URL}/npm/${REMOTE_KEY}/@${SCOPE}/${PKG_SHORT}/-/${tarball_filename}"

if curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    -o "${WORK_DIR}/remote-scoped.tgz" "$download_url" 2>/dev/null; then
  if [ -s "${WORK_DIR}/remote-scoped.tgz" ]; then
    pass
  else
    fail "downloaded tarball is empty"
  fi
else
  fail "could not download scoped tarball through remote proxy"
fi

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

api_delete "/api/v1/repositories/${REMOTE_KEY}" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${UPSTREAM_KEY}" > /dev/null 2>&1 || true

end_suite
