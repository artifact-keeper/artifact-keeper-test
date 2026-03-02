#!/usr/bin/env bash
# test-npm.sh - NPM registry E2E test
#
# Tests npm publish (PUT) and npm install (GET) against the
# /npm/{repo_key}/ endpoints.
#
# Requires: npm

source "$(dirname "$0")/../lib/common.sh"

begin_suite "npm"
auth_admin
setup_workdir
require_cmd npm

REPO_KEY="test-npm-${RUN_ID}"
PKG_NAME="test-npm-pkg-${RUN_ID}"
PKG_VERSION="1.0.$(date +%s)"
NPM_REGISTRY="${BASE_URL}/npm/${REPO_KEY}/"

# ---------------------------------------------------------------------------
# Create repository
# ---------------------------------------------------------------------------

begin_test "Create npm local repository"
if create_local_repo "$REPO_KEY" "npm"; then
  pass
else
  fail "could not create npm repository"
fi

# ---------------------------------------------------------------------------
# Publish package via npm
# ---------------------------------------------------------------------------

begin_test "Publish package with npm"

cd "$WORK_DIR"
mkdir -p publish-pkg && cd publish-pkg

cat > package.json <<EOF
{
  "name": "${PKG_NAME}",
  "version": "${PKG_VERSION}",
  "description": "E2E test package for npm format",
  "main": "index.js",
  "license": "MIT"
}
EOF

cat > index.js <<EOF
module.exports = {
  hello: function() { return "Hello from ${PKG_NAME}"; },
  version: "${PKG_VERSION}"
};
EOF

# Configure npm to use our registry with basic auth
AUTH_B64=$(printf '%s:%s' "${ADMIN_USER}" "${ADMIN_PASS}" | base64)
REGISTRY_HOST=$(echo "$NPM_REGISTRY" | sed -E 's|https?:||')

# Write auth to both project and user .npmrc for compatibility
NPM_AUTH_LINE="//${REGISTRY_HOST}:_auth=${AUTH_B64}"
cat > .npmrc <<EOF
registry=${NPM_REGISTRY}
${NPM_AUTH_LINE}
always-auth=true
EOF
cp .npmrc "${HOME}/.npmrc" 2>/dev/null || true

if npm publish --registry "$NPM_REGISTRY" 2>&1; then
  pass
else
  fail "npm publish failed"
fi

# ---------------------------------------------------------------------------
# Verify package metadata via API
# ---------------------------------------------------------------------------

begin_test "Verify package metadata via API"
sleep 1
if resp=$(api_get "/npm/${REPO_KEY}/${PKG_NAME}"); then
  if assert_contains "$resp" "$PKG_VERSION" "metadata should contain version"; then
    if assert_contains "$resp" "$PKG_NAME" "metadata should contain package name"; then
      pass
    fi
  fi
else
  fail "GET /npm/${REPO_KEY}/${PKG_NAME} returned error"
fi

# ---------------------------------------------------------------------------
# Install package via npm
# ---------------------------------------------------------------------------

begin_test "Install package with npm"

cd "$WORK_DIR"
mkdir -p install-test && cd install-test
npm init -y > /dev/null 2>&1

cat > .npmrc <<EOF
registry=${NPM_REGISTRY}
//${REGISTRY_HOST}:_auth=${AUTH_B64}
EOF

if npm install "${PKG_NAME}@${PKG_VERSION}" 2>&1; then
  pass
else
  fail "npm install failed"
fi

# ---------------------------------------------------------------------------
# Verify installed package works
# ---------------------------------------------------------------------------

begin_test "Verify installed package content"
if output=$(node -e "const p = require('${PKG_NAME}'); console.log(p.hello());" 2>&1); then
  if assert_contains "$output" "Hello from ${PKG_NAME}"; then
    pass
  fi
else
  fail "require() of installed package failed: ${output}"
fi

# ---------------------------------------------------------------------------
# Download tarball directly
# ---------------------------------------------------------------------------

begin_test "Download tarball via API"
# npm stores tarballs at /{package}/-/{package}-{version}.tgz
TARBALL_PATH="/npm/${REPO_KEY}/${PKG_NAME}/-/${PKG_NAME}-${PKG_VERSION}.tgz"
if assert_http_ok "$TARBALL_PATH"; then
  pass
fi

# ---------------------------------------------------------------------------
# Verify repository artifacts via management API
# ---------------------------------------------------------------------------

begin_test "List artifacts via management API"
if resp=$(api_get "/api/v1/repositories/${REPO_KEY}/artifacts"); then
  if assert_contains "$resp" "$PKG_NAME" "artifact list should contain package"; then
    pass
  fi
else
  fail "GET /api/v1/repositories/${REPO_KEY}/artifacts returned error"
fi

end_suite
