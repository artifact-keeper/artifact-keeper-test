#!/usr/bin/env bash
# test-puppet.sh - Puppet Forge module registry E2E test (curl-based)
#
# Uploads a minimal Puppet module tarball to the Puppet registry endpoint,
# verifies the Forge API modules listing, and lists artifacts via the
# management API.

source "$(dirname "$0")/../lib/common.sh"

begin_suite "puppet"
auth_admin
setup_workdir

REPO_KEY="test-puppet-${RUN_ID}"
MODULE_AUTHOR="e2etest"
MODULE_NAME="hellomod"
MODULE_VERSION="1.0.$(date +%s)"
FULL_MODULE_NAME="${MODULE_AUTHOR}-${MODULE_NAME}"

# -----------------------------------------------------------------------
# Create repository
# -----------------------------------------------------------------------
begin_test "Create Puppet local repository"
if create_local_repo "$REPO_KEY" "puppet"; then
  pass
else
  fail "could not create puppet repo"
fi

# -----------------------------------------------------------------------
# Generate a minimal puppet module tarball
# -----------------------------------------------------------------------
begin_test "Upload puppet module"
MOD_DIR="$WORK_DIR/${FULL_MODULE_NAME}-${MODULE_VERSION}"
mkdir -p "$MOD_DIR/manifests"

cat > "$MOD_DIR/metadata.json" <<EOF
{
  "name": "${MODULE_AUTHOR}-${MODULE_NAME}",
  "version": "${MODULE_VERSION}",
  "author": "${MODULE_AUTHOR}",
  "summary": "E2E test module for Puppet registry",
  "license": "MIT",
  "source": "https://example.com/${FULL_MODULE_NAME}",
  "dependencies": [],
  "operatingsystem_support": [
    {
      "operatingsystem": "Ubuntu",
      "operatingsystemrelease": ["22.04"]
    }
  ]
}
EOF

cat > "$MOD_DIR/manifests/init.pp" <<EOF
# @summary E2E test module
class ${MODULE_NAME} {
  notify { 'Hello from Puppet E2E test!': }
}
EOF

MOD_TARBALL="$WORK_DIR/${FULL_MODULE_NAME}-${MODULE_VERSION}.tar.gz"
tar czf "$MOD_TARBALL" -C "$WORK_DIR" "${FULL_MODULE_NAME}-${MODULE_VERSION}"

upload_status=$(curl -s -o /dev/null -w '%{http_code}' \
  -X PUT \
  -H "$(format_auth_header)" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@${MOD_TARBALL}" \
  "${BASE_URL}/puppet/${REPO_KEY}/${FULL_MODULE_NAME}/${MODULE_VERSION}") || true

if [ "$upload_status" = "200" ] || [ "$upload_status" = "201" ]; then
  pass
else
  # Try alternate upload path (POST with file field)
  upload_status=$(curl -s -o /dev/null -w '%{http_code}' \
    -X POST \
    -H "$(format_auth_header)" \
    -F "file=@${MOD_TARBALL}" \
    "${BASE_URL}/puppet/${REPO_KEY}/v3/releases" 2>/dev/null) || true
  if [ "$upload_status" = "200" ] || [ "$upload_status" = "201" ]; then
    pass
  else
    fail "module upload returned ${upload_status}, expected 200 or 201"
  fi
fi

# -----------------------------------------------------------------------
# Query Forge API modules listing
# -----------------------------------------------------------------------
begin_test "Query Forge API modules"
forge_resp=$(curl -sf -H "$(format_auth_header)" \
  "${BASE_URL}/puppet/${REPO_KEY}/v3/modules" 2>/dev/null) || true

if [ -z "$forge_resp" ]; then
  # Try with query parameter
  forge_resp=$(curl -sf -H "$(format_auth_header)" \
    "${BASE_URL}/puppet/${REPO_KEY}/v3/modules?query=${MODULE_NAME}" 2>/dev/null) || true
fi

if [ -n "$forge_resp" ] && echo "$forge_resp" | grep -q "$MODULE_NAME"; then
  pass
else
  fail "module ${MODULE_NAME} not found in Forge API modules listing"
fi

# -----------------------------------------------------------------------
# List artifacts via management API
# -----------------------------------------------------------------------
begin_test "List artifacts via management API"
if resp=$(api_get "/api/v1/repositories/${REPO_KEY}/artifacts"); then
  if assert_contains "$resp" "$MODULE_NAME" "artifact list should contain module"; then
    pass
  fi
else
  fail "GET /api/v1/repositories/${REPO_KEY}/artifacts returned error"
fi

end_suite
