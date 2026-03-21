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

# Puppet Forge publish: POST multipart with "file" (tarball) and "module" (JSON metadata)
MODULE_JSON=$(printf '{"owner":"%s","name":"%s","version":"%s"}' \
  "$MODULE_AUTHOR" "$MODULE_NAME" "$MODULE_VERSION")

upload_status=$(curl -s -o /dev/null -w '%{http_code}' \
  -X POST \
  -H "$(format_auth_header)" \
  -F "file=@${MOD_TARBALL}" \
  -F "module=${MODULE_JSON}" \
  "${BASE_URL}/puppet/${REPO_KEY}/v3/releases") || true

if [ "$upload_status" = "200" ] || [ "$upload_status" = "201" ]; then
  pass
else
  fail "module upload returned ${upload_status}, expected 200 or 201"
fi

# -----------------------------------------------------------------------
# Query Forge API module info
# -----------------------------------------------------------------------
begin_test "Query Forge API module info"
forge_resp=$(curl -sf -H "$(format_auth_header)" \
  "${BASE_URL}/puppet/${REPO_KEY}/v3/modules/${FULL_MODULE_NAME}" 2>/dev/null) || true

if [ -n "$forge_resp" ] && echo "$forge_resp" | grep -q "$MODULE_NAME"; then
  pass
else
  fail "module ${MODULE_NAME} not found via Forge API module info endpoint"
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

# -----------------------------------------------------------------------
# Download and verify module
# -----------------------------------------------------------------------
begin_test "Download and verify module"
dl_file="$WORK_DIR/downloaded-module.tar.gz"
dl_status=$(curl -sf -o "$dl_file" -w '%{http_code}' \
  -H "$(format_auth_header)" \
  "${BASE_URL}/puppet/${REPO_KEY}/v3/files/${FULL_MODULE_NAME}-${MODULE_VERSION}.tar.gz" 2>/dev/null) || true

if [ "$dl_status" = "200" ] && [ -s "$dl_file" ]; then
  pass
else
  # Try management API
  if curl -sf -H "$(auth_header)" \
      -o "$dl_file" \
      "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/${FULL_MODULE_NAME}/${MODULE_VERSION}/${FULL_MODULE_NAME}-${MODULE_VERSION}.tar.gz"; then
    if [ -s "$dl_file" ]; then
      pass
    else
      fail "downloaded file is empty"
    fi
  elif [ "$dl_status" = "404" ] || [ "$dl_status" = "405" ]; then
    skip "download endpoint not available for this format (status: ${dl_status})"
  else
    fail "download failed (status: ${dl_status})"
  fi
fi

# -----------------------------------------------------------------------
# Upload second version
# -----------------------------------------------------------------------
begin_test "Upload second version"
MODULE_VERSION_V2="2.0.$(date +%s)"
MOD_DIR_V2="$WORK_DIR/${FULL_MODULE_NAME}-${MODULE_VERSION_V2}"
mkdir -p "$MOD_DIR_V2/manifests"

cat > "$MOD_DIR_V2/metadata.json" <<EOF
{
  "name": "${MODULE_AUTHOR}-${MODULE_NAME}",
  "version": "${MODULE_VERSION_V2}",
  "author": "${MODULE_AUTHOR}",
  "summary": "E2E test module v2",
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

cat > "$MOD_DIR_V2/manifests/init.pp" <<EOF
class ${MODULE_NAME} {
  notify { 'Hello from Puppet E2E test v2!': }
}
EOF

MOD_TARBALL_V2="$WORK_DIR/${FULL_MODULE_NAME}-${MODULE_VERSION_V2}.tar.gz"
tar czf "$MOD_TARBALL_V2" -C "$WORK_DIR" "${FULL_MODULE_NAME}-${MODULE_VERSION_V2}"

MODULE_JSON_V2=$(printf '{"owner":"%s","name":"%s","version":"%s"}' \
  "$MODULE_AUTHOR" "$MODULE_NAME" "$MODULE_VERSION_V2")

v2_status=$(curl -s -o /dev/null -w '%{http_code}' \
  -X POST \
  -H "$(format_auth_header)" \
  -F "file=@${MOD_TARBALL_V2}" \
  -F "module=${MODULE_JSON_V2}" \
  "${BASE_URL}/puppet/${REPO_KEY}/v3/releases") || true

if [ "$v2_status" = "200" ] || [ "$v2_status" = "201" ]; then
  pass
elif [ "$v2_status" = "404" ] || [ "$v2_status" = "405" ]; then
  skip "version upload endpoint not available for this format (status: ${v2_status})"
else
  fail "v2 upload returned ${v2_status}"
fi

# -----------------------------------------------------------------------
# Delete module and verify removal
# -----------------------------------------------------------------------
begin_test "Delete module and verify removal"
status=$(curl -s -o /dev/null -w "%{http_code}" \
  -X DELETE -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/${FULL_MODULE_NAME}/${MODULE_VERSION}/${FULL_MODULE_NAME}-${MODULE_VERSION}.tar.gz" 2>&1) || true
if [ "$status" = "200" ] || [ "$status" = "204" ]; then
  verify_status=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "$(auth_header)" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/${FULL_MODULE_NAME}/${MODULE_VERSION}/${FULL_MODULE_NAME}-${MODULE_VERSION}.tar.gz" 2>&1) || true
  if [ "$verify_status" = "404" ]; then
    pass
  else
    fail "artifact still accessible after delete (status: ${verify_status})"
  fi
elif [ "$status" = "404" ] || [ "$status" = "405" ]; then
  skip "delete not supported for this format (status: ${status})"
else
  fail "delete returned ${status}"
fi

end_suite
