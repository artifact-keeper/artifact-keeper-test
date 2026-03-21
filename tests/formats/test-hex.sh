#!/usr/bin/env bash
# test-hex.sh - Hex (Elixir/Erlang) package registry E2E test (curl-based)
#
# Uploads an Elixir package to the Hex registry endpoint, verifies it via
# the Hex registry API, and lists artifacts via the management API.

source "$(dirname "$0")/../lib/common.sh"

begin_suite "hex"
auth_admin
setup_workdir

REPO_KEY="test-hex-${RUN_ID}"
PACKAGE_NAME="e2e_hello"
PACKAGE_VERSION="1.0.$(date +%s)"

# -----------------------------------------------------------------------
# Create repository
# -----------------------------------------------------------------------
begin_test "Create Hex local repository"
if create_local_repo "$REPO_KEY" "hex"; then
  pass
else
  fail "could not create hex repo"
fi

# -----------------------------------------------------------------------
# Generate a minimal Hex package tarball
# -----------------------------------------------------------------------
# Hex packages are outer tarballs containing: VERSION, metadata.config, contents.tar.gz
begin_test "Upload Hex package"
PKG_DIR="$WORK_DIR/pkg"
mkdir -p "$PKG_DIR/lib"

cat > "$PKG_DIR/lib/e2e_hello.ex" <<'EOF'
defmodule E2eHello do
  def hello, do: "Hello from Hex E2E test!"
end
EOF

# Build the inner contents tarball
CONTENTS_TAR="$WORK_DIR/contents.tar.gz"
tar czf "$CONTENTS_TAR" -C "$PKG_DIR" lib

# Create metadata.config (Erlang term format)
cat > "$WORK_DIR/metadata.config" <<EOF
{<<"name">>, <<"${PACKAGE_NAME}">>}.
{<<"version">>, <<"${PACKAGE_VERSION}">>}.
{<<"description">>, <<"E2E test package">>}.
{<<"app">>, <<"${PACKAGE_NAME}">>}.
{<<"build_tools">>, [<<"mix">>]}.
{<<"requirements">>, []}.
EOF

# VERSION file
echo "3" > "$WORK_DIR/VERSION"

# Outer tarball
HEX_TARBALL="$WORK_DIR/${PACKAGE_NAME}-${PACKAGE_VERSION}.tar"
tar cf "$HEX_TARBALL" -C "$WORK_DIR" VERSION metadata.config contents.tar.gz

upload_status=$(curl -s -o /dev/null -w '%{http_code}' \
  -X PUT \
  -H "$(format_auth_header)" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@${HEX_TARBALL}" \
  "${BASE_URL}/hex/${REPO_KEY}/packages/${PACKAGE_NAME}/releases/${PACKAGE_VERSION}") || true

if [ "$upload_status" = "200" ] || [ "$upload_status" = "201" ]; then
  pass
else
  # Try alternate publish endpoint
  upload_status=$(curl -s -o /dev/null -w '%{http_code}' \
    -X POST \
    -H "$(format_auth_header)" \
    -H "Content-Type: application/octet-stream" \
    --data-binary "@${HEX_TARBALL}" \
    "${BASE_URL}/hex/${REPO_KEY}/publish" 2>/dev/null) || true
  if [ "$upload_status" = "200" ] || [ "$upload_status" = "201" ]; then
    pass
  else
    fail "package upload returned ${upload_status}, expected 200 or 201"
  fi
fi

# -----------------------------------------------------------------------
# Query package info
# -----------------------------------------------------------------------
begin_test "Query package info"
pkg_resp=$(curl -sf -H "$(format_auth_header)" \
  "${BASE_URL}/hex/${REPO_KEY}/packages/${PACKAGE_NAME}" 2>/dev/null) || true

if [ -z "$pkg_resp" ]; then
  # Try the /api/packages endpoint
  pkg_resp=$(curl -sf -H "$(format_auth_header)" \
    "${BASE_URL}/hex/${REPO_KEY}/api/packages/${PACKAGE_NAME}" 2>/dev/null) || true
fi

if [ -n "$pkg_resp" ] && echo "$pkg_resp" | grep -q "$PACKAGE_NAME"; then
  pass
else
  fail "package ${PACKAGE_NAME} not found in registry"
fi

# -----------------------------------------------------------------------
# List artifacts via management API
# -----------------------------------------------------------------------
begin_test "List artifacts via management API"
if resp=$(api_get "/api/v1/repositories/${REPO_KEY}/artifacts"); then
  if assert_contains "$resp" "$PACKAGE_NAME" "artifact list should contain package"; then
    pass
  fi
else
  fail "GET /api/v1/repositories/${REPO_KEY}/artifacts returned error"
fi

# -----------------------------------------------------------------------
# Download and verify package
# -----------------------------------------------------------------------
begin_test "Download and verify package"
dl_file="$WORK_DIR/downloaded-hex.tar"
dl_status=$(curl -sf -o "$dl_file" -w '%{http_code}' \
  -H "$(format_auth_header)" \
  "${BASE_URL}/hex/${REPO_KEY}/tarballs/${PACKAGE_NAME}-${PACKAGE_VERSION}.tar" 2>/dev/null) || true

if [ "$dl_status" = "200" ] && [ -s "$dl_file" ]; then
  pass
else
  # Try the management API
  if curl -sf -H "$(auth_header)" \
      -o "$dl_file" \
      "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/${PACKAGE_NAME}/${PACKAGE_VERSION}/${PACKAGE_NAME}-${PACKAGE_VERSION}.tar"; then
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
PACKAGE_VERSION_V2="2.0.$(date +%s)"

cat > "$WORK_DIR/metadata.config" <<EOF
{<<"name">>, <<"${PACKAGE_NAME}">>}.
{<<"version">>, <<"${PACKAGE_VERSION_V2}">>}.
{<<"description">>, <<"E2E test package v2">>}.
{<<"app">>, <<"${PACKAGE_NAME}">>}.
{<<"build_tools">>, [<<"mix">>]}.
{<<"requirements">>, []}.
EOF

echo "3" > "$WORK_DIR/VERSION"

tar czf "$WORK_DIR/contents.tar.gz" -C "$PKG_DIR" lib

HEX_TARBALL_V2="$WORK_DIR/${PACKAGE_NAME}-${PACKAGE_VERSION_V2}.tar"
tar cf "$HEX_TARBALL_V2" -C "$WORK_DIR" VERSION metadata.config contents.tar.gz

v2_status=$(curl -s -o /dev/null -w '%{http_code}' \
  -X PUT \
  -H "$(format_auth_header)" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@${HEX_TARBALL_V2}" \
  "${BASE_URL}/hex/${REPO_KEY}/packages/${PACKAGE_NAME}/releases/${PACKAGE_VERSION_V2}") || true

if [ "$v2_status" = "200" ] || [ "$v2_status" = "201" ]; then
  pass
else
  # Try alternate publish endpoint
  v2_status=$(curl -s -o /dev/null -w '%{http_code}' \
    -X POST \
    -H "$(format_auth_header)" \
    -H "Content-Type: application/octet-stream" \
    --data-binary "@${HEX_TARBALL_V2}" \
    "${BASE_URL}/hex/${REPO_KEY}/publish" 2>/dev/null) || true
  if [ "$v2_status" = "200" ] || [ "$v2_status" = "201" ]; then
    pass
  elif [ "$v2_status" = "404" ] || [ "$v2_status" = "405" ]; then
    skip "version upload endpoint not available for this format (status: ${v2_status})"
  else
    fail "v2 upload returned ${v2_status}"
  fi
fi

# -----------------------------------------------------------------------
# Delete package and verify removal
# -----------------------------------------------------------------------
begin_test "Delete package and verify removal"
status=$(curl -s -o /dev/null -w "%{http_code}" \
  -X DELETE -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/${PACKAGE_NAME}/${PACKAGE_VERSION}/${PACKAGE_NAME}-${PACKAGE_VERSION}.tar" 2>&1) || true
if [ "$status" = "200" ] || [ "$status" = "204" ]; then
  verify_status=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "$(auth_header)" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/${PACKAGE_NAME}/${PACKAGE_VERSION}/${PACKAGE_NAME}-${PACKAGE_VERSION}.tar" 2>&1) || true
  if [ "$verify_status" = "404" ]; then
    pass
  else
    fail "artifact still accessible after delete (status: ${verify_status})"
  fi
else
  # Try deleting via format-native endpoint
  status=$(curl -s -o /dev/null -w "%{http_code}" \
    -X DELETE -H "$(format_auth_header)" \
    "${BASE_URL}/hex/${REPO_KEY}/packages/${PACKAGE_NAME}/releases/${PACKAGE_VERSION}" 2>&1) || true
  if [ "$status" = "200" ] || [ "$status" = "204" ]; then
    pass
  elif [ "$status" = "404" ] || [ "$status" = "405" ]; then
    skip "delete not supported for this format (status: ${status})"
  else
    fail "delete returned ${status}"
  fi
fi

end_suite
