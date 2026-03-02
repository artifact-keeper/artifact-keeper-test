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

end_suite
