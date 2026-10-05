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

# CHECKSUM member. Real `mix hex.publish` outer tarballs always carry a CHECKSUM
# member (an uppercase 64-hex sha256 over the release blob). Since backend #2648
# the hosted read path (signed protobuf registry) fail-closes with HTTP 500 when
# it is missing, so the outer tarball MUST include it. The backend validates the
# format only (64 ASCII hex chars, case-insensitive), so a sha256 over the other
# members is an acceptable CHECKSUM. See artifact-keeper-test#289.
CS=$(cat "$WORK_DIR/VERSION" "$WORK_DIR/metadata.config" "$CONTENTS_TAR" | shasum -a 256 | awk '{print toupper($1)}')
printf '%s' "$CS" > "$WORK_DIR/CHECKSUM"

# Outer tarball
HEX_TARBALL="$WORK_DIR/${PACKAGE_NAME}-${PACKAGE_VERSION}.tar"
tar cf "$HEX_TARBALL" -C "$WORK_DIR" VERSION CHECKSUM metadata.config contents.tar.gz

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
# Capture the HTTP status AND body (sibling idiom: -w '\n%{http_code}', split
# with tail/sed). The old `curl -sf` swallowed the body on any >=400 and left
# pkg_resp empty, so a backend 500 (e.g. the #2648 read path fail-closing on a
# CHECKSUM-less tarball) was mis-reported as "package not found". Surfacing the
# status makes a server error a real failure with the response body attached.
pkg_http=$(curl -s -w '\n%{http_code}' -H "$(format_auth_header)" \
  "${BASE_URL}/hex/${REPO_KEY}/packages/${PACKAGE_NAME}" 2>/dev/null) || true
pkg_status=$(echo "$pkg_http" | tail -1)
pkg_resp=$(echo "$pkg_http" | sed '$d')

# Fall back to the /api/packages route only on a genuine 404, never on a 5xx
# (which must surface, not be papered over by a second probe).
if [ "$pkg_status" = "404" ]; then
  pkg_http=$(curl -s -w '\n%{http_code}' -H "$(format_auth_header)" \
    "${BASE_URL}/hex/${REPO_KEY}/api/packages/${PACKAGE_NAME}" 2>/dev/null) || true
  pkg_status=$(echo "$pkg_http" | tail -1)
  pkg_resp=$(echo "$pkg_http" | sed '$d')
fi

if [ "$pkg_status" -ge 500 ] 2>/dev/null; then
  fail "package query returned HTTP ${pkg_status} (server error)" "$pkg_resp"
elif [ "$pkg_status" = "200" ] && echo "$pkg_resp" | grep -q "$PACKAGE_NAME"; then
  pass
else
  fail "package ${PACKAGE_NAME} not found in registry (HTTP ${pkg_status})" "$pkg_resp"
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

# CHECKSUM member (required by the read path since backend #2648; see the v1
# upload above for the full rationale, artifact-keeper-test#289).
CS=$(cat "$WORK_DIR/VERSION" "$WORK_DIR/metadata.config" "$WORK_DIR/contents.tar.gz" | shasum -a 256 | awk '{print toupper($1)}')
printf '%s' "$CS" > "$WORK_DIR/CHECKSUM"

HEX_TARBALL_V2="$WORK_DIR/${PACKAGE_NAME}-${PACKAGE_VERSION_V2}.tar"
tar cf "$HEX_TARBALL_V2" -C "$WORK_DIR" VERSION CHECKSUM metadata.config contents.tar.gz

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
# Publish without a usable CHECKSUM member is refused (artifact-keeper#2904)
#
# Since artifact-keeper PR #4388 the publish handler extracts the registry
# facts BEFORE storing anything and answers 422 when the outer tarball has
# no CHECKSUM member or a malformed one (anything other than 64 hex chars).
# Before that, the missing case was accepted and every later
# /packages/{name} read answered 500. A refused publish must leave no
# artifacts row, so the version must not show up in the artifact list.
# -----------------------------------------------------------------------

# publish_hex_without_valid_checksum <version> <checksum-mode: missing|malformed>
# Builds an outer tarball for <version> and PUTs it. Prints "<status> <body>"
# on one line; the body is the response text, truncated by the caller.
publish_hex_without_valid_checksum() {
  local version="$1" mode="$2"
  local dir="$WORK_DIR/bad-checksum-${mode}"
  rm -rf "$dir" && mkdir -p "$dir"
  cat > "$dir/metadata.config" <<EOMETA
{<<"name">>, <<"${PACKAGE_NAME}">>}.
{<<"version">>, <<"${version}">>}.
{<<"description">>, <<"E2E test package, ${mode} CHECKSUM">>}.
{<<"app">>, <<"${PACKAGE_NAME}">>}.
{<<"build_tools">>, [<<"mix">>]}.
{<<"requirements">>, []}.
EOMETA
  echo "3" > "$dir/VERSION"
  tar czf "$dir/contents.tar.gz" -C "$PKG_DIR" lib
  local members=(VERSION metadata.config contents.tar.gz)
  if [ "$mode" = "malformed" ]; then
    # 63 hex chars: one short of a sha256, so decode_inner_checksum refuses it.
    printf '%s' "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF012345678" > "$dir/CHECKSUM"
    members=(VERSION CHECKSUM metadata.config contents.tar.gz)
  fi
  local tarball="$dir/${PACKAGE_NAME}-${version}.tar"
  tar cf "$tarball" -C "$dir" "${members[@]}"

  local body_file="$dir/response.txt" status
  status=$(curl -s -o "$body_file" -w '%{http_code}' \
    -X PUT \
    -H "$(format_auth_header)" \
    -H "Content-Type: application/octet-stream" \
    --data-binary "@${tarball}" \
    "${BASE_URL}/hex/${REPO_KEY}/packages/${PACKAGE_NAME}/releases/${version}") || true
  printf '%s %s' "$status" "$(tr -d '\n' 2>/dev/null < "$body_file")"
}

# hex_version_absent <version>: true when no artifact row carries <version>.
hex_version_absent() {
  local resp
  resp=$(api_get "/api/v1/repositories/${REPO_KEY}/artifacts" 2>/dev/null) || return 2
  ! printf '%s' "$resp" | grep -qF -- "$1"
}

for mode in missing malformed; do
  begin_test "Publish with ${mode} CHECKSUM returns 422 and stores nothing"
  if [ "$mode" = "missing" ]; then
    BAD_VERSION="3.0.$(date +%s)"
    expect_msg="no CHECKSUM member"
  else
    BAD_VERSION="4.0.$(date +%s)"
    expect_msg="CHECKSUM must be 64 hex characters"
  fi
  bad_resp=$(publish_hex_without_valid_checksum "$BAD_VERSION" "$mode")
  bad_status="${bad_resp%% *}"
  bad_body="${bad_resp#* }"
  if [ "$bad_status" != "422" ]; then
    fail "publish with ${mode} CHECKSUM returned ${bad_status}, expected 422 (artifact-keeper#2904)" "${bad_body:0:400}"
  elif [[ "$bad_body" != *"$expect_msg"* ]]; then
    fail "422 body for ${mode} CHECKSUM should mention '${expect_msg}'" "${bad_body:0:400}"
  else
    absent_rc=0
    hex_version_absent "$BAD_VERSION" || absent_rc=$?
    case "$absent_rc" in
      0) pass ;;
      1) fail "refused ${mode}-CHECKSUM publish left an artifact row for ${PACKAGE_NAME} ${BAD_VERSION}" ;;
      *) fail "could not list artifacts to confirm the ${mode}-CHECKSUM publish stored nothing" ;;
    esac
  fi
done

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
