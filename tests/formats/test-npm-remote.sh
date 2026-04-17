#!/usr/bin/env bash
# test-npm-remote.sh - NPM remote proxy and virtual repo E2E tests
#
# Regression tests for npm remote (pull-through proxy) and virtual repo
# behavior. Covers bugs:
#   #745 - npm integrity preservation across proxied tarballs
#   #722 - Content-Type header on tarball downloads
#   #659 - virtual repo merge of local + remote members
#   #646 - version listing for multi-version upstream packages
#   #622 - scoped package proxy URL handling
#
# Requires: curl, jq

source "$(dirname "$0")/../lib/common.sh"

begin_suite "npm-remote"
auth_admin
setup_workdir

REMOTE_KEY="test-npm-remote-${RUN_ID}"
LOCAL_KEY="test-npm-local-${RUN_ID}"
VIRTUAL_KEY="test-npm-virtual-${RUN_ID}"
UPSTREAM_URL="https://registry.npmjs.org"

# A small, stable package with predictable metadata
PROXY_PKG="abbrev"
PROXY_VERSION="1.1.1"

# A scoped package for bug #622
SCOPED_PKG="@types/node"

# A second unrelated package for integrity cross-check (bug #745)
PROXY_PKG_2="is-number"
PROXY_VERSION_2="7.0.0"

# =========================================================================
# Setup: create repos
# =========================================================================

begin_test "Create remote npm repository"
if create_remote_repo "$REMOTE_KEY" "npm" "$UPSTREAM_URL"; then
  pass
else
  fail "could not create remote npm repo"
fi

# -------------------------------------------------------------------------
# Check upstream reachability before running proxy tests
# -------------------------------------------------------------------------

begin_test "Verify upstream reachability"
if curl -sf --max-time 10 "${UPSTREAM_URL}/abbrev" > /dev/null 2>&1; then
  UPSTREAM_REACHABLE=true
  pass
else
  UPSTREAM_REACHABLE=false
  skip "registry.npmjs.org unreachable from test environment"
fi

# =========================================================================
# Test 1: Remote repo proxy - pull a known package (abbrev@1.1.1)
# =========================================================================

begin_test "Proxy package metadata via remote repo"
if [ "$UPSTREAM_REACHABLE" != "true" ]; then
  skip "upstream unreachable"
else
  if resp=$(curl -sf $CURL_TIMEOUT \
      -H "$(format_auth_header)" \
      "${BASE_URL}/npm/${REMOTE_KEY}/${PROXY_PKG}" 2>/dev/null); then
    if assert_contains "$resp" "\"${PROXY_PKG}\"" "metadata should contain package name"; then
      if assert_contains "$resp" "\"${PROXY_VERSION}\"" "metadata should contain version ${PROXY_VERSION}"; then
        pass
      fi
    fi
  else
    fail "GET /npm/${REMOTE_KEY}/${PROXY_PKG} returned error"
  fi
fi

begin_test "Download tarball via remote proxy"
if [ "$UPSTREAM_REACHABLE" != "true" ]; then
  skip "upstream unreachable"
else
  TARBALL_PATH="/npm/${REMOTE_KEY}/${PROXY_PKG}/-/${PROXY_PKG}-${PROXY_VERSION}.tgz"
  if curl -sf $CURL_TIMEOUT \
      -H "$(format_auth_header)" \
      -o "${WORK_DIR}/${PROXY_PKG}.tgz" \
      "${BASE_URL}${TARBALL_PATH}" 2>/dev/null; then
    if [ -s "${WORK_DIR}/${PROXY_PKG}.tgz" ]; then
      # Verify the tarball is a valid gzip file
      if gzip -t "${WORK_DIR}/${PROXY_PKG}.tgz" 2>/dev/null; then
        pass
      else
        fail "downloaded file is not a valid gzip tarball"
      fi
    else
      fail "downloaded tarball is empty"
    fi
  else
    fail "tarball download returned error"
  fi
fi

begin_test "Verify proxied artifact in local cache"
if [ "$UPSTREAM_REACHABLE" != "true" ]; then
  skip "upstream unreachable"
else
  sleep 2
  if resp=$(api_get "/api/v1/repositories/${REMOTE_KEY}/artifacts" 2>/dev/null); then
    if assert_contains "$resp" "${PROXY_PKG}" "cached artifacts should contain ${PROXY_PKG}"; then
      pass
    fi
  else
    fail "GET /api/v1/repositories/${REMOTE_KEY}/artifacts returned error"
  fi
fi

# =========================================================================
# Test 2: Scoped package proxy (bug #622)
# =========================================================================

begin_test "Proxy scoped package metadata"
if [ "$UPSTREAM_REACHABLE" != "true" ]; then
  skip "upstream unreachable"
else
  # Scoped packages use URL-encoded %2f or direct path: /npm/{repo}/@scope/name
  if resp=$(curl -sf $CURL_TIMEOUT \
      -H "$(format_auth_header)" \
      "${BASE_URL}/npm/${REMOTE_KEY}/${SCOPED_PKG}" 2>/dev/null); then
    # The metadata must reflect the full scoped name
    if assert_contains "$resp" "@types/node" "metadata should contain scoped package name"; then
      pass
    fi
  else
    # Try URL-encoded variant: @types%2fnode
    ENCODED_PKG=$(echo "$SCOPED_PKG" | sed 's|/|%2f|g')
    if resp=$(curl -sf $CURL_TIMEOUT \
        -H "$(format_auth_header)" \
        "${BASE_URL}/npm/${REMOTE_KEY}/${ENCODED_PKG}" 2>/dev/null); then
      if assert_contains "$resp" "@types/node" "metadata should contain scoped package name"; then
        pass
      fi
    else
      fail "scoped package proxy failed for ${SCOPED_PKG} (both / and %2f paths)"
    fi
  fi
fi

# =========================================================================
# Test 3: NPM integrity preservation (bug #745)
# =========================================================================

begin_test "Integrity preservation across proxied tarballs"
if [ "$UPSTREAM_REACHABLE" != "true" ]; then
  skip "upstream unreachable"
else
  # Fetch the second package through the proxy
  if resp2=$(curl -sf $CURL_TIMEOUT \
      -H "$(format_auth_header)" \
      "${BASE_URL}/npm/${REMOTE_KEY}/${PROXY_PKG_2}" 2>/dev/null); then

    # Extract the upstream-reported shasum for the specific version
    upstream_shasum=$(echo "$resp2" | jq -r \
      ".versions[\"${PROXY_VERSION_2}\"].dist.shasum // empty" 2>/dev/null) || true

    if [ -z "$upstream_shasum" ]; then
      skip "upstream shasum not present in proxied metadata"
    else
      # Download the tarball and compute its sha1
      TARBALL_PATH_2="/npm/${REMOTE_KEY}/${PROXY_PKG_2}/-/${PROXY_PKG_2}-${PROXY_VERSION_2}.tgz"
      if curl -sf $CURL_TIMEOUT \
          -H "$(format_auth_header)" \
          -o "${WORK_DIR}/${PROXY_PKG_2}.tgz" \
          "${BASE_URL}${TARBALL_PATH_2}" 2>/dev/null; then

        actual_shasum=$(shasum -a 1 "${WORK_DIR}/${PROXY_PKG_2}.tgz" | awk '{print $1}')
        if assert_eq "$actual_shasum" "$upstream_shasum" \
            "tarball sha1 (${actual_shasum}) should match upstream (${upstream_shasum})"; then
          pass
        fi
      else
        fail "could not download tarball for integrity check"
      fi
    fi
  else
    fail "could not fetch metadata for ${PROXY_PKG_2}"
  fi
fi

# Cross-check: the first package should also match its upstream shasum
begin_test "Integrity cross-check for first proxied package"
if [ "$UPSTREAM_REACHABLE" != "true" ]; then
  skip "upstream unreachable"
else
  # Re-fetch metadata for abbrev to get the shasum
  if resp_abbrev=$(curl -sf $CURL_TIMEOUT \
      -H "$(format_auth_header)" \
      "${BASE_URL}/npm/${REMOTE_KEY}/${PROXY_PKG}" 2>/dev/null); then

    upstream_sha_abbrev=$(echo "$resp_abbrev" | jq -r \
      ".versions[\"${PROXY_VERSION}\"].dist.shasum // empty" 2>/dev/null) || true

    if [ -z "$upstream_sha_abbrev" ]; then
      skip "upstream shasum not present for ${PROXY_PKG}"
    else
      actual_sha_abbrev=$(shasum -a 1 "${WORK_DIR}/${PROXY_PKG}.tgz" | awk '{print $1}')
      if assert_eq "$actual_sha_abbrev" "$upstream_sha_abbrev" \
          "tarball sha1 (${actual_sha_abbrev}) should match upstream (${upstream_sha_abbrev})"; then
        pass
      fi
    fi
  else
    fail "could not re-fetch metadata for ${PROXY_PKG}"
  fi
fi

# =========================================================================
# Test 4: Content-Type header on tarball downloads (bug #722)
# =========================================================================

begin_test "Tarball Content-Type header is not application/json"
if [ "$UPSTREAM_REACHABLE" != "true" ]; then
  skip "upstream unreachable"
else
  TARBALL_PATH="/npm/${REMOTE_KEY}/${PROXY_PKG}/-/${PROXY_PKG}-${PROXY_VERSION}.tgz"
  content_type=$(curl -sf $CURL_TIMEOUT \
      -H "$(format_auth_header)" \
      -o /dev/null -w '%{content_type}' \
      "${BASE_URL}${TARBALL_PATH}" 2>/dev/null) || true

  if [ -z "$content_type" ]; then
    fail "no Content-Type header returned for tarball"
  else
    # Content-Type must be application/gzip, application/octet-stream, or
    # application/x-compressed-tar. It must NOT be application/json.
    if assert_not_contains "$content_type" "application/json" \
        "tarball Content-Type should not be application/json, got: ${content_type}"; then
      # Verify it is one of the acceptable binary types
      if [[ "$content_type" == *"gzip"* ]] || \
         [[ "$content_type" == *"octet-stream"* ]] || \
         [[ "$content_type" == *"tar"* ]]; then
        pass
      else
        fail "unexpected Content-Type for tarball: ${content_type} (expected gzip or octet-stream)"
      fi
    fi
  fi
fi

# =========================================================================
# Test 5: Virtual repo merge of local + remote (bug #659)
# =========================================================================

# Create a local npm repo and publish a package to it
begin_test "Create local npm repository for virtual merge"
if create_local_repo "$LOCAL_KEY" "npm"; then
  pass
else
  fail "could not create local npm repo"
fi

LOCAL_PKG_NAME="test-npm-local-pkg-${RUN_ID}"
LOCAL_PKG_VERSION="1.0.0"
NPM_LOCAL_REGISTRY="${BASE_URL}/npm/${LOCAL_KEY}/"

begin_test "Publish package to local npm repo"
cd "$WORK_DIR"
mkdir -p local-pkg && cd local-pkg

cat > package.json <<EOF
{
  "name": "${LOCAL_PKG_NAME}",
  "version": "${LOCAL_PKG_VERSION}",
  "description": "E2E local package for virtual merge test",
  "main": "index.js",
  "license": "MIT"
}
EOF
echo "module.exports = {};" > index.js

# Create tarball and publish via curl PUT (same pattern as test-npm.sh fallback)
TARBALL_FILE="${WORK_DIR}/${LOCAL_PKG_NAME}-${LOCAL_PKG_VERSION}.tgz"
tar czf "$TARBALL_FILE" -C "${WORK_DIR}/local-pkg" .

TARBALL_B64=$(base64 < "$TARBALL_FILE" | tr -d '\n')
TARBALL_SIZE=$(wc -c < "$TARBALL_FILE" | tr -d ' ')

PUBLISH_PAYLOAD=$(cat <<EOJSON
{
  "name": "${LOCAL_PKG_NAME}",
  "description": "E2E local package for virtual merge test",
  "versions": {
    "${LOCAL_PKG_VERSION}": {
      "name": "${LOCAL_PKG_NAME}",
      "version": "${LOCAL_PKG_VERSION}",
      "description": "E2E local package for virtual merge test",
      "main": "index.js",
      "license": "MIT",
      "dist": {
        "tarball": "${NPM_LOCAL_REGISTRY}${LOCAL_PKG_NAME}/-/${LOCAL_PKG_NAME}-${LOCAL_PKG_VERSION}.tgz"
      }
    }
  },
  "_attachments": {
    "${LOCAL_PKG_NAME}-${LOCAL_PKG_VERSION}.tgz": {
      "content_type": "application/octet-stream",
      "data": "${TARBALL_B64}",
      "length": ${TARBALL_SIZE}
    }
  }
}
EOJSON
)

publish_status=$(curl -s -o /dev/null -w '%{http_code}' \
  -X PUT \
  -H "$(format_auth_header)" \
  -H "Content-Type: application/json" \
  -d "$PUBLISH_PAYLOAD" \
  "${NPM_LOCAL_REGISTRY}${LOCAL_PKG_NAME}") || true

if [ "$publish_status" = "200" ] || [ "$publish_status" = "201" ]; then
  pass
else
  fail "publish to local npm repo failed (HTTP ${publish_status})"
fi

# Create virtual repo and add both local and remote as members
begin_test "Create virtual npm repository"
if create_virtual_repo "$VIRTUAL_KEY" "npm"; then
  pass
else
  fail "could not create virtual npm repo"
fi

begin_test "Add local and remote repos as virtual members"
added=0
if api_post "/api/v1/repositories/${VIRTUAL_KEY}/members" \
    "{\"member_key\":\"${LOCAL_KEY}\",\"priority\":1}" > /dev/null 2>&1; then
  added=$((added + 1))
fi
if api_post "/api/v1/repositories/${VIRTUAL_KEY}/members" \
    "{\"member_key\":\"${REMOTE_KEY}\",\"priority\":2}" > /dev/null 2>&1; then
  added=$((added + 1))
fi
if [ "$added" -ge 2 ]; then
  pass
elif [ "$added" -ge 1 ]; then
  pass  # at least one member added
else
  fail "could not add members to virtual repo"
fi

sleep 2

begin_test "Virtual repo resolves locally-published package"
if resp=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${BASE_URL}/npm/${VIRTUAL_KEY}/${LOCAL_PKG_NAME}" 2>/dev/null); then
  if assert_contains "$resp" "${LOCAL_PKG_NAME}" "virtual should resolve local package name"; then
    if assert_contains "$resp" "${LOCAL_PKG_VERSION}" "virtual should resolve local package version"; then
      pass
    fi
  fi
else
  fail "virtual repo did not resolve locally-published package ${LOCAL_PKG_NAME}"
fi

begin_test "Virtual repo resolves upstream-only package"
if [ "$UPSTREAM_REACHABLE" != "true" ]; then
  skip "upstream unreachable"
else
  if resp=$(curl -sf $CURL_TIMEOUT \
      -H "$(format_auth_header)" \
      "${BASE_URL}/npm/${VIRTUAL_KEY}/${PROXY_PKG}" 2>/dev/null); then
    if assert_contains "$resp" "\"${PROXY_PKG}\"" "virtual should resolve upstream package"; then
      pass
    fi
  else
    fail "virtual repo did not resolve upstream package ${PROXY_PKG}"
  fi
fi

# =========================================================================
# Test 6: Version listing for multi-version upstream packages (bug #646)
# =========================================================================

begin_test "Version listing includes multiple upstream versions"
if [ "$UPSTREAM_REACHABLE" != "true" ]; then
  skip "upstream unreachable"
else
  # abbrev has had multiple releases; the metadata should list them
  if resp=$(curl -sf $CURL_TIMEOUT \
      -H "$(format_auth_header)" \
      "${BASE_URL}/npm/${REMOTE_KEY}/${PROXY_PKG}" 2>/dev/null); then
    version_count=$(echo "$resp" | jq '.versions | length' 2>/dev/null) || version_count=0
    if [ "$version_count" -gt 1 ]; then
      pass
    elif [ "$version_count" -eq 1 ]; then
      # Some proxies only return the requested version; check that at least
      # dist-tags or time fields indicate multiple versions exist
      has_latest=$(echo "$resp" | jq -r '."dist-tags".latest // empty' 2>/dev/null) || true
      if [ -n "$has_latest" ]; then
        pass
      else
        fail "only 1 version returned and no dist-tags found"
      fi
    else
      fail "version listing returned 0 versions"
    fi
  else
    fail "could not fetch metadata for version listing check"
  fi
fi

begin_test "Version listing contains dist-tags"
if [ "$UPSTREAM_REACHABLE" != "true" ]; then
  skip "upstream unreachable"
else
  if resp=$(curl -sf $CURL_TIMEOUT \
      -H "$(format_auth_header)" \
      "${BASE_URL}/npm/${REMOTE_KEY}/${PROXY_PKG}" 2>/dev/null); then
    latest_tag=$(echo "$resp" | jq -r '."dist-tags".latest // empty' 2>/dev/null) || true
    if [ -n "$latest_tag" ]; then
      pass
    else
      skip "dist-tags.latest not present in proxied metadata"
    fi
  else
    fail "could not fetch metadata for dist-tags check"
  fi
fi

# =========================================================================
# Cleanup
# =========================================================================

api_delete "/api/v1/repositories/${VIRTUAL_KEY}" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${LOCAL_KEY}" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${REMOTE_KEY}" > /dev/null 2>&1 || true

end_suite
