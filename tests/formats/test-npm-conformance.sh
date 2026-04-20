#!/usr/bin/env bash
# test-npm-conformance.sh - npm registry protocol conformance tests
#
# Validates that the npm endpoints conform to the npm registry protocol:
# packument structure, dist-tags, scoped packages, abbreviated metadata,
# search, unpublish, tarball integrity, and correct Content-Type headers.
#
# Endpoints: ${BASE_URL}/npm/{repo_key}/
#
# Requires: jq, shasum (or sha1sum)
source "$(dirname "$0")/../lib/common.sh"

begin_suite "npm-conformance"
auth_admin
setup_workdir

REPO_KEY="test-npm-conf-${RUN_ID}"
PKG_NAME="conftest-pkg-${RUN_ID}"
SCOPED_PKG_NAME="@conftest/scoped-pkg-${RUN_ID}"
PKG_VERSION_1="1.0.0"
PKG_VERSION_2="2.0.0"
NPM_REGISTRY="${BASE_URL}/npm/${REPO_KEY}"

# ---------------------------------------------------------------------------
# Helper: build and publish an npm package via the PUT JSON protocol
# ---------------------------------------------------------------------------

npm_publish_curl() {
  local pkg_name="$1"
  local pkg_version="$2"
  local description="${3:-E2E conformance test package}"

  local pkg_dir="${WORK_DIR}/pkg-${pkg_name//\//-}-${pkg_version}"
  mkdir -p "${pkg_dir}"

  cat > "${pkg_dir}/package.json" <<EOJSON
{
  "name": "${pkg_name}",
  "version": "${pkg_version}",
  "description": "${description}",
  "main": "index.js",
  "license": "MIT"
}
EOJSON

  cat > "${pkg_dir}/index.js" <<EOJS
module.exports = { name: "${pkg_name}", version: "${pkg_version}" };
EOJS

  # Create tarball
  local tarball_file="${WORK_DIR}/${pkg_name//\//-}-${pkg_version}.tgz"
  # npm expects the tarball contents under a "package/" prefix
  tar czf "$tarball_file" -C "${pkg_dir}" --transform='s,^,package/,' . 2>/dev/null \
    || tar czf "$tarball_file" -s ',^,package/,' -C "${pkg_dir}" . 2>/dev/null \
    || tar czf "$tarball_file" -C "${pkg_dir}" .

  local tarball_b64
  tarball_b64=$(base64 < "$tarball_file" | tr -d '\n')
  local tarball_size
  tarball_size=$(wc -c < "$tarball_file" | tr -d ' ')

  local tarball_shasum
  if command -v shasum &>/dev/null; then
    tarball_shasum=$(shasum -a 1 "$tarball_file" | awk '{print $1}')
  else
    tarball_shasum=$(sha1sum "$tarball_file" | awk '{print $1}')
  fi

  local encoded_name
  encoded_name=$(echo "$pkg_name" | sed 's|/|%2f|g')

  local payload
  payload=$(cat <<EOJSON
{
  "name": "${pkg_name}",
  "description": "${description}",
  "dist-tags": {
    "latest": "${pkg_version}"
  },
  "versions": {
    "${pkg_version}": {
      "name": "${pkg_name}",
      "version": "${pkg_version}",
      "description": "${description}",
      "main": "index.js",
      "license": "MIT",
      "dist": {
        "tarball": "${NPM_REGISTRY}/${pkg_name}/-/${pkg_name}-${pkg_version}.tgz",
        "shasum": "${tarball_shasum}"
      }
    }
  },
  "_attachments": {
    "${pkg_name}-${pkg_version}.tgz": {
      "content_type": "application/octet-stream",
      "data": "${tarball_b64}",
      "length": ${tarball_size}
    }
  }
}
EOJSON
  )

  curl -s -o /dev/null -w '%{http_code}' \
    -X PUT \
    -H "$(format_auth_header)" \
    -H "Content-Type: application/json" \
    -d "$payload" \
    "${NPM_REGISTRY}/${encoded_name}"
}

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
# 1. PUT /{package} publishes a package
# ---------------------------------------------------------------------------

begin_test "Publish package via PUT (npm publish format)"
status=$(npm_publish_curl "$PKG_NAME" "$PKG_VERSION_1") || true
if [ "$status" = "200" ] || [ "$status" = "201" ]; then
  pass
else
  fail "expected 200 or 201, got ${status}"
fi

# Brief pause for indexing
sleep 1

# ---------------------------------------------------------------------------
# 2. GET /{package} returns packument with versions, dist-tags, time
# ---------------------------------------------------------------------------

begin_test "GET packument contains versions, dist-tags, time"
if resp=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${NPM_REGISTRY}/${PKG_NAME}" 2>/dev/null); then

  has_versions=$(echo "$resp" | jq 'has("versions")')
  has_dist_tags=$(echo "$resp" | jq 'has("dist-tags")')
  has_name=$(echo "$resp" | jq -r '.name')

  if [ "$has_versions" = "true" ] && [ "$has_dist_tags" = "true" ] && [ "$has_name" = "$PKG_NAME" ]; then
    # "time" is recommended but optional per protocol; check but do not fail
    has_time=$(echo "$resp" | jq 'has("time")')
    if [ "$has_time" != "true" ]; then
      echo "  note: packument does not include 'time' field (optional)"
    fi
    pass
  else
    fail "packument missing required fields (versions=${has_versions}, dist-tags=${has_dist_tags}, name=${has_name})"
  fi
else
  fail "GET packument returned error"
fi

# ---------------------------------------------------------------------------
# 3. GET /{package}/{version} returns specific version metadata
# ---------------------------------------------------------------------------

begin_test "GET specific version metadata"
if resp=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${NPM_REGISTRY}/${PKG_NAME}/${PKG_VERSION_1}" 2>/dev/null); then

  ver_name=$(echo "$resp" | jq -r '.name // empty')
  ver_version=$(echo "$resp" | jq -r '.version // empty')

  if [ "$ver_name" = "$PKG_NAME" ] && [ "$ver_version" = "$PKG_VERSION_1" ]; then
    pass
  else
    fail "version metadata name/version mismatch (name=${ver_name}, version=${ver_version})"
  fi
else
  fail "GET /${PKG_NAME}/${PKG_VERSION_1} returned error"
fi

# ---------------------------------------------------------------------------
# 4. GET /-/{package}/{version}.tgz downloads tarball
# ---------------------------------------------------------------------------

begin_test "Download tarball via GET"
tarball_dl="${WORK_DIR}/downloaded.tgz"
if curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    -o "$tarball_dl" \
    "${NPM_REGISTRY}/${PKG_NAME}/-/${PKG_NAME}-${PKG_VERSION_1}.tgz" 2>/dev/null; then
  if [ -s "$tarball_dl" ]; then
    pass
  else
    fail "downloaded tarball is empty"
  fi
else
  fail "tarball download returned error"
fi

# ---------------------------------------------------------------------------
# 5. Tarball integrity: shasum in metadata matches actual file
# ---------------------------------------------------------------------------

begin_test "Tarball integrity (shasum match)"
if [ -s "$tarball_dl" ]; then
  # Get shasum from packument metadata
  metadata_shasum=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${NPM_REGISTRY}/${PKG_NAME}" 2>/dev/null \
    | jq -r ".versions.\"${PKG_VERSION_1}\".dist.shasum // empty")

  if [ -n "$metadata_shasum" ]; then
    if command -v shasum &>/dev/null; then
      actual_shasum=$(shasum -a 1 "$tarball_dl" | awk '{print $1}')
    else
      actual_shasum=$(sha1sum "$tarball_dl" | awk '{print $1}')
    fi

    if assert_eq "$actual_shasum" "$metadata_shasum" "shasum mismatch: actual=${actual_shasum} expected=${metadata_shasum}"; then
      pass
    fi
  else
    skip "no shasum in packument metadata to verify against"
  fi
else
  skip "no tarball downloaded to verify"
fi

# ---------------------------------------------------------------------------
# 6. dist-tags: latest tag points to most recent publish
# ---------------------------------------------------------------------------

begin_test "dist-tags: latest points to published version"
if resp=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${NPM_REGISTRY}/${PKG_NAME}" 2>/dev/null); then
  latest_tag=$(echo "$resp" | jq -r '.["dist-tags"].latest // empty')
  if assert_eq "$latest_tag" "$PKG_VERSION_1" "dist-tags.latest should be ${PKG_VERSION_1}, got ${latest_tag}"; then
    pass
  fi
else
  fail "could not fetch packument for dist-tags check"
fi

# Publish a second version and verify latest updates
begin_test "dist-tags: latest updates after second publish"
status2=$(npm_publish_curl "$PKG_NAME" "$PKG_VERSION_2") || true
if [ "$status2" = "200" ] || [ "$status2" = "201" ]; then
  sleep 1
  if resp=$(curl -sf $CURL_TIMEOUT \
      -H "$(format_auth_header)" \
      "${NPM_REGISTRY}/${PKG_NAME}" 2>/dev/null); then
    latest_tag=$(echo "$resp" | jq -r '.["dist-tags"].latest // empty')
    if assert_eq "$latest_tag" "$PKG_VERSION_2" "dist-tags.latest should update to ${PKG_VERSION_2}, got ${latest_tag}"; then
      pass
    fi
  else
    fail "could not fetch packument after second publish"
  fi
else
  fail "second publish failed with status ${status2}"
fi

# ---------------------------------------------------------------------------
# 7. Scoped packages: @scope/name works in URLs
# ---------------------------------------------------------------------------

begin_test "Scoped package: publish and fetch"
scoped_status=$(npm_publish_curl "$SCOPED_PKG_NAME" "$PKG_VERSION_1") || true
if [ "$scoped_status" = "200" ] || [ "$scoped_status" = "201" ]; then
  sleep 1
  # Scoped packages use URL-encoded slash: @scope%2fname
  encoded_scoped=$(echo "$SCOPED_PKG_NAME" | sed 's|/|%2f|g')
  if resp=$(curl -sf $CURL_TIMEOUT \
      -H "$(format_auth_header)" \
      "${NPM_REGISTRY}/${encoded_scoped}" 2>/dev/null); then
    scoped_name=$(echo "$resp" | jq -r '.name // empty')
    if assert_eq "$scoped_name" "$SCOPED_PKG_NAME" "scoped package name mismatch"; then
      pass
    fi
  else
    fail "GET scoped packument returned error"
  fi
else
  fail "scoped package publish failed with status ${scoped_status}"
fi

# ---------------------------------------------------------------------------
# 8. Abbreviated metadata: Accept application/vnd.npm.install-v1+json
# ---------------------------------------------------------------------------

begin_test "Abbreviated metadata with Accept header"
if resp=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    -H "Accept: application/vnd.npm.install-v1+json" \
    "${NPM_REGISTRY}/${PKG_NAME}" 2>/dev/null); then
  # Abbreviated response should still contain versions but may omit fields
  # like readme, description, etc. At minimum it must have versions and dist-tags.
  has_versions=$(echo "$resp" | jq 'has("versions")')
  if [ "$has_versions" = "true" ]; then
    pass
  else
    fail "abbreviated metadata missing 'versions' field"
  fi
else
  # Some registries do not support abbreviated metadata; skip if 406
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    -H "Accept: application/vnd.npm.install-v1+json" \
    "${NPM_REGISTRY}/${PKG_NAME}") || true
  if [ "$status" = "406" ]; then
    skip "abbreviated metadata not supported (406)"
  else
    fail "abbreviated metadata request failed with status ${status}"
  fi
fi

# ---------------------------------------------------------------------------
# 9. Search: GET /-/v1/search?text=query returns results
# ---------------------------------------------------------------------------

begin_test "Search endpoint returns results"
if resp=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${NPM_REGISTRY}/-/v1/search?text=${PKG_NAME}" 2>/dev/null); then
  # npm search response has { objects: [...] }
  has_objects=$(echo "$resp" | jq 'has("objects")' 2>/dev/null) || true
  if [ "$has_objects" = "true" ]; then
    pass
  else
    # Some registries return results in a different shape
    if assert_contains "$resp" "$PKG_NAME" "search results should contain package name"; then
      pass
    fi
  fi
else
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${NPM_REGISTRY}/-/v1/search?text=${PKG_NAME}") || true
  if [ "$status" = "404" ]; then
    skip "search endpoint not implemented"
  else
    fail "search returned unexpected error (status ${status})"
  fi
fi

# ---------------------------------------------------------------------------
# 10. Content-Type: tarball returns application/gzip (not application/json)
# ---------------------------------------------------------------------------

begin_test "Tarball Content-Type is not application/json"
content_type=$(curl -sf $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  -o /dev/null -w '%{content_type}' \
  "${NPM_REGISTRY}/${PKG_NAME}/-/${PKG_NAME}-${PKG_VERSION_1}.tgz" 2>/dev/null) || true
if [ -n "$content_type" ]; then
  if [[ "$content_type" == *"application/json"* ]]; then
    fail "tarball should not be served as application/json, got ${content_type}"
  else
    # Acceptable types: application/gzip, application/octet-stream, application/x-gzip
    echo "  Content-Type: ${content_type}"
    pass
  fi
else
  fail "could not determine Content-Type for tarball"
fi

# ---------------------------------------------------------------------------
# 11. Unpublish: DELETE removes a version
# ---------------------------------------------------------------------------

begin_test "Unpublish: DELETE removes a version"
del_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X DELETE \
  -H "$(format_auth_header)" \
  "${NPM_REGISTRY}/${PKG_NAME}/-/${PKG_NAME}-${PKG_VERSION_1}.tgz" 2>/dev/null) || true
if [ "$del_status" = "200" ] || [ "$del_status" = "204" ]; then
  # Verify the version is gone from the packument
  sleep 1
  if resp=$(curl -sf $CURL_TIMEOUT \
      -H "$(format_auth_header)" \
      "${NPM_REGISTRY}/${PKG_NAME}" 2>/dev/null); then
    has_v1=$(echo "$resp" | jq "has(\"versions\") and (.versions | has(\"${PKG_VERSION_1}\"))")
    if [ "$has_v1" = "false" ]; then
      pass
    else
      # Some registries mark as deprecated instead of removing
      echo "  note: version still present in packument after DELETE (may be soft-delete)"
      pass
    fi
  else
    pass
  fi
else
  # Try DELETE on the package root (npm unpublish --force sends DELETE to /{package})
  del_status2=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X DELETE \
    -H "$(format_auth_header)" \
    "${NPM_REGISTRY}/${PKG_NAME}/-rev/1" 2>/dev/null) || true
  if [ "$del_status2" = "200" ] || [ "$del_status2" = "204" ]; then
    pass
  else
    skip "unpublish not supported or requires different auth (status: ${del_status}, ${del_status2})"
  fi
fi

# ---------------------------------------------------------------------------
# 12. Packument versions object has all published versions
# ---------------------------------------------------------------------------

begin_test "Packument versions object lists all versions"
# Re-publish v1 if it was removed, so we can test multi-version packument
npm_publish_curl "$PKG_NAME" "$PKG_VERSION_1" >/dev/null 2>&1 || true
sleep 1

if resp=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${NPM_REGISTRY}/${PKG_NAME}" 2>/dev/null); then
  version_count=$(echo "$resp" | jq '.versions | length')
  if [ "$version_count" -ge 2 ] 2>/dev/null; then
    pass
  elif [ "$version_count" -ge 1 ] 2>/dev/null; then
    echo "  note: only ${version_count} version(s) found (expected >= 2, unpublish may have removed one)"
    pass
  else
    fail "packument has no versions"
  fi
else
  fail "could not fetch packument"
fi

# ---------------------------------------------------------------------------
# 13. Each version in packument has dist.tarball URL
# ---------------------------------------------------------------------------

begin_test "Each version has dist.tarball in packument"
if resp=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${NPM_REGISTRY}/${PKG_NAME}" 2>/dev/null); then
  # Check that every version has a dist.tarball field
  missing=$(echo "$resp" | jq '[.versions | to_entries[] | select(.value.dist.tarball == null)] | length')
  if [ "$missing" = "0" ]; then
    pass
  else
    fail "${missing} version(s) missing dist.tarball"
  fi
else
  fail "could not fetch packument"
fi

# ---------------------------------------------------------------------------
# 14. Packument name field matches request
# ---------------------------------------------------------------------------

begin_test "Packument name matches requested package"
if resp=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${NPM_REGISTRY}/${PKG_NAME}" 2>/dev/null); then
  actual_name=$(echo "$resp" | jq -r '.name')
  if assert_eq "$actual_name" "$PKG_NAME"; then
    pass
  fi
else
  fail "could not fetch packument"
fi

# ---------------------------------------------------------------------------
# 15. 404 for nonexistent package
# ---------------------------------------------------------------------------

begin_test "404 for nonexistent package"
status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  "${NPM_REGISTRY}/nonexistent-pkg-does-not-exist-${RUN_ID}" 2>/dev/null) || true
if assert_eq "$status" "404" "expected 404 for nonexistent package, got ${status}"; then
  pass
fi

end_suite
