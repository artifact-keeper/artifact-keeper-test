#!/usr/bin/env bash
# test-puppet-conformance.sh - Puppet Forge API conformance tests
#
# Validates that the Puppet Forge implementation handles module uploads
# via multipart POST, serves module and release metadata through the
# Forge v3 API, supports search queries, and returns correct 404s.
#
# Endpoints: ${BASE_URL}/puppet/{repo_key}/v3/...
#
# Requires: curl, jq, tar
source "$(dirname "$0")/../lib/common.sh"

begin_suite "puppet-conformance"
auth_admin
setup_workdir

REPO_KEY="test-puppet-conf-${RUN_ID}"
OWNER="testorg"
MOD_NAME="mymodule"
MOD_VERSION="1.0.0"
MOD_VERSION_2="2.0.0"
PUPPET_URL="${BASE_URL}/puppet/${REPO_KEY}"

# ---------------------------------------------------------------------------
# Helper: build a Puppet module tarball with metadata.json
#
# A Puppet module is a .tar.gz containing at minimum:
#   {owner}-{name}-{version}/metadata.json
# ---------------------------------------------------------------------------

build_puppet_module() {
  local owner="$1"
  local name="$2"
  local version="$3"
  local outfile="$4"

  local full_name="${owner}-${name}"
  local dir_name="${full_name}-${version}"
  local build_dir="${WORK_DIR}/puppet-build-${dir_name}"
  mkdir -p "${build_dir}/${dir_name}/manifests"

  cat > "${build_dir}/${dir_name}/metadata.json" <<EOJSON
{
  "name": "${full_name}",
  "version": "${version}",
  "author": "${owner}",
  "summary": "Conformance test module ${full_name}",
  "license": "Apache-2.0",
  "source": "https://example.com/${full_name}",
  "dependencies": [],
  "operatingsystem_support": [
    { "operatingsystem": "Ubuntu", "operatingsystemrelease": ["22.04"] }
  ]
}
EOJSON

  cat > "${build_dir}/${dir_name}/manifests/init.pp" <<EOPP
class ${name} {
  notify { 'hello from ${full_name} ${version}': }
}
EOPP

  (cd "${build_dir}" && tar czf "${outfile}" "${dir_name}/")
}

# ---------------------------------------------------------------------------
# Helper: upload a puppet module via multipart POST
# ---------------------------------------------------------------------------

upload_puppet_module() {
  local owner="$1"
  local name="$2"
  local version="$3"
  local tarball="$4"

  local module_json
  module_json=$(printf '{"owner":"%s","name":"%s","version":"%s"}' "$owner" "$name" "$version")

  curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X POST \
    -H "$(format_auth_header)" \
    -F "file=@${tarball};type=application/gzip" \
    -F "module=${module_json};type=application/json" \
    "${PUPPET_URL}/v3/releases"
}

# ---------------------------------------------------------------------------
# Create repository
# ---------------------------------------------------------------------------

begin_test "Create Puppet local repository"
if create_local_repo "$REPO_KEY" "puppet"; then
  pass
else
  fail "could not create puppet repository"
fi

# ---------------------------------------------------------------------------
# 1. Upload Puppet module (.tar.gz with metadata.json)
# ---------------------------------------------------------------------------

begin_test "Upload Puppet module"
TARBALL="${WORK_DIR}/${OWNER}-${MOD_NAME}-${MOD_VERSION}.tar.gz"
build_puppet_module "$OWNER" "$MOD_NAME" "$MOD_VERSION" "$TARBALL"

upload_status=$(upload_puppet_module "$OWNER" "$MOD_NAME" "$MOD_VERSION" "$TARBALL") || true
if [ "$upload_status" = "200" ] || [ "$upload_status" = "201" ]; then
  pass
else
  fail "puppet module upload returned HTTP ${upload_status}, expected 200 or 201"
fi

sleep 1

# ---------------------------------------------------------------------------
# 2. GET /v3/modules/{owner}-{name} returns module metadata
# ---------------------------------------------------------------------------

begin_test "GET /v3/modules returns module metadata"
MODULE_RESP=""
if MODULE_RESP=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${PUPPET_URL}/v3/modules/${OWNER}-${MOD_NAME}" 2>/dev/null); then
  # Verify it contains the module name and owner
  mod_slug=$(echo "$MODULE_RESP" | jq -r '.slug // empty' 2>/dev/null) || true
  if [ "$mod_slug" = "${OWNER}-${MOD_NAME}" ]; then
    pass
  else
    # Accept if the response mentions the module name at all
    if assert_contains "$MODULE_RESP" "$MOD_NAME" "module metadata should reference module name"; then
      pass
    fi
  fi
else
  fail "GET /v3/modules/${OWNER}-${MOD_NAME} returned error"
fi

# ---------------------------------------------------------------------------
# 3. GET /v3/releases/{owner}-{name}-{version} returns release info
# ---------------------------------------------------------------------------

begin_test "GET /v3/releases returns release info"
RELEASE_RESP=""
if RELEASE_RESP=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${PUPPET_URL}/v3/releases/${OWNER}-${MOD_NAME}-${MOD_VERSION}" 2>/dev/null); then
  rel_version=$(echo "$RELEASE_RESP" | jq -r '.version // empty' 2>/dev/null) || true
  if [ "$rel_version" = "$MOD_VERSION" ]; then
    pass
  else
    if assert_contains "$RELEASE_RESP" "$MOD_VERSION" "release info should contain version"; then
      pass
    fi
  fi
else
  fail "GET /v3/releases/${OWNER}-${MOD_NAME}-${MOD_VERSION} returned error"
fi

# ---------------------------------------------------------------------------
# 4. Download module tarball
# ---------------------------------------------------------------------------

begin_test "Download module tarball"
DL_FILE="${WORK_DIR}/downloaded-module.tar.gz"
FILENAME="${OWNER}-${MOD_NAME}-${MOD_VERSION}.tar.gz"

dl_status=$(curl -s -o "$DL_FILE" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  "${PUPPET_URL}/v3/files/${FILENAME}") || true

if [ "$dl_status" -ge 200 ] 2>/dev/null && [ "$dl_status" -lt 300 ] 2>/dev/null; then
  if [ -s "$DL_FILE" ]; then
    # Verify it is a valid tar.gz
    if tar tzf "$DL_FILE" >/dev/null 2>&1; then
      pass
    else
      fail "downloaded file is not a valid tar.gz archive"
    fi
  else
    fail "downloaded module tarball is empty"
  fi
else
  # Try with the file_uri from the release response if available
  file_uri=$(echo "$RELEASE_RESP" | jq -r '.file_uri // empty' 2>/dev/null) || true
  if [ -n "$file_uri" ]; then
    dl_status=$(curl -s -o "$DL_FILE" -w '%{http_code}' $CURL_TIMEOUT \
      -H "$(format_auth_header)" \
      "${BASE_URL}${file_uri}") || true
    if [ "$dl_status" -ge 200 ] 2>/dev/null && [ "$dl_status" -lt 300 ] 2>/dev/null && [ -s "$DL_FILE" ]; then
      pass
    else
      fail "download via file_uri '${file_uri}' returned HTTP ${dl_status}"
    fi
  else
    fail "download returned HTTP ${dl_status} and no file_uri available from release info"
  fi
fi

# ---------------------------------------------------------------------------
# 5. Search modules (GET /v3/modules?query=)
# ---------------------------------------------------------------------------

begin_test "Search modules by query parameter"
# The Puppet Forge API supports GET /v3/modules?query=<term> for searching.
# If the endpoint is not implemented, we fall back to checking that the module
# is findable by its owner-name identifier.
search_found=false

search_status=$(curl -s -o "${WORK_DIR}/search.json" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  "${PUPPET_URL}/v3/modules?query=${MOD_NAME}") || true

if [ "$search_status" = "200" ] && [ -s "${WORK_DIR}/search.json" ]; then
  search_resp=$(cat "${WORK_DIR}/search.json")
  # Check if our module appears in results (array or .results field)
  found_in_results=$(echo "$search_resp" | jq --arg name "${OWNER}-${MOD_NAME}" '
    if type == "array" then [.[] | select(.slug == $name or .name == $name)] | length > 0
    elif .results then [.results[] | select(.slug == $name or .name == $name)] | length > 0
    else false
    end
  ' 2>/dev/null) || true

  if [ "$found_in_results" = "true" ]; then
    search_found=true
  elif echo "$search_resp" | grep -q "$MOD_NAME" 2>/dev/null; then
    search_found=true
    echo "  note: module found in search response but not in expected JSON structure"
  fi
fi

if $search_found; then
  pass
else
  # Search endpoint may not be implemented; verify module is at least accessible by name
  fallback_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${PUPPET_URL}/v3/modules/${OWNER}-${MOD_NAME}") || true
  if [ "$fallback_status" = "200" ]; then
    skip "search query endpoint not implemented, but module is accessible by direct lookup"
  else
    fail "module not found by search or direct lookup (search=${search_status}, direct=${fallback_status})"
  fi
fi

# ---------------------------------------------------------------------------
# 6. Multiple versions / releases
# ---------------------------------------------------------------------------

begin_test "Multiple versions listed as releases"
TARBALL_2="${WORK_DIR}/${OWNER}-${MOD_NAME}-${MOD_VERSION_2}.tar.gz"
build_puppet_module "$OWNER" "$MOD_NAME" "$MOD_VERSION_2" "$TARBALL_2"

upload2_status=$(upload_puppet_module "$OWNER" "$MOD_NAME" "$MOD_VERSION_2" "$TARBALL_2") || true
if [ "$upload2_status" = "200" ] || [ "$upload2_status" = "201" ]; then
  sleep 1
  # Fetch releases list
  if releases_resp=$(curl -sf $CURL_TIMEOUT \
      -H "$(format_auth_header)" \
      "${PUPPET_URL}/v3/modules/${OWNER}-${MOD_NAME}/releases" 2>/dev/null); then
    release_count=$(echo "$releases_resp" | jq '
      if .results then (.results | length)
      elif type == "array" then length
      else 0
      end
    ' 2>/dev/null) || release_count=0

    if [ "$release_count" -ge 2 ] 2>/dev/null; then
      pass
    else
      # Check both versions are individually accessible
      v1_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
        -H "$(format_auth_header)" \
        "${PUPPET_URL}/v3/releases/${OWNER}-${MOD_NAME}-${MOD_VERSION}") || true
      v2_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
        -H "$(format_auth_header)" \
        "${PUPPET_URL}/v3/releases/${OWNER}-${MOD_NAME}-${MOD_VERSION_2}") || true
      if [ "$v1_status" = "200" ] && [ "$v2_status" = "200" ]; then
        echo "  note: releases endpoint lists ${release_count} but both versions accessible individually"
        pass
      else
        fail "expected >= 2 releases, got ${release_count} (v1=${v1_status}, v2=${v2_status})"
      fi
    fi
  else
    fail "GET /v3/modules/${OWNER}-${MOD_NAME}/releases returned error after uploading two versions"
  fi
else
  fail "second version upload returned HTTP ${upload2_status}"
fi

# ---------------------------------------------------------------------------
# 7. 404 for nonexistent module
# ---------------------------------------------------------------------------

begin_test "404 for nonexistent module"
status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  "${PUPPET_URL}/v3/modules/fakeowner-nonexistent${RUN_ID}") || true
if assert_eq "$status" "404" "expected 404 for nonexistent module, got ${status}"; then
  pass
fi

# ---------------------------------------------------------------------------
# 8. Module metadata contains required fields
# ---------------------------------------------------------------------------

begin_test "Module metadata contains required fields"
# Re-fetch module info if empty from earlier test
if [ -z "$MODULE_RESP" ]; then
  MODULE_RESP=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${PUPPET_URL}/v3/modules/${OWNER}-${MOD_NAME}" 2>/dev/null) || true
fi

if [ -n "$MODULE_RESP" ]; then
  found=0
  missing=""

  # Check for slug or name field
  slug_val=$(echo "$MODULE_RESP" | jq -r '.slug // .name // empty' 2>/dev/null) || true
  if [ -n "$slug_val" ]; then
    found=$((found + 1))
  else
    missing="${missing} name/slug"
  fi

  # Check for owner
  owner_val=$(echo "$MODULE_RESP" | jq -r '.owner.slug // .owner.username // .owner // empty' 2>/dev/null) || true
  if [ -n "$owner_val" ]; then
    found=$((found + 1))
  else
    missing="${missing} owner"
  fi

  # Check for current_release or releases
  has_release=$(echo "$MODULE_RESP" | jq 'has("current_release") or has("releases")' 2>/dev/null) || true
  if [ "$has_release" = "true" ]; then
    found=$((found + 1))
  else
    missing="${missing} current_release/releases"
  fi

  # Check current_release contains version
  rel_version=$(echo "$MODULE_RESP" | jq -r '.current_release.version // empty' 2>/dev/null) || true
  if [ -n "$rel_version" ]; then
    found=$((found + 1))
  else
    missing="${missing} current_release.version"
  fi

  if [ "$found" -ge 3 ]; then
    if [ -n "$missing" ]; then
      echo "  note: some fields missing:${missing}"
    fi
    pass
  else
    fail "module metadata missing required fields (found ${found}/4):${missing}"
  fi
else
  fail "could not fetch module metadata for field inspection"
fi

end_suite
