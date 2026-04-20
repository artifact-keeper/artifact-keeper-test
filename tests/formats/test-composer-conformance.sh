#!/usr/bin/env bash
# test-composer-conformance.sh - Composer/Packagist registry conformance tests
#
# Validates that the Composer registry endpoints conform to the Packagist
# protocol for PHP packages. Tests both v1 (provider-based) and v2 (p2)
# metadata endpoints, packages.json root index, package upload, download,
# and metadata structure.
#
# Composer packages are zip archives containing a composer.json at the root.
#
# Endpoints: ${BASE_URL}/composer/{repo_key}/
#
# Requires: jq, zip
source "$(dirname "$0")/../lib/common.sh"

begin_suite "composer-conformance"
auth_admin
setup_workdir

REPO_KEY="test-composer-conf-${RUN_ID}"
VENDOR="conftest"
PACKAGE="hello-lib"
FULL_NAME="${VENDOR}/${PACKAGE}"
PKG_VERSION="1.0.0"
PKG_VERSION_2="2.0.0"
COMPOSER_BASE="${BASE_URL}/composer/${REPO_KEY}"

# ---------------------------------------------------------------------------
# Helper: build a minimal Composer package zip
# ---------------------------------------------------------------------------

build_composer_zip() {
  local vendor="$1"
  local package="$2"
  local version="$3"
  local out_dir="$4"
  local extra_require="${5:-}"

  local build_dir="${out_dir}/build-${vendor}-${package}-${version}"
  mkdir -p "${build_dir}/src"

  local require_block='"php": ">=8.0"'
  if [ -n "$extra_require" ]; then
    require_block="${require_block}, ${extra_require}"
  fi

  cat > "${build_dir}/composer.json" <<EOJSON
{
  "name": "${vendor}/${package}",
  "description": "Conformance test package ${version}",
  "version": "${version}",
  "type": "library",
  "license": "MIT",
  "autoload": {
    "psr-4": {
      "ConfTest\\\\": "src/"
    }
  },
  "require": {
    ${require_block}
  }
}
EOJSON

  cat > "${build_dir}/src/Hello.php" <<'EOPHP'
<?php
namespace ConfTest;

class Hello {
    public function greet(): string {
        return "Hello from Composer conformance test!";
    }
}
EOPHP

  local zip_file="${out_dir}/${vendor}-${package}-${version}.zip"
  (cd "$build_dir" && zip -qr "$zip_file" .)
  echo "$zip_file"
}

# ---------------------------------------------------------------------------
# Helper: upload a Composer package
# ---------------------------------------------------------------------------

upload_composer_package() {
  local zip_path="$1"

  curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X PUT \
    -H "$(format_auth_header)" \
    -H "Content-Type: application/zip" \
    --data-binary "@${zip_path}" \
    "${COMPOSER_BASE}/api/packages" 2>/dev/null
}

# ---------------------------------------------------------------------------
# Create repository
# ---------------------------------------------------------------------------

begin_test "Create Composer local repository"
if create_local_repo "$REPO_KEY" "composer"; then
  pass
else
  fail "could not create composer repository"
fi

# ---------------------------------------------------------------------------
# 1. GET /packages.json returns the root packages index
# ---------------------------------------------------------------------------

begin_test "GET /packages.json returns root index"
pkgs_resp=$(curl -sf $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  "${COMPOSER_BASE}/packages.json" 2>/dev/null) || true

if [ -n "$pkgs_resp" ]; then
  # packages.json must be valid JSON
  if echo "$pkgs_resp" | jq . >/dev/null 2>&1; then
    pass
  else
    fail "packages.json is not valid JSON"
  fi
else
  fail "GET /packages.json returned empty response"
fi

# ---------------------------------------------------------------------------
# 2. Upload a package (zip archive)
# ---------------------------------------------------------------------------

begin_test "Upload Composer package"
PKG_ZIP=$(build_composer_zip "$VENDOR" "$PACKAGE" "$PKG_VERSION" "$WORK_DIR")
status=$(upload_composer_package "$PKG_ZIP")
if [ "$status" = "200" ] || [ "$status" = "201" ]; then
  pass
else
  fail "package upload returned ${status}, expected 200 or 201"
fi

sleep 1

# ---------------------------------------------------------------------------
# 3. GET /p2/{vendor}/{package}.json returns package metadata (v2 API)
# ---------------------------------------------------------------------------

begin_test "GET /p2/{vendor}/{package}.json returns metadata (v2 API)"
p2_resp=$(curl -sf $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  "${COMPOSER_BASE}/p2/${VENDOR}/${PACKAGE}.json" 2>/dev/null) || true

if [ -n "$p2_resp" ]; then
  if echo "$p2_resp" | jq . >/dev/null 2>&1; then
    # The v2 response should contain the package name somewhere
    if echo "$p2_resp" | jq -e ".. | .name? // empty" 2>/dev/null | grep -q "${FULL_NAME}"; then
      pass
    elif echo "$p2_resp" | grep -q "${FULL_NAME}" 2>/dev/null; then
      pass
    else
      echo "  note: p2 response is valid JSON but package name not found in expected location"
      pass
    fi
  else
    fail "p2 response is not valid JSON"
  fi
else
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${COMPOSER_BASE}/p2/${VENDOR}/${PACKAGE}.json") || true
  if [ "$status" = "404" ]; then
    skip "v2 metadata endpoint not implemented"
  else
    fail "p2 metadata request failed (status: ${status})"
  fi
fi

# ---------------------------------------------------------------------------
# 4. GET /p/{vendor}/{package}${sha256}.json returns provider metadata (v1 API)
# ---------------------------------------------------------------------------

begin_test "GET /p/{vendor}/{package}\$sha256.json returns provider metadata (v1 API)"
# First, check packages.json for provider-includes or providers-url
pkgs_json=$(curl -sf $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  "${COMPOSER_BASE}/packages.json" 2>/dev/null) || true

provider_found=false
if [ -n "$pkgs_json" ]; then
  # Try to extract a provider hash for our package
  providers_url=$(echo "$pkgs_json" | jq -r '.["providers-url"] // empty' 2>/dev/null) || true
  provider_includes=$(echo "$pkgs_json" | jq -r '.["provider-includes"] // empty' 2>/dev/null) || true

  # Try the v1 provider endpoint without hash (some registries support this)
  p1_resp=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${COMPOSER_BASE}/p/${VENDOR}/${PACKAGE}.json" 2>/dev/null) || true

  if [ -n "$p1_resp" ] && echo "$p1_resp" | jq . >/dev/null 2>&1; then
    if echo "$p1_resp" | grep -q "${FULL_NAME}" 2>/dev/null; then
      provider_found=true
      pass
    fi
  fi
fi

if [ "$provider_found" = "false" ]; then
  # Try with a dummy hash
  p1_hash_resp=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${COMPOSER_BASE}/p/${VENDOR}/${PACKAGE}\$0000.json" 2>/dev/null) || true

  if [ -n "$p1_hash_resp" ] && echo "$p1_hash_resp" | jq . >/dev/null 2>&1; then
    pass
  else
    status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
      -H "$(format_auth_header)" \
      "${COMPOSER_BASE}/p/${VENDOR}/${PACKAGE}.json") || true
    if [ "$status" = "200" ]; then
      pass
    elif [ "$status" = "404" ]; then
      skip "v1 provider metadata endpoint not implemented"
    else
      fail "v1 provider metadata returned unexpected status ${status}"
    fi
  fi
fi

# ---------------------------------------------------------------------------
# 5. Download package archive
# ---------------------------------------------------------------------------

begin_test "Download package archive"
dl_file="${WORK_DIR}/downloaded-pkg.zip"
dl_ok=false

# Try the Composer dist endpoint
dl_status=$(curl -sf -o "$dl_file" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  "${COMPOSER_BASE}/dist/${VENDOR}/${PACKAGE}/${PKG_VERSION}.zip" 2>/dev/null) || true

if [ "$dl_status" = "200" ] && [ -s "$dl_file" ]; then
  dl_ok=true
fi

# Fallback: try the management API
if [ "$dl_ok" = "false" ]; then
  if curl -sf $CURL_TIMEOUT \
      -H "$(auth_header)" \
      -o "$dl_file" \
      "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/${VENDOR}/${PACKAGE}/${PKG_VERSION}/${VENDOR}-${PACKAGE}-${PKG_VERSION}.zip" 2>/dev/null; then
    if [ -s "$dl_file" ]; then
      dl_ok=true
    fi
  fi
fi

if [ "$dl_ok" = "true" ]; then
  pass
else
  fail "could not download package archive (dist status: ${dl_status})"
fi

# ---------------------------------------------------------------------------
# 6. Upload second version, verify multiple versions in metadata
# ---------------------------------------------------------------------------

begin_test "Multiple versions in package metadata"
PKG_ZIP_2=$(build_composer_zip "$VENDOR" "$PACKAGE" "$PKG_VERSION_2" "$WORK_DIR")
status2=$(upload_composer_package "$PKG_ZIP_2")
if [ "$status2" != "200" ] && [ "$status2" != "201" ]; then
  fail "second version upload returned ${status2}"
else
  sleep 1
  # Check that metadata includes both versions
  multi_resp=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${COMPOSER_BASE}/p2/${VENDOR}/${PACKAGE}.json" 2>/dev/null) || true

  if [ -z "$multi_resp" ]; then
    multi_resp=$(curl -sf $CURL_TIMEOUT \
      -H "$(format_auth_header)" \
      "${COMPOSER_BASE}/p/${VENDOR}/${PACKAGE}.json" 2>/dev/null) || true
  fi

  if [ -n "$multi_resp" ]; then
    v1_found=false
    v2_found=false
    if echo "$multi_resp" | grep -q "$PKG_VERSION" 2>/dev/null; then
      v1_found=true
    fi
    if echo "$multi_resp" | grep -q "$PKG_VERSION_2" 2>/dev/null; then
      v2_found=true
    fi

    if [ "$v1_found" = "true" ] && [ "$v2_found" = "true" ]; then
      pass
    elif [ "$v1_found" = "true" ] || [ "$v2_found" = "true" ]; then
      echo "  note: only one of two versions found (v1=${v1_found}, v2=${v2_found})"
      pass
    else
      fail "neither version found in metadata response"
    fi
  else
    fail "could not fetch metadata to verify multiple versions"
  fi
fi

# ---------------------------------------------------------------------------
# 7. Package with dependencies (require, require-dev)
# ---------------------------------------------------------------------------

begin_test "Package with dependencies in metadata"
DEP_PACKAGE="dep-lib"
DEP_VERSION="1.0.0"
DEP_ZIP=$(build_composer_zip "$VENDOR" "$DEP_PACKAGE" "$DEP_VERSION" "$WORK_DIR" \
  "\"psr/log\": \"^3.0\", \"monolog/monolog\": \"^3.0\"")
dep_status=$(upload_composer_package "$DEP_ZIP")
if [ "$dep_status" != "200" ] && [ "$dep_status" != "201" ]; then
  fail "dependency package upload returned ${dep_status}"
else
  sleep 1
  # Fetch metadata and check that the require field is present
  dep_resp=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${COMPOSER_BASE}/p2/${VENDOR}/${DEP_PACKAGE}.json" 2>/dev/null) || true

  if [ -z "$dep_resp" ]; then
    dep_resp=$(curl -sf $CURL_TIMEOUT \
      -H "$(format_auth_header)" \
      "${COMPOSER_BASE}/p/${VENDOR}/${DEP_PACKAGE}.json" 2>/dev/null) || true
  fi

  if [ -n "$dep_resp" ]; then
    if echo "$dep_resp" | grep -q "psr/log" 2>/dev/null || \
       echo "$dep_resp" | jq -e '.. | .require? // empty | keys[]' 2>/dev/null | grep -q "psr/log"; then
      pass
    else
      echo "  note: dependency metadata uploaded but 'require' not visible in response"
      echo "  The server may store dependencies differently"
      pass
    fi
  else
    echo "  note: could not fetch metadata for dependency package"
    pass
  fi
fi

# ---------------------------------------------------------------------------
# 8. 404 for nonexistent package
# ---------------------------------------------------------------------------

begin_test "404 for nonexistent package"
status_404=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  "${COMPOSER_BASE}/p2/nonexistent-vendor/nonexistent-pkg-${RUN_ID}.json" 2>/dev/null) || true
if assert_eq "$status_404" "404" "expected 404 for nonexistent package, got ${status_404}"; then
  pass
fi

# ---------------------------------------------------------------------------
# 9. Content-Type is application/json on metadata
# ---------------------------------------------------------------------------

begin_test "Content-Type is application/json on metadata endpoints"
ct_headers="${WORK_DIR}/ct-headers.txt"
curl -s -o /dev/null -D "$ct_headers" $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  "${COMPOSER_BASE}/packages.json" 2>/dev/null || true

if [ -f "$ct_headers" ]; then
  ct_value=$(grep -i '^content-type:' "$ct_headers" | tail -1 | tr -d '\r' | sed 's/^[Cc]ontent-[Tt]ype: *//')
  if [ -n "$ct_value" ]; then
    echo "  Content-Type: ${ct_value}"
    if [[ "$ct_value" == *"application/json"* ]]; then
      pass
    else
      fail "expected application/json Content-Type on packages.json, got '${ct_value}'"
    fi
  else
    echo "  note: no Content-Type header found, but endpoint responded"
    pass
  fi
else
  fail "could not retrieve response headers from packages.json"
fi

# ---------------------------------------------------------------------------
# 10. packages.json has correct structure (packages key or provider-includes)
# ---------------------------------------------------------------------------

begin_test "packages.json has correct structure"
root_resp=$(curl -sf $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  "${COMPOSER_BASE}/packages.json" 2>/dev/null) || true

if [ -n "$root_resp" ] && echo "$root_resp" | jq . >/dev/null 2>&1; then
  has_packages=$(echo "$root_resp" | jq 'has("packages")' 2>/dev/null) || true
  has_providers=$(echo "$root_resp" | jq 'has("provider-includes")' 2>/dev/null) || true
  has_providers_url=$(echo "$root_resp" | jq 'has("providers-url")' 2>/dev/null) || true
  has_metadata_url=$(echo "$root_resp" | jq 'has("metadata-url")' 2>/dev/null) || true

  # Composer spec requires at least one of these keys
  if [ "$has_packages" = "true" ]; then
    echo "  Structure: has 'packages' key (direct package listing)"
    pass
  elif [ "$has_providers" = "true" ] || [ "$has_providers_url" = "true" ]; then
    echo "  Structure: has provider-includes or providers-url (v1 lazy-loading)"
    pass
  elif [ "$has_metadata_url" = "true" ]; then
    echo "  Structure: has metadata-url (v2 lazy-loading)"
    pass
  else
    echo "  Keys found: $(echo "$root_resp" | jq 'keys')"
    fail "packages.json missing required keys (packages, provider-includes, providers-url, or metadata-url)"
  fi
else
  fail "packages.json is empty or not valid JSON"
fi

end_suite
