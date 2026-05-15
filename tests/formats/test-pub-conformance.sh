#!/usr/bin/env bash
# test-pub-conformance.sh - Dart/Flutter Pub repository conformance tests (v2 spec)
#
# Validates that the pub package repository implementation conforms to the
# pub v2 API specification: package metadata, version-specific metadata,
# upload flow, archive download, pubspec preservation, and Content-Type headers.
#
# Endpoints: ${BASE_URL}/pub/{repo_key}/
#
# Requires: curl, tar, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "pub-conformance"
auth_admin
setup_workdir

REPO_KEY="test-pub-conf-${RUN_ID}"
PKG_NAME="conftest_dart_pkg"
PKG_VERSION_1="1.0.0"
PKG_VERSION_2="2.0.0"
PUB_URL="${BASE_URL}/pub/${REPO_KEY}"
BASIC_AUTH=$(echo -n "${ADMIN_USER}:${ADMIN_PASS}" | base64)

# ---------------------------------------------------------------------------
# Helper: build a minimal pub package archive
#
# A pub package is a tar.gz containing at minimum:
#   - pubspec.yaml (package metadata)
#   - lib/ directory with Dart source files
# ---------------------------------------------------------------------------

build_pub_package() {
  local name="$1"
  local version="$2"
  local outfile="$3"
  local description="${4:-Conformance test Dart package}"

  local build_dir="${WORK_DIR}/pub-build-${name}-${version}"
  mkdir -p "${build_dir}/lib/src"

  cat > "${build_dir}/pubspec.yaml" <<EOYAML
name: ${name}
version: ${version}
description: ${description}
environment:
  sdk: ">=3.0.0 <4.0.0"
EOYAML

  cat > "${build_dir}/lib/${name}.dart" <<EODART
library ${name};

export 'src/core.dart';
EODART

  cat > "${build_dir}/lib/src/core.dart" <<EODART
String greet() => 'hello from ${name} ${version}';
EODART

  cat > "${build_dir}/CHANGELOG.md" <<EOMD
## ${version}

- Initial conformance test release
EOMD

  (cd "${build_dir}" && tar czf "${outfile}" pubspec.yaml lib/ CHANGELOG.md)
}

# ---------------------------------------------------------------------------
# Helper: upload a pub package through the two-step upload flow
# ---------------------------------------------------------------------------

upload_pub_package() {
  local archive="$1"
  local result_status=""

  # Step 1: Request upload URL from the server
  local new_resp=""
  new_resp=$(curl -sf $CURL_TIMEOUT \
    -X POST \
    -H "Authorization: Basic ${BASIC_AUTH}" \
    "${PUB_URL}/api/packages/versions/new" 2>/dev/null) || true

  local upload_url=""
  if [ -n "$new_resp" ]; then
    upload_url=$(echo "$new_resp" | jq -r '.url // empty' 2>/dev/null) || true
  fi

  # Step 2: Upload the archive
  if [ -n "$upload_url" ] && [ "$upload_url" != "null" ]; then
    # Make relative URLs absolute
    if [[ "$upload_url" != http* ]]; then
      upload_url="${BASE_URL}${upload_url}"
    fi
    result_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
      -X POST \
      -H "Authorization: Basic ${BASIC_AUTH}" \
      -F "file=@${archive}" \
      "${upload_url}") || true
  else
    # Fallback: post directly to newUpload endpoint
    result_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
      -X POST \
      -H "Authorization: Basic ${BASIC_AUTH}" \
      -F "file=@${archive}" \
      "${PUB_URL}/api/packages/versions/newUpload") || true
  fi

  # Step 3: Finalize (some servers require this)
  curl -sf $CURL_TIMEOUT \
    -H "Authorization: Basic ${BASIC_AUTH}" \
    "${PUB_URL}/api/packages/versions/newUploadFinish" >/dev/null 2>&1 || true

  echo "$result_status"
}

# ---------------------------------------------------------------------------
# Create repository
# ---------------------------------------------------------------------------

begin_test "Create pub local repository"
if create_local_repo "$REPO_KEY" "pub"; then
  pass
else
  fail "could not create pub repository"
fi

# ---------------------------------------------------------------------------
# 1. Upload package (POST multipart tar.gz through the upload flow)
# ---------------------------------------------------------------------------

begin_test "Upload pub package via newUpload flow"
PUB_ARCHIVE="${WORK_DIR}/${PKG_NAME}-${PKG_VERSION_1}.tar.gz"
build_pub_package "$PKG_NAME" "$PKG_VERSION_1" "$PUB_ARCHIVE"

status=$(upload_pub_package "$PUB_ARCHIVE") || true
if [ -n "$status" ] && [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 400 ] 2>/dev/null; then
  pass
else
  fail "upload returned HTTP ${status:-empty}, expected 2xx/3xx"
fi

sleep 1

# ---------------------------------------------------------------------------
# 2. GET /api/packages/{name} returns package metadata with versions array
# ---------------------------------------------------------------------------

begin_test "GET /api/packages/{name} returns metadata with versions"
if resp=$(curl -sf $CURL_TIMEOUT \
    -H "Authorization: Basic ${BASIC_AUTH}" \
    "${PUB_URL}/api/packages/${PKG_NAME}" 2>/dev/null); then
  pkg_resp_name=$(echo "$resp" | jq -r '.name // empty' 2>/dev/null) || true
  has_versions=$(echo "$resp" | jq 'has("versions")' 2>/dev/null) || true

  if [ "$has_versions" = "true" ]; then
    version_count=$(echo "$resp" | jq '.versions | length' 2>/dev/null) || version_count=0
    if [ "$version_count" -ge 1 ] 2>/dev/null; then
      pass
    else
      fail "versions array is empty"
    fi
  elif [ -n "$pkg_resp_name" ]; then
    # Some implementations use a different structure
    echo "  note: response has name='${pkg_resp_name}' but no 'versions' array"
    if assert_contains "$resp" "$PKG_VERSION_1" "response should contain version string"; then
      pass
    fi
  else
    fail "package metadata missing both 'versions' array and 'name' field"
  fi
else
  fail "GET /api/packages/${PKG_NAME} returned error"
fi

# ---------------------------------------------------------------------------
# 3. GET /api/packages/{name}/versions/{version} returns version metadata
# ---------------------------------------------------------------------------

begin_test "GET /api/packages/{name}/versions/{version} returns version metadata"
if resp=$(curl -sf $CURL_TIMEOUT \
    -H "Authorization: Basic ${BASIC_AUTH}" \
    "${PUB_URL}/api/packages/${PKG_NAME}/versions/${PKG_VERSION_1}" 2>/dev/null); then
  ver=$(echo "$resp" | jq -r '.version // empty' 2>/dev/null) || true
  if [ "$ver" = "$PKG_VERSION_1" ]; then
    pass
  else
    # Version info may be nested under .pubspec.version
    pubspec_ver=$(echo "$resp" | jq -r '.pubspec.version // empty' 2>/dev/null) || true
    if [ "$pubspec_ver" = "$PKG_VERSION_1" ]; then
      pass
    else
      if assert_contains "$resp" "$PKG_VERSION_1" "version metadata should contain version string"; then
        pass
      fi
    fi
  fi
else
  fail "GET /api/packages/${PKG_NAME}/versions/${PKG_VERSION_1} returned error"
fi

# ---------------------------------------------------------------------------
# 4. Download archive via URL from metadata
# ---------------------------------------------------------------------------

begin_test "Download package archive"
# First get the archive URL from version metadata
archive_url=""
if ver_resp=$(curl -sf $CURL_TIMEOUT \
    -H "Authorization: Basic ${BASIC_AUTH}" \
    "${PUB_URL}/api/packages/${PKG_NAME}/versions/${PKG_VERSION_1}" 2>/dev/null); then
  archive_url=$(echo "$ver_resp" | jq -r '.archive_url // .archive // empty' 2>/dev/null) || true
fi

DL_FILE="${WORK_DIR}/downloaded.tar.gz"
if [ -n "$archive_url" ] && [ "$archive_url" != "null" ]; then
  # Make relative URLs absolute
  if [[ "$archive_url" != http* ]]; then
    archive_url="${BASE_URL}${archive_url}"
  fi
  dl_status=$(curl -s -o "$DL_FILE" -w '%{http_code}' $CURL_TIMEOUT \
    -H "Authorization: Basic ${BASIC_AUTH}" \
    "${archive_url}") || true
else
  # Fallback: try the conventional archive path
  dl_status=$(curl -s -o "$DL_FILE" -w '%{http_code}' $CURL_TIMEOUT \
    -H "Authorization: Basic ${BASIC_AUTH}" \
    "${PUB_URL}/packages/${PKG_NAME}/versions/${PKG_VERSION_1}.tar.gz") || true
fi

if [ "$dl_status" -ge 200 ] 2>/dev/null && [ "$dl_status" -lt 300 ] 2>/dev/null; then
  if [ -s "$DL_FILE" ]; then
    pass
  else
    fail "downloaded archive is empty"
  fi
else
  fail "archive download returned HTTP ${dl_status:-empty}"
fi

# ---------------------------------------------------------------------------
# 5. Package pubspec.yaml content preserved in downloaded archive
# ---------------------------------------------------------------------------

begin_test "pubspec.yaml content preserved in downloaded archive"
if [ -s "$DL_FILE" ]; then
  EXTRACT_DIR="${WORK_DIR}/extracted"
  mkdir -p "$EXTRACT_DIR"
  if tar xzf "$DL_FILE" -C "$EXTRACT_DIR" 2>/dev/null; then
    if [ -f "${EXTRACT_DIR}/pubspec.yaml" ]; then
      # Verify key fields are present
      if grep -q "name: ${PKG_NAME}" "${EXTRACT_DIR}/pubspec.yaml" 2>/dev/null; then
        if grep -q "version: ${PKG_VERSION_1}" "${EXTRACT_DIR}/pubspec.yaml" 2>/dev/null; then
          pass
        else
          fail "pubspec.yaml does not contain expected version"
        fi
      else
        fail "pubspec.yaml does not contain expected package name"
      fi
    else
      fail "pubspec.yaml not found in extracted archive"
    fi
  else
    fail "could not extract downloaded archive"
  fi
else
  skip "no archive downloaded for pubspec verification"
fi

# ---------------------------------------------------------------------------
# 6. Multiple versions listed after uploading second version
# ---------------------------------------------------------------------------

begin_test "Multiple versions listed in package metadata"
PUB_ARCHIVE_2="${WORK_DIR}/${PKG_NAME}-${PKG_VERSION_2}.tar.gz"
build_pub_package "$PKG_NAME" "$PKG_VERSION_2" "$PUB_ARCHIVE_2" "Conformance test v2"

status2=$(upload_pub_package "$PUB_ARCHIVE_2") || true
if [ -n "$status2" ] && [ "$status2" -ge 200 ] 2>/dev/null && [ "$status2" -lt 400 ] 2>/dev/null; then
  sleep 1
  if resp=$(curl -sf $CURL_TIMEOUT \
      -H "Authorization: Basic ${BASIC_AUTH}" \
      "${PUB_URL}/api/packages/${PKG_NAME}" 2>/dev/null); then
    version_count=$(echo "$resp" | jq '.versions | length' 2>/dev/null) || version_count=0
    if [ "$version_count" -ge 2 ] 2>/dev/null; then
      pass
    else
      # Check if both versions appear anywhere in the response
      has_v1=$(echo "$resp" | grep -c "$PKG_VERSION_1" 2>/dev/null) || has_v1=0
      has_v2=$(echo "$resp" | grep -c "$PKG_VERSION_2" 2>/dev/null) || has_v2=0
      if [ "$has_v1" -ge 1 ] && [ "$has_v2" -ge 1 ]; then
        echo "  note: both versions present but versions array count is ${version_count}"
        pass
      else
        fail "expected >= 2 versions, got ${version_count} (v1=${has_v1}, v2=${has_v2})"
      fi
    fi
  else
    fail "could not fetch package metadata after second upload"
  fi
else
  fail "second version upload returned HTTP ${status2:-empty}"
fi

# ---------------------------------------------------------------------------
# 7. 404 for nonexistent package
# ---------------------------------------------------------------------------

begin_test "404 for nonexistent package"
status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -H "Authorization: Basic ${BASIC_AUTH}" \
  "${PUB_URL}/api/packages/nonexistent_pkg_${RUN_ID}") || true
if assert_eq "$status" "404" "expected 404 for nonexistent package, got ${status}"; then
  pass
fi

# ---------------------------------------------------------------------------
# 8. Content-Type is application/json on metadata endpoints
# ---------------------------------------------------------------------------

begin_test "Metadata endpoint returns Content-Type application/json"
content_type=$(curl -sf $CURL_TIMEOUT \
  -H "Authorization: Basic ${BASIC_AUTH}" \
  -o /dev/null -w '%{content_type}' \
  "${PUB_URL}/api/packages/${PKG_NAME}" 2>/dev/null) || true

if [ -n "$content_type" ]; then
  if [[ "$content_type" == *"application/json"* ]]; then
    pass
  else
    # Some servers return application/vnd.pub.v2+json which is also acceptable
    if [[ "$content_type" == *"json"* ]]; then
      echo "  Content-Type: ${content_type} (JSON variant, acceptable)"
      pass
    else
      fail "expected application/json Content-Type, got ${content_type}"
    fi
  fi
else
  fail "could not determine Content-Type for metadata endpoint"
fi

end_suite
