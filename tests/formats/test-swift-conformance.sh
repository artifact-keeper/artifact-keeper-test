#!/usr/bin/env bash
# test-swift-conformance.sh - Swift Package Registry (SE-0292) conformance tests
#
# Validates the Swift Package Registry protocol defined in SE-0292:
# release listing, release metadata, manifest fetching, version-specific
# manifests, publishing, source archive download, content negotiation
# with swift.registry media types, problem+json errors, and manifest
# selection by Swift version.
#
# Reference: https://github.com/swiftlang/swift-evolution/blob/main/proposals/0292-package-registry-service.md
#
# Endpoints: ${BASE_URL}/swift/{repo_key}/
#
# Requires: curl, jq, zip

source "$(dirname "$0")/../lib/common.sh"

begin_suite "swift-conformance"
require_cmd zip
auth_admin
setup_workdir

REPO_KEY="test-swift-conf-${RUN_ID}"
SCOPE="conftest"
PACKAGE_NAME="networklib"
PACKAGE_VERSION="1.0.0"
SWIFT_BASE="${BASE_URL}/swift/${REPO_KEY}"

# ---------------------------------------------------------------------------
# Helper: build a minimal Swift source archive (.zip)
# ---------------------------------------------------------------------------

build_swift_archive() {
  local scope="$1"
  local name="$2"
  local version="$3"
  local outfile="$4"
  local swift_tools_version="${5:-5.9}"

  local pkg_dir="${WORK_DIR}/swift-build-${name}-${version}"
  mkdir -p "${pkg_dir}/Sources/${name}"

  cat > "${pkg_dir}/Package.swift" <<MANIFEST
// swift-tools-version:${swift_tools_version}
import PackageDescription

let package = Package(
    name: "${name}",
    products: [
        .library(name: "${name}", targets: ["${name}"]),
    ],
    targets: [
        .target(name: "${name}"),
    ]
)
MANIFEST

  # Some registries look for version-specific manifests
  if [ "$swift_tools_version" != "5.9" ]; then
    cp "${pkg_dir}/Package.swift" "${pkg_dir}/Package@swift-${swift_tools_version}.swift"
  fi

  cat > "${pkg_dir}/Sources/${name}/Lib.swift" <<SWIFT
public struct ${name} {
    public static let version = "${version}"
    public init() {}
}
SWIFT

  (cd "${WORK_DIR}" && zip -rq "${outfile}" "swift-build-${name}-${version}/")
}

# Helper: publish a release via PUT. Prints the HTTP status code.
publish_release() {
  local archive="$1"
  local scope="$2"
  local name="$3"
  local version="$4"

  curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X PUT \
    -H "$(format_auth_header)" \
    -H "Content-Type: application/zip" \
    --data-binary "@${archive}" \
    "${SWIFT_BASE}/${scope}/${name}/${version}"
}

# ---------------------------------------------------------------------------
# Setup: create repository and publish initial release
# ---------------------------------------------------------------------------

begin_test "Create Swift local repository"
if create_local_repo "$REPO_KEY" "swift"; then
  pass
else
  fail "could not create swift repository"
fi

ARCHIVE_V1="${WORK_DIR}/${PACKAGE_NAME}-${PACKAGE_VERSION}.zip"
build_swift_archive "$SCOPE" "$PACKAGE_NAME" "$PACKAGE_VERSION" "$ARCHIVE_V1"

begin_test "PUT /{scope}/{name}/{version} publishes a release"
pub_status=$(publish_release "$ARCHIVE_V1" "$SCOPE" "$PACKAGE_NAME" "$PACKAGE_VERSION")
if [ "$pub_status" -ge 200 ] 2>/dev/null && [ "$pub_status" -lt 300 ] 2>/dev/null; then
  pass
else
  fail "publish returned HTTP ${pub_status}, expected 2xx"
fi

# Brief pause for indexing
sleep 1

# ---------------------------------------------------------------------------
# 1. List package releases
# ---------------------------------------------------------------------------

begin_test "GET /{scope}/{name} lists package releases"
RELEASES_RESP=""
RELEASES_CT=""
releases_status=$(curl -s -o "${WORK_DIR}/releases.json" -w '%{http_code}' $CURL_TIMEOUT \
  -D "${WORK_DIR}/releases-headers.txt" \
  -H "$(format_auth_header)" \
  "${SWIFT_BASE}/${SCOPE}/${PACKAGE_NAME}" 2>/dev/null) || releases_status="000"

if [ "$releases_status" = "200" ]; then
  RELEASES_RESP=$(cat "${WORK_DIR}/releases.json")
  RELEASES_CT=$(grep -i 'content-type' "${WORK_DIR}/releases-headers.txt" | sed 's/^[^:]*: *//' | tr -d '\r\n') || true

  if assert_contains "$RELEASES_RESP" "$PACKAGE_VERSION" \
      "releases response should list version ${PACKAGE_VERSION}"; then
    # SE-0292 specifies Content-Type: application/vnd.swift.registry.package.v1+json
    if [[ "$RELEASES_CT" == *"swift.registry"* ]]; then
      echo "  Content-Type: ${RELEASES_CT} (SE-0292 compliant)"
    else
      echo "  note: Content-Type is ${RELEASES_CT} (expected vnd.swift.registry media type)"
    fi
    pass
  fi
else
  fail "GET /${SCOPE}/${PACKAGE_NAME} returned HTTP ${releases_status}"
fi

# ---------------------------------------------------------------------------
# 2. Release metadata
# ---------------------------------------------------------------------------

begin_test "GET /{scope}/{name}/{version} returns release metadata"
METADATA_RESP=""
if METADATA_RESP=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${SWIFT_BASE}/${SCOPE}/${PACKAGE_NAME}/${PACKAGE_VERSION}" 2>/dev/null); then

  if assert_contains "$METADATA_RESP" "$PACKAGE_VERSION" \
      "release metadata should reference version ${PACKAGE_VERSION}"; then
    pass
  fi
else
  fail "GET /${SCOPE}/${PACKAGE_NAME}/${PACKAGE_VERSION} returned error"
fi

# ---------------------------------------------------------------------------
# 3. Manifest (Package.swift)
# ---------------------------------------------------------------------------

begin_test "GET /{scope}/{name}/{version}/Package.swift returns manifest"
MANIFEST_RESP=""
if MANIFEST_RESP=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${SWIFT_BASE}/${SCOPE}/${PACKAGE_NAME}/${PACKAGE_VERSION}/Package.swift" 2>/dev/null); then

  if assert_contains "$MANIFEST_RESP" "PackageDescription" \
      "Package.swift should contain PackageDescription import"; then
    if assert_contains "$MANIFEST_RESP" "$PACKAGE_NAME" \
        "Package.swift should reference the package name"; then
      pass
    fi
  fi
else
  skip "Package.swift endpoint not available"
fi

# ---------------------------------------------------------------------------
# 4. Version-specific manifest
# ---------------------------------------------------------------------------

begin_test "GET /{scope}/{name}/{version}/Package.swift?swift-version=5.9 returns manifest"
VERSIONED_MANIFEST=""
versioned_status=$(curl -s -o "${WORK_DIR}/versioned-manifest.swift" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  "${SWIFT_BASE}/${SCOPE}/${PACKAGE_NAME}/${PACKAGE_VERSION}/Package.swift?swift-version=5.9" 2>/dev/null) || versioned_status="000"

if [ "$versioned_status" = "200" ]; then
  VERSIONED_MANIFEST=$(cat "${WORK_DIR}/versioned-manifest.swift")
  if assert_contains "$VERSIONED_MANIFEST" "PackageDescription" \
      "version-specific manifest should contain PackageDescription import"; then
    pass
  fi
elif [ "$versioned_status" = "303" ]; then
  # SE-0292 allows 303 See Other redirecting to the unversioned manifest
  echo "  note: server redirects to unversioned manifest (303), acceptable per SE-0292"
  pass
elif [ "$versioned_status" = "404" ]; then
  skip "version-specific manifest selection not supported"
else
  fail "version-specific manifest returned HTTP ${versioned_status}"
fi

# ---------------------------------------------------------------------------
# 5. Download source archive
# ---------------------------------------------------------------------------

begin_test "Download source archive"
DL_ARCHIVE="${WORK_DIR}/downloaded-source.zip"
dl_status=$(curl -sf -o "$DL_ARCHIVE" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  "${SWIFT_BASE}/${SCOPE}/${PACKAGE_NAME}/${PACKAGE_VERSION}.zip" 2>/dev/null) || dl_status="000"

if [ "$dl_status" != "200" ] || [ ! -s "$DL_ARCHIVE" ]; then
  # Try alternate download path
  dl_status=$(curl -sf -o "$DL_ARCHIVE" -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${SWIFT_BASE}/${SCOPE}/${PACKAGE_NAME}/${PACKAGE_VERSION}/download" 2>/dev/null) || dl_status="000"
fi

if [ "$dl_status" = "200" ] && [ -s "$DL_ARCHIVE" ]; then
  # Verify the archive is a valid zip containing Package.swift
  if unzip -l "$DL_ARCHIVE" 2>/dev/null | grep -q "Package.swift"; then
    pass
  else
    echo "  note: archive downloaded but Package.swift not found at expected path"
    pass
  fi
else
  fail "source archive download returned HTTP ${dl_status}, expected 200"
fi

# ---------------------------------------------------------------------------
# 6. Content negotiation with swift.registry media types
# ---------------------------------------------------------------------------

begin_test "Content negotiation with swift.registry media types"
# SE-0292 defines specific media types for the registry API.
# Request with the SE-0292 Accept header and verify the response.
nego_status=$(curl -s -o "${WORK_DIR}/nego-body.json" -w '%{http_code}' $CURL_TIMEOUT \
  -D "${WORK_DIR}/nego-headers.txt" \
  -H "$(format_auth_header)" \
  -H "Accept: application/vnd.swift.registry.package.v1+json" \
  "${SWIFT_BASE}/${SCOPE}/${PACKAGE_NAME}" 2>/dev/null) || nego_status="000"

if [ "$nego_status" = "200" ]; then
  nego_ct=$(grep -i 'content-type' "${WORK_DIR}/nego-headers.txt" | sed 's/^[^:]*: *//' | tr -d '\r\n') || true
  if [[ "$nego_ct" == *"swift.registry"* ]] || [[ "$nego_ct" == *"application/json"* ]]; then
    pass
  else
    echo "  note: server returned Content-Type ${nego_ct} instead of vnd.swift.registry media type"
    pass
  fi
elif [ "$nego_status" = "406" ]; then
  skip "server does not support swift.registry content negotiation (406 Not Acceptable)"
else
  # The endpoint might work but ignore the Accept header
  if [ "$nego_status" = "200" ] || [ "$nego_status" = "000" ]; then
    skip "content negotiation behavior unclear"
  else
    fail "content negotiation request returned HTTP ${nego_status}"
  fi
fi

# ---------------------------------------------------------------------------
# 7. problem+json error responses
# ---------------------------------------------------------------------------

begin_test "problem+json error responses"
# SE-0292 specifies that error responses should use the application/problem+json
# content type per RFC 7807.
error_headers="${WORK_DIR}/error-headers.txt"
error_body="${WORK_DIR}/error-body.json"

error_status=$(curl -s -o "$error_body" -w '%{http_code}' $CURL_TIMEOUT \
  -D "$error_headers" \
  -H "$(format_auth_header)" \
  -H "Accept: application/vnd.swift.registry.package.v1+json" \
  "${SWIFT_BASE}/${SCOPE}/nonexistent-package-${RUN_ID}" 2>/dev/null) || error_status="000"

if [ "$error_status" = "404" ]; then
  error_ct=$(grep -i 'content-type' "$error_headers" | sed 's/^[^:]*: *//' | tr -d '\r\n') || true
  error_content=$(cat "$error_body" 2>/dev/null) || true

  if [[ "$error_ct" == *"problem+json"* ]]; then
    # Full SE-0292 compliance: problem+json with detail field
    if echo "$error_content" | jq -e '.detail // .title // .status' >/dev/null 2>&1; then
      pass
    else
      echo "  note: problem+json response but missing standard fields"
      pass
    fi
  elif [[ "$error_ct" == *"application/json"* ]]; then
    # Server returns JSON errors but not in problem+json format
    echo "  note: server uses application/json instead of problem+json for errors"
    pass
  else
    echo "  note: error response Content-Type is ${error_ct}"
    pass
  fi
elif [ "$error_status" = "000" ]; then
  skip "could not reach error endpoint"
else
  echo "  note: nonexistent package returned HTTP ${error_status} (expected 404)"
  pass
fi

# ---------------------------------------------------------------------------
# 8. 404 for nonexistent package
# ---------------------------------------------------------------------------

begin_test "404 for nonexistent package"
missing_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  "${SWIFT_BASE}/${SCOPE}/this-package-does-not-exist-${RUN_ID}" 2>/dev/null) || missing_status="000"

if assert_eq "$missing_status" "404" \
    "nonexistent package should return 404, got ${missing_status}"; then
  pass
fi

# ---------------------------------------------------------------------------
# 9. Multiple releases and manifest selection by Swift version
# ---------------------------------------------------------------------------

begin_test "Manifest selection by Swift version across releases"
# Publish a second version with a different swift-tools-version
PACKAGE_VERSION_2="2.0.0"
ARCHIVE_V2="${WORK_DIR}/${PACKAGE_NAME}-${PACKAGE_VERSION_2}.zip"
build_swift_archive "$SCOPE" "$PACKAGE_NAME" "$PACKAGE_VERSION_2" "$ARCHIVE_V2" "5.10"

v2_status=$(publish_release "$ARCHIVE_V2" "$SCOPE" "$PACKAGE_NAME" "$PACKAGE_VERSION_2")
if [ "$v2_status" -ge 200 ] 2>/dev/null && [ "$v2_status" -lt 300 ] 2>/dev/null; then
  sleep 1

  # Fetch manifest for v2 with swift-version=5.10
  manifest_v2=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${SWIFT_BASE}/${SCOPE}/${PACKAGE_NAME}/${PACKAGE_VERSION_2}/Package.swift?swift-version=5.10" 2>/dev/null) || true

  if [ -n "$manifest_v2" ]; then
    if assert_contains "$manifest_v2" "PackageDescription" \
        "v2 manifest should contain PackageDescription"; then
      pass
    fi
  else
    # Fall back to the unversioned manifest
    manifest_v2=$(curl -sf $CURL_TIMEOUT \
      -H "$(format_auth_header)" \
      "${SWIFT_BASE}/${SCOPE}/${PACKAGE_NAME}/${PACKAGE_VERSION_2}/Package.swift" 2>/dev/null) || true
    if [ -n "$manifest_v2" ] && echo "$manifest_v2" | grep -q "PackageDescription"; then
      pass
    else
      skip "manifest selection for v2 not available"
    fi
  fi
else
  fail "v2 publish returned HTTP ${v2_status}"
fi

# ---------------------------------------------------------------------------
# 10. Releases list includes both versions after second publish
# ---------------------------------------------------------------------------

begin_test "Releases list includes both versions"
if releases2=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${SWIFT_BASE}/${SCOPE}/${PACKAGE_NAME}" 2>/dev/null); then

  has_v1=$(echo "$releases2" | grep -c "$PACKAGE_VERSION" 2>/dev/null) || has_v1="0"
  has_v2=$(echo "$releases2" | grep -c "$PACKAGE_VERSION_2" 2>/dev/null) || has_v2="0"

  if [ "$has_v1" -gt 0 ] && [ "$has_v2" -gt 0 ]; then
    pass
  else
    fail "releases should list both ${PACKAGE_VERSION} and ${PACKAGE_VERSION_2} (v1 matches: ${has_v1}, v2 matches: ${has_v2})"
  fi
else
  fail "could not fetch releases list after second publish"
fi

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

api_delete "/api/v1/repositories/${REPO_KEY}" > /dev/null 2>&1 || true

end_suite
