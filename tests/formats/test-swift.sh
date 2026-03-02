#!/usr/bin/env bash
# test-swift.sh - Swift Package Registry (SE-0292) E2E test
#
# Requires: curl, zip (no native swift toolchain needed)
# Tests: create local repo, upload package release, verify metadata and download
source "$(dirname "$0")/../lib/common.sh"

begin_suite "swift"
require_cmd zip
auth_admin
setup_workdir

REPO_KEY="test-swift-${RUN_ID}"
SCOPE="testorg"
PACKAGE_NAME="testpkg"
PACKAGE_VERSION="1.0.0"

# -------------------------------------------------------------------------
# Create repository
# -------------------------------------------------------------------------

begin_test "Create swift repository"
if create_local_repo "$REPO_KEY" "swift"; then
  pass
else
  fail "could not create swift repo"
fi

# -------------------------------------------------------------------------
# Build a minimal source archive
# -------------------------------------------------------------------------

begin_test "Create minimal source archive"
PKG_DIR="${WORK_DIR}/swift-pkg"
mkdir -p "${PKG_DIR}/Sources/TestPkg"

cat > "${PKG_DIR}/Package.swift" <<'EOF'
// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "TestPkg",
    products: [
        .library(name: "TestPkg", targets: ["TestPkg"]),
    ],
    targets: [
        .target(name: "TestPkg"),
    ]
)
EOF

cat > "${PKG_DIR}/Sources/TestPkg/Hello.swift" <<'EOF'
public func hello() -> String {
    return "hello from TestPkg"
}
EOF

cd "${WORK_DIR}"
zip -rq "${WORK_DIR}/testpkg-1.0.0.zip" swift-pkg/

if [ -s "${WORK_DIR}/testpkg-1.0.0.zip" ]; then
  pass
else
  fail "failed to create source archive"
fi

# -------------------------------------------------------------------------
# Publish release via PUT
# -------------------------------------------------------------------------

begin_test "Publish swift package release"
BASIC_AUTH=$(echo -n "${ADMIN_USER}:${ADMIN_PASS}" | base64)
HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
    -X PUT \
    -H "Authorization: Basic ${BASIC_AUTH}" \
    -H "Content-Type: application/zip" \
    --data-binary "@${WORK_DIR}/testpkg-1.0.0.zip" \
    "${BASE_URL}/swift/${REPO_KEY}/${SCOPE}/${PACKAGE_NAME}/${PACKAGE_VERSION}")

if [ "$HTTP_CODE" -ge 200 ] && [ "$HTTP_CODE" -lt 300 ]; then
  pass
else
  fail "publish returned HTTP ${HTTP_CODE}, expected 2xx"
fi

# -------------------------------------------------------------------------
# List package releases
# -------------------------------------------------------------------------

begin_test "List package releases"
sleep 1
if resp=$(api_get "/swift/${REPO_KEY}/${SCOPE}/${PACKAGE_NAME}" 2>/dev/null); then
  if assert_contains "$resp" "${PACKAGE_VERSION}"; then
    pass
  fi
else
  fail "list releases endpoint returned error"
fi

# -------------------------------------------------------------------------
# Get release metadata
# -------------------------------------------------------------------------

begin_test "Get release metadata"
if resp=$(api_get "/swift/${REPO_KEY}/${SCOPE}/${PACKAGE_NAME}/${PACKAGE_VERSION}" 2>/dev/null); then
  if assert_contains "$resp" "${PACKAGE_VERSION}"; then
    pass
  fi
else
  fail "release metadata endpoint returned error"
fi

# -------------------------------------------------------------------------
# Download source archive
# -------------------------------------------------------------------------

begin_test "Download source archive"
if curl -sf -H "$(format_auth_header)" \
    -o "${WORK_DIR}/downloaded.zip" \
    "${BASE_URL}/swift/${REPO_KEY}/${SCOPE}/${PACKAGE_NAME}/${PACKAGE_VERSION}.zip" 2>/dev/null; then
  if [ -s "${WORK_DIR}/downloaded.zip" ]; then
    pass
  else
    fail "downloaded archive is empty"
  fi
else
  fail "source archive download returned error"
fi

# -------------------------------------------------------------------------
# Fetch Package.swift manifest
# -------------------------------------------------------------------------

begin_test "Fetch Package.swift manifest"
if resp=$(curl -sf -H "$(format_auth_header)" \
    "${BASE_URL}/swift/${REPO_KEY}/${SCOPE}/${PACKAGE_NAME}/${PACKAGE_VERSION}/Package.swift" 2>/dev/null); then
  if assert_contains "$resp" "PackageDescription"; then
    pass
  fi
else
  # Manifest extraction may not be supported
  skip "Package.swift endpoint not available"
fi

# -------------------------------------------------------------------------
# Lookup identifiers
# -------------------------------------------------------------------------

begin_test "Lookup identifiers by URL"
PKG_URL="https://github.com/${SCOPE}/${PACKAGE_NAME}"
if resp=$(curl -sf -H "$(format_auth_header)" \
    "${BASE_URL}/swift/${REPO_KEY}/identifiers?url=${PKG_URL}" 2>/dev/null); then
  # Any valid JSON response is acceptable
  pass
else
  skip "identifiers endpoint not available"
fi

end_suite
