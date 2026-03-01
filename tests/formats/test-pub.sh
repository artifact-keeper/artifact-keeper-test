#!/usr/bin/env bash
# test-pub.sh - Dart/Flutter pub repository E2E test
#
# Requires: curl, tar (no native dart toolchain needed)
# Tests: create local repo, upload package archive, verify via pub API endpoints
source "$(dirname "$0")/../lib/common.sh"

begin_suite "pub"
auth_admin
setup_workdir

REPO_KEY="test-pub-${RUN_ID}"
PACKAGE_NAME="testpkg"
PACKAGE_VERSION="1.0.0"

# -------------------------------------------------------------------------
# Create repository
# -------------------------------------------------------------------------

begin_test "Create pub repository"
if create_local_repo "$REPO_KEY" "pub"; then
  pass
else
  fail "could not create pub repo"
fi

# -------------------------------------------------------------------------
# Build a minimal pub package archive
# -------------------------------------------------------------------------

begin_test "Create minimal pub package archive"
PKG_DIR="${WORK_DIR}/pkg"
mkdir -p "${PKG_DIR}/lib"

cat > "${PKG_DIR}/pubspec.yaml" <<EOF
name: ${PACKAGE_NAME}
version: ${PACKAGE_VERSION}
description: E2E test package for artifact-keeper pub registry
environment:
  sdk: ">=3.0.0 <4.0.0"
EOF

cat > "${PKG_DIR}/lib/${PACKAGE_NAME}.dart" <<EOF
String hello() => 'hello from ${PACKAGE_NAME}';
EOF

# Pub packages are uploaded as tar.gz archives
cd "${PKG_DIR}"
tar czf "${WORK_DIR}/package.tar.gz" pubspec.yaml lib/

if [ -s "${WORK_DIR}/package.tar.gz" ]; then
  pass
else
  fail "failed to create package archive"
fi

# -------------------------------------------------------------------------
# Upload package via multipart POST (newUpload endpoint)
# -------------------------------------------------------------------------

begin_test "Upload package via newUpload endpoint"
BASIC_AUTH=$(echo -n "${ADMIN_USER}:${ADMIN_PASS}" | base64)

# Step 1: Request upload URL
upload_resp=$(curl -sf -X POST \
    -H "Authorization: Basic ${BASIC_AUTH}" \
    "${BASE_URL}/pub/${REPO_KEY}/api/packages/versions/new" 2>/dev/null) || true

if [ -n "$upload_resp" ]; then
  # The response should contain an upload URL
  upload_url=$(echo "$upload_resp" | jq -r '.url // empty' 2>/dev/null)
fi

# Step 2: Upload the archive via multipart form
if [ -n "$upload_url" ] && [ "$upload_url" != "null" ]; then
  HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
      -X POST \
      -H "Authorization: Basic ${BASIC_AUTH}" \
      -F "file=@${WORK_DIR}/package.tar.gz" \
      "${upload_url}")
else
  # Fallback: post directly to the newUpload endpoint
  HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
      -X POST \
      -H "Authorization: Basic ${BASIC_AUTH}" \
      -F "file=@${WORK_DIR}/package.tar.gz" \
      "${BASE_URL}/pub/${REPO_KEY}/api/packages/versions/newUpload")
fi

if [ "$HTTP_CODE" -ge 200 ] && [ "$HTTP_CODE" -lt 400 ]; then
  pass
else
  fail "upload returned HTTP ${HTTP_CODE}"
fi

# Step 3: Finalize upload
finalize_code=$(curl -s -o /dev/null -w '%{http_code}' \
    -H "Authorization: Basic ${BASIC_AUTH}" \
    "${BASE_URL}/pub/${REPO_KEY}/api/packages/versions/newUploadFinish" 2>/dev/null) || true

# Finalize may return 200 or 302; both are acceptable

# -------------------------------------------------------------------------
# Verify package info via API
# -------------------------------------------------------------------------

begin_test "Verify package info endpoint"
sleep 1
if resp=$(curl -sf -H "Authorization: Basic ${BASIC_AUTH}" \
    "${BASE_URL}/pub/${REPO_KEY}/api/packages/${PACKAGE_NAME}" 2>/dev/null); then
  if assert_contains "$resp" "${PACKAGE_NAME}"; then
    pass
  fi
else
  fail "package info endpoint returned error"
fi

# -------------------------------------------------------------------------
# Verify version info endpoint
# -------------------------------------------------------------------------

begin_test "Verify version info endpoint"
if resp=$(curl -sf -H "Authorization: Basic ${BASIC_AUTH}" \
    "${BASE_URL}/pub/${REPO_KEY}/api/packages/${PACKAGE_NAME}/versions/${PACKAGE_VERSION}" 2>/dev/null); then
  if assert_contains "$resp" "${PACKAGE_VERSION}"; then
    pass
  fi
else
  fail "version info endpoint returned error"
fi

# -------------------------------------------------------------------------
# Download package archive
# -------------------------------------------------------------------------

begin_test "Download package archive"
if curl -sf -H "Authorization: Basic ${BASIC_AUTH}" \
    -o "${WORK_DIR}/downloaded.tar.gz" \
    "${BASE_URL}/pub/${REPO_KEY}/packages/${PACKAGE_NAME}/versions/${PACKAGE_VERSION}.tar.gz" 2>/dev/null; then
  if [ -s "${WORK_DIR}/downloaded.tar.gz" ]; then
    pass
  else
    fail "downloaded archive is empty"
  fi
else
  fail "package archive download returned error"
fi

# -------------------------------------------------------------------------
# Verify archive contents
# -------------------------------------------------------------------------

begin_test "Verify downloaded archive contents"
EXTRACT_DIR="${WORK_DIR}/extracted"
mkdir -p "${EXTRACT_DIR}"
if tar xzf "${WORK_DIR}/downloaded.tar.gz" -C "${EXTRACT_DIR}" 2>/dev/null; then
  if [ -f "${EXTRACT_DIR}/pubspec.yaml" ]; then
    pass
  else
    fail "pubspec.yaml not found in extracted archive"
  fi
else
  fail "failed to extract downloaded archive"
fi

end_suite
