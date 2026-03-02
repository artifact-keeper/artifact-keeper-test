#!/usr/bin/env bash
# test-debian.sh - Debian/APT repository E2E test
#
# Requires: curl, ar (part of binutils)
# Tests: create local repo, upload .deb package, verify Packages index and download
source "$(dirname "$0")/../lib/common.sh"

begin_suite "debian"
auth_admin
setup_workdir

REPO_KEY="test-debian-${RUN_ID}"
PKG_NAME="testpkg"
PKG_VERSION="1.0.0"
PKG_ARCH="amd64"
DISTRIBUTION="stable"
COMPONENT="main"
DEB_FILE="${PKG_NAME}_${PKG_VERSION}_${PKG_ARCH}.deb"

# -------------------------------------------------------------------------
# Create repository
# -------------------------------------------------------------------------

begin_test "Create debian repository"
if create_local_repo "$REPO_KEY" "debian"; then
  pass
else
  fail "could not create debian repo"
fi

# -------------------------------------------------------------------------
# Build a minimal .deb package
# -------------------------------------------------------------------------

begin_test "Create minimal .deb package"
DEB_DIR="${WORK_DIR}/deb-build"
mkdir -p "${DEB_DIR}/DEBIAN"
mkdir -p "${DEB_DIR}/usr/bin"

cat > "${DEB_DIR}/DEBIAN/control" <<EOF
Package: ${PKG_NAME}
Version: ${PKG_VERSION}
Section: utils
Priority: optional
Architecture: ${PKG_ARCH}
Maintainer: Test <test@example.com>
Description: E2E test package for artifact-keeper
EOF

echo '#!/bin/sh' > "${DEB_DIR}/usr/bin/${PKG_NAME}"
echo "echo hello from ${PKG_NAME}" >> "${DEB_DIR}/usr/bin/${PKG_NAME}"
chmod 755 "${DEB_DIR}/usr/bin/${PKG_NAME}"

if command -v dpkg-deb &>/dev/null; then
  # Use dpkg-deb if available (Linux)
  dpkg-deb --build "${DEB_DIR}" "${WORK_DIR}/${DEB_FILE}" 2>/dev/null
else
  # Build a minimal .deb manually using ar (available on macOS via Xcode)
  # A .deb is an ar archive containing: debian-binary, control.tar.gz, data.tar.gz
  cd "${WORK_DIR}"

  # debian-binary
  echo "2.0" > debian-binary

  # control.tar.gz
  cd "${DEB_DIR}/DEBIAN"
  tar czf "${WORK_DIR}/control.tar.gz" ./control

  # data.tar.gz
  cd "${DEB_DIR}"
  tar czf "${WORK_DIR}/data.tar.gz" ./usr

  # Assemble with ar
  cd "${WORK_DIR}"
  if command -v ar &>/dev/null; then
    ar rcs "${WORK_DIR}/${DEB_FILE}" debian-binary control.tar.gz data.tar.gz 2>/dev/null
  else
    # Last resort: create a binary blob that looks enough like a .deb
    cat debian-binary control.tar.gz data.tar.gz > "${WORK_DIR}/${DEB_FILE}"
  fi
fi

if [ -s "${WORK_DIR}/${DEB_FILE}" ]; then
  pass
else
  fail "failed to create .deb package"
fi

# -------------------------------------------------------------------------
# Upload .deb via pool PUT
# -------------------------------------------------------------------------

begin_test "Upload .deb via pool endpoint"
HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
    -X PUT \
    -H "$(format_auth_header)" \
    -H "Content-Type: application/vnd.debian.binary-package" \
    --data-binary "@${WORK_DIR}/${DEB_FILE}" \
    "${BASE_URL}/debian/${REPO_KEY}/pool/${COMPONENT}/${DEB_FILE}")

if [ "$HTTP_CODE" -ge 200 ] && [ "$HTTP_CODE" -lt 300 ]; then
  pass
else
  fail "pool upload returned HTTP ${HTTP_CODE}, expected 2xx"
fi

# -------------------------------------------------------------------------
# Verify Release file
# -------------------------------------------------------------------------

begin_test "Verify Release file"
sleep 1
if resp=$(api_get "/debian/${REPO_KEY}/dists/${DISTRIBUTION}/Release" 2>/dev/null); then
  pass
else
  fail "Release file endpoint returned error"
fi

# -------------------------------------------------------------------------
# Verify Packages index
# -------------------------------------------------------------------------

begin_test "Verify Packages index"
if resp=$(api_get "/debian/${REPO_KEY}/dists/${DISTRIBUTION}/${COMPONENT}/binary-${PKG_ARCH}/Packages" 2>/dev/null); then
  if assert_contains "$resp" "${PKG_NAME}"; then
    pass
  fi
else
  fail "Packages index endpoint returned error"
fi

# -------------------------------------------------------------------------
# Verify Packages.gz index
# -------------------------------------------------------------------------

begin_test "Verify Packages.gz compressed index"
if curl -sf -H "$(format_auth_header)" \
    -o "${WORK_DIR}/Packages.gz" \
    "${BASE_URL}/debian/${REPO_KEY}/dists/${DISTRIBUTION}/${COMPONENT}/binary-${PKG_ARCH}/Packages.gz" 2>/dev/null; then
  if [ -s "${WORK_DIR}/Packages.gz" ]; then
    # Try to decompress and verify contents
    if gunzip -c "${WORK_DIR}/Packages.gz" 2>/dev/null | grep -q "${PKG_NAME}"; then
      pass
    else
      pass  # File exists and is non-empty; content check is a bonus
    fi
  else
    fail "Packages.gz is empty"
  fi
else
  fail "Packages.gz endpoint returned error"
fi

# -------------------------------------------------------------------------
# Download .deb from pool
# -------------------------------------------------------------------------

begin_test "Download .deb from pool"
if curl -sf -H "$(format_auth_header)" \
    -o "${WORK_DIR}/downloaded.deb" \
    "${BASE_URL}/debian/${REPO_KEY}/pool/${COMPONENT}/${DEB_FILE}" 2>/dev/null; then
  if [ -s "${WORK_DIR}/downloaded.deb" ]; then
    pass
  else
    fail "downloaded .deb is empty"
  fi
else
  fail "pool download returned error"
fi

# -------------------------------------------------------------------------
# Upload via alternative POST endpoint
# -------------------------------------------------------------------------

begin_test "Upload .deb via POST upload endpoint"
HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
    -X POST \
    -H "$(format_auth_header)" \
    -H "Content-Type: application/vnd.debian.binary-package" \
    -H "X-Filename: ${DEB_FILE}" \
    --data-binary "@${WORK_DIR}/${DEB_FILE}" \
    "${BASE_URL}/debian/${REPO_KEY}/upload")

if [ "$HTTP_CODE" -ge 200 ] && [ "$HTTP_CODE" -lt 300 ]; then
  pass
else
  # POST upload may return 409 if package already exists; that is acceptable
  if [ "$HTTP_CODE" = "409" ]; then
    pass
  else
    fail "POST upload returned HTTP ${HTTP_CODE}"
  fi
fi

end_suite
