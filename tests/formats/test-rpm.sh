#!/usr/bin/env bash
# test-rpm.sh - RPM/YUM repository E2E test
#
# Requires: curl
# Tests: create local repo, upload .rpm package, verify repodata and download
source "$(dirname "$0")/../lib/common.sh"

begin_suite "rpm"
auth_admin
setup_workdir

REPO_KEY="test-rpm-${RUN_ID}"
PKG_NAME="testpkg"
PKG_VERSION="1.0.0"
RPM_FILE="${PKG_NAME}-${PKG_VERSION}-1.x86_64.rpm"

# -------------------------------------------------------------------------
# Create repository
# -------------------------------------------------------------------------

begin_test "Create rpm repository"
if create_local_repo "$REPO_KEY" "rpm"; then
  pass
else
  fail "could not create rpm repo"
fi

# -------------------------------------------------------------------------
# Build a minimal .rpm package (or binary blob)
# -------------------------------------------------------------------------

begin_test "Create minimal .rpm package"
if command -v rpmbuild &>/dev/null; then
  # Build a real RPM if rpmbuild is available
  RPM_TOPDIR="${WORK_DIR}/rpmbuild"
  mkdir -p "${RPM_TOPDIR}"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

  cat > "${RPM_TOPDIR}/SPECS/${PKG_NAME}.spec" <<EOF
Name:    ${PKG_NAME}
Version: ${PKG_VERSION}
Release: 1
Summary: E2E test RPM package
License: MIT
BuildArch: x86_64

%description
Test package for artifact-keeper RPM registry.

%install
mkdir -p %{buildroot}/usr/bin
echo '#!/bin/sh' > %{buildroot}/usr/bin/${PKG_NAME}
echo 'echo hello from ${PKG_NAME}' >> %{buildroot}/usr/bin/${PKG_NAME}
chmod 755 %{buildroot}/usr/bin/${PKG_NAME}

%files
/usr/bin/${PKG_NAME}
EOF

  rpmbuild --define "_topdir ${RPM_TOPDIR}" -bb "${RPM_TOPDIR}/SPECS/${PKG_NAME}.spec" 2>/dev/null
  RPM_PATH=$(find "${RPM_TOPDIR}/RPMS" -name "*.rpm" -type f | head -1)
  if [ -n "$RPM_PATH" ]; then
    cp "$RPM_PATH" "${WORK_DIR}/${RPM_FILE}"
  fi
else
  # Create a minimal binary blob with the RPM magic number.
  # The RPM lead is: 4-byte magic (0xed 0xab 0xee 0xdb) + header.
  # This is enough for the registry to accept it as an RPM upload.
  printf '\xed\xab\xee\xdb' > "${WORK_DIR}/${RPM_FILE}"
  # Add some padding to make it look like a real RPM (96-byte lead)
  dd if=/dev/zero bs=1 count=92 2>/dev/null >> "${WORK_DIR}/${RPM_FILE}"
  # Append a small payload so the file is not trivially empty
  echo "${PKG_NAME}-${PKG_VERSION}" >> "${WORK_DIR}/${RPM_FILE}"
fi

if [ -s "${WORK_DIR}/${RPM_FILE}" ]; then
  pass
else
  fail "failed to create .rpm package"
fi

# -------------------------------------------------------------------------
# Upload .rpm via PUT
# -------------------------------------------------------------------------

begin_test "Upload .rpm via packages endpoint"
HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
    -X PUT \
    -H "$(auth_header)" \
    -H "Content-Type: application/x-rpm" \
    --data-binary "@${WORK_DIR}/${RPM_FILE}" \
    "${BASE_URL}/rpm/${REPO_KEY}/packages/${RPM_FILE}")

if [ "$HTTP_CODE" -ge 200 ] && [ "$HTTP_CODE" -lt 300 ]; then
  pass
else
  fail "packages upload returned HTTP ${HTTP_CODE}, expected 2xx"
fi

# -------------------------------------------------------------------------
# Verify repomd.xml
# -------------------------------------------------------------------------

begin_test "Verify repomd.xml"
sleep 1
if resp=$(api_get "/rpm/${REPO_KEY}/repodata/repomd.xml" 2>/dev/null); then
  if assert_contains "$resp" "repomd"; then
    pass
  fi
else
  fail "repomd.xml endpoint returned error"
fi

# -------------------------------------------------------------------------
# Verify primary.xml.gz
# -------------------------------------------------------------------------

begin_test "Verify primary.xml.gz"
if curl -sf -H "$(auth_header)" \
    -o "${WORK_DIR}/primary.xml.gz" \
    "${BASE_URL}/rpm/${REPO_KEY}/repodata/primary.xml.gz" 2>/dev/null; then
  if [ -s "${WORK_DIR}/primary.xml.gz" ]; then
    pass
  else
    fail "primary.xml.gz is empty"
  fi
else
  fail "primary.xml.gz endpoint returned error"
fi

# -------------------------------------------------------------------------
# Download .rpm from packages
# -------------------------------------------------------------------------

begin_test "Download .rpm from packages endpoint"
if curl -sf -H "$(auth_header)" \
    -o "${WORK_DIR}/downloaded.rpm" \
    "${BASE_URL}/rpm/${REPO_KEY}/packages/${RPM_FILE}" 2>/dev/null; then
  if [ -s "${WORK_DIR}/downloaded.rpm" ]; then
    pass
  else
    fail "downloaded .rpm is empty"
  fi
else
  fail "package download returned error"
fi

# -------------------------------------------------------------------------
# Verify filelists.xml.gz and other.xml.gz
# -------------------------------------------------------------------------

begin_test "Verify filelists.xml.gz"
if curl -sf -H "$(auth_header)" \
    -o "${WORK_DIR}/filelists.xml.gz" \
    "${BASE_URL}/rpm/${REPO_KEY}/repodata/filelists.xml.gz" 2>/dev/null; then
  if [ -s "${WORK_DIR}/filelists.xml.gz" ]; then
    pass
  else
    fail "filelists.xml.gz is empty"
  fi
else
  fail "filelists.xml.gz endpoint returned error"
fi

begin_test "Verify other.xml.gz"
if curl -sf -H "$(auth_header)" \
    -o "${WORK_DIR}/other.xml.gz" \
    "${BASE_URL}/rpm/${REPO_KEY}/repodata/other.xml.gz" 2>/dev/null; then
  if [ -s "${WORK_DIR}/other.xml.gz" ]; then
    pass
  else
    fail "other.xml.gz is empty"
  fi
else
  fail "other.xml.gz endpoint returned error"
fi

# -------------------------------------------------------------------------
# Upload via alternative POST endpoint
# -------------------------------------------------------------------------

begin_test "Upload .rpm via POST upload endpoint"
HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
    -X POST \
    -H "$(auth_header)" \
    -H "Content-Type: application/x-rpm" \
    --data-binary "@${WORK_DIR}/${RPM_FILE}" \
    "${BASE_URL}/rpm/${REPO_KEY}/upload")

if [ "$HTTP_CODE" -ge 200 ] && [ "$HTTP_CODE" -lt 300 ]; then
  pass
else
  if [ "$HTTP_CODE" = "409" ]; then
    pass  # already exists is acceptable
  else
    fail "POST upload returned HTTP ${HTTP_CODE}"
  fi
fi

end_suite
