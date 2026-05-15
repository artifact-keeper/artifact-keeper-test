#!/usr/bin/env bash
# test-rpm-conformance.sh - RPM/YUM repository conformance tests
#
# Validates that the RPM repository implementation produces correct
# repomd.xml, primary/filelists/other metadata, checksums, and
# handles updates and signing properly.
#
# Requires: curl, gzip, sha256sum or shasum
source "$(dirname "$0")/../lib/common.sh"

begin_suite "rpm-conformance"
auth_admin
setup_workdir

REPO_KEY="test-rpm-conf-${RUN_ID}"

# Portable SHA256 helper
sha256_hex() {
  if command -v sha256sum &>/dev/null; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

# -------------------------------------------------------------------------
# Helper: build a minimal .rpm binary blob
#
# If rpmbuild is available, produce a real RPM. Otherwise create a file
# with the correct RPM magic bytes (0xedabeedb) followed by enough
# structure for the server to accept it.
# -------------------------------------------------------------------------
build_rpm() {
  local name="$1"
  local version="$2"
  local release="$3"
  local arch="$4"
  local outfile="$5"

  if command -v rpmbuild &>/dev/null; then
    local topdir="${WORK_DIR}/rpmbuild-${name}-${version}"
    mkdir -p "${topdir}"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
    cat > "${topdir}/SPECS/${name}.spec" <<SPEC
Name:    ${name}
Version: ${version}
Release: ${release}
Summary: Conformance test RPM
License: MIT
BuildArch: ${arch}

%description
Conformance test package for artifact-keeper.

%install
mkdir -p %{buildroot}/usr/bin
echo '#!/bin/sh' > %{buildroot}/usr/bin/${name}
echo 'echo hello' >> %{buildroot}/usr/bin/${name}
chmod 755 %{buildroot}/usr/bin/${name}

%files
/usr/bin/${name}
SPEC
    rpmbuild --define "_topdir ${topdir}" -bb "${topdir}/SPECS/${name}.spec" 2>/dev/null
    local built
    built=$(find "${topdir}/RPMS" -name "*.rpm" -type f | head -1)
    if [ -n "$built" ]; then
      cp "$built" "$outfile"
      return 0
    fi
  fi

  # Fallback: RPM lead (96 bytes) with correct magic, then a small payload.
  printf '\xed\xab\xee\xdb' > "$outfile"
  # Pad the rest of the 96-byte lead
  dd if=/dev/zero bs=1 count=92 2>/dev/null >> "$outfile"
  # Add identifiable payload
  echo "${name}-${version}-${release}.${arch}" >> "$outfile"
}

# -------------------------------------------------------------------------
# Create repository
# -------------------------------------------------------------------------

begin_test "Create RPM repository"
if create_local_repo "$REPO_KEY" "rpm"; then
  pass
else
  fail "could not create rpm repo"
fi

# -------------------------------------------------------------------------
# 1. Upload .rpm package
# -------------------------------------------------------------------------

RPM_V1="${WORK_DIR}/conftest-1.0.0-1.x86_64.rpm"
build_rpm "conftest" "1.0.0" "1" "x86_64" "$RPM_V1"

begin_test "Upload .rpm package"
HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
    -X PUT \
    -H "$(format_auth_header)" \
    -H "Content-Type: application/x-rpm" \
    --data-binary "@${RPM_V1}" \
    "${BASE_URL}/rpm/${REPO_KEY}/packages/conftest-1.0.0-1.x86_64.rpm")

if [ "$HTTP_CODE" -ge 200 ] && [ "$HTTP_CODE" -lt 300 ]; then
  pass
else
  fail "upload returned HTTP ${HTTP_CODE}, expected 2xx"
fi

sleep 1

# -------------------------------------------------------------------------
# 2. GET repomd.xml returns valid XML with data entries
# -------------------------------------------------------------------------

begin_test "repomd.xml is valid XML with data entries"
REPOMD=""
if REPOMD=$(curl -sf -H "$(format_auth_header)" \
    "${BASE_URL}/rpm/${REPO_KEY}/repodata/repomd.xml" 2>/dev/null); then
  if echo "$REPOMD" | grep -q "<repomd"; then
    if echo "$REPOMD" | grep -q "<data"; then
      pass
    else
      fail "repomd.xml has no <data> entries"
    fi
  else
    fail "response does not look like valid repomd XML"
  fi
else
  fail "GET repomd.xml returned error"
fi

# -------------------------------------------------------------------------
# 3. repomd.xml lists primary, filelists, other metadata files
# -------------------------------------------------------------------------

begin_test "repomd.xml lists primary, filelists, and other"
missing=""
for dtype in "primary" "filelists" "other"; do
  if ! echo "$REPOMD" | grep -q "\"${dtype}\""; then
    missing="${missing} ${dtype}"
  fi
done

if [ -z "$missing" ]; then
  pass
else
  fail "repomd.xml missing data types:${missing}"
fi

# -------------------------------------------------------------------------
# 4. GET primary.xml.gz contains package metadata
# -------------------------------------------------------------------------

begin_test "primary.xml.gz contains package metadata"
if curl -sf -H "$(format_auth_header)" \
    -o "${WORK_DIR}/primary.xml.gz" \
    "${BASE_URL}/rpm/${REPO_KEY}/repodata/primary.xml.gz" 2>/dev/null; then
  PRIMARY_XML=$(gunzip -c "${WORK_DIR}/primary.xml.gz" 2>/dev/null) || true
  if [ -z "$PRIMARY_XML" ]; then
    fail "primary.xml.gz did not decompress"
  else
    missing=""
    for field in "name" "version" "arch" "checksum"; do
      if ! echo "$PRIMARY_XML" | grep -qi "$field"; then
        missing="${missing} ${field}"
      fi
    done
    if [ -z "$missing" ]; then
      pass
    else
      fail "primary.xml missing expected fields:${missing}"
    fi
  fi
else
  fail "GET primary.xml.gz returned error"
fi

# -------------------------------------------------------------------------
# 5. Downloaded .rpm matches checksum in primary.xml
# -------------------------------------------------------------------------

begin_test "Downloaded .rpm checksum matches primary.xml"
if curl -sf -H "$(format_auth_header)" \
    -o "${WORK_DIR}/downloaded.rpm" \
    "${BASE_URL}/rpm/${REPO_KEY}/packages/conftest-1.0.0-1.x86_64.rpm" 2>/dev/null; then

  ACTUAL_SHA=$(sha256_hex "${WORK_DIR}/downloaded.rpm")

  # Extract checksum from primary.xml (look for sha256 checksum near the package entry)
  EXPECTED_SHA=""
  if [ -n "$PRIMARY_XML" ]; then
    # The checksum element in primary.xml looks like:
    # <checksum type="sha256">abcdef...</checksum>
    EXPECTED_SHA=$(echo "$PRIMARY_XML" | grep -o '<checksum[^>]*type="sha256"[^>]*>[a-f0-9]\{64\}</checksum>' | head -1 | grep -o '[a-f0-9]\{64\}')
  fi

  if [ -n "$EXPECTED_SHA" ]; then
    if assert_eq "$ACTUAL_SHA" "$EXPECTED_SHA" "RPM checksum mismatch: got ${ACTUAL_SHA}, expected ${EXPECTED_SHA}"; then
      pass
    fi
  else
    # If we cannot extract the checksum from primary.xml, verify the download is non-empty
    if [ -s "${WORK_DIR}/downloaded.rpm" ]; then
      skip "could not extract checksum from primary.xml to verify, but download succeeded"
    else
      fail "downloaded RPM is empty and checksum unavailable"
    fi
  fi
else
  fail "download of uploaded RPM returned error"
fi

# -------------------------------------------------------------------------
# 6. Multiple packages listed correctly
# -------------------------------------------------------------------------

RPM_V2="${WORK_DIR}/conftest2-2.0.0-1.x86_64.rpm"
build_rpm "conftest2" "2.0.0" "1" "x86_64" "$RPM_V2"

begin_test "Multiple packages in primary.xml"
UPLOAD2_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
    -X PUT \
    -H "$(format_auth_header)" \
    -H "Content-Type: application/x-rpm" \
    --data-binary "@${RPM_V2}" \
    "${BASE_URL}/rpm/${REPO_KEY}/packages/conftest2-2.0.0-1.x86_64.rpm")

if [ "$UPLOAD2_CODE" -lt 200 ] || [ "$UPLOAD2_CODE" -ge 300 ]; then
  fail "second RPM upload returned HTTP ${UPLOAD2_CODE}"
else
  sleep 1
  if curl -sf -H "$(format_auth_header)" \
      -o "${WORK_DIR}/primary2.xml.gz" \
      "${BASE_URL}/rpm/${REPO_KEY}/repodata/primary.xml.gz" 2>/dev/null; then
    PRIMARY2=$(gunzip -c "${WORK_DIR}/primary2.xml.gz" 2>/dev/null) || true
    # Count <package> elements or look for both package names
    has_first=false
    has_second=false
    if echo "$PRIMARY2" | grep -qi "conftest"; then
      has_first=true
    fi
    if echo "$PRIMARY2" | grep -qi "conftest2"; then
      has_second=true
    fi
    if $has_first && $has_second; then
      pass
    else
      fail "primary.xml does not list both packages (conftest: ${has_first}, conftest2: ${has_second})"
    fi
  else
    fail "could not fetch primary.xml.gz after second upload"
  fi
fi

# -------------------------------------------------------------------------
# 7. repomd.xml has correct Content-Type (application/xml)
# -------------------------------------------------------------------------

begin_test "repomd.xml Content-Type is application/xml"
HEADERS=$(curl -sf -D - -o /dev/null \
    -H "$(format_auth_header)" \
    "${BASE_URL}/rpm/${REPO_KEY}/repodata/repomd.xml" 2>/dev/null) || true

CT=$(echo "$HEADERS" | grep -i "^content-type:" | tr -d '\r' | head -1)
if echo "$CT" | grep -qi "application/xml"; then
  pass
elif echo "$CT" | grep -qi "text/xml"; then
  pass
else
  fail "expected Content-Type application/xml or text/xml, got: ${CT}"
fi

# -------------------------------------------------------------------------
# 8. GPG signing: repomd.xml.asc exists (if signing enabled)
# -------------------------------------------------------------------------

begin_test "repomd.xml.asc available if signing enabled"
ASC_STATUS=$(curl -s -o "${WORK_DIR}/repomd.xml.asc" -w '%{http_code}' \
    -H "$(format_auth_header)" \
    "${BASE_URL}/rpm/${REPO_KEY}/repodata/repomd.xml.asc") || true

if [ "$ASC_STATUS" -ge 200 ] && [ "$ASC_STATUS" -lt 300 ]; then
  ASC_BODY=$(cat "${WORK_DIR}/repomd.xml.asc")
  if echo "$ASC_BODY" | grep -q "BEGIN PGP"; then
    pass
  elif [ -s "${WORK_DIR}/repomd.xml.asc" ]; then
    # File exists and is non-empty; signature format may differ
    pass
  else
    fail "repomd.xml.asc is empty"
  fi
else
  skip "repomd.xml.asc not available (HTTP ${ASC_STATUS}), signing may not be enabled"
fi

# -------------------------------------------------------------------------
# 9. Update: uploading new version updates repodata automatically
# -------------------------------------------------------------------------

RPM_V1B="${WORK_DIR}/conftest-2.0.0-1.x86_64.rpm"
build_rpm "conftest" "2.0.0" "1" "x86_64" "$RPM_V1B"

begin_test "Uploading new version updates repodata"
# Capture current repomd.xml before uploading the new version
REPOMD_BEFORE=$(curl -sf -H "$(format_auth_header)" \
    "${BASE_URL}/rpm/${REPO_KEY}/repodata/repomd.xml" 2>/dev/null) || true

UPLOAD3_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
    -X PUT \
    -H "$(format_auth_header)" \
    -H "Content-Type: application/x-rpm" \
    --data-binary "@${RPM_V1B}" \
    "${BASE_URL}/rpm/${REPO_KEY}/packages/conftest-2.0.0-1.x86_64.rpm")

if [ "$UPLOAD3_CODE" -lt 200 ] || [ "$UPLOAD3_CODE" -ge 300 ]; then
  fail "new version upload returned HTTP ${UPLOAD3_CODE}"
else
  sleep 1
  # Fetch primary.xml.gz and look for the new version
  if curl -sf -H "$(format_auth_header)" \
      -o "${WORK_DIR}/primary3.xml.gz" \
      "${BASE_URL}/rpm/${REPO_KEY}/repodata/primary.xml.gz" 2>/dev/null; then
    PRIMARY3=$(gunzip -c "${WORK_DIR}/primary3.xml.gz" 2>/dev/null) || true
    if echo "$PRIMARY3" | grep -q "2.0.0"; then
      pass
    else
      fail "primary.xml does not contain updated version 2.0.0"
    fi
  else
    fail "could not fetch primary.xml.gz after update"
  fi
fi

# -------------------------------------------------------------------------
# 10. 404 for nonexistent package download
# -------------------------------------------------------------------------

begin_test "404 for nonexistent package"
NOTFOUND_STATUS=$(curl -s -o /dev/null -w '%{http_code}' \
    -H "$(format_auth_header)" \
    "${BASE_URL}/rpm/${REPO_KEY}/packages/nonexistent-99.99.99-1.x86_64.rpm") || true

if [ "$NOTFOUND_STATUS" = "404" ]; then
  pass
else
  fail "expected 404 for nonexistent package, got ${NOTFOUND_STATUS}"
fi

end_suite
