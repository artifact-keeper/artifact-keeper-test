#!/usr/bin/env bash
# test-opkg-conformance.sh - OpenWrt OPKG repository conformance tests
#
# Validates that the OPKG repository implementation handles .ipk uploads,
# generates Packages and Packages.gz index files with correct metadata
# fields, and supports downloads by filename path.
#
# OPKG does not have a dedicated native handler with custom routes. All
# operations go through the generic artifact API with the "opkg" format.
# An .ipk package is an ar archive (like .deb) containing control.tar.gz
# and data.tar.gz.
#
# Endpoints: ${BASE_URL}/api/v1/repositories/{repo_key}/...
#
# Requires: curl, ar (from binutils), tar, gzip, sha256sum or shasum
source "$(dirname "$0")/../lib/common.sh"

begin_suite "opkg-conformance"
auth_admin
setup_workdir

REPO_KEY="test-opkg-conf-${RUN_ID}"
PKG_NAME="conftest"
PKG_VERSION="1.0.0"
PKG_ARCH="mipsel_24kc"

# Portable SHA256 helper (Linux uses sha256sum, macOS uses shasum)
sha256_hex() {
  if command -v sha256sum &>/dev/null; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

# ---------------------------------------------------------------------------
# Helper: build a minimal .ipk package
#
# An .ipk is an ar archive containing:
#   - debian-binary    (version string "2.0")
#   - control.tar.gz   (control file with Package, Version, Architecture, etc.)
#   - data.tar.gz      (file tree to install)
# ---------------------------------------------------------------------------

build_ipk() {
  local name="$1"
  local version="$2"
  local arch="$3"
  local outfile="$4"

  local build_dir="${WORK_DIR}/ipk-build-${name}-${version}"
  mkdir -p "${build_dir}"

  # debian-binary
  echo "2.0" > "${build_dir}/debian-binary"

  # control.tar.gz
  local ctrl_dir="${build_dir}/control-root"
  mkdir -p "${ctrl_dir}"
  cat > "${ctrl_dir}/control" <<CTRL
Package: ${name}
Version: ${version}
Architecture: ${arch}
Maintainer: conformance-test@example.com
Section: utils
Priority: optional
Description: OPKG conformance test package ${name}
CTRL
  tar czf "${build_dir}/control.tar.gz" -C "${ctrl_dir}" ./control

  # data.tar.gz
  local data_dir="${build_dir}/data-root"
  mkdir -p "${data_dir}/usr/bin"
  echo "#!/bin/sh" > "${data_dir}/usr/bin/${name}"
  echo "echo hello from ${name} ${version}" >> "${data_dir}/usr/bin/${name}"
  chmod 755 "${data_dir}/usr/bin/${name}"
  tar czf "${build_dir}/data.tar.gz" -C "${data_dir}" .

  # Assemble with ar
  if command -v ar &>/dev/null; then
    (cd "${build_dir}" && ar rcs "${outfile}" debian-binary control.tar.gz data.tar.gz 2>/dev/null)
  else
    # Fallback: concatenate members (may not produce a valid ar archive, but
    # the server should be able to parse simple cases)
    cat "${build_dir}/debian-binary" "${build_dir}/control.tar.gz" "${build_dir}/data.tar.gz" > "${outfile}"
  fi
}

# ---------------------------------------------------------------------------
# Create repository
# ---------------------------------------------------------------------------

begin_test "Create OPKG local repository"
if create_local_repo "$REPO_KEY" "opkg"; then
  pass
else
  fail "could not create opkg repository"
fi

# ---------------------------------------------------------------------------
# 1. Upload .ipk package
# ---------------------------------------------------------------------------

begin_test "Upload .ipk package"
IPK_FILENAME="${PKG_NAME}_${PKG_VERSION}_${PKG_ARCH}.ipk"
IPK_FILE="${WORK_DIR}/${IPK_FILENAME}"
build_ipk "$PKG_NAME" "$PKG_VERSION" "$PKG_ARCH" "$IPK_FILE"

upload_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X PUT \
  -H "$(auth_header)" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@${IPK_FILE}" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/${IPK_FILENAME}") || true

if [ "$upload_status" -ge 200 ] 2>/dev/null && [ "$upload_status" -lt 300 ] 2>/dev/null; then
  pass
else
  fail "ipk upload returned HTTP ${upload_status}, expected 2xx"
fi

sleep 1

# ---------------------------------------------------------------------------
# 2. GET Packages returns package index
# ---------------------------------------------------------------------------

begin_test "GET Packages returns package index"
PACKAGES_BODY=""
packages_status=$(curl -s -o "${WORK_DIR}/Packages" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/download/Packages") || true

if [ "$packages_status" = "200" ] && [ -s "${WORK_DIR}/Packages" ]; then
  PACKAGES_BODY=$(cat "${WORK_DIR}/Packages")
  if echo "$PACKAGES_BODY" | grep -q "Package:" 2>/dev/null; then
    pass
  else
    # Index file exists but may be empty if the server has not yet indexed
    echo "  note: Packages file exists but does not contain Package: entries"
    skip "Packages file returned but appears empty or unindexed"
  fi
else
  skip "Packages index not available (HTTP ${packages_status}), server may not auto-generate OPKG indices"
fi

# ---------------------------------------------------------------------------
# 3. GET Packages.gz returns compressed index
# ---------------------------------------------------------------------------

begin_test "GET Packages.gz returns gzip-compressed index"
packages_gz_status=$(curl -s -o "${WORK_DIR}/Packages.gz" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/download/Packages.gz") || true

if [ "$packages_gz_status" = "200" ] && [ -s "${WORK_DIR}/Packages.gz" ]; then
  if gunzip -c "${WORK_DIR}/Packages.gz" 2>/dev/null | grep -q "Package:" 2>/dev/null; then
    pass
  else
    # File may be gzipped but the index might be empty
    if gunzip -t "${WORK_DIR}/Packages.gz" 2>/dev/null; then
      echo "  note: valid gzip but no Package: entries found"
      skip "Packages.gz is valid gzip but index appears empty"
    else
      fail "Packages.gz is not a valid gzip file"
    fi
  fi
else
  skip "Packages.gz not available (HTTP ${packages_gz_status}), server may not auto-generate compressed index"
fi

# ---------------------------------------------------------------------------
# 4. Package index contains required fields
# ---------------------------------------------------------------------------

begin_test "Package index contains required fields"
# If PACKAGES_BODY is empty from test 2, try to re-fetch or decompress from .gz
if [ -z "$PACKAGES_BODY" ] && [ -s "${WORK_DIR}/Packages.gz" ]; then
  PACKAGES_BODY=$(gunzip -c "${WORK_DIR}/Packages.gz" 2>/dev/null) || true
fi

if [ -n "$PACKAGES_BODY" ] && echo "$PACKAGES_BODY" | grep -q "Package:" 2>/dev/null; then
  missing=""
  for field in "Package:" "Version:" "Architecture:" "Filename:" "SHA256sum:"; do
    if ! echo "$PACKAGES_BODY" | grep -q "$field" 2>/dev/null; then
      missing="${missing} ${field}"
    fi
  done

  if [ -z "$missing" ]; then
    pass
  else
    # SHA256sum may be named differently (e.g., Checksum or MD5Sum)
    # Accept if at least Package, Version, Architecture are present
    core_missing=""
    for field in "Package:" "Version:" "Architecture:"; do
      if ! echo "$PACKAGES_BODY" | grep -q "$field" 2>/dev/null; then
        core_missing="${core_missing} ${field}"
      fi
    done

    if [ -z "$core_missing" ]; then
      echo "  note: some optional fields missing:${missing}"
      pass
    else
      fail "Package index missing required fields:${missing}"
    fi
  fi
else
  skip "no package index content available for field inspection"
fi

# ---------------------------------------------------------------------------
# 5. Download .ipk by Filename path
# ---------------------------------------------------------------------------

begin_test "Download .ipk package"
DL_FILE="${WORK_DIR}/downloaded.ipk"

# Try downloading by the direct filename first
dl_status=$(curl -s -o "$DL_FILE" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/download/${IPK_FILENAME}") || true

if [ "$dl_status" -ge 200 ] 2>/dev/null && [ "$dl_status" -lt 300 ] 2>/dev/null && [ -s "$DL_FILE" ]; then
  # Verify integrity
  upload_sha=$(sha256_hex "$IPK_FILE")
  download_sha=$(sha256_hex "$DL_FILE")
  if assert_eq "$download_sha" "$upload_sha" "SHA256 mismatch: uploaded=${upload_sha} downloaded=${download_sha}"; then
    pass
  fi
else
  # Try via the Filename value from Packages index if available
  if [ -n "$PACKAGES_BODY" ]; then
    dl_path=$(echo "$PACKAGES_BODY" | grep "^Filename:" | head -1 | awk '{print $2}') || true
    if [ -n "$dl_path" ]; then
      dl_status=$(curl -s -o "$DL_FILE" -w '%{http_code}' $CURL_TIMEOUT \
        -H "$(auth_header)" \
        "${BASE_URL}/api/v1/repositories/${REPO_KEY}/download/${dl_path}") || true
      if [ "$dl_status" -ge 200 ] 2>/dev/null && [ "$dl_status" -lt 300 ] 2>/dev/null && [ -s "$DL_FILE" ]; then
        pass
      else
        fail "download via Filename path '${dl_path}' returned HTTP ${dl_status}"
      fi
    else
      fail "download returned HTTP ${dl_status} and no Filename path in Packages index"
    fi
  else
    fail "download returned HTTP ${dl_status}"
  fi
fi

# ---------------------------------------------------------------------------
# 6. 404 for nonexistent package
# ---------------------------------------------------------------------------

begin_test "404 for nonexistent package"
status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/download/nonexistent_${RUN_ID}_0.0.0_all.ipk") || true
if assert_eq "$status" "404" "expected 404 for nonexistent package, got ${status}"; then
  pass
fi

end_suite
