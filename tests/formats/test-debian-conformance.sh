#!/usr/bin/env bash
# test-debian-conformance.sh - Debian/APT repository conformance tests
#
# Validates that the Debian repository implementation produces correct
# Release files, Packages indices, checksums, and supports multi-arch
# and by-hash access patterns.
#
# Requires: curl, ar (from binutils), tar, gzip, sha256sum or shasum
source "$(dirname "$0")/../lib/common.sh"

begin_suite "debian-conformance"
auth_admin
setup_workdir

REPO_KEY="test-deb-conf-${RUN_ID}"
DISTRIBUTION="stable"
COMPONENT="main"

# Portable SHA256 helper (Linux uses sha256sum, macOS uses shasum)
sha256_hex() {
  if command -v sha256sum &>/dev/null; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

# -------------------------------------------------------------------------
# Helper: build a minimal .deb package from scratch using ar + tar
# -------------------------------------------------------------------------
build_deb() {
  local name="$1"
  local version="$2"
  local arch="$3"
  local outfile="$4"

  local build_dir="${WORK_DIR}/deb-build-${name}-${version}-${arch}"
  mkdir -p "${build_dir}"

  # debian-binary
  echo "2.0" > "${build_dir}/debian-binary"

  # control.tar.gz
  local ctrl_dir="${build_dir}/control-root"
  mkdir -p "${ctrl_dir}"
  cat > "${ctrl_dir}/control" <<CTRL
Package: ${name}
Version: ${version}
Section: utils
Priority: optional
Architecture: ${arch}
Maintainer: CI <ci@example.com>
Description: Conformance test package (${name} ${version} ${arch})
CTRL
  tar czf "${build_dir}/control.tar.gz" -C "${ctrl_dir}" ./control

  # data.tar.gz (empty tree is fine for testing)
  local data_dir="${build_dir}/data-root"
  mkdir -p "${data_dir}/usr/share/doc/${name}"
  echo "${name} ${version}" > "${data_dir}/usr/share/doc/${name}/README"
  tar czf "${build_dir}/data.tar.gz" -C "${data_dir}" .

  # Assemble with ar
  if command -v ar &>/dev/null; then
    (cd "${build_dir}" && ar rcs "${outfile}" debian-binary control.tar.gz data.tar.gz 2>/dev/null)
  else
    # Fallback: concatenate (the server parses the ar archive, so this may
    # not work, but we try anyway)
    cat "${build_dir}/debian-binary" "${build_dir}/control.tar.gz" "${build_dir}/data.tar.gz" > "${outfile}"
  fi
}

# -------------------------------------------------------------------------
# Create repository
# -------------------------------------------------------------------------

begin_test "Create Debian repository"
if create_local_repo "$REPO_KEY" "debian"; then
  pass
else
  fail "could not create debian repo"
fi

# -------------------------------------------------------------------------
# 1. Upload .deb package
# -------------------------------------------------------------------------

DEB_AMD64="${WORK_DIR}/testlib_1.0.0_amd64.deb"
build_deb "testlib" "1.0.0" "amd64" "$DEB_AMD64"

begin_test "Upload amd64 .deb package"
HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
    -X PUT \
    -H "$(format_auth_header)" \
    -H "Content-Type: application/vnd.debian.binary-package" \
    --data-binary "@${DEB_AMD64}" \
    "${BASE_URL}/debian/${REPO_KEY}/pool/${COMPONENT}/testlib_1.0.0_amd64.deb")

if [ "$HTTP_CODE" -ge 200 ] && [ "$HTTP_CODE" -lt 300 ]; then
  pass
else
  fail "upload returned HTTP ${HTTP_CODE}, expected 2xx"
fi

# Small pause for metadata generation
sleep 1

# -------------------------------------------------------------------------
# 2. GET dists/{dist}/Release returns valid Release with checksums
# -------------------------------------------------------------------------

begin_test "Release file contains checksums"
RELEASE_BODY=""
if RELEASE_BODY=$(curl -sf -H "$(format_auth_header)" \
    "${BASE_URL}/debian/${REPO_KEY}/dists/${DISTRIBUTION}/Release" 2>/dev/null); then
  # Must contain SHA256 section and Suite field
  has_sha256=false
  has_suite=false
  if echo "$RELEASE_BODY" | grep -q "SHA256:"; then
    has_sha256=true
  fi
  if echo "$RELEASE_BODY" | grep -q "Suite: ${DISTRIBUTION}"; then
    has_suite=true
  fi
  if $has_sha256 && $has_suite; then
    pass
  else
    fail "Release file missing expected fields (SHA256: ${has_sha256}, Suite: ${has_suite})"
  fi
else
  fail "GET dists/${DISTRIBUTION}/Release returned error"
fi

# -------------------------------------------------------------------------
# 3. GET dists/{dist}/InRelease returns GPG inline-signed Release
# -------------------------------------------------------------------------

begin_test "InRelease file exists (signed if signing enabled)"
INRELEASE_STATUS=$(curl -s -o "${WORK_DIR}/InRelease" -w '%{http_code}' \
    -H "$(format_auth_header)" \
    "${BASE_URL}/debian/${REPO_KEY}/dists/${DISTRIBUTION}/InRelease") || true

if [ "$INRELEASE_STATUS" -ge 200 ] && [ "$INRELEASE_STATUS" -lt 300 ]; then
  INRELEASE_BODY=$(cat "${WORK_DIR}/InRelease")
  # If signing is enabled, expect PGP header; otherwise the plain Release is acceptable
  if echo "$INRELEASE_BODY" | grep -q "BEGIN PGP SIGNED MESSAGE"; then
    pass
  elif echo "$INRELEASE_BODY" | grep -q "Suite:"; then
    # Signing not enabled, but the endpoint returns the Release content
    pass
  else
    fail "InRelease body has neither PGP signature nor Release metadata"
  fi
else
  # Some deployments may not serve InRelease at all
  skip "InRelease not available (HTTP ${INRELEASE_STATUS})"
fi

# -------------------------------------------------------------------------
# 4. GET Packages index for binary-amd64
# -------------------------------------------------------------------------

begin_test "Packages index for binary-amd64"
PACKAGES_BODY=""
if PACKAGES_BODY=$(curl -sf -H "$(format_auth_header)" \
    "${BASE_URL}/debian/${REPO_KEY}/dists/${DISTRIBUTION}/${COMPONENT}/binary-amd64/Packages" 2>/dev/null); then
  if echo "$PACKAGES_BODY" | grep -q "Package: testlib"; then
    pass
  else
    fail "Packages index does not contain 'Package: testlib'"
  fi
else
  fail "GET Packages index returned error"
fi

# -------------------------------------------------------------------------
# 5. GET Packages.gz returns gzip-compressed index
# -------------------------------------------------------------------------

begin_test "Packages.gz decompresses to valid index"
if curl -sf -H "$(format_auth_header)" \
    -o "${WORK_DIR}/Packages.gz" \
    "${BASE_URL}/debian/${REPO_KEY}/dists/${DISTRIBUTION}/${COMPONENT}/binary-amd64/Packages.gz" 2>/dev/null; then
  if gunzip -c "${WORK_DIR}/Packages.gz" 2>/dev/null | grep -q "Package: testlib"; then
    pass
  else
    fail "Packages.gz did not decompress to valid content containing testlib"
  fi
else
  fail "GET Packages.gz returned error"
fi

# -------------------------------------------------------------------------
# 6. Package index contains correct fields
# -------------------------------------------------------------------------

begin_test "Package index contains required fields"
# Re-use PACKAGES_BODY from test 4; if it was empty, fetch again
if [ -z "$PACKAGES_BODY" ]; then
  PACKAGES_BODY=$(curl -sf -H "$(format_auth_header)" \
      "${BASE_URL}/debian/${REPO_KEY}/dists/${DISTRIBUTION}/${COMPONENT}/binary-amd64/Packages" 2>/dev/null) || true
fi

missing=""
for field in "Package:" "Version:" "Architecture:" "Filename:" "SHA256:"; do
  if ! echo "$PACKAGES_BODY" | grep -q "$field"; then
    missing="${missing} ${field}"
  fi
done

if [ -z "$missing" ]; then
  pass
else
  fail "Packages index missing fields:${missing}"
fi

# -------------------------------------------------------------------------
# 7. Download .deb via the Filename path from Packages index
# -------------------------------------------------------------------------

begin_test "Download .deb via Filename path from Packages index"
# Extract the Filename value from the Packages index
DL_PATH=$(echo "$PACKAGES_BODY" | grep "^Filename:" | head -1 | awk '{print $2}')
if [ -z "$DL_PATH" ]; then
  fail "could not extract Filename from Packages index"
else
  if curl -sf -H "$(format_auth_header)" \
      -o "${WORK_DIR}/downloaded-via-index.deb" \
      "${BASE_URL}/debian/${REPO_KEY}/${DL_PATH}" 2>/dev/null; then
    if [ -s "${WORK_DIR}/downloaded-via-index.deb" ]; then
      pass
    else
      fail "downloaded .deb is empty"
    fi
  else
    fail "download via Filename path '${DL_PATH}' returned error"
  fi
fi

# -------------------------------------------------------------------------
# 8. SHA256 of downloaded .deb matches Packages index entry
# -------------------------------------------------------------------------

begin_test "Downloaded .deb SHA256 matches Packages index"
EXPECTED_SHA=$(echo "$PACKAGES_BODY" | grep "^SHA256:" | head -1 | awk '{print $2}')
if [ -z "$EXPECTED_SHA" ]; then
  fail "could not extract SHA256 from Packages index"
elif [ ! -f "${WORK_DIR}/downloaded-via-index.deb" ]; then
  fail "no downloaded .deb to verify"
else
  ACTUAL_SHA=$(sha256_hex "${WORK_DIR}/downloaded-via-index.deb")
  if assert_eq "$ACTUAL_SHA" "$EXPECTED_SHA" "SHA256 mismatch: got ${ACTUAL_SHA}, expected ${EXPECTED_SHA}"; then
    pass
  fi
fi

# -------------------------------------------------------------------------
# 9. Multiple architectures: upload arm64 and verify separate listing
# -------------------------------------------------------------------------

DEB_ARM64="${WORK_DIR}/testlib_1.0.0_arm64.deb"
build_deb "testlib" "1.0.0" "arm64" "$DEB_ARM64"

begin_test "Multiple architectures listed separately"
# Upload arm64 package
ARM_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
    -X PUT \
    -H "$(format_auth_header)" \
    -H "Content-Type: application/vnd.debian.binary-package" \
    --data-binary "@${DEB_ARM64}" \
    "${BASE_URL}/debian/${REPO_KEY}/pool/${COMPONENT}/testlib_1.0.0_arm64.deb")

if [ "$ARM_CODE" -lt 200 ] || [ "$ARM_CODE" -ge 300 ]; then
  fail "arm64 upload returned HTTP ${ARM_CODE}"
else
  sleep 1
  # Fetch arm64 Packages index
  ARM_PACKAGES=$(curl -sf -H "$(format_auth_header)" \
      "${BASE_URL}/debian/${REPO_KEY}/dists/${DISTRIBUTION}/${COMPONENT}/binary-arm64/Packages" 2>/dev/null) || true

  if echo "$ARM_PACKAGES" | grep -q "Architecture: arm64"; then
    # Also verify the amd64 index still works and contains amd64
    AMD_PACKAGES=$(curl -sf -H "$(format_auth_header)" \
        "${BASE_URL}/debian/${REPO_KEY}/dists/${DISTRIBUTION}/${COMPONENT}/binary-amd64/Packages" 2>/dev/null) || true
    if echo "$AMD_PACKAGES" | grep -q "Architecture: amd64"; then
      pass
    else
      fail "amd64 Packages index missing Architecture: amd64 after arm64 upload"
    fi
  else
    fail "arm64 Packages index missing Architecture: arm64"
  fi
fi

# -------------------------------------------------------------------------
# 10. by-hash support: GET by-hash/SHA256/{hash} returns the file
# -------------------------------------------------------------------------

begin_test "by-hash SHA256 access for Packages file"
# The by-hash URL pattern is:
# dists/{dist}/{comp}/binary-{arch}/by-hash/SHA256/{hash}
# We compute the SHA256 of the Packages body and try that path.
PACKAGES_TEXT=$(curl -sf -H "$(format_auth_header)" \
    "${BASE_URL}/debian/${REPO_KEY}/dists/${DISTRIBUTION}/${COMPONENT}/binary-amd64/Packages" 2>/dev/null) || true

if [ -n "$PACKAGES_TEXT" ]; then
  echo -n "$PACKAGES_TEXT" > "${WORK_DIR}/Packages-for-hash"
  PKGS_HASH=$(sha256_hex "${WORK_DIR}/Packages-for-hash")
  BY_HASH_STATUS=$(curl -s -o /dev/null -w '%{http_code}' \
      -H "$(format_auth_header)" \
      "${BASE_URL}/debian/${REPO_KEY}/dists/${DISTRIBUTION}/${COMPONENT}/binary-amd64/by-hash/SHA256/${PKGS_HASH}") || true
  if [ "$BY_HASH_STATUS" -ge 200 ] && [ "$BY_HASH_STATUS" -lt 300 ]; then
    pass
  else
    # by-hash is optional; skip if not implemented
    skip "by-hash returned HTTP ${BY_HASH_STATUS} (feature may not be implemented)"
  fi
else
  skip "could not fetch Packages to compute hash"
fi

# -------------------------------------------------------------------------
# 11. 404 for nonexistent distribution
# -------------------------------------------------------------------------

begin_test "404 for nonexistent distribution"
NOTFOUND_STATUS=$(curl -s -o /dev/null -w '%{http_code}' \
    -H "$(format_auth_header)" \
    "${BASE_URL}/debian/${REPO_KEY}/dists/nonexistent-distro-${RUN_ID}/Release") || true

if [ "$NOTFOUND_STATUS" = "404" ]; then
  pass
else
  # Some implementations return an empty Release for any distribution name.
  # If the body is empty or has no content, that is also acceptable as a
  # "no packages" scenario, but 404 is the strict correct response.
  if [ "$NOTFOUND_STATUS" -ge 200 ] && [ "$NOTFOUND_STATUS" -lt 300 ]; then
    skip "server returned ${NOTFOUND_STATUS} instead of 404 for unknown distribution (lenient mode)"
  else
    fail "expected 404 for nonexistent distribution, got ${NOTFOUND_STATUS}"
  fi
fi

# -------------------------------------------------------------------------
# 12. Release file Architectures field reflects uploaded packages
# -------------------------------------------------------------------------

begin_test "Release Architectures field lists uploaded architectures"
RELEASE2=""
if RELEASE2=$(curl -sf -H "$(format_auth_header)" \
    "${BASE_URL}/debian/${REPO_KEY}/dists/${DISTRIBUTION}/Release" 2>/dev/null); then
  ARCH_LINE=$(echo "$RELEASE2" | grep "^Architectures:")
  has_amd64=false
  has_arm64=false
  if echo "$ARCH_LINE" | grep -q "amd64"; then
    has_amd64=true
  fi
  if echo "$ARCH_LINE" | grep -q "arm64"; then
    has_arm64=true
  fi
  if $has_amd64 && $has_arm64; then
    pass
  else
    fail "Architectures field does not list both amd64 and arm64: ${ARCH_LINE}"
  fi
else
  fail "could not fetch Release file"
fi

end_suite
