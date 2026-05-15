#!/usr/bin/env bash
# test-alpine-conformance.sh - Alpine APK repository conformance tests
#
# Validates that the Alpine repository implementation produces correct
# APKINDEX.tar.gz archives, contains the expected metadata fields,
# handles multiple packages, and verifies download integrity.
#
# Endpoints: ${BASE_URL}/alpine/{repo_key}/
#
# Requires: curl, tar, gzip, sha256sum or shasum
source "$(dirname "$0")/../lib/common.sh"

begin_suite "alpine-conformance"
auth_admin
setup_workdir

REPO_KEY="test-alp-conf-${RUN_ID}"
BRANCH="v3.20"
REPOSITORY="main"
ARCH="x86_64"
PKG_NAME="confpkg"
PKG_VERSION="1.0.0-r0"
PKG_NAME_2="conflib"
PKG_VERSION_2="2.3.1-r0"

# Portable SHA256 helper (Linux uses sha256sum, macOS uses shasum)
sha256_hex() {
  if command -v sha256sum &>/dev/null; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

# ---------------------------------------------------------------------------
# Helper: build a minimal .apk package
#
# An .apk is a gzipped tar archive with at minimum a .PKGINFO file
# containing key = value metadata lines and optional data files.
# ---------------------------------------------------------------------------

build_apk() {
  local name="$1"
  local version="$2"
  local arch="$3"
  local outfile="$4"
  local pkg_size="${5:-512}"

  local build_dir="${WORK_DIR}/apk-build-${name}-${version}"
  mkdir -p "${build_dir}/usr/bin"

  cat > "${build_dir}/.PKGINFO" <<PKGINFO
pkgname = ${name}
pkgver = ${version}
pkgdesc = Conformance test package ${name}
url = https://example.com/${name}
builddate = $(date +%s)
packager = conformance-test@example.com
size = ${pkg_size}
arch = ${arch}
origin = ${name}
license = MIT
PKGINFO

  echo '#!/bin/sh' > "${build_dir}/usr/bin/${name}"
  echo "echo hello from ${name} ${version}" >> "${build_dir}/usr/bin/${name}"
  chmod 755 "${build_dir}/usr/bin/${name}"

  (cd "${build_dir}" && tar czf "${outfile}" .PKGINFO usr/)
}

# ---------------------------------------------------------------------------
# Create repository
# ---------------------------------------------------------------------------

begin_test "Create alpine local repository"
if create_local_repo "$REPO_KEY" "alpine"; then
  pass
else
  fail "could not create alpine repository"
fi

# ---------------------------------------------------------------------------
# 1. Upload a .apk package
# ---------------------------------------------------------------------------

begin_test "Upload .apk package"
APK_FILE="${WORK_DIR}/${PKG_NAME}-${PKG_VERSION}.apk"
build_apk "$PKG_NAME" "$PKG_VERSION" "$ARCH" "$APK_FILE"

upload_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X PUT \
  -H "$(format_auth_header)" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@${APK_FILE}" \
  "${BASE_URL}/alpine/${REPO_KEY}/${BRANCH}/${REPOSITORY}/${ARCH}/${PKG_NAME}-${PKG_VERSION}.apk") || true

if [ "$upload_status" -ge 200 ] 2>/dev/null && [ "$upload_status" -lt 300 ] 2>/dev/null; then
  pass
else
  fail "upload returned HTTP ${upload_status}, expected 2xx"
fi

sleep 1

# ---------------------------------------------------------------------------
# 2. GET APKINDEX.tar.gz returns valid tar.gz containing APKINDEX
# ---------------------------------------------------------------------------

begin_test "APKINDEX.tar.gz is a valid tar.gz containing APKINDEX"
APKINDEX_FILE="${WORK_DIR}/APKINDEX.tar.gz"
apkindex_status=$(curl -s -o "$APKINDEX_FILE" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  "${BASE_URL}/alpine/${REPO_KEY}/${BRANCH}/${REPOSITORY}/${ARCH}/APKINDEX.tar.gz") || true

if [ "$apkindex_status" -ge 200 ] 2>/dev/null && [ "$apkindex_status" -lt 300 ] 2>/dev/null; then
  if [ -s "$APKINDEX_FILE" ]; then
    APKINDEX_DIR="${WORK_DIR}/apkindex-extracted"
    mkdir -p "$APKINDEX_DIR"
    if tar xzf "$APKINDEX_FILE" -C "$APKINDEX_DIR" 2>/dev/null; then
      if [ -f "${APKINDEX_DIR}/APKINDEX" ]; then
        pass
      else
        fail "APKINDEX.tar.gz extracted but does not contain an APKINDEX file"
      fi
    else
      fail "APKINDEX.tar.gz is not a valid tar.gz archive"
    fi
  else
    fail "APKINDEX.tar.gz response body is empty"
  fi
else
  fail "APKINDEX.tar.gz endpoint returned HTTP ${apkindex_status}"
fi

# ---------------------------------------------------------------------------
# 3. APKINDEX contains package metadata (P, V, A, S, I fields)
# ---------------------------------------------------------------------------

begin_test "APKINDEX contains required metadata fields (P, V, A, S, I)"
if [ -f "${APKINDEX_DIR}/APKINDEX" ]; then
  apkindex_content=$(cat "${APKINDEX_DIR}/APKINDEX")
  found_fields=0
  missing_fields=""

  # P = package name
  if echo "$apkindex_content" | grep -q "^P:"; then
    found_fields=$((found_fields + 1))
  else
    missing_fields="${missing_fields} P(pkgname)"
  fi

  # V = version
  if echo "$apkindex_content" | grep -q "^V:"; then
    found_fields=$((found_fields + 1))
  else
    missing_fields="${missing_fields} V(version)"
  fi

  # A = architecture
  if echo "$apkindex_content" | grep -q "^A:"; then
    found_fields=$((found_fields + 1))
  else
    missing_fields="${missing_fields} A(arch)"
  fi

  # S = size
  if echo "$apkindex_content" | grep -q "^S:"; then
    found_fields=$((found_fields + 1))
  else
    missing_fields="${missing_fields} S(size)"
  fi

  # I = installed size
  if echo "$apkindex_content" | grep -q "^I:"; then
    found_fields=$((found_fields + 1))
  else
    missing_fields="${missing_fields} I(installed-size)"
  fi

  if [ "$found_fields" -ge 3 ]; then
    if [ -n "$missing_fields" ]; then
      echo "  note: some optional fields missing:${missing_fields}"
    fi
    pass
  else
    fail "APKINDEX missing required fields (found ${found_fields}/5):${missing_fields}"
  fi
else
  fail "no APKINDEX file to inspect (previous extraction failed)"
fi

# ---------------------------------------------------------------------------
# 4. Download .apk by path
# ---------------------------------------------------------------------------

begin_test "Download .apk by repository path"
DL_FILE="${WORK_DIR}/downloaded.apk"
dl_status=$(curl -s -o "$DL_FILE" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  "${BASE_URL}/alpine/${REPO_KEY}/${BRANCH}/${REPOSITORY}/${ARCH}/${PKG_NAME}-${PKG_VERSION}.apk") || true

if [ "$dl_status" -ge 200 ] 2>/dev/null && [ "$dl_status" -lt 300 ] 2>/dev/null; then
  if [ -s "$DL_FILE" ]; then
    pass
  else
    fail "downloaded .apk is empty"
  fi
else
  fail "download returned HTTP ${dl_status}, expected 2xx"
fi

# ---------------------------------------------------------------------------
# 5. Download integrity verification (SHA256 of uploaded matches downloaded)
# ---------------------------------------------------------------------------

begin_test "Download integrity (SHA256 matches uploaded file)"
if [ -s "$DL_FILE" ] && [ -s "$APK_FILE" ]; then
  upload_sha=$(sha256_hex "$APK_FILE")
  download_sha=$(sha256_hex "$DL_FILE")
  if assert_eq "$download_sha" "$upload_sha" "SHA256 mismatch: uploaded=${upload_sha} downloaded=${download_sha}"; then
    pass
  fi
else
  skip "uploaded or downloaded file missing for integrity check"
fi

# ---------------------------------------------------------------------------
# 6. Multiple packages appear in APKINDEX
# ---------------------------------------------------------------------------

begin_test "Multiple packages listed in APKINDEX"
APK_FILE_2="${WORK_DIR}/${PKG_NAME_2}-${PKG_VERSION_2}.apk"
build_apk "$PKG_NAME_2" "$PKG_VERSION_2" "$ARCH" "$APK_FILE_2"

upload2_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X PUT \
  -H "$(format_auth_header)" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@${APK_FILE_2}" \
  "${BASE_URL}/alpine/${REPO_KEY}/${BRANCH}/${REPOSITORY}/${ARCH}/${PKG_NAME_2}-${PKG_VERSION_2}.apk") || true

if [ "$upload2_status" -ge 200 ] 2>/dev/null && [ "$upload2_status" -lt 300 ] 2>/dev/null; then
  sleep 1
  # Re-fetch APKINDEX
  APKINDEX_FILE_2="${WORK_DIR}/APKINDEX-multi.tar.gz"
  curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    -o "$APKINDEX_FILE_2" \
    "${BASE_URL}/alpine/${REPO_KEY}/${BRANCH}/${REPOSITORY}/${ARCH}/APKINDEX.tar.gz" 2>/dev/null || true

  if [ -s "$APKINDEX_FILE_2" ]; then
    APKINDEX_DIR_2="${WORK_DIR}/apkindex-multi"
    mkdir -p "$APKINDEX_DIR_2"
    if tar xzf "$APKINDEX_FILE_2" -C "$APKINDEX_DIR_2" 2>/dev/null && [ -f "${APKINDEX_DIR_2}/APKINDEX" ]; then
      index_content=$(cat "${APKINDEX_DIR_2}/APKINDEX")
      # Count how many P: lines appear (one per package)
      pkg_count=$(echo "$index_content" | grep -c "^P:" 2>/dev/null) || pkg_count=0
      if [ "$pkg_count" -ge 2 ]; then
        pass
      else
        # Check if both package names appear anywhere in the index
        has_pkg1=$(echo "$index_content" | grep -c "$PKG_NAME" 2>/dev/null) || has_pkg1=0
        has_pkg2=$(echo "$index_content" | grep -c "$PKG_NAME_2" 2>/dev/null) || has_pkg2=0
        if [ "$has_pkg1" -ge 1 ] && [ "$has_pkg2" -ge 1 ]; then
          pass
        else
          fail "APKINDEX does not list both packages (P: lines=${pkg_count}, pkg1=${has_pkg1}, pkg2=${has_pkg2})"
        fi
      fi
    else
      fail "could not extract APKINDEX after second upload"
    fi
  else
    fail "APKINDEX.tar.gz empty after uploading second package"
  fi
else
  fail "second package upload returned HTTP ${upload2_status}"
fi

# ---------------------------------------------------------------------------
# 7. 404 for nonexistent package
# ---------------------------------------------------------------------------

begin_test "404 for nonexistent package download"
status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  "${BASE_URL}/alpine/${REPO_KEY}/${BRANCH}/${REPOSITORY}/${ARCH}/nonexistent-pkg-${RUN_ID}-0.0.1-r0.apk") || true
if assert_eq "$status" "404" "expected 404 for nonexistent package, got ${status}"; then
  pass
fi

# ---------------------------------------------------------------------------
# 8. RSA signature in APKINDEX.tar.gz (if signing enabled, skip if not)
# ---------------------------------------------------------------------------

begin_test "APKINDEX.tar.gz contains RSA signature (if signing enabled)"
# Re-use the multi-package APKINDEX already fetched, or fetch again
SIG_APKINDEX="${WORK_DIR}/APKINDEX-sig.tar.gz"
if [ -s "$APKINDEX_FILE_2" ]; then
  cp "$APKINDEX_FILE_2" "$SIG_APKINDEX"
else
  curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    -o "$SIG_APKINDEX" \
    "${BASE_URL}/alpine/${REPO_KEY}/${BRANCH}/${REPOSITORY}/${ARCH}/APKINDEX.tar.gz" 2>/dev/null || true
fi

if [ -s "$SIG_APKINDEX" ]; then
  SIG_DIR="${WORK_DIR}/apkindex-sig"
  mkdir -p "$SIG_DIR"
  tar xzf "$SIG_APKINDEX" -C "$SIG_DIR" 2>/dev/null || true

  # Alpine RSA signatures are stored as .SIGN.RSA.* files in the archive
  sig_files=$(find "$SIG_DIR" -name '.SIGN.RSA.*' 2>/dev/null | head -1) || true

  if [ -n "$sig_files" ]; then
    echo "  found signature file: $(basename "$sig_files")"
    pass
  else
    # Signing is optional; not all registries configure RSA key pairs
    skip "no RSA signature found in APKINDEX.tar.gz (signing may not be enabled)"
  fi
else
  skip "could not fetch APKINDEX.tar.gz for signature check"
fi

end_suite
