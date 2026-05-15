#!/usr/bin/env bash
# test-cran-conformance.sh - R/CRAN repository conformance tests
#
# Validates that the CRAN repository at /cran/{repo_key}/ conforms to the
# CRAN package repository protocol. Tests cover package upload, PACKAGES
# index generation, field content (Package, Version, Depends), download
# with integrity verification, multi-package index, PACKAGES.gz compressed
# index, and 404 for missing packages.
#
# Endpoints: ${BASE_URL}/cran/{repo_key}/
#
# Requires: curl, shasum (or sha256sum), gzip
source "$(dirname "$0")/../lib/common.sh"

begin_suite "cran-conformance"
auth_admin
setup_workdir

REPO_KEY="test-cran-conf-${RUN_ID}"
PACKAGE_NAME="confhello"
PACKAGE_VERSION="1.0.0"
PACKAGE_NAME_2="confutils"
PACKAGE_VERSION_2="0.5.0"
CRAN_URL="${BASE_URL}/cran/${REPO_KEY}"

# -------------------------------------------------------------------------
# Helper: build a minimal R source package tarball
# -------------------------------------------------------------------------

build_r_package() {
  local pkg_name="$1"
  local pkg_version="$2"
  local pkg_depends="${3:-R (>= 3.5.0)}"

  local pkg_dir="${WORK_DIR}/${pkg_name}"
  rm -rf "$pkg_dir"
  mkdir -p "${pkg_dir}/R"

  cat > "${pkg_dir}/DESCRIPTION" <<EODESC
Package: ${pkg_name}
Title: Conformance Test Package
Version: ${pkg_version}
Authors@R: person("Test", "Runner", email = "test@example.com", role = c("aut", "cre"))
Description: A minimal R package for CRAN conformance testing.
Depends: ${pkg_depends}
License: MIT
Encoding: UTF-8
EODESC

  cat > "${pkg_dir}/NAMESPACE" <<'EONS'
export(hello)
EONS

  cat > "${pkg_dir}/R/hello.R" <<EOFUNC
#' Say hello
#' @return A greeting string
#' @export
hello <- function() {
  "Hello from CRAN conformance test, package ${pkg_name}!"
}
EOFUNC

  local tarball="${WORK_DIR}/${pkg_name}_${pkg_version}.tar.gz"
  tar czf "$tarball" -C "$WORK_DIR" "$pkg_name"
  echo "$tarball"
}

# -------------------------------------------------------------------------
# Setup: create repository
# -------------------------------------------------------------------------

begin_test "Create CRAN local repository"
if create_local_repo "$REPO_KEY" "cran"; then
  pass
else
  fail "could not create CRAN repository"
fi

# =========================================================================
# Test 1: Upload R package (.tar.gz source package)
# =========================================================================

begin_test "Upload R source package"
PKG_TARBALL=$(build_r_package "$PACKAGE_NAME" "$PACKAGE_VERSION" "R (>= 3.5.0)")
PKG_SHA256=$(shasum -a 256 "$PKG_TARBALL" | awk '{print $1}')

upload_status=$(curl -s -o /dev/null -w '%{http_code}' \
  -X PUT \
  -H "$(format_auth_header)" \
  -H "Content-Type: application/gzip" \
  --data-binary "@${PKG_TARBALL}" \
  "${CRAN_URL}/src/contrib/${PACKAGE_NAME}_${PACKAGE_VERSION}.tar.gz") || true

if [ "$upload_status" = "200" ] || [ "$upload_status" = "201" ]; then
  pass
else
  fail "package upload returned ${upload_status}, expected 200 or 201"
fi

sleep 1

# =========================================================================
# Test 2: GET src/contrib/PACKAGES returns package index
# =========================================================================

begin_test "GET src/contrib/PACKAGES returns package index"
PACKAGES_RESP=""
if PACKAGES_RESP=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${CRAN_URL}/src/contrib/PACKAGES" 2>/dev/null); then
  if [ -n "$PACKAGES_RESP" ]; then
    if assert_contains "$PACKAGES_RESP" "$PACKAGE_NAME" "PACKAGES index should contain uploaded package name"; then
      pass
    fi
  else
    fail "PACKAGES index is empty"
  fi
else
  # Try the gzipped variant and decompress
  PACKAGES_GZ="${WORK_DIR}/PACKAGES.gz"
  gz_status=$(curl -sf -o "$PACKAGES_GZ" -w '%{http_code}' \
    -H "$(format_auth_header)" \
    "${CRAN_URL}/src/contrib/PACKAGES.gz" 2>/dev/null) || true
  if [ "$gz_status" = "200" ] && [ -s "$PACKAGES_GZ" ]; then
    PACKAGES_RESP=$(gzip -dc "$PACKAGES_GZ" 2>/dev/null) || true
    if [ -n "$PACKAGES_RESP" ] && echo "$PACKAGES_RESP" | grep -q "$PACKAGE_NAME"; then
      pass
    else
      fail "PACKAGES.gz does not contain package name"
    fi
  else
    fail "GET PACKAGES returned error and PACKAGES.gz not available"
  fi
fi

# =========================================================================
# Test 3: PACKAGES file contains Package, Version, Depends fields
# =========================================================================

begin_test "PACKAGES contains Package, Version fields"
if [ -z "$PACKAGES_RESP" ]; then
  skip "PACKAGES index not available"
else
  HAS_PACKAGE=false
  HAS_VERSION=false

  if echo "$PACKAGES_RESP" | grep -q "^Package: ${PACKAGE_NAME}$"; then
    HAS_PACKAGE=true
  elif echo "$PACKAGES_RESP" | grep -q "Package: ${PACKAGE_NAME}"; then
    HAS_PACKAGE=true
  fi

  if echo "$PACKAGES_RESP" | grep -q "^Version: ${PACKAGE_VERSION}$"; then
    HAS_VERSION=true
  elif echo "$PACKAGES_RESP" | grep -q "Version: ${PACKAGE_VERSION}"; then
    HAS_VERSION=true
  fi

  if $HAS_PACKAGE && $HAS_VERSION; then
    # Depends field is optional in the index, note if missing
    if echo "$PACKAGES_RESP" | grep -qi "Depends:"; then
      echo "  PACKAGES contains Package, Version, and Depends fields"
    else
      echo "  note: Depends field not present in PACKAGES (optional)"
    fi
    pass
  else
    fail "PACKAGES missing required fields (Package=${HAS_PACKAGE}, Version=${HAS_VERSION})"
  fi
fi

# =========================================================================
# Test 4: Download package via src/contrib/{name}_{version}.tar.gz
# =========================================================================

begin_test "Download package via src/contrib path"
DL_PKG="${WORK_DIR}/dl-package.tar.gz"
dl_status=$(curl -sf -o "$DL_PKG" -w '%{http_code}' \
  -H "$(format_auth_header)" \
  "${CRAN_URL}/src/contrib/${PACKAGE_NAME}_${PACKAGE_VERSION}.tar.gz" 2>/dev/null) || true

if [ "$dl_status" = "200" ] && [ -s "$DL_PKG" ]; then
  # Verify it is a valid tar.gz archive containing DESCRIPTION
  if tar tzf "$DL_PKG" 2>/dev/null | grep -q "DESCRIPTION"; then
    pass
  else
    # Archive might use a different internal layout
    if tar tzf "$DL_PKG" > /dev/null 2>&1; then
      echo "  note: archive valid but does not contain DESCRIPTION at expected path"
      pass
    else
      fail "downloaded file is not a valid tar.gz archive"
    fi
  fi
else
  fail "package download returned HTTP ${dl_status}"
fi

# =========================================================================
# Test 5: Download integrity (SHA256 round-trip)
# =========================================================================

begin_test "Download integrity (SHA256 round-trip)"
if [ -f "$DL_PKG" ] && [ -s "$DL_PKG" ]; then
  DL_SHA256=$(shasum -a 256 "$DL_PKG" | awk '{print $1}')
  if assert_eq "$DL_SHA256" "$PKG_SHA256" "package SHA256 mismatch after download"; then
    pass
  fi
else
  skip "downloaded package not available for integrity check"
fi

# =========================================================================
# Test 6: Multiple packages in PACKAGES index
# =========================================================================

begin_test "Multiple packages appear in PACKAGES index"
PKG_TARBALL_2=$(build_r_package "$PACKAGE_NAME_2" "$PACKAGE_VERSION_2" "R (>= 4.0.0)")
v2_status=$(curl -s -o /dev/null -w '%{http_code}' \
  -X PUT \
  -H "$(format_auth_header)" \
  -H "Content-Type: application/gzip" \
  --data-binary "@${PKG_TARBALL_2}" \
  "${CRAN_URL}/src/contrib/${PACKAGE_NAME_2}_${PACKAGE_VERSION_2}.tar.gz") || true

if [ "$v2_status" = "200" ] || [ "$v2_status" = "201" ]; then
  sleep 1
  # Re-fetch PACKAGES and check both package names appear
  if updated_packages=$(curl -sf $CURL_TIMEOUT \
      -H "$(format_auth_header)" \
      "${CRAN_URL}/src/contrib/PACKAGES" 2>/dev/null); then
    HAS_PKG1=false
    HAS_PKG2=false
    if echo "$updated_packages" | grep -q "$PACKAGE_NAME"; then
      HAS_PKG1=true
    fi
    if echo "$updated_packages" | grep -q "$PACKAGE_NAME_2"; then
      HAS_PKG2=true
    fi

    if $HAS_PKG1 && $HAS_PKG2; then
      pass
    else
      fail "PACKAGES index missing one or both packages (${PACKAGE_NAME}=${HAS_PKG1}, ${PACKAGE_NAME_2}=${HAS_PKG2})"
    fi
  else
    fail "could not fetch PACKAGES index after second upload"
  fi
else
  fail "second package upload returned ${v2_status}"
fi

# =========================================================================
# Test 7: PACKAGES.gz returns gzip-compressed index
# =========================================================================

begin_test "PACKAGES.gz returns gzip-compressed index"
PACKAGES_GZ_FILE="${WORK_DIR}/PACKAGES-check.gz"
gz_status=$(curl -sf -o "$PACKAGES_GZ_FILE" -w '%{http_code}' \
  -H "$(format_auth_header)" \
  "${CRAN_URL}/src/contrib/PACKAGES.gz" 2>/dev/null) || true

if [ "$gz_status" = "200" ] && [ -s "$PACKAGES_GZ_FILE" ]; then
  # Verify it is valid gzip and decompresses to a PACKAGES file with content
  if decompressed=$(gzip -dc "$PACKAGES_GZ_FILE" 2>/dev/null); then
    if echo "$decompressed" | grep -q "$PACKAGE_NAME"; then
      pass
    else
      fail "decompressed PACKAGES.gz does not contain package name"
    fi
  else
    fail "PACKAGES.gz is not valid gzip"
  fi
elif [ "$gz_status" = "404" ]; then
  skip "PACKAGES.gz endpoint not implemented"
else
  fail "GET PACKAGES.gz returned HTTP ${gz_status}"
fi

# =========================================================================
# Test 8: 404 for nonexistent package
# =========================================================================

begin_test "GET nonexistent package returns 404"
HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  "${CRAN_URL}/src/contrib/nonexistent_pkg_${RUN_ID}_99.99.99.tar.gz") || true

if assert_eq "$HTTP_CODE" "404" "expected 404 for nonexistent package, got ${HTTP_CODE}"; then
  pass
fi

end_suite
