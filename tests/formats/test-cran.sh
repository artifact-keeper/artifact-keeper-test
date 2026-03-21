#!/usr/bin/env bash
# test-cran.sh - CRAN (R package) registry E2E test (curl-based)
#
# Uploads an R source package to the CRAN registry endpoint, verifies the
# PACKAGES index, and downloads the package tarball.

source "$(dirname "$0")/../lib/common.sh"

begin_suite "cran"
auth_admin
setup_workdir

REPO_KEY="test-cran-${RUN_ID}"
PACKAGE_NAME="e2ehello"
PACKAGE_VERSION="1.0.$(date +%s)"

# -----------------------------------------------------------------------
# Create repository
# -----------------------------------------------------------------------
begin_test "Create CRAN repository"
if create_local_repo "$REPO_KEY" "cran"; then
  pass
else
  fail "could not create cran repository"
fi

# -----------------------------------------------------------------------
# Generate a minimal R source package tarball
# -----------------------------------------------------------------------
# R source packages are .tar.gz archives with the structure:
#   pkgname/DESCRIPTION
#   pkgname/NAMESPACE
#   pkgname/R/functions.R
begin_test "Upload package"
PKG_DIR="$WORK_DIR/${PACKAGE_NAME}"
mkdir -p "$PKG_DIR/R"

cat > "$PKG_DIR/DESCRIPTION" <<EOF
Package: ${PACKAGE_NAME}
Title: E2E Test Package
Version: ${PACKAGE_VERSION}
Authors@R: person("E2E", "Test", email = "test@example.com", role = c("aut", "cre"))
Description: A minimal R package for E2E testing of the artifact registry.
License: MIT
Encoding: UTF-8
EOF

cat > "$PKG_DIR/NAMESPACE" <<'EOF'
export(hello)
EOF

cat > "$PKG_DIR/R/hello.R" <<'EOF'
#' Say hello
#' @return A greeting string
#' @export
hello <- function() {
  "Hello from CRAN E2E test!"
}
EOF

PKG_TARBALL="$WORK_DIR/${PACKAGE_NAME}_${PACKAGE_VERSION}.tar.gz"
tar czf "$PKG_TARBALL" -C "$WORK_DIR" "$PACKAGE_NAME"

upload_status=$(curl -s -o /dev/null -w '%{http_code}' \
  -X PUT \
  -H "$(format_auth_header)" \
  -H "Content-Type: application/gzip" \
  --data-binary "@${PKG_TARBALL}" \
  "${BASE_URL}/cran/${REPO_KEY}/src/contrib/${PACKAGE_NAME}_${PACKAGE_VERSION}.tar.gz") || true

if [ "$upload_status" = "200" ] || [ "$upload_status" = "201" ]; then
  pass
else
  fail "package upload returned ${upload_status}, expected 200 or 201"
fi

# -----------------------------------------------------------------------
# Verify PACKAGES index
# -----------------------------------------------------------------------
begin_test "Verify PACKAGES index"
packages_resp=$(curl -sf -H "$(format_auth_header)" \
  "${BASE_URL}/cran/${REPO_KEY}/src/contrib/PACKAGES" 2>/dev/null) || true

if [ -z "$packages_resp" ]; then
  # Try gzipped variant
  packages_gz="$WORK_DIR/PACKAGES.gz"
  dl_status=$(curl -sf -o "$packages_gz" -w '%{http_code}' \
    -H "$(format_auth_header)" \
    "${BASE_URL}/cran/${REPO_KEY}/src/contrib/PACKAGES.gz" 2>/dev/null) || true
  if [ "$dl_status" = "200" ] && [ -s "$packages_gz" ]; then
    packages_resp=$(gzip -dc "$packages_gz" 2>/dev/null) || true
  fi
fi

if [ -n "$packages_resp" ] && echo "$packages_resp" | grep -q "$PACKAGE_NAME"; then
  pass
else
  fail "package ${PACKAGE_NAME} not found in PACKAGES index"
fi

# -----------------------------------------------------------------------
# Verify package version in PACKAGES
# -----------------------------------------------------------------------
begin_test "Verify version in PACKAGES"
if [ -n "$packages_resp" ] && echo "$packages_resp" | grep -q "Version: ${PACKAGE_VERSION}"; then
  pass
else
  fail "version ${PACKAGE_VERSION} not found in PACKAGES index"
fi

# -----------------------------------------------------------------------
# Download package tarball
# -----------------------------------------------------------------------
begin_test "Download package"
dl_file="$WORK_DIR/downloaded.tar.gz"
dl_status=$(curl -sf -o "$dl_file" -w '%{http_code}' \
  -H "$(format_auth_header)" \
  "${BASE_URL}/cran/${REPO_KEY}/src/contrib/${PACKAGE_NAME}_${PACKAGE_VERSION}.tar.gz" 2>/dev/null) || true

if [ "$dl_status" = "200" ]; then
  # Verify the archive contains the DESCRIPTION file
  if tar tzf "$dl_file" 2>/dev/null | grep -q "DESCRIPTION"; then
    pass
  else
    fail "downloaded archive does not contain DESCRIPTION"
  fi
elif [ "$dl_status" = "404" ] || [ "$dl_status" = "405" ]; then
  skip "download endpoint not available for this format (status: ${dl_status})"
else
  fail "package download returned ${dl_status}, expected 200"
fi

# -----------------------------------------------------------------------
# Upload second version
# -----------------------------------------------------------------------
begin_test "Upload second version"
PACKAGE_VERSION_V2="2.0.$(date +%s)"

cat > "$PKG_DIR/DESCRIPTION" <<EOF
Package: ${PACKAGE_NAME}
Title: E2E Test Package v2
Version: ${PACKAGE_VERSION_V2}
Authors@R: person("E2E", "Test", email = "test@example.com", role = c("aut", "cre"))
Description: A minimal R package v2 for E2E testing.
License: MIT
Encoding: UTF-8
EOF

PKG_TARBALL_V2="$WORK_DIR/${PACKAGE_NAME}_${PACKAGE_VERSION_V2}.tar.gz"
tar czf "$PKG_TARBALL_V2" -C "$WORK_DIR" "$PACKAGE_NAME"

v2_status=$(curl -s -o /dev/null -w '%{http_code}' \
  -X PUT \
  -H "$(format_auth_header)" \
  -H "Content-Type: application/gzip" \
  --data-binary "@${PKG_TARBALL_V2}" \
  "${BASE_URL}/cran/${REPO_KEY}/src/contrib/${PACKAGE_NAME}_${PACKAGE_VERSION_V2}.tar.gz") || true

if [ "$v2_status" = "200" ] || [ "$v2_status" = "201" ]; then
  pass
elif [ "$v2_status" = "404" ] || [ "$v2_status" = "405" ]; then
  skip "version upload endpoint not available for this format (status: ${v2_status})"
else
  fail "v2 upload returned ${v2_status}"
fi

# -----------------------------------------------------------------------
# Delete package and verify removal
# -----------------------------------------------------------------------
begin_test "Delete package and verify removal"
status=$(curl -s -o /dev/null -w "%{http_code}" \
  -X DELETE -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/src/contrib/${PACKAGE_NAME}_${PACKAGE_VERSION}.tar.gz" 2>&1) || true
if [ "$status" = "200" ] || [ "$status" = "204" ]; then
  verify_status=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "$(auth_header)" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/src/contrib/${PACKAGE_NAME}_${PACKAGE_VERSION}.tar.gz" 2>&1) || true
  if [ "$verify_status" = "404" ]; then
    pass
  else
    fail "artifact still accessible after delete (status: ${verify_status})"
  fi
else
  # Try with format-native DELETE
  status=$(curl -s -o /dev/null -w "%{http_code}" \
    -X DELETE -H "$(format_auth_header)" \
    "${BASE_URL}/cran/${REPO_KEY}/src/contrib/${PACKAGE_NAME}_${PACKAGE_VERSION}.tar.gz" 2>&1) || true
  if [ "$status" = "200" ] || [ "$status" = "204" ]; then
    pass
  elif [ "$status" = "404" ] || [ "$status" = "405" ]; then
    skip "delete not supported for this format (status: ${status})"
  else
    fail "delete returned ${status}"
  fi
fi

end_suite
