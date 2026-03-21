#!/usr/bin/env bash
# test-composer.sh - PHP Composer registry E2E test (curl-based)
#
# Uploads a PHP package archive to the Composer registry endpoint,
# verifies the packages.json metadata endpoint, and confirms the
# package name appears in the listing.

source "$(dirname "$0")/../lib/common.sh"

begin_suite "composer"
auth_admin
setup_workdir

REPO_KEY="test-composer-${RUN_ID}"
VENDOR="e2etest"
PACKAGE="hello-php"
PACKAGE_VERSION="1.0.$(date +%s)"

# -----------------------------------------------------------------------
# Create repository
# -----------------------------------------------------------------------
begin_test "Create Composer local repository"
if create_local_repo "$REPO_KEY" "composer"; then
  pass
else
  fail "could not create composer repo"
fi

# -----------------------------------------------------------------------
# Generate a minimal Composer package archive
# -----------------------------------------------------------------------
begin_test "Upload Composer package"
PKG_DIR="$WORK_DIR/pkg"
mkdir -p "$PKG_DIR/src"

cat > "$PKG_DIR/composer.json" <<EOF
{
  "name": "${VENDOR}/${PACKAGE}",
  "description": "E2E test package for Composer registry",
  "version": "${PACKAGE_VERSION}",
  "type": "library",
  "license": "MIT",
  "autoload": {
    "psr-4": {
      "E2ETest\\\\": "src/"
    }
  },
  "require": {
    "php": ">=8.0"
  }
}
EOF

cat > "$PKG_DIR/src/Hello.php" <<'EOF'
<?php
namespace E2ETest;

class Hello {
    public function greet(): string {
        return "Hello from Composer E2E test!";
    }
}
EOF

PKG_ARCHIVE="$WORK_DIR/${VENDOR}-${PACKAGE}-${PACKAGE_VERSION}.zip"
(cd "$PKG_DIR" && zip -qr "$PKG_ARCHIVE" .)

upload_status=$(curl -s -o /dev/null -w '%{http_code}' \
  -X PUT \
  -H "$(format_auth_header)" \
  -H "Content-Type: application/zip" \
  --data-binary "@${PKG_ARCHIVE}" \
  "${BASE_URL}/composer/${REPO_KEY}/api/packages") || true

if [ "$upload_status" = "200" ] || [ "$upload_status" = "201" ]; then
  pass
else
  fail "package upload returned ${upload_status}, expected 200 or 201"
fi

# -----------------------------------------------------------------------
# Verify packages.json
# -----------------------------------------------------------------------
begin_test "Query packages.json"
packages_resp=$(curl -sf -H "$(format_auth_header)" \
  "${BASE_URL}/composer/${REPO_KEY}/packages.json" 2>/dev/null) || true

if [ -z "$packages_resp" ]; then
  fail "could not fetch packages.json"
else
  if assert_contains "$packages_resp" "packages" "packages.json should contain packages key"; then
    pass
  fi
fi

# -----------------------------------------------------------------------
# Verify package name in listing
# -----------------------------------------------------------------------
begin_test "Verify package name in listing"
if [ -n "$packages_resp" ] && echo "$packages_resp" | grep -q "${VENDOR}/${PACKAGE}"; then
  pass
else
  fail "package ${VENDOR}/${PACKAGE} not found in packages.json"
fi

# -----------------------------------------------------------------------
# Download and verify package
# -----------------------------------------------------------------------
begin_test "Download and verify package"
dl_file="$WORK_DIR/downloaded-pkg.zip"
if curl -sf -H "$(auth_header)" \
    -o "$dl_file" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/${VENDOR}/${PACKAGE}/${PACKAGE_VERSION}/${VENDOR}-${PACKAGE}-${PACKAGE_VERSION}.zip"; then
  if [ -s "$dl_file" ]; then
    pass
  else
    fail "downloaded file is empty"
  fi
else
  # Try the Composer dist endpoint
  dl_status=$(curl -s -o "$dl_file" -w '%{http_code}' \
    -H "$(format_auth_header)" \
    "${BASE_URL}/composer/${REPO_KEY}/dist/${VENDOR}/${PACKAGE}/${PACKAGE_VERSION}.zip" 2>/dev/null) || true
  if [ "$dl_status" = "200" ] && [ -s "$dl_file" ]; then
    pass
  else
    fail "download failed (status: ${dl_status})"
  fi
fi

# -----------------------------------------------------------------------
# Upload second version
# -----------------------------------------------------------------------
begin_test "Upload second version"
PACKAGE_VERSION_V2="2.0.$(date +%s)"

cat > "$PKG_DIR/composer.json" <<EOF
{
  "name": "${VENDOR}/${PACKAGE}",
  "description": "E2E test package v2",
  "version": "${PACKAGE_VERSION_V2}",
  "type": "library",
  "license": "MIT",
  "autoload": {
    "psr-4": {
      "E2ETest\\\\": "src/"
    }
  },
  "require": {
    "php": ">=8.0"
  }
}
EOF

PKG_ARCHIVE_V2="$WORK_DIR/${VENDOR}-${PACKAGE}-${PACKAGE_VERSION_V2}.zip"
(cd "$PKG_DIR" && zip -qr "$PKG_ARCHIVE_V2" .)

v2_status=$(curl -s -o /dev/null -w '%{http_code}' \
  -X PUT \
  -H "$(format_auth_header)" \
  -H "Content-Type: application/zip" \
  --data-binary "@${PKG_ARCHIVE_V2}" \
  "${BASE_URL}/composer/${REPO_KEY}/api/packages") || true

if [ "$v2_status" = "200" ] || [ "$v2_status" = "201" ]; then
  pass
else
  fail "v2 upload returned ${v2_status}"
fi

# -----------------------------------------------------------------------
# Delete package and verify removal
# -----------------------------------------------------------------------
begin_test "Delete package and verify removal"
status=$(curl -s -o /dev/null -w "%{http_code}" \
  -X DELETE -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/${VENDOR}/${PACKAGE}/${PACKAGE_VERSION}/${VENDOR}-${PACKAGE}-${PACKAGE_VERSION}.zip" 2>&1) || true
if [ "$status" = "200" ] || [ "$status" = "204" ]; then
  verify_status=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "$(auth_header)" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/${VENDOR}/${PACKAGE}/${PACKAGE_VERSION}/${VENDOR}-${PACKAGE}-${PACKAGE_VERSION}.zip" 2>&1) || true
  if [ "$verify_status" = "404" ]; then
    pass
  else
    fail "artifact still accessible after delete (status: ${verify_status})"
  fi
else
  fail "delete returned ${status}"
fi

end_suite
