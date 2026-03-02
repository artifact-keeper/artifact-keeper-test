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
  "${BASE_URL}/composer/${REPO_KEY}/${VENDOR}/${PACKAGE}/${PACKAGE_VERSION}") || true

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

end_suite
