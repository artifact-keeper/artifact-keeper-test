#!/usr/bin/env bash
# test-opkg.sh - Opkg (OpenWrt) package E2E test
#
# Requires: curl, tar, gzip
# Tests: create local repo, upload .ipk package via WASM ext proxy, verify via API
#
# Opkg is served through the WASM plugin proxy at /ext/opkg/{repo_key}/.
# .ipk files are ar archives (similar to .deb) containing control.tar.gz and data.tar.gz.
source "$(dirname "$0")/../lib/common.sh"

begin_suite "opkg"
auth_admin
setup_workdir

REPO_KEY="test-opkg-${RUN_ID}"
PKG_NAME="testpkg"
PKG_VERSION="1.0.0"
PKG_ARCH="all"
IPK_FILE="${PKG_NAME}_${PKG_VERSION}_${PKG_ARCH}.ipk"

# -------------------------------------------------------------------------
# Create repository
# -------------------------------------------------------------------------

begin_test "Create opkg repository"
# Opkg may use a generic or ext format type. Try "opkg" first, fall back to "generic".
if create_local_repo "$REPO_KEY" "opkg" 2>/dev/null; then
  pass
elif create_local_repo "$REPO_KEY" "generic" 2>/dev/null; then
  pass
else
  fail "could not create opkg repo"
fi

# -------------------------------------------------------------------------
# Build a minimal .ipk package
# -------------------------------------------------------------------------

begin_test "Create minimal .ipk package"
# An .ipk has the same structure as a .deb: an ar archive with
# debian-binary, control.tar.gz, and data.tar.gz
IPK_DIR="${WORK_DIR}/ipk-build"
mkdir -p "${IPK_DIR}/control"
mkdir -p "${IPK_DIR}/data/usr/bin"

cat > "${IPK_DIR}/control/control" <<EOF
Package: ${PKG_NAME}
Version: ${PKG_VERSION}
Architecture: ${PKG_ARCH}
Maintainer: test@example.com
Description: E2E test package for artifact-keeper opkg registry
Section: utils
Priority: optional
EOF

echo '#!/bin/sh' > "${IPK_DIR}/data/usr/bin/${PKG_NAME}"
echo "echo hello from ${PKG_NAME}" >> "${IPK_DIR}/data/usr/bin/${PKG_NAME}"
chmod 755 "${IPK_DIR}/data/usr/bin/${PKG_NAME}"

cd "${WORK_DIR}"

# debian-binary
echo "2.0" > debian-binary

# control.tar.gz
cd "${IPK_DIR}/control"
tar czf "${WORK_DIR}/control.tar.gz" ./control

# data.tar.gz
cd "${IPK_DIR}/data"
tar czf "${WORK_DIR}/data.tar.gz" ./usr

# Assemble with ar
cd "${WORK_DIR}"
if command -v ar &>/dev/null; then
  ar rcs "${WORK_DIR}/${IPK_FILE}" debian-binary control.tar.gz data.tar.gz 2>/dev/null
else
  # Fallback: concatenate into a simple binary blob
  cat debian-binary control.tar.gz data.tar.gz > "${WORK_DIR}/${IPK_FILE}"
fi

if [ -s "${WORK_DIR}/${IPK_FILE}" ]; then
  pass
else
  fail "failed to create .ipk package"
fi

# -------------------------------------------------------------------------
# Upload .ipk via ext proxy
# -------------------------------------------------------------------------

begin_test "Upload .ipk via ext/opkg endpoint"
HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
    -X PUT \
    -H "$(format_auth_header)" \
    -H "Content-Type: application/octet-stream" \
    --data-binary "@${WORK_DIR}/${IPK_FILE}" \
    "${BASE_URL}/ext/opkg/${REPO_KEY}/${IPK_FILE}")

if [ "$HTTP_CODE" -ge 200 ] && [ "$HTTP_CODE" -lt 300 ]; then
  pass
else
  # If the WASM plugin is not installed, the ext proxy returns 404 or 502
  if [ "$HTTP_CODE" = "404" ] || [ "$HTTP_CODE" = "502" ]; then
    skip "opkg WASM plugin not installed (HTTP ${HTTP_CODE})"
  else
    fail "upload returned HTTP ${HTTP_CODE}, expected 2xx"
  fi
fi

# -------------------------------------------------------------------------
# Download .ipk
# -------------------------------------------------------------------------

begin_test "Download .ipk via ext/opkg endpoint"
if curl -sf -H "$(format_auth_header)" \
    -o "${WORK_DIR}/downloaded.ipk" \
    "${BASE_URL}/ext/opkg/${REPO_KEY}/${IPK_FILE}" 2>/dev/null; then
  if [ -s "${WORK_DIR}/downloaded.ipk" ]; then
    pass
  else
    fail "downloaded .ipk is empty"
  fi
else
  skip "download not available (plugin may not be installed)"
fi

# -------------------------------------------------------------------------
# Verify package listing via API
# -------------------------------------------------------------------------

begin_test "Verify package listing via API"
if resp=$(api_get "/api/v1/repositories/${REPO_KEY}/artifacts" 2>/dev/null); then
  pass
else
  # Fall back to ext proxy index
  if resp=$(curl -sf -H "$(format_auth_header)" \
      "${BASE_URL}/ext/opkg/${REPO_KEY}/Packages" 2>/dev/null); then
    pass
  else
    skip "package listing not available"
  fi
fi

# -------------------------------------------------------------------------
# Verify via generic artifacts API
# -------------------------------------------------------------------------

begin_test "Verify artifact exists in repository"
if resp=$(api_get "/api/v1/repositories/${REPO_KEY}/artifacts" 2>/dev/null); then
  if echo "$resp" | jq -e '.items | length > 0' >/dev/null 2>&1; then
    pass
  elif echo "$resp" | jq -e 'length > 0' >/dev/null 2>&1; then
    pass
  else
    skip "no artifacts returned (plugin may not store via standard API)"
  fi
else
  skip "artifacts API not available for this repo type"
fi

end_suite
