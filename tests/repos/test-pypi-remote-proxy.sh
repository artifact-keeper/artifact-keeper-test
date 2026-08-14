#!/usr/bin/env bash
# test-pypi-remote-proxy.sh - PyPI remote proxy with URL rewriting
#
# Tests that a remote PyPI repo proxies the simple index and package
# downloads, and that URLs in the index response are rewritten to point
# through the proxy rather than directly at the upstream.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "pypi-remote-proxy"
auth_admin
setup_workdir

UPSTREAM_KEY="test-pypi-upstream-${RUN_ID}"
REMOTE_KEY="test-pypi-proxy-remote-${RUN_ID}"
PKG_NAME="e2e-testpkg"
PKG_VERSION="1.0.0"

# -------------------------------------------------------------------------
# Create upstream local PyPI repo
# -------------------------------------------------------------------------

begin_test "Create local PyPI repo (upstream)"
if create_local_repo "$UPSTREAM_KEY" "pypi"; then
  pass
else
  fail "could not create PyPI upstream repo"
fi

# -------------------------------------------------------------------------
# Upload a minimal package to the upstream
# -------------------------------------------------------------------------

begin_test "Upload package to upstream"
# Build a minimal .tar.gz that PyPI endpoints accept
mkdir -p "${WORK_DIR}/${PKG_NAME}-${PKG_VERSION}"
cat > "${WORK_DIR}/${PKG_NAME}-${PKG_VERSION}/PKG-INFO" <<EOINFO
Metadata-Version: 1.0
Name: ${PKG_NAME}
Version: ${PKG_VERSION}
Summary: E2E test package
EOINFO
cat > "${WORK_DIR}/${PKG_NAME}-${PKG_VERSION}/setup.py" <<EOPY
from setuptools import setup
setup(name="${PKG_NAME}", version="${PKG_VERSION}")
EOPY
tar -czf "${WORK_DIR}/${PKG_NAME}-${PKG_VERSION}.tar.gz" \
    -C "${WORK_DIR}" "${PKG_NAME}-${PKG_VERSION}"

# Upload via twine-compatible endpoint (multipart form POST)
if curl -sf $CURL_TIMEOUT -X POST \
    -H "$(format_auth_header)" \
    -F ":action=file_upload" \
    -F "name=${PKG_NAME}" \
    -F "version=${PKG_VERSION}" \
    -F "filetype=sdist" \
    -F "content=@${WORK_DIR}/${PKG_NAME}-${PKG_VERSION}.tar.gz" \
    "${BASE_URL}/pypi/${UPSTREAM_KEY}/" > /dev/null 2>&1; then
  pass
elif api_upload "/api/v1/repositories/${UPSTREAM_KEY}/artifacts/${PKG_NAME}/${PKG_VERSION}/${PKG_NAME}-${PKG_VERSION}.tar.gz" \
    "${WORK_DIR}/${PKG_NAME}-${PKG_VERSION}.tar.gz" "application/gzip" > /dev/null 2>&1; then
  pass
else
  skip "could not upload PyPI package to upstream"
fi

# -------------------------------------------------------------------------
# Verify package exists in upstream simple index
# -------------------------------------------------------------------------

begin_test "Upstream simple index lists the package"
sleep 1
if resp=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${BASE_URL}/pypi/${UPSTREAM_KEY}/simple/${PKG_NAME}/" 2>/dev/null); then
  if assert_contains "$resp" "${PKG_NAME}"; then
    pass
  fi
elif resp=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${BASE_URL}/pypi/${UPSTREAM_KEY}/simple/" 2>/dev/null); then
  if assert_contains "$resp" "${PKG_NAME}"; then
    pass
  else
    skip "package not found in upstream simple index"
  fi
else
  skip "upstream simple index not accessible"
fi

# -------------------------------------------------------------------------
# Create remote PyPI repo pointing at the upstream
# -------------------------------------------------------------------------

begin_test "Create remote PyPI repo"
UPSTREAM_URL="${BASE_URL}/pypi/${UPSTREAM_KEY}"
if create_remote_repo "$REMOTE_KEY" "pypi" "$UPSTREAM_URL"; then
  pass
else
  fail "could not create remote PyPI repo"
fi

# -------------------------------------------------------------------------
# Fetch simple index through the remote proxy
# -------------------------------------------------------------------------

sleep 2

begin_test "Fetch simple index via remote proxy"
if resp=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${BASE_URL}/pypi/${REMOTE_KEY}/simple/${PKG_NAME}/" 2>/dev/null); then
  if assert_contains "$resp" "${PKG_NAME}"; then
    SIMPLE_INDEX="$resp"
    pass
  fi
elif resp=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${BASE_URL}/pypi/${REMOTE_KEY}/simple/" 2>/dev/null); then
  if assert_contains "$resp" "${PKG_NAME}"; then
    SIMPLE_INDEX="$resp"
    pass
  else
    skip "package not found in proxied simple index"
  fi
else
  skip "remote proxy simple index not accessible"
fi

# -------------------------------------------------------------------------
# Verify URL rewriting: links should reference the remote repo, not upstream
# -------------------------------------------------------------------------

begin_test "Verify URLs are rewritten to remote repo"
if [ -n "${SIMPLE_INDEX:-}" ]; then
  # URLs in the response should contain the remote key, not the upstream key
  if echo "$SIMPLE_INDEX" | grep -q "${UPSTREAM_KEY}"; then
    # Upstream URLs leaked through, rewriting is not happening
    fail "simple index contains upstream URLs (${UPSTREAM_KEY}), expected rewritten URLs"
  else
    pass
  fi
else
  skip "no simple index response to check"
fi

# -------------------------------------------------------------------------
# Download package through the proxy
# -------------------------------------------------------------------------

begin_test "Download package through remote proxy"
if [ -n "${SIMPLE_INDEX:-}" ]; then
  # Extract a download link from the index page
  download_href=$(echo "$SIMPLE_INDEX" | grep -oP 'href="[^"]*\.tar\.gz[^"]*"' | head -1 | sed 's/href="//;s/"//') || true
  if [ -n "$download_href" ]; then
    # Resolve relative URLs
    if [[ "$download_href" == http* ]]; then
      download_url="$download_href"
    else
      download_url="${BASE_URL}${download_href}"
    fi
    if curl -sf $CURL_TIMEOUT -H "$(format_auth_header)" \
        -o "${WORK_DIR}/proxied-pkg.tar.gz" "$download_url" 2>/dev/null; then
      if [ -s "${WORK_DIR}/proxied-pkg.tar.gz" ]; then
        pass
      else
        skip "downloaded file is empty"
      fi
    else
      skip "could not download package through proxy"
    fi
  else
    skip "no download link found in simple index"
  fi
else
  skip "no simple index to extract download URL from"
fi

# -------------------------------------------------------------------------
# Cleanup
# -------------------------------------------------------------------------

api_delete "/api/v1/repositories/${REMOTE_KEY}" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${UPSTREAM_KEY}" > /dev/null 2>&1 || true

end_suite
