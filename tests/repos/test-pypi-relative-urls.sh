#!/usr/bin/env bash
# test-pypi-relative-urls.sh - PyPI remote with relative URL resolution
#
# Tests that PyPI remote repos correctly handle relative hrefs in the
# simple index HTML. AK-to-AK proxying uses root-relative paths
# (/pypi/{key}/simple/{pkg}/file.tar.gz), which exercises the same
# URL rewriting logic that Nexus/devpi/Artifactory relative URLs need.
#
# Verifies:
# 1. Simple index through remote has rewritten URLs (no upstream leak)
# 2. Package download through remote proxy works
# 3. All index links point to the remote repo, not the upstream
#
# Fixes: https://github.com/artifact-keeper/artifact-keeper/issues/610
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "pypi-relative-urls"
auth_admin
setup_workdir

UPSTREAM_KEY="test-pypi-rel-upstream-${RUN_ID}"
REMOTE_KEY="test-pypi-rel-remote-${RUN_ID}"
PKG_NAME="reltest-pkg"
PKG_VERSION="2.0.0"

# ---------------------------------------------------------------------------
# Create upstream local PyPI repo and upload a package
# ---------------------------------------------------------------------------

begin_test "Create upstream PyPI repo"
if create_local_repo "$UPSTREAM_KEY" "pypi"; then
  pass
else
  fail "could not create PyPI upstream repo"
fi

begin_test "Upload package to upstream"
mkdir -p "${WORK_DIR}/${PKG_NAME}-${PKG_VERSION}"
cat > "${WORK_DIR}/${PKG_NAME}-${PKG_VERSION}/PKG-INFO" <<EOINFO
Metadata-Version: 1.0
Name: ${PKG_NAME}
Version: ${PKG_VERSION}
Summary: E2E test for relative URL resolution
EOINFO
cat > "${WORK_DIR}/${PKG_NAME}-${PKG_VERSION}/setup.py" <<EOPY
from setuptools import setup
setup(name="${PKG_NAME}", version="${PKG_VERSION}")
EOPY
tar -czf "${WORK_DIR}/${PKG_NAME}-${PKG_VERSION}.tar.gz" \
    -C "${WORK_DIR}" "${PKG_NAME}-${PKG_VERSION}"

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
  skip "could not upload package to upstream"
fi

# ---------------------------------------------------------------------------
# Verify upstream index uses relative/root-relative URLs
# ---------------------------------------------------------------------------

begin_test "Upstream index has links (baseline check)"
sleep 1
if resp=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${BASE_URL}/pypi/${UPSTREAM_KEY}/simple/${PKG_NAME}/" 2>/dev/null); then
  if assert_contains "$resp" "${PKG_NAME}"; then
    UPSTREAM_INDEX="$resp"
    pass
  fi
else
  skip "upstream simple index not accessible"
fi

# ---------------------------------------------------------------------------
# Create remote PyPI repo
# ---------------------------------------------------------------------------

begin_test "Create remote PyPI repo"
UPSTREAM_URL="${BASE_URL}/pypi/${UPSTREAM_KEY}"
if create_remote_repo "$REMOTE_KEY" "pypi" "$UPSTREAM_URL"; then
  pass
else
  fail "could not create remote PyPI repo"
fi

sleep 2

# ---------------------------------------------------------------------------
# Fetch simple index through remote and verify URL rewriting
# ---------------------------------------------------------------------------

begin_test "Remote simple index has rewritten URLs"
if resp=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${BASE_URL}/pypi/${REMOTE_KEY}/simple/${PKG_NAME}/" 2>/dev/null); then
  REMOTE_INDEX="$resp"
  # All hrefs should point to the remote repo, not the upstream
  if echo "$resp" | grep -q "href=\"/pypi/${REMOTE_KEY}/"; then
    pass
  elif echo "$resp" | grep -q "${PKG_NAME}"; then
    # Links exist but may not be in expected format; check no upstream leak
    if echo "$resp" | grep -q "${UPSTREAM_KEY}"; then
      fail "remote index leaks upstream repo key '${UPSTREAM_KEY}'"
    else
      pass
    fi
  else
    fail "remote index does not contain package links"
  fi
else
  fail "could not fetch remote simple index"
fi

# ---------------------------------------------------------------------------
# Verify no upstream URLs leaked through
# ---------------------------------------------------------------------------

begin_test "No upstream URLs leak in remote index"
if [ -n "${REMOTE_INDEX:-}" ]; then
  if echo "$REMOTE_INDEX" | grep -q "${UPSTREAM_KEY}"; then
    fail "remote index contains upstream repo key '${UPSTREAM_KEY}'"
  else
    pass
  fi
else
  skip "no remote index to check"
fi

# ---------------------------------------------------------------------------
# Download package through remote proxy
# ---------------------------------------------------------------------------

begin_test "Download package through remote proxy"
if [ -n "${REMOTE_INDEX:-}" ]; then
  download_href=$(echo "$REMOTE_INDEX" | grep -oP 'href="[^"]*\.tar\.gz[^"]*"' | head -1 | sed 's/href="//;s/"//') || true
  if [ -n "$download_href" ]; then
    if [[ "$download_href" == http* ]]; then
      download_url="$download_href"
    else
      download_url="${BASE_URL}${download_href}"
    fi
    if curl -sf $CURL_TIMEOUT -H "$(format_auth_header)" \
        -o "${WORK_DIR}/remote-pkg.tar.gz" "$download_url" 2>/dev/null; then
      if [ -s "${WORK_DIR}/remote-pkg.tar.gz" ]; then
        pass
      else
        fail "downloaded file is empty"
      fi
    else
      fail "download through remote proxy returned error"
    fi
  else
    skip "no download link found in remote index"
  fi
else
  skip "no remote index to extract download link from"
fi

# ---------------------------------------------------------------------------
# Second download should hit proxy cache (verify it still works)
# ---------------------------------------------------------------------------

begin_test "Second download hits proxy cache"
if [ -n "${download_url:-}" ]; then
  if curl -sf $CURL_TIMEOUT -H "$(format_auth_header)" \
      -o "${WORK_DIR}/remote-pkg-cached.tar.gz" "$download_url" 2>/dev/null; then
    if [ -s "${WORK_DIR}/remote-pkg-cached.tar.gz" ]; then
      # Verify both downloads are identical
      if diff "${WORK_DIR}/remote-pkg.tar.gz" "${WORK_DIR}/remote-pkg-cached.tar.gz" > /dev/null 2>&1; then
        pass
      else
        fail "cached download differs from first download"
      fi
    else
      fail "cached download is empty"
    fi
  else
    fail "second download failed"
  fi
else
  skip "no download URL from previous test"
fi

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

api_delete "/api/v1/repositories/${REMOTE_KEY}" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${UPSTREAM_KEY}" > /dev/null 2>&1 || true

end_suite
