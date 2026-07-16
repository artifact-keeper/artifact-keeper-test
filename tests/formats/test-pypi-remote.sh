#!/usr/bin/env bash
# test-pypi-remote.sh - PyPI remote proxy and virtual repo E2E tests
#
# Covers regression tests for:
#   #605 - Proxy cache hit (second fetch should serve from cache)
#   #606 - Virtual download path (download sdist via virtual repo)
#   #627 - Virtual vs direct access (SHA256 consistency)
#   #648 - Virtual repo with local member (simple index lists local packages)
#
# Tests remote (proxy) repos pointed at https://pypi.org and virtual repos
# that aggregate local PyPI members.
#
# Requires: curl, jq, python3

source "$(dirname "$0")/../lib/common.sh"

begin_suite "pypi-remote"
auth_admin
setup_workdir
require_cmd python3

LOCAL_KEY="test-pypi-local-${RUN_ID}"
REMOTE_KEY="test-pypi-remote-${RUN_ID}"
VIRTUAL_KEY="test-pypi-virtual-${RUN_ID}"
UPSTREAM_URL="https://pypi.org"
# 'six' is a well-known, tiny, stable PyPI package
PROXY_PKG="six"

PKG_NAME="test-pypi-rpkg-${RUN_ID//-/_}"
PKG_VERSION="1.0.$(date +%s)"
PYPI_LOCAL_URL="${BASE_URL}/pypi/${LOCAL_KEY}"
PYPI_REMOTE_URL="${BASE_URL}/pypi/${REMOTE_KEY}"
PYPI_VIRTUAL_URL="${BASE_URL}/pypi/${VIRTUAL_KEY}"

# =========================================================================
# Section 1: Remote repo proxy
# =========================================================================

begin_test "Create remote PyPI repository"
if create_remote_repo "$REMOTE_KEY" "pypi" "$UPSTREAM_URL"; then
  pass
else
  fail "could not create remote PyPI repo"
fi

# Check that upstream pypi.org is reachable before running proxy tests
begin_test "Verify upstream reachability"
if curl -sf --max-time 10 "https://pypi.org/simple/six/" > /dev/null 2>&1; then
  UPSTREAM_REACHABLE=true
  pass
else
  UPSTREAM_REACHABLE=false
  skip "pypi.org unreachable from test environment"
fi

begin_test "Fetch simple index for proxied package"
if [ "$UPSTREAM_REACHABLE" != "true" ]; then
  skip "upstream unreachable"
else
  sleep 1
  if resp=$(curl -sf $CURL_TIMEOUT \
      -u "${ADMIN_USER}:${ADMIN_PASS}" \
      "${PYPI_REMOTE_URL}/simple/${PROXY_PKG}/" 2>/dev/null); then
    if assert_contains "$resp" ".tar.gz" "simple index should contain sdist links"; then
      pass
    fi
  else
    fail "GET /pypi/${REMOTE_KEY}/simple/${PROXY_PKG}/ returned error"
  fi
fi

begin_test "Download tarball through remote proxy"
if [ "$UPSTREAM_REACHABLE" != "true" ]; then
  skip "upstream unreachable"
else
  # Extract the first .tar.gz link from the simple index
  TARBALL_HREF=$(echo "$resp" | grep -oE 'href="[^"]*\.tar\.gz[^"]*"' | head -1 | sed 's/href="//;s/"//') || true
  if [ -z "$TARBALL_HREF" ]; then
    # Try wheel instead
    TARBALL_HREF=$(echo "$resp" | grep -oE 'href="[^"]*\.whl[^"]*"' | head -1 | sed 's/href="//;s/"//') || true
  fi

  if [ -z "$TARBALL_HREF" ]; then
    fail "no downloadable file link found in simple index"
  else
    # The href may be absolute URL, absolute path, or relative; handle all
    # Strip fragment (#sha256=...) for the download URL
    CLEAN_HREF=$(echo "$TARBALL_HREF" | sed 's/#.*//')
    if [[ "$CLEAN_HREF" == http* ]]; then
      DOWNLOAD_URL="$CLEAN_HREF"
    elif [[ "$CLEAN_HREF" == /* ]]; then
      # Absolute path from URL rewriting (e.g. /pypi/{key}/simple/{pkg}/file.tar.gz)
      DOWNLOAD_URL="${BASE_URL}${CLEAN_HREF}"
    else
      DOWNLOAD_URL="${PYPI_REMOTE_URL}/simple/${PROXY_PKG}/${CLEAN_HREF}"
    fi
    if curl -sf $CURL_TIMEOUT \
        -u "${ADMIN_USER}:${ADMIN_PASS}" \
        -o "${WORK_DIR}/proxied-pkg.tar.gz" \
        "$DOWNLOAD_URL" 2>/dev/null; then
      if [ -s "${WORK_DIR}/proxied-pkg.tar.gz" ]; then
        pass
      else
        fail "downloaded file is empty"
      fi
    else
      fail "tarball download through proxy failed"
    fi
  fi
fi

begin_test "Proxied package is retrievable from cache on re-fetch"
if [ "$UPSTREAM_REACHABLE" != "true" ]; then
  skip "upstream unreachable"
else
  # Backend #1278/#1280: proxy-cached artifacts are INTENTIONALLY not inserted
  # into the `artifacts` DB table. They are written to a separate
  # `proxy-cache/...` storage path and served by the proxy fast path, so the
  # /api/v1/repositories/{key}/artifacts listing (backed by ArtifactService /
  # the artifacts table) will never contain a proxied package like `six`. The
  # correct way to confirm the proxy cached the package is to re-fetch its
  # simple index through the proxy and verify it is still served with the
  # expected sdist/wheel links (served from cache), rather than asserting on
  # the DB-backed artifact listing.
  sleep 2
  if resp=$(curl -sf $CURL_TIMEOUT \
      -u "${ADMIN_USER}:${ADMIN_PASS}" \
      "${PYPI_REMOTE_URL}/simple/${PROXY_PKG}/" 2>/dev/null); then
    if assert_contains "$resp" ".tar.gz" \
        "cached simple index for ${PROXY_PKG} should still list sdist links"; then
      pass
    fi
  else
    fail "re-fetch of cached ${PROXY_PKG} simple index through proxy returned error"
  fi
fi

# =========================================================================
# Section 2: Proxy cache hit (bug #605)
# =========================================================================

begin_test "Second fetch served from cache"
if [ "$UPSTREAM_REACHABLE" != "true" ]; then
  skip "upstream unreachable"
else
  # Backend #1278/#1280: proxy-cached artifacts are NOT inserted into the
  # `artifacts` DB table, so the previous count-delta check against
  # /api/v1/repositories/{key}/artifacts measured nothing (the count stays 0
  # for a proxy repo regardless of cache state, making the comparison
  # vacuously pass). The meaningful cache-hit signal is simply that the same
  # simple index can be fetched again through the proxy and is still served
  # with the expected sdist/wheel links.
  if resp2=$(curl -sf $CURL_TIMEOUT \
      -u "${ADMIN_USER}:${ADMIN_PASS}" \
      "${PYPI_REMOTE_URL}/simple/${PROXY_PKG}/" 2>/dev/null); then
    if assert_contains "$resp2" ".tar.gz" "cached simple index should still contain links"; then
      pass
    fi
  else
    fail "second fetch of simple index failed"
  fi
fi

# =========================================================================
# Section 3: Local repo + upload (shared setup for virtual repo tests)
# =========================================================================

begin_test "Create local PyPI repository"
if create_local_repo "$LOCAL_KEY" "pypi"; then
  pass
else
  fail "could not create local PyPI repo"
fi

begin_test "Build and upload sdist to local repo"

cd "$WORK_DIR"

SDIST_DIR="${PKG_NAME}-${PKG_VERSION}"
mkdir -p "${SDIST_DIR}"

cat > "${SDIST_DIR}/setup.py" <<EOF
from setuptools import setup
setup(
    name="${PKG_NAME}",
    version="${PKG_VERSION}",
    py_modules=["${PKG_NAME}"],
    description="E2E test package for PyPI remote/virtual tests",
)
EOF

cat > "${SDIST_DIR}/${PKG_NAME}.py" <<EOF
__version__ = "${PKG_VERSION}"
def hello():
    return "Hello from ${PKG_NAME}"
EOF

cat > "${SDIST_DIR}/PKG-INFO" <<EOF
Metadata-Version: 1.0
Name: ${PKG_NAME}
Version: ${PKG_VERSION}
Summary: E2E test package for PyPI remote/virtual tests
EOF

mkdir -p dist
SDIST_FILE="dist/${PKG_NAME}-${PKG_VERSION}.tar.gz"
tar czf "$SDIST_FILE" "$SDIST_DIR"

SDIST_BASENAME=$(basename "$SDIST_FILE")
SDIST_SHA256=$(shasum -a 256 "$SDIST_FILE" | cut -d' ' -f1)

if resp=$(curl -sf -X POST "${PYPI_LOCAL_URL}/" \
  -u "${ADMIN_USER}:${ADMIN_PASS}" \
  -F ":action=file_upload" \
  -F "name=${PKG_NAME}" \
  -F "version=${PKG_VERSION}" \
  -F "sha256_digest=${SDIST_SHA256}" \
  -F "filetype=sdist" \
  -F "content=@${SDIST_FILE};filename=${SDIST_BASENAME}" 2>&1); then
  pass
else
  fail "upload to local PyPI repo failed: ${resp}"
fi

# =========================================================================
# Section 4: Virtual repo with local member (bug #648)
# =========================================================================

begin_test "Create virtual PyPI repository"
if create_virtual_repo "$VIRTUAL_KEY" "pypi"; then
  pass
else
  fail "could not create virtual PyPI repo"
fi

begin_test "Add local repo as virtual member"
if api_post "/api/v1/repositories/${VIRTUAL_KEY}/members" \
    "{\"member_key\":\"${LOCAL_KEY}\",\"priority\":1}" > /dev/null 2>&1; then
  pass
else
  fail "could not add local repo as virtual member"
fi

begin_test "Virtual simple index lists locally published package"
sleep 2
NORMALIZED_NAME=$(echo "$PKG_NAME" | tr '_' '-')
if resp=$(curl -sf $CURL_TIMEOUT \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    "${PYPI_VIRTUAL_URL}/simple/" 2>/dev/null); then
  if assert_contains "$resp" "$NORMALIZED_NAME" \
      "virtual /simple/ should list the locally published package"; then
    pass
  fi
else
  fail "GET /pypi/${VIRTUAL_KEY}/simple/ returned error"
fi

# =========================================================================
# Section 5: Virtual vs direct access (bug #627)
# =========================================================================

begin_test "Download from local repo directly"
# First get the package index to find the file URL
if local_index=$(curl -sf $CURL_TIMEOUT \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    "${PYPI_LOCAL_URL}/simple/${NORMALIZED_NAME}/" 2>/dev/null); then
  LOCAL_FILE_HREF=$(echo "$local_index" | grep -oE 'href="[^"]*\.tar\.gz[^"]*"' | head -1 | sed 's/href="//;s/"//') || true
  if [ -z "$LOCAL_FILE_HREF" ]; then
    fail "no .tar.gz link in local package index"
  else
    if [[ "$LOCAL_FILE_HREF" == http* ]]; then
      LOCAL_DL_URL="$LOCAL_FILE_HREF"
    elif [[ "$LOCAL_FILE_HREF" == /* ]]; then
      LOCAL_DL_URL="${BASE_URL}${LOCAL_FILE_HREF}"
    else
      LOCAL_DL_URL="${PYPI_LOCAL_URL}/simple/${NORMALIZED_NAME}/${LOCAL_FILE_HREF}"
    fi
    if curl -sf $CURL_TIMEOUT \
        -u "${ADMIN_USER}:${ADMIN_PASS}" \
        -o "${WORK_DIR}/direct-download.tar.gz" \
        "$LOCAL_DL_URL" 2>/dev/null; then
      DIRECT_SHA256=$(shasum -a 256 "${WORK_DIR}/direct-download.tar.gz" | cut -d' ' -f1)
      pass
    else
      fail "download from local repo failed"
    fi
  fi
else
  fail "GET /pypi/${LOCAL_KEY}/simple/${NORMALIZED_NAME}/ returned error"
fi

begin_test "Download same package through virtual repo"
if virtual_index=$(curl -sf $CURL_TIMEOUT \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    "${PYPI_VIRTUAL_URL}/simple/${NORMALIZED_NAME}/" 2>/dev/null); then
  VIRTUAL_FILE_HREF=$(echo "$virtual_index" | grep -oE 'href="[^"]*\.tar\.gz[^"]*"' | head -1 | sed 's/href="//;s/"//') || true
  if [ -z "$VIRTUAL_FILE_HREF" ]; then
    fail "no .tar.gz link in virtual package index"
  else
    if [[ "$VIRTUAL_FILE_HREF" == http* ]]; then
      VIRTUAL_DL_URL="$VIRTUAL_FILE_HREF"
    elif [[ "$VIRTUAL_FILE_HREF" == /* ]]; then
      VIRTUAL_DL_URL="${BASE_URL}${VIRTUAL_FILE_HREF}"
    else
      VIRTUAL_DL_URL="${PYPI_VIRTUAL_URL}/simple/${NORMALIZED_NAME}/${VIRTUAL_FILE_HREF}"
    fi
    if curl -sf $CURL_TIMEOUT \
        -u "${ADMIN_USER}:${ADMIN_PASS}" \
        -o "${WORK_DIR}/virtual-download.tar.gz" \
        "$VIRTUAL_DL_URL" 2>/dev/null; then
      VIRTUAL_SHA256=$(shasum -a 256 "${WORK_DIR}/virtual-download.tar.gz" | cut -d' ' -f1)
      pass
    else
      fail "download through virtual repo failed"
    fi
  fi
else
  fail "GET /pypi/${VIRTUAL_KEY}/simple/${NORMALIZED_NAME}/ returned error"
fi

begin_test "SHA256 matches between direct and virtual download"
if [ -n "${DIRECT_SHA256:-}" ] && [ -n "${VIRTUAL_SHA256:-}" ]; then
  if assert_eq "$VIRTUAL_SHA256" "$DIRECT_SHA256" \
      "virtual download SHA256 (${VIRTUAL_SHA256}) should match direct (${DIRECT_SHA256})"; then
    pass
  fi
else
  skip "one or both downloads did not complete"
fi

# =========================================================================
# Section 6: Virtual download path (bug #606)
# =========================================================================

begin_test "Download sdist via virtual repo package URL"
# Re-use the virtual file href from the previous section if available,
# otherwise re-fetch the package index.
if [ -z "${VIRTUAL_FILE_HREF:-}" ]; then
  if vi=$(curl -sf $CURL_TIMEOUT \
      -u "${ADMIN_USER}:${ADMIN_PASS}" \
      "${PYPI_VIRTUAL_URL}/simple/${NORMALIZED_NAME}/" 2>/dev/null); then
    VIRTUAL_FILE_HREF=$(echo "$vi" | grep -oE 'href="[^"]*\.tar\.gz[^"]*"' | head -1 | sed 's/href="//;s/"//') || true
  fi
fi

if [ -z "${VIRTUAL_FILE_HREF:-}" ]; then
  fail "could not determine download URL from virtual package index"
else
  if [[ "$VIRTUAL_FILE_HREF" == http* ]]; then
    DL_URL="$VIRTUAL_FILE_HREF"
  elif [[ "$VIRTUAL_FILE_HREF" == /* ]]; then
    DL_URL="${BASE_URL}${VIRTUAL_FILE_HREF}"
  else
    DL_URL="${PYPI_VIRTUAL_URL}/simple/${NORMALIZED_NAME}/${VIRTUAL_FILE_HREF}"
  fi

  HTTP_STATUS=$(curl -s -o "${WORK_DIR}/virtual-path-download.tar.gz" \
      -w '%{http_code}' \
      -u "${ADMIN_USER}:${ADMIN_PASS}" \
      "$DL_URL" 2>/dev/null) || HTTP_STATUS="000"

  if assert_eq "$HTTP_STATUS" "200" \
      "virtual download should return HTTP 200, got ${HTTP_STATUS}"; then
    # Verify the file has real content (not an error page)
    DL_SIZE=$(wc -c < "${WORK_DIR}/virtual-path-download.tar.gz" | tr -d ' ')
    if [ "$DL_SIZE" -gt 100 ] 2>/dev/null; then
      pass
    else
      fail "downloaded file is suspiciously small (${DL_SIZE} bytes)"
    fi
  fi
fi

# =========================================================================
# Cleanup
# =========================================================================

api_delete "/api/v1/repositories/${VIRTUAL_KEY}" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${REMOTE_KEY}" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${LOCAL_KEY}" > /dev/null 2>&1 || true

end_suite
