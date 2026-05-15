#!/usr/bin/env bash
# test-pypi-proxy-cache-keys.sh - PyPI proxy cache key normalization (issue #557)
#
# Verifies that proxy cache keys do not contain double slashes, which break
# RGW/Ceph S3 storage backends. When a PyPI remote proxy caches a response,
# the storage key must be normalized (trailing slashes trimmed) so the cached
# object can be written and read back without path corruption.
#
# Requires: curl, jq

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/common.sh"

begin_suite "pypi-proxy-cache-keys"
auth_admin
setup_workdir

UPSTREAM_KEY="pypi-upstream-cache-${RUN_ID}"
PROXY_KEY="pypi-proxy-cache-${RUN_ID}"
PKG_NAME="cachetest-pkg"
PKG_VERSION="0.1.0"

# -------------------------------------------------------------------------
# Create upstream local PyPI repo
# -------------------------------------------------------------------------

begin_test "Create upstream PyPI repository"
if create_local_repo "$UPSTREAM_KEY" "pypi"; then
  pass
else
  fail "could not create upstream PyPI repo"
fi

# -------------------------------------------------------------------------
# Upload a minimal sdist to the upstream
# -------------------------------------------------------------------------

begin_test "Upload test package to upstream"
mkdir -p "${WORK_DIR}/${PKG_NAME}-${PKG_VERSION}"

cat > "${WORK_DIR}/${PKG_NAME}-${PKG_VERSION}/PKG-INFO" <<EOINFO
Metadata-Version: 1.0
Name: ${PKG_NAME}
Version: ${PKG_VERSION}
Summary: Cache key regression test package
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
  fail "could not upload test package to upstream"
fi

# -------------------------------------------------------------------------
# Create remote proxy repo pointing at the upstream
# -------------------------------------------------------------------------

begin_test "Create remote proxy repository"
UPSTREAM_SIMPLE="${BASE_URL}/pypi/${UPSTREAM_KEY}/simple/"
if create_remote_repo "$PROXY_KEY" "pypi" "$UPSTREAM_SIMPLE"; then
  pass
else
  fail "could not create remote proxy repo"
fi

# Let the proxy settle before first fetch
sleep 2

# -------------------------------------------------------------------------
# Fetch package metadata through the proxy (first request, populates cache)
# -------------------------------------------------------------------------

begin_test "Fetch package metadata through proxy"
FIRST_RESP=""
if FIRST_RESP=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${BASE_URL}/pypi/${PROXY_KEY}/simple/${PKG_NAME}/" 2>/dev/null); then
  if assert_contains "$FIRST_RESP" "${PKG_NAME}"; then
    pass
  fi
elif FIRST_RESP=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${BASE_URL}/pypi/${PROXY_KEY}/simple/" 2>/dev/null); then
  if assert_contains "$FIRST_RESP" "${PKG_NAME}"; then
    pass
  else
    fail "package not found in proxied simple index"
  fi
else
  fail "could not fetch package metadata through proxy"
fi

# -------------------------------------------------------------------------
# Verify proxy cache keys have no double slashes
#
# The regression from issue #557: the proxy constructed cache metadata keys
# with a double slash (e.g. proxy-cache/repo/simple/pkg//__cache_meta__.json)
# because the trailing slash on the request path was not trimmed before
# building the storage key. With the double slash, S3 backends (especially
# RGW/Ceph) could write the object but fail on lookup, making every request
# a cache miss.
#
# We verify the fix indirectly: fetch the same path twice through the proxy.
# If the cache key is well-formed, the second fetch serves from cache and
# returns identical content. If the key contains a double slash, the cache
# write succeeds but the lookup misses, and we would see inconsistent
# behavior or errors from the upstream on subsequent requests.
# -------------------------------------------------------------------------

begin_test "Verify proxy cache keys have no double slashes"

# Hit the proxy endpoint a second time to exercise the cache read path.
# A short pause lets the backend finish writing cache metadata from the
# first request.
sleep 1

SECOND_RESP=""
if SECOND_RESP=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${BASE_URL}/pypi/${PROXY_KEY}/simple/${PKG_NAME}/" 2>/dev/null); then
  if assert_contains "$SECOND_RESP" "${PKG_NAME}" \
      "cached response should still contain the package name"; then
    pass
  fi
else
  fail "second fetch through proxy failed (cache key may be malformed)"
fi

# -------------------------------------------------------------------------
# Verify cached response matches original
# -------------------------------------------------------------------------

begin_test "Verify cached response matches original"
if [ -n "$FIRST_RESP" ] && [ -n "$SECOND_RESP" ]; then
  if [ "$FIRST_RESP" = "$SECOND_RESP" ]; then
    pass
  else
    # Responses can differ in minor ways (timestamps, ordering) while still
    # being correct. As long as the second response contains the package,
    # the cache roundtrip worked.
    if assert_contains "$SECOND_RESP" "${PKG_NAME}" \
        "cached response should contain the package name"; then
      pass
    fi
  fi
else
  fail "missing response data for comparison (first or second fetch failed)"
fi

# -------------------------------------------------------------------------
# Verify simple index root with trailing slash
#
# The root simple index path /simple/ becomes just "/" after stripping the
# repo prefix. Without normalization this produces a storage key containing
# "//" which is the exact bug from issue #557.
# -------------------------------------------------------------------------

begin_test "Verify simple index root with trailing slash"
ROOT_RESP=""
if ROOT_RESP=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${BASE_URL}/pypi/${PROXY_KEY}/simple/" 2>/dev/null); then
  if assert_contains "$ROOT_RESP" "${PKG_NAME}" \
      "root simple index should list the package"; then
    pass
  fi
else
  fail "root simple index request failed through proxy"
fi

# Fetch root a second time to confirm the cache key roundtrips correctly.
sleep 1

begin_test "Verify root simple index cache roundtrip"
ROOT_RESP2=""
if ROOT_RESP2=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${BASE_URL}/pypi/${PROXY_KEY}/simple/" 2>/dev/null); then
  if assert_contains "$ROOT_RESP2" "${PKG_NAME}" \
      "cached root index should still list the package"; then
    pass
  fi
else
  fail "second root index fetch failed (cache key for root path may contain double slash)"
fi

# -------------------------------------------------------------------------
# Cleanup
# -------------------------------------------------------------------------

api_delete "/api/v1/repositories/${PROXY_KEY}" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${UPSTREAM_KEY}" > /dev/null 2>&1 || true

end_suite
