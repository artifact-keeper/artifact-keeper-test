#!/usr/bin/env bash
# test-proxy-cache-stats.sh - System stats report proxy-cache totals
# (artifact-keeper#3087, fixed by artifact-keeper#3088, ships in v1.7.1)
#
# Regression: proxy-cached (pull-through) objects live in the separate
# proxy_cache_artifacts catalog, not the artifacts table, so the system
# stats endpoint silently excluded them. An instance used mostly as a
# pull-through cache reported near-zero storage and artifact counts. The
# #3088 fix adds proxy_artifact_count and proxy_storage_bytes to
# GET /api/v1/admin/stats.
#
# Strategy: AK-to-AK upstream
# ---------------------------
# Same rationale as test-cache-hit-no-refetch.sh: the Python mock fixture
# binds to a runner-pod RFC1918 address the backend's outbound-URL
# validation rejects, and required tiers must not dial external networks.
# We stand up a local PyPI repo U as the upstream, publish a small sdist
# to it, then create a remote repo R whose upstream_url is U's AK URL and
# pull the sdist through R. The cache write lands a proxy_cache_artifacts
# row, which the stats endpoint must now report.
#
# Assertions (in order):
#   1. The stats response carries the new proxy_cache fields
#      (proxy_artifact_count, proxy_storage_bytes) as numbers.
#   2. Pulling a package through R produces a cache row in R.
#   3. After the pull, stats report proxy_artifact_count >= 1 and
#      proxy_storage_bytes >= 1. The table is a whole-DB aggregate shared
#      with parallel suites, so the assertion is ">= 1 with our own row
#      confirmed present", not an exact delta.
#
# Requires: curl, jq, tar

source "$(dirname "$0")/../lib/common.sh"

begin_suite "proxy-cache-stats"
auth_admin
setup_workdir

begin_test "Backend reports proxy-cache stats (artifact-keeper#3088)"
require_feature "system_stats_proxy_cache" || { end_suite; exit 0; }
pass

UPSTREAM_KEY="pcs-upstream-${RUN_ID}"
REMOTE_KEY="pcs-remote-${RUN_ID}"
PKG_NAME="pcspkg${RUN_ID//-/}"
PKG_VERSION="1.0.0"
SDIST_BASENAME="${PKG_NAME}-${PKG_VERSION}.tar.gz"
STATS_PATH="/api/v1/admin/stats"

# ---------------------------------------------------------------------------
# Assertion 1: schema carries the new fields
# ---------------------------------------------------------------------------

begin_test "GET ${STATS_PATH} exposes numeric proxy_artifact_count and proxy_storage_bytes"
if resp=$(api_get_with_retry "$STATS_PATH"); then
  count_type=$(echo "$resp" | jq -r '.proxy_artifact_count | type' 2>/dev/null) || count_type=""
  bytes_type=$(echo "$resp" | jq -r '.proxy_storage_bytes | type' 2>/dev/null) || bytes_type=""
  if [ "$count_type" = "number" ] && [ "$bytes_type" = "number" ]; then
    pass
  else
    fail "stats response missing numeric proxy-cache fields (proxy_artifact_count=${count_type:-absent}, proxy_storage_bytes=${bytes_type:-absent})" "${resp:0:400}"
  fi
else
  fail "GET ${STATS_PATH} returned error"
fi

# ---------------------------------------------------------------------------
# Setup: upstream U with one published sdist, remote R pointing at U
# ---------------------------------------------------------------------------

begin_test "Create local PyPI upstream U and publish v${PKG_VERSION}"
pkgdir="${WORK_DIR}/${PKG_NAME}-${PKG_VERSION}"
mkdir -p "$pkgdir"
cat > "${pkgdir}/PKG-INFO" <<EOF
Metadata-Version: 1.0
Name: ${PKG_NAME}
Version: ${PKG_VERSION}
Summary: proxy-cache stats probe
EOF
cat > "${pkgdir}/setup.py" <<EOF
from setuptools import setup
setup(name="${PKG_NAME}", version="${PKG_VERSION}")
EOF
SDIST_FILE="${WORK_DIR}/${SDIST_BASENAME}"
tar -czf "$SDIST_FILE" -C "$WORK_DIR" "${PKG_NAME}-${PKG_VERSION}" || true
if ! create_local_repo "$UPSTREAM_KEY" "pypi"; then
  fail "could not create PyPI upstream"
elif curl -sf $CURL_TIMEOUT -X POST \
    -H "$(format_auth_header)" \
    -F ":action=file_upload" \
    -F "name=${PKG_NAME}" \
    -F "version=${PKG_VERSION}" \
    -F "filetype=sdist" \
    -F "content=@${SDIST_FILE}" \
    "${BASE_URL}/pypi/${UPSTREAM_KEY}/" > /dev/null 2>&1; then
  pass
else
  fail "could not publish sdist to upstream U"
fi

begin_test "Create remote R pointing at U"
if create_remote_repo "$REMOTE_KEY" "pypi" "${BASE_URL}/pypi/${UPSTREAM_KEY}"; then
  pass
else
  fail "could not create remote R"
fi

# ---------------------------------------------------------------------------
# Assertion 2: pull through R and confirm a cache row exists
# ---------------------------------------------------------------------------

begin_test "Pull sdist through R (pull-through cache write)"
# Warm the index first so the proxy has resolved the project, then fetch
# the package file itself; the file bytes are what land in the cache
# catalog with a real size.
curl -sf $CURL_TIMEOUT -H "$(format_auth_header)" \
  "${BASE_URL}/pypi/${REMOTE_KEY}/simple/${PKG_NAME}/" > /dev/null 2>&1 || true
pull_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  "${BASE_URL}/pypi/${REMOTE_KEY}/simple/${PKG_NAME}/${SDIST_BASENAME}" 2>/dev/null) || pull_status="000"
if assert_http_2xx "$pull_status" "pull through remote R failed"; then
  pass
fi

begin_test "Cache row for the pulled sdist appears in R"
cached=0
deadline=$(( $(date +%s) + 20 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  rows=$(api_get "/api/v1/repositories/${REMOTE_KEY}/artifacts" 2>/dev/null) || rows=""
  if [ -n "$rows" ] && echo "$rows" | grep -q "$PKG_NAME"; then
    cached=1
    break
  fi
  sleep 2
done
if [ "$cached" -eq 1 ]; then
  pass
else
  fail "no cache row for ${PKG_NAME} appeared in ${REMOTE_KEY} within 20s"
fi

# ---------------------------------------------------------------------------
# Assertion 3: stats reflect the cached object
# ---------------------------------------------------------------------------

begin_test "Stats report nonzero proxy-cache totals after pull-through"
proxy_count=0
proxy_bytes=0
deadline=$(( $(date +%s) + 20 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  resp=$(api_get "$STATS_PATH" 2>/dev/null) || resp=""
  proxy_count=$(echo "$resp" | jq -r '.proxy_artifact_count // 0' 2>/dev/null) || proxy_count=0
  proxy_bytes=$(echo "$resp" | jq -r '.proxy_storage_bytes // 0' 2>/dev/null) || proxy_bytes=0
  if [ "$proxy_count" -ge 1 ] 2>/dev/null && [ "$proxy_bytes" -ge 1 ] 2>/dev/null; then
    break
  fi
  sleep 2
done
if [ "$proxy_count" -ge 1 ] 2>/dev/null && [ "$proxy_bytes" -ge 1 ] 2>/dev/null; then
  pass
else
  fail "stats did not reflect the cached object (proxy_artifact_count=${proxy_count}, proxy_storage_bytes=${proxy_bytes}); pre-#3088 backends omit proxy-cache rows from system stats"
fi

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

api_delete "/api/v1/repositories/${REMOTE_KEY}" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${UPSTREAM_KEY}" > /dev/null 2>&1 || true

end_suite
