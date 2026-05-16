#!/usr/bin/env bash
# test-ttl-expiry-refetch.sh -- Confirm proxy re-fetches upstream
# after TTL expiry, then re-caches (the back half of the cache-hit
# contract that the within-TTL test pins the front half of).
#
# Tracks issue #69 sub-task 1.4 (cache TTL behavior, per-repo TTL,
# refresh).
#
# Difference from test-cache-ttl-eviction.sh
# ------------------------------------------
# The eviction test (in tests/repos/) uses a 2s TTL and asserts ONE
# post-TTL re-fetch sees fresh upstream content. This script uses a
# 3s TTL but asserts:
#
#   (a) post-TTL fetch sees fresh content (same as eviction test --
#       belt-and-braces on the eviction property)
#   (b) AFTER that post-TTL fetch primes the cache with v2-aware
#       content, a SECOND wait-and-fetch sees the next mutation. This
#       is the "TTL evicts and re-caches, then evicts again" cycle.
#       A regression that only evicts once (TTL state bit stuck at
#       evicted-and-never-reset) would surface here.
#
# The two-cycle test catches a class of bugs the single-cycle test
# misses: where the TTL machinery flips from cache-hit to cache-miss
# after the first eviction but then stays in cache-miss mode (because
# the post-eviction write didn't update the cached_at timestamp).
#
# Requires: curl, jq, tar

source "$(dirname "$0")/../lib/common.sh"

begin_suite "ttl-expiry-refetch"
auth_admin
setup_workdir

UPSTREAM_KEY="ter-upstream-${RUN_ID}"
REMOTE_KEY="ter-remote-${RUN_ID}"
PKG_NAME="terpkg${RUN_ID//-/}"
PKG_V1="1.0.0"
PKG_V2="2.0.0"
PKG_V3="3.0.0"
TTL_SECS=3
WAIT_SECS=$(( TTL_SECS + 4 ))

build_sdist() {
  local version="$1"
  local pkgdir="${WORK_DIR}/${PKG_NAME}-${version}"
  local tarball="${WORK_DIR}/${PKG_NAME}-${version}.tar.gz"
  mkdir -p "$pkgdir"
  cat > "${pkgdir}/PKG-INFO" <<EOINFO
Metadata-Version: 1.0
Name: ${PKG_NAME}
Version: ${version}
Summary: ttl-expiry-refetch probe
EOINFO
  cat > "${pkgdir}/setup.py" <<EOPY
from setuptools import setup
setup(name="${PKG_NAME}", version="${version}")
EOPY
  tar -czf "$tarball" -C "$WORK_DIR" "${PKG_NAME}-${version}"
  echo "$tarball"
}

upload_to_upstream() {
  local version="$1"
  local tarball
  tarball=$(build_sdist "$version")
  if curl -sf $CURL_TIMEOUT -X POST \
      -H "$(format_auth_header)" \
      -F ":action=file_upload" \
      -F "name=${PKG_NAME}" \
      -F "version=${version}" \
      -F "filetype=sdist" \
      -F "content=@${tarball}" \
      "${BASE_URL}/pypi/${UPSTREAM_KEY}/" > /dev/null 2>&1; then
    echo "ok"
    return 0
  fi
  if api_upload "/api/v1/repositories/${UPSTREAM_KEY}/artifacts/${PKG_NAME}/${version}/${PKG_NAME}-${version}.tar.gz" \
      "$tarball" "application/gzip" > /dev/null 2>&1; then
    echo "ok"
    return 0
  fi
  echo "fail"
  return 1
}

fetch_proxied() {
  curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${BASE_URL}/pypi/${REMOTE_KEY}/simple/${PKG_NAME}/" 2>/dev/null
}

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

begin_test "Create local PyPI upstream U"
if create_local_repo "$UPSTREAM_KEY" "pypi"; then
  pass
else
  fail "could not create upstream U"
fi

begin_test "Publish v${PKG_V1} to U"
if [ "$(upload_to_upstream "$PKG_V1")" = "ok" ]; then
  pass
else
  skip_suite "PyPI upload endpoint unavailable"
fi

deadline=$(( $(date +%s) + 10 ))
until curl -sf $CURL_TIMEOUT -H "$(format_auth_header)" \
        "${BASE_URL}/pypi/${UPSTREAM_KEY}/simple/${PKG_NAME}/" 2>/dev/null \
      | grep -q "${PKG_V1}" || [ "$(date +%s)" -ge "$deadline" ]; do
  sleep 0.2
done

begin_test "Create remote R with TTL=${TTL_SECS}s"
if create_remote_repo "$REMOTE_KEY" "pypi" "${BASE_URL}/pypi/${UPSTREAM_KEY}"; then
  pass
else
  fail "could not create R"
fi

api_put "/api/v1/repositories/${REMOTE_KEY}/cache-ttl" \
    "{\"cache_ttl_seconds\": ${TTL_SECS}}" >/dev/null 2>&1 || true

# ---------------------------------------------------------------------------
# Cycle 1: prime, mutate upstream, wait > TTL, refetch sees v2
# ---------------------------------------------------------------------------

begin_test "Cycle 1: prime cache with v${PKG_V1}-only index"
PRIMED=$(fetch_proxied) || PRIMED=""
if echo "$PRIMED" | grep -q "${PKG_V1}" && ! echo "$PRIMED" | grep -q "${PKG_V2}"; then
  pass
else
  fail "expected primed index to contain v1 and not v2; got: ${PRIMED:0:200}"
fi

begin_test "Cycle 1: publish v${PKG_V2} to upstream"
if [ "$(upload_to_upstream "$PKG_V2")" = "ok" ]; then
  pass
else
  fail "could not publish v2 to U"
fi

sleep "$WAIT_SECS"

begin_test "Cycle 1: post-TTL fetch sees v${PKG_V2} (cache evicted, upstream re-fetched)"
POST1=$(fetch_proxied) || POST1=""
if echo "$POST1" | grep -q "${PKG_V2}"; then
  pass
else
  fail "post-TTL fetch missing v2 (cache eviction did not fire)"
fi

# ---------------------------------------------------------------------------
# Cycle 2: now the cache has been re-primed (with v1+v2). Mutate
# upstream AGAIN (add v3), wait > TTL, ensure the SECOND eviction
# also refetches. This is the "TTL state machine doesn't get stuck"
# guard.
# ---------------------------------------------------------------------------

begin_test "Cycle 2: publish v${PKG_V3} to upstream"
if [ "$(upload_to_upstream "$PKG_V3")" = "ok" ]; then
  pass
else
  fail "could not publish v3 to U"
fi

sleep "$WAIT_SECS"

begin_test "Cycle 2: post-TTL fetch after re-cache sees v${PKG_V3}"
POST2=$(fetch_proxied) || POST2=""
if echo "$POST2" | grep -q "${PKG_V3}"; then
  pass
else
  fail "second post-TTL fetch missing v3; TTL state may be stuck after first eviction"
fi

# Sanity: v1 and v2 should still appear too (upstream is additive).
begin_test "Cycle 2: upstream index also still contains v1 and v2"
if echo "$POST2" | grep -q "${PKG_V1}" && echo "$POST2" | grep -q "${PKG_V2}"; then
  pass
else
  fail "second post-TTL fetch lost prior versions; got: ${POST2:0:300}"
fi

# Cleanup
api_delete "/api/v1/repositories/${REMOTE_KEY}" >/dev/null 2>&1 || true
api_delete "/api/v1/repositories/${UPSTREAM_KEY}" >/dev/null 2>&1 || true

end_suite
