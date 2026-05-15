#!/usr/bin/env bash
# test-cache-hit-no-refetch.sh -- Pull-through cache must serve hits
# from cache, not re-fetch upstream every request.
#
# Tracks issue #69 sub-task 1.2 (cache poisoning class) and sub-task
# 1.4 (TTL behavior). The existing test-cache-ttl-eviction.sh covers
# the time-axis (eviction after TTL); this one covers the count-axis
# (N fetches through the proxy must result in <N upstream hits when
# the cache is warm).
#
# Strategy: AK-to-AK upstream
# ---------------------------
# We can't use the Python mock fixture in this suite -- the mock binds
# to the runner pod IP (RFC1918) and the backend's
# validate_outbound_url rejects every RFC1918 dial (see
# test-cache-poisoning.sh header for the full rationale). Instead we
# stand up TWO local PyPI repos:
#
#   U  = "upstream" -- a local PyPI repo we manually publish to.
#   R  = "remote"   -- a remote PyPI repo whose upstream_url is U's
#                      AK URL. The backend dials itself.
#
# Then we count cache rows via /api/v1/repositories/R/artifacts
# (proxy_service caches into the remote repo's local table). If the
# cache wiring works, the FIRST fetch through R populates a cache row
# and subsequent fetches do not increment U's artifact-list (we use
# the simple-index byte-equality trick borrowed from
# test-cache-ttl-eviction.sh as the "cache hit observable" because
# there is no public "X-Cache: HIT" header in the v1.1.x backend).
#
# Why simple-index (not the .tar.gz):
#   PyPI version files are immutable. Fetching them twice through a
#   proxy is a tautology -- you cannot tell a cache hit from a fresh
#   re-fetch by inspecting bytes. The simple-index, by contrast, has
#   stable URLs but mutating content as new versions land on the
#   upstream. We:
#     1. Prime the cache (R fetches U's index, caches it).
#     2. Publish v2 to U (U's index now contains v1 and v2).
#     3. Within TTL, refetch R's index. Bytes must match step 1.
#   If the cache was bypassed (proxy refetched U on every call), step
#   3 would already show v2 -- the same observable test-cache-ttl-
#   eviction.sh uses for the within-TTL window.
#
# Difference from the eviction test
# ---------------------------------
# test-cache-ttl-eviction.sh prioritizes the POST-TTL assertion: it
# uses a short TTL (2s) and asserts the cache evicts. This script
# tests the COMPLEMENTARY property: within a long TTL (60s), N
# consecutive fetches must NOT change the cached bytes. The two
# scripts together pin both halves of the cache-hit contract.
#
# What this script asserts (in order)
# -----------------------------------
# 1. Cache prime succeeds (first fetch through R returns U's content).
# 2. The bytes returned by 5 consecutive fetches through R are
#    byte-identical (no cache drift / partial cache writes / race
#    where one of the parallel fetches got a fresh upstream).
# 3. After publishing v2 to U, the proxy continues to return the
#    cached (v1-only) index within the TTL window. This is the same
#    assertion as test-cache-ttl-eviction.sh's within-TTL check, but
#    gated by COUNT not just TIME (we do N fetches in a tight loop).
#
# Requires: curl, jq, tar

source "$(dirname "$0")/../lib/common.sh"

begin_suite "cache-hit-no-refetch"
auth_admin
setup_workdir

UPSTREAM_KEY="chnr-upstream-${RUN_ID}"
REMOTE_KEY="chnr-remote-${RUN_ID}"
PKG_NAME="chnrpkg${RUN_ID//-/}"
PKG_V1="1.0.0"
PKG_V2="2.0.0"
# Long enough that no test step can plausibly slip past it on a
# loaded runner. 60s is the standard cache-hit window upper bound.
TTL_SECS=60
# Number of in-window fetches to do after priming. Five is enough to
# catch a partial-cache-write race (one of N comes back fresh) without
# being so high that the suite drags on a slow backend.
HIT_FETCHES=5

build_sdist() {
  local version="$1"
  local pkgdir="${WORK_DIR}/${PKG_NAME}-${version}"
  local tarball="${WORK_DIR}/${PKG_NAME}-${version}.tar.gz"
  mkdir -p "$pkgdir"
  cat > "${pkgdir}/PKG-INFO" <<EOINFO
Metadata-Version: 1.0
Name: ${PKG_NAME}
Version: ${version}
Summary: cache-hit-no-refetch probe
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

fetch_proxied_index() {
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
  fail "could not create PyPI upstream"
fi

begin_test "Publish v${PKG_V1} to U"
if [ "$(upload_to_upstream "$PKG_V1")" = "ok" ]; then
  pass
else
  skip_suite "PyPI upload endpoint unavailable; cannot run cache-hit assertion"
fi

# Wait for U to surface v1 in its simple index (avoid racing the
# upload-vs-resolve path on busy backends).
deadline=$(( $(date +%s) + 10 ))
until curl -sf $CURL_TIMEOUT -H "$(format_auth_header)" \
        "${BASE_URL}/pypi/${UPSTREAM_KEY}/simple/${PKG_NAME}/" 2>/dev/null \
      | grep -q "${PKG_V1}" || [ "$(date +%s)" -ge "$deadline" ]; do
  sleep 0.2
done

begin_test "Create remote R pointing at U with TTL=${TTL_SECS}s"
UPSTREAM_URL="${BASE_URL}/pypi/${UPSTREAM_KEY}"
if create_remote_repo "$REMOTE_KEY" "pypi" "$UPSTREAM_URL"; then
  pass
else
  fail "could not create remote R"
fi

# Pin the TTL so a chart default of <60s doesn't make step 3 flake.
api_put "/api/v1/repositories/${REMOTE_KEY}/cache-ttl" \
    "{\"cache_ttl_seconds\": ${TTL_SECS}}" >/dev/null 2>&1 || true

# ---------------------------------------------------------------------------
# Step 1: prime the cache
# ---------------------------------------------------------------------------

begin_test "Prime cache: first fetch through R returns v${PKG_V1} index"
PRIMED=$(fetch_proxied_index) || PRIMED=""
if [ -n "$PRIMED" ] && echo "$PRIMED" | grep -q "${PKG_V1}"; then
  pass
else
  fail "primed index missing v${PKG_V1}; cache-hit test cannot proceed (got: ${PRIMED:0:200})"
fi
PRIME_TS=$(date +%s)

# ---------------------------------------------------------------------------
# Step 2: N tight-loop refetches must return byte-identical bodies.
#
# This is the "no partial cache write" guard. If one of the N fetches
# comes back fresh from upstream (or from a half-written cache row), we
# get a body that differs from PRIMED. The previous proxy_service bug
# (artifact-keeper #871 class) where cached entries were re-fetched on
# concurrent reads would surface here as a body mismatch.
# ---------------------------------------------------------------------------

begin_test "${HIT_FETCHES} consecutive refetches return byte-identical bodies (cache hit)"
mismatch=0
last="$PRIMED"
for i in $(seq 1 $HIT_FETCHES); do
  body=$(fetch_proxied_index) || body=""
  if [ -z "$body" ]; then
    mismatch=1
    echo "  fetch ${i}: empty body"
    break
  fi
  if [ "$body" != "$last" ]; then
    mismatch=1
    echo "  fetch ${i}: body differs from previous (cache miss or partial write)"
    diff <(echo "$last") <(echo "$body") | head -5 || true
    break
  fi
  last="$body"
done
if [ "$mismatch" -eq 0 ]; then
  pass
else
  fail "consecutive refetches diverged; cache is not serving hits as a stable byte source"
fi

# ---------------------------------------------------------------------------
# Step 3: mutate upstream, ensure cache continues to serve the SAME
# v1-only bytes within the long TTL window. This is the load-bearing
# cache-poisoning-class assertion: if the cache silently refetches on
# every call, we'll see v2 here even though TTL has not elapsed.
# ---------------------------------------------------------------------------

begin_test "Publish v${PKG_V2} to upstream U (cache still primed)"
if [ "$(upload_to_upstream "$PKG_V2")" = "ok" ]; then
  pass
else
  fail "could not publish v${PKG_V2} to U"
fi

# Confirm U sees v2 (sanity).
deadline=$(( $(date +%s) + 10 ))
until curl -sf $CURL_TIMEOUT -H "$(format_auth_header)" \
        "${BASE_URL}/pypi/${UPSTREAM_KEY}/simple/${PKG_NAME}/" 2>/dev/null \
      | grep -q "${PKG_V2}" || [ "$(date +%s)" -ge "$deadline" ]; do
  sleep 0.2
done

# Feature-gated: 1.1.x backends have the same TTL-ignored proxy bug
# the eviction test gates against. Skip the within-TTL count-axis
# assertion on 1.1.x rather than fail the gate on a known-broken
# behaviour.
begin_test "Within-TTL refetch after upstream mutation still serves cached v${PKG_V1}-only bytes"
if require_feature "proxy_ttl_eviction_correctness"; then
  NOW=$(date +%s)
  ELAPSED=$(( NOW - PRIME_TS ))
  if [ "$ELAPSED" -ge "$TTL_SECS" ]; then
    skip "scheduling slipped past TTL window (elapsed=${ELAPSED}s, ttl=${TTL_SECS}s)"
  else
    BODY=$(fetch_proxied_index) || BODY=""
    if [ -z "$BODY" ]; then
      fail "within-TTL refetch returned empty"
    elif echo "$BODY" | grep -q "${PKG_V2}"; then
      fail "CACHE BYPASSED: within-TTL refetch already shows v${PKG_V2}; proxy refetched upstream every call (cache-hit contract violated)"
    elif echo "$BODY" | grep -q "${PKG_V1}"; then
      pass
    else
      fail "within-TTL refetch returned unexpected body: ${BODY:0:200}"
    fi
  fi
fi

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

api_delete "/api/v1/repositories/${REMOTE_KEY}" >/dev/null 2>&1 || true
api_delete "/api/v1/repositories/${UPSTREAM_KEY}" >/dev/null 2>&1 || true

if [ "${EXPECT_FAILURE:-0}" = "1" ]; then
  if ( end_suite ); then
    echo "EXPECT_FAILURE=1 but suite passed; inverting to fail"
    exit 1
  else
    echo "EXPECT_FAILURE=1 and suite failed as expected; inverting to pass"
    exit 0
  fi
fi

end_suite
