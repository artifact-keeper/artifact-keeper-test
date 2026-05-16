#!/usr/bin/env bash
# test-stale-on-upstream-error.sh -- Serve stale cached artifact when
# upstream is unreachable (issue #69 sub-task 1.3).
#
# What this asserts
# -----------------
# When the proxy_service upstream fetch errors out, the backend MUST
# fall back to a stale cached copy via get_stale_cached_artifact rather
# than propagating 502/504 to the client. The wiring lives in
# backend/src/services/proxy_service.rs:175-198 (the Err arm of the
# match on the upstream fetch result calls get_stale_cached_artifact
# at line 186; success returns the stale copy, failure surfaces the
# original upstream_err).
#
# This is the load-bearing reliability contract: when an upstream goes
# down, downstream builds should NOT cliff-fall to all-red. This is
# what customers cite in artifact-keeper#872: "the cache works until
# it doesn't, and when it doesn't we lose the day."
#
# Strategy: AK-to-AK upstream with a forced upstream failure
# ----------------------------------------------------------
# We can't use the Python mock fixture (RFC1918 SSRF reject, see
# tests/security/test-cache-poisoning.sh for the full rationale).
# Instead we use the same AK-to-AK pattern as test-cache-hit-no-refetch.sh
# and force the upstream-error branch by DELETING the upstream repo
# after the cache has been primed. The next fetch through R triggers
# the upstream-error path because the backend will get a 404 from its
# own /pypi/<deleted-key>/simple/<pkg>/ route, and proxy_service will
# fall back to the stale cached row in R's cache table.
#
# What we assert, in order:
#   1. Prime cache: fetch through R, cache row written, body contains
#      the package we just published to U.
#   2. Delete U from the backend (upstream now permanently unavailable
#      from the proxy's perspective).
#   3. Re-fetch through R. Client MUST see HTTP 2xx (NOT 502/504/5xx),
#      and the body MUST contain the same package the cache was primed
#      with. This is the load-bearing assertion: any non-2xx or any
#      empty body here means stale-on-error did NOT kick in.
#   4. Optional bonus: if the backend exposes X-Cache: STALE on the
#      stale-served response (proxy_service.rs:983 emits it for the
#      stale-while-revalidate branch; the stale-on-error branch may or
#      may not), record it but do not gate on it.
#
# Caveats / non-assertions
# ------------------------
# - We use upstream DELETE (not a kill -STOP or transient network
#   blip) because the test environment does not give us per-repo
#   network controls. Both paths exercise the same proxy_service.rs
#   Err arm; DELETE is the most deterministic way to force it.
# - We do NOT assert anything about TTL state here. The TTL eviction
#   tests (test-cache-ttl-eviction.sh, test-ttl-expiry-refetch.sh)
#   own that surface. This script only asserts the upstream-down
#   reliability property within a long TTL window where eviction
#   cannot interfere.
# - get_stale_cached_artifact (proxy_service.rs:853) returns Option;
#   if the cache row was never written (prime step silently no-op'd),
#   the post-delete fetch falls through to upstream_err and we'd see
#   5xx. We assert PRIMED is non-empty before deleting U to defend
#   against that confounder.
#
# Requires: curl, jq, tar

source "$(dirname "$0")/../lib/common.sh"

begin_suite "stale-on-upstream-error"
auth_admin
setup_workdir

UPSTREAM_KEY="stale-up-${RUN_ID}"
REMOTE_KEY="stale-rem-${RUN_ID}"
PKG_NAME="stalepkg${RUN_ID//-/}"
PKG_VERSION="1.0.0"
# Long TTL so eviction cannot interfere with the stale-on-error path.
TTL_SECS=300

cleanup_repos() {
  api_delete "/api/v1/repositories/${REMOTE_KEY}" >/dev/null 2>&1 || true
  api_delete "/api/v1/repositories/${UPSTREAM_KEY}" >/dev/null 2>&1 || true
}
add_exit_handler "cleanup_repos"

build_sdist() {
  local version="$1"
  local pkgdir="${WORK_DIR}/${PKG_NAME}-${version}"
  local tarball="${WORK_DIR}/${PKG_NAME}-${version}.tar.gz"
  mkdir -p "$pkgdir"
  cat > "${pkgdir}/PKG-INFO" <<EOINFO
Metadata-Version: 1.0
Name: ${PKG_NAME}
Version: ${version}
Summary: stale-on-upstream-error probe
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

# fetch_proxied_index_with_status: GET the proxied simple-index and
# emit "<status>|<body>" on stdout. Two-channel return is needed
# because the load-bearing assertion checks BOTH (status must be 2xx
# AND body must be non-empty).
fetch_proxied_index_with_status() {
  local body_file="${WORK_DIR}/fetch-body.$$"
  local headers_file="${WORK_DIR}/fetch-headers.$$"
  local status
  status=$(curl -s -o "$body_file" -D "$headers_file" -w '%{http_code}' \
    $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${BASE_URL}/pypi/${REMOTE_KEY}/simple/${PKG_NAME}/" 2>/dev/null) || status="000"
  local body
  body=$(cat "$body_file" 2>/dev/null || echo "")
  rm -f "$body_file" "$headers_file"
  echo "${status}|${body}"
}

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

begin_test "Create local PyPI upstream U"
if create_local_repo "$UPSTREAM_KEY" "pypi"; then
  pass
else
  fail "could not create PyPI upstream U"
fi

begin_test "Publish v${PKG_VERSION} to U"
if [ "$(upload_to_upstream "$PKG_VERSION")" = "ok" ]; then
  pass
else
  skip_suite "PyPI upload endpoint unavailable; stale-on-error test cannot proceed"
fi

# Make sure U surfaces the package before R tries to proxy through it.
# Without this wait, a slow indexer can make the cache prime cache an
# EMPTY index, which would then defeat the stale-on-error assertion
# (you can't serve a stale copy of nothing).
deadline=$(( $(date +%s) + 15 ))
until curl -sf $CURL_TIMEOUT -H "$(format_auth_header)" \
        "${BASE_URL}/pypi/${UPSTREAM_KEY}/simple/${PKG_NAME}/" 2>/dev/null \
      | grep -q "${PKG_VERSION}" || [ "$(date +%s)" -ge "$deadline" ]; do
  sleep 0.3
done

begin_test "Create remote R pointing at U with TTL=${TTL_SECS}s"
if create_remote_repo "$REMOTE_KEY" "pypi" "${BASE_URL}/pypi/${UPSTREAM_KEY}"; then
  api_put "/api/v1/repositories/${REMOTE_KEY}/cache-ttl" \
      "{\"cache_ttl_seconds\": ${TTL_SECS}}" >/dev/null 2>&1 || true
  pass
else
  fail "could not create remote R"
fi

# ---------------------------------------------------------------------------
# Step 1: prime the cache.
# ---------------------------------------------------------------------------

begin_test "Prime cache: first fetch through R caches v${PKG_VERSION} index"
RESP=$(fetch_proxied_index_with_status)
PRIME_STATUS="${RESP%%|*}"
PRIME_BODY="${RESP#*|}"
if [ "$PRIME_STATUS" != "200" ]; then
  fail "prime fetch returned HTTP ${PRIME_STATUS}; cannot proceed (body=${PRIME_BODY:0:200})"
elif [ -z "$PRIME_BODY" ]; then
  fail "prime fetch returned empty body; cache row never written"
elif ! echo "$PRIME_BODY" | grep -q "${PKG_VERSION}"; then
  fail "primed body missing v${PKG_VERSION}; cache prime is not valid for the stale-fallback assertion"
else
  pass
fi

# Guard the rest of the suite: if the prime didn't put real content
# into the cache there is no stale copy to fall back to, so the
# downstream assertion would be vacuous.
if ! echo "$PRIME_BODY" | grep -q "${PKG_VERSION}"; then
  end_suite
fi

# ---------------------------------------------------------------------------
# Step 2: forcibly remove the upstream. From this point on the
# proxy_service.rs upstream fetch through R MUST fail (the backend
# will get a 404 from its own /pypi/<deleted-key>/... route), which
# is exactly the Err arm that triggers stale-on-error.
# ---------------------------------------------------------------------------

begin_test "Delete upstream U to force upstream-fetch failure"
del_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X DELETE \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${UPSTREAM_KEY}" 2>/dev/null) || del_status="000"
if [ "$del_status" -ge 200 ] 2>/dev/null && [ "$del_status" -lt 300 ] 2>/dev/null; then
  pass
else
  fail "could not delete upstream U (status=${del_status}); cannot force upstream failure"
fi

# Confirm U really is gone from the proxy's perspective. Without this
# guard a flaky DELETE could leave U serving and the rest of the test
# would be testing "cache still works" rather than "stale-on-error".
deadline=$(( $(date +%s) + 5 ))
upstream_status="000"
while [ "$(date +%s)" -lt "$deadline" ]; do
  upstream_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${BASE_URL}/pypi/${UPSTREAM_KEY}/simple/${PKG_NAME}/" 2>/dev/null) || upstream_status="000"
  if [ "$upstream_status" = "404" ]; then
    break
  fi
  sleep 0.2
done

begin_test "Upstream U returns 404 (sanity: actually gone)"
if [ "$upstream_status" = "404" ]; then
  pass
else
  # 401/403 would mean an auth path still treats U as a repo; only
  # 404 confirms the route resolver has dropped it. If we proceed
  # without 404 the next assertion is ambiguous.
  fail "expected upstream U to 404 after delete, got ${upstream_status}; cannot guarantee upstream-error branch"
fi

# ---------------------------------------------------------------------------
# Step 3: load-bearing assertion. With U gone, R MUST still return the
# stale cached copy. Failure modes:
#   - 502/504: stale-on-error not wired (or feature regressed).
#   - 200 with empty body: stale fallback ran but returned the
#     upstream-error body instead of the cached row.
#   - 404: proxy_service returned upstream's 404 directly rather than
#     falling back (this is the actual customer pain in #872).
# ---------------------------------------------------------------------------

begin_test "Refetch through R serves stale cached copy (NOT 5xx, NOT 404)"
RESP=$(fetch_proxied_index_with_status)
STALE_STATUS="${RESP%%|*}"
STALE_BODY="${RESP#*|}"

if [ "$STALE_STATUS" = "200" ] && echo "$STALE_BODY" | grep -q "${PKG_VERSION}"; then
  pass
elif [ "$STALE_STATUS" = "200" ] && [ -z "$STALE_BODY" ]; then
  fail "200 with empty body; stale fallback returned upstream-error envelope, not cached row"
elif [ "$STALE_STATUS" = "404" ]; then
  fail "404 surfaced to client; upstream-error branch did NOT fall back to stale cache (this is the artifact-keeper#872 customer regression class)"
elif [ "$STALE_STATUS" -ge 500 ] 2>/dev/null; then
  fail "HTTP ${STALE_STATUS} surfaced to client; stale-on-error contract violated (upstream_err propagated instead of get_stale_cached_artifact result)"
else
  fail "unexpected status ${STALE_STATUS}; body=${STALE_BODY:0:200}"
fi

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
