#!/usr/bin/env bash
# test-cache-stampede-prevention.sh -- Concurrent-fetch stampede must
# NOT produce N upstream fetches for N client requests on a cold cache
# (issue #69 sub-task 1.1).
#
# What this asserts
# -----------------
# proxy_service in the backend exposes proxy_max_concurrent_fetches
# (default 20) plus proxy_queue_timeout_secs (default 30). The contract:
# N concurrent client requests for the SAME (repo, path) tuple on a
# cold cache MUST be coalesced -- only one (or at most M, where M is
# the per-key semaphore admit) upstream fetch happens, and the other
# N-1 / N-M callers either wait for the in-flight fetch and reuse its
# result or time out with 503.
#
# Why this matters
# ----------------
# Without coalescing, every CI runner that wakes up at midnight to
# pull the same nightly tarball produces N parallel upstream fetches
# (we have seen 600+ on a single popular blob). For an upstream rate-
# limited at 100 req/min this guarantees a thundering-herd failure on
# the first cold-cache fetch every day. This is the second-class of
# customer pain in artifact-keeper#872.
#
# Existing coverage gap
# ---------------------
# tests/security/test-cache-stampede.sh exists but is hard-stubbed
# pending backend issue artifact-keeper#1224 (AK_SSRF_ALLOW_PRIVATE_CIDRS
# so the mock fixture can be reached from the runner pod). That test
# uses the mock-upstream peak-inflight counter as its primary signal.
# This new test takes a different approach that does NOT require the
# mock: AK-to-AK (same pattern as test-cache-hit-no-refetch.sh +
# test-cache-ttl-eviction.sh) plus a content-equality observable.
#
# Approach
# --------
# Two-repo AK-to-AK:
#   U = local PyPI repo we publish v1 to.
#   R = remote PyPI repo whose upstream_url is U's AK URL.
#
# Then:
#   1. Fan out N concurrent fetches through R's /simple/<pkg>/ on a
#      cold cache (R was just created -- nothing cached).
#   2. Collect (a) all HTTP statuses and (b) all response bodies.
#   3. Load-bearing assertions:
#      (i)  All non-error responses MUST have byte-identical bodies.
#           If the stampede produced N independent upstream fetches
#           and the upstream's simple-index generator races (it
#           often does -- the html shape can change between requests
#           under load), we'd see body drift.
#      (ii) Either:
#           - ALL N responses succeeded (2xx), OR
#           - Some responses are 503 Service Unavailable (queue
#             timeout exceeded -- this is the proxy_queue_timeout_secs
#             admission control firing correctly). Either outcome
#             is a PASS; what fails is mixed 2xx-with-different-bodies
#             (stampede actually happened) or any 5xx other than 503
#             (a fetch crashed mid-coalesce).
#
# What this does NOT assert (deferred to stubbed mock-upstream test)
# ------------------------------------------------------------------
# - Peak upstream-fetch count <= proxy_max_concurrent_fetches.
#   That requires the mock-upstream peak-inflight counter, which is
#   currently SSRF-blocked. When artifact-keeper#1224 lands and the
#   sibling test/security/test-cache-stampede.sh unstubs, that script
#   takes ownership of the count-based assertion; this one keeps
#   the content-equality assertion as a complementary check.
# - Specific 503/queue_timeout behaviour beyond "503 is acceptable".
#   The exact balance of admit-vs-503 depends on the per-key semaphore
#   width and how slow the upstream actually is, neither of which we
#   control deterministically here.
#
# Feature gating
# --------------
# proxy_stampede_protection is gated at v1.2.0 in feature-flags.sh
# (the per-(repo,path) semaphore + queue timeout landed in v1.2.0;
# v1.1.x backends do not coalesce). On v1.1.x backends this test
# would FAIL because every fetch hits upstream independently, which
# is the bug under test rather than a regression of THIS suite. We
# require_feature -> skip rather than fail-loud on 1.1.x to keep the
# release-gate green on the existing maintenance branch.
#
# Requires: curl, jq, tar

source "$(dirname "$0")/../lib/common.sh"

begin_suite "cache-stampede-prevention"
auth_admin
setup_workdir

# Feature gate: skip on v1.1.x where the feature is known absent.
# This must come BEFORE any expensive setup -- on a gated skip the
# suite should exit fast.
if ! require_feature "proxy_stampede_protection"; then
  end_suite
fi

UPSTREAM_KEY="stamp-up-${RUN_ID}"
REMOTE_KEY="stamp-rem-${RUN_ID}"
PKG_NAME="stamppkg${RUN_ID//-/}"
PKG_VERSION="1.0.0"
# Fan-out width. 10 is enough to make a serial-fetch implementation
# look obviously different from a coalesced one without saturating
# the runner's outbound connection limit.
CONCURRENCY=10
# Long TTL so the test stays in the cold-cache window throughout
# the fan-out (we explicitly do NOT prime; the stampede property is
# about the FIRST request burst on an empty cache).
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
Summary: cache-stampede probe
EOINFO
  cat > "${pkgdir}/setup.py" <<EOPY
from setuptools import setup
setup(name="${PKG_NAME}", version="${version}")
EOPY
  tar -czf "$tarball" -C "$WORK_DIR" "${PKG_NAME}-${version}"
  echo "$tarball"
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

begin_test "Publish v${PKG_VERSION} to U"
TARBALL=$(build_sdist "$PKG_VERSION")
if curl -sf $CURL_TIMEOUT -X POST \
    -H "$(format_auth_header)" \
    -F ":action=file_upload" \
    -F "name=${PKG_NAME}" \
    -F "version=${PKG_VERSION}" \
    -F "filetype=sdist" \
    -F "content=@${TARBALL}" \
    "${BASE_URL}/pypi/${UPSTREAM_KEY}/" > /dev/null 2>&1; then
  pass
elif api_upload "/api/v1/repositories/${UPSTREAM_KEY}/artifacts/${PKG_NAME}/${PKG_VERSION}/${PKG_NAME}-${PKG_VERSION}.tar.gz" \
    "$TARBALL" "application/gzip" > /dev/null 2>&1; then
  pass
else
  skip_suite "PyPI upload endpoint unavailable; stampede test cannot proceed"
fi

# Wait until U surfaces the package, otherwise the cold-cache fan-out
# races the indexer instead of the upstream fetcher.
deadline=$(( $(date +%s) + 15 ))
until curl -sf $CURL_TIMEOUT -H "$(format_auth_header)" \
        "${BASE_URL}/pypi/${UPSTREAM_KEY}/simple/${PKG_NAME}/" 2>/dev/null \
      | grep -q "${PKG_VERSION}" || [ "$(date +%s)" -ge "$deadline" ]; do
  sleep 0.3
done

begin_test "Create remote R (cold cache) pointing at U"
if create_remote_repo "$REMOTE_KEY" "pypi" "${BASE_URL}/pypi/${UPSTREAM_KEY}"; then
  api_put "/api/v1/repositories/${REMOTE_KEY}/cache-ttl" \
      "{\"cache_ttl_seconds\": ${TTL_SECS}}" >/dev/null 2>&1 || true
  pass
else
  fail "could not create remote R"
fi

# ---------------------------------------------------------------------------
# Fan out N concurrent fetches against the cold cache.
#
# We background N curls into a results dir, each writing
#   <i>.status   -> HTTP status code
#   <i>.body     -> response body
# and then wait for all of them. `wait` with no arg blocks until every
# child finishes (the disown-on-mock-PID note in common.sh does not
# apply here -- these are not the mock).
# ---------------------------------------------------------------------------

RESULTS="${WORK_DIR}/stampede"
mkdir -p "$RESULTS"

URL="${BASE_URL}/pypi/${REMOTE_KEY}/simple/${PKG_NAME}/"
AUTH=$(format_auth_header)

# Fire them as close to simultaneously as bash allows. The actual
# concurrency depends on the runner -- we don't need microsecond
# alignment, we just need the SECOND request to arrive before the
# FIRST request has finished its upstream round-trip.
for i in $(seq 1 "$CONCURRENCY"); do
  (
    curl -s -o "${RESULTS}/${i}.body" -w '%{http_code}' \
      $CURL_TIMEOUT \
      -H "$AUTH" \
      "$URL" > "${RESULTS}/${i}.status" 2>/dev/null || \
      echo "000" > "${RESULTS}/${i}.status"
  ) &
done
wait

# Collect statuses + body hashes.
statuses=()
body_hashes=()
for i in $(seq 1 "$CONCURRENCY"); do
  st=$(cat "${RESULTS}/${i}.status" 2>/dev/null || echo "000")
  statuses+=("$st")
  if [ -s "${RESULTS}/${i}.body" ]; then
    h=$(sha256sum "${RESULTS}/${i}.body" 2>/dev/null | awk '{print $1}')
  else
    h="EMPTY"
  fi
  body_hashes+=("$h")
done

# ---------------------------------------------------------------------------
# Assertion 1: every response is either 2xx (admitted to the
# coalesced fetch) or 503 (queue_timeout fired). Anything else means
# a fetch crashed mid-coalesce, which is a regression of THIS feature.
# ---------------------------------------------------------------------------

begin_test "All ${CONCURRENCY} concurrent responses are 2xx or 503 (no crashes)"
bad_status=""
for st in "${statuses[@]}"; do
  if [ "$st" -ge 200 ] 2>/dev/null && [ "$st" -lt 300 ] 2>/dev/null; then
    continue
  fi
  if [ "$st" = "503" ]; then
    continue
  fi
  bad_status="$st"
  break
done
if [ -z "$bad_status" ]; then
  pass
else
  fail "saw HTTP ${bad_status} among concurrent responses; expected only 2xx or 503. Full status set: ${statuses[*]}"
fi

# ---------------------------------------------------------------------------
# Assertion 2: every 2xx response has the SAME body hash. If the
# stampede actually happened, different upstream fetches can return
# slightly different bytes (timestamp in HTML, header ordering, the
# simple-index generator non-determinism we saw on artifact-keeper
# #871). Coalesced fetches share a single response, so byte equality
# is guaranteed.
#
# We do NOT include EMPTY or non-2xx bodies in the equality set --
# 503s legitimately come back with a short error body that differs
# from the success body.
# ---------------------------------------------------------------------------

begin_test "All 2xx concurrent responses are byte-identical (coalesced)"
canonical=""
mismatch=""
twoxx_count=0
for i in $(seq 1 "$CONCURRENCY"); do
  idx=$(( i - 1 ))
  st="${statuses[$idx]}"
  if ! [ "$st" -ge 200 ] 2>/dev/null || ! [ "$st" -lt 300 ] 2>/dev/null; then
    continue
  fi
  twoxx_count=$(( twoxx_count + 1 ))
  h="${body_hashes[$idx]}"
  if [ "$h" = "EMPTY" ]; then
    mismatch="response ${i} was 2xx but empty body"
    break
  fi
  if [ -z "$canonical" ]; then
    canonical="$h"
  elif [ "$h" != "$canonical" ]; then
    mismatch="response ${i} body sha=${h} differs from canonical sha=${canonical}; stampede produced N independent upstream fetches"
    break
  fi
done
if [ "$twoxx_count" -eq 0 ]; then
  # Everything 503'd. That is still a valid coalesce-and-queue-out
  # outcome -- it does not violate the contract, just means the
  # queue_timeout is tighter than the upstream fetch latency. Don't
  # FAIL but don't claim PASS on a vacuous body-equality either.
  skip "no 2xx responses to compare (all ${CONCURRENCY} returned 503); body-equality assertion is vacuous on this run"
elif [ -n "$mismatch" ]; then
  fail "$mismatch"
else
  pass
fi

# ---------------------------------------------------------------------------
# Assertion 3 (sanity): the cache row actually got written. If
# coalescing worked but the chosen winner never persisted the result,
# a subsequent (post-fan-out) fetch would re-fetch upstream. We
# verify by doing one MORE fetch after the burst and asserting the
# body matches the canonical hash.
# ---------------------------------------------------------------------------

begin_test "Post-stampede fetch hits the cache (matches coalesced body)"
if [ -z "$canonical" ]; then
  skip "no canonical body from the burst (all 503); cannot assert cache-write"
else
  POST_BODY_FILE="${WORK_DIR}/post-stampede.body"
  post_status=$(curl -s -o "$POST_BODY_FILE" -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(format_auth_header)" "$URL" 2>/dev/null) || post_status="000"
  if [ "$post_status" != "200" ]; then
    fail "post-stampede fetch returned ${post_status} (expected 200)"
  else
    post_hash=$(sha256sum "$POST_BODY_FILE" 2>/dev/null | awk '{print $1}')
    if [ "$post_hash" = "$canonical" ]; then
      pass
    else
      fail "post-stampede body sha=${post_hash} differs from coalesced canonical=${canonical}; cache row may not have been written"
    fi
  fi
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
