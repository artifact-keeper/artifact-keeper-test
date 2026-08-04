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
#   3. The stats totals INCREASE across this suite's own pull-through:
#      proxy_artifact_count by at least 1 and proxy_storage_bytes by at
#      least the sdist's size, measured against a baseline snapshotted
#      immediately before the pull.
#
# Why assertion 3 is a delta and not ">= 1"
# -----------------------------------------
# proxy_artifact_count / proxy_storage_bytes are INSTANCE-WIDE aggregates over
# the whole proxy_cache_artifacts table. run-suite.sh globs and sorts this
# directory, so six other pullthrough suites have already populated cache rows
# by the time this one starts: both counters are >= 1 before this script does
# anything. An absolute ">= 1" check therefore passes even if this suite's own
# pull-through never happens and even if the #3088 aggregation is wrong, which
# is what it was doing. Anchoring on a pre-pull baseline is what actually
# exercises the fix. The counters can still move under parallel suites, but
# only upward within a run, so a floor of baseline+delta stays sound.
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
SDIST_SIZE=0
BASE_PROXY_COUNT=0
BASE_PROXY_BYTES=0

# read_proxy_stats - echo "<proxy_artifact_count> <proxy_storage_bytes>" from
# the stats endpoint on stdout. Returns 1 (echoing nothing) if the GET failed,
# so callers can tell "could not read the counters" from "counters are zero".
# Absent or non-numeric fields normalize to 0 so every call site can do plain
# integer arithmetic on the result.
read_proxy_stats() {
  local resp c b
  resp=$(api_get "$STATS_PATH" 2>/dev/null) || return 1
  c=$(echo "$resp" | jq -r '.proxy_artifact_count // 0' 2>/dev/null) || c=0
  b=$(echo "$resp" | jq -r '.proxy_storage_bytes // 0' 2>/dev/null) || b=0
  [[ "$c" =~ ^[0-9]+$ ]] || c=0
  [[ "$b" =~ ^[0-9]+$ ]] || b=0
  echo "$c $b"
}

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
# A failed tar is a broken fixture, not a product verdict, and it must not be
# swallowed: the byte-delta assertion below is measured against this file's
# size, so a zero-byte or missing sdist would quietly weaken it.
if ! tar -czf "$SDIST_FILE" -C "$WORK_DIR" "${PKG_NAME}-${PKG_VERSION}"; then
  infra_fail "could not create the sdist fixture ${SDIST_BASENAME}"
elif ! create_local_repo "$UPSTREAM_KEY" "pypi"; then
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
# Size of the object the pull-through will cache; the byte delta below is
# measured against it. Fall back to 1 rather than 0 if the size is somehow
# unreadable, so the assertion still demands a strict increase.
SDIST_SIZE=$(wc -c < "$SDIST_FILE" 2>/dev/null | tr -d '[:space:]') || SDIST_SIZE=1
[[ "$SDIST_SIZE" =~ ^[1-9][0-9]*$ ]] || SDIST_SIZE=1

begin_test "Create remote R pointing at U"
if create_remote_repo "$REMOTE_KEY" "pypi" "${BASE_URL}/pypi/${UPSTREAM_KEY}"; then
  pass
else
  fail "could not create remote R"
fi

# ---------------------------------------------------------------------------
# Baseline for assertion 3, taken immediately before the pull-through so the
# delta below covers only this suite's own cache write.
# ---------------------------------------------------------------------------

begin_test "Snapshot instance-wide proxy-cache totals before this suite pulls"
if snapshot=$(read_proxy_stats); then
  BASE_PROXY_COUNT="${snapshot%% *}"
  BASE_PROXY_BYTES="${snapshot##* }"
  echo "  baseline: proxy_artifact_count=${BASE_PROXY_COUNT}, proxy_storage_bytes=${BASE_PROXY_BYTES}"
  pass
else
  # Without a baseline there is no delta to assert, and falling back to zero
  # would silently restore the vacuous ">= 1" check. That is a harness
  # problem, not a product verdict.
  infra_fail "could not read ${STATS_PATH} for the pre-pull baseline; the delta assertion needs it"
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
# Assertion 3: stats GREW by this suite's own cached object
#
# Against the pre-pull baseline, not against zero: see the header note on why
# an absolute ">= 1" here was vacuous. The poll is retained because the cache
# write and the stats aggregate are eventually consistent.
# ---------------------------------------------------------------------------

begin_test "Stats proxy-cache totals grow by this suite's cached object"
WANT_COUNT=$(( BASE_PROXY_COUNT + 1 ))
WANT_BYTES=$(( BASE_PROXY_BYTES + SDIST_SIZE ))
proxy_count=0
proxy_bytes=0
deadline=$(( $(date +%s) + 20 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  if snapshot=$(read_proxy_stats); then
    proxy_count="${snapshot%% *}"
    proxy_bytes="${snapshot##* }"
  fi
  if [ "$proxy_count" -ge "$WANT_COUNT" ] && [ "$proxy_bytes" -ge "$WANT_BYTES" ]; then
    break
  fi
  sleep 2
done
if [ "$proxy_count" -ge "$WANT_COUNT" ] && [ "$proxy_bytes" -ge "$WANT_BYTES" ]; then
  pass
else
  fail "stats did not grow by the cached object (proxy_artifact_count ${BASE_PROXY_COUNT} -> ${proxy_count}, want >= ${WANT_COUNT}; proxy_storage_bytes ${BASE_PROXY_BYTES} -> ${proxy_bytes}, want >= ${WANT_BYTES})" \
    "cached sdist: ${SDIST_BASENAME} (${SDIST_SIZE} bytes) pulled through ${REMOTE_KEY}
pre-#3088 backends omit proxy_cache_artifacts rows from the system stats aggregate,
so both counters stay flat across a pull-through that did land a cache row."
fi

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

api_delete "/api/v1/repositories/${REMOTE_KEY}" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${UPSTREAM_KEY}" > /dev/null 2>&1 || true

end_suite
