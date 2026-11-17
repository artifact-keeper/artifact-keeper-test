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
# pull-through never happens and even if the #3088 aggregation is wrong.
# Anchoring on a pre-pull baseline is what actually exercises the fix.
#
# Why assertion 3 gets more than one attempt (artifact-keeper-test#883)
# ---------------------------------------------------------------------
# Every gate job runs against the same backend, so sibling suites change these
# totals while this one measures, and not only upward. In the backend,
# proxy_artifact_count is COUNT(*) over proxy_cache_artifacts, and
# proxy_storage_bytes is the usage ledger's proxy_bytes, which the migration-182
# trigger keeps equal to SUM(size_bytes) of the same rows. A re-cache upserts
# an existing row's size_bytes, so it moves the byte total either way without
# moving the count. An eviction, or a sibling deleting its remote, lowers both.
# In the 1.11.14 Release Candidate the count went 7 -> 8 and the bytes fell
# 7154 below the baseline: this suite's row landed while a sibling shrank the
# cache. So the delta is measured up to PCS_ATTEMPTS times, each time with a
# fresh baseline and a version this suite has never pulled. One clean window
# proves #3088. Churn cannot produce a false pass: on a backend that leaves
# proxy_cache_artifacts out of the aggregate, no cache write moves either
# counter, so every attempt fails.
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
# One version per assertion-3 attempt, all published before the first pull so
# U's index already lists every one when R first caches it.
PKG_VERSIONS=(1.0.0 1.0.1 1.0.2)
PCS_ATTEMPTS=${#PKG_VERSIONS[@]}
PKG_VERSION="${PKG_VERSIONS[0]}"
SDIST_BASENAME="${PKG_NAME}-${PKG_VERSION}.tar.gz"
STATS_PATH="/api/v1/admin/stats"
BASE_PROXY_COUNT=0
BASE_PROXY_BYTES=0
declare -A SDIST_SIZES=()
# Bounded waits: one 20 s row wait and one 20 s stats poll on attempt 1, then a
# 20 s row wait and a 15 s stats poll on each retry.
require_wait_budget $(( 20 + 20 + (PCS_ATTEMPTS - 1) * (20 + 15) )) "cache-row and stats polls"

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
# Setup: upstream U with one published sdist per attempt, remote R pointing at U
# ---------------------------------------------------------------------------

# build_sdist VERSION - write ${WORK_DIR}/${PKG_NAME}-VERSION.tar.gz.
build_sdist() {
  local v="$1" dir="${WORK_DIR}/${PKG_NAME}-$1"
  mkdir -p "$dir" || return 1
  cat > "${dir}/PKG-INFO" <<EOF
Metadata-Version: 1.0
Name: ${PKG_NAME}
Version: ${v}
Summary: proxy-cache stats probe
EOF
  cat > "${dir}/setup.py" <<EOF
from setuptools import setup
setup(name="${PKG_NAME}", version="${v}")
EOF
  tar -czf "${WORK_DIR}/${PKG_NAME}-${v}.tar.gz" -C "$WORK_DIR" "${PKG_NAME}-${v}"
}

# publish_sdist VERSION - upload the built sdist to U.
publish_sdist() {
  curl -sf $CURL_TIMEOUT -X POST \
    -H "$(format_auth_header)" \
    -F ":action=file_upload" \
    -F "name=${PKG_NAME}" \
    -F "version=$1" \
    -F "filetype=sdist" \
    -F "content=@${WORK_DIR}/${PKG_NAME}-$1.tar.gz" \
    "${BASE_URL}/pypi/${UPSTREAM_KEY}/" > /dev/null 2>&1
}

begin_test "Create local PyPI upstream U and publish ${PKG_VERSIONS[*]}"
# A failed tar is a broken fixture, not a product verdict, and it must not be
# swallowed: the byte-delta assertion below is measured against each file's
# size, so a zero-byte or missing sdist would quietly weaken it.
setup_err=""
for v in "${PKG_VERSIONS[@]}"; do
  if ! build_sdist "$v"; then
    setup_err="infra:could not create the sdist fixture ${PKG_NAME}-${v}.tar.gz"
    break
  fi
  # Fall back to 1 rather than 0 if the size is somehow unreadable, so the
  # assertion still demands a strict increase.
  sz=$(wc -c < "${WORK_DIR}/${PKG_NAME}-${v}.tar.gz" 2>/dev/null | tr -d '[:space:]') || sz=1
  [[ "$sz" =~ ^[1-9][0-9]*$ ]] || sz=1
  SDIST_SIZES[$v]="$sz"
done
if [ -z "$setup_err" ] && ! create_local_repo "$UPSTREAM_KEY" "pypi"; then
  setup_err="could not create PyPI upstream"
fi
if [ -z "$setup_err" ]; then
  for v in "${PKG_VERSIONS[@]}"; do
    if ! publish_sdist "$v"; then
      setup_err="could not publish sdist ${v} to upstream U"
      break
    fi
  done
fi
case "$setup_err" in
  "") pass ;;
  infra:*) infra_fail "${setup_err#infra:}" ;;
  *) fail "$setup_err" ;;
esac
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

# pull_sdist VERSION - echo the HTTP status of pulling that sdist through R.
# Warm the index first so the proxy has resolved the project, then fetch the
# package file itself; the file bytes are what land in the cache catalog with a
# real size.
pull_sdist() {
  local status
  curl -sf $CURL_TIMEOUT -H "$(format_auth_header)" \
    "${BASE_URL}/pypi/${REMOTE_KEY}/simple/${PKG_NAME}/" > /dev/null 2>&1 || true
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${BASE_URL}/pypi/${REMOTE_KEY}/simple/${PKG_NAME}/${PKG_NAME}-$1.tar.gz" 2>/dev/null) || status="000"
  echo "${status:-000}"
}

begin_test "Pull sdist through R (pull-through cache write)"
pull_status=$(pull_sdist "$PKG_VERSION")
if assert_http_2xx "$pull_status" "pull through remote R failed"; then
  pass
fi

begin_test "Cache row for the pulled sdist appears in R"
if wait_until "${SDIST_BASENAME} listed in ${REMOTE_KEY}" 20 \
    repo_lists_artifact "$REMOTE_KEY" "$SDIST_BASENAME"; then
  pass
else
  fail "no cache row for ${SDIST_BASENAME} appeared in ${REMOTE_KEY} within 20s"
fi

# ---------------------------------------------------------------------------
# Assertion 3: stats GREW by this suite's own cached object
#
# Against a pre-pull baseline, not against zero: see the header note on why an
# absolute ">= 1" here was vacuous, and on why a sibling's re-cache or eviction
# can mask one attempt. The poll is retained because the cache write and the
# stats aggregate are eventually consistent.
# ---------------------------------------------------------------------------

# poll_growth BASE_COUNT BASE_BYTES SIZE TIMEOUT - poll the stats until both
# totals reach BASE+1 / BASE+SIZE. Leaves the last reading in proxy_count /
# proxy_bytes ("?" if no read succeeded). Returns 0 once both have grown.
poll_growth() {
  local want_c=$(( $1 + 1 )) want_b=$(( $2 + $3 )) deadline snap
  proxy_count="?"
  proxy_bytes="?"
  deadline=$(( $(date +%s) + $4 ))
  while :; do
    if snap=$(read_proxy_stats); then
      proxy_count="${snap%% *}"
      proxy_bytes="${snap##* }"
      if [ "$proxy_count" -ge "$want_c" ] && [ "$proxy_bytes" -ge "$want_b" ]; then
        return 0
      fi
    fi
    [ "$(date +%s)" -lt "$deadline" ] || return 1
    sleep 2  # sleep-ok: poll interval
  done
}

begin_test "Stats proxy-cache totals grow by this suite's cached object"
grew=0
attempt_log=""
for (( i = 0; i < PCS_ATTEMPTS; i++ )); do
  v="${PKG_VERSIONS[$i]}"
  size="${SDIST_SIZES[$v]:-1}"
  if [ "$i" -gt 0 ]; then
    # Fresh baseline and a never-pulled version, so this attempt's window
    # covers only its own cache write plus whatever siblings do meanwhile.
    if ! snapshot=$(read_proxy_stats); then
      attempt_log+="attempt $(( i + 1 )) (${v}): could not read ${STATS_PATH} for a baseline"$'\n'
      continue
    fi
    BASE_PROXY_COUNT="${snapshot%% *}"
    BASE_PROXY_BYTES="${snapshot##* }"
    pull_status=$(pull_sdist "$v")
    if [[ ! "$pull_status" =~ ^2[0-9][0-9]$ ]]; then
      attempt_log+="attempt $(( i + 1 )) (${v}): pull through R answered HTTP ${pull_status}"$'\n'
      continue
    fi
    if ! wait_until "${PKG_NAME}-${v}.tar.gz listed in ${REMOTE_KEY}" 20 \
        repo_lists_artifact "$REMOTE_KEY" "${PKG_NAME}-${v}.tar.gz"; then
      attempt_log+="attempt $(( i + 1 )) (${v}): no cache row appeared in ${REMOTE_KEY} within 20s"$'\n'
      continue
    fi
    window=15
  else
    window=20
  fi
  if poll_growth "$BASE_PROXY_COUNT" "$BASE_PROXY_BYTES" "$size" "$window"; then
    grew=1
    echo "  attempt $(( i + 1 )) (${v}): proxy_artifact_count ${BASE_PROXY_COUNT} -> ${proxy_count}, proxy_storage_bytes ${BASE_PROXY_BYTES} -> ${proxy_bytes} (+${size} wanted)"
    break
  fi
  attempt_log+="attempt $(( i + 1 )) (${v}): proxy_artifact_count ${BASE_PROXY_COUNT} -> ${proxy_count} (want >= $(( BASE_PROXY_COUNT + 1 ))), proxy_storage_bytes ${BASE_PROXY_BYTES} -> ${proxy_bytes} (want >= $(( BASE_PROXY_BYTES + size )))"$'\n'
done
if [ "$grew" -eq 1 ] && [ -n "$attempt_log" ]; then
  printf '  earlier attempts did not see clean growth (sibling suites share these totals):\n%s' \
    "$(printf '%s' "$attempt_log" | sed 's/^/    /')"
  echo
fi
if [ "$grew" -eq 1 ]; then
  pass
else
  fail "stats did not grow by this suite's cached object in any of ${PCS_ATTEMPTS} attempts" \
    "${attempt_log}
each attempt pulled a fresh sdist through ${REMOTE_KEY} against a fresh baseline.
pre-#3088 backends omit proxy_cache_artifacts rows from the system stats aggregate,
so both counters stay flat across a pull-through that did land a cache row. A
single sibling re-cache or eviction can mask one attempt, but not all of them."
fi

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

api_delete "/api/v1/repositories/${REMOTE_KEY}" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${UPSTREAM_KEY}" > /dev/null 2>&1 || true

end_suite
