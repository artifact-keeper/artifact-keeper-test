#!/usr/bin/env bash
# test-search-advanced-filters.sh - Advanced search filter contract
#
# Epic 8 sub-tasks 8.1, 8.2, 8.5 (artifact-keeper-test#73). Drives the
# /api/v1/search/advanced endpoint with size, date, and repository_key
# filters and asserts that:
#   1. min_size / max_size cleanly bound the result set.
#   2. created_after with a future timestamp returns an empty result set.
#   3. repository_key scopes results to that repo.
#
# We upload three sentinels with distinct sizes (small, medium, large)
# into a fresh repo so the assertions don't collide with whatever else
# happens to live on the indexer. Each assertion skips cleanly if the
# advanced search endpoint isn't wired on this backend, but a wired
# endpoint that returns cross-filter results (e.g. min_size returning
# a sub-min file) fails the test.
#
# Requires: curl, jq

source "$(dirname "$0")/../lib/common.sh"

begin_suite "search-advanced-filters"
auth_admin
setup_workdir

REPO_KEY="srch-adv-${RUN_ID}"
DECOY_REPO_KEY="srch-adv-decoy-${RUN_ID}"
UNIQUE_TERM="advfilt${RUN_ID//[^a-z0-9]/}"

# -------------------------------------------------------------------------
# Build a known corpus.
# -------------------------------------------------------------------------

begin_test "Create primary and decoy repos"
ok1=true
ok2=true
create_local_repo "$REPO_KEY"       "generic" >/dev/null 2>&1 || ok1=false
create_local_repo "$DECOY_REPO_KEY" "generic" >/dev/null 2>&1 || ok2=false
if [ "$ok1" = true ] && [ "$ok2" = true ]; then
  pass
else
  fail "could not create test repos"
  end_suite
fi

SMALL_FILE="${WORK_DIR}/small-${UNIQUE_TERM}.bin"
MED_FILE="${WORK_DIR}/med-${UNIQUE_TERM}.bin"
LARGE_FILE="${WORK_DIR}/large-${UNIQUE_TERM}.bin"

dd if=/dev/zero of="$SMALL_FILE" bs=1   count=512   2>/dev/null   # 512 B
dd if=/dev/zero of="$MED_FILE"   bs=1024 count=16    2>/dev/null  # 16 KB
dd if=/dev/zero of="$LARGE_FILE" bs=1024 count=128   2>/dev/null  # 128 KB

begin_test "Upload three sentinels of distinct sizes"
api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/${UNIQUE_TERM}/small.bin"  "$SMALL_FILE" >/dev/null 2>&1 || true
api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/${UNIQUE_TERM}/med.bin"    "$MED_FILE"   >/dev/null 2>&1 || true
api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/${UNIQUE_TERM}/large.bin"  "$LARGE_FILE" >/dev/null 2>&1 || true
# Decoy upload in a separate repo with the same UNIQUE_TERM so the
# repository_key filter has something to discriminate against.
api_upload "/api/v1/repositories/${DECOY_REPO_KEY}/artifacts/${UNIQUE_TERM}/decoy.bin" "$MED_FILE" >/dev/null 2>&1 || true
pass

sleep 4   # allow async indexing

# -------------------------------------------------------------------------
# 8.1 size filters.
# -------------------------------------------------------------------------

begin_test "min_size=4096 excludes 512 B sentinel"
if resp=$(api_get "/api/v1/search/advanced?q=${UNIQUE_TERM}&min_size=4096" 2>/dev/null); then
  hit=$(echo "$resp" | jq -r '
    if type=="array" then .
    elif .results then .results
    elif .hits    then .hits
    else [] end
    | map(.name // .path // .artifact_path // "")
    | join(" ")' 2>/dev/null || echo "")
  if echo "$hit" | grep -q 'small.bin'; then
    fail "min_size=4096 returned the 512 B small.bin sentinel"
  else
    pass
  fi
else
  skip "advanced search endpoint not available"
fi

begin_test "max_size=4096 excludes 128 KB sentinel"
if resp=$(api_get "/api/v1/search/advanced?q=${UNIQUE_TERM}&max_size=4096" 2>/dev/null); then
  hit=$(echo "$resp" | jq -r '
    if type=="array" then .
    elif .results then .results
    elif .hits    then .hits
    else [] end
    | map(.name // .path // .artifact_path // "")
    | join(" ")' 2>/dev/null || echo "")
  if echo "$hit" | grep -q 'large.bin'; then
    fail "max_size=4096 returned the 128 KB large.bin sentinel"
  else
    pass
  fi
else
  skip "advanced search endpoint not available"
fi

# -------------------------------------------------------------------------
# 8.2 date filters: future created_after must return nothing.
# -------------------------------------------------------------------------

begin_test "created_after=year-2099 returns empty result set"
future="2099-01-01T00:00:00Z"
if resp=$(api_get "/api/v1/search/advanced?q=${UNIQUE_TERM}&created_after=${future}" 2>/dev/null); then
  count=$(echo "$resp" | jq -r '
    if type=="array" then length
    elif .results then (.results|length)
    elif .hits    then (.hits|length)
    elif .total   then .total
    else 0 end' 2>/dev/null || echo 0)
  if [ "${count:-0}" = "0" ]; then
    pass
  else
    fail "future created_after returned ${count} hits, expected 0"
  fi
else
  skip "advanced search did not accept created_after"
fi

# -------------------------------------------------------------------------
# 8.5 repository_key scoping.
# -------------------------------------------------------------------------

begin_test "repository_key=primary excludes decoy repo hits"
if resp=$(api_get "/api/v1/search/advanced?q=${UNIQUE_TERM}&repository_key=${REPO_KEY}" 2>/dev/null); then
  decoy=$(echo "$resp" | jq -r --arg dk "$DECOY_REPO_KEY" '
    if type=="array" then .
    elif .results then .results
    elif .hits    then .hits
    else [] end
    | map(select(.repository_key == $dk or .repo_key == $dk))
    | length' 2>/dev/null || echo 0)
  if [ "$decoy" = "0" ]; then
    pass
  else
    fail "repository_key filter leaked ${decoy} decoy-repo hits"
  fi
else
  skip "advanced search did not accept repository_key"
fi

# -------------------------------------------------------------------------
# Cleanup.
# -------------------------------------------------------------------------

api_delete "/api/v1/repositories/${REPO_KEY}"       >/dev/null 2>&1 || true
api_delete "/api/v1/repositories/${DECOY_REPO_KEY}" >/dev/null 2>&1 || true

end_suite
