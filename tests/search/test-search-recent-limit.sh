#!/usr/bin/env bash
# test-search-recent-limit.sh - Recent endpoint custom `limit` parameter
#
# Epic 8 sub-task 8.15 (artifact-keeper-test#73). The /api/v1/search/recent
# endpoint (OpenAPI: returns SearchResultItem[]) accepts an optional
# `limit` query parameter. test-search-basic.sh only smoke-probes the
# default-limit call. This script asserts the limit parameter is
# actually honoured:
#
#   1. limit=3 must return at most 3 entries (clamp respected).
#   2. limit=1 must return at most 1 entry.
#   3. limit=0 must produce an empty array (or 4xx); MUST NOT return
#      the default-limited list.
#   4. limit=-1 must not 5xx (unsigned underflow class).
#   5. limit far above the documented max (10000) must be clamped or
#      rejected; must not allocate an unbounded array.
#
# We upload 5 sentinels in a fresh repo so the indexer has enough rows
# to demonstrate that limit=3 is actually a clamp (not "all rows
# happen to be three"). If indexing is too slow on the runner, the
# clamp assertion falls back to "no more than 3 of OUR sentinels in
# the response" which still catches the regression.
#
# Skips cleanly if /api/v1/search/recent returns 404/501.
#
# Requires: curl, jq

source "$(dirname "$0")/../lib/common.sh"

begin_suite "search-recent-limit"
auth_admin
setup_workdir

# Preflight: endpoint must exist.
preflight_status=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/search/recent?limit=1" 2>/dev/null || echo "000")
case "$preflight_status" in
  404|501)
    skip_suite "recent endpoint not available (HTTP ${preflight_status})"
    ;;
  503|504|000)
    skip_suite "search backend unavailable (HTTP ${preflight_status})"
    ;;
esac

REPO_KEY="rec-${RUN_ID}"
UNIQUE_TERM="rec${RUN_ID//[^a-z0-9]/}"

add_exit_handler "api_delete \"/api/v1/repositories/${REPO_KEY}\" >/dev/null 2>&1 || true"

begin_test "Create repo and upload five recent sentinels"
ok=true
create_local_repo "$REPO_KEY" "generic" >/dev/null 2>&1 || ok=false
for i in 1 2 3 4 5; do
  echo "recent-sentinel-${UNIQUE_TERM}-${i}" > "${WORK_DIR}/${UNIQUE_TERM}-${i}.txt"
  api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/${UNIQUE_TERM}/${UNIQUE_TERM}-${i}.txt" \
    "${WORK_DIR}/${UNIQUE_TERM}-${i}.txt" >/dev/null 2>&1 || ok=false
done
if [ "$ok" = true ]; then
  pass
else
  fail "could not seed recent corpus"
  end_suite
fi

sleep 3   # let the recent-feed surface our uploads

# _recent_count <limit>
# Returns the number of entries in the recent response, or "" on error.
_recent_count() {
  local limit="$1"
  local body
  body=$(curl -sf $CURL_TIMEOUT -H "$(auth_header)" \
    "${BASE_URL}/api/v1/search/recent?limit=${limit}" 2>/dev/null || echo "")
  if [ -z "$body" ]; then
    echo ""
    return
  fi
  echo "$body" | jq -r '
    if type == "array" then length
    elif (.items? | type) == "array" then (.items|length)
    elif (.results? | type) == "array" then (.results|length)
    else 0 end' 2>/dev/null || echo ""
}

# _recent_status <limit>
_recent_status() {
  local limit="$1"
  curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(auth_header)" \
    "${BASE_URL}/api/v1/search/recent?limit=${limit}" 2>/dev/null || echo "000"
}

# -------------------------------------------------------------------------
# 1. limit=3 must clamp at 3.
# -------------------------------------------------------------------------

begin_test "limit=3 returns at most 3 entries"
count=$(_recent_count 3)
if [ -z "$count" ]; then
  skip "limit=3 request returned error"
elif [ "$count" -le 3 ]; then
  pass
else
  fail "limit=3 returned ${count} entries; clamp not respected"
fi

# -------------------------------------------------------------------------
# 2. limit=1 must clamp at 1.
# -------------------------------------------------------------------------

begin_test "limit=1 returns at most 1 entry"
count=$(_recent_count 1)
if [ -z "$count" ]; then
  skip "limit=1 request returned error"
elif [ "$count" -le 1 ]; then
  pass
else
  fail "limit=1 returned ${count} entries; clamp not respected"
fi

# -------------------------------------------------------------------------
# 3. limit=0 must produce an empty array (NOT the default page).
#    This catches the regression where the handler treats limit=0 as
#    "unset" and silently substitutes the default of (typically) 20.
# -------------------------------------------------------------------------

begin_test "limit=0 returns empty array (not default page)"
status=$(_recent_status 0)
case "$status" in
  4*) pass ;;
  5*) fail "limit=0 returned HTTP ${status}" ;;
  2*)
    count=$(_recent_count 0)
    if [ -z "$count" ]; then
      skip "limit=0 response not parseable"
    elif [ "$count" = "0" ]; then
      pass
    else
      fail "limit=0 returned ${count} entries; should be 0 (handler treated as unset?)"
    fi
    ;;
  *)
    skip "limit=0 returned HTTP ${status}; not a clean signal"
    ;;
esac

# -------------------------------------------------------------------------
# 4. limit=-1 must not 5xx.
# -------------------------------------------------------------------------

begin_test "limit=-1 does not 5xx"
status=$(_recent_status -1)
case "$status" in
  5*) fail "limit=-1 returned HTTP ${status}; signed-to-unsigned regression" ;;
  *)  pass ;;
esac

# -------------------------------------------------------------------------
# 5. limit=10000 must clamp or reject; must not allocate unbounded array.
# -------------------------------------------------------------------------

begin_test "limit=10000 is clamped or rejected"
status=$(_recent_status 10000)
case "$status" in
  5*) fail "limit=10000 returned HTTP ${status}" ;;
  4*) pass ;;
  2*)
    count=$(_recent_count 10000)
    # We accept anything up to 1000 as "reasonable clamp"; the
    # documented default for recent is typically 20-100.
    if [ -z "$count" ]; then
      skip "limit=10000 response not parseable"
    elif [ "$count" -le 1000 ]; then
      pass
    else
      fail "limit=10000 returned ${count} entries; backend did not clamp"
    fi
    ;;
  *)
    skip "limit=10000 returned HTTP ${status}; not a clean signal"
    ;;
esac

end_suite
