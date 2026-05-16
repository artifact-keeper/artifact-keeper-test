#!/usr/bin/env bash
# test-search-pagination-overflow.sh - Offset / pagination overflow edges
#
# Epic 8 sub-task 8.11 (artifact-keeper-test#73). The companion script
# test-search-pagination.sh already covers page=0, page=-1, per_page=0,
# and page-beyond-total. This script focuses on the OFFSET-overflow and
# UNSIGNED-UNDERFLOW class of regressions that motivated the subtask:
#
#   1. per_page=-1: a signed int negative that, if cast to usize without
#      validation, becomes a multi-exabyte allocation request and panics
#      the handler. Must 4xx or be ignored, never 5xx.
#
#   2. page=2147483647 (INT32_MAX) with per_page=100: triggers offset
#      arithmetic of (2147483647 - 1) * 100 which overflows i32 / i64
#      depending on the type. Must not 5xx, must return either 2xx
#      with hits=0 or a deterministic 4xx.
#
#   3. page=0 combined with per_page=0: the legacy underflow case that
#      computed offset = (0 - 1) * 0 with signed math and then handed
#      the result to the SQL OFFSET clause. Must not 5xx.
#
#   4. per_page = a value far above the documented max (e.g. 100000):
#      the backend must either clamp (return <= max) or 4xx. It must
#      not allocate an unbounded result page.
#
# All of these probes assert ONLY non-5xx; the contract we're locking
# down here is "the offset math doesn't panic", not the exact response
# shape, which varies by backend version.
#
# Skips cleanly if neither /api/v1/search nor /api/v1/search/advanced
# is reachable at preflight.
#
# Requires: curl, jq

source "$(dirname "$0")/../lib/common.sh"

begin_suite "search-pagination-overflow"
auth_admin
setup_workdir

# Preflight: bail fast if the search backend isn't wired.
preflight_status=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/search?q=preflight&per_page=1" 2>/dev/null || echo "000")
case "$preflight_status" in
  503|504|000)
    skip_suite "search backend unavailable (HTTP ${preflight_status})"
    ;;
esac

REPO_KEY="pag-of-${RUN_ID}"
UNIQUE_TERM="paof${RUN_ID//[^a-z0-9]/}"

add_exit_handler "api_delete \"/api/v1/repositories/${REPO_KEY}\" >/dev/null 2>&1 || true"

begin_test "Create repo and upload sentinel"
if create_local_repo "$REPO_KEY" "generic" >/dev/null 2>&1; then
  echo "overflow-sentinel-${UNIQUE_TERM}" > "${WORK_DIR}/${UNIQUE_TERM}.txt"
  api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/${UNIQUE_TERM}/${UNIQUE_TERM}.txt" \
    "${WORK_DIR}/${UNIQUE_TERM}.txt" >/dev/null 2>&1 || true
  pass
else
  fail "could not create repo"
  end_suite
fi

sleep 3

# Pick whichever search endpoint the backend exposes for this corpus.
SEARCH_BASE=""
for candidate in "/api/v1/search" "/api/v1/search/advanced"; do
  if curl -sf $CURL_TIMEOUT -o /dev/null -H "$(auth_header)" \
     "${BASE_URL}${candidate}?q=${UNIQUE_TERM}&query=${UNIQUE_TERM}" 2>/dev/null; then
    SEARCH_BASE="$candidate"
    break
  fi
done

begin_test "Search base endpoint reachable"
if [ -n "$SEARCH_BASE" ]; then
  pass
else
  skip "no search endpoint responded 200 for the test corpus"
  end_suite
fi

# Both /search and /search/advanced disagree on the query-param name
# (q vs query). Probe with both keys so neither variant misses.
QUERY_PARAMS="q=${UNIQUE_TERM}&query=${UNIQUE_TERM}"

# _probe_status <extra_params>
# Returns the HTTP status code for the given pagination probe.
_probe_status() {
  local extra="$1"
  curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(auth_header)" \
    "${BASE_URL}${SEARCH_BASE}?${QUERY_PARAMS}&${extra}" 2>/dev/null || echo "000"
}

# -------------------------------------------------------------------------
# 1. per_page=-1 must not panic the unsigned-cast path.
# -------------------------------------------------------------------------

begin_test "per_page=-1 does not 5xx (unsigned-cast underflow regression)"
status=$(_probe_status "page=1&per_page=-1")
case "$status" in
  5*) fail "per_page=-1 returned HTTP ${status}; likely usize underflow on cast" ;;
  *)  pass ;;
esac

# -------------------------------------------------------------------------
# 2. page=INT32_MAX exercises offset arithmetic overflow.
# -------------------------------------------------------------------------

begin_test "page=INT32_MAX,per_page=100 does not 5xx (offset overflow)"
status=$(_probe_status "page=2147483647&per_page=100")
case "$status" in
  5*) fail "page=INT32_MAX returned HTTP ${status}; offset math likely overflowed" ;;
  2*)
    # Bonus: if 2xx, the response must say "no hits" because the offset
    # is far beyond any plausible total. A 2xx with > 0 hits at this
    # offset would imply the offset was silently coerced to a much
    # smaller value, which is also a regression worth flagging.
    body=$(curl -sf $CURL_TIMEOUT -H "$(auth_header)" \
      "${BASE_URL}${SEARCH_BASE}?${QUERY_PARAMS}&page=2147483647&per_page=100" 2>/dev/null || echo "")
    hits=$(echo "$body" | jq -r '
      if type=="array" then length
      elif (.items?   | type) == "array" then (.items|length)
      elif (.results? | type) == "array" then (.results|length)
      elif (.hits?    | type) == "array" then (.hits|length)
      else 0 end' 2>/dev/null || echo 0)
    if [ "${hits:-0}" = "0" ]; then
      pass
    else
      fail "page=INT32_MAX returned ${hits} hits; offset was silently coerced (regression)"
    fi
    ;;
  *)  pass ;;
esac

# -------------------------------------------------------------------------
# 3. page=0 + per_page=0: combined underflow case.
# -------------------------------------------------------------------------

begin_test "page=0,per_page=0 does not 5xx (combined underflow)"
status=$(_probe_status "page=0&per_page=0")
case "$status" in
  5*) fail "page=0,per_page=0 returned HTTP ${status}; combined underflow" ;;
  *)  pass ;;
esac

# -------------------------------------------------------------------------
# 4. per_page far above documented max must clamp or reject.
#    A 2xx response with > 1000 hits returned for a single page would
#    imply an unbounded allocation, which is a soft DoS surface.
# -------------------------------------------------------------------------

begin_test "per_page=100000 is clamped or rejected (no unbounded page)"
status=$(_probe_status "page=1&per_page=100000")
case "$status" in
  5*) fail "per_page=100000 returned HTTP ${status}" ;;
  4*) pass ;;
  2*)
    body=$(curl -sf $CURL_TIMEOUT -H "$(auth_header)" \
      "${BASE_URL}${SEARCH_BASE}?${QUERY_PARAMS}&page=1&per_page=100000" 2>/dev/null || echo "")
    hits=$(echo "$body" | jq -r '
      if type=="array" then length
      elif (.items?   | type) == "array" then (.items|length)
      elif (.results? | type) == "array" then (.results|length)
      elif (.hits?    | type) == "array" then (.hits|length)
      else 0 end' 2>/dev/null || echo 0)
    # 1000 is a generous upper bound; the contract says per_page should
    # be clamped to a reasonable maximum (typically 100 or 200).
    if [ "${hits:-0}" -le 1000 ]; then
      pass
    else
      fail "per_page=100000 returned ${hits} rows; backend did not clamp (DoS surface)"
    fi
    ;;
  *)
    skip "per_page=100000 returned HTTP ${status}; not a clean signal"
    ;;
esac

end_suite
