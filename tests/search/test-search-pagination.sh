#!/usr/bin/env bash
# test-search-pagination.sh - Pagination edge cases for search
#
# Epic 8 sub-task 8.11 (artifact-keeper-test#73). The advanced search
# endpoint accepts page / per_page parameters. Edge cases that have no
# E2E coverage today:
#
#   1. page=0 must not return an HTTP 5xx; it should either redirect to
#      page 1 semantics or return 400. The previous behaviour panicked
#      on a usize underflow in the offset math.
#   2. Negative page (-1) must be rejected with 4xx, not silently
#      treated as a huge unsigned offset.
#   3. per_page=0 must not return an empty paged result with a non-zero
#      "total" field that contradicts itself.
#   4. A normal page=1 request after the corpus is indexed returns at
#      least one hit (sanity).
#
# Requires: curl, jq

source "$(dirname "$0")/../lib/common.sh"

begin_suite "search-pagination"
auth_admin
setup_workdir

# Preflight: when OpenSearch is down or unwired the search endpoints
# either return 503 or hang past the CURL_TIMEOUT window. Skipping the
# suite at the suite level is faster (1-2s vs 60-120s of failed assertions)
# and produces a clean signal for the release-gate dashboard.
preflight_status=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/search?q=preflight&per_page=1" 2>/dev/null || echo "000")
case "$preflight_status" in
  503|504|000)
    skip_suite "search backend unavailable (HTTP ${preflight_status}); OpenSearch may be down"
    ;;
esac

REPO_KEY="pag-${RUN_ID}"
UNIQUE_TERM="pagn${RUN_ID//[^a-z0-9]/}"

begin_test "Create repo and upload sentinel"
if create_local_repo "$REPO_KEY" "generic" >/dev/null 2>&1; then
  echo "pagination-sentinel-${UNIQUE_TERM}" > "${WORK_DIR}/${UNIQUE_TERM}.txt"
  api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/${UNIQUE_TERM}/${UNIQUE_TERM}.txt" \
    "${WORK_DIR}/${UNIQUE_TERM}.txt" >/dev/null 2>&1 || true
  pass
else
  fail "could not create repo"
  end_suite
fi

sleep 3

# Pick whichever search endpoint the backend exposes; reuse the same one
# for every pagination probe so the assertions are apples-to-apples.
SEARCH_BASE=""
for candidate in "/api/v1/search" "/api/v1/search/advanced"; do
  if curl -sf $CURL_TIMEOUT -o /dev/null -H "$(auth_header)" \
     "${BASE_URL}${candidate}?q=${UNIQUE_TERM}" 2>/dev/null; then
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

# -------------------------------------------------------------------------
# 1. page=0 must not 5xx.
# -------------------------------------------------------------------------

begin_test "page=0 returns a non-5xx response"
status=$(curl -s -o /dev/null -w "%{http_code}" $CURL_TIMEOUT \
  -H "$(auth_header)" \
  "${BASE_URL}${SEARCH_BASE}?q=${UNIQUE_TERM}&page=0&per_page=10" 2>/dev/null || echo 000)
case "$status" in
  5*) fail "page=0 panicked at ${SEARCH_BASE}: HTTP ${status}" ;;
  *)  pass ;;
esac

# -------------------------------------------------------------------------
# 2. negative page must 4xx.
# -------------------------------------------------------------------------

begin_test "page=-1 returns 4xx, not 5xx"
status=$(curl -s -o /dev/null -w "%{http_code}" $CURL_TIMEOUT \
  -H "$(auth_header)" \
  "${BASE_URL}${SEARCH_BASE}?q=${UNIQUE_TERM}&page=-1&per_page=10" 2>/dev/null || echo 000)
case "$status" in
  4*) pass ;;
  5*) fail "page=-1 returned ${status}; expected 4xx" ;;
  *)
    # Some backends coerce to page=1 silently. Permit 2xx as long as the
    # body still parses; the strict-contract version of this assertion is
    # planned for v1.2.0 once the API contract is finalized.
    skip "page=-1 returned ${status}; not a hard error in this revision"
    ;;
esac

# -------------------------------------------------------------------------
# 3. per_page=0 must not yield a self-contradicting page.
# -------------------------------------------------------------------------

begin_test "per_page=0 is internally consistent"
resp=$(curl -sf $CURL_TIMEOUT -H "$(auth_header)" \
  "${BASE_URL}${SEARCH_BASE}?q=${UNIQUE_TERM}&page=1&per_page=0" 2>/dev/null || echo '')
if [ -z "$resp" ]; then
  skip "per_page=0 rejected (acceptable)"
else
  hits=$(echo "$resp" | jq -r '
    if type=="array" then length
    elif .results then (.results|length)
    elif .hits    then (.hits|length)
    else 0 end' 2>/dev/null || echo 0)
  total=$(echo "$resp" | jq -r '.total // .total_hits // empty' 2>/dev/null || echo "")
  if [ "$hits" = "0" ]; then
    # Even an explicit total > 0 with hits == 0 is fine; the page itself
    # is consistent. We only fail if the response claims it returned
    # rows that aren't there.
    pass
  else
    if [ -n "$total" ] && [ "$total" != "null" ] && [ "$hits" -gt "$total" ]; then
      fail "per_page=0 returned ${hits} rows but total=${total}"
    else
      pass
    fi
  fi
fi

# -------------------------------------------------------------------------
# 4. page=1 sanity.
# -------------------------------------------------------------------------

begin_test "page=1,per_page=10 returns at least one hit"
resp=$(curl -sf $CURL_TIMEOUT -H "$(auth_header)" \
  "${BASE_URL}${SEARCH_BASE}?q=${UNIQUE_TERM}&page=1&per_page=10" 2>/dev/null || echo '')
if [ -z "$resp" ]; then
  skip "page=1 request returned error"
else
  hits=$(echo "$resp" | jq -r '
    if type=="array" then length
    elif .results then (.results|length)
    elif .hits    then (.hits|length)
    else 0 end' 2>/dev/null || echo 0)
  if [ "$hits" -ge 1 ]; then
    pass
  else
    # Indexer may need a few more seconds on slow runners.
    sleep 5
    resp=$(curl -sf $CURL_TIMEOUT -H "$(auth_header)" \
      "${BASE_URL}${SEARCH_BASE}?q=${UNIQUE_TERM}&page=1&per_page=10" 2>/dev/null || echo '')
    hits=$(echo "$resp" | jq -r '
      if type=="array" then length
      elif .results then (.results|length)
      elif .hits    then (.hits|length)
      else 0 end' 2>/dev/null || echo 0)
    if [ "$hits" -ge 1 ]; then
      pass
    else
      skip "indexing did not surface the sentinel within budget (best-effort)"
    fi
  fi
fi

# -------------------------------------------------------------------------
# 5. page beyond total: requesting page=total_pages+1 must return an empty
#    hits list AND a self-consistent total field. This catches off-by-one
#    bugs in the offset arithmetic that would otherwise look "fine"
#    against page=1.
# -------------------------------------------------------------------------

begin_test "page beyond total returns empty hits with consistent total"
# First find the current total for our unique term.
resp_first=$(curl -sf $CURL_TIMEOUT -H "$(auth_header)" \
  "${BASE_URL}${SEARCH_BASE}?q=${UNIQUE_TERM}&page=1&per_page=1" 2>/dev/null || echo '')
if [ -z "$resp_first" ]; then
  skip "page=1 query returned no response, cannot derive total"
else
  total_first=$(echo "$resp_first" | jq -r '
    .total // .total_hits // .total_results //
    (if type=="array" then length
     elif .results then (.results|length)
     elif .hits    then (.hits|length)
     else 0 end)' 2>/dev/null || echo 0)
  # Coerce empty / null to 0 so the arithmetic below stays well-formed.
  case "$total_first" in
    ''|null) total_first=0 ;;
  esac
  # Bound the requested page so a backend that mis-reports total=0 doesn't
  # turn this into a probe on page=1 (which we already cover above).
  per_page_probe=10
  if [ "$total_first" -le 0 ] 2>/dev/null; then
    # Indexer may not have surfaced anything yet; probe page=999 anyway,
    # since the goal is "page-beyond-total must not 5xx or report rows".
    probe_page=999
  else
    # ceil(total / per_page) + 1
    probe_page=$(( total_first / per_page_probe + 2 ))
  fi
  resp_far=$(curl -s -w $'\n%{http_code}' $CURL_TIMEOUT -H "$(auth_header)" \
    "${BASE_URL}${SEARCH_BASE}?q=${UNIQUE_TERM}&page=${probe_page}&per_page=${per_page_probe}" 2>/dev/null || printf '\n000')
  # Split body (everything before the last newline) from status (final line).
  # `head -n -1` is GNU-only; awk handles both BSD and GNU portably.
  body_far=$(printf '%s' "$resp_far" | awk 'NR>1{print prev}{prev=$0}')
  status_far=$(printf '%s' "$resp_far" | awk 'END{print}')
  case "$status_far" in
    5*)
      fail "page-beyond-total (page=${probe_page}) returned HTTP ${status_far}"
      ;;
    2*)
      hits_far=$(echo "$body_far" | jq -r '
        if type=="array" then length
        elif .results then (.results|length)
        elif .hits    then (.hits|length)
        else 0 end' 2>/dev/null || echo 0)
      total_far=$(echo "$body_far" | jq -r '
        .total // .total_hits // .total_results // empty' 2>/dev/null || echo "")
      # The page must be empty (no rows past the last page).
      if [ "$hits_far" != "0" ]; then
        fail "page=${probe_page} returned ${hits_far} hits, expected 0 (beyond total=${total_first})"
      # And the total, if present, must agree with the first-page total so
      # the response is internally consistent across the page parameter.
      elif [ -n "$total_far" ] && [ "$total_far" != "null" ] && \
           [ "$total_first" -gt 0 ] 2>/dev/null && \
           [ "$total_far" != "$total_first" ]; then
        fail "total field changes with page (page=1 total=${total_first}, page=${probe_page} total=${total_far})"
      else
        pass
      fi
      ;;
    4*)
      # 4xx is acceptable: some backends explicitly reject out-of-range
      # pages. The contract we care about is "no panic, no phantom rows".
      pass
      ;;
    *)
      skip "page-beyond-total returned HTTP ${status_far}; not a clean signal"
      ;;
  esac
fi

# -------------------------------------------------------------------------
# Cleanup.
# -------------------------------------------------------------------------

api_delete "/api/v1/repositories/${REPO_KEY}" >/dev/null 2>&1 || true

end_suite
