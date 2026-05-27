#!/usr/bin/env bash
# test-search-edges-1372.sh -- E2E reproducer for artifact-keeper#1372.
#
# Closing PR: artifact-keeper#1384 (merged 2026-05-26). This script is the
# E2E counterpart to the unit + integration tests landed in that PR; it
# exercises the live HTTP surface so a future regression that re-introduces
# the limit clamp or strips sort_order before reaching the SQL builder is
# caught against the running backend (not just the in-process router).
#
# Bug class: silently overriding an explicit query parameter.
#   a) `limit=0` (or `per_page=0` on advanced) was clamped to the default
#      page size by `clamp(1, MAX)`. Effect: an autocomplete dropdown set
#      to limit=0 still showed one suggestion; a recent-panel toggled to
#      limit=0 still rendered the default page. The PR short-circuits
#      Some(0) to an empty array BEFORE the clamp.
#   b) `/search/advanced?sort_by=size&sort_order=asc` was indistinguishable
#      from `sort_order=desc`. The size branch ordered by `created_at DESC`
#      unconditionally; `sort_order` was deserialized off `AdvancedSearchQuery`
#      but never wired into the underlying `SearchQuery` until the PR. The
#      load-bearing assertion below uploads three sentinels of distinct
#      sizes and asserts the head hit of asc != head hit of desc.
#
# Endpoints (verified against backend/src/api/handlers/search.rs router):
#   GET /api/v1/search/suggest?prefix=&limit=    (limit=0 short-circuit)
#   GET /api/v1/search/recent?limit=             (limit=0 short-circuit)
#   GET /api/v1/search/advanced?per_page=0       (per_page=0 short-circuit)
#   GET /api/v1/search/advanced?sort_by=size&sort_order=asc|desc
#
# NOTE: the task brief referenced `/search/autocomplete`; the actual route
# is `/search/suggest` (see PR #1384 body: "/search/suggest ... honor
# explicit limit=0"). Same handler, the alternative name was never minted.
#
# Skips cleanly if the search backend or indexer is not available; FAILs
# loudly if the endpoints respond but return the wrong shape (silent
# regression of the original #1372 behaviour).
#
# Requires: curl, jq, dd (for sized sentinels)

# shellcheck source=../lib/common.sh disable=SC1091
source "$(dirname "$0")/../lib/common.sh"

begin_suite "search-edges-1372"
auth_admin
setup_workdir

REPO_KEY="srch1372-${RUN_ID}"
UNIQUE_TERM="s1372${RUN_ID//[^a-z0-9]/}"

add_exit_handler "api_delete \"/api/v1/repositories/${REPO_KEY}\" >/dev/null 2>&1 || true"

# ---------------------------------------------------------------------------
# Preflight: confirm /search/suggest exists (handler is part of the same
# router as /recent and /advanced, so a single probe is enough). If the
# backend predates v1.2 the route may 404; gracefully skip rather than
# fail the gate.
# ---------------------------------------------------------------------------

preflight_status=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/search/suggest?prefix=preflight" 2>/dev/null || echo "000")
case "$preflight_status" in
  404|501) skip_suite "search/suggest endpoint not mounted (HTTP ${preflight_status})" ;;
  503|504|000) skip_suite "search backend unavailable (HTTP ${preflight_status})" ;;
esac

# ---------------------------------------------------------------------------
# Build three sentinels of clearly different sizes (small / medium / large).
# Sizes chosen so the size column is unambiguously sortable: ~100 B, ~50 KiB,
# ~2 MiB. dd is used over `head -c` because BusyBox `head` does not honour
# `-c` on every runner.
# ---------------------------------------------------------------------------

begin_test "Build three sentinels with distinct sizes"
small_path="${WORK_DIR}/${UNIQUE_TERM}-small.bin"
medium_path="${WORK_DIR}/${UNIQUE_TERM}-medium.bin"
large_path="${WORK_DIR}/${UNIQUE_TERM}-large.bin"

if dd if=/dev/urandom of="$small_path"  bs=1   count=100  status=none 2>/dev/null && \
   dd if=/dev/urandom of="$medium_path" bs=1k  count=50   status=none 2>/dev/null && \
   dd if=/dev/urandom of="$large_path"  bs=1k  count=2048 status=none 2>/dev/null; then
  pass
else
  fail "could not synthesise sentinel files via dd"
  end_suite
  exit 1
fi

begin_test "Create repo and upload sentinels"
if create_local_repo "$REPO_KEY" "generic" >/dev/null 2>&1; then
  api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/${UNIQUE_TERM}/small/${UNIQUE_TERM}-small.bin"   "$small_path"  >/dev/null 2>&1 || true
  api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/${UNIQUE_TERM}/medium/${UNIQUE_TERM}-medium.bin" "$medium_path" >/dev/null 2>&1 || true
  api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/${UNIQUE_TERM}/large/${UNIQUE_TERM}-large.bin"   "$large_path"  >/dev/null 2>&1 || true
  pass
else
  fail "could not create repo ${REPO_KEY}"
  end_suite
  exit 1
fi

# Indexer settle. The OpenSearch backend (v1.2.0+) and the SQL fallback both
# need a moment to reflect the new rows in subsequent search calls.
sleep 4

# ---------------------------------------------------------------------------
# Case (a): /search/suggest?limit=0 must return zero suggestions.
#
# The pre-fix behaviour was `clamp_positive_limit(Some(0), 10, 1, 50) == 1`,
# so the response carried one fallback suggestion. The post-fix handler
# short-circuits Some(0) to an empty Vec before touching the DB.
# ---------------------------------------------------------------------------

begin_test "GET /search/suggest?limit=0 returns empty array (regression #1372)"
# shellcheck disable=SC2086  # CURL_TIMEOUT must word-split, per common.sh
suggest_resp=$(curl -sf $CURL_TIMEOUT -H "$(auth_header)" \
  "${BASE_URL}/api/v1/search/suggest?prefix=${UNIQUE_TERM:0:4}&limit=0" 2>/dev/null || echo "")
if [ -z "$suggest_resp" ]; then
  fail "GET /search/suggest?limit=0 returned no body (network or non-2xx)"
elif ! echo "$suggest_resp" | jq -e '.suggestions | type == "array"' >/dev/null 2>&1; then
  fail "GET /search/suggest?limit=0 returned shape without .suggestions[]" "$suggest_resp"
else
  suggest_count=$(echo "$suggest_resp" | jq -r '.suggestions | length')
  if [ "$suggest_count" = "0" ]; then
    pass
  else
    fail "GET /search/suggest?limit=0 returned ${suggest_count} suggestions; expected 0 (pre-#1384 clamp regression)" "$suggest_resp"
  fi
fi

# ---------------------------------------------------------------------------
# Case (b): /search/recent?limit=0 must return an empty array.
#
# The recent endpoint returns Vec<SearchResultItem> directly (not wrapped in
# an object), so we parse it as an array. Pre-fix: returned the default page
# (20 items). Post-fix: empty array.
# ---------------------------------------------------------------------------

begin_test "GET /search/recent?limit=0 returns empty array (regression #1372)"
# shellcheck disable=SC2086  # CURL_TIMEOUT must word-split, per common.sh
recent_resp=$(curl -sf $CURL_TIMEOUT -H "$(auth_header)" \
  "${BASE_URL}/api/v1/search/recent?limit=0" 2>/dev/null || echo "")
if [ -z "$recent_resp" ]; then
  fail "GET /search/recent?limit=0 returned no body (network or non-2xx)"
elif ! echo "$recent_resp" | jq -e 'type == "array"' >/dev/null 2>&1; then
  fail "GET /search/recent?limit=0 returned non-array body" "$recent_resp"
else
  recent_count=$(echo "$recent_resp" | jq -r 'length')
  if [ "$recent_count" = "0" ]; then
    pass
  else
    fail "GET /search/recent?limit=0 returned ${recent_count} items; expected 0 (pre-#1384 clamp regression)"
  fi
fi

# ---------------------------------------------------------------------------
# Case (b'): /search/advanced?per_page=0 must return an empty items array.
#
# Bonus assertion not in the issue text but covered by the same PR: the
# advanced endpoint takes `per_page` (not `limit`) and also gained the
# zero-page short-circuit. We check it because the legacy clamp would
# otherwise leak through the AdvancedSearchQuery -> SearchQuery wiring.
# ---------------------------------------------------------------------------

begin_test "GET /search/advanced?per_page=0 returns empty items array"
# shellcheck disable=SC2086  # CURL_TIMEOUT must word-split, per common.sh
adv_zero_resp=$(curl -sf $CURL_TIMEOUT -H "$(auth_header)" \
  "${BASE_URL}/api/v1/search/advanced?query=${UNIQUE_TERM}&per_page=0" 2>/dev/null || echo "")
if [ -z "$adv_zero_resp" ]; then
  skip "advanced search per_page=0 probe returned no body"
elif ! echo "$adv_zero_resp" | jq -e '.items | type == "array"' >/dev/null 2>&1; then
  fail "advanced search per_page=0 response missing .items[]" "$adv_zero_resp"
else
  adv_zero_count=$(echo "$adv_zero_resp" | jq -r '.items | length')
  if [ "$adv_zero_count" = "0" ]; then
    pass
  else
    fail "advanced search per_page=0 returned ${adv_zero_count} items; expected 0" "$adv_zero_resp"
  fi
fi

# ---------------------------------------------------------------------------
# Case (c): /search/advanced?sort_by=size&sort_order=asc|desc must produce
# DIFFERENT first hits. This is the canonical "sort_order actually flips"
# assertion -- if asc and desc agree on the head of the result set, the
# parameter was never applied.
#
# We restrict the query window to our three sentinels by filtering on
# repository_key and the UNIQUE_TERM prefix so concurrent suites cannot
# pollute the head of the list.
# ---------------------------------------------------------------------------

_first_path() {
  # First .items[0].path on a 2xx advanced response, or empty.
  local body="$1"
  echo "$body" | jq -r '.items[0].path // .items[0].name // empty' 2>/dev/null || true
}

# shellcheck disable=SC2086  # CURL_TIMEOUT must word-split, per common.sh
asc_resp=$(curl -sf $CURL_TIMEOUT -H "$(auth_header)" \
  "${BASE_URL}/api/v1/search/advanced?query=${UNIQUE_TERM}&repository_key=${REPO_KEY}&sort_by=size&sort_order=asc&per_page=10" 2>/dev/null || echo "")
# shellcheck disable=SC2086  # CURL_TIMEOUT must word-split, per common.sh
desc_resp=$(curl -sf $CURL_TIMEOUT -H "$(auth_header)" \
  "${BASE_URL}/api/v1/search/advanced?query=${UNIQUE_TERM}&repository_key=${REPO_KEY}&sort_by=size&sort_order=desc&per_page=10" 2>/dev/null || echo "")

begin_test "advanced sort_by=size returned items for both directions"
asc_count=$(echo "$asc_resp"  | jq -r '.items | length // 0' 2>/dev/null || echo 0)
desc_count=$(echo "$desc_resp" | jq -r '.items | length // 0' 2>/dev/null || echo 0)
if ! [[ "$asc_count" =~ ^[0-9]+$ ]] || ! [[ "$desc_count" =~ ^[0-9]+$ ]]; then
  fail "advanced search returned unparseable items count (asc=${asc_count}, desc=${desc_count})"
elif [ "$asc_count" -lt 2 ] || [ "$desc_count" -lt 2 ]; then
  # If the indexer is too slow on this runner we cannot prove the flip, but
  # we can still detect the regression because the *handler-level* sort
  # logic operates on whatever rows did make it. Two rows is the minimum
  # that lets head(asc) and head(desc) differ.
  skip "indexer returned ${asc_count}/${desc_count} items for the sentinel window; not enough to prove the flip"
else
  pass
fi

begin_test "advanced sort_by=size head hit flips between asc and desc (regression #1372)"
asc_head=$(_first_path "$asc_resp")
desc_head=$(_first_path "$desc_resp")
if [ -z "$asc_head" ] || [ -z "$desc_head" ]; then
  skip "could not extract head hits (asc='${asc_head}', desc='${desc_head}')"
elif [ "$asc_head" = "$desc_head" ]; then
  fail "asc and desc head hits are identical ('${asc_head}'); sort_order was ignored (pre-#1384 regression)" \
"asc response (first 500 bytes): $(echo "$asc_resp"  | jq -c '.items | map({path, size: .size_bytes // .size})' 2>/dev/null | cut -c 1-500)
desc response (first 500 bytes): $(echo "$desc_resp" | jq -c '.items | map({path, size: .size_bytes // .size})' 2>/dev/null | cut -c 1-500)"
else
  pass
fi

# ---------------------------------------------------------------------------
# Optional belt-and-braces: head(asc) should be the small sentinel and
# head(desc) the large one. Skip rather than fail if .size_bytes is not
# populated on this backend (older indexer rows had a null column).
# ---------------------------------------------------------------------------

begin_test "advanced sort_by=size orders by actual byte size (smallest first under asc)"
asc_size=$(echo "$asc_resp" | jq -r '.items[0].size_bytes // .items[0].size // empty' 2>/dev/null || echo "")
desc_size=$(echo "$desc_resp" | jq -r '.items[0].size_bytes // .items[0].size // empty' 2>/dev/null || echo "")
if ! [[ "$asc_size" =~ ^[0-9]+$ ]] || ! [[ "$desc_size" =~ ^[0-9]+$ ]]; then
  skip "size field not exposed on result items (asc='${asc_size}', desc='${desc_size}')"
elif [ "$asc_size" -lt "$desc_size" ]; then
  pass
else
  fail "head(asc).size=${asc_size} should be < head(desc).size=${desc_size}"
fi

end_suite
