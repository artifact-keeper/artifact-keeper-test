#!/usr/bin/env bash
# =============================================================================
# tiers/search-gin-2871/oracle.sh -- #2871 GIN-indexed search_vector oracle
# =============================================================================
# run.sh has stood up filesystem/single and exported BASE_URL, DB_CONTAINER,
# ADMIN_USER/ADMIN_PASS, RELEASE_GATE=1, COMMON_SH, JUNIT_OUTPUT_DIR, DTF_SLOT,
# RUN_ID.
#
# PERF FIX UNDER TEST (#2871 / PF-009, epic #2516): SearchService::search
# (/search/quick + /search/advanced) filtered on an inline
#   to_tsvector('english', name || ' ' || path || ' ' || COALESCE(version,''))
#     @@ to_tsquery('english', $1)
# predicate with no matching column/index -> a Parallel Seq Scan that recomputed
# to_tsvector per live row, twice (item query + pagination COUNT). The fix adds
# a trigger-maintained `search_vector tsvector` column + a partial GIN index
# (WHERE is_deleted=false) and rewrites both queries + the COUNT to the stored
# column, preserving match semantics and ordering exactly.
#
# This oracle proves BOTH the structural fix (column/trigger/index exist -- the
# discriminator vs a pre-#2871 image) AND that behavior is unchanged.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"
# shellcheck source=/dev/null
source "$COMMON_SH"

require_cmd jq
require_cmd sha256sum

# Unique, alphanumeric marker so search-term assertions are exact regardless of
# any other data in the disposable stack.
ALNUM="$(printf '%s' "${RUN_ID}" | tr -cd '[:alnum:]' | tail -c 8)"
TOKEN="zsearch${ALNUM}"
REPO="ginsearch-${ALNUM}"

psql_q() {
  docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]'
}

# Chunked upload (the universal write path): POST session -> PATCH single chunk
# -> PUT complete. Small bodies fit one 8 MiB chunk.
upload_artifact() {
  local name="$1" ver="$2" path="$3" body="$4"
  local size sha sid code
  size=$(printf '%s' "$body" | wc -c)
  sha=$(printf '%s' "$body" | sha256sum | cut -d' ' -f1)
  sid=$(curl -s -X POST "${BASE_URL}/api/v1/uploads" -H "$(auth_header)" \
        -H 'Content-Type: application/json' \
        -d "{\"repository_key\":\"${REPO}\",\"artifact_path\":\"${path}\",\"artifact_name\":\"${name}\",\"artifact_version\":\"${ver}\",\"total_size\":${size},\"checksum_sha256\":\"${sha}\",\"chunk_size\":8388608}" \
        | jq -r '.session_id // empty')
  [ -n "$sid" ] || { echo "  upload ${name}: no session_id" >&2; return 1; }
  curl -s -X PATCH "${BASE_URL}/api/v1/uploads/${sid}" -H "$(auth_header)" \
    -H "Content-Range: bytes 0-$((size - 1))/${size}" \
    -H 'Content-Type: application/octet-stream' \
    --data-binary "$body" >/dev/null || return 1
  code=$(curl -s -o /dev/null -w '%{http_code}' -X PUT \
    "${BASE_URL}/api/v1/uploads/${sid}/complete" -H "$(auth_header)")
  [ "$code" = "200" ] || { echo "  upload ${name}: complete HTTP ${code}" >&2; return 1; }
  return 0
}

# newline-separated result names for a quick search term
quick_names() {
  curl -s -H "$(auth_header)" "${BASE_URL}/api/v1/search/quick?q=$1" | jq -r '.results[].name'
}
# newline-separated item names for an advanced search term
adv_names() {
  curl -s -H "$(auth_header)" "${BASE_URL}/api/v1/search/advanced?query=$1" | jq -r '.items[].name'
}

begin_suite "search-gin-2871"

auth_admin

# --- setup: repo + a discriminating artifact set -----------------------------
# Two artifacts whose names carry the unique TOKEN (must match a TOKEN search)
# and two "unrelated" artifacts that must NOT (proves the filter still filters).
begin_test "setup: create repo and upload the artifact fixture set"
setup_ok=1
create_local_repo "$REPO" generic || setup_ok=0
upload_artifact "${TOKEN}apollo"   "1.0.0" "pkg/${TOKEN}apollo/1.0.0/${TOKEN}apollo-1.0.0.bin"   "body-apollo"   || setup_ok=0
upload_artifact "${TOKEN}borealis" "2.0.0" "pkg/${TOKEN}borealis/2.0.0/${TOKEN}borealis-2.0.0.bin" "body-borealis" || setup_ok=0
upload_artifact "unrel${ALNUM}cygnus" "1.0.0" "pkg/cygnus/1.0.0/cygnus-1.0.0.bin" "body-cygnus" || setup_ok=0
upload_artifact "unrel${ALNUM}draco"  "1.0.0" "pkg/draco/1.0.0/draco-1.0.0.bin"   "body-draco"  || setup_ok=0
if [ "$setup_ok" != "1" ]; then
  fail "could not create repo / upload fixture artifacts"
  end_suite
fi
pass "repo ${REPO} created and 4 artifacts uploaded"

# --- structural discriminators (DB truth) ------------------------------------
# On a pre-#2871 image the column/trigger/index do not exist -> RED here.
begin_test "artifacts.search_vector tsvector column exists (#2871)"
col_type="$(psql_q "SELECT data_type FROM information_schema.columns WHERE table_name='artifacts' AND column_name='search_vector';")"
assert_eq "$col_type" "tsvector" \
  "artifacts.search_vector type is '${col_type}' (want tsvector; a pre-#2871 image has no such column)" \
  && pass "stored search_vector column present"

begin_test "partial GIN index idx_artifacts_search_vector_gin exists"
idx="$(psql_q "SELECT indexname FROM pg_indexes WHERE tablename='artifacts' AND indexname='idx_artifacts_search_vector_gin';")"
assert_eq "$idx" "idx_artifacts_search_vector_gin" \
  "expected GIN index idx_artifacts_search_vector_gin, got '${idx}'" \
  && pass "partial GIN index present"

begin_test "maintenance trigger ak_artifacts_search_vector_trg exists"
trg="$(psql_q "SELECT tgname FROM pg_trigger WHERE tgname='ak_artifacts_search_vector_trg';")"
assert_eq "$trg" "ak_artifacts_search_vector_trg" \
  "expected trigger ak_artifacts_search_vector_trg, got '${trg}'" \
  && pass "search_vector maintenance trigger present"

# --- behavior: quick search returns exactly the TOKEN set --------------------
begin_test "quick search matches exactly the two TOKEN artifacts"
q_sorted="$(quick_names "$TOKEN" | sort | paste -sd, -)"
assert_eq "$q_sorted" "${TOKEN}apollo,${TOKEN}borealis" \
  "quick search for '${TOKEN}' returned '${q_sorted}' (want the two TOKEN artifacts only)" \
  && pass "quick search membership is exact"

# --- behavior: advanced == quick (identical ordered results) + exact count ---
begin_test "advanced search returns identical ordered results to quick"
q_order="$(quick_names "$TOKEN" | paste -sd, -)"
a_order="$(adv_names  "$TOKEN" | paste -sd, -)"
assert_eq "$a_order" "$q_order" \
  "advanced order '${a_order}' != quick order '${q_order}' (semantics/ordering must be preserved)" \
  && pass "advanced and quick return the same ordered result set"

begin_test "advanced pagination total is exact (index-backed COUNT)"
adv_total="$(curl -s -H "$(auth_header)" "${BASE_URL}/api/v1/search/advanced?query=${TOKEN}" | jq -r '.pagination.total')"
assert_eq "$adv_total" "2" \
  "advanced total for '${TOKEN}' is '${adv_total}' (want exactly 2)" \
  && pass "advanced total count is exact"

# --- behavior: unrelated artifacts are excluded ------------------------------
begin_test "unrelated artifacts are excluded from a TOKEN search"
q_all="$(quick_names "$TOKEN")"
if printf '%s\n' "$q_all" | grep -q "cygnus\|draco"; then
  fail "TOKEN search leaked an unrelated artifact: ${q_all}"
else
  pass "search filters -- unrelated artifacts excluded"
fi

# --- behavior: prefix match is honored ---------------------------------------
begin_test "prefix search narrows to a single artifact"
pfx_sorted="$(quick_names "${TOKEN}apo" | sort | paste -sd, -)"
assert_eq "$pfx_sorted" "${TOKEN}apollo" \
  "prefix search '${TOKEN}apo' returned '${pfx_sorted}' (want only ${TOKEN}apollo)" \
  && pass "prefix match honored"

# --- behavior: tsquery-metacharacter term -> empty, HTTP 200 (not 500) -------
begin_test "metacharacter query returns empty result with HTTP 200 (not 500)"
meta_code="$(curl -s -o /tmp/dtf_meta_${ALNUM}.json -w '%{http_code}' -H "$(auth_header)" \
  "${BASE_URL}/api/v1/search/advanced?query=%21%28%26%7C%29")"
meta_total="$(jq -r '.pagination.total' /tmp/dtf_meta_${ALNUM}.json 2>/dev/null)"
rm -f /tmp/dtf_meta_${ALNUM}.json
if [ "$meta_code" = "200" ] && [ "$meta_total" = "0" ]; then
  pass "metacharacter query -> HTTP 200, total 0"
else
  fail "metacharacter query -> HTTP ${meta_code}, total '${meta_total}' (want 200 / 0)"
fi

# --- behavior: fresh upload is immediately searchable + trigger-populated ----
begin_test "freshly uploaded artifact is immediately searchable"
fresh_ok=1
upload_artifact "${TOKEN}fresh" "9.9.9" "pkg/${TOKEN}fresh/9.9.9/${TOKEN}fresh-9.9.9.bin" "body-fresh" || fresh_ok=0
if [ "$fresh_ok" != "1" ]; then
  fail "could not upload the fresh artifact"
else
  fresh_hit="$(quick_names "${TOKEN}fresh" | sort | paste -sd, -)"
  assert_eq "$fresh_hit" "${TOKEN}fresh" \
    "fresh-upload search returned '${fresh_hit}' (want ${TOKEN}fresh immediately)" \
    && pass "fresh upload is immediately searchable"
fi

begin_test "trigger populated search_vector on the fresh insert (DB truth)"
fresh_vec="$(psql_q "SELECT (search_vector IS NOT NULL) FROM artifacts WHERE name='${TOKEN}fresh' AND is_deleted=false;")"
assert_eq "$fresh_vec" "t" \
  "search_vector IS NOT NULL for the fresh row is '${fresh_vec}' (want t; the BEFORE INSERT trigger must populate it)" \
  && pass "search_vector populated by the maintenance trigger on insert"

end_suite
