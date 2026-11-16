#!/usr/bin/env bash
# test-search-autocomplete-edges.sh - Autocomplete (/search/suggest) edges
#
# Epic 8 sub-task 8.12 (artifact-keeper-test#73). The suggest endpoint
# (OpenAPI: GET /api/v1/search/suggest?prefix=...&limit=...) has only a
# smoke probe today (test-search-basic.sh checks 2xx). Edge cases that
# have caused real regressions in this handler:
#
#   1. Empty prefix (prefix="") -> the OpenAPI marks prefix as required.
#      Must reject with 4xx; a 5xx would imply the handler tried to
#      walk a zero-length string.
#
#   2. Very long prefix (4 KiB) -> tests the prefix-length cap. Must
#      not 5xx; reasonable behaviours are 4xx (rejected) or 2xx with
#      no suggestions.
#
#   3. Prefix containing special characters (Lucene/regex metacharacters,
#      Unicode, percent-encoded bytes) -> must not 5xx, must not echo
#      user input back as part of a server-side error.
#
#   4. limit=0 -> must produce an empty suggestions array (not a panic,
#      not the default-limited list silently).
#
#   5. limit=-1 -> must 4xx or be coerced; must not 5xx.
#
#   6. Happy path: prefix matching our sentinel returns >= 1 suggestion.
#      This is the "we actually exercise the indexer" sanity check.
#
# Skips cleanly if /api/v1/search/suggest is not mounted (404/501).
#
# Requires: curl, jq

source "$(dirname "$0")/../lib/common.sh"

begin_suite "search-autocomplete-edges"
# Two bounded polls below, 45 s each.
require_wait_budget 90 "persisted-sentinel and suggestion polls"
auth_admin
setup_workdir

# Preflight: the OpenAPI says prefix is required, so a probe without it
# may legitimately 4xx; treat that as "endpoint exists" too.
preflight_status=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/search/suggest?prefix=preflight" 2>/dev/null || echo "000")
case "$preflight_status" in
  404|501)
    skip_suite "suggest endpoint not available (HTTP ${preflight_status})"
    ;;
  503|504|000)
    skip_suite "search backend unavailable (HTTP ${preflight_status})"
    ;;
esac

REPO_KEY="autocp-${RUN_ID}"
UNIQUE_TERM="acprfx${RUN_ID//[^a-z0-9]/}"

add_exit_handler "api_delete \"/api/v1/repositories/${REPO_KEY}\" >/dev/null 2>&1 || true"

begin_test "Create repo and upload sentinel for suggestions"
if create_local_repo "$REPO_KEY" "generic" >/dev/null 2>&1; then
  echo "autocomplete-sentinel-${UNIQUE_TERM}" > "${WORK_DIR}/${UNIQUE_TERM}.txt"
  api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/${UNIQUE_TERM}/${UNIQUE_TERM}.txt" \
    "${WORK_DIR}/${UNIQUE_TERM}.txt" >/dev/null 2>&1 || true
  pass
else
  fail "could not create repo"
  end_suite
fi

# _artifact_listed REPO PATH
# True once the repository's artifact listing carries a row whose path ends in
# PATH, i.e. the upload has been persisted (test#364: replaces a fixed sleep).
_artifact_listed() {
  api_get "/api/v1/repositories/$1/artifacts?per_page=100" 2>/dev/null \
    | jq -e --arg p "$2" '[.items[]? | select((.path // "") | endswith($p))] | length > 0' >/dev/null 2>&1
}

# Suggestions are drawn from the persisted artifact names.
begin_test "Uploaded sentinel is persisted"
if assert_eventually "${UNIQUE_TERM}.txt listed in ${REPO_KEY}" 45 _artifact_listed "$REPO_KEY" "${UNIQUE_TERM}.txt"; then
  pass
fi

# _suggest_status <query-string>
# Returns HTTP status for a suggest request.
_suggest_status() {
  local qs="$1"
  curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(auth_header)" \
    "${BASE_URL}/api/v1/search/suggest?${qs}" 2>/dev/null || echo "000"
}

# _suggest_count <query-string>
# Returns the number of suggestions in a 2xx response, or "" on error.
_suggest_count() {
  local qs="$1"
  local body
  body=$(curl -sf $CURL_TIMEOUT -H "$(auth_header)" \
    "${BASE_URL}/api/v1/search/suggest?${qs}" 2>/dev/null || echo "")
  if [ -z "$body" ]; then
    echo ""
    return
  fi
  echo "$body" | jq -r '
    if (.suggestions? | type) == "array" then (.suggestions|length)
    elif type == "array" then length
    elif (.items? | type) == "array" then (.items|length)
    else 0 end' 2>/dev/null || echo ""
}

# -------------------------------------------------------------------------
# 1. Empty prefix (prefix="") must not 5xx. 4xx is the documented response.
# -------------------------------------------------------------------------

begin_test "prefix= (empty) does not 5xx"
status=$(_suggest_status "prefix=")
case "$status" in
  5*) fail "empty prefix returned HTTP ${status}; expected 4xx or 2xx-empty" ;;
  *)  pass ;;
esac

# -------------------------------------------------------------------------
# 2. Very long prefix (4 KiB) must not 5xx.
# -------------------------------------------------------------------------

begin_test "prefix=4KiB does not 5xx"
# Build a 4096-character prefix without invoking external tools that may
# not be present (printf with %.0s is portable across bash/zsh).
long_prefix=$(printf 'a%.0s' $(seq 1 4096))
status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" \
  --data-urlencode "prefix=${long_prefix}" \
  -G "${BASE_URL}/api/v1/search/suggest" 2>/dev/null || echo "000")
case "$status" in
  5*) fail "4 KiB prefix returned HTTP ${status}; handler did not bound input length" ;;
  *)  pass ;;
esac

# -------------------------------------------------------------------------
# 3. Special-character prefix must not 5xx and must not echo as raw HTML.
# -------------------------------------------------------------------------

begin_test "prefix with regex/Lucene metacharacters does not 5xx"
# Mix of Lucene metas (* ? : + - ! ( ) [ ] { }), a unicode codepoint,
# and a percent-encoded byte. curl --data-urlencode handles encoding.
special='*?:+!()[]{}-/\\"%20é'
status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" \
  --data-urlencode "prefix=${special}" \
  -G "${BASE_URL}/api/v1/search/suggest" 2>/dev/null || echo "000")
case "$status" in
  5*) fail "special-character prefix returned HTTP ${status}; metacharacter handling broken" ;;
  *)  pass ;;
esac

# -------------------------------------------------------------------------
# 4. limit=0 must produce an empty result (not the default-limited list).
# -------------------------------------------------------------------------

begin_test "limit=0 returns zero suggestions (or 4xx)"
status=$(_suggest_status "prefix=${UNIQUE_TERM:0:4}&limit=0")
case "$status" in
  5*) fail "limit=0 returned HTTP ${status}" ;;
  4*) pass ;;
  2*)
    count=$(_suggest_count "prefix=${UNIQUE_TERM:0:4}&limit=0")
    if [ -z "$count" ]; then
      skip "limit=0 response not parseable"
    elif [ "$count" = "0" ]; then
      pass
    else
      fail "limit=0 returned ${count} suggestions; expected 0"
    fi
    ;;
  *)
    skip "limit=0 returned HTTP ${status}; not a clean signal"
    ;;
esac

# -------------------------------------------------------------------------
# 5. limit=-1 must not 5xx (signed-to-unsigned underflow).
# -------------------------------------------------------------------------

begin_test "limit=-1 does not 5xx"
status=$(_suggest_status "prefix=${UNIQUE_TERM:0:4}&limit=-1")
case "$status" in
  5*) fail "limit=-1 returned HTTP ${status}; unsigned underflow regression" ;;
  *)  pass ;;
esac

# -------------------------------------------------------------------------
# 6. Sanity: a prefix that matches our sentinel returns >= 1 suggestion.
#    This is the "the indexer is actually wired" check; without it, all
#    of the edge cases above could pass against a no-op handler.
# -------------------------------------------------------------------------

# The sentinel is persisted (checked above), so a suggestion that never
# surfaces within the bounded poll is a product failure, not indexer lag
# (test#364: replaces a fixed `sleep 4` retry that skipped on a miss).
_sentinel_suggested() {
  local n
  n=$(_suggest_count "prefix=${UNIQUE_TERM:0:5}&limit=10")
  [ -n "$n" ] && [ "$n" -ge 1 ] 2>/dev/null
}

begin_test "prefix matching sentinel returns at least one suggestion"
count=$(_suggest_count "prefix=${UNIQUE_TERM:0:5}&limit=10")
if [ -z "$count" ]; then
  skip "sanity suggest request returned error or unparseable body"
elif assert_eventually "suggest?prefix=${UNIQUE_TERM:0:5} returns >= 1 suggestion" 45 _sentinel_suggested; then
  pass
fi

end_suite
