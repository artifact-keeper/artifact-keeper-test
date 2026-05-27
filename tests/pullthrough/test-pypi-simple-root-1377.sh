#!/usr/bin/env bash
# test-pypi-simple-root-1377.sh - PyPI Remote simple-root index against a real upstream
#
# E2E reproducer for artifact-keeper#1377 assertion (a): the PyPI Remote
# /simple/ root index must return a non-empty HTML listing when proxied
# against a real upstream.
#
# Closing PR: artifact-keeper#1391 (merged at 172508c0).
#
# Root cause (per #1391):
#   pypi.rs::simple_root previously only queried the local artifacts
#   table, so a pure-proxy Remote PyPI repo returned an empty
#   <body></body> for /simple/ even when the upstream advertised
#   hundreds of projects. The fix in #1391 adds an upstream proxy +
#   merge path for Remote/Virtual repos and parses PEP 503 root HTML.
#
# What this test asserts:
#   1. /pypi/<remote-key>/simple/ returns HTTP 200 against a real
#      pypi.org-backed Remote repo (reachability gate first).
#   2. The body contains at least one <a ...>...</a> anchor entry,
#      proving simple_root proxied + parsed the upstream rather than
#      returning the previously-empty local-only result.
#   3. A second fetch of /simple/ also returns HTTP 200 with the same
#      shape, exercising the cache_path="simple/" proxy cache the fix
#      wired up (no upstream re-fetch is required for the assertion to
#      pass, but a working cache roundtrip would also satisfy it).
#
# Companion #1377 assertion (b) -- PyPI simple-root XSS sanitisation
# against a hostile upstream -- is NOT covered here. It is covered by
# the inline Rust unit tests added in #1391:
#
#   backend/src/api/handlers/pypi::tests::
#     test_parse_simple_root_projects_extracts_from_pep503_html
#     test_parse_simple_root_projects_falls_back_to_href_when_text_missing
#     test_parse_simple_root_projects_empty_when_no_anchors
#     test_parse_simple_root_projects_accepts_single_quoted_hrefs
#     test_parse_simple_root_projects_mixed_quote_styles
#     test_parse_simple_root_projects_decodes_html_entities_in_text
#     test_parse_simple_root_projects_decodes_html_entities_in_href_fallback
#     test_simple_root_remote_proxies_and_caches_upstream_index
#
# Driving a hostile upstream from bash would require a wiremock-style
# fixture serving crafted PEP 503 HTML with <script> payloads; the unit
# tests above already exercise the parser directly, so an E2E sanity
# check against real pypi.org is sufficient for the proxy + cache path.
#
# Skip behaviour:
#   If pypi.org is unreachable from the test runner (offline CI, egress
#   restrictions), the suite skips gracefully rather than failing. The
#   reachability gate is the first test so partial state doesn't leak
#   into the JUnit output.
#
# Requires: curl, jq

source "$(dirname "$0")/../lib/common.sh"

begin_suite "pypi-simple-root-1377"
auth_admin
setup_workdir

REMOTE_KEY="test-pypi-simpleroot-1377-${RUN_ID}"
UPSTREAM_URL="https://pypi.org"

UPSTREAM_REACHABLE=false

# -------------------------------------------------------------------------
# Reachability gate. Probe pypi.org BEFORE creating any repos so an
# offline runner produces a single "skip" line rather than failing later.
# -------------------------------------------------------------------------

begin_test "Probe upstream pypi.org reachability"
if curl -sf --max-time 10 "https://pypi.org/simple/" -o /dev/null 2>/dev/null; then
  UPSTREAM_REACHABLE=true
  pass
else
  skip "pypi.org unreachable from test environment"
fi

# -------------------------------------------------------------------------
# Create Remote PyPI repo pointing at pypi.org.
# -------------------------------------------------------------------------

begin_test "Create Remote PyPI repo against pypi.org"
if [ "$UPSTREAM_REACHABLE" != "true" ]; then
  skip "upstream unreachable"
elif create_remote_repo "$REMOTE_KEY" "pypi" "$UPSTREAM_URL"; then
  pass
else
  fail "could not create Remote PyPI repo against ${UPSTREAM_URL}"
fi

# Brief settle before the first proxy fetch.
sleep 2

# -------------------------------------------------------------------------
# Assertion (a) part 1: /simple/ returns 200 with non-empty HTML.
#
# Before #1391, this returned an empty <body></body>. After #1391,
# simple_root proxies the upstream and merges with any local artifacts.
# -------------------------------------------------------------------------

FIRST_BODY=""
FIRST_STATUS="000"
ROOT_TMP="${WORK_DIR}/simple-root-first.html"

begin_test "GET /simple/ returns non-empty HTML listing"
if [ "$UPSTREAM_REACHABLE" != "true" ]; then
  skip "upstream unreachable"
else
  FIRST_STATUS=$(curl -s -o "$ROOT_TMP" -w '%{http_code}' \
    $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${BASE_URL}/pypi/${REMOTE_KEY}/simple/" 2>/dev/null) || FIRST_STATUS="000"
  FIRST_BODY=$(cat "$ROOT_TMP" 2>/dev/null || echo "")
  if [ "$FIRST_STATUS" != "200" ]; then
    fail "expected HTTP 200, got ${FIRST_STATUS}" "${FIRST_BODY:0:500}"
  elif [ -z "$FIRST_BODY" ]; then
    fail "/simple/ returned 200 with an empty body (the exact #1377 regression)"
  else
    pass
  fi
fi

# -------------------------------------------------------------------------
# Assertion (a) part 2: body contains at least one <a ...>...</a> anchor.
#
# This is the strict bar from the task: "non-empty HTML listing at
# least one anchor tag". PEP 503 root indexes look like:
#   <a href="/simple/foo/">foo</a>
# The pre-#1391 regression returned <html><body></body></html> with
# zero anchors. We grep -c so the count itself is asserted, not just
# the presence of the substring.
# -------------------------------------------------------------------------

begin_test "Body contains at least one anchor tag"
if [ "$UPSTREAM_REACHABLE" != "true" ]; then
  skip "upstream unreachable"
elif [ -z "$FIRST_BODY" ]; then
  fail "no body to inspect (earlier fetch failed)"
else
  anchor_count=$(printf '%s' "$FIRST_BODY" | grep -oE '<a [^>]*>' | wc -l | tr -d ' ')
  if [ "${anchor_count:-0}" -lt 1 ]; then
    fail "expected >=1 <a ...> anchor in /simple/ body, got ${anchor_count}" "${FIRST_BODY:0:500}"
  else
    pass
  fi
fi

# -------------------------------------------------------------------------
# Cache roundtrip: second fetch should also return 200 with a
# similarly-shaped body. The fix wired the response through the
# proxy_service cache under cache_path="simple/", so this exercises
# both the cache-write (first call) and cache-read (this call) paths.
#
# We don't byte-diff the bodies because upstream pypi.org adds new
# packages constantly and the listing can drift between the two
# fetches; the anchor-count assertion is the load-bearing check.
# -------------------------------------------------------------------------

begin_test "Second GET /simple/ also returns non-empty HTML"
if [ "$UPSTREAM_REACHABLE" != "true" ]; then
  skip "upstream unreachable"
else
  sleep 1
  SECOND_TMP="${WORK_DIR}/simple-root-second.html"
  SECOND_STATUS=$(curl -s -o "$SECOND_TMP" -w '%{http_code}' \
    $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${BASE_URL}/pypi/${REMOTE_KEY}/simple/" 2>/dev/null) || SECOND_STATUS="000"
  SECOND_BODY=$(cat "$SECOND_TMP" 2>/dev/null || echo "")
  if [ "$SECOND_STATUS" != "200" ]; then
    fail "expected HTTP 200 on second fetch, got ${SECOND_STATUS}" "${SECOND_BODY:0:500}"
  elif [ -z "$SECOND_BODY" ]; then
    fail "second /simple/ fetch returned 200 with an empty body (cache regression?)"
  else
    second_anchor_count=$(printf '%s' "$SECOND_BODY" | grep -oE '<a [^>]*>' | wc -l | tr -d ' ')
    if [ "${second_anchor_count:-0}" -lt 1 ]; then
      fail "expected >=1 anchor on second fetch, got ${second_anchor_count}"
    else
      pass
    fi
  fi
fi

# -------------------------------------------------------------------------
# Cleanup
# -------------------------------------------------------------------------

api_delete "/api/v1/repositories/${REMOTE_KEY}" > /dev/null 2>&1 || true

end_suite
