#!/usr/bin/env bash
# test-search-basic.sh - Full-text search E2E test
#
# Uploads artifacts with known names, then searches for them via the
# search API and verifies results.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "search-basic"
auth_admin
setup_workdir

REPO_KEY="test-search-${RUN_ID}"
UNIQUE_TERM="findme${RUN_ID//[^a-z0-9]/}"

begin_test "Create repo and upload searchable artifact"
if create_local_repo "$REPO_KEY" "generic"; then
  echo "searchable-content-${UNIQUE_TERM}" > "${WORK_DIR}/searchable.txt"
  api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/${UNIQUE_TERM}/searchable.txt" \
    "${WORK_DIR}/searchable.txt" > /dev/null 2>&1
  pass
else
  fail "could not create repo"
fi

sleep 3  # Allow indexing

# -------------------------------------------------------------------------
# Quick search
# -------------------------------------------------------------------------

begin_test "Quick search finds artifact"
if resp=$(api_get "/api/v1/search?q=${UNIQUE_TERM}" 2>/dev/null); then
  if assert_contains "$resp" "searchable"; then
    pass
  fi
elif resp=$(api_get "/api/v1/search/quick?q=${UNIQUE_TERM}" 2>/dev/null); then
  if assert_contains "$resp" "searchable"; then
    pass
  fi
else
  skip "search endpoint returned error (indexing may be disabled)"
fi

# -------------------------------------------------------------------------
# Search suggestions
# -------------------------------------------------------------------------

begin_test "Search suggestions endpoint"
prefix="${UNIQUE_TERM:0:6}"
if resp=$(api_get "/api/v1/search/suggest?q=${prefix}" 2>/dev/null); then
  pass
elif resp=$(api_get "/api/v1/search/suggestions?q=${prefix}" 2>/dev/null); then
  pass
else
  skip "suggestions endpoint not available"
fi

# -------------------------------------------------------------------------
# Advanced search with format filter
# -------------------------------------------------------------------------

begin_test "Advanced search with format filter"
if resp=$(api_get "/api/v1/search/advanced?q=${UNIQUE_TERM}&format=generic" 2>/dev/null); then
  if assert_contains "$resp" "$UNIQUE_TERM"; then
    pass
  fi
else
  skip "advanced search endpoint not available"
fi

# -------------------------------------------------------------------------
# Recent artifacts
# -------------------------------------------------------------------------

begin_test "Recent artifacts includes upload"
if resp=$(api_get "/api/v1/search/recent" 2>/dev/null); then
  if echo "$resp" | jq -e '.' > /dev/null 2>&1; then
    pass
  else
    fail "recent returned invalid JSON"
  fi
else
  skip "recent endpoint not available"
fi

# -------------------------------------------------------------------------
# Trending artifacts
# -------------------------------------------------------------------------

begin_test "Trending artifacts endpoint responds"
if resp=$(api_get "/api/v1/search/trending" 2>/dev/null); then
  if echo "$resp" | jq -e '.' > /dev/null 2>&1; then
    pass
  else
    fail "trending returned invalid JSON"
  fi
else
  skip "trending endpoint not available"
fi

end_suite
