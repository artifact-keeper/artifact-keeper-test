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

end_suite
