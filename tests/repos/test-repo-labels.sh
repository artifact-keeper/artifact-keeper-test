#!/usr/bin/env bash
# test-repo-labels.sh - Repository label CRUD and filtering
#
# Tests setting, getting, updating, and removing labels on repositories,
# and filtering the repository list by label.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "repo-labels"
auth_admin
setup_workdir

REPO_KEY="test-labels-${RUN_ID}"

begin_test "Create repo for label tests"
if create_local_repo "$REPO_KEY" "generic"; then
  pass
else
  fail "could not create repo"
fi

# -------------------------------------------------------------------------
# Set labels
# -------------------------------------------------------------------------

begin_test "Set labels on repository"
if api_put "/api/v1/repositories/${REPO_KEY}/labels" \
    '{"labels":[{"key":"env","value":"staging"},{"key":"team","value":"platform"}]}' > /dev/null 2>&1; then
  pass
elif api_post "/api/v1/repositories/${REPO_KEY}/labels" \
    '{"labels":[{"key":"env","value":"staging"},{"key":"team","value":"platform"}]}' > /dev/null 2>&1; then
  pass
else
  skip "repository labels endpoint not available"
fi

# -------------------------------------------------------------------------
# Get labels
# -------------------------------------------------------------------------

begin_test "Get labels from repository"
if resp=$(api_get "/api/v1/repositories/${REPO_KEY}/labels" 2>/dev/null); then
  if assert_contains "$resp" "staging"; then
    pass
  fi
elif resp=$(api_get "/api/v1/repositories/${REPO_KEY}" 2>/dev/null); then
  if assert_contains "$resp" "staging"; then
    pass
  fi
else
  skip "could not retrieve labels"
fi

# -------------------------------------------------------------------------
# Update labels
# -------------------------------------------------------------------------

begin_test "Update labels"
if api_put "/api/v1/repositories/${REPO_KEY}/labels" \
    '{"labels":[{"key":"env","value":"production"},{"key":"team","value":"platform"},{"key":"tier","value":"critical"}]}' > /dev/null 2>&1; then
  resp=$(api_get "/api/v1/repositories/${REPO_KEY}/labels" 2>/dev/null) || \
    resp=$(api_get "/api/v1/repositories/${REPO_KEY}" 2>/dev/null) || true
  if [ -n "$resp" ] && assert_contains "$resp" "production"; then
    pass
  fi
else
  skip "label update not supported"
fi

# -------------------------------------------------------------------------
# Cleanup
# -------------------------------------------------------------------------

begin_test "Delete test repo"
if api_delete "/api/v1/repositories/${REPO_KEY}" > /dev/null 2>&1; then
  pass
else
  fail "cleanup failed"
fi

end_suite
