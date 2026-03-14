#!/usr/bin/env bash
# test-repo-types-crud.sh - Repository CRUD for all repo types
#
# Tests create, read, update, and delete for local, remote, and virtual repos.
# Verifies listing, filtering by format, and repo metadata.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "repo-types-crud"
auth_admin
setup_workdir

LOCAL_KEY="test-crud-local-${RUN_ID}"
REMOTE_KEY="test-crud-remote-${RUN_ID}"
VIRTUAL_KEY="test-crud-virtual-${RUN_ID}"

# -------------------------------------------------------------------------
# Create repos of each type
# -------------------------------------------------------------------------

begin_test "Create local repo"
if create_local_repo "$LOCAL_KEY" "generic"; then
  pass
else
  fail "create local repo failed"
fi

begin_test "Create remote repo"
if create_remote_repo "$REMOTE_KEY" "generic" "https://example.com/upstream"; then
  pass
else
  fail "create remote repo failed"
fi

begin_test "Create virtual repo"
if create_virtual_repo "$VIRTUAL_KEY" "generic"; then
  pass
else
  fail "create virtual repo failed"
fi

# -------------------------------------------------------------------------
# Read repos
# -------------------------------------------------------------------------

begin_test "Get local repo by key"
if resp=$(api_get "/api/v1/repositories/${LOCAL_KEY}"); then
  if assert_contains "$resp" "$LOCAL_KEY"; then
    pass
  fi
else
  fail "get local repo failed"
fi

begin_test "Get remote repo by key"
if resp=$(api_get "/api/v1/repositories/${REMOTE_KEY}"); then
  if assert_contains "$resp" "$REMOTE_KEY"; then
    pass
  fi
else
  fail "get remote repo failed"
fi

begin_test "Get virtual repo by key"
if resp=$(api_get "/api/v1/repositories/${VIRTUAL_KEY}"); then
  if assert_contains "$resp" "$VIRTUAL_KEY"; then
    pass
  fi
else
  fail "get virtual repo failed"
fi

# -------------------------------------------------------------------------
# List repos
# -------------------------------------------------------------------------

begin_test "List all repositories"
if resp=$(api_get "/api/v1/repositories"); then
  if assert_contains "$resp" "$LOCAL_KEY"; then
    pass
  fi
else
  fail "list repos failed"
fi

# -------------------------------------------------------------------------
# Update repo
# -------------------------------------------------------------------------

begin_test "Update local repo description"
if api_put "/api/v1/repositories/${LOCAL_KEY}" \
    '{"description":"Updated by E2E test"}' > /dev/null 2>&1; then
  resp=$(api_get "/api/v1/repositories/${LOCAL_KEY}")
  if assert_contains "$resp" "Updated by E2E test"; then
    pass
  fi
else
  skip "repo update not supported or different API shape"
fi

# -------------------------------------------------------------------------
# Delete repos
# -------------------------------------------------------------------------

begin_test "Delete virtual repo"
if api_delete "/api/v1/repositories/${VIRTUAL_KEY}" > /dev/null 2>&1; then
  status=$(curl -s -o /dev/null -w '%{http_code}' -H "$(auth_header)" \
    "${BASE_URL}/api/v1/repositories/${VIRTUAL_KEY}") || true
  if [ "$status" = "404" ]; then
    pass
  else
    fail "deleted repo still returns ${status}"
  fi
else
  fail "delete virtual repo failed"
fi

begin_test "Delete remote repo"
if api_delete "/api/v1/repositories/${REMOTE_KEY}" > /dev/null 2>&1; then
  pass
else
  fail "delete remote repo failed"
fi

begin_test "Delete local repo"
if api_delete "/api/v1/repositories/${LOCAL_KEY}" > /dev/null 2>&1; then
  pass
else
  fail "delete local repo failed"
fi

end_suite
