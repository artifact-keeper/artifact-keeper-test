#!/usr/bin/env bash
# test-repo-management-scopes.sh - Repository-management endpoints must
# accept the colon-form scopes API tokens can actually carry (#3831)
#
# Bug: the repo-management handlers gated on the bare `write` / `read` /
# `delete` scopes, which validate_scopes_pure refuses to mint (#2996) --
# so only session auth and admin/* tokens could ever call them, and a
# write:repositories token held by a global admin got
# 403 "Token does not have required scope: write".
#
# Verifies:
#   1. A write:repositories token can set a remote repo's cache TTL and
#      invalidate its cache (pre-fix: 403).
#   2. A write:artifacts token is still 403 there (no cross-resource
#      widening).
#   3. A delete:artifacts token can delete an artifact via the generic
#      REST endpoint (pre-fix: 403 "required scope: delete").
#   4. A delete:repositories token can delete a repository (pre-fix: 403).
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "repo-management-scopes"
auth_admin
setup_workdir

REMOTE_REPO="e2e-repomgmt-remote-${RUN_ID}"
LOCAL_REPO="e2e-repomgmt-local-${RUN_ID}"
THROWAWAY_REPO="e2e-repomgmt-del-${RUN_ID}"

mint_token() {
  # mint_token NAME_SUFFIX SCOPES_JSON -> prints token value
  local resp
  resp=$(api_post "/api/v1/auth/tokens" \
    "{\"name\":\"e2e-repomgmt-${RUN_ID}-$1\",\"scopes\":$2}" 2>/dev/null) || return 1
  echo "$resp" | jq -r '.token // empty'
}

# The repo-management handlers layer a per-repository permission check behind
# the scope gate (the issue asks for exactly this: "subject to the existing
# per-repository permission check"). An admin-owned token WITHOUT the `admin`
# scope is folded to non-admin at authentication (with_scope_gated_admin), so
# it must hold a fine-grained `admin` grant on the target repository -- grant
# that to the admin user up front.
grant_self_repo_admin() {
  # grant_self_repo_admin KEY
  local key="$1" repo_id admin_id
  repo_id=$(api_get "/api/v1/repositories/${key}" 2>/dev/null | jq -r '.id // empty') || true
  admin_id=$(resolve_user_id_by_username "${ADMIN_USER}") || true
  if [ -z "$repo_id" ] || [ "$repo_id" = "null" ] || [ -z "${admin_id:-}" ]; then
    return 1
  fi
  api_post "/api/v1/permissions" \
    "{\"principal_type\":\"user\",\"principal_id\":\"${admin_id}\",\"target_type\":\"repository\",\"target_id\":\"${repo_id}\",\"actions\":[\"admin\"]}" \
    > /dev/null 2>&1
}

# -------------------------------------------------------------------------
# Setup
# -------------------------------------------------------------------------

begin_test "Create remote repo (cache endpoints target)"
if create_remote_repo "$REMOTE_REPO" "generic" "https://upstream.example.test/${RUN_ID}"; then
  pass
else
  fail "could not create remote repo"
fi

begin_test "Create local repo (artifact delete target)"
if create_local_repo "$LOCAL_REPO" "generic"; then
  pass
else
  fail "could not create local repo"
fi

begin_test "Create throwaway repo (repository delete target)"
if create_local_repo "$THROWAWAY_REPO" "generic"; then
  pass
else
  fail "could not create throwaway repo"
fi

echo "repo-mgmt-${RUN_ID}" > "${WORK_DIR}/replace-me.bin"
api_upload "/api/v1/repositories/${LOCAL_REPO}/artifacts/replace-me.bin" \
  "${WORK_DIR}/replace-me.bin" > /dev/null 2>&1 || true

begin_test "Grant repo-admin to the token owner on cache/delete targets"
if grant_self_repo_admin "$REMOTE_REPO" && grant_self_repo_admin "$THROWAWAY_REPO"; then
  pass
else
  fail "could not grant fine-grained repo admin"
fi

# -------------------------------------------------------------------------
# 1. write:repositories reaches the repo-management write endpoints
# -------------------------------------------------------------------------

WRITE_REPO_TOKEN=$(mint_token "wrepos" '["write:repositories"]')

begin_test "write:repositories token sets cache TTL (#3831)"
if [ -z "${WRITE_REPO_TOKEN:-}" ] || [ "$WRITE_REPO_TOKEN" = "null" ]; then
  fail "could not mint write:repositories token"
else
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X PUT -H "Authorization: Bearer ${WRITE_REPO_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"cache_ttl_seconds":300}' \
    "${BASE_URL}/api/v1/repositories/${REMOTE_REPO}/cache-ttl" 2>/dev/null)
  if [ "$status" = "200" ]; then
    pass
  else
    fail "expected 200 for cache-ttl with write:repositories token, got ${status}"
  fi
fi

begin_test "write:repositories token invalidates cache (#3831)"
if [ -z "${WRITE_REPO_TOKEN:-}" ] || [ "$WRITE_REPO_TOKEN" = "null" ]; then
  skip "no write:repositories token"
else
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X POST -H "Authorization: Bearer ${WRITE_REPO_TOKEN}" \
    "${BASE_URL}/api/v1/repositories/${REMOTE_REPO}/cache/invalidate?path=some%2Fcached.bin" \
    2>/dev/null)
  if [ "$status" = "200" ]; then
    pass
  else
    fail "expected 200 for cache invalidate with write:repositories token, got ${status}"
  fi
fi

# -------------------------------------------------------------------------
# 2. write:artifacts must NOT cross resources into repo management
# -------------------------------------------------------------------------

WRITE_ART_TOKEN=$(mint_token "warts" '["write:artifacts"]')

begin_test "write:artifacts token still 403 on cache TTL"
if [ -z "${WRITE_ART_TOKEN:-}" ] || [ "$WRITE_ART_TOKEN" = "null" ]; then
  skip "no write:artifacts token"
else
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X PUT -H "Authorization: Bearer ${WRITE_ART_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"cache_ttl_seconds":300}' \
    "${BASE_URL}/api/v1/repositories/${REMOTE_REPO}/cache-ttl" 2>/dev/null)
  if [ "$status" = "403" ]; then
    pass
  else
    fail "expected 403 for cache-ttl with write:artifacts token, got ${status}"
  fi
fi

# -------------------------------------------------------------------------
# 3. delete:artifacts reaches the generic artifact-delete endpoint
# -------------------------------------------------------------------------

DELETE_ART_TOKEN=$(mint_token "darts" '["delete:artifacts"]')

begin_test "delete:artifacts token deletes an artifact (#3831)"
if [ -z "${DELETE_ART_TOKEN:-}" ] || [ "$DELETE_ART_TOKEN" = "null" ]; then
  fail "could not mint delete:artifacts token"
else
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X DELETE -H "Authorization: Bearer ${DELETE_ART_TOKEN}" \
    "${BASE_URL}/api/v1/repositories/${LOCAL_REPO}/artifacts/replace-me.bin" 2>/dev/null)
  if [ "$status" = "200" ] || [ "$status" = "204" ]; then
    pass
  else
    fail "expected 200/204 for artifact delete with delete:artifacts token, got ${status}"
  fi
fi

# -------------------------------------------------------------------------
# 4. delete:repositories reaches the repository-delete endpoint
# -------------------------------------------------------------------------

DELETE_REPO_TOKEN=$(mint_token "drepos" '["delete:repositories"]')

begin_test "delete:repositories token deletes a repository (#3831)"
if [ -z "${DELETE_REPO_TOKEN:-}" ] || [ "$DELETE_REPO_TOKEN" = "null" ]; then
  fail "could not mint delete:repositories token"
else
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X DELETE -H "Authorization: Bearer ${DELETE_REPO_TOKEN}" \
    "${BASE_URL}/api/v1/repositories/${THROWAWAY_REPO}" 2>/dev/null)
  if [ "$status" = "200" ] || [ "$status" = "204" ]; then
    pass
  else
    fail "expected 200/204 for repository delete with delete:repositories token, got ${status}"
  fi
fi

end_suite
