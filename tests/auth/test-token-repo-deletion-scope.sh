#!/usr/bin/env bash
# test-token-repo-deletion-scope.sh - Deleting repositories must NARROW a
# repository-scoped token, never widen it (#4228)
#
# Bug: api_token_repositories rows are ON DELETE CASCADE, and a token with
# zero rows was treated as UNRESTRICTED -- so deleting the one repository a
# CI token could reach silently widened it to the whole instance.
#
# Verifies:
#   1. A token minted on repo A lists repo A but not repo B.
#   2. After repo A is deleted, the token lists NO repositories (the
#      pre-fix bug: it listed every repository, including repo B).
#   3. After the deletion, the token gets 404 reading surviving repo B
#      (the pre-fix bug: 200).
#   4. Control: the admin session still sees repo B (the deletion did not
#      break unrelated credentials).
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "token-repo-deletion-scope"
auth_admin
setup_workdir

REPO_A="e2e-tokdel-a-${RUN_ID}"
REPO_B="e2e-tokdel-b-${RUN_ID}"
SCOPED_TOKEN=""

# -------------------------------------------------------------------------
# Setup: two repositories; the token is pinned to the first only
# -------------------------------------------------------------------------

begin_test "Create repo A (token's repository)"
if create_local_repo "$REPO_A" "generic"; then
  pass
else
  fail "could not create repo A"
fi

begin_test "Create repo B (private; must stay unreachable)"
# create_local_repo hardcodes is_public:true, and a PUBLIC repo is correctly
# world-readable even to an emptied-out token (require_visible early-returns
# on is_public) -- so B must be private for the widening pin to mean anything.
if resp=$(api_post "/api/v1/repositories" \
    "{\"key\":\"${REPO_B}\",\"name\":\"${REPO_B}\",\"format\":\"generic\",\"repo_type\":\"local\",\"is_public\":false}" 2>/dev/null); then
  pass
else
  fail "could not create private repo B: ${resp:0:200}"
fi

begin_test "Mint repo-scoped token on repo A"
if resp=$(api_post "/api/v1/repositories/${REPO_A}/tokens" \
    '{"name":"e2e-tokdel","scopes":["read:artifacts"]}' 2>/dev/null); then
  SCOPED_TOKEN=$(echo "$resp" | jq -r '.token // empty') || true
  if [ -n "$SCOPED_TOKEN" ] && [ "$SCOPED_TOKEN" != "null" ]; then
    pass
  else
    fail "repo token created but no token value in response: ${resp:0:200}"
  fi
else
  fail "could not mint repo-scoped token"
fi

# -------------------------------------------------------------------------
# Sanity: before any deletion the token reaches repo A only
# -------------------------------------------------------------------------

begin_test "Scoped token lists repo A but not repo B"
if [ -z "${SCOPED_TOKEN:-}" ]; then
  skip "no scoped token"
else
  resp=$(curl -sf $CURL_TIMEOUT -H "Authorization: Bearer ${SCOPED_TOKEN}" \
    "${BASE_URL}/api/v1/repositories" 2>/dev/null) || resp=""
  if echo "$resp" | jq -e '.items // .' 2>/dev/null | grep -q "$REPO_A" \
     && ! echo "$resp" | grep -q "$REPO_B"; then
    pass
  else
    fail "scoped token sanity failed (want A listed, B hidden): ${resp:0:200}"
  fi
fi

# -------------------------------------------------------------------------
# Delete the token's only repository
# -------------------------------------------------------------------------

begin_test "Delete repo A"
if api_delete "/api/v1/repositories/${REPO_A}" > /dev/null 2>&1; then
  pass
else
  fail "could not delete repo A"
fi

# -------------------------------------------------------------------------
# #4228 pin: the emptied-out token must now reach NOTHING
# -------------------------------------------------------------------------

begin_test "Deleted-repo token lists no repositories (#4228)"
if [ -z "${SCOPED_TOKEN:-}" ]; then
  skip "no scoped token"
else
  resp=$(curl -sf $CURL_TIMEOUT -H "Authorization: Bearer ${SCOPED_TOKEN}" \
    "${BASE_URL}/api/v1/repositories" 2>/dev/null) || resp=""
  if echo "$resp" | grep -q "$REPO_B"; then
    fail "token became UNRESTRICTED after its repository was deleted: repo B visible"
  elif echo "$resp" | grep -q "$REPO_A"; then
    fail "deleted repo A still listed for the token"
  else
    pass
  fi
fi

begin_test "Deleted-repo token gets 404 reading repo B (#4228)"
if [ -z "${SCOPED_TOKEN:-}" ]; then
  skip "no scoped token"
else
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "Authorization: Bearer ${SCOPED_TOKEN}" \
    "${BASE_URL}/api/v1/repositories/${REPO_B}" 2>/dev/null)
  if [ "$status" = "404" ] || [ "$status" = "403" ]; then
    pass
  else
    fail "expected 404/403 for repo B with emptied-out token, got ${status} (token widened)"
  fi
fi

# -------------------------------------------------------------------------
# Control: the deletion broke nothing for other credentials
# -------------------------------------------------------------------------

begin_test "Admin session still sees repo B"
if resp=$(api_get "/api/v1/repositories" 2>/dev/null); then
  if assert_contains "$resp" "$REPO_B"; then
    pass
  fi
else
  fail "admin listing failed after repo deletion"
fi

end_suite
