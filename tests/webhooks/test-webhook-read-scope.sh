#!/usr/bin/env bash
# test-webhook-read-scope.sh - Webhook fetch-by-id must require the same
# read-carrying grant as the webhook listing, and a repository-scoped token
# must confine an admin holder (#3901)
#
# Bugs:
#   1. get_webhook / list_deliveries gated with the action-blind
#      RepoAccess::TenantOnly, so a {write}-only fine-grained grantee was
#      refused the webhook in the LISTING but served its URL, headers and
#      secret metadata by ID.
#   2. The repository and packages listings evaluated is_admin before the
#      token's repository scope, so an admin holding a repo-scoped token
#      enumerated everything instead of the token's set.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "webhook-read-scope"
auth_admin
setup_workdir

REPO="e2e-whread-${RUN_ID}"
REPO_TOKEN_REPO="e2e-whread-tok-${RUN_ID}"
OTHER_REPO="e2e-whread-other-${RUN_ID}"
WRITER_USER="e2e-whread-writer-${RUN_ID}"
WRITER_PASS="WhRead_Pass123!"
WEBHOOK_ID=""
WRITER_JWT=""

# -------------------------------------------------------------------------
# Setup: private repo, a write-only grantee, and an admin-owned webhook
# -------------------------------------------------------------------------

begin_test "Create private repo for webhook"
if create_local_repo "$REPO" "generic"; then
  pass
else
  fail "could not create repo"
fi

begin_test "Create write-only grantee user"
if resp=$(api_post "/api/v1/users" \
    "{\"username\":\"${WRITER_USER}\",\"password\":\"${WRITER_PASS}\",\"email\":\"${WRITER_USER}@test.local\",\"display_name\":\"WH Writer\"}" 2>/dev/null); then
  WRITER_ID=$(echo "$resp" | jq -r '.user.id // .id // empty') || true
  if [ -n "$WRITER_ID" ] && [ "$WRITER_ID" != "null" ]; then
    pass
  else
    fail "user created but no ID: ${resp:0:200}"
  fi
else
  fail "could not create writer user"
fi

REPO_ID=""
begin_test "Grant writer {write} on the repo"
REPO_ID=$(api_get "/api/v1/repositories/${REPO}" 2>/dev/null | jq -r '.id // empty') || true
if [ -z "$REPO_ID" ] || [ "$REPO_ID" = "null" ]; then
  fail "could not resolve repo id"
elif resp=$(api_post "/api/v1/permissions" \
    "{\"principal_type\":\"user\",\"principal_id\":\"${WRITER_ID}\",\"target_type\":\"repository\",\"target_id\":\"${REPO_ID}\",\"actions\":[\"write\"]}" 2>/dev/null); then
  pass
else
  fail "could not grant write permission"
fi

begin_test "Admin creates webhook on the repo"
if [ -z "$REPO_ID" ] || [ "$REPO_ID" = "null" ]; then
  skip "no repo id"
elif resp=$(api_post "/api/v1/webhooks" \
    "{\"name\":\"e2e-whread-${RUN_ID}\",\"url\":\"https://httpbin.org/post\",\"events\":[\"artifact.uploaded\"],\"repository_id\":\"${REPO_ID}\"}" 2>/dev/null); then
  WEBHOOK_ID=$(echo "$resp" | jq -r '.id // .webhook.id // empty') || true
  if [ -n "$WEBHOOK_ID" ] && [ "$WEBHOOK_ID" != "null" ]; then
    pass
  else
    fail "webhook created but no ID: ${resp:0:200}"
  fi
else
  fail "could not create webhook"
fi

begin_test "Writer logs in"
WRITER_JWT=$(login_as "$WRITER_USER" "$WRITER_PASS") || true
if [ -n "$WRITER_JWT" ]; then
  pass
else
  fail "writer login failed"
fi

# -------------------------------------------------------------------------
# #3901 pin 1: a {write}-only grantee must NOT read the webhook by id
# -------------------------------------------------------------------------

begin_test "Write-only grantee gets 404 on get_webhook (#3901)"
if [ -z "${WEBHOOK_ID:-}" ] || [ -z "${WRITER_JWT:-}" ]; then
  skip "no webhook or writer JWT"
else
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "Authorization: Bearer ${WRITER_JWT}" \
    "${BASE_URL}/api/v1/webhooks/${WEBHOOK_ID}" 2>/dev/null)
  if [ "$status" = "404" ]; then
    pass
  else
    fail "expected 404 for write-only grantee, got ${status} (webhook metadata leaked by id)"
  fi
fi

begin_test "Write-only grantee gets 404 on list_deliveries (#3901)"
if [ -z "${WEBHOOK_ID:-}" ] || [ -z "${WRITER_JWT:-}" ]; then
  skip "no webhook or writer JWT"
else
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "Authorization: Bearer ${WRITER_JWT}" \
    "${BASE_URL}/api/v1/webhooks/${WEBHOOK_ID}/deliveries" 2>/dev/null)
  if [ "$status" = "404" ]; then
    pass
  else
    fail "expected 404 for write-only grantee on deliveries, got ${status}"
  fi
fi

begin_test "Granting read restores by-id access"
if [ -z "${WEBHOOK_ID:-}" ] || [ -z "${WRITER_JWT:-}" ]; then
  skip "no webhook or writer JWT"
elif ! api_post "/api/v1/permissions" \
    "{\"principal_type\":\"user\",\"principal_id\":\"${WRITER_ID}\",\"target_type\":\"repository\",\"target_id\":\"${REPO_ID}\",\"actions\":[\"read\",\"write\"]}" > /dev/null 2>&1; then
  fail "could not widen grant to read"
else
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "Authorization: Bearer ${WRITER_JWT}" \
    "${BASE_URL}/api/v1/webhooks/${WEBHOOK_ID}" 2>/dev/null)
  if [ "$status" = "200" ]; then
    pass
  else
    fail "expected 200 once the grant carries read, got ${status}"
  fi
fi

# -------------------------------------------------------------------------
# #3901 pin 2: an admin's repository-scoped token is confined to its repo
# -------------------------------------------------------------------------

begin_test "Create token-scope repo and an unrelated repo"
if create_local_repo "$REPO_TOKEN_REPO" "generic" && create_local_repo "$OTHER_REPO" "generic"; then
  pass
else
  fail "could not create confinement repos"
fi

begin_test "Mint admin-owned token scoped to one repo"
SCOPED_ADMIN_TOKEN=""
if resp=$(api_post "/api/v1/repositories/${REPO_TOKEN_REPO}/tokens" \
    '{"name":"e2e-whread-scoped","scopes":["read:repositories"]}' 2>/dev/null); then
  SCOPED_ADMIN_TOKEN=$(echo "$resp" | jq -r '.token // empty') || true
  if [ -n "$SCOPED_ADMIN_TOKEN" ] && [ "$SCOPED_ADMIN_TOKEN" != "null" ]; then
    pass
  else
    fail "no token value in response: ${resp:0:200}"
  fi
else
  fail "could not mint scoped token"
fi

begin_test "Admin's scoped token lists only its repository (#3901)"
if [ -z "${SCOPED_ADMIN_TOKEN:-}" ]; then
  skip "no scoped token"
else
  resp=$(curl -sf $CURL_TIMEOUT -H "Authorization: Bearer ${SCOPED_ADMIN_TOKEN}" \
    "${BASE_URL}/api/v1/repositories" 2>/dev/null) || resp=""
  if echo "$resp" | grep -q "$OTHER_REPO"; then
    fail "admin's repo-scoped token enumerated unrelated repos (scope not confining)"
  elif ! echo "$resp" | grep -q "$REPO_TOKEN_REPO"; then
    fail "scoped token lost sight of its own repository: ${resp:0:200}"
  else
    pass
  fi
fi

end_suite
