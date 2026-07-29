#!/usr/bin/env bash
# test-virtual-repo-member-authz.sh - Write-scope rejection on virtual member +
# cache-ttl endpoints (closes ak-0q3a).
#
# Backend authz contract (backend/src/api/handlers/repositories.rs):
#   add_virtual_member       -> auth.require_scope("write")
#   remove_virtual_member    -> auth.require_scope("write")
#   update_virtual_members   -> auth.require_scope("write")
#   set_cache_ttl (PUT)      -> auth.require_scope("write")
#   list_virtual_members     -> read-only (no require_scope("write"))
#   get_cache_ttl (GET)      -> read-only (no require_scope("write"))
#
# A token created with scopes:["read:artifacts"] (see existing pattern in
# tests/rbac/test-scope-enforcement.sh, which provisions tokens via
# POST /api/v1/auth/tokens) must therefore be 403'd on every write path
# but 200'd on the two read paths. Anything else is the silent-success
# class we are trying to close.
#
# If the API-tokens endpoint is not available on the target backend
# (some lite/auth-stripped builds), skip_suite with a precise reason so
# the gate dashboard surfaces the gap rather than silently passing.
#
# EXPECT_FAILURE=1 inverts the suite exit code (matches sibling scripts).
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "virtual-repo-member-authz"
auth_admin

LOCAL_A="test-vauthz-a-${RUN_ID}"
LOCAL_B="test-vauthz-b-${RUN_ID}"
VIRTUAL_KEY="test-vauthz-virt-${RUN_ID}"
REMOTE_KEY="test-vauthz-remote-${RUN_ID}"
RO_TOKEN_NAME="e2e-vauthz-readonly-${RUN_ID}"

# -------------------------------------------------------------------------
# Provision a read-only token first; if the endpoint is unavailable, skip
# the whole suite explicitly. Do NOT silently succeed by inventing a fake
# token (that's the failure mode ak-0q3a is closing).
# -------------------------------------------------------------------------

RO_TOKEN=""
RO_TOKEN_ID=""
if RO_RESP=$(api_post "/api/v1/auth/tokens" \
    "{\"name\":\"${RO_TOKEN_NAME}\",\"scopes\":[\"read:artifacts\"]}" 2>/dev/null); then
  RO_TOKEN=$(echo "$RO_RESP" | jq -r '.token // .api_key // .key // empty') || true
  RO_TOKEN_ID=$(echo "$RO_RESP" | jq -r '.id // .token_id // empty') || true
fi

if [ -z "$RO_TOKEN" ] || [ "$RO_TOKEN" = "null" ]; then
  skip_suite "POST /api/v1/auth/tokens did not return a usable read-only token; the write-scope-rejection contract cannot be exercised on this backend"
fi

# -------------------------------------------------------------------------
# Setup: two local repos, a virtual repo wrapping them, and a remote repo
# for the cache-ttl endpoints. All created with the admin token.
# -------------------------------------------------------------------------

begin_test "Setup: create local repo A"
if create_local_repo "$LOCAL_A" "generic"; then
  pass
else
  fail "could not create local repo A"
fi

begin_test "Setup: create local repo B"
if create_local_repo "$LOCAL_B" "generic"; then
  pass
else
  fail "could not create local repo B"
fi

begin_test "Setup: create virtual repo V with members A,B"
if create_virtual_repo "$VIRTUAL_KEY" "generic" "${LOCAL_A},${LOCAL_B}"; then
  pass
else
  fail "could not create virtual repo with members"
fi

begin_test "Setup: create remote repo R for cache-ttl probes"
if create_remote_repo "$REMOTE_KEY" "generic" "https://example.invalid/upstream"; then
  pass
else
  fail "could not create remote repo R"
fi

# Settle: members must be visible before we exercise authz on them
# (otherwise a 404 would mask a 403 we expected).
deadline=$(( $(date +%s) + 10 ))
until [ "$(api_get "/api/v1/repositories/${VIRTUAL_KEY}/members" 2>/dev/null | jq '.members | length // 0')" = "2" ] || [ "$(date +%s)" -ge "$deadline" ]; do
  sleep 0.2
done

# -------------------------------------------------------------------------
# Negative cases: read-only token must be 403'd on every write path.
#
# We assert exact 403 (not 401/403 OR'd) per the HTTP Status Code Guide
# in tests/lib/common.sh: 401 means "no/invalid creds" and 403 means
# "valid creds, insufficient scope". An OR-check would mask a regression
# where the auth middleware accepts the token but then mis-rejects it.
# -------------------------------------------------------------------------

begin_test "Read-only token: POST /V/members -> 403"
ADD_BODY="{\"member_key\":\"${LOCAL_A}\",\"priority\":99}"
ADD_STATUS=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X POST \
  -H "Authorization: Bearer ${RO_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "$ADD_BODY" \
  "${BASE_URL}/api/v1/repositories/${VIRTUAL_KEY}/members") || ADD_STATUS="000"
assert_eq "$ADD_STATUS" "403" "expected 403 for POST /V/members with read-only token, got ${ADD_STATUS}" && pass

begin_test "Read-only token: DELETE /V/members/A -> 403"
DEL_STATUS=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X DELETE \
  -H "Authorization: Bearer ${RO_TOKEN}" \
  "${BASE_URL}/api/v1/repositories/${VIRTUAL_KEY}/members/${LOCAL_A}") || DEL_STATUS="000"
assert_eq "$DEL_STATUS" "403" "expected 403 for DELETE /V/members/A with read-only token, got ${DEL_STATUS}" && pass

begin_test "Read-only token: PUT /V/members -> 403"
# PUT body shape per VirtualMembersBulkUpdateRequest: { members: [{ member_key, priority }] }
PUT_BODY="{\"members\":[{\"member_key\":\"${LOCAL_A}\",\"priority\":1},{\"member_key\":\"${LOCAL_B}\",\"priority\":2}]}"
PUT_STATUS=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X PUT \
  -H "Authorization: Bearer ${RO_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "$PUT_BODY" \
  "${BASE_URL}/api/v1/repositories/${VIRTUAL_KEY}/members") || PUT_STATUS="000"
assert_eq "$PUT_STATUS" "403" "expected 403 for PUT /V/members with read-only token, got ${PUT_STATUS}" && pass

begin_test "Read-only token: PUT /R/cache-ttl -> 403"
TTL_BODY='{"cache_ttl_seconds": 600}'
TTL_PUT_STATUS=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X PUT \
  -H "Authorization: Bearer ${RO_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "$TTL_BODY" \
  "${BASE_URL}/api/v1/repositories/${REMOTE_KEY}/cache-ttl") || TTL_PUT_STATUS="000"
assert_eq "$TTL_PUT_STATUS" "403" "expected 403 for PUT /R/cache-ttl with read-only token, got ${TTL_PUT_STATUS}" && pass

# -------------------------------------------------------------------------
# Positive controls: read-only token MUST still be allowed on read paths.
# Without these, a "deny everything" middleware regression would let the
# negative cases above pass (silent-success class).
# -------------------------------------------------------------------------

begin_test "Read-only token: GET /R/cache-ttl -> 2xx"
TTL_GET_STATUS=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -H "Authorization: Bearer ${RO_TOKEN}" \
  "${BASE_URL}/api/v1/repositories/${REMOTE_KEY}/cache-ttl") || TTL_GET_STATUS="000"
assert_http_2xx "$TTL_GET_STATUS" "expected 2xx for GET /R/cache-ttl with read-only token, got ${TTL_GET_STATUS}" && pass

begin_test "Read-only token: GET /V/members -> 2xx"
LIST_STATUS=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -H "Authorization: Bearer ${RO_TOKEN}" \
  "${BASE_URL}/api/v1/repositories/${VIRTUAL_KEY}/members") || LIST_STATUS="000"
assert_http_2xx "$LIST_STATUS" "expected 2xx for GET /V/members with read-only token, got ${LIST_STATUS}" && pass

# -------------------------------------------------------------------------
# Cleanup. Re-auth as admin in case any test above mutated ADMIN_TOKEN
# state (it shouldn't, but the test-scope-enforcement.sh sibling does
# this defensively too).
# -------------------------------------------------------------------------

auth_admin

if [ -n "${RO_TOKEN_ID:-}" ] && [ "$RO_TOKEN_ID" != "null" ]; then
  api_delete "/api/v1/auth/tokens/${RO_TOKEN_ID}" > /dev/null 2>&1 || true
fi

api_delete "/api/v1/repositories/${VIRTUAL_KEY}" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${LOCAL_B}" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${LOCAL_A}" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${REMOTE_KEY}" > /dev/null 2>&1 || true

if [ "${EXPECT_FAILURE:-0}" = "1" ]; then
  if ( end_suite ); then
    echo "EXPECT_FAILURE=1 but suite passed; inverting to fail"
    exit 1
  else
    echo "EXPECT_FAILURE=1 and suite failed as expected; inverting to pass"
    exit 0
  fi
fi

end_suite
