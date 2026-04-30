#!/usr/bin/env bash
# test-virtual-repo-authn.sh - Authentication failure paths on virtual member
# and cache-ttl management endpoints.
#
# Issue artifact-keeper-test#93. PR #80 exercises the happy path on these
# endpoints but does not exercise the unauthenticated or malformed-token
# paths. An auth middleware regression that accidentally allowed anonymous
# writes to virtual-member or cache-ttl endpoints would ship undetected
# without these cases. Write-scope (read-only token receives 403) is being
# covered separately by ak-0q3a in PR #80; this file is scoped to:
#
#   - missing Authorization header   -> 401
#   - malformed bearer token         -> 401
#
# against:
#   PUT    /api/v1/repositories/:key/members
#   DELETE /api/v1/repositories/:key/members/:member_key
#   PUT    /api/v1/repositories/:key/cache-ttl
#
# Gated to backend >= 1.2.0 via require_feature so the 1.1.9 release-gate
# isn't asked to validate this contract. The endpoints exist in 1.1.x; the
# gate is a release-process guard, not a backend-feature guard.
#
# EXPECT_FAILURE=1 inverts the suite exit code.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "virtual-repo-authn"
auth_admin

LOCAL_A="test-vauthn-a-${RUN_ID}"
LOCAL_B="test-vauthn-b-${RUN_ID}"
VIRTUAL_KEY="test-vauthn-virt-${RUN_ID}"
REMOTE_KEY="test-vauthn-remote-${RUN_ID}"

# -------------------------------------------------------------------------
# Setup
#
# We provision real targets so a 401 from a missing header isn't masked
# by a 404 from a non-existent repo. The handler's auth middleware runs
# before the path-resolution layer, but pinning that ordering is part of
# what we want to assert: even with a valid path, no token must mean 401.
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

begin_test "Setup: create virtual repo with members A,B"
if create_virtual_repo "$VIRTUAL_KEY" "generic" "${LOCAL_A},${LOCAL_B}"; then
  pass
else
  fail "could not create virtual repo with members"
fi

# Settle: poll until both members are visible (10s budget) so the auth
# tests that follow are pointed at a fully-realized virtual repo.
deadline=$(( $(date +%s) + 10 ))
until [ "$(api_get "/api/v1/repositories/${VIRTUAL_KEY}/members" 2>/dev/null | jq '.members | length // 0')" = "2" ] || [ "$(date +%s)" -ge "$deadline" ]; do
  sleep 0.2
done

# A remote repo is the cleanest target for cache-ttl, since cache_ttl
# is a proxy-cache concept; the validator accepts it on local repos
# today but the realistic call site is remote.
begin_test "Setup: create remote repo for cache-ttl target"
REMOTE_PAYLOAD=$(jq -n \
  --arg k "$REMOTE_KEY" \
  '{key: $k, name: $k, format: "generic", repo_type: "remote", is_public: true, upstream_url: "https://example.invalid"}')
if api_post "/api/v1/repositories" "$REMOTE_PAYLOAD" > /dev/null 2>&1; then
  pass
else
  fail "could not create remote repo for cache-ttl test"
fi

# -------------------------------------------------------------------------
# Helper: send a request with an explicit Authorization header value
# (or none if $1 is empty). Echoes the HTTP status on stdout.
#
# Usage:
#   status=$(http_status_with_auth "<header value or ''>" METHOD PATH [BODY])
#
# Empty header value omits the Authorization header entirely. Non-empty
# value is sent verbatim (so callers control the full "Bearer xyz" form).
# -------------------------------------------------------------------------

http_status_with_auth() {
  local auth_value="$1"
  local method="$2"
  local path="$3"
  local body="${4:-}"

  local args=(-s -o /dev/null -w '%{http_code}' --max-time 60 --connect-timeout 10 -X "$method")
  if [ -n "$auth_value" ]; then
    args+=(-H "Authorization: ${auth_value}")
  fi
  if [ -n "$body" ]; then
    args+=(-H "Content-Type: application/json" -d "$body")
  fi
  args+=("${BASE_URL}${path}")

  local code
  code=$(curl "${args[@]}") || code="000"
  echo "$code"
}

# Reusable bodies for the PUT cases.
MEMBERS_PAYLOAD=$(jq -n \
  --arg a "$LOCAL_A" \
  '{members: [{member_key: $a, priority: 1}]}')
CACHE_TTL_PAYLOAD='{"cache_ttl_seconds": 60}'

# -------------------------------------------------------------------------
# Block A: no Authorization header -> 401
# -------------------------------------------------------------------------

begin_test "PUT /:key/members without Authorization returns 401"
if require_feature "virtual_member_strict_contract"; then
  status=$(http_status_with_auth "" PUT "/api/v1/repositories/${VIRTUAL_KEY}/members" "$MEMBERS_PAYLOAD")
  assert_eq "$status" "401" "expected 401 for unauthenticated PUT /members, got $status" && pass
fi

begin_test "DELETE /:key/members/:member_key without Authorization returns 401"
if require_feature "virtual_member_strict_contract"; then
  status=$(http_status_with_auth "" DELETE "/api/v1/repositories/${VIRTUAL_KEY}/members/${LOCAL_A}" "")
  assert_eq "$status" "401" "expected 401 for unauthenticated DELETE /members/<m>, got $status" && pass
fi

begin_test "PUT /:key/cache-ttl without Authorization returns 401"
if require_feature "virtual_member_strict_contract"; then
  status=$(http_status_with_auth "" PUT "/api/v1/repositories/${REMOTE_KEY}/cache-ttl" "$CACHE_TTL_PAYLOAD")
  assert_eq "$status" "401" "expected 401 for unauthenticated PUT /cache-ttl, got $status" && pass
fi

# -------------------------------------------------------------------------
# Block B: malformed bearer token -> 401
#
# A literal "Bearer not-a-jwt" should fail JWT decode in the auth
# middleware and surface as 401, not 500 or 403. This is the case that
# would silently regress if a middleware swap mapped decode errors to
# the wrong status.
# -------------------------------------------------------------------------

MALFORMED_BEARER="Bearer not-a-jwt"

begin_test "PUT /:key/members with malformed bearer returns 401"
if require_feature "virtual_member_strict_contract"; then
  status=$(http_status_with_auth "$MALFORMED_BEARER" PUT "/api/v1/repositories/${VIRTUAL_KEY}/members" "$MEMBERS_PAYLOAD")
  assert_eq "$status" "401" "expected 401 for malformed-bearer PUT /members, got $status" && pass
fi

begin_test "DELETE /:key/members/:member_key with malformed bearer returns 401"
if require_feature "virtual_member_strict_contract"; then
  status=$(http_status_with_auth "$MALFORMED_BEARER" DELETE "/api/v1/repositories/${VIRTUAL_KEY}/members/${LOCAL_A}" "")
  assert_eq "$status" "401" "expected 401 for malformed-bearer DELETE /members/<m>, got $status" && pass
fi

begin_test "PUT /:key/cache-ttl with malformed bearer returns 401"
if require_feature "virtual_member_strict_contract"; then
  status=$(http_status_with_auth "$MALFORMED_BEARER" PUT "/api/v1/repositories/${REMOTE_KEY}/cache-ttl" "$CACHE_TTL_PAYLOAD")
  assert_eq "$status" "401" "expected 401 for malformed-bearer PUT /cache-ttl, got $status" && pass
fi

# -------------------------------------------------------------------------
# Cleanup
# -------------------------------------------------------------------------

api_delete "/api/v1/repositories/${REMOTE_KEY}" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${VIRTUAL_KEY}" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${LOCAL_B}" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${LOCAL_A}" > /dev/null 2>&1 || true

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
