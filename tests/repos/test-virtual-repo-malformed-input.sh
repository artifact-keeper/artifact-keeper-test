#!/usr/bin/env bash
# test-virtual-repo-malformed-input.sh - 400 contract for malformed JSON
# bodies on virtual member + cache-ttl management endpoints.
#
# Issue artifact-keeper-test#94. Today there is no test pinning the axum
# JSON extractor's 400 behavior on:
#
#   PUT /api/v1/repositories/:key/members
#   PUT /api/v1/repositories/:key/cache-ttl
#
# A future axum upgrade or extractor swap could change error mapping
# (status code, body format) without anyone noticing. This script asserts
# that each of:
#
#   - empty body
#   - syntactically malformed JSON (e.g. "{")
#   - missing required field
#   - wrong-type field
#
# returns HTTP 400 today, so a silent change in client-visible error
# contracts fails the gate loudly.
#
# Gated to backend >= 1.2.0 via require_feature so the 1.1.9 release-gate
# isn't asked to validate this contract. The endpoints exist in 1.1.x; the
# gate is a release-process guard, not a backend-feature guard.
#
# EXPECT_FAILURE=1 inverts the suite exit code.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "virtual-repo-malformed-input"
auth_admin

LOCAL_A="test-vmali-a-${RUN_ID}"
LOCAL_B="test-vmali-b-${RUN_ID}"
VIRTUAL_KEY="test-vmali-virt-${RUN_ID}"
REMOTE_KEY="test-vmali-remote-${RUN_ID}"

# -------------------------------------------------------------------------
# Setup
#
# We provision real targets so a 400 from a malformed body isn't masked
# by a 404 from a non-existent repo. The JSON extractor runs after path
# resolution; pinning the path-then-body ordering keeps the assertion
# precise.
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

# Settle: poll until both members are visible (10s budget) so the malformed
# tests that follow are pointed at a fully-realized virtual repo.
deadline=$(( $(date +%s) + 10 ))
until [ "$(api_get "/api/v1/repositories/${VIRTUAL_KEY}/members" 2>/dev/null | jq '.members | length // 0')" = "2" ] || [ "$(date +%s)" -ge "$deadline" ]; do
  sleep 0.2
done

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
# Helper: PUT a literal request body to a path with admin auth and echo
# the HTTP status. Bypasses api_put because api_put expects a sane jq-built
# JSON; here we deliberately send invalid bytes (or none).
# -------------------------------------------------------------------------

put_status_with_body() {
  local path="$1"
  local body="$2"

  local args=(-s -o /dev/null -w '%{http_code}' --max-time 60 --connect-timeout 10
              -X PUT
              -H "$(auth_header)"
              -H "Content-Type: application/json")
  if [ -n "$body" ]; then
    args+=(--data-binary "$body")
  fi
  args+=("${BASE_URL}${path}")

  local code
  code=$(curl "${args[@]}") || code="000"
  echo "$code"
}

MEMBERS_PATH="/api/v1/repositories/${VIRTUAL_KEY}/members"
CACHE_TTL_PATH="/api/v1/repositories/${REMOTE_KEY}/cache-ttl"

# -------------------------------------------------------------------------
# Block A: PUT /:key/members
# -------------------------------------------------------------------------

begin_test "PUT /members with empty body returns 400"
if require_feature "virtual_member_strict_contract"; then
  status=$(put_status_with_body "$MEMBERS_PATH" "")
  assert_eq "$status" "400" "expected 400 for empty body on PUT /members, got $status" && pass
fi

begin_test "PUT /members with syntactically malformed JSON returns 400"
if require_feature "virtual_member_strict_contract"; then
  status=$(put_status_with_body "$MEMBERS_PATH" '{')
  assert_eq "$status" "400" "expected 400 for malformed JSON on PUT /members, got $status" && pass
fi

begin_test "PUT /members with member missing member_key returns 400"
if require_feature "virtual_member_strict_contract"; then
  # priority is present, member_key is omitted from the array element.
  status=$(put_status_with_body "$MEMBERS_PATH" '{"members":[{"priority":1}]}')
  assert_eq "$status" "400" "expected 400 for member missing member_key, got $status" && pass
fi

begin_test "PUT /members with priority as string returns 400"
if require_feature "virtual_member_strict_contract"; then
  # member_key is fine; priority is the wrong JSON type.
  status=$(put_status_with_body "$MEMBERS_PATH" "{\"members\":[{\"member_key\":\"${LOCAL_A}\",\"priority\":\"high\"}]}")
  assert_eq "$status" "400" "expected 400 for non-integer priority, got $status" && pass
fi

# -------------------------------------------------------------------------
# Block B: PUT /:key/cache-ttl
# -------------------------------------------------------------------------

begin_test "PUT /cache-ttl with empty body returns 400"
if require_feature "virtual_member_strict_contract"; then
  status=$(put_status_with_body "$CACHE_TTL_PATH" "")
  assert_eq "$status" "400" "expected 400 for empty body on PUT /cache-ttl, got $status" && pass
fi

begin_test "PUT /cache-ttl with syntactically malformed JSON returns 400"
if require_feature "virtual_member_strict_contract"; then
  status=$(put_status_with_body "$CACHE_TTL_PATH" '{')
  assert_eq "$status" "400" "expected 400 for malformed JSON on PUT /cache-ttl, got $status" && pass
fi

begin_test "PUT /cache-ttl missing cache_ttl_seconds returns 400"
if require_feature "virtual_member_strict_contract"; then
  status=$(put_status_with_body "$CACHE_TTL_PATH" '{}')
  assert_eq "$status" "400" "expected 400 for missing cache_ttl_seconds, got $status" && pass
fi

begin_test "PUT /cache-ttl with cache_ttl_seconds as string returns 400"
if require_feature "virtual_member_strict_contract"; then
  status=$(put_status_with_body "$CACHE_TTL_PATH" '{"cache_ttl_seconds":"forever"}')
  assert_eq "$status" "400" "expected 400 for non-integer cache_ttl_seconds, got $status" && pass
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
