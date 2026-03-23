#!/usr/bin/env bash
# test-grpc-token-invalidation.sh - #549: gRPC token invalidation after password change
#
# Verifies that gRPC endpoints reject tokens belonging to users whose
# password has been changed. Requires grpcurl; skips gracefully if
# not available or gRPC is unreachable.

source "$(dirname "$0")/../lib/common.sh"

begin_suite "grpc-token-invalidation"
auth_admin
setup_workdir

# gRPC runs on port 9090 by default. Derive host from BASE_URL.
GRPC_HOST=$(echo "$BASE_URL" | sed -E 's|https?://||; s|:[0-9]+$||; s|/.*||')
GRPC_PORT="${GRPC_PORT:-9090}"
GRPC_TARGET="${GRPC_HOST}:${GRPC_PORT}"

TEST_USER="e2e-grpc-inval-${RUN_ID}"
TEST_PASS="GrpcInval123!"
NEW_PASS="GrpcInval456!"
USER_ID=""

# ---------------------------------------------------------------------------
# Check prerequisites
# ---------------------------------------------------------------------------

begin_test "Check grpcurl availability"
if ! command -v grpcurl &>/dev/null; then
  skip "grpcurl not found on PATH"
  GRPCURL_AVAILABLE=false
else
  GRPCURL_AVAILABLE=true
  pass
fi

begin_test "Check gRPC endpoint reachability"
if [ "$GRPCURL_AVAILABLE" != "true" ]; then
  skip "grpcurl not available"
else
  conn_result=$(grpcurl -plaintext -connect-timeout 5 "$GRPC_TARGET" list 2>&1) || true
  if echo "$conn_result" | grep -q "Failed to dial\|connection refused\|context deadline exceeded\|transport: Error"; then
    GRPC_REACHABLE=false
    skip "gRPC endpoint not reachable at ${GRPC_TARGET}"
  else
    GRPC_REACHABLE=true
    pass
  fi
fi

# ---------------------------------------------------------------------------
# Create test user and get initial token
# ---------------------------------------------------------------------------

begin_test "Create test user for token invalidation"
if [ "$GRPCURL_AVAILABLE" != "true" ] || [ "${GRPC_REACHABLE:-false}" != "true" ]; then
  skip "gRPC not available"
else
  if resp=$(api_post "/api/v1/users" \
      "{\"username\":\"${TEST_USER}\",\"password\":\"${TEST_PASS}\",\"email\":\"${TEST_USER}@test.local\"}" 2>/dev/null); then
    USER_ID=$(echo "$resp" | jq -r '.user.id // .id // .user_id // empty') || true
    if [ -n "$USER_ID" ] && [ "$USER_ID" != "null" ]; then
      pass
    else
      fail "user created but no ID returned"
    fi
  else
    fail "could not create test user"
  fi
fi

begin_test "Obtain initial token for test user"
OLD_TOKEN=""
if [ "$GRPCURL_AVAILABLE" != "true" ] || [ "${GRPC_REACHABLE:-false}" != "true" ]; then
  skip "gRPC not available"
else
  if resp=$(curl -sf $CURL_TIMEOUT -X POST "${BASE_URL}/api/v1/auth/login" \
      -H "Content-Type: application/json" \
      -d "{\"username\":\"${TEST_USER}\",\"password\":\"${TEST_PASS}\"}" 2>/dev/null); then
    OLD_TOKEN=$(echo "$resp" | jq -r '.token // .access_token // empty') || true
    if [ -n "$OLD_TOKEN" ]; then
      pass
    else
      fail "no token in login response"
    fi
  else
    fail "login failed for test user"
  fi
fi

# ---------------------------------------------------------------------------
# Verify initial token works on gRPC
# ---------------------------------------------------------------------------

begin_test "Initial token works on gRPC"
if [ "$GRPCURL_AVAILABLE" != "true" ] || [ "${GRPC_REACHABLE:-false}" != "true" ] || [ -z "$OLD_TOKEN" ]; then
  skip "prerequisites not met"
else
  grpc_result=$(grpcurl -plaintext -connect-timeout 5 \
    -H "Authorization: Bearer ${OLD_TOKEN}" \
    -d '{"repository_name":"test","artifact_name":"test"}' \
    "$GRPC_TARGET" artifact_keeper.sbom.v1.SbomService/ListSbomsForArtifact 2>&1) || true

  if echo "$grpc_result" | grep -q "Unauthenticated\|UNAUTHENTICATED"; then
    # gRPC may use a different auth mechanism; skip the invalidation test
    skip "gRPC auth does not accept REST tokens"
  elif echo "$grpc_result" | grep -q "Unknown service\|Unimplemented"; then
    skip "SbomService not available, cannot test token acceptance"
  else
    pass
  fi
fi

# ---------------------------------------------------------------------------
# Change password and verify old token is rejected on gRPC
# ---------------------------------------------------------------------------

begin_test "Change test user password"
if [ "$GRPCURL_AVAILABLE" != "true" ] || [ "${GRPC_REACHABLE:-false}" != "true" ] || [ -z "$OLD_TOKEN" ]; then
  skip "prerequisites not met"
else
  # Try password change via admin API
  change_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X PUT \
    -H "$(auth_header)" \
    -H "Content-Type: application/json" \
    -d "{\"password\":\"${NEW_PASS}\"}" \
    "${BASE_URL}/api/v1/users/${USER_ID}/password" 2>/dev/null) || true

  if [ "$change_status" = "404" ]; then
    # Try alternate endpoint
    change_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
      -X PUT \
      -H "$(auth_header)" \
      -H "Content-Type: application/json" \
      -d "{\"password\":\"${NEW_PASS}\"}" \
      "${BASE_URL}/api/v1/users/${USER_ID}" 2>/dev/null) || true
  fi

  if [ "$change_status" -ge 200 ] 2>/dev/null && [ "$change_status" -lt 300 ] 2>/dev/null; then
    pass
  else
    skip "could not change password (HTTP ${change_status})"
  fi
fi

begin_test "Old token rejected on gRPC after password change"
if [ "$GRPCURL_AVAILABLE" != "true" ] || [ "${GRPC_REACHABLE:-false}" != "true" ] || [ -z "$OLD_TOKEN" ]; then
  skip "prerequisites not met"
else
  grpc_result=$(grpcurl -plaintext -connect-timeout 5 \
    -H "Authorization: Bearer ${OLD_TOKEN}" \
    -d '{"repository_name":"test","artifact_name":"test"}' \
    "$GRPC_TARGET" artifact_keeper.sbom.v1.SbomService/ListSbomsForArtifact 2>&1) || true

  if echo "$grpc_result" | grep -q "Unauthenticated\|UNAUTHENTICATED\|PermissionDenied\|PERMISSION_DENIED\|token.*invalid\|token.*expired"; then
    pass
  elif echo "$grpc_result" | grep -q "Unknown service\|Unimplemented"; then
    skip "SbomService not available, cannot verify token rejection"
  else
    # If old token still works, that is the bug #549 was about
    fail "old token was not invalidated after password change on gRPC"
  fi
fi

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

if [ -n "$USER_ID" ] && [ "$USER_ID" != "null" ]; then
  api_delete "/api/v1/users/${USER_ID}" > /dev/null 2>&1 || true
fi

end_suite
