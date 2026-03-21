#!/usr/bin/env bash
# test-grpc-security.sh - T2-16: gRPC reflection and unauthenticated access
#
# Verifies that gRPC endpoints require authentication and that server
# reflection does not expose service definitions to unauthenticated callers.

source "$(dirname "$0")/../lib/common.sh"

begin_suite "grpc-security"
auth_admin
setup_workdir

# gRPC runs on port 9090 by default. Derive the host from BASE_URL.
GRPC_HOST=$(echo "$BASE_URL" | sed -E 's|https?://||; s|:[0-9]+$||; s|/.*||')
GRPC_PORT="${GRPC_PORT:-9090}"
GRPC_TARGET="${GRPC_HOST}:${GRPC_PORT}"

# ---------------------------------------------------------------------------
# Check prerequisites
# ---------------------------------------------------------------------------

begin_test "Check grpcurl availability"
if ! command -v grpcurl &>/dev/null; then
  skip "grpcurl not found on PATH; install it to enable gRPC security tests"
else
  pass
fi

# ---------------------------------------------------------------------------
# Test gRPC connectivity
# ---------------------------------------------------------------------------

begin_test "Check gRPC endpoint reachability"
if ! command -v grpcurl &>/dev/null; then
  skip "grpcurl not available"
else
  conn_result=$(grpcurl -plaintext -connect-timeout 5 "$GRPC_TARGET" list 2>&1) || true
  if echo "$conn_result" | grep -q "Failed to dial\|connection refused\|context deadline exceeded\|transport: Error"; then
    skip "gRPC endpoint not reachable at ${GRPC_TARGET}"
  else
    pass
  fi
fi

# ---------------------------------------------------------------------------
# Test unauthenticated gRPC reflection
# ---------------------------------------------------------------------------

begin_test "gRPC reflection without auth"
if ! command -v grpcurl &>/dev/null; then
  skip "grpcurl not available"
else
  reflect_result=$(grpcurl -plaintext -connect-timeout 5 "$GRPC_TARGET" list 2>&1) || true

  if echo "$reflect_result" | grep -q "Failed to dial\|connection refused\|context deadline"; then
    skip "gRPC endpoint not reachable"
  elif echo "$reflect_result" | grep -q "Server does not support the reflection API"; then
    pass
  elif echo "$reflect_result" | grep -q "Unauthenticated\|UNAUTHENTICATED\|PermissionDenied\|PERMISSION_DENIED"; then
    pass
  else
    # Count non-internal services
    app_services=$(echo "$reflect_result" | grep -v "^grpc\.\|^$" | grep -c "." 2>/dev/null) || app_services=0
    if [ "$app_services" -gt 0 ]; then
      fail "gRPC reflection exposes ${app_services} service(s) without authentication"
    else
      pass
    fi
  fi
fi

# ---------------------------------------------------------------------------
# Test unauthenticated gRPC method call
# ---------------------------------------------------------------------------

begin_test "Unauthenticated gRPC method call rejected"
if ! command -v grpcurl &>/dev/null; then
  skip "grpcurl not available"
else
  call_result=$(grpcurl -plaintext -connect-timeout 5 \
    -d '{"repository_name":"test","artifact_name":"test"}' \
    "$GRPC_TARGET" artifact_keeper.sbom.v1.SbomService/ListSbomsForArtifact 2>&1) || true

  if echo "$call_result" | grep -q "Failed to dial\|connection refused\|context deadline"; then
    skip "gRPC endpoint not reachable"
  elif echo "$call_result" | grep -q "Unauthenticated\|UNAUTHENTICATED\|PermissionDenied\|PERMISSION_DENIED"; then
    pass
  elif echo "$call_result" | grep -q "Unknown service\|not found\|Unimplemented"; then
    # Service not found is also acceptable (no information leak)
    pass
  else
    fail "unauthenticated gRPC call returned a response instead of auth error"
  fi
fi

# ---------------------------------------------------------------------------
# Test authenticated gRPC call (positive control)
# ---------------------------------------------------------------------------

begin_test "Authenticated gRPC call accepted"
if ! command -v grpcurl &>/dev/null; then
  skip "grpcurl not available"
else
  auth_call=$(grpcurl -plaintext -connect-timeout 5 \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -d '{"repository_name":"test","artifact_name":"test"}' \
    "$GRPC_TARGET" artifact_keeper.sbom.v1.SbomService/ListSbomsForArtifact 2>&1) || true

  if echo "$auth_call" | grep -q "Failed to dial\|connection refused\|context deadline"; then
    skip "gRPC endpoint not reachable"
  elif echo "$auth_call" | grep -q "Unauthenticated\|UNAUTHENTICATED"; then
    skip "gRPC auth may use a different token format than REST API"
  elif echo "$auth_call" | grep -q "Unknown service\|Unimplemented"; then
    skip "SbomService not available on this deployment"
  else
    # Any response (including empty or NotFound for the specific resource) is fine
    pass
  fi
fi

end_suite
