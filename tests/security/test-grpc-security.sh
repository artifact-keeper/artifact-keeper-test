#!/usr/bin/env bash
# test-grpc-security.sh - T2-16: gRPC reflection and unauthenticated access
#
# Verifies that gRPC endpoints require authentication and that server
# reflection does not expose service definitions to unauthenticated callers.
#
# Why this suite is driven from a vendored .proto (artifact-keeper-test#343)
# -------------------------------------------------------------------------
# Until #343 this suite had never executed a single assertion in the release
# gate: grpcurl was not installed on the runner, so every testcase took the
# `command -v grpcurl` skip branch and the suite certified nothing while
# security-tests reported green.
#
# Installing grpcurl alone is not sufficient. grpcurl resolves method and
# message descriptors over gRPC server reflection, and the backend leaves
# reflection OFF by default (GRPC_REFLECTION_ENABLED, info-disclosure
# hardening artifact-keeper#2226) -- which is exactly the posture the
# "reflection without auth" assertion below demands. Without descriptors,
# every method call died client-side with
#
#   failed to query for service descriptor "artifact_keeper.sbom.v1.SbomService":
#   server does not support the reflection API
#
# ...which never reaches the server, so it proves nothing about authorization.
# The suite therefore carries its own copy of the service contract at
# tests/proto/sbom.proto and passes it to grpcurl with -import-path/-proto.
#
# The old request payload ({"repository_name":...,"artifact_name":...}) did not
# match ListSbomsRequest either; the correct field is `artifact_id`. Both bugs
# had to be fixed before these assertions could ever have run.

source "$(dirname "$0")/../lib/common.sh"

begin_suite "grpc-security"

# grpcurl is installed by the security-tests job in release-gate.yml. If that
# install step ever breaks, require_cmd hard-fails under RELEASE_GATE=1 rather
# than letting the suite skip its way to green (the #870/#871/#888 class).
require_cmd grpcurl

auth_admin
setup_workdir

# gRPC runs on port 9090 by default. Derive the host from BASE_URL.
GRPC_HOST=$(echo "$BASE_URL" | sed -E 's|https?://||; s|:[0-9]+$||; s|/.*||')
GRPC_PORT="${GRPC_PORT:-9090}"
GRPC_TARGET="${GRPC_HOST}:${GRPC_PORT}"

PROTO_DIR="$(cd "$(dirname "$0")/../proto" && pwd)"
SBOM_METHOD="artifact_keeper.sbom.v1.SbomService/ListSbomsForArtifact"
# ListSbomsRequest has exactly one field: `artifact_id` (see tests/proto/sbom.proto).
# A well-formed request for a non-existent artifact is enough to exercise the
# auth interceptor, which runs before any handler logic.
SBOM_REQ='{"artifact_id":"00000000-0000-0000-0000-000000000000"}'

# grpc_call <auth-header-or-empty> -- issue SBOM_METHOD, echo combined output.
grpc_call() {
  local auth="$1"
  if [ -n "$auth" ]; then
    grpcurl -plaintext -connect-timeout 5 \
      -import-path "$PROTO_DIR" -proto sbom.proto \
      -H "$auth" -d "$SBOM_REQ" "$GRPC_TARGET" "$SBOM_METHOD" 2>&1 || true
  else
    grpcurl -plaintext -connect-timeout 5 \
      -import-path "$PROTO_DIR" -proto sbom.proto \
      -d "$SBOM_REQ" "$GRPC_TARGET" "$SBOM_METHOD" 2>&1 || true
  fi
}

# A descriptor/parse problem is a HARNESS fault, not a product verdict: it means
# the vendored proto has drifted from the backend contract. Detect it so it is
# never mistaken for an authorization result.
grpc_is_descriptor_error() {
  echo "$1" | grep -q \
    "has no known field named\|method not found\|Failed to process proto\|could not parse\|service descriptor"
}

# ---------------------------------------------------------------------------
# gRPC endpoint must be reachable. Unreachable is an INFRA failure, not a skip:
# the gate deploys a backend whose chart exposes 9090, so "cannot dial" means
# the environment is broken and the tier cannot be evaluated.
# ---------------------------------------------------------------------------

begin_test "gRPC endpoint reachable"
dial_probe=$(grpcurl -plaintext -connect-timeout 5 "$GRPC_TARGET" list 2>&1 || true)
if echo "$dial_probe" | grep -q "Failed to dial\|connection refused\|context deadline exceeded\|transport: Error"; then
  infra_fail "gRPC endpoint not reachable at ${GRPC_TARGET}" "$dial_probe"
else
  pass
fi

# ---------------------------------------------------------------------------
# Unauthenticated reflection must not enumerate the service catalog.
#
# The backend registers tonic-reflection only when GRPC_REFLECTION_ENABLED is
# set (artifact-keeper#2226). The expected posture is "reflection absent"; an
# UNAUTHENTICATED/PERMISSION_DENIED response is also acceptable. Anything that
# lists application services to an anonymous caller is an info-disclosure bug.
# ---------------------------------------------------------------------------

begin_test "gRPC reflection does not enumerate services without auth"
reflect_result=$(grpcurl -plaintext -connect-timeout 5 "$GRPC_TARGET" list 2>&1 || true)

if echo "$reflect_result" | grep -q "Failed to dial\|connection refused\|context deadline"; then
  infra_fail "gRPC endpoint became unreachable mid-suite" "$reflect_result"
elif echo "$reflect_result" | grep -q "does not support the reflection API"; then
  pass
elif echo "$reflect_result" | grep -q "Unauthenticated\|UNAUTHENTICATED\|PermissionDenied\|PERMISSION_DENIED"; then
  pass
else
  app_services=$(echo "$reflect_result" | grep -v "^grpc\.\|^$" | grep -c "." 2>/dev/null) || app_services=0
  if [ "$app_services" -gt 0 ]; then
    fail "gRPC reflection exposes ${app_services} service(s) without authentication: $(echo "$reflect_result" | tr '\n' ' ')"
  else
    pass
  fi
fi

# ---------------------------------------------------------------------------
# An unauthenticated data-plane call must be rejected by the auth interceptor.
# ---------------------------------------------------------------------------

begin_test "Unauthenticated gRPC method call rejected"
call_result=$(grpc_call "")

if grpc_is_descriptor_error "$call_result"; then
  infra_fail "vendored proto has drifted from the backend contract; the call never reached the server" "$call_result"
elif echo "$call_result" | grep -q "Unauthenticated\|UNAUTHENTICATED\|PermissionDenied\|PERMISSION_DENIED"; then
  pass
else
  fail "unauthenticated gRPC call was not rejected: ${call_result}"
fi

# ---------------------------------------------------------------------------
# A structurally-valid but bogus bearer token must also be rejected. This
# separates "the interceptor rejects anonymous callers" from "the interceptor
# actually validates the token it was given".
# ---------------------------------------------------------------------------

begin_test "Invalid bearer token rejected on gRPC"
bogus_result=$(grpc_call "Authorization: Bearer not-a-real-token")

if grpc_is_descriptor_error "$bogus_result"; then
  infra_fail "vendored proto has drifted from the backend contract" "$bogus_result"
elif echo "$bogus_result" | grep -q "Unauthenticated\|UNAUTHENTICATED"; then
  pass
else
  fail "gRPC accepted a bogus bearer token: ${bogus_result}"
fi

# ---------------------------------------------------------------------------
# Positive control: a valid admin token must be ACCEPTED. Without this, the
# suite could pass by rejecting everything (including valid credentials), which
# would make the negative assertions above meaningless.
#
# SbomService is admin-gated, so the admin JWT is the right credential here.
# ---------------------------------------------------------------------------

begin_test "Authenticated gRPC call accepted (positive control)"
auth_result=$(grpc_call "Authorization: Bearer ${ADMIN_TOKEN}")

if grpc_is_descriptor_error "$auth_result"; then
  infra_fail "vendored proto has drifted from the backend contract" "$auth_result"
elif echo "$auth_result" | grep -q "Unauthenticated\|UNAUTHENTICATED"; then
  fail "valid admin token was rejected on gRPC: ${auth_result}"
elif echo "$auth_result" | grep -q "PermissionDenied\|PERMISSION_DENIED"; then
  fail "admin token lacks permission on SbomService: ${auth_result}"
else
  pass
fi

end_suite
