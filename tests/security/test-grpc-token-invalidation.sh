#!/usr/bin/env bash
# test-grpc-token-invalidation.sh - #549: gRPC token invalidation after password change
#
# Verifies that a JWT stops working on the gRPC data plane once the owning
# user's password changes -- i.e. that the gRPC auth interceptor consults the
# credential-invalidation state and does not honour a token for the remainder
# of its natural lifetime.
#
# Why this suite was rewritten (artifact-keeper-test#343)
# ------------------------------------------------------
# This suite had never executed an assertion in the release gate (grpcurl was
# not installed, so every testcase skipped). Installing grpcurl exposed three
# further defects that meant the load-bearing assertion could not have passed
# honestly in ANY configuration:
#
#   1. grpcurl was invoked without descriptors, so it needed gRPC server
#      reflection -- which the backend deliberately leaves OFF
#      (artifact-keeper#2226). Every call failed client-side with "server does
#      not support the reflection API" and never reached the server. Fixed by
#      driving grpcurl from the vendored tests/proto/sbom.proto.
#
#   2. The request payload was {"repository_name":...,"artifact_name":...}, but
#      ListSbomsRequest has a single field, `artifact_id`.
#
#   3. The password change used PUT /api/v1/users/{id}/password, which the
#      backend answers 405 (the route is POST). The suite only had a fallback
#      for 404, so the change silently never happened -- and the "old token
#      rejected" assertion then ran against a password that had not changed.
#
#   4. The test user was created WITHOUT admin, but SbomService is admin-gated,
#      so every gRPC call returned PermissionDenied. The old assertion counted
#      PermissionDenied as proof of invalidation, so it would have reported
#      "pass" for a user whose token was never invalidated at all. This suite
#      therefore provisions an admin test user and treats PermissionDenied as a
#      FAILURE of the positive control, never as evidence of revocation.

source "$(dirname "$0")/../lib/common.sh"

begin_suite "grpc-token-invalidation"

require_cmd grpcurl

auth_admin
setup_workdir

GRPC_HOST=$(echo "$BASE_URL" | sed -E 's|https?://||; s|:[0-9]+$||; s|/.*||')
GRPC_PORT="${GRPC_PORT:-9090}"
GRPC_TARGET="${GRPC_HOST}:${GRPC_PORT}"

PROTO_DIR="$(cd "$(dirname "$0")/../proto" && pwd)"
SBOM_METHOD="artifact_keeper.sbom.v1.SbomService/ListSbomsForArtifact"
SBOM_REQ='{"artifact_id":"00000000-0000-0000-0000-000000000000"}'

TEST_USER="e2e-grpc-inval-${RUN_ID}"
TEST_PASS="GrpcInval123!"
NEW_PASS="GrpcInval456!"
USER_ID=""
OLD_TOKEN=""

grpc_call_as() {
  grpcurl -plaintext -connect-timeout 5 \
    -import-path "$PROTO_DIR" -proto sbom.proto \
    -H "Authorization: Bearer $1" -d "$SBOM_REQ" \
    "$GRPC_TARGET" "$SBOM_METHOD" 2>&1 || true
}

grpc_is_descriptor_error() {
  echo "$1" | grep -q \
    "has no known field named\|method not found\|Failed to process proto\|could not parse\|service descriptor"
}

# ---------------------------------------------------------------------------
# Setup. Every step here is a PRECONDITION: if it fails, the harness cannot
# evaluate #549 at all, so it is recorded as an INFRA failure rather than a
# skip. A skip would leave the suite certifying nothing while exiting 0.
# ---------------------------------------------------------------------------

begin_test "gRPC endpoint reachable"
dial_probe=$(grpcurl -plaintext -connect-timeout 5 "$GRPC_TARGET" list 2>&1 || true)
if echo "$dial_probe" | grep -q "Failed to dial\|connection refused\|context deadline exceeded\|transport: Error"; then
  infra_fail "gRPC endpoint not reachable at ${GRPC_TARGET}" "$dial_probe"
  end_suite
fi
pass

begin_test "Create admin test user for token invalidation"
# SbomService is admin-gated. A non-admin user yields PermissionDenied on every
# call, which would make the invalidation assertion vacuous (see header note 4).
create_resp=$(api_post "/api/v1/users" \
  "{\"username\":\"${TEST_USER}\",\"password\":\"${TEST_PASS}\",\"email\":\"${TEST_USER}@test.local\",\"is_admin\":true}" 2>/dev/null) || true
USER_ID=$(echo "$create_resp" | jq -r '.user.id // .id // empty' 2>/dev/null) || true
if [ -z "$USER_ID" ] || [ "$USER_ID" = "null" ]; then
  infra_fail "could not create admin test user" "${create_resp:0:400}"
  end_suite
fi
if [ "$(echo "$create_resp" | jq -r '.user.is_admin // .is_admin // empty')" != "true" ]; then
  infra_fail "test user was created without admin; SbomService would return PermissionDenied and the invalidation assertion would be vacuous" "${create_resp:0:400}"
  end_suite
fi
pass

begin_test "Obtain initial token for test user"
login_resp=$(curl -sf $CURL_TIMEOUT -X POST "${BASE_URL}/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"${TEST_USER}\",\"password\":\"${TEST_PASS}\"}" 2>/dev/null) || true
OLD_TOKEN=$(echo "$login_resp" | jq -r '.access_token // .token // empty' 2>/dev/null) || true
if [ -z "$OLD_TOKEN" ] || [ "$OLD_TOKEN" = "null" ]; then
  infra_fail "could not log in as the test user" "${login_resp:0:400}"
  end_suite
fi
pass

# ---------------------------------------------------------------------------
# Positive control: the token must WORK before the password change. Without
# this, "rejected after the change" proves nothing -- a token that never worked
# is trivially "rejected".
# ---------------------------------------------------------------------------

begin_test "Initial token is accepted on gRPC (positive control)"
before_result=$(grpc_call_as "$OLD_TOKEN")
if grpc_is_descriptor_error "$before_result"; then
  infra_fail "vendored proto has drifted from the backend contract; the call never reached the server" "$before_result"
  end_suite
elif echo "$before_result" | grep -q "Unauthenticated\|UNAUTHENTICATED"; then
  infra_fail "freshly-issued token was rejected on gRPC before any password change" "$before_result"
  end_suite
elif echo "$before_result" | grep -q "PermissionDenied\|PERMISSION_DENIED"; then
  infra_fail "test user is not authorized for SbomService; the invalidation assertion would be vacuous" "$before_result"
  end_suite
else
  pass
fi

# ---------------------------------------------------------------------------
# Change the password. POST /api/v1/users/{id}/password with the user's OWN
# token is the real #549 scenario (self-service change). A non-2xx here is a
# precondition failure, not a product verdict.
# ---------------------------------------------------------------------------

begin_test "Test user changes their own password"
change_body=$(mktemp)
change_status=$(curl -s -o "$change_body" -w '%{http_code}' $CURL_TIMEOUT \
  -X POST \
  -H "Authorization: Bearer ${OLD_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{\"current_password\":\"${TEST_PASS}\",\"new_password\":\"${NEW_PASS}\"}" \
  "${BASE_URL}/api/v1/users/${USER_ID}/password" 2>/dev/null) || true
change_out=$(cat "$change_body" 2>/dev/null || true); rm -f "$change_body"
if [ "$change_status" -ge 200 ] 2>/dev/null && [ "$change_status" -lt 300 ] 2>/dev/null; then
  pass
else
  infra_fail "password change failed (HTTP ${change_status})" "${change_out:0:400}"
  end_suite
fi

# ---------------------------------------------------------------------------
# The load-bearing assertion (#549).
#
# Only UNAUTHENTICATED counts as invalidation. PermissionDenied explicitly does
# NOT: it means the caller was authenticated but unauthorized, which is what the
# previous version of this suite mistook for revocation.
# ---------------------------------------------------------------------------

begin_test "Old token rejected on gRPC after password change"
after_result=$(grpc_call_as "$OLD_TOKEN")
if grpc_is_descriptor_error "$after_result"; then
  infra_fail "vendored proto has drifted from the backend contract" "$after_result"
elif echo "$after_result" | grep -q "Unauthenticated\|UNAUTHENTICATED"; then
  pass
elif echo "$after_result" | grep -q "PermissionDenied\|PERMISSION_DENIED"; then
  fail "gRPC returned PermissionDenied, not an authentication rejection; the token was still accepted as authentic after the password change: ${after_result}"
else
  fail "old token was NOT invalidated after password change on gRPC (#549): ${after_result}"
fi

# ---------------------------------------------------------------------------
# Cross-check the REST plane. #549 is specifically about gRPC lagging REST, so
# recording both makes a future regression unambiguous.
# ---------------------------------------------------------------------------

begin_test "Old token also rejected on REST after password change"
rest_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -H "Authorization: Bearer ${OLD_TOKEN}" "${BASE_URL}/api/v1/auth/me" 2>/dev/null) || true
if [ "$rest_status" = "401" ] || [ "$rest_status" = "403" ]; then
  pass
else
  fail "old token still accepted on REST after password change (HTTP ${rest_status})"
fi

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

if [ -n "$USER_ID" ] && [ "$USER_ID" != "null" ]; then
  api_delete "/api/v1/users/${USER_ID}" > /dev/null 2>&1 || true
fi

end_suite
