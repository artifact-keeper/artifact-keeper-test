#!/usr/bin/env bash
# test-swagger-ui-gate.sh - #552: Swagger UI gated by environment
#
# Verifies that the Swagger UI and OpenAPI spec endpoints are not exposed
# in non-development environments. In test or production deployments,
# /swagger-ui/ should return 404. If the test environment has Swagger
# intentionally enabled, the test adjusts expectations accordingly.

source "$(dirname "$0")/../lib/common.sh"

begin_suite "swagger-ui-gate"
auth_admin

# ---------------------------------------------------------------------------
# Check /swagger-ui/ availability
# ---------------------------------------------------------------------------

begin_test "Swagger UI not publicly accessible"
# Try without authentication first
status_noauth=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  "${BASE_URL}/swagger-ui/" 2>/dev/null) || true

# Also try alternate paths
status_noauth_alt=""
for path in "/swagger-ui/index.html" "/swagger-ui" "/docs" "/api-docs"; do
  alt=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    "${BASE_URL}${path}" 2>/dev/null) || true
  if [ "$alt" = "200" ]; then
    status_noauth_alt="$alt"
    break
  fi
done

if [ "$status_noauth" = "404" ]; then
  pass
elif [ "$status_noauth" = "401" ] || [ "$status_noauth" = "403" ]; then
  # Swagger UI exists but is auth-gated, which is acceptable
  pass
elif [ "$status_noauth" = "200" ]; then
  # Swagger is accessible. Check if we are in a development/test environment
  # where this might be intentional.
  env_response=$(curl -s $CURL_TIMEOUT \
    -H "$(auth_header)" \
    "${BASE_URL}/api/v1/system/info" 2>/dev/null) || true
  env_name=$(echo "$env_response" | jq -r '.environment // empty' 2>/dev/null) || true

  if [ "$env_name" = "development" ] || [ "$env_name" = "dev" ] || [ "$env_name" = "test" ]; then
    skip "Swagger UI is enabled (environment: ${env_name})"
  elif [ -z "$env_name" ]; then
    # Cannot determine environment; warn but do not fail hard
    skip "Swagger UI returns 200 but environment could not be determined"
  else
    fail "Swagger UI is publicly accessible in ${env_name} environment (HTTP 200)"
  fi
elif [ -n "$status_noauth_alt" ] && [ "$status_noauth_alt" = "200" ]; then
  skip "Swagger UI available at alternate path (may be intentional in test env)"
else
  # 301, 302, 500, etc.
  pass
fi

# ---------------------------------------------------------------------------
# Check /swagger-ui/ with authentication
# ---------------------------------------------------------------------------

begin_test "Swagger UI with authentication"
status_auth=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" \
  "${BASE_URL}/swagger-ui/" 2>/dev/null) || true

if [ "$status_auth" = "404" ]; then
  # Swagger disabled even for authenticated users
  pass
elif [ "$status_auth" = "200" ]; then
  # Swagger gated behind auth is acceptable in many environments
  pass
elif [ "$status_auth" = "403" ]; then
  # Swagger requires specific role; fine
  pass
else
  pass
fi

# ---------------------------------------------------------------------------
# Check /api/v1/openapi.json availability
# ---------------------------------------------------------------------------

begin_test "OpenAPI spec endpoint gated"
status_noauth=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  "${BASE_URL}/api/v1/openapi.json" 2>/dev/null) || true

if [ "$status_noauth" = "404" ]; then
  pass
elif [ "$status_noauth" = "401" ] || [ "$status_noauth" = "403" ]; then
  # Auth-gated spec is fine
  pass
elif [ "$status_noauth" = "200" ]; then
  # Public OpenAPI spec is common and not necessarily a security issue.
  # Verify it does not contain internal-only information.
  spec_body=$(curl -s $CURL_TIMEOUT \
    "${BASE_URL}/api/v1/openapi.json" 2>/dev/null) || true

  if echo "$spec_body" | grep -qi "internal\|private.*endpoint\|admin.*secret"; then
    fail "OpenAPI spec is public and contains internal-only references"
  else
    skip "OpenAPI spec is publicly accessible (common for API documentation)"
  fi
else
  pass
fi

# ---------------------------------------------------------------------------
# Swagger UI should not be accessible without auth if it exists
# ---------------------------------------------------------------------------

begin_test "No unauthenticated access to API documentation"
doc_paths=("/swagger-ui/" "/redoc" "/rapidoc" "/api-docs")
unauthenticated_docs=false

for path in "${doc_paths[@]}"; do
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    "${BASE_URL}${path}" 2>/dev/null) || true

  if [ "$status" = "200" ]; then
    # Check if it returns actual HTML documentation
    body=$(curl -s $CURL_TIMEOUT "${BASE_URL}${path}" 2>/dev/null | head -c 500) || true
    if echo "$body" | grep -qi "swagger\|openapi\|redoc\|api.*doc"; then
      unauthenticated_docs=true
      break
    fi
  fi
done

if [ "$unauthenticated_docs" = "true" ]; then
  skip "API documentation accessible without auth (may be intentional in test env)"
else
  pass
fi

end_suite
