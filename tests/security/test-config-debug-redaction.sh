#!/usr/bin/env bash
# test-config-debug-redaction.sh - #534: Verify backend does not leak secrets
#
# Confirms that health, readiness, and error responses do not expose JWT
# secrets, database credentials, or internal configuration values.

source "$(dirname "$0")/../lib/common.sh"

begin_suite "config-debug-redaction"
auth_admin
setup_workdir

# Patterns that should never appear in any API response body
SECRET_PATTERNS="JWT_SECRET\|jwt_secret\|DATABASE_URL\|database_url\|DB_PASSWORD\|db_password\|ADMIN_PASS\|admin_pass\|SECRET_KEY\|secret_key\|-----BEGIN.*PRIVATE KEY"

# ---------------------------------------------------------------------------
# Health endpoint must not leak configuration
# ---------------------------------------------------------------------------

begin_test "GET /api/v1/system/health does not leak secrets"
response=$(curl -s $CURL_TIMEOUT "${BASE_URL}/api/v1/system/health" 2>/dev/null) || true

if [ -z "$response" ]; then
  skip "health endpoint returned empty response"
else
  if echo "$response" | grep -qi "$SECRET_PATTERNS"; then
    fail "health response contains secret-like patterns"
  else
    pass
  fi
fi

# ---------------------------------------------------------------------------
# Readiness endpoint must not leak credentials
# ---------------------------------------------------------------------------

begin_test "GET /readyz does not leak database credentials"
response=$(curl -s $CURL_TIMEOUT "${BASE_URL}/readyz" 2>/dev/null) || true

if [ -z "$response" ]; then
  skip "readyz endpoint returned empty response"
else
  if echo "$response" | grep -qi "$SECRET_PATTERNS"; then
    fail "readyz response contains secret-like patterns"
  elif echo "$response" | grep -qi "postgresql://\|postgres://\|password="; then
    fail "readyz response contains database connection string"
  else
    pass
  fi
fi

# ---------------------------------------------------------------------------
# System info endpoint (if it exists) must redact secrets
# ---------------------------------------------------------------------------

begin_test "GET /api/v1/system/info redacts secrets"
status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/system/info" 2>/dev/null) || true

if [ "$status" = "404" ]; then
  skip "system info endpoint does not exist"
else
  response=$(curl -s $CURL_TIMEOUT \
    -H "$(auth_header)" \
    "${BASE_URL}/api/v1/system/info" 2>/dev/null) || true
  if echo "$response" | grep -qi "$SECRET_PATTERNS"; then
    fail "system info response contains secret-like patterns"
  elif echo "$response" | grep -qi "postgresql://\|postgres://\|password="; then
    fail "system info response contains database connection string"
  else
    pass
  fi
fi

# ---------------------------------------------------------------------------
# Error responses must not leak internal config
# ---------------------------------------------------------------------------

begin_test "404 error response does not leak config"
response=$(curl -s $CURL_TIMEOUT \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/this-endpoint-does-not-exist-${RUN_ID}" 2>/dev/null) || true

if echo "$response" | grep -qi "$SECRET_PATTERNS"; then
  fail "404 response contains secret-like patterns"
elif echo "$response" | grep -qi "postgresql://\|postgres://\|password="; then
  fail "404 response contains database connection string"
else
  pass
fi

begin_test "Invalid format endpoint error does not leak config"
response=$(curl -s $CURL_TIMEOUT \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/nonexistent-${RUN_ID}/artifacts/test.tar.gz" 2>/dev/null) || true

if echo "$response" | grep -qi "$SECRET_PATTERNS"; then
  fail "error response contains secret-like patterns"
elif echo "$response" | grep -qi "stack trace\|backtrace\|at src/"; then
  fail "error response contains stack trace information"
else
  pass
fi

# ---------------------------------------------------------------------------
# Malformed request to trigger potential error path
# ---------------------------------------------------------------------------

begin_test "Malformed JSON body error does not leak internals"
response=$(curl -s $CURL_TIMEOUT -X POST \
  -H "$(auth_header)" \
  -H "Content-Type: application/json" \
  -d '{"broken json' \
  "${BASE_URL}/api/v1/repositories" 2>/dev/null) || true

if echo "$response" | grep -qi "$SECRET_PATTERNS"; then
  fail "malformed request error contains secret-like patterns"
elif echo "$response" | grep -qi "stack trace\|backtrace\|at src/\|panicked at"; then
  fail "malformed request error contains stack trace"
else
  pass
fi

end_suite
