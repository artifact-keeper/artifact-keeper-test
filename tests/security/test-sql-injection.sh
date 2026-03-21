#!/usr/bin/env bash
# test-sql-injection.sh - T2-15: SQL injection payloads handled safely
#
# Verifies that SQL injection payloads in search and listing endpoints do not
# cause SQL errors, data leaks, or unexpected behavior. The backend uses
# parameterized queries (SQLx), so these should all be handled cleanly.

source "$(dirname "$0")/../lib/common.sh"

begin_suite "sql-injection"
auth_admin
setup_workdir

# SQL error patterns that indicate raw SQL errors leaking to the client
SQL_ERROR_REGEX="SQL syntax|mysql_fetch|ORA-[0-9]|pg_query|sqlite3\.|SQLSTATE|Unclosed quotation|syntax error at or near|unterminated|column .* does not exist|relation .* does not exist"

# ---------------------------------------------------------------------------
# Helper: test a SQL injection payload against an endpoint
# ---------------------------------------------------------------------------

test_sqli_payload() {
  local endpoint="$1"
  local param_name="$2"
  local payload="$3"
  local description="$4"

  # URL-encode the payload
  local encoded
  encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''${payload}'''))" 2>/dev/null) || encoded="$payload"

  local response
  response=$(curl -s -w "\n%{http_code}" $CURL_TIMEOUT \
    -H "$(auth_header)" \
    "${BASE_URL}${endpoint}?${param_name}=${encoded}") || true

  local http_code
  http_code=$(echo "$response" | tail -1)
  local body
  body=$(echo "$response" | sed '$d')

  # Check for SQL error messages in response body
  if echo "$body" | grep -qiE "$SQL_ERROR_REGEX"; then
    fail "SQL error leaked in response for ${description}: $(echo "$body" | head -c 200)"
    return 1
  fi

  # A 500 with SQL-related payload is suspicious but not necessarily a vulnerability
  if [ "$http_code" = "500" ]; then
    # Check response body for SQL error details
    if echo "$body" | grep -qiE "internal|panic|stack trace"; then
      fail "server error with potential info leak for ${description} (HTTP 500)"
      return 1
    fi
  fi

  return 0
}

# ---------------------------------------------------------------------------
# Search endpoint SQL injection tests
# ---------------------------------------------------------------------------

begin_test "Search: basic OR injection"
if test_sqli_payload "/api/v1/search" "q" "' OR '1'='1" "basic OR injection"; then
  pass
fi

begin_test "Search: DROP TABLE injection"
if test_sqli_payload "/api/v1/search" "q" "'; DROP TABLE artifacts;--" "DROP TABLE injection"; then
  pass
fi

begin_test "Search: UNION SELECT injection"
if test_sqli_payload "/api/v1/search" "q" "' UNION SELECT 1,2,3--" "UNION SELECT injection"; then
  pass
fi

begin_test "Search: stacked query injection"
if test_sqli_payload "/api/v1/search" "q" "'; SELECT pg_sleep(1);--" "stacked query injection"; then
  pass
fi

begin_test "Search: comment-based injection"
if test_sqli_payload "/api/v1/search" "q" "admin'/*" "comment-based injection"; then
  pass
fi

# ---------------------------------------------------------------------------
# Repository listing SQL injection tests
# ---------------------------------------------------------------------------

begin_test "Repo listing: UNION SELECT injection"
if test_sqli_payload "/api/v1/repositories" "search" "1' UNION SELECT 1--" "repo listing UNION injection"; then
  pass
fi

begin_test "Repo listing: boolean-based injection"
if test_sqli_payload "/api/v1/repositories" "search" "' AND 1=1--" "repo listing boolean injection"; then
  pass
fi

begin_test "Repo listing: error-based injection"
if test_sqli_payload "/api/v1/repositories" "search" "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--" "repo listing error-based injection"; then
  pass
fi

# ---------------------------------------------------------------------------
# Artifact listing SQL injection tests
# ---------------------------------------------------------------------------

begin_test "Artifact search: time-based blind injection"
if test_sqli_payload "/api/v1/search" "q" "'; WAITFOR DELAY '0:0:1';--" "time-based blind injection"; then
  pass
fi

begin_test "Artifact search: second-order injection payload"
if test_sqli_payload "/api/v1/search" "q" "test'); INSERT INTO users(username,password) VALUES('evil','evil');--" "second-order injection"; then
  pass
fi

# ---------------------------------------------------------------------------
# Verify search still works after injection attempts
# ---------------------------------------------------------------------------

begin_test "Search endpoint still functional after injection attempts"
status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/search?q=test") || true

if [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 500 ] 2>/dev/null; then
  pass
else
  fail "search endpoint returned ${status} after injection tests (may indicate damage)"
fi

end_suite
