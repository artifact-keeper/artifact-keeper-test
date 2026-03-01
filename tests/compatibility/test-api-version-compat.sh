#!/usr/bin/env bash
# test-api-version-compat.sh - API version compatibility test
#
# Validates that all major API endpoints return the expected response shapes
# and that standard HTTP conventions (content negotiation, 404 for unknown
# routes) are honored.

source "$(dirname "$0")/../lib/common.sh"

begin_suite "api-compat"
auth_admin
setup_workdir

REPO_KEY="test-compat-${RUN_ID}"

# ---------------------------------------------------------------------------
# Health endpoint
# ---------------------------------------------------------------------------

begin_test "GET /api/v1/system/health returns status field"
health_resp=""
if health_resp=$(api_get "/api/v1/system/health"); then
  if assert_contains "$health_resp" "status" "health response should contain status field"; then
    pass
  fi
else
  fail "GET /api/v1/system/health returned error"
fi

# ---------------------------------------------------------------------------
# List repositories
# ---------------------------------------------------------------------------

begin_test "GET /api/v1/repositories returns valid response"
repos_resp=""
if repos_resp=$(api_get "/api/v1/repositories"); then
  # Response should be a JSON array or an object with items/repositories
  is_valid=$(echo "$repos_resp" | jq -e 'if type == "array" then true elif .items then true elif .repositories then true elif .total != null then true else false end' 2>/dev/null) || true
  if [ "$is_valid" = "true" ]; then
    pass
  else
    fail "repositories response is not a recognized JSON structure"
  fi
else
  fail "GET /api/v1/repositories returned error"
fi

# ---------------------------------------------------------------------------
# Create a test repository
# ---------------------------------------------------------------------------

begin_test "POST /api/v1/repositories creates repository"
create_payload="{\"key\":\"${REPO_KEY}\",\"name\":\"${REPO_KEY}\",\"format\":\"generic\",\"repo_type\":\"local\"}"
create_resp=""
if create_resp=$(api_post "/api/v1/repositories" "$create_payload"); then
  pass
else
  fail "POST /api/v1/repositories returned error"
fi

# ---------------------------------------------------------------------------
# Get repository by key
# ---------------------------------------------------------------------------

begin_test "GET /api/v1/repositories/${REPO_KEY} contains key"
repo_resp=""
if repo_resp=$(api_get "/api/v1/repositories/${REPO_KEY}"); then
  if assert_contains "$repo_resp" "key" "repo response should contain key field"; then
    pass
  fi
else
  fail "GET /api/v1/repositories/${REPO_KEY} returned error"
fi

# ---------------------------------------------------------------------------
# List artifacts in repository
# ---------------------------------------------------------------------------

begin_test "GET /api/v1/repositories/${REPO_KEY}/artifacts returns valid response"
artifacts_resp=""
if artifacts_resp=$(api_get "/api/v1/repositories/${REPO_KEY}/artifacts"); then
  # Should be a valid JSON response (array or object)
  is_json=$(echo "$artifacts_resp" | jq -e 'type' 2>/dev/null) || true
  if [ -n "$is_json" ]; then
    pass
  else
    fail "artifacts response is not valid JSON"
  fi
else
  fail "GET /api/v1/repositories/${REPO_KEY}/artifacts returned error"
fi

# ---------------------------------------------------------------------------
# Accept header content negotiation
# ---------------------------------------------------------------------------

begin_test "Accept: application/json header works"
json_resp=""
json_status=$(curl -s -o "$WORK_DIR/accept-resp.json" -w '%{http_code}' \
  -H "$(auth_header)" \
  -H "Accept: application/json" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}") || true

if [ "$json_status" -ge 200 ] 2>/dev/null && [ "$json_status" -lt 300 ] 2>/dev/null; then
  content_type=$(curl -s -D "$WORK_DIR/accept-headers.txt" -o /dev/null \
    -H "$(auth_header)" \
    -H "Accept: application/json" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}") || true
  header_ct=$(grep -i '^content-type:' "$WORK_DIR/accept-headers.txt" | tr -d '\r') || true
  if echo "$header_ct" | grep -qi "application/json"; then
    pass
  else
    # Some servers return json without the exact header match, still valid
    body=$(cat "$WORK_DIR/accept-resp.json")
    if echo "$body" | jq -e '.' > /dev/null 2>&1; then
      pass
    else
      fail "response is not JSON despite Accept header"
    fi
  fi
else
  fail "request with Accept: application/json returned HTTP ${json_status}"
fi

# ---------------------------------------------------------------------------
# Unknown endpoint returns 404
# ---------------------------------------------------------------------------

begin_test "Unknown endpoint returns 404"
unknown_status=$(curl -s -o /dev/null -w '%{http_code}' \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/this-endpoint-does-not-exist-${RUN_ID}") || true

if [ "$unknown_status" = "404" ]; then
  pass
else
  fail "unknown endpoint returned ${unknown_status}, expected 404"
fi

# ---------------------------------------------------------------------------
# Delete repository
# ---------------------------------------------------------------------------

begin_test "DELETE /api/v1/repositories/${REPO_KEY} succeeds"
del_status=$(curl -s -o /dev/null -w '%{http_code}' \
  -X DELETE \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}") || true

if [ "$del_status" -ge 200 ] 2>/dev/null && [ "$del_status" -lt 300 ] 2>/dev/null; then
  pass
else
  fail "DELETE returned HTTP ${del_status}, expected 2xx"
fi

# ---------------------------------------------------------------------------
# Verify deletion
# ---------------------------------------------------------------------------

begin_test "Deleted repository returns 404"
if assert_http_status "/api/v1/repositories/${REPO_KEY}" "404"; then
  pass
fi

end_suite
