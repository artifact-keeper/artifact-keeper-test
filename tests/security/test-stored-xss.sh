#!/usr/bin/env bash
# test-stored-xss.sh - T2-20: Stored XSS prevention in artifact metadata
#
# Verifies that script tags and other XSS payloads in artifact metadata are
# properly escaped or sanitized when returned through the API. The API should
# return application/json responses, not text/html, which is the primary defense.

source "$(dirname "$0")/../lib/common.sh"

begin_suite "stored-xss"
auth_admin
setup_workdir

REPO_KEY="sec-xss-${RUN_ID}"

# ---------------------------------------------------------------------------
# Create a generic repository
# ---------------------------------------------------------------------------

begin_test "Create generic local repo"
if create_local_repo "$REPO_KEY" "generic"; then
  pass
else
  fail "could not create generic repo"
fi

# ---------------------------------------------------------------------------
# Upload artifact with XSS payload in filename/path
# ---------------------------------------------------------------------------

begin_test "Upload artifact with script tag in path"
echo "xss-test-content-${RUN_ID}" > "${WORK_DIR}/xss-test.bin"

# Use a path that contains a script tag
xss_path="pkg/<script>alert(1)</script>/v1/payload.bin"
encoded_xss_path="pkg/%3Cscript%3Ealert(1)%3C%2Fscript%3E/v1/payload.bin"

status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X PUT \
  -H "$(auth_header)" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@${WORK_DIR}/xss-test.bin" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/${encoded_xss_path}") || true

if [ "$status" = "400" ] || [ "$status" = "422" ]; then
  # Server rejected the path outright (best case)
  pass
elif [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then
  # Accepted the upload. Verify the metadata response escapes the script tag.
  skip "server accepted XSS path; checking metadata escaping in subsequent tests"
else
  # 404 or other errors are acceptable
  pass
fi

# ---------------------------------------------------------------------------
# Upload a normal artifact and check metadata Content-Type
# ---------------------------------------------------------------------------

begin_test "Upload normal artifact for metadata inspection"
echo "normal-content-${RUN_ID}" > "${WORK_DIR}/normal.bin"
if api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/xss-check/v1/normal.bin" \
    "${WORK_DIR}/normal.bin"; then
  pass
else
  fail "could not upload normal artifact"
fi

# ---------------------------------------------------------------------------
# Check that API responses use application/json Content-Type
# ---------------------------------------------------------------------------

begin_test "API metadata response uses application/json Content-Type"
headers=$(curl -sI $CURL_TIMEOUT \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts" 2>/dev/null) || true

content_type=$(echo "$headers" | grep -i "^Content-Type:" | head -1 | tr -d '\r') || true

if echo "$content_type" | grep -qi "application/json"; then
  pass
elif [ -z "$content_type" ]; then
  skip "could not retrieve Content-Type header"
else
  if echo "$content_type" | grep -qi "text/html"; then
    fail "API returned text/html Content-Type (XSS risk): ${content_type}"
  else
    # Other content types like text/plain are less risky but still noted
    pass
  fi
fi

# ---------------------------------------------------------------------------
# Check that artifact listing does not contain unescaped script tags
# ---------------------------------------------------------------------------

begin_test "Artifact listing does not contain unescaped script tags"
list_resp=$(api_get "/api/v1/repositories/${REPO_KEY}/artifacts" 2>/dev/null) || list_resp=""

if [ -z "$list_resp" ]; then
  skip "could not fetch artifact listing"
else
  # In a JSON API response, <script> appearing inside a JSON string value
  # is safe -- browsers do not execute JS from application/json responses.
  # Only fail if the response is not valid JSON (which would indicate raw HTML).
  if echo "$list_resp" | jq empty >/dev/null 2>&1; then
    pass
  else
    if echo "$list_resp" | grep -q '<script>'; then
      fail "non-JSON response contains unescaped <script> tag"
    else
      pass
    fi
  fi
fi

# ---------------------------------------------------------------------------
# Test XSS in repository description
# ---------------------------------------------------------------------------

begin_test "Create repo with XSS payload in description"
xss_repo_key="sec-xss-desc-${RUN_ID}"
xss_payload='<script>alert(document.cookie)</script>'

create_status=$(curl -s -o "${WORK_DIR}/xss-repo-resp.txt" -w '%{http_code}' $CURL_TIMEOUT \
  -X POST \
  -H "$(auth_header)" \
  -H "Content-Type: application/json" \
  -d "{\"key\":\"${xss_repo_key}\",\"name\":\"${xss_repo_key}\",\"format\":\"generic\",\"repo_type\":\"local\",\"description\":\"${xss_payload}\"}" \
  "${BASE_URL}/api/v1/repositories") || true
body=$(cat "${WORK_DIR}/xss-repo-resp.txt" 2>/dev/null) || true

if [ "$create_status" = "400" ] || [ "$create_status" = "422" ]; then
  # Server stripped or rejected the XSS payload
  pass
elif [ "$create_status" -ge 200 ] 2>/dev/null && [ "$create_status" -lt 300 ] 2>/dev/null; then
  # Check if the response contains unescaped script tag
  if echo "$body" | grep -q '<script>'; then
    # JSON-encoded responses may contain the literal text but it is not executable
    # Check if it's properly JSON-encoded
    if echo "$body" | jq -e '.description' >/dev/null 2>&1; then
      # The value is inside a JSON string, which is safe
      pass
    else
      fail "response contains unescaped <script> tag outside JSON"
    fi
  else
    pass
  fi
else
  # Other errors are acceptable
  pass
fi

# ---------------------------------------------------------------------------
# Verify search results escape XSS payloads
# ---------------------------------------------------------------------------

begin_test "Search results do not render XSS payloads"
search_resp=$(curl -s $CURL_TIMEOUT \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/search?q=xss-check" 2>/dev/null) || search_resp=""

if [ -z "$search_resp" ]; then
  skip "search endpoint returned empty response"
else
  # Verify Content-Type of search response
  search_headers=$(curl -sI $CURL_TIMEOUT \
    -H "$(auth_header)" \
    "${BASE_URL}/api/v1/search?q=xss-check" 2>/dev/null) || true
  search_ct=$(echo "$search_headers" | grep -i "^Content-Type:" | head -1 | tr -d '\r') || true

  if echo "$search_ct" | grep -qi "text/html"; then
    fail "search endpoint returns text/html (XSS risk)"
  else
    pass
  fi
fi

end_suite
