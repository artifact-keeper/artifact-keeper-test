#!/usr/bin/env bash
# test-oci-auth-scope.sh - Regression tests for OCI auth scope in WWW-Authenticate
#
# Covers bug #821:
#   1. WWW-Authenticate challenge was missing the `scope` parameter, which
#      caused Docker token cache misses and repeated auth round-trips.
#   2. Only /v2/ accepted Basic auth directly; all other OCI endpoints
#      required Bearer tokens, breaking clients that send Basic credentials
#      on every request.
#
# These tests exercise the OCI Distribution /v2/ endpoints with curl,
# verifying that unauthenticated requests return 401 with the correct
# WWW-Authenticate header (including scope), and that Basic auth is
# accepted on all OCI endpoints (not just /v2/).

source "$(dirname "$0")/../lib/common.sh"

begin_suite "oci-auth-scope"
auth_admin
setup_workdir

REPO_KEY="test-oci-auth-${RUN_ID}"
IMAGE_NAME="scope-test"
FAKE_DIGEST="sha256:$(printf 'nonexistent-blob' | shasum -a 256 | awk '{print $1}')"
BASIC_AUTH=$(printf '%s:%s' "$ADMIN_USER" "$ADMIN_PASS" | base64)
BAD_BASIC_AUTH=$(printf '%s:%s' "$ADMIN_USER" "wrong-password-definitely" | base64)

# ---------------------------------------------------------------------------
# Helper: fetch response headers into a file and return the status code
# ---------------------------------------------------------------------------
fetch_headers() {
  local method="$1"
  local url="$2"
  local header_file="$3"
  shift 3

  curl -s -o /dev/null -D "$header_file" -w '%{http_code}' \
    $CURL_TIMEOUT -X "$method" "$@" "$url" || true
}

# Helper: extract WWW-Authenticate header value (case-insensitive)
get_www_authenticate() {
  local header_file="$1"
  grep -i '^www-authenticate:' "$header_file" | head -1 | sed 's/^[^:]*: *//' | tr -d '\r'
}

# ---------------------------------------------------------------------------
# 1. Create OCI repository
# ---------------------------------------------------------------------------
begin_test "Create OCI/Docker repository"
if create_local_repo "$REPO_KEY" "docker"; then
  pass
else
  fail "could not create docker repository"
fi

# ---------------------------------------------------------------------------
# 2. GET /v2/ returns 401 with WWW-Authenticate containing realm and service
# ---------------------------------------------------------------------------
begin_test "GET /v2/ unauthenticated returns 401 with realm and service"
status=$(fetch_headers GET "${BASE_URL}/v2/" "$WORK_DIR/v2-headers.txt")
if [ "$status" != "401" ]; then
  fail "GET /v2/ returned ${status}, expected 401"
else
  www_auth=$(get_www_authenticate "$WORK_DIR/v2-headers.txt")
  if [ -z "$www_auth" ]; then
    fail "GET /v2/ 401 response missing WWW-Authenticate header"
  elif ! echo "$www_auth" | grep -qi 'realm='; then
    fail "WWW-Authenticate missing realm parameter: ${www_auth}"
  elif ! echo "$www_auth" | grep -qi 'service='; then
    fail "WWW-Authenticate missing service parameter: ${www_auth}"
  else
    pass
  fi
fi

# ---------------------------------------------------------------------------
# 3. HEAD /v2/{name}/blobs/{digest} returns 401 with scope=repository:{name}:pull
# ---------------------------------------------------------------------------
begin_test "HEAD blob returns 401 with scope containing pull"
status=$(fetch_headers HEAD \
  "${BASE_URL}/v2/${REPO_KEY}/${IMAGE_NAME}/blobs/${FAKE_DIGEST}" \
  "$WORK_DIR/blob-head-headers.txt")
if [ "$status" != "401" ]; then
  fail "HEAD blob returned ${status}, expected 401"
else
  www_auth=$(get_www_authenticate "$WORK_DIR/blob-head-headers.txt")
  if [ -z "$www_auth" ]; then
    fail "HEAD blob 401 response missing WWW-Authenticate header"
  elif ! echo "$www_auth" | grep -q "scope="; then
    fail "WWW-Authenticate missing scope parameter: ${www_auth}"
  elif ! echo "$www_auth" | grep -q "repository:${REPO_KEY}/${IMAGE_NAME}:pull"; then
    fail "scope does not contain repository:${REPO_KEY}/${IMAGE_NAME}:pull -- got: ${www_auth}"
  else
    pass
  fi
fi

# ---------------------------------------------------------------------------
# 4. PUT /v2/{name}/manifests/{tag} returns 401 with scope containing pull,push
# ---------------------------------------------------------------------------
begin_test "PUT manifest returns 401 with scope containing pull,push"
status=$(fetch_headers PUT \
  "${BASE_URL}/v2/${REPO_KEY}/${IMAGE_NAME}/manifests/latest" \
  "$WORK_DIR/manifest-put-headers.txt" \
  -H "Content-Type: application/vnd.oci.image.manifest.v1+json" \
  -d '{}')
if [ "$status" != "401" ]; then
  fail "PUT manifest returned ${status}, expected 401"
else
  www_auth=$(get_www_authenticate "$WORK_DIR/manifest-put-headers.txt")
  if [ -z "$www_auth" ]; then
    fail "PUT manifest 401 response missing WWW-Authenticate header"
  elif ! echo "$www_auth" | grep -q "scope="; then
    fail "WWW-Authenticate missing scope parameter: ${www_auth}"
  elif ! echo "$www_auth" | grep -q "pull,push"; then
    fail "scope does not contain pull,push -- got: ${www_auth}"
  else
    pass
  fi
fi

# ---------------------------------------------------------------------------
# 5. GET /v2/{name}/tags/list returns 401 with scope containing pull
# ---------------------------------------------------------------------------
begin_test "GET tags/list returns 401 with scope containing pull"
status=$(fetch_headers GET \
  "${BASE_URL}/v2/${REPO_KEY}/${IMAGE_NAME}/tags/list" \
  "$WORK_DIR/tags-headers.txt")
if [ "$status" != "401" ]; then
  fail "GET tags/list returned ${status}, expected 401"
else
  www_auth=$(get_www_authenticate "$WORK_DIR/tags-headers.txt")
  if [ -z "$www_auth" ]; then
    fail "GET tags/list 401 response missing WWW-Authenticate header"
  elif ! echo "$www_auth" | grep -q "scope="; then
    fail "WWW-Authenticate missing scope parameter: ${www_auth}"
  elif ! echo "$www_auth" | grep -q "repository:${REPO_KEY}/${IMAGE_NAME}:pull"; then
    fail "scope does not contain repository:${REPO_KEY}/${IMAGE_NAME}:pull -- got: ${www_auth}"
  else
    pass
  fi
fi

# ---------------------------------------------------------------------------
# 6. POST /v2/{name}/blobs/uploads/ returns 401 with scope containing pull,push
# ---------------------------------------------------------------------------
begin_test "POST blob upload returns 401 with scope containing pull,push"
status=$(fetch_headers POST \
  "${BASE_URL}/v2/${REPO_KEY}/${IMAGE_NAME}/blobs/uploads/" \
  "$WORK_DIR/upload-headers.txt")
if [ "$status" != "401" ]; then
  fail "POST blob upload returned ${status}, expected 401"
else
  www_auth=$(get_www_authenticate "$WORK_DIR/upload-headers.txt")
  if [ -z "$www_auth" ]; then
    fail "POST blob upload 401 response missing WWW-Authenticate header"
  elif ! echo "$www_auth" | grep -q "scope="; then
    fail "WWW-Authenticate missing scope parameter: ${www_auth}"
  elif ! echo "$www_auth" | grep -q "pull,push"; then
    fail "scope does not contain pull,push -- got: ${www_auth}"
  else
    pass
  fi
fi

# ---------------------------------------------------------------------------
# 7. Basic auth works on blob HEAD (should get 404, not 401)
# ---------------------------------------------------------------------------
begin_test "Basic auth accepted on blob HEAD endpoint"
status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -I \
  -H "Authorization: Basic ${BASIC_AUTH}" \
  "${BASE_URL}/v2/${REPO_KEY}/${IMAGE_NAME}/blobs/${FAKE_DIGEST}") || true
if [ "$status" = "401" ]; then
  fail "blob HEAD with Basic auth returned 401, Basic auth not accepted on blob endpoint"
elif [ "$status" = "404" ] || [ "$status" = "200" ]; then
  # 404 is expected for a non-existent blob, 200 if it somehow exists
  pass
else
  fail "blob HEAD with Basic auth returned unexpected ${status}, expected 404"
fi

# ---------------------------------------------------------------------------
# 8. Basic auth works on manifest PUT (should pass auth even if body is invalid)
# ---------------------------------------------------------------------------
begin_test "Basic auth accepted on manifest PUT endpoint"
status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X PUT \
  -H "Authorization: Basic ${BASIC_AUTH}" \
  -H "Content-Type: application/vnd.oci.image.manifest.v1+json" \
  -d '{"schemaVersion":2}' \
  "${BASE_URL}/v2/${REPO_KEY}/${IMAGE_NAME}/manifests/basic-auth-test") || true
if [ "$status" = "401" ]; then
  fail "manifest PUT with Basic auth returned 401, Basic auth not accepted on manifest endpoint"
else
  # Any non-401 status means Basic auth was accepted. The request may fail for
  # other reasons (400, 404, etc.) because the manifest body is incomplete,
  # but auth itself succeeded.
  pass
fi

# ---------------------------------------------------------------------------
# 9. Basic auth works on tags list
# ---------------------------------------------------------------------------
begin_test "Basic auth accepted on tags list endpoint"
status=$(curl -s -o "$WORK_DIR/tags-basic.json" -w '%{http_code}' $CURL_TIMEOUT \
  -H "Authorization: Basic ${BASIC_AUTH}" \
  "${BASE_URL}/v2/${REPO_KEY}/${IMAGE_NAME}/tags/list") || true
if [ "$status" = "401" ]; then
  fail "tags/list with Basic auth returned 401, Basic auth not accepted on tags endpoint"
elif [ "$status" = "200" ] || [ "$status" = "404" ]; then
  # 200 with a tags response, or 404 if the image has no tags yet
  pass
else
  fail "tags/list with Basic auth returned unexpected ${status}, expected 200 or 404"
fi

# ---------------------------------------------------------------------------
# 10. Token exchange flow: obtain token via /v2/token, use on blob endpoint
# ---------------------------------------------------------------------------
begin_test "Token exchange flow works for blob endpoints"
token_resp=$(curl -sf $CURL_TIMEOUT \
  -u "${ADMIN_USER}:${ADMIN_PASS}" \
  "${BASE_URL}/v2/token?service=artifact-keeper&scope=repository:${REPO_KEY}/${IMAGE_NAME}:pull" \
  2>/dev/null) || true
if [ -z "$token_resp" ]; then
  fail "token endpoint returned empty response"
else
  v2_token=$(echo "$token_resp" | jq -r '.token // .access_token // empty')
  if [ -z "$v2_token" ]; then
    fail "token response did not contain a token"
  else
    # Use the token to HEAD a blob. Expect 404 (blob does not exist), not 401.
    bearer_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
      -I \
      -H "Authorization: Bearer ${v2_token}" \
      "${BASE_URL}/v2/${REPO_KEY}/${IMAGE_NAME}/blobs/${FAKE_DIGEST}") || true
    if [ "$bearer_status" = "401" ]; then
      fail "bearer token from /v2/token rejected on blob HEAD (got 401)"
    elif [ "$bearer_status" = "404" ] || [ "$bearer_status" = "200" ]; then
      pass
    else
      fail "blob HEAD with exchanged token returned unexpected ${bearer_status}"
    fi
  fi
fi

# ---------------------------------------------------------------------------
# 11. Invalid Basic auth returns 401
# ---------------------------------------------------------------------------
begin_test "Invalid Basic auth credentials return 401"
status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -H "Authorization: Basic ${BAD_BASIC_AUTH}" \
  "${BASE_URL}/v2/${REPO_KEY}/${IMAGE_NAME}/tags/list") || true
if [ "$status" = "401" ]; then
  pass
else
  fail "invalid Basic auth returned ${status}, expected 401"
fi

# ---------------------------------------------------------------------------
# 12. Cleanup
# ---------------------------------------------------------------------------
begin_test "Cleanup test repository"
if api_delete "/api/v1/repositories/${REPO_KEY}" > /dev/null 2>&1; then
  pass
else
  # Cleanup failure is not critical; pass anyway to not mask real test results
  pass
fi

end_suite
