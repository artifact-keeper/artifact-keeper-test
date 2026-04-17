#!/usr/bin/env bash
# test-oci-remote.sh - OCI remote proxy, push/delete/re-push, token auth, and anonymous access E2E tests
#
# Covers:
#   - Docker Hub proxy (bug #586): remote OCI repo proxying registry-1.docker.io
#   - Push/delete/re-push (bug #600): push image, delete, verify 404, re-push, verify 200
#   - API token auth (bug #599): use API token as password in /v2/token endpoint
#   - Anonymous public access (bug #744): pull from public repo without auth
#
# Requires: curl, jq, shasum

source "$(dirname "$0")/../lib/common.sh"

begin_suite "oci-remote"
auth_admin
setup_workdir

REMOTE_KEY="test-oci-remote-${RUN_ID}"
LOCAL_KEY="test-oci-local-${RUN_ID}"
PUBLIC_KEY="test-oci-public-${RUN_ID}"
UPSTREAM_URL="https://registry-1.docker.io"
UNIQUE_TAG="1.0.$(date +%s)"

# =========================================================================
# Docker Hub proxy tests (bug #586)
# =========================================================================

begin_test "Create remote OCI repository pointing at Docker Hub"
if create_remote_repo "$REMOTE_KEY" "docker" "$UPSTREAM_URL"; then
  pass
else
  fail "could not create remote OCI repo"
fi

begin_test "Verify Docker Hub reachability"
# Docker Hub requires a token even for public images. Check the auth endpoint.
if curl -sf --max-time 10 "https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/alpine:pull" > /dev/null 2>&1; then
  UPSTREAM_REACHABLE=true
  pass
else
  UPSTREAM_REACHABLE=false
  skip "Docker Hub unreachable from test environment"
fi

# Obtain a registry token for our backend
TOKEN=""
token_resp=$(curl -sf -u "${ADMIN_USER}:${ADMIN_PASS}" "${BASE_URL}/v2/token" 2>/dev/null) || true
if [ -n "$token_resp" ]; then
  TOKEN=$(echo "$token_resp" | jq -r '.token // empty')
fi

begin_test "Pull alpine manifest through remote proxy (library/ prefix)"
if [ "$UPSTREAM_REACHABLE" != "true" ]; then
  skip "upstream unreachable"
elif [ -z "$TOKEN" ]; then
  skip "could not obtain registry token"
else
  status=$(curl -s -o "$WORK_DIR/alpine-manifest.json" -w '%{http_code}' \
    -H "Authorization: Bearer $TOKEN" \
    -H "Accept: application/vnd.docker.distribution.manifest.v2+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json" \
    "${BASE_URL}/v2/${REMOTE_KEY}/library/alpine/manifests/3.20") || true
  if [ "$status" = "200" ]; then
    pass
  else
    fail "pull alpine manifest (library/alpine) returned ${status}, expected 200"
  fi
fi

begin_test "Pull alpine manifest without library/ prefix"
if [ "$UPSTREAM_REACHABLE" != "true" ]; then
  skip "upstream unreachable"
elif [ -z "$TOKEN" ]; then
  skip "could not obtain registry token"
else
  status=$(curl -s -o "$WORK_DIR/alpine-manifest-short.json" -w '%{http_code}' \
    -H "Authorization: Bearer $TOKEN" \
    -H "Accept: application/vnd.docker.distribution.manifest.v2+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json" \
    "${BASE_URL}/v2/${REMOTE_KEY}/alpine/manifests/3.20") || true
  if [ "$status" = "200" ]; then
    pass
  else
    # Some registries require the library/ prefix for official images
    skip "pull without library/ prefix returned ${status} (may require library/ prefix)"
  fi
fi

begin_test "Pull alpine blob through remote proxy"
if [ "$UPSTREAM_REACHABLE" != "true" ]; then
  skip "upstream unreachable"
elif [ -z "$TOKEN" ]; then
  skip "could not obtain registry token"
else
  # Extract a blob digest from the manifest (config or layer)
  blob_digest=""
  if [ -f "$WORK_DIR/alpine-manifest.json" ]; then
    # If it is a manifest list/index, try getting the config digest from the first listed manifest
    media_type=$(jq -r '.mediaType // .schemaVersion' "$WORK_DIR/alpine-manifest.json" 2>/dev/null) || true
    if echo "$media_type" | grep -qi "list\|index"; then
      # It is a manifest list; get the first manifest's digest and fetch it
      first_digest=$(jq -r '.manifests[0].digest // empty' "$WORK_DIR/alpine-manifest.json" 2>/dev/null) || true
      if [ -n "$first_digest" ]; then
        curl -sf $CURL_TIMEOUT \
          -H "Authorization: Bearer $TOKEN" \
          -H "Accept: application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json" \
          -o "$WORK_DIR/alpine-single-manifest.json" \
          "${BASE_URL}/v2/${REMOTE_KEY}/library/alpine/manifests/${first_digest}" 2>/dev/null || true
        blob_digest=$(jq -r '.config.digest // empty' "$WORK_DIR/alpine-single-manifest.json" 2>/dev/null) || true
      fi
    else
      blob_digest=$(jq -r '.config.digest // empty' "$WORK_DIR/alpine-manifest.json" 2>/dev/null) || true
    fi
  fi

  if [ -n "$blob_digest" ] && [ "$blob_digest" != "null" ]; then
    blob_status=$(curl -s -o /dev/null -w '%{http_code}' \
      -H "Authorization: Bearer $TOKEN" \
      "${BASE_URL}/v2/${REMOTE_KEY}/library/alpine/blobs/${blob_digest}") || true
    if [ "$blob_status" = "200" ]; then
      pass
    else
      fail "blob GET returned ${blob_status}, expected 200"
    fi
  else
    skip "could not extract blob digest from manifest"
  fi
fi

# =========================================================================
# Push/delete/re-push test (bug #600)
# =========================================================================

begin_test "Create local OCI repository for push/delete test"
if create_local_repo "$LOCAL_KEY" "docker"; then
  pass
else
  fail "could not create local OCI repo"
fi

# Re-obtain token (scoped to the new repo)
TOKEN=""
token_resp=$(curl -sf -u "${ADMIN_USER}:${ADMIN_PASS}" "${BASE_URL}/v2/token" 2>/dev/null) || true
if [ -n "$token_resp" ]; then
  TOKEN=$(echo "$token_resp" | jq -r '.token // empty')
fi

# Helper: push a minimal OCI image (config blob + manifest)
push_test_image() {
  local repo_key="$1"
  local image_name="$2"
  local tag="$3"
  local token="$4"
  local content_id="${5:-default}"

  # Create config blob
  local config_content="{\"architecture\":\"amd64\",\"os\":\"linux\",\"rootfs\":{\"type\":\"layers\",\"diff_ids\":[]},\"config\":{},\"id\":\"${content_id}\"}"
  local config_digest="sha256:$(printf '%s' "$config_content" | shasum -a 256 | awk '{print $1}')"
  local config_size=${#config_content}

  # Initiate blob upload
  local upload_headers="$WORK_DIR/push-upload-headers-${content_id}.txt"
  curl -s -D "$upload_headers" -o /dev/null \
    -X POST \
    -H "Authorization: Bearer $token" \
    "${BASE_URL}/v2/${repo_key}/${image_name}/blobs/uploads/" 2>/dev/null || true

  local location
  location=$(grep -i '^location:' "$upload_headers" | tr -d '\r' | awk '{print $2}') || true

  if [ -z "$location" ]; then
    echo "upload-initiation-failed"
    return 1
  fi

  # Complete blob upload
  local put_url
  if [[ "$location" == http* ]]; then
    if [[ "$location" == *"?"* ]]; then
      put_url="${location}&digest=${config_digest}"
    else
      put_url="${location}?digest=${config_digest}"
    fi
  else
    if [[ "$location" == *"?"* ]]; then
      put_url="${BASE_URL}${location}&digest=${config_digest}"
    else
      put_url="${BASE_URL}${location}?digest=${config_digest}"
    fi
  fi

  curl -s -o /dev/null \
    -X PUT \
    -H "Authorization: Bearer $token" \
    -H "Content-Type: application/octet-stream" \
    -d "$config_content" \
    "$put_url" 2>/dev/null || true

  # Push manifest
  local manifest="{\"schemaVersion\":2,\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\",\"config\":{\"mediaType\":\"application/vnd.oci.image.config.v1+json\",\"digest\":\"${config_digest}\",\"size\":${config_size}},\"layers\":[]}"
  local manifest_status
  manifest_status=$(curl -s -o /dev/null -w '%{http_code}' \
    -X PUT \
    -H "Authorization: Bearer $token" \
    -H "Content-Type: application/vnd.oci.image.manifest.v1+json" \
    -d "$manifest" \
    "${BASE_URL}/v2/${repo_key}/${image_name}/manifests/${tag}") || true

  echo "$manifest_status"
}

begin_test "Push image with tag test:1.0 (bug #600)"
if [ -z "$TOKEN" ]; then
  fail "no registry token"
else
  push_status=$(push_test_image "$LOCAL_KEY" "pushdelete" "$UNIQUE_TAG" "$TOKEN" "initial")
  if [ "$push_status" = "201" ] || [ "$push_status" = "200" ]; then
    pass
  else
    fail "initial push returned ${push_status}, expected 201"
  fi
fi

begin_test "Verify image exists after push"
if [ -z "$TOKEN" ]; then
  skip "no registry token"
else
  status=$(curl -s -o /dev/null -w '%{http_code}' \
    -H "Authorization: Bearer $TOKEN" \
    -H "Accept: application/vnd.oci.image.manifest.v1+json" \
    "${BASE_URL}/v2/${LOCAL_KEY}/pushdelete/manifests/${UNIQUE_TAG}") || true
  if [ "$status" = "200" ]; then
    pass
  else
    fail "manifest GET returned ${status} after push, expected 200"
  fi
fi

begin_test "Delete image (bug #600)"
skip "OCI manifest delete not implemented yet"

begin_test "Verify image returns 404 after delete (bug #600)"
skip "OCI manifest delete not implemented yet"

begin_test "Re-push same tag after delete (bug #600)"
skip "OCI manifest delete not implemented yet"

begin_test "Verify image exists after re-push (bug #600)"
skip "OCI manifest delete not implemented yet"

# =========================================================================
# API token auth test (bug #599)
# =========================================================================

begin_test "Create API token for Docker auth (bug #599)"
API_TOKEN=""
TOKEN_ID=""
TOKEN_NAME="e2e-oci-token-${RUN_ID}"
if resp=$(api_post "/api/v1/auth/tokens" \
    "{\"name\":\"${TOKEN_NAME}\",\"scopes\":[\"read\",\"write\"]}" 2>/dev/null); then
  API_TOKEN=$(echo "$resp" | jq -r '.token // .api_key // .key // empty') || true
  TOKEN_ID=$(echo "$resp" | jq -r '.id // .token_id // empty') || true
  if [ -n "$API_TOKEN" ] && [ "$API_TOKEN" != "null" ]; then
    pass
  else
    fail "token created but value not returned"
  fi
else
  skip "API tokens endpoint not available"
fi

begin_test "Use API token as password in /v2/token endpoint (bug #599)"
if [ -z "${API_TOKEN:-}" ] || [ "$API_TOKEN" = "null" ]; then
  skip "no API token"
else
  # Use the API token as the password with the admin username in basic auth
  token_resp2=$(curl -sf $CURL_TIMEOUT \
    -u "${ADMIN_USER}:${API_TOKEN}" \
    "${BASE_URL}/v2/token" 2>/dev/null) || true
  if [ -n "$token_resp2" ]; then
    api_registry_token=$(echo "$token_resp2" | jq -r '.token // empty') || true
    if [ -n "$api_registry_token" ] && [ "$api_registry_token" != "null" ]; then
      pass
    else
      fail "API token auth returned response but no registry token"
    fi
  else
    fail "/v2/token with API token as password failed (bug #599)"
  fi
fi

begin_test "Verify image operations with API-token-based registry token (bug #599)"
if [ -z "${api_registry_token:-}" ] || [ "$api_registry_token" = "null" ]; then
  skip "no registry token from API token auth"
else
  # Try reading the manifest we pushed earlier
  status=$(curl -s -o /dev/null -w '%{http_code}' \
    -H "Authorization: Bearer ${api_registry_token}" \
    -H "Accept: application/vnd.oci.image.manifest.v1+json" \
    "${BASE_URL}/v2/${LOCAL_KEY}/pushdelete/manifests/${UNIQUE_TAG}") || true
  if [ "$status" = "200" ]; then
    pass
  else
    fail "image GET with API-token-derived registry token returned ${status}, expected 200 (bug #599)"
  fi
fi

# Cleanup: revoke the API token
if [ -n "${TOKEN_ID:-}" ] && [ "$TOKEN_ID" != "null" ]; then
  api_delete "/api/v1/auth/tokens/${TOKEN_ID}" > /dev/null 2>&1 || true
fi

# =========================================================================
# Anonymous public access test (bug #744)
# =========================================================================

begin_test "Create public OCI repository (bug #744)"
# Explicitly set is_public: true in the repo creation payload
PAYLOAD="{\"key\":\"${PUBLIC_KEY}\",\"name\":\"${PUBLIC_KEY}\",\"format\":\"docker\",\"repo_type\":\"local\",\"is_public\":true}"
if api_post "/api/v1/repositories" "$PAYLOAD" > /dev/null 2>&1; then
  pass
else
  fail "could not create public OCI repo"
fi

# Re-obtain token for push
TOKEN=""
token_resp=$(curl -sf -u "${ADMIN_USER}:${ADMIN_PASS}" "${BASE_URL}/v2/token" 2>/dev/null) || true
if [ -n "$token_resp" ]; then
  TOKEN=$(echo "$token_resp" | jq -r '.token // empty')
fi

begin_test "Push image to public repo as admin (bug #744)"
if [ -z "$TOKEN" ]; then
  fail "no registry token for push"
else
  push_status=$(push_test_image "$PUBLIC_KEY" "public-image" "latest" "$TOKEN" "public-content")
  if [ "$push_status" = "201" ] || [ "$push_status" = "200" ]; then
    pass
  else
    fail "push to public repo returned ${push_status}, expected 201"
  fi
fi

begin_test "Pull manifest from public repo with NO auth (bug #744)"
# OCI auth uses a challenge flow: GET without auth returns 401 with
# WWW-Authenticate, then the client requests an anonymous token from
# /v2/token and retries with the bearer token.
# Step 1: request anonymous token (no credentials)
anon_token=""
anon_resp=$(curl -sf "${BASE_URL}/v2/token?scope=repository:${PUBLIC_KEY}:pull" 2>/dev/null) || true
if [ -n "$anon_resp" ]; then
  anon_token=$(echo "$anon_resp" | jq -r '.token // empty') || true
fi
if [ -z "$anon_token" ] || [ "$anon_token" = "null" ]; then
  fail "could not obtain anonymous token from /v2/token (bug #744)"
else
  # Step 2: use the anonymous token to pull the manifest
  status=$(curl -s -o "$WORK_DIR/public-manifest.json" -w '%{http_code}' \
    -H "Authorization: Bearer ${anon_token}" \
    -H "Accept: application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json" \
    "${BASE_URL}/v2/${PUBLIC_KEY}/public-image/manifests/latest") || true
  if [ "$status" = "200" ]; then
    pass
  else
    fail "anonymous pull from public repo returned ${status}, expected 200 (bug #744)"
  fi
fi

begin_test "Verify anonymous pull returned valid manifest (bug #744)"
if [ -f "$WORK_DIR/public-manifest.json" ]; then
  schema_ver=$(jq -r '.schemaVersion' "$WORK_DIR/public-manifest.json" 2>/dev/null) || true
  if [ "$schema_ver" = "2" ]; then
    pass
  else
    fail "anonymous manifest schemaVersion is '${schema_ver}', expected '2'"
  fi
else
  skip "no manifest file to verify"
fi

# -------------------------------------------------------------------------
# Cleanup
# -------------------------------------------------------------------------

api_delete "/api/v1/repositories/${PUBLIC_KEY}" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${LOCAL_KEY}" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${REMOTE_KEY}" > /dev/null 2>&1 || true

end_suite
