#!/usr/bin/env bash
# test-oci.sh - OCI Distribution API E2E test
#
# If docker is available: build a minimal image, push and pull via the /v2/
# registry endpoint. Otherwise, fall back to curl-based OCI distribution API
# simulation (upload a blob and manifest directly).
#
# The OCI registry lives at the root /v2/ path, not under a format prefix.

source "$(dirname "$0")/../lib/common.sh"

begin_suite "oci"
auth_admin
setup_workdir

REPO_KEY="test-oci-${RUN_ID}"
UNIQUE_TAG="1.0.$(date +%s)"

# Create a Docker/OCI repository via the management API
begin_test "Create OCI repository"
if create_local_repo "$REPO_KEY" "docker"; then
  pass
else
  fail "could not create docker repository"
fi

# ---------------------------------------------------------------------------
# Determine whether to use docker or curl
# ---------------------------------------------------------------------------
USE_DOCKER=false
if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
  USE_DOCKER=true
fi

# We need a registry host:port (without http://) for docker commands.
# Strip the scheme from BASE_URL.
REGISTRY_HOST="${BASE_URL#http://}"
REGISTRY_HOST="${REGISTRY_HOST#https://}"

if $USE_DOCKER; then
  # -----------------------------------------------------------------------
  # Docker-based tests
  # -----------------------------------------------------------------------

  begin_test "Docker login"
  if echo "$ADMIN_PASS" | docker login "$REGISTRY_HOST" -u "$ADMIN_USER" --password-stdin 2>/dev/null; then
    pass
  else
    fail "docker login failed"
  fi

  begin_test "Build and push image"
  cat > "$WORK_DIR/Dockerfile" <<EOF
FROM scratch
COPY hello.txt /hello.txt
EOF
  echo "oci-e2e-test ${UNIQUE_TAG}" > "$WORK_DIR/hello.txt"
  IMAGE_NAME="${REGISTRY_HOST}/${REPO_KEY}/e2e-test:${UNIQUE_TAG}"
  if docker build -t "$IMAGE_NAME" "$WORK_DIR" -q >/dev/null 2>&1 \
     && docker push "$IMAGE_NAME" >/dev/null 2>&1; then
    pass
  else
    fail "docker build+push failed"
  fi

  begin_test "Verify manifest via API"
  # Obtain a registry token for V2 API calls
  TOKEN=$(curl -sf -u "${ADMIN_USER}:${ADMIN_PASS}" "${BASE_URL}/v2/token" | jq -r '.token // empty') || true
  if [ -n "$TOKEN" ]; then
    status=$(curl -s -o /dev/null -w '%{http_code}' \
      -H "Authorization: Bearer $TOKEN" \
      -H "Accept: application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json" \
      "${BASE_URL}/v2/${REPO_KEY}/e2e-test/manifests/${UNIQUE_TAG}") || true
    if [ "$status" = "200" ]; then
      pass
    else
      fail "manifest GET returned ${status}, expected 200"
    fi
  else
    # Try with bearer token from auth_admin
    if assert_http_ok "/v2/${REPO_KEY}/e2e-test/manifests/${UNIQUE_TAG}"; then
      pass
    else
      fail "could not verify manifest"
    fi
  fi

  begin_test "Pull image"
  docker rmi "$IMAGE_NAME" 2>/dev/null || true
  if docker pull "$IMAGE_NAME" >/dev/null 2>&1; then
    pass
  else
    fail "docker pull failed"
  fi

  # Cleanup
  docker rmi "$IMAGE_NAME" 2>/dev/null || true
  docker logout "$REGISTRY_HOST" 2>/dev/null || true

else
  # -----------------------------------------------------------------------
  # Curl-based OCI distribution simulation
  # -----------------------------------------------------------------------

  begin_test "V2 version check (unauthenticated returns 401)"
  status=$(curl -s -o /dev/null -w '%{http_code}' "${BASE_URL}/v2/") || true
  if [ "$status" = "401" ]; then
    pass
  else
    fail "GET /v2/ returned ${status}, expected 401"
  fi

  begin_test "Obtain registry token"
  TOKEN=""
  token_resp=$(curl -sf -u "${ADMIN_USER}:${ADMIN_PASS}" "${BASE_URL}/v2/token" 2>/dev/null) || true
  if [ -n "$token_resp" ]; then
    TOKEN=$(echo "$token_resp" | jq -r '.token // empty')
  fi
  if [ -n "$TOKEN" ]; then
    pass
  else
    fail "could not obtain registry token"
  fi

  begin_test "V2 version check (authenticated returns 200)"
  status=$(curl -s -o /dev/null -w '%{http_code}' \
    -H "Authorization: Bearer $TOKEN" "${BASE_URL}/v2/") || true
  if [ "$status" = "200" ]; then
    pass
  else
    fail "authenticated GET /v2/ returned ${status}, expected 200"
  fi

  begin_test "Upload blob via chunked upload"
  # Create a small config blob
  CONFIG_CONTENT='{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]},"config":{}}'
  CONFIG_DIGEST="sha256:$(printf '%s' "$CONFIG_CONTENT" | shasum -a 256 | awk '{print $1}')"
  CONFIG_SIZE=${#CONFIG_CONTENT}

  # Initiate upload
  upload_url=$(curl -s -D "$WORK_DIR/upload-headers.txt" -o /dev/null \
    -X POST \
    -H "Authorization: Bearer $TOKEN" \
    "${BASE_URL}/v2/${REPO_KEY}/e2e-test/blobs/uploads/" 2>/dev/null) || true

  location=$(grep -i '^location:' "$WORK_DIR/upload-headers.txt" | tr -d '\r' | awk '{print $2}') || true
  upload_status=$(grep -i '^HTTP/' "$WORK_DIR/upload-headers.txt" | tail -1 | awk '{print $2}') || true

  if [ "$upload_status" = "202" ] && [ -n "$location" ]; then
    # Complete the upload with the digest
    # Handle relative vs absolute location
    if [[ "$location" == http* ]]; then
      put_url="${location}&digest=${CONFIG_DIGEST}"
    else
      put_url="${BASE_URL}${location}&digest=${CONFIG_DIGEST}"
    fi
    # Add ? if no query string yet
    if [[ "$location" != *"?"* ]]; then
      if [[ "$location" == http* ]]; then
        put_url="${location}?digest=${CONFIG_DIGEST}"
      else
        put_url="${BASE_URL}${location}?digest=${CONFIG_DIGEST}"
      fi
    fi

    put_status=$(curl -s -o /dev/null -w '%{http_code}' \
      -X PUT \
      -H "Authorization: Bearer $TOKEN" \
      -H "Content-Type: application/octet-stream" \
      -d "$CONFIG_CONTENT" \
      "$put_url") || true

    if [ "$put_status" = "201" ]; then
      pass
    else
      fail "blob PUT returned ${put_status}, expected 201"
    fi
  else
    fail "blob upload initiation returned ${upload_status}, expected 202"
  fi

  begin_test "Upload manifest"
  MANIFEST=$(cat <<EOFM
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "config": {
    "mediaType": "application/vnd.oci.image.config.v1+json",
    "digest": "${CONFIG_DIGEST}",
    "size": ${CONFIG_SIZE}
  },
  "layers": []
}
EOFM
  )

  manifest_status=$(curl -s -o /dev/null -w '%{http_code}' \
    -X PUT \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/vnd.oci.image.manifest.v1+json" \
    -d "$MANIFEST" \
    "${BASE_URL}/v2/${REPO_KEY}/e2e-test/manifests/${UNIQUE_TAG}") || true

  if [ "$manifest_status" = "201" ] || [ "$manifest_status" = "200" ]; then
    pass
  else
    fail "manifest PUT returned ${manifest_status}, expected 201"
  fi

  begin_test "Retrieve manifest"
  resp_status=$(curl -s -o "$WORK_DIR/manifest-out.json" -w '%{http_code}' \
    -H "Authorization: Bearer $TOKEN" \
    -H "Accept: application/vnd.oci.image.manifest.v1+json" \
    "${BASE_URL}/v2/${REPO_KEY}/e2e-test/manifests/${UNIQUE_TAG}") || true

  if [ "$resp_status" = "200" ]; then
    schema_ver=$(jq -r '.schemaVersion' "$WORK_DIR/manifest-out.json" 2>/dev/null) || true
    if [ "$schema_ver" = "2" ]; then
      pass
    else
      fail "manifest schemaVersion is '${schema_ver}', expected '2'"
    fi
  else
    fail "manifest GET returned ${resp_status}, expected 200"
  fi

  begin_test "Non-existent manifest returns 404"
  not_found=$(curl -s -o /dev/null -w '%{http_code}' \
    -H "Authorization: Bearer $TOKEN" \
    "${BASE_URL}/v2/${REPO_KEY}/no-such-image/manifests/notreal") || true
  if [ "$not_found" = "404" ]; then
    pass
  else
    fail "non-existent manifest returned ${not_found}, expected 404"
  fi
fi

end_suite
