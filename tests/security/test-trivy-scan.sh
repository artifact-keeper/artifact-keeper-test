#!/usr/bin/env bash
# test-trivy-scan.sh - Trivy vulnerability scanning E2E test
#
# Creates a Docker/OCI repository, pushes a minimal OCI manifest, then polls
# the scan results API until Trivy completes (or times out). If the Trivy
# scanner is not enabled on the backend, the test is skipped.

source "$(dirname "$0")/../lib/common.sh"

begin_suite "trivy-scan"
auth_admin
setup_workdir

REPO_KEY="test-trivy-${RUN_ID}"
IMAGE_NAME="scan-target"
UNIQUE_TAG="1.0.$(date +%s)"
SCAN_TIMEOUT="${SCAN_TIMEOUT:-60}"

# ---------------------------------------------------------------------------
# Create OCI repository
# ---------------------------------------------------------------------------

begin_test "Create Docker/OCI repository"
if create_local_repo "$REPO_KEY" "docker"; then
  pass
else
  fail "could not create docker repository"
fi

# ---------------------------------------------------------------------------
# Obtain a registry token for V2 API calls
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# Upload a config blob
# ---------------------------------------------------------------------------

begin_test "Upload config blob"
CONFIG_CONTENT='{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":["sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]},"config":{}}'
CONFIG_DIGEST="sha256:$(printf '%s' "$CONFIG_CONTENT" | shasum -a 256 | awk '{print $1}')"
CONFIG_SIZE=${#CONFIG_CONTENT}

# Initiate upload
upload_resp=$(curl -s -D "$WORK_DIR/config-headers.txt" -o /dev/null \
  -X POST \
  -H "Authorization: Bearer $TOKEN" \
  "${BASE_URL}/v2/${REPO_KEY}/${IMAGE_NAME}/blobs/uploads/" 2>/dev/null) || true

location=$(grep -i '^location:' "$WORK_DIR/config-headers.txt" | tr -d '\r' | awk '{print $2}') || true
upload_status=$(grep -i '^HTTP/' "$WORK_DIR/config-headers.txt" | tail -1 | awk '{print $2}') || true

if [ "$upload_status" = "202" ] && [ -n "$location" ]; then
  if [[ "$location" == http* ]]; then
    put_url="${location}"
  else
    put_url="${BASE_URL}${location}"
  fi
  if [[ "$put_url" == *"?"* ]]; then
    put_url="${put_url}&digest=${CONFIG_DIGEST}"
  else
    put_url="${put_url}?digest=${CONFIG_DIGEST}"
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
    fail "config blob PUT returned ${put_status}, expected 201"
  fi
else
  fail "config blob upload initiation returned ${upload_status}, expected 202"
fi

# ---------------------------------------------------------------------------
# Upload a dummy layer blob
# ---------------------------------------------------------------------------

begin_test "Upload layer blob"
dd if=/dev/urandom bs=512 count=1 of="${WORK_DIR}/layer.bin" 2>/dev/null
LAYER_DIGEST="sha256:$(shasum -a 256 "${WORK_DIR}/layer.bin" | awk '{print $1}')"
LAYER_SIZE=$(wc -c < "${WORK_DIR}/layer.bin" | tr -d ' ')

layer_resp=$(curl -s -D "$WORK_DIR/layer-headers.txt" -o /dev/null \
  -X POST \
  -H "Authorization: Bearer $TOKEN" \
  "${BASE_URL}/v2/${REPO_KEY}/${IMAGE_NAME}/blobs/uploads/" 2>/dev/null) || true

layer_loc=$(grep -i '^location:' "$WORK_DIR/layer-headers.txt" | tr -d '\r' | awk '{print $2}') || true
layer_init_status=$(grep -i '^HTTP/' "$WORK_DIR/layer-headers.txt" | tail -1 | awk '{print $2}') || true

if [ "$layer_init_status" = "202" ] && [ -n "$layer_loc" ]; then
  if [[ "$layer_loc" == http* ]]; then
    layer_put_url="${layer_loc}"
  else
    layer_put_url="${BASE_URL}${layer_loc}"
  fi
  if [[ "$layer_put_url" == *"?"* ]]; then
    layer_put_url="${layer_put_url}&digest=${LAYER_DIGEST}"
  else
    layer_put_url="${layer_put_url}?digest=${LAYER_DIGEST}"
  fi

  layer_put_status=$(curl -s -o /dev/null -w '%{http_code}' \
    -X PUT \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/octet-stream" \
    --data-binary "@${WORK_DIR}/layer.bin" \
    "$layer_put_url") || true

  if [ "$layer_put_status" = "201" ]; then
    pass
  else
    fail "layer blob PUT returned ${layer_put_status}, expected 201"
  fi
else
  fail "layer blob upload initiation returned ${layer_init_status}, expected 202"
fi

# ---------------------------------------------------------------------------
# Push OCI manifest
# ---------------------------------------------------------------------------

begin_test "Push OCI manifest"
MANIFEST=$(cat <<EOFM
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "config": {
    "mediaType": "application/vnd.oci.image.config.v1+json",
    "digest": "${CONFIG_DIGEST}",
    "size": ${CONFIG_SIZE}
  },
  "layers": [
    {
      "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
      "digest": "${LAYER_DIGEST}",
      "size": ${LAYER_SIZE}
    }
  ]
}
EOFM
)

manifest_status=$(curl -s -o /dev/null -w '%{http_code}' \
  -X PUT \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/vnd.oci.image.manifest.v1+json" \
  -d "$MANIFEST" \
  "${BASE_URL}/v2/${REPO_KEY}/${IMAGE_NAME}/manifests/${UNIQUE_TAG}") || true

if [ "$manifest_status" = "201" ] || [ "$manifest_status" = "200" ]; then
  pass
else
  fail "manifest PUT returned ${manifest_status}, expected 201"
fi

# ---------------------------------------------------------------------------
# Poll for scan results
# ---------------------------------------------------------------------------

begin_test "Poll Trivy scan results"
SCAN_PATH="/api/v1/repositories/${REPO_KEY}/artifacts/${IMAGE_NAME}/${UNIQUE_TAG}/security/scan"
scan_ready=false
not_found_count=0
elapsed=0

while [ "$elapsed" -lt "$SCAN_TIMEOUT" ]; do
  scan_status=$(curl -s -o "$WORK_DIR/scan-resp.json" -w '%{http_code}' \
    -H "$(auth_header)" \
    -H "Accept: application/json" \
    "${BASE_URL}${SCAN_PATH}") || true

  if [ "$scan_status" = "200" ]; then
    scan_body=$(cat "$WORK_DIR/scan-resp.json")
    # Check if scan has completed (not still "pending" or "in_progress")
    scan_state=$(echo "$scan_body" | jq -r '.status // .state // "unknown"' 2>/dev/null) || true
    if [ "$scan_state" = "pending" ] || [ "$scan_state" = "in_progress" ] || [ "$scan_state" = "queued" ]; then
      echo "  scan status: ${scan_state}, waiting..."
      sleep 5
      elapsed=$((elapsed + 5))
      continue
    fi
    scan_ready=true
    break
  elif [ "$scan_status" = "404" ] || [ "$scan_status" = "503" ]; then
    not_found_count=$((not_found_count + 1))
    # If we consistently get 404/503, the scanner is likely not enabled
    if [ "$not_found_count" -ge 6 ]; then
      skip "Trivy scanning not enabled (scan endpoint returned ${scan_status} consistently)"
      scan_ready="skipped"
      break
    fi
    sleep 5
    elapsed=$((elapsed + 5))
    continue
  else
    echo "  scan endpoint returned ${scan_status}, retrying..."
    sleep 5
    elapsed=$((elapsed + 5))
  fi
done

if [ "$scan_ready" = "true" ]; then
  pass
elif [ "$scan_ready" != "skipped" ]; then
  fail "scan did not complete within ${SCAN_TIMEOUT}s"
fi

# ---------------------------------------------------------------------------
# Verify scan results contain vulnerability data
# ---------------------------------------------------------------------------

begin_test "Verify scan results structure"
if [ "$scan_ready" = "true" ]; then
  scan_body=$(cat "$WORK_DIR/scan-resp.json")
  found_vuln_field=false

  # Check for common vulnerability response fields
  for field in "vulnerabilities" "results" "findings" "matches" "report"; do
    if echo "$scan_body" | jq -e ".${field}" > /dev/null 2>&1; then
      found_vuln_field=true
      break
    fi
  done

  if $found_vuln_field; then
    pass
  else
    fail "scan response does not contain vulnerability data fields"
  fi
elif [ "$scan_ready" = "skipped" ]; then
  skip "Trivy scanning not enabled"
else
  skip "scan did not complete, cannot verify results"
fi

end_suite
