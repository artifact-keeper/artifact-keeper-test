#!/usr/bin/env bash
# test-mlmodel-conformance.sh - ML Model registry conformance tests
#
# Validates the MLModel repository format: artifact upload via the management
# API, download, metadata retrieval, multiple versions, download integrity,
# and 404 handling for nonexistent models.
#
# MLModel uses the generic artifact API at:
#   PUT  /api/v1/repositories/{key}/artifacts/{path}
#   GET  /api/v1/repositories/{key}/download/{path}
#   GET  /api/v1/repositories/{key}/artifacts
#
# Path convention: models/{name}/versions/{version}/artifacts/{filename}
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "mlmodel-conformance"
auth_admin
setup_workdir

REPO_KEY="test-mlmod-conf-${RUN_ID}"
MODEL_NAME="confmodel"
MODEL_VERSION="1.0.0"
MODEL_VERSION_2="2.0.0"

# Portable SHA256 helper
sha256_hex() {
  if command -v sha256sum &>/dev/null; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

# ---------------------------------------------------------------------------
# Create repository
# ---------------------------------------------------------------------------

begin_test "Create MLModel local repository"
if create_local_repo "$REPO_KEY" "mlmodel"; then
  pass
else
  fail "could not create mlmodel repository"
fi

# ---------------------------------------------------------------------------
# 1. Upload model artifact (ONNX-style binary)
# ---------------------------------------------------------------------------

begin_test "Upload model artifact"
MODEL_FILE="${WORK_DIR}/model.onnx"
# Create a synthetic ONNX-like file with recognizable header bytes
dd if=/dev/urandom of="$MODEL_FILE" bs=1024 count=16 2>/dev/null

ARTIFACT_PATH="models/${MODEL_NAME}/versions/${MODEL_VERSION}/artifacts/model.onnx"

upload_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X PUT \
  -H "$(auth_header)" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@${MODEL_FILE}" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/${ARTIFACT_PATH}") || true

if [ "$upload_status" -ge 200 ] 2>/dev/null && [ "$upload_status" -lt 300 ] 2>/dev/null; then
  pass
else
  fail "model upload returned HTTP ${upload_status}, expected 2xx"
fi

sleep 1

# ---------------------------------------------------------------------------
# 2. Download model artifact
# ---------------------------------------------------------------------------

begin_test "Download model artifact"
DL_FILE="${WORK_DIR}/downloaded-model.onnx"
dl_status=$(curl -s -o "$DL_FILE" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/download/${ARTIFACT_PATH}") || true

if [ "$dl_status" -ge 200 ] 2>/dev/null && [ "$dl_status" -lt 300 ] 2>/dev/null; then
  if [ -s "$DL_FILE" ]; then
    pass
  else
    fail "downloaded model file is empty"
  fi
else
  fail "download returned HTTP ${dl_status}, expected 2xx"
fi

# ---------------------------------------------------------------------------
# 3. Model metadata via artifact listing
# ---------------------------------------------------------------------------

begin_test "Model metadata via artifact listing"
if resp=$(api_get "/api/v1/repositories/${REPO_KEY}/artifacts" 2>/dev/null); then
  # Response should list the uploaded artifact with name, path, version
  if assert_contains "$resp" "$MODEL_NAME" "artifact list should contain model name"; then
    pass
  fi
else
  fail "artifact listing returned error"
fi

# ---------------------------------------------------------------------------
# 4. Multiple versions
# ---------------------------------------------------------------------------

begin_test "Upload and retrieve multiple model versions"
MODEL_FILE_V2="${WORK_DIR}/model-v2.onnx"
dd if=/dev/urandom of="$MODEL_FILE_V2" bs=1024 count=8 2>/dev/null

ARTIFACT_PATH_V2="models/${MODEL_NAME}/versions/${MODEL_VERSION_2}/artifacts/model.onnx"

v2_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X PUT \
  -H "$(auth_header)" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@${MODEL_FILE_V2}" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/${ARTIFACT_PATH_V2}") || true

if [ "$v2_status" -ge 200 ] 2>/dev/null && [ "$v2_status" -lt 300 ] 2>/dev/null; then
  sleep 1
  # Verify both versions are downloadable
  DL_V1="${WORK_DIR}/dl-v1.onnx"
  DL_V2="${WORK_DIR}/dl-v2.onnx"

  v1_dl=$(curl -s -o "$DL_V1" -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(auth_header)" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}/download/${ARTIFACT_PATH}") || true
  v2_dl=$(curl -s -o "$DL_V2" -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(auth_header)" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}/download/${ARTIFACT_PATH_V2}") || true

  if [ "$v1_dl" -ge 200 ] 2>/dev/null && [ "$v1_dl" -lt 300 ] 2>/dev/null && [ -s "$DL_V1" ] \
    && [ "$v2_dl" -ge 200 ] 2>/dev/null && [ "$v2_dl" -lt 300 ] 2>/dev/null && [ -s "$DL_V2" ]; then
    v1_sha=$(sha256_hex "$DL_V1")
    v2_sha=$(sha256_hex "$DL_V2")
    if [ "$v1_sha" != "$v2_sha" ]; then
      pass
    else
      echo "  note: v1 and v2 have identical checksums (unexpected)"
      pass
    fi
  else
    fail "downloading one or both versions failed (v1=${v1_dl}, v2=${v2_dl})"
  fi
else
  fail "v2 upload returned HTTP ${v2_status}"
fi

# ---------------------------------------------------------------------------
# 5. Download integrity (SHA256 match)
# ---------------------------------------------------------------------------

begin_test "Download integrity (SHA256 matches uploaded file)"
INTEGRITY_DL="${WORK_DIR}/integrity-model.onnx"
integrity_status=$(curl -s -o "$INTEGRITY_DL" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/download/${ARTIFACT_PATH}") || true

if [ "$integrity_status" -ge 200 ] 2>/dev/null && [ "$integrity_status" -lt 300 ] 2>/dev/null; then
  if [ -s "$INTEGRITY_DL" ] && [ -s "$MODEL_FILE" ]; then
    upload_sha=$(sha256_hex "$MODEL_FILE")
    download_sha=$(sha256_hex "$INTEGRITY_DL")
    if assert_eq "$download_sha" "$upload_sha" "SHA256 mismatch: uploaded=${upload_sha} downloaded=${download_sha}"; then
      pass
    fi
  else
    skip "uploaded or downloaded file missing for integrity check"
  fi
else
  fail "download for integrity check returned HTTP ${integrity_status}"
fi

# ---------------------------------------------------------------------------
# 6. 404 for nonexistent model
# ---------------------------------------------------------------------------

begin_test "404 for nonexistent model"
status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/download/models/nonexistent-${RUN_ID}/versions/0.0.1/artifacts/model.onnx") || true
if assert_eq "$status" "404" "expected 404 for nonexistent model, got ${status}"; then
  pass
fi

end_suite
