#!/usr/bin/env bash
# test-mlmodel.sh - ML Model (WASM ext) E2E test
#
# Tests model upload and retrieval via the /ext/mlmodel/{repo_key}/ endpoints.
# This format uses the WASM plugin proxy. Uses curl only.
#
# Requires: curl (no native client needed)

source "$(dirname "$0")/../lib/common.sh"

begin_suite "mlmodel"
auth_admin
setup_workdir

REPO_KEY="test-mlmodel-${RUN_ID}"
MODEL_NAME="test-model"
MODEL_VERSION="1.0.$(date +%s)"
EXT_URL="${BASE_URL}/ext/mlmodel/${REPO_KEY}"

# ---------------------------------------------------------------------------
# Create repository
# ---------------------------------------------------------------------------

begin_test "Create mlmodel local repository"
if create_local_repo "$REPO_KEY" "mlmodel"; then
  pass
else
  fail "could not create mlmodel repository"
fi

# ---------------------------------------------------------------------------
# Create test model files
# ---------------------------------------------------------------------------

begin_test "Create test model files"
cd "$WORK_DIR"

# Create a model metadata file
cat > model-metadata.json <<EOF
{
  "name": "${MODEL_NAME}",
  "version": "${MODEL_VERSION}",
  "framework": "pytorch",
  "task": "text-classification",
  "metrics": {
    "accuracy": 0.95,
    "f1": 0.93
  }
}
EOF

# Create a small binary "model" file (simulated weights)
dd if=/dev/urandom bs=1024 count=8 of=model.bin 2>/dev/null

pass

# ---------------------------------------------------------------------------
# Upload model metadata
# ---------------------------------------------------------------------------

begin_test "Upload model metadata"
UPLOAD_PATH="/ext/mlmodel/${REPO_KEY}/${MODEL_NAME}/${MODEL_VERSION}/model-metadata.json"
if resp=$(curl -sf -X PUT "${BASE_URL}${UPLOAD_PATH}" \
  -H "$(auth_header)" \
  -H "Content-Type: application/json" \
  --data-binary "@${WORK_DIR}/model-metadata.json" 2>&1); then
  pass
else
  fail "upload model-metadata.json failed: ${resp}"
fi

# ---------------------------------------------------------------------------
# Upload model binary
# ---------------------------------------------------------------------------

begin_test "Upload model binary"
UPLOAD_PATH="/ext/mlmodel/${REPO_KEY}/${MODEL_NAME}/${MODEL_VERSION}/model.bin"
if resp=$(curl -sf -X PUT "${BASE_URL}${UPLOAD_PATH}" \
  -H "$(auth_header)" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@${WORK_DIR}/model.bin" 2>&1); then
  pass
else
  fail "upload model.bin failed: ${resp}"
fi

# ---------------------------------------------------------------------------
# Download model metadata
# ---------------------------------------------------------------------------

begin_test "Download model metadata"
sleep 1
DL_PATH="/ext/mlmodel/${REPO_KEY}/${MODEL_NAME}/${MODEL_VERSION}/model-metadata.json"
if resp=$(curl -sf "${BASE_URL}${DL_PATH}" -H "$(auth_header)"); then
  if assert_contains "$resp" "$MODEL_NAME" "metadata should contain model name"; then
    if assert_contains "$resp" "$MODEL_VERSION" "metadata should contain version"; then
      pass
    fi
  fi
else
  fail "download model-metadata.json failed"
fi

# ---------------------------------------------------------------------------
# Download model binary and verify size
# ---------------------------------------------------------------------------

begin_test "Download model binary"
DL_PATH="/ext/mlmodel/${REPO_KEY}/${MODEL_NAME}/${MODEL_VERSION}/model.bin"
DL_FILE="${WORK_DIR}/downloaded_model.bin"
if curl -sf -H "$(auth_header)" -o "$DL_FILE" "${BASE_URL}${DL_PATH}"; then
  DL_SIZE=$(wc -c < "$DL_FILE" | tr -d ' ')
  ORIG_SIZE=$(wc -c < "${WORK_DIR}/model.bin" | tr -d ' ')
  if assert_eq "$DL_SIZE" "$ORIG_SIZE" "downloaded file size should match original"; then
    pass
  fi
else
  fail "download model.bin failed"
fi

# ---------------------------------------------------------------------------
# Verify repository artifacts via management API
# ---------------------------------------------------------------------------

begin_test "List artifacts via management API"
if resp=$(api_get "/api/v1/repositories/${REPO_KEY}/artifacts"); then
  if assert_contains "$resp" "$MODEL_NAME" "artifact list should contain model name"; then
    pass
  fi
else
  fail "GET /api/v1/repositories/${REPO_KEY}/artifacts returned error"
fi

end_suite
