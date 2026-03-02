#!/usr/bin/env bash
# HuggingFace Hub format E2E test
# Tests model file upload, listing, and download via the /huggingface/{repo_key}/ endpoints.
source "$(dirname "$0")/../lib/common.sh"

begin_suite "huggingface"
auth_admin
setup_workdir

REPO_KEY="test-huggingface-${RUN_ID}"
MODEL_ID="test-model-${RUN_ID}"
REVISION="main"
HF_URL="${BASE_URL}/huggingface/${REPO_KEY}"

# ---------------------------------------------------------------------------
# Create repository
# ---------------------------------------------------------------------------

begin_test "Create huggingface local repository"
if create_local_repo "$REPO_KEY" "huggingface"; then
  pass
else
  fail "could not create huggingface repo"
fi

# ---------------------------------------------------------------------------
# Create test model files
# ---------------------------------------------------------------------------

begin_test "Create test model files"
cd "$WORK_DIR"

cat > config.json <<EOF
{
  "model_type": "test",
  "hidden_size": 128,
  "num_attention_heads": 4,
  "num_hidden_layers": 2,
  "vocab_size": 1000
}
EOF

# Small binary file simulating model weights
dd if=/dev/urandom bs=1024 count=4 of=model.safetensors 2>/dev/null

pass

# ---------------------------------------------------------------------------
# Upload config.json via the upload endpoint
# Backend: POST /api/models/{model_id}/upload/{revision} with x-filename header
# ---------------------------------------------------------------------------

begin_test "Upload config.json to model"
if resp=$(curl -sf -X POST \
  -H "$(format_auth_header)" \
  -H "Content-Type: application/octet-stream" \
  -H "x-filename: config.json" \
  --data-binary "@${WORK_DIR}/config.json" \
  "${HF_URL}/api/models/${MODEL_ID}/upload/${REVISION}" 2>&1); then
  pass
else
  fail "upload config.json failed: ${resp}"
fi

# ---------------------------------------------------------------------------
# Upload model weights
# ---------------------------------------------------------------------------

begin_test "Upload model weights file"
if resp=$(curl -sf -X POST \
  -H "$(format_auth_header)" \
  -H "Content-Type: application/octet-stream" \
  -H "x-filename: model.safetensors" \
  --data-binary "@${WORK_DIR}/model.safetensors" \
  "${HF_URL}/api/models/${MODEL_ID}/upload/${REVISION}" 2>&1); then
  pass
else
  fail "upload model.safetensors failed: ${resp}"
fi

# ---------------------------------------------------------------------------
# Query model listing
# ---------------------------------------------------------------------------

begin_test "Query model listing"
sleep 1
if resp=$(curl -sf "${HF_URL}/api/models" -H "$(format_auth_header)"); then
  if assert_contains "$resp" "$MODEL_ID" "model listing should contain model ID"; then
    pass
  fi
else
  fail "GET /api/models returned error"
fi

# ---------------------------------------------------------------------------
# Get model info
# ---------------------------------------------------------------------------

begin_test "Get model info"
if resp=$(curl -sf "${HF_URL}/api/models/${MODEL_ID}" -H "$(format_auth_header)"); then
  if assert_contains "$resp" "$MODEL_ID" "model info should contain model ID"; then
    pass
  fi
else
  fail "GET /api/models/${MODEL_ID} returned error"
fi

# ---------------------------------------------------------------------------
# Verify artifacts via management API
# ---------------------------------------------------------------------------

begin_test "List artifacts via management API"
if resp=$(api_get "/api/v1/repositories/${REPO_KEY}/artifacts"); then
  if assert_contains "$resp" "config.json" "artifact list should contain config.json"; then
    pass
  fi
else
  fail "GET /api/v1/repositories/${REPO_KEY}/artifacts returned error"
fi

end_suite
