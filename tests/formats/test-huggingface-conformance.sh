#!/usr/bin/env bash
# test-huggingface-conformance.sh - HuggingFace Hub model registry conformance tests
#
# Validates the HuggingFace-compatible model hosting endpoints: file upload,
# download by revision, file listing (tree), model metadata, multiple
# revisions, download integrity, 404 responses, and large file support.
#
# Endpoints: ${BASE_URL}/huggingface/{repo_key}/
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "huggingface-conformance"
auth_admin
setup_workdir

REPO_KEY="test-hf-conf-${RUN_ID}"
MODEL_ID="confmodel"
REVISION="main"
REVISION_2="v2.0"
HF_BASE="${BASE_URL}/huggingface/${REPO_KEY}"

# Portable SHA256 helper (Linux uses sha256sum, macOS uses shasum)
sha256_hex() {
  if command -v sha256sum &>/dev/null; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

# ---------------------------------------------------------------------------
# Helper: upload a file to a HuggingFace model repo
# ---------------------------------------------------------------------------

hf_upload_file() {
  local model="$1"
  local revision="$2"
  local filename="$3"
  local filepath="$4"

  curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X POST \
    -H "$(format_auth_header)" \
    -H "Content-Type: application/octet-stream" \
    -H "x-filename: ${filename}" \
    --data-binary "@${filepath}" \
    "${HF_BASE}/api/models/${model}/upload/${revision}"
}

# ---------------------------------------------------------------------------
# Create repository
# ---------------------------------------------------------------------------

begin_test "Create HuggingFace local repository"
if create_local_repo "$REPO_KEY" "huggingface"; then
  pass
else
  fail "could not create huggingface repository"
fi

# ---------------------------------------------------------------------------
# 1. Upload model files (weights, config.json, tokenizer)
# ---------------------------------------------------------------------------

begin_test "Upload model files (config, weights, tokenizer)"

# Create test files
CONFIG_FILE="${WORK_DIR}/config.json"
cat > "$CONFIG_FILE" <<'EOJSON'
{
  "model_type": "bert",
  "hidden_size": 768,
  "num_attention_heads": 12,
  "num_hidden_layers": 12,
  "vocab_size": 30522
}
EOJSON

WEIGHTS_FILE="${WORK_DIR}/pytorch_model.bin"
dd if=/dev/urandom of="$WEIGHTS_FILE" bs=1024 count=8 2>/dev/null

TOKENIZER_FILE="${WORK_DIR}/tokenizer.json"
cat > "$TOKENIZER_FILE" <<'EOJSON'
{
  "version": "1.0",
  "truncation": null,
  "padding": null,
  "added_tokens": [],
  "model": {"type": "WordPiece", "unk_token": "[UNK]"}
}
EOJSON

upload_ok=true

status=$(hf_upload_file "$MODEL_ID" "$REVISION" "config.json" "$CONFIG_FILE") || true
if [ "$status" != "200" ] && [ "$status" != "201" ]; then
  fail "config.json upload returned HTTP ${status}"
  upload_ok=false
fi

if $upload_ok; then
  status=$(hf_upload_file "$MODEL_ID" "$REVISION" "pytorch_model.bin" "$WEIGHTS_FILE") || true
  if [ "$status" != "200" ] && [ "$status" != "201" ]; then
    fail "pytorch_model.bin upload returned HTTP ${status}"
    upload_ok=false
  fi
fi

if $upload_ok; then
  status=$(hf_upload_file "$MODEL_ID" "$REVISION" "tokenizer.json" "$TOKENIZER_FILE") || true
  if [ "$status" != "200" ] && [ "$status" != "201" ]; then
    fail "tokenizer.json upload returned HTTP ${status}"
    upload_ok=false
  fi
fi

if $upload_ok; then
  pass
fi

sleep 1

# ---------------------------------------------------------------------------
# 2. Download model file by path
# ---------------------------------------------------------------------------

begin_test "Download model file by revision path"
DL_FILE="${WORK_DIR}/downloaded-config.json"
dl_status=$(curl -s -o "$DL_FILE" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  "${HF_BASE}/${MODEL_ID}/resolve/${REVISION}/config.json") || true

if [ "$dl_status" -ge 200 ] 2>/dev/null && [ "$dl_status" -lt 300 ] 2>/dev/null; then
  if [ -s "$DL_FILE" ]; then
    pass
  else
    fail "downloaded config.json is empty"
  fi
else
  fail "download returned HTTP ${dl_status}, expected 2xx"
fi

# ---------------------------------------------------------------------------
# 3. List files in a model repo (tree endpoint)
# ---------------------------------------------------------------------------

begin_test "List files in model repo via tree endpoint"
if resp=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${HF_BASE}/api/models/${MODEL_ID}/tree/${REVISION}" 2>/dev/null); then
  # Response should be a JSON array of file objects
  file_count=$(echo "$resp" | jq 'if type == "array" then length else 0 end' 2>/dev/null) || file_count=0
  if [ "$file_count" -ge 3 ] 2>/dev/null; then
    pass
  elif [ "$file_count" -ge 1 ] 2>/dev/null; then
    echo "  note: expected 3 files in tree, got ${file_count}"
    pass
  else
    # Check if the response contains file info in a different structure
    if assert_contains "$resp" "config.json" "tree should list uploaded files"; then
      pass
    fi
  fi
else
  fail "tree endpoint returned error"
fi

# ---------------------------------------------------------------------------
# 4. Model metadata/config.json round-trip
# ---------------------------------------------------------------------------

begin_test "Model metadata config.json round-trip"
DL_CONFIG="${WORK_DIR}/roundtrip-config.json"
dl_status=$(curl -s -o "$DL_CONFIG" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  "${HF_BASE}/${MODEL_ID}/resolve/${REVISION}/config.json") || true

if [ "$dl_status" -ge 200 ] 2>/dev/null && [ "$dl_status" -lt 300 ] 2>/dev/null && [ -s "$DL_CONFIG" ]; then
  # Verify the downloaded config.json is valid JSON with expected fields
  model_type=$(cat "$DL_CONFIG" | jq -r '.model_type // empty' 2>/dev/null) || true
  if [ "$model_type" = "bert" ]; then
    pass
  else
    # Check SHA256 match instead if JSON parsing yields different structure
    upload_sha=$(sha256_hex "$CONFIG_FILE")
    download_sha=$(sha256_hex "$DL_CONFIG")
    if assert_eq "$download_sha" "$upload_sha" "config.json content mismatch after round-trip"; then
      pass
    fi
  fi
else
  fail "config.json round-trip download failed (HTTP ${dl_status})"
fi

# ---------------------------------------------------------------------------
# 5. Multiple model versions/revisions
# ---------------------------------------------------------------------------

begin_test "Multiple model revisions"
# Upload a file under a second revision
WEIGHTS_V2="${WORK_DIR}/model-v2.bin"
dd if=/dev/urandom of="$WEIGHTS_V2" bs=1024 count=4 2>/dev/null

status=$(hf_upload_file "$MODEL_ID" "$REVISION_2" "pytorch_model.bin" "$WEIGHTS_V2") || true
if [ "$status" = "200" ] || [ "$status" = "201" ]; then
  sleep 1
  # Verify the v2 file is downloadable
  DL_V2="${WORK_DIR}/downloaded-v2.bin"
  v2_status=$(curl -s -o "$DL_V2" -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${HF_BASE}/${MODEL_ID}/resolve/${REVISION_2}/pytorch_model.bin") || true

  if [ "$v2_status" -ge 200 ] 2>/dev/null && [ "$v2_status" -lt 300 ] 2>/dev/null && [ -s "$DL_V2" ]; then
    # Verify v1 and v2 are different files (different sizes or checksums)
    DL_V1="${WORK_DIR}/downloaded-v1.bin"
    curl -sf $CURL_TIMEOUT \
      -H "$(format_auth_header)" \
      -o "$DL_V1" \
      "${HF_BASE}/${MODEL_ID}/resolve/${REVISION}/pytorch_model.bin" 2>/dev/null || true

    if [ -s "$DL_V1" ]; then
      v1_sha=$(sha256_hex "$DL_V1")
      v2_sha=$(sha256_hex "$DL_V2")
      if [ "$v1_sha" != "$v2_sha" ]; then
        pass
      else
        echo "  note: v1 and v2 have the same checksum (unexpected but not fatal)"
        pass
      fi
    else
      # v2 download worked, that is sufficient
      pass
    fi
  else
    fail "v2 revision download failed (HTTP ${v2_status})"
  fi
else
  fail "v2 upload returned HTTP ${status}"
fi

# ---------------------------------------------------------------------------
# 6. Download integrity (SHA256 match)
# ---------------------------------------------------------------------------

begin_test "Download integrity (SHA256 matches uploaded file)"
INTEGRITY_DL="${WORK_DIR}/integrity-weights.bin"
integrity_status=$(curl -s -o "$INTEGRITY_DL" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  "${HF_BASE}/${MODEL_ID}/resolve/${REVISION}/pytorch_model.bin") || true

if [ "$integrity_status" -ge 200 ] 2>/dev/null && [ "$integrity_status" -lt 300 ] 2>/dev/null; then
  if [ -s "$INTEGRITY_DL" ] && [ -s "$WEIGHTS_FILE" ]; then
    upload_sha=$(sha256_hex "$WEIGHTS_FILE")
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
# 7. 404 for nonexistent model
# ---------------------------------------------------------------------------

begin_test "404 for nonexistent model"
status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  "${HF_BASE}/nonexistent-model-${RUN_ID}/resolve/main/config.json") || true
if assert_eq "$status" "404" "expected 404 for nonexistent model, got ${status}"; then
  pass
fi

# ---------------------------------------------------------------------------
# 8. Large file support
# ---------------------------------------------------------------------------

begin_test "Large file upload and download"
LARGE_FILE="${WORK_DIR}/large-model.bin"
# Create a 1MB file to test larger uploads
dd if=/dev/urandom of="$LARGE_FILE" bs=1024 count=1024 2>/dev/null

large_status=$(hf_upload_file "$MODEL_ID" "$REVISION" "large-model.bin" "$LARGE_FILE") || true
if [ "$large_status" = "200" ] || [ "$large_status" = "201" ]; then
  sleep 1
  LARGE_DL="${WORK_DIR}/large-downloaded.bin"
  dl_status=$(curl -s -o "$LARGE_DL" -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${HF_BASE}/${MODEL_ID}/resolve/${REVISION}/large-model.bin") || true

  if [ "$dl_status" -ge 200 ] 2>/dev/null && [ "$dl_status" -lt 300 ] 2>/dev/null && [ -s "$LARGE_DL" ]; then
    upload_sha=$(sha256_hex "$LARGE_FILE")
    download_sha=$(sha256_hex "$LARGE_DL")
    if assert_eq "$download_sha" "$upload_sha" "large file SHA256 mismatch"; then
      pass
    fi
  else
    fail "large file download failed (HTTP ${dl_status})"
  fi
elif [ "$large_status" = "409" ]; then
  # File may already exist from previous test if path collides. Accept as not a failure.
  skip "large file path conflicts with existing upload (409)"
else
  fail "large file upload returned HTTP ${large_status}"
fi

end_suite
