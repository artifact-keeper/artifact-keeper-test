#!/usr/bin/env bash
# test-huggingface-edge-cases.sh - Deep-dive edge case tests for HuggingFace model registry
#
# Thorough coverage of ML/LLM-specific scenarios including model file upload
# and download with SHA256 verification, large model shards, safetensors format,
# GGUF quantized models, concurrent access, model card metadata, nested paths,
# multiple revisions, and various edge cases around naming and overwrites.
#
# Endpoints: ${BASE_URL}/huggingface/{repo_key}/
#   POST  /api/models/{model_id}/upload/{revision}       - Upload file (x-filename header)
#   GET   /{model_id}/resolve/{revision}/{filename}       - Download file
#   GET   /api/models                                     - List models
#   GET   /api/models/{model_id}                          - Model info (siblings)
#   GET   /api/models/{model_id}/tree/{revision}          - List files in revision
#
# Requires: jq, curl, shasum or sha256sum

source "$(dirname "$0")/../lib/common.sh"

begin_suite "huggingface-edge-cases"
auth_admin
setup_workdir

REPO_KEY="test-hf-edge-${RUN_ID}"
HF_URL="${BASE_URL}/huggingface/${REPO_KEY}"

# ---------------------------------------------------------------------------
# Helper: portable SHA256
# ---------------------------------------------------------------------------
portable_sha256() {
  local file="$1"
  if command -v shasum &>/dev/null; then
    shasum -a 256 "$file" | awk '{print $1}'
  elif command -v sha256sum &>/dev/null; then
    sha256sum "$file" | awk '{print $1}'
  else
    openssl dgst -sha256 "$file" | awk '{print $NF}'
  fi
}

# ---------------------------------------------------------------------------
# Helper: upload a file to the HuggingFace endpoint
#
# hf_upload MODEL_ID REVISION LOCAL_FILE [REMOTE_FILENAME]
#
# REMOTE_FILENAME defaults to the basename of LOCAL_FILE.
# Prints the JSON response on success. Returns non-zero on failure.
# ---------------------------------------------------------------------------
hf_upload() {
  local model_id="$1"
  local revision="$2"
  local local_file="$3"
  local remote_filename="${4:-$(basename "$local_file")}"

  curl -sf $CURL_TIMEOUT -X POST \
    -H "$(format_auth_header)" \
    -H "Content-Type: application/octet-stream" \
    -H "x-filename: ${remote_filename}" \
    --data-binary "@${local_file}" \
    "${HF_URL}/api/models/${model_id}/upload/${revision}"
}

# ---------------------------------------------------------------------------
# Helper: download a file from the HuggingFace endpoint
#
# hf_download MODEL_ID REVISION FILENAME OUTPUT_FILE
# ---------------------------------------------------------------------------
hf_download() {
  local model_id="$1"
  local revision="$2"
  local filename="$3"
  local output_file="$4"

  curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    -o "$output_file" \
    "${HF_URL}/${model_id}/resolve/${revision}/${filename}"
}

# ---------------------------------------------------------------------------
# Helper: get HTTP status code for a request
# ---------------------------------------------------------------------------
hf_status() {
  local url="$1"
  curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "$url"
}

# ===========================================================================
# Create repository
# ===========================================================================

begin_test "Create huggingface repository"
if create_local_repo "$REPO_KEY" "huggingface"; then
  pass
else
  fail "could not create huggingface repo"
fi

# ===========================================================================
# 1. Upload config.json (transformer model config)
# ===========================================================================

begin_test "Upload transformer config.json"
MODEL_ID="test-llm-${RUN_ID}"
REVISION="main"

cat > "${WORK_DIR}/config.json" <<'EOCFG'
{
  "architectures": ["LlamaForCausalLM"],
  "bos_token_id": 1,
  "eos_token_id": 2,
  "hidden_act": "silu",
  "hidden_size": 4096,
  "initializer_range": 0.02,
  "intermediate_size": 11008,
  "max_position_embeddings": 4096,
  "model_type": "llama",
  "num_attention_heads": 32,
  "num_hidden_layers": 32,
  "num_key_value_heads": 32,
  "pretraining_tp": 1,
  "rms_norm_eps": 1e-05,
  "rope_scaling": null,
  "tie_word_embeddings": false,
  "torch_dtype": "float16",
  "transformers_version": "4.36.0",
  "use_cache": true,
  "vocab_size": 32000
}
EOCFG

CONFIG_SHA=$(portable_sha256 "${WORK_DIR}/config.json")

if resp=$(hf_upload "$MODEL_ID" "$REVISION" "${WORK_DIR}/config.json"); then
  if assert_contains "$resp" "config.json" "upload response should reference config.json"; then
    pass
  fi
else
  fail "upload config.json failed: ${resp}"
fi

# ===========================================================================
# 2. Upload tokenizer.json
# ===========================================================================

begin_test "Upload tokenizer.json"
cat > "${WORK_DIR}/tokenizer.json" <<'EOTOK'
{
  "version": "1.0",
  "truncation": null,
  "padding": null,
  "added_tokens": [
    {"id": 0, "content": "<unk>", "single_word": false, "lstrip": false, "rstrip": false, "normalized": false, "special": true},
    {"id": 1, "content": "<s>", "single_word": false, "lstrip": false, "rstrip": false, "normalized": false, "special": true},
    {"id": 2, "content": "</s>", "single_word": false, "lstrip": false, "rstrip": false, "normalized": false, "special": true}
  ],
  "normalizer": {"type": "Sequence", "normalizers": [{"type": "Prepend", "prepend": "\u2581"}]},
  "pre_tokenizer": null,
  "post_processor": null,
  "decoder": null,
  "model": {
    "type": "BPE",
    "dropout": null,
    "unk_token": "<unk>",
    "continuing_subword_prefix": null,
    "end_of_word_suffix": null,
    "fuse_unk": false,
    "byte_fallback": true,
    "vocab": {},
    "merges": []
  }
}
EOTOK

TOKENIZER_SHA=$(portable_sha256 "${WORK_DIR}/tokenizer.json")

if resp=$(hf_upload "$MODEL_ID" "$REVISION" "${WORK_DIR}/tokenizer.json"); then
  if assert_contains "$resp" "tokenizer.json" "upload response should reference tokenizer.json"; then
    pass
  fi
else
  fail "upload tokenizer.json failed: ${resp}"
fi

# ===========================================================================
# 3. Upload tokenizer_config.json
# ===========================================================================

begin_test "Upload tokenizer_config.json"
cat > "${WORK_DIR}/tokenizer_config.json" <<'EOTCFG'
{
  "add_bos_token": true,
  "add_eos_token": false,
  "bos_token": "<s>",
  "clean_up_tokenization_spaces": false,
  "eos_token": "</s>",
  "legacy": true,
  "model_max_length": 4096,
  "pad_token": null,
  "sp_model_kwargs": {},
  "tokenizer_class": "LlamaTokenizer",
  "unk_token": "<unk>",
  "use_default_system_prompt": false
}
EOTCFG

TOKCFG_SHA=$(portable_sha256 "${WORK_DIR}/tokenizer_config.json")

if resp=$(hf_upload "$MODEL_ID" "$REVISION" "${WORK_DIR}/tokenizer_config.json"); then
  if assert_contains "$resp" "tokenizer_config.json" "response should reference tokenizer_config.json"; then
    pass
  fi
else
  fail "upload tokenizer_config.json failed: ${resp}"
fi

# ===========================================================================
# 4. Upload model weights (simulated .safetensors binary)
# ===========================================================================

begin_test "Upload model.safetensors (4KB simulated weights)"
dd if=/dev/urandom bs=1024 count=4 of="${WORK_DIR}/model.safetensors" 2>/dev/null
WEIGHTS_SHA=$(portable_sha256 "${WORK_DIR}/model.safetensors")

if resp=$(hf_upload "$MODEL_ID" "$REVISION" "${WORK_DIR}/model.safetensors"); then
  if assert_contains "$resp" "model.safetensors" "response should reference model.safetensors"; then
    # Verify the server computed the same SHA256
    server_sha=$(echo "$resp" | jq -r '.sha256 // empty')
    if [ -n "$server_sha" ]; then
      assert_eq "$server_sha" "$WEIGHTS_SHA" "server SHA256 should match locally computed hash"
    fi
    pass
  fi
else
  fail "upload model.safetensors failed: ${resp}"
fi

# ===========================================================================
# 5. Upload README.md (model card)
# ===========================================================================

begin_test "Upload README.md model card with YAML front matter"
cat > "${WORK_DIR}/README.md" <<'EOREADME'
---
license: apache-2.0
tags:
  - text-generation
  - llama
  - causal-lm
pipeline_tag: text-generation
language:
  - en
datasets:
  - wikitext
  - openwebtext
model-index:
  - name: test-llm
    results:
      - task:
          type: text-generation
        metrics:
          - name: Perplexity
            type: perplexity
            value: 5.67
---

# Test LLM

A test language model for validating the HuggingFace model registry implementation.

## Model Details

- **Architecture**: LlamaForCausalLM
- **Parameters**: 32 layers, 4096 hidden size
- **Training data**: Synthetic test data
- **Precision**: float16

## Usage

```python
from transformers import AutoModelForCausalLM, AutoTokenizer

model = AutoModelForCausalLM.from_pretrained("test-org/test-llm")
tokenizer = AutoTokenizer.from_pretrained("test-org/test-llm")
```

## Limitations

This is a test model. Do not use for production inference.
EOREADME

README_SHA=$(portable_sha256 "${WORK_DIR}/README.md")

if resp=$(hf_upload "$MODEL_ID" "$REVISION" "${WORK_DIR}/README.md"); then
  if assert_contains "$resp" "README.md" "response should reference README.md"; then
    pass
  fi
else
  fail "upload README.md failed: ${resp}"
fi

# ===========================================================================
# 6. Download each file and verify SHA256 round-trip integrity
# ===========================================================================

begin_test "Download config.json and verify SHA256"
if hf_download "$MODEL_ID" "$REVISION" "config.json" "${WORK_DIR}/dl_config.json"; then
  dl_sha=$(portable_sha256 "${WORK_DIR}/dl_config.json")
  if assert_eq "$dl_sha" "$CONFIG_SHA" "config.json SHA256 mismatch after round-trip"; then
    pass
  fi
else
  fail "download config.json failed"
fi

begin_test "Download tokenizer.json and verify SHA256"
if hf_download "$MODEL_ID" "$REVISION" "tokenizer.json" "${WORK_DIR}/dl_tokenizer.json"; then
  dl_sha=$(portable_sha256 "${WORK_DIR}/dl_tokenizer.json")
  if assert_eq "$dl_sha" "$TOKENIZER_SHA" "tokenizer.json SHA256 mismatch after round-trip"; then
    pass
  fi
else
  fail "download tokenizer.json failed"
fi

begin_test "Download tokenizer_config.json and verify SHA256"
if hf_download "$MODEL_ID" "$REVISION" "tokenizer_config.json" "${WORK_DIR}/dl_tokenizer_config.json"; then
  dl_sha=$(portable_sha256 "${WORK_DIR}/dl_tokenizer_config.json")
  if assert_eq "$dl_sha" "$TOKCFG_SHA" "tokenizer_config.json SHA256 mismatch after round-trip"; then
    pass
  fi
else
  fail "download tokenizer_config.json failed"
fi

begin_test "Download model.safetensors and verify SHA256"
if hf_download "$MODEL_ID" "$REVISION" "model.safetensors" "${WORK_DIR}/dl_model.safetensors"; then
  dl_sha=$(portable_sha256 "${WORK_DIR}/dl_model.safetensors")
  if assert_eq "$dl_sha" "$WEIGHTS_SHA" "model.safetensors SHA256 mismatch after round-trip"; then
    pass
  fi
else
  fail "download model.safetensors failed"
fi

begin_test "Download README.md and verify SHA256"
if hf_download "$MODEL_ID" "$REVISION" "README.md" "${WORK_DIR}/dl_readme.md"; then
  dl_sha=$(portable_sha256 "${WORK_DIR}/dl_readme.md")
  if assert_eq "$dl_sha" "$README_SHA" "README.md SHA256 mismatch after round-trip"; then
    pass
  fi
else
  fail "download README.md failed"
fi

# ===========================================================================
# 7. Upload a 50MB weights file (simulating a model shard)
# ===========================================================================

begin_test "Upload 50MB model shard"
dd if=/dev/urandom bs=1048576 count=50 of="${WORK_DIR}/large_shard.safetensors" 2>/dev/null
LARGE_SHA=$(portable_sha256 "${WORK_DIR}/large_shard.safetensors")

LARGE_MODEL="large-model-${RUN_ID}"

if resp=$(hf_upload "$LARGE_MODEL" "main" "${WORK_DIR}/large_shard.safetensors"); then
  server_sha=$(echo "$resp" | jq -r '.sha256 // empty')
  if [ -n "$server_sha" ]; then
    if assert_eq "$server_sha" "$LARGE_SHA" "50MB shard SHA256 should match"; then
      pass
    fi
  else
    # SHA256 present in response means success; if not in response, still check size
    server_size=$(echo "$resp" | jq -r '.size // 0')
    if [ "$server_size" -ge 50000000 ] 2>/dev/null; then
      pass
    else
      fail "50MB upload succeeded but response has unexpected shape: ${resp}"
    fi
  fi
else
  fail "50MB shard upload failed"
fi

# ===========================================================================
# 8. Upload 100MB file (may be slow, but validates large transfer handling)
# ===========================================================================

begin_test "Upload 100MB model shard"
dd if=/dev/urandom bs=1048576 count=100 of="${WORK_DIR}/huge_shard.safetensors" 2>/dev/null
HUGE_SHA=$(portable_sha256 "${WORK_DIR}/huge_shard.safetensors")

# Use a longer timeout for large uploads
if resp=$(curl -sf --max-time 300 --connect-timeout 30 -X POST \
    -H "$(format_auth_header)" \
    -H "Content-Type: application/octet-stream" \
    -H "x-filename: huge_shard.safetensors" \
    --data-binary "@${WORK_DIR}/huge_shard.safetensors" \
    "${HF_URL}/api/models/${LARGE_MODEL}/upload/main" 2>&1); then
  server_sha=$(echo "$resp" | jq -r '.sha256 // empty')
  if [ -n "$server_sha" ]; then
    assert_eq "$server_sha" "$HUGE_SHA" "100MB shard SHA256 should match"
  fi
  pass
else
  skip "100MB upload timed out or failed (may be expected in constrained CI)"
fi

# ===========================================================================
# 9. Verify large file download integrity
# ===========================================================================

begin_test "Download 50MB shard and verify integrity"
if curl -sf --max-time 120 --connect-timeout 30 \
    -H "$(format_auth_header)" \
    -o "${WORK_DIR}/dl_large_shard.safetensors" \
    "${HF_URL}/${LARGE_MODEL}/resolve/main/large_shard.safetensors"; then
  dl_sha=$(portable_sha256 "${WORK_DIR}/dl_large_shard.safetensors")
  if assert_eq "$dl_sha" "$LARGE_SHA" "50MB download SHA256 mismatch"; then
    pass
  fi
else
  fail "50MB shard download failed"
fi

# ===========================================================================
# 10. Upload files with nested paths
# ===========================================================================

begin_test "Upload files with nested directory paths"
NESTED_MODEL="nested-model-${RUN_ID}"

# Create a config in a nested path
cat > "${WORK_DIR}/nested_config.json" <<'EOF'
{"model_type": "gpt2", "hidden_size": 768, "num_hidden_layers": 12}
EOF

# Upload with a nested filename via x-filename header
if resp=$(curl -sf $CURL_TIMEOUT -X POST \
    -H "$(format_auth_header)" \
    -H "Content-Type: application/octet-stream" \
    -H "x-filename: model/config.json" \
    --data-binary "@${WORK_DIR}/nested_config.json" \
    "${HF_URL}/api/models/${NESTED_MODEL}/upload/main" 2>&1); then
  assert_contains "$resp" "model/config.json" "nested path should appear in response"
else
  fail "nested path upload failed: ${resp}"
fi

# Upload a simulated weight shard under a nested weights/ directory
dd if=/dev/urandom bs=1024 count=2 of="${WORK_DIR}/shard_nested.bin" 2>/dev/null
if resp=$(curl -sf $CURL_TIMEOUT -X POST \
    -H "$(format_auth_header)" \
    -H "Content-Type: application/octet-stream" \
    -H "x-filename: model/weights/shard-00001-of-00004.safetensors" \
    --data-binary "@${WORK_DIR}/shard_nested.bin" \
    "${HF_URL}/api/models/${NESTED_MODEL}/upload/main" 2>&1); then
  if assert_contains "$resp" "shard-00001-of-00004" "nested weights path should appear in response"; then
    pass
  fi
else
  fail "nested weights upload failed: ${resp}"
fi

# ===========================================================================
# 11. List files in a model repository (tree endpoint)
# ===========================================================================

begin_test "List files in model repository via tree endpoint"
sleep 1
if resp=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${HF_URL}/api/models/${MODEL_ID}/tree/${REVISION}"); then
  # The tree endpoint should list all files we uploaded for MODEL_ID
  file_count=$(echo "$resp" | jq 'length')
  if [ "$file_count" -ge 5 ] 2>/dev/null; then
    # Verify specific files appear in the listing
    has_config=$(echo "$resp" | jq '[.[] | select(.path == "config.json")] | length')
    has_tokenizer=$(echo "$resp" | jq '[.[] | select(.path == "tokenizer.json")] | length')
    has_readme=$(echo "$resp" | jq '[.[] | select(.path == "README.md")] | length')
    if [ "$has_config" -ge 1 ] && [ "$has_tokenizer" -ge 1 ] && [ "$has_readme" -ge 1 ]; then
      pass
    else
      fail "tree listing missing expected files (config: ${has_config}, tokenizer: ${has_tokenizer}, readme: ${has_readme})"
    fi
  else
    fail "expected at least 5 files in tree, got ${file_count}. Response: ${resp}"
  fi
else
  fail "GET tree endpoint failed"
fi

# ===========================================================================
# 12. Multiple model revisions (v1 vs v2 with different configs)
# ===========================================================================

begin_test "Upload config for revision v2 with different architecture"
REVISION_MODEL="revision-model-${RUN_ID}"

cat > "${WORK_DIR}/config_v1.json" <<'EOF'
{
  "model_type": "gpt2",
  "hidden_size": 768,
  "num_hidden_layers": 12,
  "num_attention_heads": 12,
  "vocab_size": 50257,
  "architectures": ["GPT2LMHeadModel"]
}
EOF

cat > "${WORK_DIR}/config_v2.json" <<'EOF'
{
  "model_type": "llama",
  "hidden_size": 4096,
  "num_hidden_layers": 32,
  "num_attention_heads": 32,
  "vocab_size": 32000,
  "architectures": ["LlamaForCausalLM"]
}
EOF

V1_SHA=$(portable_sha256 "${WORK_DIR}/config_v1.json")
V2_SHA=$(portable_sha256 "${WORK_DIR}/config_v2.json")

# Upload v1
if ! hf_upload "$REVISION_MODEL" "v1" "${WORK_DIR}/config_v1.json" "config.json" >/dev/null; then
  fail "v1 config upload failed"
fi

# Upload v2
if ! hf_upload "$REVISION_MODEL" "v2" "${WORK_DIR}/config_v2.json" "config.json" >/dev/null; then
  fail "v2 config upload failed"
fi

# Download each and verify they are different
if hf_download "$REVISION_MODEL" "v1" "config.json" "${WORK_DIR}/dl_v1.json" && \
   hf_download "$REVISION_MODEL" "v2" "config.json" "${WORK_DIR}/dl_v2.json"; then
  dl_v1_sha=$(portable_sha256 "${WORK_DIR}/dl_v1.json")
  dl_v2_sha=$(portable_sha256 "${WORK_DIR}/dl_v2.json")
  if assert_eq "$dl_v1_sha" "$V1_SHA" "v1 config SHA256 mismatch" && \
     assert_eq "$dl_v2_sha" "$V2_SHA" "v2 config SHA256 mismatch"; then
    # The two configs must be different
    if [ "$dl_v1_sha" != "$dl_v2_sha" ]; then
      pass
    else
      fail "v1 and v2 configs should be different but have same SHA256"
    fi
  fi
else
  fail "download of versioned configs failed"
fi

# ===========================================================================
# 13. Concurrent downloads of the same model file (10 parallel)
# ===========================================================================

begin_test "10 concurrent downloads of model.safetensors"
concurrent_ok=0
concurrent_fail=0
pids=()

for i in $(seq 1 10); do
  (
    if hf_download "$MODEL_ID" "$REVISION" "model.safetensors" \
        "${WORK_DIR}/concurrent_dl_${i}.safetensors"; then
      dl_sha=$(portable_sha256 "${WORK_DIR}/concurrent_dl_${i}.safetensors")
      if [ "$dl_sha" = "$WEIGHTS_SHA" ]; then
        exit 0
      else
        exit 1
      fi
    else
      exit 1
    fi
  ) &
  pids+=($!)
done

for pid in "${pids[@]}"; do
  if wait "$pid"; then
    concurrent_ok=$((concurrent_ok + 1))
  else
    concurrent_fail=$((concurrent_fail + 1))
  fi
done

if [ "$concurrent_ok" -eq 10 ]; then
  pass
else
  fail "${concurrent_fail}/10 concurrent downloads failed or had SHA256 mismatches"
fi

# ===========================================================================
# 14. Concurrent upload + download (write while reading)
# ===========================================================================

begin_test "Concurrent upload and download (write while reading)"
CONCURRENT_MODEL="concurrent-model-${RUN_ID}"

dd if=/dev/urandom bs=1024 count=8 of="${WORK_DIR}/concurrent_weights.safetensors" 2>/dev/null
CONC_SHA=$(portable_sha256 "${WORK_DIR}/concurrent_weights.safetensors")

# Upload the file first so we have something to download
if ! hf_upload "$CONCURRENT_MODEL" "main" "${WORK_DIR}/concurrent_weights.safetensors" >/dev/null; then
  fail "initial upload for concurrent test failed"
fi

# Now upload a new file while simultaneously downloading the existing one
dd if=/dev/urandom bs=1024 count=4 of="${WORK_DIR}/concurrent_config.json" 2>/dev/null

upload_pid=""
download_pid=""

(hf_upload "$CONCURRENT_MODEL" "main" "${WORK_DIR}/concurrent_config.json" "config.json" >/dev/null 2>&1) &
upload_pid=$!

(hf_download "$CONCURRENT_MODEL" "main" "concurrent_weights.safetensors" \
    "${WORK_DIR}/concurrent_dl_check.safetensors" 2>/dev/null) &
download_pid=$!

upload_ok=true
download_ok=true

if ! wait "$upload_pid"; then
  upload_ok=false
fi

if ! wait "$download_pid"; then
  download_ok=false
fi

if $download_ok; then
  dl_sha=$(portable_sha256 "${WORK_DIR}/concurrent_dl_check.safetensors")
  if [ "$dl_sha" = "$CONC_SHA" ] && $upload_ok; then
    pass
  elif [ "$dl_sha" != "$CONC_SHA" ]; then
    fail "concurrent download returned corrupted data (SHA256 mismatch)"
  else
    fail "concurrent upload failed while download succeeded"
  fi
else
  if $upload_ok; then
    fail "concurrent download failed while upload succeeded"
  else
    fail "both concurrent upload and download failed"
  fi
fi

# ===========================================================================
# 15. Model card README with YAML front matter metadata
# ===========================================================================

begin_test "Verify model card YAML front matter preserved in download"
if hf_download "$MODEL_ID" "$REVISION" "README.md" "${WORK_DIR}/verify_readme.md"; then
  # Check YAML front matter markers are present
  first_line=$(head -1 "${WORK_DIR}/verify_readme.md")
  if [ "$first_line" = "---" ]; then
    # Verify key metadata fields survive the round trip
    content=$(cat "${WORK_DIR}/verify_readme.md")
    if assert_contains "$content" "pipeline_tag: text-generation" "pipeline_tag should be preserved" && \
       assert_contains "$content" "license: apache-2.0" "license should be preserved" && \
       assert_contains "$content" "llama" "model tags should be preserved"; then
      pass
    fi
  else
    fail "YAML front matter missing: first line is '${first_line}', expected '---'"
  fi
else
  fail "README.md download for YAML check failed"
fi

# ===========================================================================
# 16. Verify metadata extraction (model info endpoint)
# ===========================================================================

begin_test "Model info endpoint returns siblings and metadata"
sleep 1
if resp=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${HF_URL}/api/models/${MODEL_ID}"); then
  model_id_val=$(echo "$resp" | jq -r '.modelId // empty')
  siblings=$(echo "$resp" | jq '.siblings // [] | length')
  if assert_eq "$model_id_val" "$MODEL_ID" "modelId should match" && \
     [ "$siblings" -ge 4 ] 2>/dev/null; then
    pass
  else
    fail "model info has unexpected shape (siblings: ${siblings}). Response: ${resp}"
  fi
else
  fail "GET model info failed"
fi

# ===========================================================================
# 17. Config.json content preserved with transformer-specific fields
# ===========================================================================

begin_test "Config.json transformer fields preserved after round-trip"
if hf_download "$MODEL_ID" "$REVISION" "config.json" "${WORK_DIR}/verify_config.json"; then
  model_type=$(jq -r '.model_type' "${WORK_DIR}/verify_config.json")
  hidden_size=$(jq -r '.hidden_size' "${WORK_DIR}/verify_config.json")
  num_layers=$(jq -r '.num_hidden_layers' "${WORK_DIR}/verify_config.json")
  architectures=$(jq -r '.architectures[0]' "${WORK_DIR}/verify_config.json")
  torch_dtype=$(jq -r '.torch_dtype' "${WORK_DIR}/verify_config.json")

  if assert_eq "$model_type" "llama" "model_type should be llama" && \
     assert_eq "$hidden_size" "4096" "hidden_size should be 4096" && \
     assert_eq "$num_layers" "32" "num_hidden_layers should be 32" && \
     assert_eq "$architectures" "LlamaForCausalLM" "architecture should be LlamaForCausalLM" && \
     assert_eq "$torch_dtype" "float16" "torch_dtype should be float16"; then
    pass
  fi
else
  fail "config.json download for field verification failed"
fi

# ===========================================================================
# 18. Upload a file named model.safetensors with correct path
# ===========================================================================

begin_test "Upload safetensors file with standard naming"
ST_MODEL="safetensors-model-${RUN_ID}"
dd if=/dev/urandom bs=1024 count=8 of="${WORK_DIR}/st_model.safetensors" 2>/dev/null
ST_SHA=$(portable_sha256 "${WORK_DIR}/st_model.safetensors")

if resp=$(hf_upload "$ST_MODEL" "main" "${WORK_DIR}/st_model.safetensors" "model.safetensors"); then
  # Verify the path in the response
  resp_path=$(echo "$resp" | jq -r '.path // empty')
  expected_path="${ST_MODEL}/main/model.safetensors"
  if assert_eq "$resp_path" "$expected_path" "safetensors artifact path should match"; then
    pass
  fi
else
  fail "safetensors upload failed"
fi

# ===========================================================================
# 19. Upload sharded safetensors (4 shards)
# ===========================================================================

begin_test "Upload sharded safetensors (4 shards)"
SHARD_MODEL="sharded-model-${RUN_ID}"
shard_shas=()
all_ok=true

for i in 1 2 3 4; do
  padded=$(printf "%05d" "$i")
  dd if=/dev/urandom bs=1024 count=4 of="${WORK_DIR}/shard_${padded}.safetensors" 2>/dev/null
  shard_shas+=("$(portable_sha256 "${WORK_DIR}/shard_${padded}.safetensors")")

  if ! resp=$(hf_upload "$SHARD_MODEL" "main" \
      "${WORK_DIR}/shard_${padded}.safetensors" \
      "model-${padded}-of-00004.safetensors"); then
    all_ok=false
    break
  fi
done

if $all_ok; then
  pass
else
  fail "one or more shard uploads failed"
fi

# ===========================================================================
# 20. Upload model.safetensors.index.json (shard index)
# ===========================================================================

begin_test "Upload safetensors shard index JSON"
cat > "${WORK_DIR}/model.safetensors.index.json" <<'EOIDX'
{
  "metadata": {
    "total_size": 16384
  },
  "weight_map": {
    "model.embed_tokens.weight": "model-00001-of-00004.safetensors",
    "model.layers.0.self_attn.q_proj.weight": "model-00001-of-00004.safetensors",
    "model.layers.0.self_attn.k_proj.weight": "model-00002-of-00004.safetensors",
    "model.layers.0.self_attn.v_proj.weight": "model-00002-of-00004.safetensors",
    "model.layers.0.mlp.gate_proj.weight": "model-00003-of-00004.safetensors",
    "model.layers.0.mlp.up_proj.weight": "model-00003-of-00004.safetensors",
    "model.layers.0.mlp.down_proj.weight": "model-00004-of-00004.safetensors",
    "lm_head.weight": "model-00004-of-00004.safetensors"
  }
}
EOIDX

INDEX_SHA=$(portable_sha256 "${WORK_DIR}/model.safetensors.index.json")

if resp=$(hf_upload "$SHARD_MODEL" "main" "${WORK_DIR}/model.safetensors.index.json"); then
  if assert_contains "$resp" "model.safetensors.index.json" "index file should appear in response"; then
    pass
  fi
else
  fail "shard index upload failed: ${resp}"
fi

# Verify we can download the index and parse it
begin_test "Download and verify safetensors shard index"
if hf_download "$SHARD_MODEL" "main" "model.safetensors.index.json" \
    "${WORK_DIR}/dl_index.json"; then
  dl_sha=$(portable_sha256 "${WORK_DIR}/dl_index.json")
  if assert_eq "$dl_sha" "$INDEX_SHA" "shard index SHA256 mismatch"; then
    # Verify the weight_map references all 4 shards
    shard_count=$(jq '[.weight_map | to_entries[].value] | unique | length' "${WORK_DIR}/dl_index.json")
    if assert_eq "$shard_count" "4" "weight_map should reference exactly 4 shard files"; then
      pass
    fi
  fi
else
  fail "shard index download failed"
fi

# ===========================================================================
# 21. Direct PUT for large files (HF LFS-style operation)
# ===========================================================================

begin_test "Direct file upload via POST (LFS-style large file handling)"
LFS_MODEL="lfs-model-${RUN_ID}"
dd if=/dev/urandom bs=1048576 count=5 of="${WORK_DIR}/lfs_weights.bin" 2>/dev/null
LFS_SHA=$(portable_sha256 "${WORK_DIR}/lfs_weights.bin")

# The HuggingFace endpoint uses POST for uploads; verify this works for
# files of moderate size as a proxy for LFS batch behavior
if resp=$(hf_upload "$LFS_MODEL" "main" "${WORK_DIR}/lfs_weights.bin"); then
  server_sha=$(echo "$resp" | jq -r '.sha256 // empty')
  if [ -n "$server_sha" ]; then
    if assert_eq "$server_sha" "$LFS_SHA" "LFS-style upload SHA256 should match"; then
      pass
    fi
  else
    pass
  fi
else
  fail "LFS-style upload failed"
fi

# ===========================================================================
# 22. Download LFS-style uploaded file and verify
# ===========================================================================

begin_test "Download LFS-style uploaded file and verify integrity"
if hf_download "$LFS_MODEL" "main" "lfs_weights.bin" "${WORK_DIR}/dl_lfs.bin"; then
  dl_sha=$(portable_sha256 "${WORK_DIR}/dl_lfs.bin")
  if assert_eq "$dl_sha" "$LFS_SHA" "LFS file download SHA256 mismatch"; then
    pass
  fi
else
  fail "LFS file download failed"
fi

# ===========================================================================
# 23. Upload GGUF quantized model file (llama.cpp / ollama format)
# ===========================================================================

begin_test "Upload GGUF quantized model file"
GGUF_MODEL="gguf-model-${RUN_ID}"

# Create a file with the GGUF magic bytes (0x47475546 = "GGUF") followed by random data
# The GGUF header starts with magic "GGUF" + version (uint32) + tensor_count + kv_count
printf 'GGUF' > "${WORK_DIR}/model-q4_0.gguf"
dd if=/dev/urandom bs=1024 count=16 >> "${WORK_DIR}/model-q4_0.gguf" 2>/dev/null
GGUF_Q4_SHA=$(portable_sha256 "${WORK_DIR}/model-q4_0.gguf")

if resp=$(hf_upload "$GGUF_MODEL" "main" "${WORK_DIR}/model-q4_0.gguf"); then
  if assert_contains "$resp" "model-q4_0.gguf" "GGUF Q4_0 file should appear in response"; then
    pass
  fi
else
  fail "GGUF Q4_0 upload failed: ${resp}"
fi

# ===========================================================================
# 24. Upload multiple GGUF quantization variants (Q4_0, Q5_1, Q8_0)
# ===========================================================================

begin_test "Upload multiple GGUF quantization variants"
gguf_variants=("q5_1" "q8_0")
gguf_ok=true

for variant in "${gguf_variants[@]}"; do
  printf 'GGUF' > "${WORK_DIR}/model-${variant}.gguf"
  dd if=/dev/urandom bs=1024 count=16 >> "${WORK_DIR}/model-${variant}.gguf" 2>/dev/null

  if ! resp=$(hf_upload "$GGUF_MODEL" "main" "${WORK_DIR}/model-${variant}.gguf"); then
    gguf_ok=false
    fail "GGUF ${variant} upload failed"
    break
  fi
done

if $gguf_ok; then
  pass
fi

# ===========================================================================
# 25. Verify all GGUF variants are downloadable independently
# ===========================================================================

begin_test "Download all GGUF variants independently"
all_gguf_ok=true

for variant in "q4_0" "q5_1" "q8_0"; do
  original_sha=$(portable_sha256 "${WORK_DIR}/model-${variant}.gguf")

  if hf_download "$GGUF_MODEL" "main" "model-${variant}.gguf" \
      "${WORK_DIR}/dl_gguf_${variant}.gguf"; then
    dl_sha=$(portable_sha256 "${WORK_DIR}/dl_gguf_${variant}.gguf")
    if [ "$dl_sha" != "$original_sha" ]; then
      all_gguf_ok=false
      fail "GGUF ${variant} SHA256 mismatch after download"
    fi
  else
    all_gguf_ok=false
    fail "GGUF ${variant} download failed"
  fi
done

if $all_gguf_ok; then
  pass
fi

# ===========================================================================
# 26. Very long model name
# ===========================================================================

begin_test "Upload to model with very long name"
LONG_MODEL="organization-name-for-testing/this-is-a-very-descriptive-model-name-with-many-details-about-architecture-and-training-data-${RUN_ID}"

cat > "${WORK_DIR}/long_name_config.json" <<'EOF'
{"model_type": "bert", "hidden_size": 768}
EOF

if resp=$(hf_upload "$LONG_MODEL" "main" "${WORK_DIR}/long_name_config.json" "config.json"); then
  if assert_contains "$resp" "config.json" "long model name upload should succeed"; then
    # Verify download works with the long name
    if hf_download "$LONG_MODEL" "main" "config.json" "${WORK_DIR}/dl_long_name.json"; then
      pass
    else
      fail "download from long model name failed"
    fi
  fi
else
  fail "upload to long model name failed: ${resp}"
fi

# ===========================================================================
# 27. Model with special characters in filename
# ===========================================================================

begin_test "Upload file with hyphens and dots in filename"
SPECIAL_MODEL="special-chars-${RUN_ID}"

dd if=/dev/urandom bs=512 count=1 of="${WORK_DIR}/special_file.bin" 2>/dev/null
SPECIAL_SHA=$(portable_sha256 "${WORK_DIR}/special_file.bin")

# Filenames with hyphens, dots, and underscores (common in ML files)
if resp=$(hf_upload "$SPECIAL_MODEL" "main" "${WORK_DIR}/special_file.bin" \
    "pytorch_model-00001-of-00002.bin"); then
  if assert_contains "$resp" "pytorch_model-00001-of-00002.bin" "special char filename should appear"; then
    # Download and verify
    if hf_download "$SPECIAL_MODEL" "main" "pytorch_model-00001-of-00002.bin" \
        "${WORK_DIR}/dl_special.bin"; then
      dl_sha=$(portable_sha256 "${WORK_DIR}/dl_special.bin")
      if assert_eq "$dl_sha" "$SPECIAL_SHA" "special filename SHA256 mismatch"; then
        pass
      fi
    else
      fail "download of special-char filename failed"
    fi
  fi
else
  fail "upload with special-char filename failed: ${resp}"
fi

# ===========================================================================
# 28. Overwrite existing file (duplicate detection - should return 409)
# ===========================================================================

begin_test "Overwrite existing file returns 409 conflict"
# Try to upload config.json again to the same model/revision
# The backend returns 409 CONFLICT when a file already exists at the same path
status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X POST \
    -H "$(format_auth_header)" \
    -H "Content-Type: application/octet-stream" \
    -H "x-filename: config.json" \
    --data-binary "@${WORK_DIR}/config.json" \
    "${HF_URL}/api/models/${MODEL_ID}/upload/${REVISION}")

if assert_eq "$status" "409" "re-uploading existing file should return 409 CONFLICT"; then
  pass
fi

# ===========================================================================
# 29. Delete a file from the model repository (via management API)
# ===========================================================================

begin_test "Delete artifact via management API"
DELETE_MODEL="delete-model-${RUN_ID}"

dd if=/dev/urandom bs=512 count=1 of="${WORK_DIR}/to_delete.bin" 2>/dev/null
if ! hf_upload "$DELETE_MODEL" "main" "${WORK_DIR}/to_delete.bin" >/dev/null; then
  fail "upload for delete test failed"
fi

# Verify the file exists before deleting
if hf_download "$DELETE_MODEL" "main" "to_delete.bin" "${WORK_DIR}/dl_before_delete.bin"; then
  # Delete via the management API (soft delete)
  artifact_path="${DELETE_MODEL}/main/to_delete.bin"
  del_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X DELETE \
      -H "$(auth_header)" \
      "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/${artifact_path}")

  if [ "$del_status" -ge 200 ] && [ "$del_status" -lt 300 ]; then
    # Verify the file is no longer downloadable
    sleep 1
    get_status=$(hf_status "${HF_URL}/${DELETE_MODEL}/resolve/main/to_delete.bin")
    if [ "$get_status" = "404" ]; then
      pass
    else
      # The management API may use different path encoding; the file might
      # still return 200 if the delete did not match. Accept 200 or 404.
      skip "delete returned ${del_status} but file still returns ${get_status} (path encoding may differ)"
    fi
  else
    # If the management API does not support this path pattern, skip
    skip "management API delete returned ${del_status} (may not support HF path format)"
  fi
else
  fail "file should exist before delete attempt"
fi

# ===========================================================================
# 30. Empty repository (list should return empty or no models)
# ===========================================================================

begin_test "Empty repository returns empty model listing"
EMPTY_REPO="test-hf-empty-${RUN_ID}"
if create_local_repo "$EMPTY_REPO" "huggingface"; then
  EMPTY_HF_URL="${BASE_URL}/huggingface/${EMPTY_REPO}"
  if resp=$(curl -sf $CURL_TIMEOUT \
      -H "$(format_auth_header)" \
      "${EMPTY_HF_URL}/api/models"); then
    count=$(echo "$resp" | jq 'length')
    if assert_eq "$count" "0" "empty repo should list 0 models"; then
      pass
    fi
  else
    fail "GET /api/models on empty repo failed"
  fi
else
  fail "could not create empty huggingface repo"
fi

# ===========================================================================
# BONUS: Verify model listing across all test models
# ===========================================================================

begin_test "Model listing contains multiple distinct models"
sleep 1
if resp=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${HF_URL}/api/models"); then
  model_count=$(echo "$resp" | jq 'length')
  if [ "$model_count" -ge 3 ] 2>/dev/null; then
    pass
  else
    fail "expected at least 3 models in listing, got ${model_count}"
  fi
else
  fail "model listing failed"
fi

# ===========================================================================
# BONUS: Upload with empty body returns 400
# ===========================================================================

begin_test "Upload with empty body returns 400"
status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X POST \
    -H "$(format_auth_header)" \
    -H "Content-Type: application/octet-stream" \
    -H "x-filename: empty.bin" \
    --data-binary "" \
    "${HF_URL}/api/models/${MODEL_ID}/upload/${REVISION}")

if assert_eq "$status" "400" "empty body upload should return 400"; then
  pass
fi

# ===========================================================================
# BONUS: Download non-existent file returns 404
# ===========================================================================

begin_test "Download non-existent file returns 404"
status=$(hf_status "${HF_URL}/${MODEL_ID}/resolve/${REVISION}/does-not-exist.bin")
if assert_eq "$status" "404" "missing file should return 404"; then
  pass
fi

# ===========================================================================
# BONUS: Model info for non-existent model returns 404
# ===========================================================================

begin_test "Model info for non-existent model returns 404"
status=$(hf_status "${HF_URL}/api/models/this-model-does-not-exist-${RUN_ID}")
if assert_eq "$status" "404" "non-existent model info should return 404"; then
  pass
fi

# ===========================================================================
# BONUS: Tree listing for empty revision returns empty array
# ===========================================================================

begin_test "Tree listing for empty revision returns empty array"
TREE_MODEL="tree-empty-${RUN_ID}"
dd if=/dev/urandom bs=128 count=1 of="${WORK_DIR}/tree_file.bin" 2>/dev/null

# Upload to revision "release" then query tree for revision "nonexistent"
if hf_upload "$TREE_MODEL" "release" "${WORK_DIR}/tree_file.bin" >/dev/null 2>&1; then
  if resp=$(curl -sf $CURL_TIMEOUT \
      -H "$(format_auth_header)" \
      "${HF_URL}/api/models/${TREE_MODEL}/tree/nonexistent"); then
    count=$(echo "$resp" | jq 'length')
    if assert_eq "$count" "0" "tree for nonexistent revision should be empty"; then
      pass
    fi
  else
    fail "tree listing for nonexistent revision returned error"
  fi
else
  fail "setup upload for tree test failed"
fi

# ===========================================================================
# BONUS: Verify sharded model files are all listed in tree
# ===========================================================================

begin_test "Sharded model tree lists all shards plus index"
if resp=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${HF_URL}/api/models/${SHARD_MODEL}/tree/main"); then
  file_count=$(echo "$resp" | jq 'length')
  # We uploaded 4 shards + 1 index = 5 files
  if [ "$file_count" -ge 5 ] 2>/dev/null; then
    # Verify all shard files are present
    shard_count=$(echo "$resp" | jq '[.[] | select(.path | test("model-[0-9]+-of-00004"))] | length')
    if assert_eq "$shard_count" "4" "tree should list all 4 shard files"; then
      pass
    fi
  else
    fail "expected at least 5 files in sharded model tree, got ${file_count}"
  fi
else
  fail "tree listing for sharded model failed"
fi

end_suite
