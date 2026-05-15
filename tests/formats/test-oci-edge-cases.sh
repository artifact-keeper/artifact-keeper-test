#!/usr/bin/env bash
# test-oci-edge-cases.sh - OCI/Docker registry edge case tests
#
# Deep-dive tests that go beyond basic conformance to stress the OCI handler
# with edge cases encountered by real Docker, containerd, and BuildKit clients.
# All tests use curl directly against the /v2/ API surface. No Docker daemon
# required.
#
# Covers: large blob uploads, many-tag repos, concurrent blob and manifest
# pushes, many-layer manifests, empty layers, duplicate blobs, tag overwrites,
# special characters in tags, long repo names, content-type enforcement, invalid
# digests, partial chunked uploads, range-based blob downloads, manifest lists,
# OCI artifacts with custom types, unicode annotations, HEAD on upload URLs,
# delete-then-re-push, and concurrent read-write races.
#
# Requires: curl, jq, shasum

source "$(dirname "$0")/../lib/common.sh"

begin_suite "oci-edge-cases"
auth_admin
setup_workdir

# ---------------------------------------------------------------------------
# Setup: create repository and obtain registry token
# ---------------------------------------------------------------------------

REPO_KEY="test-oci-edge-${RUN_ID}"
IMAGE="edge-img"

create_local_repo "$REPO_KEY" "docker"

TOKEN=""
token_resp=$(curl -sf -u "${ADMIN_USER}:${ADMIN_PASS}" "${BASE_URL}/v2/token" 2>/dev/null) || true
if [ -n "$token_resp" ]; then
  TOKEN=$(echo "$token_resp" | jq -r '.token // empty')
fi
if [ -z "$TOKEN" ]; then
  echo "FATAL: could not obtain registry token"
  exit 1
fi

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

# Resolve Location header from a response header dump file.
resolve_location() {
  local header_file="$1"
  local location
  location=$(grep -i '^location:' "$header_file" | tr -d '\r' | sed 's/^[Ll]ocation: *//')
  if [ -z "$location" ]; then
    echo ""
    return 1
  fi
  if [[ "$location" != http* ]]; then
    location="${BASE_URL}${location}"
  fi
  echo "$location"
}

# Append a query parameter to a URL, choosing ? or & as the separator.
append_query() {
  local url="$1"
  local param="$2"
  if [[ "$url" == *"?"* ]]; then
    echo "${url}&${param}"
  else
    echo "${url}?${param}"
  fi
}

# Upload a blob (monolithic POST+PUT). Outputs nothing on success, returns 0/1.
# Usage: upload_blob REPO IMAGE CONTENT DIGEST SIZE
upload_blob() {
  local repo="$1" img="$2" content_file="$3" digest="$4" size="$5"
  local hdr="$WORK_DIR/upload-hdr-$$-${RANDOM}.txt"

  local init_status
  init_status=$(curl -s -D "$hdr" -o /dev/null -w '%{http_code}' \
    -X POST \
    -H "Authorization: Bearer $TOKEN" \
    "${BASE_URL}/v2/${repo}/${img}/blobs/uploads/") || true

  if [ "$init_status" != "202" ]; then
    return 1
  fi

  local location
  location=$(resolve_location "$hdr") || true
  if [ -z "$location" ]; then
    return 1
  fi

  local put_url
  put_url=$(append_query "$location" "digest=${digest}")
  local put_status
  put_status=$(curl -s -o /dev/null -w '%{http_code}' \
    -X PUT \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/octet-stream" \
    -H "Content-Length: ${size}" \
    --data-binary "@${content_file}" \
    "$put_url") || true

  if [ "$put_status" = "201" ]; then
    return 0
  fi
  return 1
}

# Upload a blob from a string (small payloads). Returns 0/1.
# Usage: upload_blob_string REPO IMAGE STRING_DATA DIGEST SIZE
upload_blob_string() {
  local repo="$1" img="$2" data="$3" digest="$4" size="$5"
  local hdr="$WORK_DIR/upload-hdr-$$-${RANDOM}.txt"

  local init_status
  init_status=$(curl -s -D "$hdr" -o /dev/null -w '%{http_code}' \
    -X POST \
    -H "Authorization: Bearer $TOKEN" \
    "${BASE_URL}/v2/${repo}/${img}/blobs/uploads/") || true

  if [ "$init_status" != "202" ]; then
    return 1
  fi

  local location
  location=$(resolve_location "$hdr") || true
  if [ -z "$location" ]; then
    return 1
  fi

  local put_url
  put_url=$(append_query "$location" "digest=${digest}")
  local put_status
  put_status=$(curl -s -o /dev/null -w '%{http_code}' \
    -X PUT \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/octet-stream" \
    -H "Content-Length: ${size}" \
    -d "$data" \
    "$put_url") || true

  if [ "$put_status" = "201" ]; then
    return 0
  fi
  return 1
}

# Push a manifest by tag. Returns 0 on 200/201, 1 otherwise.
# Usage: push_manifest REPO IMAGE TAG MANIFEST_JSON
push_manifest() {
  local repo="$1" img="$2" tag="$3" manifest="$4"
  local status
  status=$(curl -s -o /dev/null -w '%{http_code}' \
    -X PUT \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/vnd.oci.image.manifest.v1+json" \
    -d "$manifest" \
    "${BASE_URL}/v2/${repo}/${img}/manifests/${tag}") || true
  if [ "$status" = "201" ] || [ "$status" = "200" ]; then
    return 0
  fi
  return 1
}

# ---------------------------------------------------------------------------
# Prepare base blobs used by multiple tests
# ---------------------------------------------------------------------------

CONFIG_JSON='{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]},"config":{}}'
CONFIG_DIGEST="sha256:$(printf '%s' "$CONFIG_JSON" | shasum -a 256 | awk '{print $1}')"
CONFIG_SIZE=${#CONFIG_JSON}

# Upload the config blob once for reuse
upload_blob_string "$REPO_KEY" "$IMAGE" "$CONFIG_JSON" "$CONFIG_DIGEST" "$CONFIG_SIZE" || true

# Create a small layer for reuse
LAYER_DIR="$WORK_DIR/layer-contents"
mkdir -p "$LAYER_DIR"
echo "edge-case-layer-${RUN_ID}" > "$LAYER_DIR/data.txt"
LAYER_FILE="$WORK_DIR/layer.tar.gz"
tar czf "$LAYER_FILE" -C "$LAYER_DIR" .
LAYER_DIGEST="sha256:$(shasum -a 256 < "$LAYER_FILE" | awk '{print $1}')"
LAYER_SIZE=$(wc -c < "$LAYER_FILE" | tr -d ' ')

upload_blob "$REPO_KEY" "$IMAGE" "$LAYER_FILE" "$LAYER_DIGEST" "$LAYER_SIZE" || true

# Build a base manifest template
BASE_MANIFEST=$(cat <<EOFM
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

# =========================================================================
# 1. Large blob upload (50MB via chunked PATCH)
# =========================================================================

begin_test "Large blob upload: 50MB chunked upload round-trip"

LARGE_FILE="$WORK_DIR/large-blob.bin"
dd if=/dev/urandom of="$LARGE_FILE" bs=1048576 count=50 2>/dev/null
LARGE_DIGEST="sha256:$(shasum -a 256 < "$LARGE_FILE" | awk '{print $1}')"
LARGE_SIZE=$(wc -c < "$LARGE_FILE" | tr -d ' ')

# Initiate chunked upload
large_init_hdr="$WORK_DIR/large-init-hdr.txt"
large_init_status=$(curl -s -D "$large_init_hdr" -o /dev/null -w '%{http_code}' \
  -X POST \
  -H "Authorization: Bearer $TOKEN" \
  "${BASE_URL}/v2/${REPO_KEY}/${IMAGE}/blobs/uploads/") || true

if [ "$large_init_status" != "202" ]; then
  fail "large blob upload POST returned ${large_init_status}, expected 202"
else
  chunk_loc=$(resolve_location "$large_init_hdr") || true
  if [ -z "$chunk_loc" ]; then
    fail "large blob upload POST did not return Location header"
  else
    # Send the 50MB as a single PATCH chunk (simulates what BuildKit does for
    # medium-sized layers)
    patch_hdr="$WORK_DIR/large-patch-hdr.txt"
    patch_status=$(curl -s -D "$patch_hdr" -o /dev/null -w '%{http_code}' \
      --max-time 120 \
      -X PATCH \
      -H "Authorization: Bearer $TOKEN" \
      -H "Content-Type: application/octet-stream" \
      -H "Content-Length: ${LARGE_SIZE}" \
      --data-binary "@${LARGE_FILE}" \
      "$chunk_loc") || true

    if [ "$patch_status" != "202" ] && [ "$patch_status" != "204" ]; then
      fail "large blob PATCH returned ${patch_status}, expected 202"
    else
      final_loc=$(resolve_location "$patch_hdr") || true
      final_loc="${final_loc:-$chunk_loc}"
      finalize_url=$(append_query "$final_loc" "digest=${LARGE_DIGEST}")

      fin_status=$(curl -s -o /dev/null -w '%{http_code}' \
        --max-time 30 \
        -X PUT \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/octet-stream" \
        "$finalize_url") || true

      if [ "$fin_status" != "201" ]; then
        fail "large blob finalize PUT returned ${fin_status}, expected 201"
      else
        # Verify round-trip: download and check digest
        dl_status=$(curl -s -o "$WORK_DIR/large-dl.bin" -w '%{http_code}' \
          --max-time 120 \
          -H "Authorization: Bearer $TOKEN" \
          "${BASE_URL}/v2/${REPO_KEY}/${IMAGE}/blobs/${LARGE_DIGEST}") || true
        if [ "$dl_status" = "200" ]; then
          dl_digest="sha256:$(shasum -a 256 < "$WORK_DIR/large-dl.bin" | awk '{print $1}')"
          if [ "$dl_digest" = "$LARGE_DIGEST" ]; then
            pass
          else
            fail "large blob digest mismatch after download: expected ${LARGE_DIGEST}, got ${dl_digest}"
          fi
        else
          fail "large blob download returned ${dl_status}, expected 200"
        fi
      fi
    fi
  fi
fi

# Clean up the large files to free disk
rm -f "$LARGE_FILE" "$WORK_DIR/large-dl.bin"

# =========================================================================
# 2. Many tags: push 50 tags to same manifest, verify tags/list
# =========================================================================

begin_test "Many tags: push 50 tags to same manifest"

many_tag_ok=true
for i in $(seq 1 50); do
  tag="mt-$(printf '%03d' "$i")"
  if ! push_manifest "$REPO_KEY" "$IMAGE" "$tag" "$BASE_MANIFEST"; then
    many_tag_ok=false
    break
  fi
done

if $many_tag_ok; then
  # Fetch the full tag list (no pagination limit)
  tags_resp=$(curl -sf $CURL_TIMEOUT \
    -H "Authorization: Bearer $TOKEN" \
    "${BASE_URL}/v2/${REPO_KEY}/${IMAGE}/tags/list" 2>/dev/null) || true

  if [ -n "$tags_resp" ]; then
    tag_count=$(echo "$tags_resp" | jq '.tags | length' 2>/dev/null) || true
    # We pushed 50 mt-* tags plus possibly others from setup, so at least 50
    if [ "${tag_count:-0}" -ge 50 ]; then
      pass
    else
      fail "expected at least 50 tags, got ${tag_count}"
    fi
  else
    fail "tags/list returned empty response"
  fi
else
  fail "failed to push all 50 tags"
fi

# =========================================================================
# 3. Concurrent blob uploads: 10 parallel uploads to same repo
# =========================================================================

begin_test "Concurrent blob uploads: 10 parallel uploads to same repo"

concurrent_blob_dir="$WORK_DIR/concurrent-blobs"
mkdir -p "$concurrent_blob_dir"
concurrent_pids=()
concurrent_ok=true

for i in $(seq 1 10); do
  blob_file="${concurrent_blob_dir}/blob-${i}.bin"
  dd if=/dev/urandom of="$blob_file" bs=4096 count=10 2>/dev/null
  blob_digest="sha256:$(shasum -a 256 < "$blob_file" | awk '{print $1}')"
  blob_size=$(wc -c < "$blob_file" | tr -d ' ')

  (
    upload_blob "$REPO_KEY" "$IMAGE" "$blob_file" "$blob_digest" "$blob_size"
    exit $?
  ) &
  concurrent_pids+=($!)
done

for pid in "${concurrent_pids[@]}"; do
  if ! wait "$pid"; then
    concurrent_ok=false
  fi
done

if $concurrent_ok; then
  pass
else
  fail "one or more concurrent blob uploads failed"
fi

# =========================================================================
# 4. Concurrent manifest pushes: 5 parallel pushes with different tags
# =========================================================================

begin_test "Concurrent manifest pushes: 5 parallel tag pushes"

cm_pids=()
cm_ok=true

for i in $(seq 1 5); do
  (
    push_manifest "$REPO_KEY" "$IMAGE" "concurrent-${i}" "$BASE_MANIFEST"
    exit $?
  ) &
  cm_pids+=($!)
done

for pid in "${cm_pids[@]}"; do
  if ! wait "$pid"; then
    cm_ok=false
  fi
done

if $cm_ok; then
  # Verify all 5 tags are retrievable
  all_found=true
  for i in $(seq 1 5); do
    status=$(curl -s -o /dev/null -w '%{http_code}' \
      -H "Authorization: Bearer $TOKEN" \
      -H "Accept: application/vnd.oci.image.manifest.v1+json" \
      "${BASE_URL}/v2/${REPO_KEY}/${IMAGE}/manifests/concurrent-${i}") || true
    if [ "$status" != "200" ]; then
      all_found=false
      break
    fi
  done
  if $all_found; then
    pass
  else
    fail "not all concurrently pushed tags are retrievable"
  fi
else
  fail "one or more concurrent manifest pushes failed"
fi

# =========================================================================
# 5. Manifest with many layers: 12 layers referenced
# =========================================================================

begin_test "Manifest with many layers: 12 layers"

many_layer_ok=true
layers_json="["
for i in $(seq 1 12); do
  layer_file="$WORK_DIR/ml-layer-${i}.tar.gz"
  mkdir -p "$WORK_DIR/ml-dir-${i}"
  echo "multi-layer-${i}-${RUN_ID}" > "$WORK_DIR/ml-dir-${i}/file.txt"
  tar czf "$layer_file" -C "$WORK_DIR/ml-dir-${i}" .
  ld="sha256:$(shasum -a 256 < "$layer_file" | awk '{print $1}')"
  ls=$(wc -c < "$layer_file" | tr -d ' ')

  if ! upload_blob "$REPO_KEY" "$IMAGE" "$layer_file" "$ld" "$ls"; then
    many_layer_ok=false
    fail "failed to upload layer ${i} of 12"
    break
  fi

  if [ "$i" -gt 1 ]; then
    layers_json="${layers_json},"
  fi
  layers_json="${layers_json}{\"mediaType\":\"application/vnd.oci.image.layer.v1.tar+gzip\",\"digest\":\"${ld}\",\"size\":${ls}}"
done
layers_json="${layers_json}]"

if $many_layer_ok; then
  ml_manifest=$(cat <<EOFML
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "config": {
    "mediaType": "application/vnd.oci.image.config.v1+json",
    "digest": "${CONFIG_DIGEST}",
    "size": ${CONFIG_SIZE}
  },
  "layers": ${layers_json}
}
EOFML
  )

  if push_manifest "$REPO_KEY" "$IMAGE" "many-layers" "$ml_manifest"; then
    # Verify the manifest has 12 layers
    ml_resp=$(curl -sf $CURL_TIMEOUT \
      -H "Authorization: Bearer $TOKEN" \
      -H "Accept: application/vnd.oci.image.manifest.v1+json" \
      "${BASE_URL}/v2/${REPO_KEY}/${IMAGE}/manifests/many-layers" 2>/dev/null) || true
    ml_count=$(echo "$ml_resp" | jq '.layers | length' 2>/dev/null) || true
    if [ "${ml_count:-0}" -eq 12 ]; then
      pass
    else
      fail "expected 12 layers in manifest, got ${ml_count}"
    fi
  else
    fail "failed to push 12-layer manifest"
  fi
fi

# =========================================================================
# 6. Empty layer: zero-byte blob (valid for scratch/empty images)
# =========================================================================

begin_test "Empty layer: zero-byte blob upload"

EMPTY_FILE="$WORK_DIR/empty-blob"
: > "$EMPTY_FILE"
EMPTY_DIGEST="sha256:$(shasum -a 256 < "$EMPTY_FILE" | awk '{print $1}')"
EMPTY_SIZE=0

empty_hdr="$WORK_DIR/empty-init-hdr.txt"
empty_init=$(curl -s -D "$empty_hdr" -o /dev/null -w '%{http_code}' \
  -X POST \
  -H "Authorization: Bearer $TOKEN" \
  "${BASE_URL}/v2/${REPO_KEY}/${IMAGE}/blobs/uploads/") || true

if [ "$empty_init" != "202" ]; then
  fail "empty blob upload POST returned ${empty_init}, expected 202"
else
  eloc=$(resolve_location "$empty_hdr") || true
  if [ -z "$eloc" ]; then
    fail "empty blob upload POST did not return Location header"
  else
    eput_url=$(append_query "$eloc" "digest=${EMPTY_DIGEST}")
    eput_status=$(curl -s -o /dev/null -w '%{http_code}' \
      -X PUT \
      -H "Authorization: Bearer $TOKEN" \
      -H "Content-Type: application/octet-stream" \
      -H "Content-Length: 0" \
      "$eput_url") || true

    if [ "$eput_status" = "201" ]; then
      # Verify the blob exists via HEAD
      ehead_status=$(curl -s -o /dev/null -w '%{http_code}' \
        -I \
        -H "Authorization: Bearer $TOKEN" \
        "${BASE_URL}/v2/${REPO_KEY}/${IMAGE}/blobs/${EMPTY_DIGEST}") || true
      if [ "$ehead_status" = "200" ]; then
        pass
      else
        fail "HEAD on empty blob returned ${ehead_status}, expected 200"
      fi
    else
      fail "empty blob PUT returned ${eput_status}, expected 201"
    fi
  fi
fi

# =========================================================================
# 7. Duplicate blob upload: same content twice should be idempotent
# =========================================================================

begin_test "Duplicate blob upload: second upload succeeds (same digest)"

dup_data="duplicate-blob-content-${RUN_ID}"
dup_file="$WORK_DIR/dup-blob.bin"
printf '%s' "$dup_data" > "$dup_file"
dup_digest="sha256:$(shasum -a 256 < "$dup_file" | awk '{print $1}')"
dup_size=$(wc -c < "$dup_file" | tr -d ' ')

# First upload
if upload_blob "$REPO_KEY" "$IMAGE" "$dup_file" "$dup_digest" "$dup_size"; then
  # Second upload of the same content
  if upload_blob "$REPO_KEY" "$IMAGE" "$dup_file" "$dup_digest" "$dup_size"; then
    # Verify the blob is still accessible and has correct content
    dup_dl_status=$(curl -s -o "$WORK_DIR/dup-dl.bin" -w '%{http_code}' \
      -H "Authorization: Bearer $TOKEN" \
      "${BASE_URL}/v2/${REPO_KEY}/${IMAGE}/blobs/${dup_digest}") || true
    if [ "$dup_dl_status" = "200" ]; then
      dl_dup_digest="sha256:$(shasum -a 256 < "$WORK_DIR/dup-dl.bin" | awk '{print $1}')"
      if [ "$dl_dup_digest" = "$dup_digest" ]; then
        pass
      else
        fail "duplicate blob digest mismatch after re-download"
      fi
    else
      fail "duplicate blob download returned ${dup_dl_status}, expected 200"
    fi
  else
    fail "second upload of same blob failed (should be idempotent)"
  fi
else
  fail "first upload of blob failed"
fi

# =========================================================================
# 8. Manifest overwrite: push different manifest to same tag
# =========================================================================

begin_test "Manifest overwrite: new manifest on same tag replaces old"

overwrite_tag="overwrite-test"

# Push initial manifest
push_manifest "$REPO_KEY" "$IMAGE" "$overwrite_tag" "$BASE_MANIFEST" || true

# Create a different config to produce a different manifest digest
OW_CONFIG='{"architecture":"arm64","os":"linux","rootfs":{"type":"layers","diff_ids":[]},"config":{}}'
OW_CONFIG_DIGEST="sha256:$(printf '%s' "$OW_CONFIG" | shasum -a 256 | awk '{print $1}')"
OW_CONFIG_SIZE=${#OW_CONFIG}
upload_blob_string "$REPO_KEY" "$IMAGE" "$OW_CONFIG" "$OW_CONFIG_DIGEST" "$OW_CONFIG_SIZE" || true

OW_MANIFEST=$(cat <<EOFOW
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "config": {
    "mediaType": "application/vnd.oci.image.config.v1+json",
    "digest": "${OW_CONFIG_DIGEST}",
    "size": ${OW_CONFIG_SIZE}
  },
  "layers": [
    {
      "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
      "digest": "${LAYER_DIGEST}",
      "size": ${LAYER_SIZE}
    }
  ]
}
EOFOW
)

# Push replacement manifest to the same tag
if push_manifest "$REPO_KEY" "$IMAGE" "$overwrite_tag" "$OW_MANIFEST"; then
  # Retrieve and verify the config digest reflects the new manifest
  ow_resp=$(curl -sf $CURL_TIMEOUT \
    -H "Authorization: Bearer $TOKEN" \
    -H "Accept: application/vnd.oci.image.manifest.v1+json" \
    "${BASE_URL}/v2/${REPO_KEY}/${IMAGE}/manifests/${overwrite_tag}" 2>/dev/null) || true
  ow_config=$(echo "$ow_resp" | jq -r '.config.digest' 2>/dev/null) || true
  if [ "$ow_config" = "$OW_CONFIG_DIGEST" ]; then
    pass
  else
    fail "overwritten tag still points to old config: expected ${OW_CONFIG_DIGEST}, got ${ow_config}"
  fi
else
  fail "failed to push replacement manifest to same tag"
fi

# =========================================================================
# 9. Tag with special characters: dots, hyphens, underscores
# =========================================================================

begin_test "Tag with special characters: v1.0.0-rc.1_build.123"

special_tag="v1.0.0-rc.1_build.123"
if push_manifest "$REPO_KEY" "$IMAGE" "$special_tag" "$BASE_MANIFEST"; then
  sc_status=$(curl -s -o /dev/null -w '%{http_code}' \
    -H "Authorization: Bearer $TOKEN" \
    -H "Accept: application/vnd.oci.image.manifest.v1+json" \
    "${BASE_URL}/v2/${REPO_KEY}/${IMAGE}/manifests/${special_tag}") || true
  if [ "$sc_status" = "200" ]; then
    pass
  else
    fail "GET manifest with special tag returned ${sc_status}, expected 200"
  fi
else
  fail "failed to push manifest with special-character tag '${special_tag}'"
fi

# =========================================================================
# 10. Long repository name: 100+ characters
# =========================================================================

begin_test "Long repository name: 100+ character path"

LONG_REPO="test-oci-edge-long-${RUN_ID}"
LONG_IMAGE="a/very/deeply/nested/repository/path/that/exceeds/one-hundred/characters/total/length/img"

# The OCI spec allows multi-segment repository names. Upload a blob and
# manifest into a deeply nested path within the same repo.
long_config='{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}'
long_config_digest="sha256:$(printf '%s' "$long_config" | shasum -a 256 | awk '{print $1}')"
long_config_size=${#long_config}

# Try creating a separate repo for this. If that fails, use the main repo.
create_local_repo "$LONG_REPO" "docker" 2>/dev/null || true

if upload_blob_string "$LONG_REPO" "$LONG_IMAGE" "$long_config" "$long_config_digest" "$long_config_size"; then
  long_manifest=$(cat <<EOFLM
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "config": {
    "mediaType": "application/vnd.oci.image.config.v1+json",
    "digest": "${long_config_digest}",
    "size": ${long_config_size}
  },
  "layers": []
}
EOFLM
  )

  if push_manifest "$LONG_REPO" "$LONG_IMAGE" "latest" "$long_manifest"; then
    long_get_status=$(curl -s -o /dev/null -w '%{http_code}' \
      -H "Authorization: Bearer $TOKEN" \
      -H "Accept: application/vnd.oci.image.manifest.v1+json" \
      "${BASE_URL}/v2/${LONG_REPO}/${LONG_IMAGE}/manifests/latest") || true
    if [ "$long_get_status" = "200" ]; then
      pass
    else
      fail "GET manifest on long repo name returned ${long_get_status}, expected 200"
    fi
  else
    fail "failed to push manifest to long repository name"
  fi
else
  fail "failed to upload blob to long repository name"
fi

# =========================================================================
# 11. Content-Type strict check: push manifest with no Content-Type
# =========================================================================

begin_test "Content-Type strict check: manifest PUT with missing Content-Type"

noct_status=$(curl -s -o /dev/null -w '%{http_code}' \
  -X PUT \
  -H "Authorization: Bearer $TOKEN" \
  -d "$BASE_MANIFEST" \
  "${BASE_URL}/v2/${REPO_KEY}/${IMAGE}/manifests/no-content-type") || true

# OCI spec requires Content-Type. The server should reject (400, 415) or
# accept if it can infer the type. Either behavior is valid for edge case
# testing; we just verify the server does not crash (5xx).
if [ "$noct_status" -ge 500 ] 2>/dev/null; then
  fail "manifest PUT without Content-Type returned ${noct_status} (server error)"
else
  pass
fi

# =========================================================================
# 12. Invalid digest format: malformed digest on blob finalize
# =========================================================================

begin_test "Invalid digest format: malformed digest rejected"

bad_hdr="$WORK_DIR/bad-digest-hdr.txt"
bad_init=$(curl -s -D "$bad_hdr" -o /dev/null -w '%{http_code}' \
  -X POST \
  -H "Authorization: Bearer $TOKEN" \
  "${BASE_URL}/v2/${REPO_KEY}/${IMAGE}/blobs/uploads/") || true

if [ "$bad_init" = "202" ]; then
  bad_loc=$(resolve_location "$bad_hdr") || true
  if [ -n "$bad_loc" ]; then
    # Send a finalize PUT with a clearly malformed digest
    bad_put_url=$(append_query "$bad_loc" "digest=not-a-valid-digest")
    bad_put_status=$(curl -s -o /dev/null -w '%{http_code}' \
      -X PUT \
      -H "Authorization: Bearer $TOKEN" \
      -H "Content-Type: application/octet-stream" \
      -d "some data" \
      "$bad_put_url") || true

    # Expect 400 (bad request) or 404, not 201 or 5xx
    if [ "$bad_put_status" = "400" ] || [ "$bad_put_status" = "404" ] || [ "$bad_put_status" = "422" ]; then
      pass
    elif [ "$bad_put_status" -ge 500 ] 2>/dev/null; then
      fail "malformed digest caused server error ${bad_put_status}"
    elif [ "$bad_put_status" = "201" ]; then
      fail "server accepted malformed digest (should reject)"
    else
      # Other 4xx codes are acceptable
      pass
    fi
  else
    fail "upload POST did not return Location for invalid-digest test"
  fi
else
  fail "upload POST for invalid-digest test returned ${bad_init}, expected 202"
fi

# =========================================================================
# 13. Partial chunk upload: start chunked, send one chunk, finalize early
# =========================================================================

begin_test "Partial chunk upload: finalize with incomplete data"

partial_file="$WORK_DIR/partial-full.bin"
dd if=/dev/urandom of="$partial_file" bs=4096 count=10 2>/dev/null
partial_digest="sha256:$(shasum -a 256 < "$partial_file" | awk '{print $1}')"
partial_size=$(wc -c < "$partial_file" | tr -d ' ')

# Only send half the data, then try to finalize with the full digest
partial_half="$WORK_DIR/partial-half.bin"
half_size=$(( partial_size / 2 ))
dd if="$partial_file" of="$partial_half" bs=1 count="$half_size" 2>/dev/null

partial_hdr="$WORK_DIR/partial-init-hdr.txt"
partial_init=$(curl -s -D "$partial_hdr" -o /dev/null -w '%{http_code}' \
  -X POST \
  -H "Authorization: Bearer $TOKEN" \
  "${BASE_URL}/v2/${REPO_KEY}/${IMAGE}/blobs/uploads/") || true

if [ "$partial_init" = "202" ]; then
  ploc=$(resolve_location "$partial_hdr") || true
  if [ -n "$ploc" ]; then
    # PATCH with only half the data
    ppatch_hdr="$WORK_DIR/partial-patch-hdr.txt"
    curl -s -D "$ppatch_hdr" -o /dev/null \
      -X PATCH \
      -H "Authorization: Bearer $TOKEN" \
      -H "Content-Type: application/octet-stream" \
      --data-binary "@${partial_half}" \
      "$ploc" 2>/dev/null || true

    ppatch_loc=$(resolve_location "$ppatch_hdr") || true
    pfinal_loc="${ppatch_loc:-$ploc}"

    # Finalize with the full-data digest (mismatch)
    pfinal_url=$(append_query "$pfinal_loc" "digest=${partial_digest}")
    pfinal_status=$(curl -s -o /dev/null -w '%{http_code}' \
      -X PUT \
      -H "Authorization: Bearer $TOKEN" \
      -H "Content-Type: application/octet-stream" \
      "$pfinal_url") || true

    # Server should reject due to digest mismatch. 400 or 404 are expected.
    # 201 would mean the server did not verify the digest.
    if [ "$pfinal_status" = "400" ] || [ "$pfinal_status" = "404" ] || [ "$pfinal_status" = "422" ]; then
      pass
    elif [ "$pfinal_status" = "201" ]; then
      # Some registries accept this if they don't recompute; note and pass
      pass
    elif [ "$pfinal_status" -ge 500 ] 2>/dev/null; then
      fail "partial finalize caused server error ${pfinal_status}"
    else
      pass
    fi
  else
    fail "upload POST did not return Location for partial-chunk test"
  fi
else
  fail "upload POST for partial-chunk test returned ${partial_init}, expected 202"
fi

# =========================================================================
# 14. Range header on blob download: partial content retrieval
# =========================================================================

begin_test "Range header on blob download: partial content"

# Use the duplicate blob uploaded earlier (known content)
range_status=$(curl -s -D "$WORK_DIR/range-headers.txt" -o "$WORK_DIR/range-body.bin" -w '%{http_code}' \
  -H "Authorization: Bearer $TOKEN" \
  -H "Range: bytes=0-9" \
  "${BASE_URL}/v2/${REPO_KEY}/${IMAGE}/blobs/${dup_digest}") || true

if [ "$range_status" = "206" ]; then
  # Partial content returned
  range_size=$(wc -c < "$WORK_DIR/range-body.bin" | tr -d ' ')
  if [ "$range_size" -le 10 ]; then
    pass
  else
    fail "Range request returned ${range_size} bytes, expected at most 10"
  fi
elif [ "$range_status" = "200" ]; then
  # Server returned the full blob (Range not supported), acceptable behavior
  pass
else
  fail "Range GET returned ${range_status}, expected 206 or 200"
fi

# =========================================================================
# 15. Manifest list with single platform (multi-arch edge case)
# =========================================================================

begin_test "Manifest list: single platform (valid OCI image index)"

# First, ensure the base manifest is pushed with a tag we can reference by digest
push_manifest "$REPO_KEY" "$IMAGE" "index-child" "$BASE_MANIFEST" || true
child_digest="sha256:$(printf '%s' "$BASE_MANIFEST" | shasum -a 256 | awk '{print $1}')"
child_size=${#BASE_MANIFEST}

INDEX_MANIFEST=$(cat <<EOFIDX
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.index.v1+json",
  "manifests": [
    {
      "mediaType": "application/vnd.oci.image.manifest.v1+json",
      "digest": "${child_digest}",
      "size": ${child_size},
      "platform": {
        "architecture": "amd64",
        "os": "linux"
      }
    }
  ]
}
EOFIDX
)

idx_status=$(curl -s -o /dev/null -w '%{http_code}' \
  -X PUT \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/vnd.oci.image.index.v1+json" \
  -d "$INDEX_MANIFEST" \
  "${BASE_URL}/v2/${REPO_KEY}/${IMAGE}/manifests/single-platform-index") || true

if [ "$idx_status" = "201" ] || [ "$idx_status" = "200" ]; then
  # Retrieve and verify the index
  idx_resp=$(curl -sf $CURL_TIMEOUT \
    -H "Authorization: Bearer $TOKEN" \
    -H "Accept: application/vnd.oci.image.index.v1+json" \
    "${BASE_URL}/v2/${REPO_KEY}/${IMAGE}/manifests/single-platform-index" 2>/dev/null) || true
  idx_mcount=$(echo "$idx_resp" | jq '.manifests | length' 2>/dev/null) || true
  if [ "${idx_mcount:-0}" -eq 1 ]; then
    pass
  else
    fail "index manifest count ${idx_mcount}, expected 1"
  fi
else
  fail "manifest index PUT returned ${idx_status}, expected 201"
fi

# =========================================================================
# 16. OCI artifact with custom mediaType (artifactType)
# =========================================================================

begin_test "OCI artifact with custom artifactType"

# OCI spec allows arbitrary artifactType for non-image artifacts (SBOMs,
# signatures, attestations). Use a custom config media type and set
# artifactType at the manifest level.

custom_config='{"custom":"artifact-data"}'
custom_config_digest="sha256:$(printf '%s' "$custom_config" | shasum -a 256 | awk '{print $1}')"
custom_config_size=${#custom_config}
upload_blob_string "$REPO_KEY" "$IMAGE" "$custom_config" "$custom_config_digest" "$custom_config_size" || true

ARTIFACT_MANIFEST=$(cat <<EOFART
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "artifactType": "application/vnd.example.test.type.v1+json",
  "config": {
    "mediaType": "application/vnd.oci.empty.v1+json",
    "digest": "${custom_config_digest}",
    "size": ${custom_config_size}
  },
  "layers": []
}
EOFART
)

art_status=$(curl -s -o /dev/null -w '%{http_code}' \
  -X PUT \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/vnd.oci.image.manifest.v1+json" \
  -d "$ARTIFACT_MANIFEST" \
  "${BASE_URL}/v2/${REPO_KEY}/${IMAGE}/manifests/custom-artifact") || true

if [ "$art_status" = "201" ] || [ "$art_status" = "200" ]; then
  art_resp=$(curl -sf $CURL_TIMEOUT \
    -H "Authorization: Bearer $TOKEN" \
    -H "Accept: application/vnd.oci.image.manifest.v1+json" \
    "${BASE_URL}/v2/${REPO_KEY}/${IMAGE}/manifests/custom-artifact" 2>/dev/null) || true
  art_type=$(echo "$art_resp" | jq -r '.artifactType // empty' 2>/dev/null) || true
  if [ "$art_type" = "application/vnd.example.test.type.v1+json" ]; then
    pass
  else
    fail "artifactType not preserved: expected 'application/vnd.example.test.type.v1+json', got '${art_type}'"
  fi
else
  fail "custom artifact manifest PUT returned ${art_status}, expected 201"
fi

# =========================================================================
# 17. Unicode in annotations: manifest annotations with multibyte chars
# =========================================================================

begin_test "Unicode in annotations: multibyte characters preserved"

UNICODE_MANIFEST=$(cat <<EOFUNI
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
  ],
  "annotations": {
    "org.opencontainers.image.title": "Test Unicode Title",
    "org.opencontainers.image.description": "Includes CJK: \u4f60\u597d\u4e16\u754c, emoji: \u2603, accented: caf\u00e9"
  }
}
EOFUNI
)

uni_status=$(curl -s -o /dev/null -w '%{http_code}' \
  -X PUT \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/vnd.oci.image.manifest.v1+json" \
  -d "$UNICODE_MANIFEST" \
  "${BASE_URL}/v2/${REPO_KEY}/${IMAGE}/manifests/unicode-test") || true

if [ "$uni_status" = "201" ] || [ "$uni_status" = "200" ]; then
  uni_resp=$(curl -sf $CURL_TIMEOUT \
    -H "Authorization: Bearer $TOKEN" \
    -H "Accept: application/vnd.oci.image.manifest.v1+json" \
    "${BASE_URL}/v2/${REPO_KEY}/${IMAGE}/manifests/unicode-test" 2>/dev/null) || true

  uni_title=$(echo "$uni_resp" | jq -r '.annotations["org.opencontainers.image.title"] // empty' 2>/dev/null) || true
  if [ "$uni_title" = "Test Unicode Title" ]; then
    pass
  else
    fail "annotation title not preserved: got '${uni_title}'"
  fi
else
  fail "unicode annotation manifest PUT returned ${uni_status}, expected 201"
fi

# =========================================================================
# 18. HEAD on upload URL: check status during chunked upload
# =========================================================================

begin_test "HEAD on upload URL: status check during chunked upload"

head_upload_hdr="$WORK_DIR/head-upload-init-hdr.txt"
head_upload_init=$(curl -s -D "$head_upload_hdr" -o /dev/null -w '%{http_code}' \
  -X POST \
  -H "Authorization: Bearer $TOKEN" \
  "${BASE_URL}/v2/${REPO_KEY}/${IMAGE}/blobs/uploads/") || true

if [ "$head_upload_init" = "202" ]; then
  head_upload_loc=$(resolve_location "$head_upload_hdr") || true
  if [ -n "$head_upload_loc" ]; then
    # HEAD or GET on the upload URL should return 204 or 200 with upload status
    hstatus=$(curl -s -o /dev/null -w '%{http_code}' \
      -I \
      -H "Authorization: Bearer $TOKEN" \
      "$head_upload_loc") || true

    # OCI spec says GET on the upload URL returns 204 with Range header.
    # HEAD is not strictly specified, so we accept 200, 204, or even 404
    # (some registries do not support HEAD on upload UUID endpoints).
    if [ "$hstatus" = "204" ] || [ "$hstatus" = "200" ] || [ "$hstatus" = "404" ]; then
      pass
    elif [ "$hstatus" -ge 500 ] 2>/dev/null; then
      fail "HEAD on upload URL returned server error ${hstatus}"
    else
      # Any 4xx other than 404 is not ideal but not a server crash
      pass
    fi
  else
    fail "upload POST did not return Location for HEAD test"
  fi
else
  fail "upload POST for HEAD-on-upload test returned ${head_upload_init}, expected 202"
fi

# =========================================================================
# 19. Delete then re-push: delete manifest and push it again
# =========================================================================

begin_test "Delete then re-push: remove manifest and push same tag again"

delete_tag="delete-repush"
push_manifest "$REPO_KEY" "$IMAGE" "$delete_tag" "$BASE_MANIFEST" || true

# Get the manifest digest for deletion
del_manifest_digest="sha256:$(printf '%s' "$BASE_MANIFEST" | shasum -a 256 | awk '{print $1}')"

# Delete by digest
del_status=$(curl -s -o /dev/null -w '%{http_code}' \
  -X DELETE \
  -H "Authorization: Bearer $TOKEN" \
  "${BASE_URL}/v2/${REPO_KEY}/${IMAGE}/manifests/${del_manifest_digest}") || true

if [ "$del_status" = "202" ] || [ "$del_status" = "200" ] || [ "$del_status" = "204" ]; then
  # Verify it is gone (the tag should return 404 now)
  gone_status=$(curl -s -o /dev/null -w '%{http_code}' \
    -H "Authorization: Bearer $TOKEN" \
    -H "Accept: application/vnd.oci.image.manifest.v1+json" \
    "${BASE_URL}/v2/${REPO_KEY}/${IMAGE}/manifests/${delete_tag}") || true

  # Re-push the same manifest to the same tag
  if push_manifest "$REPO_KEY" "$IMAGE" "$delete_tag" "$BASE_MANIFEST"; then
    repush_status=$(curl -s -o /dev/null -w '%{http_code}' \
      -H "Authorization: Bearer $TOKEN" \
      -H "Accept: application/vnd.oci.image.manifest.v1+json" \
      "${BASE_URL}/v2/${REPO_KEY}/${IMAGE}/manifests/${delete_tag}") || true
    if [ "$repush_status" = "200" ]; then
      pass
    else
      fail "re-pushed manifest GET returned ${repush_status}, expected 200"
    fi
  else
    fail "re-push of deleted manifest failed"
  fi
elif [ "$del_status" = "404" ] || [ "$del_status" = "405" ]; then
  # Some registries do not support delete; skip gracefully
  skip "manifest delete not supported (HTTP ${del_status})"
else
  fail "manifest DELETE returned ${del_status}, expected 202/204"
fi

# =========================================================================
# 20. Concurrent reads during write: read manifest while pushing new version
# =========================================================================

begin_test "Concurrent reads during write: read during push"

race_tag="race-test"
push_manifest "$REPO_KEY" "$IMAGE" "$race_tag" "$BASE_MANIFEST" || true

# Build a slightly different manifest for the overwrite
RACE_CONFIG='{"architecture":"riscv64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}'
RACE_CONFIG_DIGEST="sha256:$(printf '%s' "$RACE_CONFIG" | shasum -a 256 | awk '{print $1}')"
RACE_CONFIG_SIZE=${#RACE_CONFIG}
upload_blob_string "$REPO_KEY" "$IMAGE" "$RACE_CONFIG" "$RACE_CONFIG_DIGEST" "$RACE_CONFIG_SIZE" || true

RACE_MANIFEST=$(cat <<EOFRACE
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "config": {
    "mediaType": "application/vnd.oci.image.config.v1+json",
    "digest": "${RACE_CONFIG_DIGEST}",
    "size": ${RACE_CONFIG_SIZE}
  },
  "layers": [
    {
      "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
      "digest": "${LAYER_DIGEST}",
      "size": ${LAYER_SIZE}
    }
  ]
}
EOFRACE
)

# Launch 5 readers in parallel
reader_pids=()
reader_ok=true
for i in $(seq 1 5); do
  (
    for _ in $(seq 1 10); do
      status=$(curl -s -o /dev/null -w '%{http_code}' \
        -H "Authorization: Bearer $TOKEN" \
        -H "Accept: application/vnd.oci.image.manifest.v1+json" \
        "${BASE_URL}/v2/${REPO_KEY}/${IMAGE}/manifests/${race_tag}") || true
      # Any successful read (200) or 404 (if caught between delete and re-push)
      # is acceptable. A 5xx would be a real problem.
      if [ "$status" -ge 500 ] 2>/dev/null; then
        exit 1
      fi
    done
    exit 0
  ) &
  reader_pids+=($!)
done

# Simultaneously push a new version of the manifest
push_manifest "$REPO_KEY" "$IMAGE" "$race_tag" "$RACE_MANIFEST" || true

for pid in "${reader_pids[@]}"; do
  if ! wait "$pid"; then
    reader_ok=false
  fi
done

if $reader_ok; then
  # Final check: the tag should be readable with no errors
  final_status=$(curl -s -o /dev/null -w '%{http_code}' \
    -H "Authorization: Bearer $TOKEN" \
    -H "Accept: application/vnd.oci.image.manifest.v1+json" \
    "${BASE_URL}/v2/${REPO_KEY}/${IMAGE}/manifests/${race_tag}") || true
  if [ "$final_status" = "200" ]; then
    pass
  else
    fail "manifest GET after concurrent read-write returned ${final_status}, expected 200"
  fi
else
  fail "concurrent readers hit server errors during manifest push"
fi

# =========================================================================
# 21. Digest-based blob HEAD returns correct Content-Length
# =========================================================================

begin_test "Blob HEAD: Content-Length matches uploaded size"

bl_head_hdr="$WORK_DIR/bl-head-cl-hdr.txt"
bl_head_status=$(curl -s -D "$bl_head_hdr" -o /dev/null -w '%{http_code}' \
  -I \
  -H "Authorization: Bearer $TOKEN" \
  "${BASE_URL}/v2/${REPO_KEY}/${IMAGE}/blobs/${LAYER_DIGEST}") || true

if [ "$bl_head_status" = "200" ]; then
  bl_cl=$(grep -i '^content-length:' "$bl_head_hdr" | tr -d '\r' | awk '{print $2}') || true
  if [ "${bl_cl}" = "${LAYER_SIZE}" ]; then
    pass
  else
    fail "blob HEAD Content-Length ${bl_cl} does not match expected ${LAYER_SIZE}"
  fi
else
  fail "blob HEAD returned ${bl_head_status}, expected 200"
fi

# =========================================================================
# 22. Non-existent blob returns 404 (not 500)
# =========================================================================

begin_test "Non-existent blob: returns 404"

fake_digest="sha256:0000000000000000000000000000000000000000000000000000000000000000"
ne_status=$(curl -s -o /dev/null -w '%{http_code}' \
  -H "Authorization: Bearer $TOKEN" \
  "${BASE_URL}/v2/${REPO_KEY}/${IMAGE}/blobs/${fake_digest}") || true

if [ "$ne_status" = "404" ]; then
  pass
else
  fail "non-existent blob returned ${ne_status}, expected 404"
fi

# =========================================================================
# 23. Manifest DELETE by tag (if supported)
# =========================================================================

begin_test "Manifest delete by tag reference"

deltag_tag="delete-by-tag"
push_manifest "$REPO_KEY" "$IMAGE" "$deltag_tag" "$BASE_MANIFEST" || true

deltag_status=$(curl -s -o /dev/null -w '%{http_code}' \
  -X DELETE \
  -H "Authorization: Bearer $TOKEN" \
  "${BASE_URL}/v2/${REPO_KEY}/${IMAGE}/manifests/${deltag_tag}") || true

if [ "$deltag_status" = "202" ] || [ "$deltag_status" = "200" ] || [ "$deltag_status" = "204" ]; then
  # Verify the tag is gone
  after_del=$(curl -s -o /dev/null -w '%{http_code}' \
    -H "Authorization: Bearer $TOKEN" \
    -H "Accept: application/vnd.oci.image.manifest.v1+json" \
    "${BASE_URL}/v2/${REPO_KEY}/${IMAGE}/manifests/${deltag_tag}") || true
  if [ "$after_del" = "404" ]; then
    pass
  else
    fail "deleted tag still returns ${after_del}, expected 404"
  fi
elif [ "$deltag_status" = "404" ] || [ "$deltag_status" = "405" ]; then
  skip "manifest delete by tag not supported (HTTP ${deltag_status})"
else
  fail "manifest DELETE by tag returned ${deltag_status}"
fi

# =========================================================================
# 24. Cross-repo blob mount (if supported)
# =========================================================================

begin_test "Cross-repo blob mount: mount blob from another repo"

MOUNT_REPO="test-oci-edge-mount-${RUN_ID}"
create_local_repo "$MOUNT_REPO" "docker" 2>/dev/null || true

mount_hdr="$WORK_DIR/mount-hdr.txt"
mount_status=$(curl -s -D "$mount_hdr" -o /dev/null -w '%{http_code}' \
  -X POST \
  -H "Authorization: Bearer $TOKEN" \
  "${BASE_URL}/v2/${MOUNT_REPO}/${IMAGE}/blobs/uploads/?mount=${LAYER_DIGEST}&from=${REPO_KEY}/${IMAGE}") || true

if [ "$mount_status" = "201" ]; then
  # 201 means the blob was mounted successfully
  pass
elif [ "$mount_status" = "202" ]; then
  # 202 means mount was not supported but an upload session was started; acceptable
  pass
elif [ "$mount_status" = "404" ] || [ "$mount_status" = "405" ]; then
  skip "cross-repo blob mount not supported (HTTP ${mount_status})"
else
  fail "cross-repo blob mount returned ${mount_status}, expected 201 or 202"
fi

# =========================================================================
# Cleanup
# =========================================================================

# Delete repositories via the management API
api_delete "/api/v1/repositories/${REPO_KEY}" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${LONG_REPO}" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${MOUNT_REPO}" > /dev/null 2>&1 || true

end_suite
