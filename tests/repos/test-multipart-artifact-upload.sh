#!/usr/bin/env bash
# test-multipart-artifact-upload.sh - Multipart (chunked) artifact upload
#
# Covers Epic 6 sub-task 6.13 (artifact-keeper-test#71):
#   upload_artifact_multipart / upload_artifact_multipart_with_path
#
# Background: the standard artifact upload path is PUT
# /api/v1/repositories/{key}/artifacts/{path} with
# application/octet-stream. The multipart variants on the backend
# accept multipart/form-data, which lets clients chunk a single blob
# across multiple form parts (typically named "chunk0", "chunk1", ...
# or "file"). OpenAPI does not enumerate this transport explicitly,
# so the test discovers it by trying multipart/form-data against the
# existing path and gracefully skipping if the backend returns 4xx
# (415 Unsupported Media Type / 400 / 404 / 501).
#
# Contract under test:
#   1. Split a payload of >= 64 KiB into 3 chunks on the client side.
#   2. Upload via multipart/form-data with one form part per chunk.
#   3. Download the artifact back as a single blob.
#   4. Assert SHA256(downloaded) == SHA256(concatenated client-side
#      chunks). This is the load-bearing assertion: if the backend
#      reassembled correctly, the hash matches; if it concatenated in
#      the wrong order or dropped a chunk, the hash differs.
#
# Requires: curl, jq, sha256sum
source "$(dirname "$0")/../lib/common.sh"

begin_suite "multipart-artifact-upload"
auth_admin
setup_workdir
require_cmd sha256sum

REPO_KEY="test-multipart-${RUN_ID}"
ART_PATH="multipart-blob.bin"

add_exit_handler "curl -s -o /dev/null -X DELETE -H 'Authorization: Bearer \$ADMIN_TOKEN' \"\${BASE_URL}/api/v1/repositories/${REPO_KEY}\" || true"

# -------------------------------------------------------------------------
# Setup: local repo to receive the blob.
# -------------------------------------------------------------------------

begin_test "Create repo"
if create_local_repo "$REPO_KEY" "generic"; then
  pass
else
  skip_suite "could not create repo"
fi

# -------------------------------------------------------------------------
# Build 3 chunks. Use deterministic but non-uniform data so a wrong-order
# reassembly is detectable in the SHA256 (vs all-zero data which would
# hash to the same thing regardless of order).
# -------------------------------------------------------------------------

CHUNK_SIZE=$((24 * 1024))  # 24 KiB per chunk = 72 KiB total.
for i in 0 1 2; do
  # Fill each chunk with a distinct repeating byte (0x10+i) so the
  # SHA256 of the concatenation is order-sensitive.
  byte=$(printf '\\x%02x' $((0x10 + i)))
  # shellcheck disable=SC2059
  printf "$byte%.0s" $(seq 1 "$CHUNK_SIZE") > "${WORK_DIR}/chunk-${i}.bin"
done

# Expected hash = SHA256 of chunks in order.
cat "${WORK_DIR}/chunk-0.bin" "${WORK_DIR}/chunk-1.bin" "${WORK_DIR}/chunk-2.bin" \
  > "${WORK_DIR}/expected.bin"
EXPECTED_SHA=$(sha256sum "${WORK_DIR}/expected.bin" | awk '{print $1}')
EXPECTED_LEN=$(wc -c < "${WORK_DIR}/expected.bin" | tr -d ' ')

# -------------------------------------------------------------------------
# 6.13.a: Multipart upload. Try a couple of common form field name
# conventions in case the backend names the field "chunks" / "files"
# rather than a numeric "chunk0/chunk1/chunk2".
# -------------------------------------------------------------------------

UPLOAD_URL="${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/${ART_PATH}"

try_multipart() {
  # $1 = HTTP verb (PUT or POST), $2 = form-field-name template printf
  # ("chunk%d", "file", "chunks[]") so we can try variants.
  local verb="$1"
  local field_tpl="$2"
  local out="${WORK_DIR}/upload-${verb}-$(echo "$field_tpl" | tr -d '%[]').json"
  local field0 field1 field2
  case "$field_tpl" in
    *"%d"*)
      field0=$(printf "$field_tpl" 0)
      field1=$(printf "$field_tpl" 1)
      field2=$(printf "$field_tpl" 2)
      ;;
    *)
      # Same name three times for array-style fields.
      field0="$field_tpl"
      field1="$field_tpl"
      field2="$field_tpl"
      ;;
  esac
  curl -s -o "$out" -w '%{http_code}' $CURL_TIMEOUT \
    -X "$verb" -H "$(auth_header)" \
    -F "${field0}=@${WORK_DIR}/chunk-0.bin" \
    -F "${field1}=@${WORK_DIR}/chunk-1.bin" \
    -F "${field2}=@${WORK_DIR}/chunk-2.bin" \
    "$UPLOAD_URL" 2>/dev/null || echo "000"
}

begin_test "Multipart upload (chunked) returns 2xx"
MP_STATUS="000"
for verb in PUT POST; do
  for tpl in "chunk%d" "chunks[]" "file"; do
    s=$(try_multipart "$verb" "$tpl")
    if [ "$s" -ge 200 ] 2>/dev/null && [ "$s" -lt 300 ] 2>/dev/null; then
      MP_STATUS="$s"
      MP_VERB="$verb"; MP_TPL="$tpl"
      break 2
    fi
    # Track the most informative status code for the skip message.
    case "$s" in
      404|405|415|501) MP_STATUS="$s" ;;
      *) [ "$MP_STATUS" = "000" ] && MP_STATUS="$s" ;;
    esac
  done
done

case "$MP_STATUS" in
  2[0-9][0-9])
    echo "  upload accepted via ${MP_VERB} with form field '${MP_TPL}'"
    pass
    ;;
  404|405|415|501)
    skip_suite "multipart upload not exposed in this build (final status ${MP_STATUS})"
    ;;
  *)
    fail "multipart upload returned unexpected HTTP ${MP_STATUS}"
    end_suite
    ;;
esac

# -------------------------------------------------------------------------
# 6.13.b: Download the blob back and compare SHA256.
# -------------------------------------------------------------------------

begin_test "Downloaded blob SHA256 matches concatenated chunks"
DL_FILE="${WORK_DIR}/downloaded.bin"
DL_STATUS=$(curl -s -o "$DL_FILE" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/download/${ART_PATH}" 2>/dev/null) || DL_STATUS="000"
# Fall back to /artifacts/{path} if /download/ isn't the download surface.
if [ "$DL_STATUS" != "200" ]; then
  DL_STATUS=$(curl -s -o "$DL_FILE" -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(auth_header)" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/${ART_PATH}" 2>/dev/null) || DL_STATUS="000"
fi

if [ "$DL_STATUS" != "200" ]; then
  fail "could not download reassembled blob; HTTP ${DL_STATUS}"
else
  GOT_LEN=$(wc -c < "$DL_FILE" | tr -d ' ')
  GOT_SHA=$(sha256sum "$DL_FILE" | awk '{print $1}')
  if [ "$GOT_LEN" = "$EXPECTED_LEN" ] && [ "$GOT_SHA" = "$EXPECTED_SHA" ]; then
    pass
  else
    fail "blob mismatch: expected ${EXPECTED_LEN}B sha256=${EXPECTED_SHA}, got ${GOT_LEN}B sha256=${GOT_SHA}"
  fi
fi

end_suite
