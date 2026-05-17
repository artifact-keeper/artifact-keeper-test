#!/usr/bin/env bash
# test-multipart-artifact-upload.sh - Single-file multipart artifact upload
#
# Covers Epic 6 sub-task 6.13 (artifact-keeper-test#71):
#   upload_artifact_multipart / upload_artifact_multipart_with_path
#
# Background: the standard artifact upload path is PUT
# /api/v1/repositories/{key}/artifacts/{path} with
# application/octet-stream. The multipart variants on the backend
# (POST .../artifacts and POST .../artifacts/{path}) accept
# multipart/form-data with a SINGLE file field; the backend extracts
# the first form field that has a filename and stores it as one blob
# (see backend repositories.rs::extract_multipart_file, which returns
# after the first matching field). The OpenAPI spec documents the
# multipart/form-data POST surfaces but does not enumerate a chunked
# transport, and no upload-session or chunked-part endpoint exists
# anywhere in the spec.
#
# Chunked-upload gap: a true multi-part chunked upload (client splits
# a blob across N form fields and the backend reassembles in order)
# is NOT supported by the current backend. Asserting "chunk0/chunk1/
# chunk2 + SHA of concatenation" against the existing endpoint would
# silently truncate to chunk0 and yield a false-positive failure. The
# chunked-upload feature is documented as a v1.2.0 backend follow-up
# (issue #71); when an upload-session/parts endpoint lands in OpenAPI,
# extend this test to cover it.
#
# Contract under test (scope narrowed to what the backend actually
# implements):
#   1. POST multipart/form-data to the documented multipart upload
#      endpoint with a single `file` field.
#   2. The response is JSON describing the uploaded artifact, with
#      content_type and checksum_sha256 set, and the server-reported
#      checksum matches the client-computed checksum.
#   3. Download the artifact back and assert SHA256(downloaded) ==
#      SHA256(uploaded). This is the load-bearing assertion: if the
#      backend silently dropped bytes or mis-stored the body, the
#      hash differs.
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
# Build a single 72 KiB blob with non-uniform content so any byte-range
# corruption between upload and storage is detectable in the SHA256.
# -------------------------------------------------------------------------

CHUNK_SIZE=$((24 * 1024))  # 24 KiB per segment = 72 KiB total.
: > "${WORK_DIR}/blob.bin"
for i in 0 1 2; do
  byte=$(printf '\\x%02x' $((0x10 + i)))
  # shellcheck disable=SC2059
  printf "$byte%.0s" $(seq 1 "$CHUNK_SIZE") >> "${WORK_DIR}/blob.bin"
done

EXPECTED_SHA=$(sha256sum "${WORK_DIR}/blob.bin" | awk '{print $1}')
EXPECTED_LEN=$(wc -c < "${WORK_DIR}/blob.bin" | tr -d ' ')

# -------------------------------------------------------------------------
# 6.13.a: Multipart POST upload. Try both documented surfaces:
#   POST /repositories/{key}/artifacts            (path comes from filename)
#   POST /repositories/{key}/artifacts/{path}     (path comes from URL)
# A single `file` form field is what the backend's extract_multipart_file
# accepts. If neither surface accepts the request (404/405/415/501),
# skip the whole suite -- nothing to assert.
# -------------------------------------------------------------------------

UPLOAD_RESP="${WORK_DIR}/upload-resp.json"

try_multipart_post() {
  # $1 = full URL
  local url="$1"
  curl -s -o "$UPLOAD_RESP" -w '%{http_code}' $CURL_TIMEOUT \
    -X POST -H "$(auth_header)" \
    -F "file=@${WORK_DIR}/blob.bin;filename=${ART_PATH}" \
    "$url" 2>/dev/null || echo "000"
}

begin_test "Multipart upload (single file) returns 2xx"
MP_STATUS="000"
MP_URL_USED=""
for url in \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/${ART_PATH}" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts"
do
  s=$(try_multipart_post "$url")
  if [ "$s" -ge 200 ] 2>/dev/null && [ "$s" -lt 300 ] 2>/dev/null; then
    MP_STATUS="$s"
    MP_URL_USED="$url"
    break
  fi
  case "$s" in
    404|405|415|501) MP_STATUS="$s" ;;
    *) [ "$MP_STATUS" = "000" ] && MP_STATUS="$s" ;;
  esac
done

case "$MP_STATUS" in
  2[0-9][0-9])
    echo "  upload accepted at ${MP_URL_USED}"
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
# 6.13.b: Response shape: id, content_type, and checksum_sha256 must be
# present, and the server-reported checksum must match the client side.
# -------------------------------------------------------------------------

begin_test "Multipart response carries content_type + matching checksum_sha256"
RESP_CT=$(jq -r '.content_type // empty' < "$UPLOAD_RESP")
RESP_SHA=$(jq -r '.checksum_sha256 // empty' < "$UPLOAD_RESP")
RESP_ID=$(jq -r '.id // empty' < "$UPLOAD_RESP")
if [ -z "$RESP_CT" ] || [ -z "$RESP_SHA" ] || [ -z "$RESP_ID" ]; then
  body=$(head -c 400 "$UPLOAD_RESP" 2>/dev/null || true)
  fail "response missing required fields (content_type='${RESP_CT}', checksum_sha256='${RESP_SHA}', id='${RESP_ID}'): ${body}"
elif [ "$RESP_SHA" != "$EXPECTED_SHA" ]; then
  fail "server-reported checksum_sha256=${RESP_SHA} does not match client-computed ${EXPECTED_SHA}"
else
  pass
fi

# -------------------------------------------------------------------------
# 6.13.c: Download the blob back and compare SHA256. This catches any
# byte-range corruption between upload and storage.
# -------------------------------------------------------------------------

begin_test "Downloaded blob SHA256 matches uploaded blob"
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
  fail "could not download uploaded blob; HTTP ${DL_STATUS}"
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
