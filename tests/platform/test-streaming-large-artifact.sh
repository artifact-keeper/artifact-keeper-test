#!/usr/bin/env bash
# test-streaming-large-artifact.sh - A >16 MiB artifact must stream, not buffer.
#
# Release gate for:
#   artifact-keeper#1608 - streaming invariant (>16 MiB not buffered / 502'd)
#
# The backend buffers request/response bodies up to a 16 MiB in-memory cap.
# Artifacts larger than that MUST be streamed to/from storage; if the cap is
# applied to the artifact path the upload/download of a >16 MiB blob returns
# 502 (or the pod OOM-crashes) instead of 2xx. This gate PUTs a 24 MiB blob
# (comfortably over the 16 MiB cap) to a generic repo and GETs it back,
# asserting:
#   - upload is 2xx and is NEVER 502 (buffered/OOM) or 413 (over MAX_UPLOAD_SIZE;
#     the test overlay's default cap is 10 GiB, so 413 here means the streaming
#     path was not taken)
#   - download is 2xx
#   - the SHA256 and byte size round-trip exactly (no truncation from a partial
#     buffered read)
#
# Unlike tests/resilience/data/test-large-artifact.sh (100 MB, gated behind
# `require_cmd kubectl`), this copy needs no kubectl so it runs in the normal
# platform matrix. 24 MiB keeps it fast while still crossing the 16 MiB cap.
#
# Feature-gated on `streaming_large_artifact` so it auto-skips on a 1.2.x
# backend instead of hard-failing.
#
# Requires: curl, dd, shasum

source "$(dirname "$0")/../lib/common.sh"

begin_suite "streaming-large-artifact"
auth_admin
setup_workdir

# Feature gate: skip on backends without the streaming invariant.
begin_test "Backend supports streaming_large_artifact (v1.3.0)"
if require_feature "streaming_large_artifact"; then
  pass
else
  end_suite
  exit 0
fi

REPO_KEY="e2e-streaming-${RUN_ID}"
# 24 MiB: strictly greater than the 16 MiB in-memory buffer cap.
LARGE_SIZE_MB=24
ART_PATH="files/v1/large-${RUN_ID}.bin"

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

begin_test "Create generic repository"
if create_local_repo "$REPO_KEY" "generic"; then
  pass
else
  fail "could not create generic repo"
fi

begin_test "Generate ${LARGE_SIZE_MB} MiB test file (> 16 MiB buffer cap)"
dd if=/dev/urandom bs=1048576 count="$LARGE_SIZE_MB" \
  of="${WORK_DIR}/large.bin" 2>/dev/null
ORIG_SHA=$(shasum -a 256 "${WORK_DIR}/large.bin" | awk '{print $1}')
ORIG_SIZE=$(wc -c < "${WORK_DIR}/large.bin" | tr -d ' ')
echo "  File size: ${ORIG_SIZE} bytes, SHA256: ${ORIG_SHA}"
if [ "$ORIG_SIZE" -gt $((16 * 1024 * 1024)) ] 2>/dev/null; then
  pass
else
  fail "generated file is ${ORIG_SIZE} bytes, expected > 16 MiB"
fi

# ---------------------------------------------------------------------------
# Upload: must stream (2xx), never 502 (buffered/OOM) or 413 (cap)
# ---------------------------------------------------------------------------

begin_test "Upload ${LARGE_SIZE_MB} MiB artifact is 2xx (streamed, not 502/413)"
upload_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X PUT \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@${WORK_DIR}/large.bin" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/${ART_PATH}" 2>/dev/null) || upload_status="000"
echo "  Upload status: ${upload_status}"
if [ "$upload_status" = "502" ]; then
  fail "upload returned 502: >16 MiB body was buffered/OOM instead of streamed"
elif [ "$upload_status" = "413" ]; then
  fail "upload returned 413: streaming path not taken (overlay MAX_UPLOAD_SIZE default is 10 GiB)"
elif assert_http_2xx "$upload_status" "large artifact upload should be 2xx"; then
  pass
fi

# ---------------------------------------------------------------------------
# Download: must stream (2xx) and round-trip byte-exact
# ---------------------------------------------------------------------------

begin_test "Download ${LARGE_SIZE_MB} MiB artifact is 2xx (streamed, not 502)"
dl_status=$(curl -s -o "${WORK_DIR}/large-dl.bin" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/download/${ART_PATH}" 2>/dev/null) || dl_status="000"
echo "  Download status: ${dl_status}"
if [ "$dl_status" = "502" ]; then
  fail "download returned 502: >16 MiB body was buffered/OOM instead of streamed"
elif assert_http_2xx "$dl_status" "large artifact download should be 2xx"; then
  pass
fi

begin_test "Downloaded artifact SHA256 matches (no truncation)"
if [ -f "${WORK_DIR}/large-dl.bin" ]; then
  DL_SHA=$(shasum -a 256 "${WORK_DIR}/large-dl.bin" | awk '{print $1}')
  if assert_eq "$DL_SHA" "$ORIG_SHA" "SHA256 mismatch on ${LARGE_SIZE_MB} MiB round-trip"; then
    pass
  fi
else
  fail "downloaded file does not exist"
fi

begin_test "Downloaded artifact byte size matches"
if [ -f "${WORK_DIR}/large-dl.bin" ]; then
  DL_SIZE=$(wc -c < "${WORK_DIR}/large-dl.bin" | tr -d ' ')
  if assert_eq "$DL_SIZE" "$ORIG_SIZE" "size mismatch: expected ${ORIG_SIZE}, got ${DL_SIZE}"; then
    pass
  fi
else
  fail "downloaded file does not exist"
fi

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

api_delete "/api/v1/repositories/${REPO_KEY}" > /dev/null 2>&1 || true

end_suite
