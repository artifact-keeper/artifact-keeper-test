#!/usr/bin/env bash
# test-chunked-upload.sh - E2E tests for the chunked upload API
#
# Validates the full lifecycle of chunked file uploads: session creation,
# sequential chunk upload with Content-Range, progress tracking, finalize
# with checksum verification, download integrity, resume, cancel, idempotent
# chunk re-upload, and bad checksum rejection.
#
# Requires: curl, jq, sha256sum (or shasum), dd
#
# Environment:
#   TEST_FILE_SIZE_MB  - size of the test file in MB (default: 50)
#   CHUNK_SIZE_MB      - chunk size in MB (default: 5)

source "$(dirname "$0")/../lib/common.sh"

begin_suite "chunked-upload"
auth_admin
setup_workdir

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

TEST_FILE_SIZE_MB="${TEST_FILE_SIZE_MB:-50}"
CHUNK_SIZE_MB="${CHUNK_SIZE_MB:-5}"
TEST_FILE_SIZE=$(( TEST_FILE_SIZE_MB * 1024 * 1024 ))
CHUNK_SIZE=$(( CHUNK_SIZE_MB * 1024 * 1024 ))
REPO_KEY="chunked-upload-${RUN_ID}"

# Detect sha256 command
if command -v sha256sum &>/dev/null; then
  sha256cmd="sha256sum"
elif command -v shasum &>/dev/null; then
  sha256cmd="shasum -a 256"
else
  echo "FATAL: neither sha256sum nor shasum found"
  exit 1
fi

compute_sha256() {
  $sha256cmd "$1" | awk '{print $1}'
}

# ---------------------------------------------------------------------------
# Setup: create test file and repository
# ---------------------------------------------------------------------------

echo "Generating ${TEST_FILE_SIZE_MB}MB test file..."
dd if=/dev/urandom of="${WORK_DIR}/testfile.bin" bs=1048576 count="$TEST_FILE_SIZE_MB" 2>/dev/null
FILE_SHA256=$(compute_sha256 "${WORK_DIR}/testfile.bin")
echo "  SHA256: ${FILE_SHA256}"
echo "  Size: ${TEST_FILE_SIZE} bytes"

mkdir -p "${WORK_DIR}/chunks"

begin_test "Create repository for chunked upload tests"
if create_local_repo "$REPO_KEY" "generic"; then
  pass
else
  fail "could not create repo ${REPO_KEY}"
fi

# =========================================================================
# Test 1: Create upload session
# =========================================================================

begin_test "Create upload session"
SESSION_RESP=""
SESSION_ID=""
if SESSION_RESP=$(curl -s $CURL_TIMEOUT -X POST \
  -H "$(auth_header)" \
  -H "Content-Type: application/json" \
  -w "\n%{http_code}" \
  -d "{
    \"repository_key\": \"${REPO_KEY}\",
    \"artifact_path\": \"test/chunked-file.bin\",
    \"total_size\": ${TEST_FILE_SIZE},
    \"chunk_size\": ${CHUNK_SIZE},
    \"checksum_sha256\": \"${FILE_SHA256}\"
  }" \
  "${BASE_URL}/api/v1/uploads" 2>/dev/null); then
  HTTP_CODE=$(echo "$SESSION_RESP" | tail -1)
  SESSION_BODY=$(echo "$SESSION_RESP" | sed '$d')

  if [ "$HTTP_CODE" = "201" ]; then
    SESSION_ID=$(echo "$SESSION_BODY" | jq -r '.session_id // .id // empty')
    RESP_CHUNK_COUNT=$(echo "$SESSION_BODY" | jq -r '.chunk_count // .total_chunks // empty')
    RESP_CHUNK_SIZE=$(echo "$SESSION_BODY" | jq -r '.chunk_size // empty')

    if [ -n "$SESSION_ID" ]; then
      echo "  session_id: ${SESSION_ID}"
      echo "  chunk_count: ${RESP_CHUNK_COUNT}"
      echo "  chunk_size: ${RESP_CHUNK_SIZE}"
      pass
    else
      fail "201 response but no session_id in body: ${SESSION_BODY}"
    fi
  else
    fail "expected HTTP 201, got ${HTTP_CODE}: ${SESSION_BODY}"
  fi
else
  fail "curl request failed"
fi

# =========================================================================
# Test 2: Upload chunks sequentially
# =========================================================================

begin_test "Upload all chunks sequentially"
if [ -z "$SESSION_ID" ]; then
  skip "no session_id from previous test"
else
  EXPECTED_CHUNKS=$(( (TEST_FILE_SIZE + CHUNK_SIZE - 1) / CHUNK_SIZE ))
  UPLOAD_OK=true

  for (( i=0; i<EXPECTED_CHUNKS; i++ )); do
    RANGE_START=$(( i * CHUNK_SIZE ))
    REMAINING=$(( TEST_FILE_SIZE - RANGE_START ))
    THIS_CHUNK=$(( REMAINING < CHUNK_SIZE ? REMAINING : CHUNK_SIZE ))
    RANGE_END=$(( RANGE_START + THIS_CHUNK - 1 ))

    # Extract chunk from test file. skip is measured in bs-sized (1 MB)
    # blocks, so chunk i begins at block i*CHUNK_SIZE_MB, not block i.
    dd if="${WORK_DIR}/testfile.bin" of="${WORK_DIR}/chunks/chunk_${i}" \
      bs=1048576 skip="$(( i * CHUNK_SIZE_MB ))" count="$CHUNK_SIZE_MB" 2>/dev/null
    # Truncate last chunk to exact remaining bytes if needed
    if [ "$THIS_CHUNK" -lt "$CHUNK_SIZE" ]; then
      truncate -s "$THIS_CHUNK" "${WORK_DIR}/chunks/chunk_${i}" 2>/dev/null || \
        dd if="${WORK_DIR}/testfile.bin" of="${WORK_DIR}/chunks/chunk_${i}" \
          bs=1 skip="$RANGE_START" count="$THIS_CHUNK" 2>/dev/null
    fi

    CHUNK_HTTP=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X PATCH \
      -H "$(auth_header)" \
      -H "Content-Type: application/octet-stream" \
      -H "Content-Range: bytes ${RANGE_START}-${RANGE_END}/${TEST_FILE_SIZE}" \
      --data-binary "@${WORK_DIR}/chunks/chunk_${i}" \
      "${BASE_URL}/api/v1/uploads/${SESSION_ID}") || true

    if [ "$CHUNK_HTTP" != "200" ] && [ "$CHUNK_HTTP" != "202" ]; then
      fail "chunk ${i} upload failed with HTTP ${CHUNK_HTTP}"
      UPLOAD_OK=false
      break
    fi
    echo "  chunk ${i}/${EXPECTED_CHUNKS}: bytes ${RANGE_START}-${RANGE_END} -> HTTP ${CHUNK_HTTP}"
  done

  if $UPLOAD_OK; then
    pass
  fi
fi

# =========================================================================
# Test 3: Verify upload progress
# =========================================================================

begin_test "GET upload session shows correct progress"
if [ -z "$SESSION_ID" ]; then
  skip "no session_id"
else
  PROGRESS_RESP=""
  if PROGRESS_RESP=$(api_get "/api/v1/uploads/${SESSION_ID}" 2>/dev/null); then
    BYTES_RECEIVED=$(echo "$PROGRESS_RESP" | jq -r '.bytes_received // 0')
    echo "  bytes_received: ${BYTES_RECEIVED}"
    echo "  expected: ${TEST_FILE_SIZE}"

    if [ "$BYTES_RECEIVED" -ge "$TEST_FILE_SIZE" ] 2>/dev/null; then
      pass
    else
      fail "bytes_received (${BYTES_RECEIVED}) < file size (${TEST_FILE_SIZE})"
    fi
  else
    fail "GET /api/v1/uploads/${SESSION_ID} failed"
  fi
fi

# =========================================================================
# Test 4: Finalize upload
# =========================================================================

begin_test "Finalize upload session"
ARTIFACT_ID=""
if [ -z "$SESSION_ID" ]; then
  skip "no session_id"
else
  FINALIZE_HTTP=$(curl -s -o "${WORK_DIR}/finalize-resp.json" -w '%{http_code}' \
    $CURL_TIMEOUT -X PUT \
    -H "$(auth_header)" \
    -H "Content-Type: application/json" \
    "${BASE_URL}/api/v1/uploads/${SESSION_ID}/complete" 2>/dev/null) || FINALIZE_HTTP="000"
  FINALIZE_BODY=$(cat "${WORK_DIR}/finalize-resp.json" 2>/dev/null) || FINALIZE_BODY=""

  if [ "$FINALIZE_HTTP" = "200" ]; then
    ARTIFACT_ID=$(echo "$FINALIZE_BODY" | jq -r '.artifact_id // .id // empty')
    echo "  artifact_id: ${ARTIFACT_ID}"
    pass
  else
    fail "expected HTTP 200, got ${FINALIZE_HTTP}: ${FINALIZE_BODY}"
  fi
fi

# =========================================================================
# Test 5: Download and verify SHA256 integrity
# =========================================================================

begin_test "Download artifact and verify SHA256"
if [ -z "$ARTIFACT_ID" ] && [ -z "$SESSION_ID" ]; then
  skip "no artifact to download"
else
  # /artifacts/*path GET returns metadata JSON; the raw bytes are served by
  # /download/*path.
  DL_HTTP=$(curl -s -o "${WORK_DIR}/downloaded.bin" -w '%{http_code}' \
    $CURL_TIMEOUT \
    -H "$(auth_header)" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}/download/test/chunked-file.bin" 2>/dev/null) || DL_HTTP="000"

  if [ "$DL_HTTP" = "200" ]; then
    DL_SHA256=$(compute_sha256 "${WORK_DIR}/downloaded.bin")
    echo "  original SHA256: ${FILE_SHA256}"
    echo "  download SHA256: ${DL_SHA256}"
    if [ "$DL_SHA256" = "$FILE_SHA256" ]; then
      pass
    else
      fail "SHA256 mismatch: original=${FILE_SHA256} downloaded=${DL_SHA256}"
    fi
  else
    fail "download returned HTTP ${DL_HTTP}"
  fi
fi

# =========================================================================
# Test 6: Resume - upload half, then GET status and continue
# =========================================================================

begin_test "Resume interrupted upload"
RESUME_SESSION_ID=""
RESUME_RESP=$(curl -s $CURL_TIMEOUT -X POST \
  -H "$(auth_header)" \
  -H "Content-Type: application/json" \
  -w "\n%{http_code}" \
  -d "{
    \"repository_key\": \"${REPO_KEY}\",
    \"artifact_path\": \"test/resumed-file.bin\",
    \"total_size\": ${TEST_FILE_SIZE},
    \"chunk_size\": ${CHUNK_SIZE},
    \"checksum_sha256\": \"${FILE_SHA256}\"
  }" \
  "${BASE_URL}/api/v1/uploads" 2>/dev/null) || true
RESUME_HTTP=$(echo "$RESUME_RESP" | tail -1)
RESUME_BODY=$(echo "$RESUME_RESP" | sed '$d')

if [ "$RESUME_HTTP" = "201" ]; then
  RESUME_SESSION_ID=$(echo "$RESUME_BODY" | jq -r '.session_id // .id // empty')
else
  skip "could not create resume session (HTTP ${RESUME_HTTP})"
fi

if [ -n "$RESUME_SESSION_ID" ]; then
  HALF_CHUNKS=$(( EXPECTED_CHUNKS / 2 ))
  echo "  uploading first ${HALF_CHUNKS} of ${EXPECTED_CHUNKS} chunks..."

  for (( i=0; i<HALF_CHUNKS; i++ )); do
    RANGE_START=$(( i * CHUNK_SIZE ))
    REMAINING=$(( TEST_FILE_SIZE - RANGE_START ))
    THIS_CHUNK=$(( REMAINING < CHUNK_SIZE ? REMAINING : CHUNK_SIZE ))
    RANGE_END=$(( RANGE_START + THIS_CHUNK - 1 ))

    dd if="${WORK_DIR}/testfile.bin" of="${WORK_DIR}/chunks/resume_${i}" \
      bs=1 skip="$RANGE_START" count="$THIS_CHUNK" 2>/dev/null

    curl -s -o /dev/null $CURL_TIMEOUT -X PATCH \
      -H "$(auth_header)" \
      -H "Content-Type: application/octet-stream" \
      -H "Content-Range: bytes ${RANGE_START}-${RANGE_END}/${TEST_FILE_SIZE}" \
      --data-binary "@${WORK_DIR}/chunks/resume_${i}" \
      "${BASE_URL}/api/v1/uploads/${RESUME_SESSION_ID}" 2>/dev/null || true
  done

  # Check progress
  PROGRESS=$(api_get "/api/v1/uploads/${RESUME_SESSION_ID}" 2>/dev/null) || true
  RECEIVED_BEFORE=$(echo "$PROGRESS" | jq -r '.bytes_received // 0' 2>/dev/null) || RECEIVED_BEFORE=0
  echo "  bytes after first half: ${RECEIVED_BEFORE}"

  # Upload remaining chunks
  echo "  resuming from chunk ${HALF_CHUNKS}..."
  RESUME_OK=true
  for (( i=HALF_CHUNKS; i<EXPECTED_CHUNKS; i++ )); do
    RANGE_START=$(( i * CHUNK_SIZE ))
    REMAINING=$(( TEST_FILE_SIZE - RANGE_START ))
    THIS_CHUNK=$(( REMAINING < CHUNK_SIZE ? REMAINING : CHUNK_SIZE ))
    RANGE_END=$(( RANGE_START + THIS_CHUNK - 1 ))

    dd if="${WORK_DIR}/testfile.bin" of="${WORK_DIR}/chunks/resume_${i}" \
      bs=1 skip="$RANGE_START" count="$THIS_CHUNK" 2>/dev/null

    R_HTTP=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X PATCH \
      -H "$(auth_header)" \
      -H "Content-Type: application/octet-stream" \
      -H "Content-Range: bytes ${RANGE_START}-${RANGE_END}/${TEST_FILE_SIZE}" \
      --data-binary "@${WORK_DIR}/chunks/resume_${i}" \
      "${BASE_URL}/api/v1/uploads/${RESUME_SESSION_ID}") || true

    if [ "$R_HTTP" != "200" ] && [ "$R_HTTP" != "202" ]; then
      fail "resume chunk ${i} failed with HTTP ${R_HTTP}"
      RESUME_OK=false
      break
    fi
  done

  if $RESUME_OK; then
    # Finalize
    R_FIN_HTTP=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X PUT \
      -H "$(auth_header)" \
      -H "Content-Type: application/json" \
      "${BASE_URL}/api/v1/uploads/${RESUME_SESSION_ID}/complete") || R_FIN_HTTP="000"

    if [ "$R_FIN_HTTP" = "200" ]; then
      pass
    else
      fail "finalize after resume returned HTTP ${R_FIN_HTTP}"
    fi
  fi
fi

# =========================================================================
# Test 7: Cancel upload session
# =========================================================================

begin_test "Cancel upload session"
CANCEL_RESP=$(curl -s $CURL_TIMEOUT -X POST \
  -H "$(auth_header)" \
  -H "Content-Type: application/json" \
  -w "\n%{http_code}" \
  -d "{
    \"repository_key\": \"${REPO_KEY}\",
    \"artifact_path\": \"test/cancelled-file.bin\",
    \"total_size\": ${TEST_FILE_SIZE},
    \"chunk_size\": ${CHUNK_SIZE},
    \"checksum_sha256\": \"${FILE_SHA256}\"
  }" \
  "${BASE_URL}/api/v1/uploads" 2>/dev/null) || true
CANCEL_HTTP=$(echo "$CANCEL_RESP" | tail -1)
CANCEL_BODY=$(echo "$CANCEL_RESP" | sed '$d')

CANCEL_SESSION_ID=""
if [ "$CANCEL_HTTP" = "201" ]; then
  CANCEL_SESSION_ID=$(echo "$CANCEL_BODY" | jq -r '.session_id // .id // empty')
fi

if [ -n "$CANCEL_SESSION_ID" ]; then
  # Upload one chunk so session has data
  dd if="${WORK_DIR}/testfile.bin" of="${WORK_DIR}/chunks/cancel_0" \
    bs=1048576 count="$CHUNK_SIZE_MB" 2>/dev/null
  RANGE_END=$(( CHUNK_SIZE - 1 ))

  curl -s -o /dev/null $CURL_TIMEOUT -X PATCH \
    -H "$(auth_header)" \
    -H "Content-Type: application/octet-stream" \
    -H "Content-Range: bytes 0-${RANGE_END}/${TEST_FILE_SIZE}" \
    --data-binary "@${WORK_DIR}/chunks/cancel_0" \
    "${BASE_URL}/api/v1/uploads/${CANCEL_SESSION_ID}" 2>/dev/null || true

  # Cancel the session
  DEL_HTTP=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X DELETE \
    -H "$(auth_header)" \
    "${BASE_URL}/api/v1/uploads/${CANCEL_SESSION_ID}") || DEL_HTTP="000"

  if [ "$DEL_HTTP" = "204" ]; then
    echo "  cancelled session ${CANCEL_SESSION_ID}"
    pass
  else
    fail "DELETE session returned HTTP ${DEL_HTTP}, expected 204"
  fi
else
  skip "could not create session for cancel test"
fi

# =========================================================================
# Test 8: Duplicate chunk upload (idempotent)
# =========================================================================

begin_test "Duplicate chunk upload is idempotent"
DUP_RESP=$(curl -s $CURL_TIMEOUT -X POST \
  -H "$(auth_header)" \
  -H "Content-Type: application/json" \
  -w "\n%{http_code}" \
  -d "{
    \"repository_key\": \"${REPO_KEY}\",
    \"artifact_path\": \"test/dup-chunk-file.bin\",
    \"total_size\": ${TEST_FILE_SIZE},
    \"chunk_size\": ${CHUNK_SIZE},
    \"checksum_sha256\": \"${FILE_SHA256}\"
  }" \
  "${BASE_URL}/api/v1/uploads" 2>/dev/null) || true
DUP_HTTP=$(echo "$DUP_RESP" | tail -1)
DUP_BODY=$(echo "$DUP_RESP" | sed '$d')

DUP_SESSION_ID=""
if [ "$DUP_HTTP" = "201" ]; then
  DUP_SESSION_ID=$(echo "$DUP_BODY" | jq -r '.session_id // .id // empty')
fi

if [ -n "$DUP_SESSION_ID" ]; then
  dd if="${WORK_DIR}/testfile.bin" of="${WORK_DIR}/chunks/dup_0" \
    bs=1048576 count="$CHUNK_SIZE_MB" 2>/dev/null
  RANGE_END=$(( CHUNK_SIZE - 1 ))

  # Upload chunk 0 first time
  DUP1_HTTP=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X PATCH \
    -H "$(auth_header)" \
    -H "Content-Type: application/octet-stream" \
    -H "Content-Range: bytes 0-${RANGE_END}/${TEST_FILE_SIZE}" \
    --data-binary "@${WORK_DIR}/chunks/dup_0" \
    "${BASE_URL}/api/v1/uploads/${DUP_SESSION_ID}") || DUP1_HTTP="000"

  # Upload chunk 0 second time (should be accepted)
  DUP2_HTTP=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X PATCH \
    -H "$(auth_header)" \
    -H "Content-Type: application/octet-stream" \
    -H "Content-Range: bytes 0-${RANGE_END}/${TEST_FILE_SIZE}" \
    --data-binary "@${WORK_DIR}/chunks/dup_0" \
    "${BASE_URL}/api/v1/uploads/${DUP_SESSION_ID}") || DUP2_HTTP="000"

  echo "  first upload: HTTP ${DUP1_HTTP}"
  echo "  second upload: HTTP ${DUP2_HTTP}"

  if [ "$DUP2_HTTP" = "200" ] || [ "$DUP2_HTTP" = "202" ]; then
    pass
  else
    fail "duplicate chunk upload returned HTTP ${DUP2_HTTP}, expected 200/202"
  fi

  # Clean up this session
  curl -s -o /dev/null $CURL_TIMEOUT -X DELETE \
    -H "$(auth_header)" \
    "${BASE_URL}/api/v1/uploads/${DUP_SESSION_ID}" 2>/dev/null || true
else
  skip "could not create session for duplicate chunk test"
fi

# =========================================================================
# Test 9: Bad checksum on finalize
# =========================================================================

begin_test "Finalize with wrong checksum returns 409"
BAD_RESP=$(curl -s $CURL_TIMEOUT -X POST \
  -H "$(auth_header)" \
  -H "Content-Type: application/json" \
  -w "\n%{http_code}" \
  -d "{
    \"repository_key\": \"${REPO_KEY}\",
    \"artifact_path\": \"test/bad-checksum-file.bin\",
    \"total_size\": ${CHUNK_SIZE},
    \"chunk_size\": ${CHUNK_SIZE},
    \"checksum_sha256\": \"0000000000000000000000000000000000000000000000000000000000000000\"
  }" \
  "${BASE_URL}/api/v1/uploads" 2>/dev/null) || true
BAD_HTTP=$(echo "$BAD_RESP" | tail -1)
BAD_BODY=$(echo "$BAD_RESP" | sed '$d')

BAD_SESSION_ID=""
if [ "$BAD_HTTP" = "201" ]; then
  BAD_SESSION_ID=$(echo "$BAD_BODY" | jq -r '.session_id // .id // empty')
fi

if [ -n "$BAD_SESSION_ID" ]; then
  # Upload one chunk (the full file for this single-chunk session)
  dd if="${WORK_DIR}/testfile.bin" of="${WORK_DIR}/chunks/bad_0" \
    bs=1048576 count="$CHUNK_SIZE_MB" 2>/dev/null
  RANGE_END=$(( CHUNK_SIZE - 1 ))

  curl -s -o /dev/null $CURL_TIMEOUT -X PATCH \
    -H "$(auth_header)" \
    -H "Content-Type: application/octet-stream" \
    -H "Content-Range: bytes 0-${RANGE_END}/${CHUNK_SIZE}" \
    --data-binary "@${WORK_DIR}/chunks/bad_0" \
    "${BASE_URL}/api/v1/uploads/${BAD_SESSION_ID}" 2>/dev/null || true

  # Finalize: should fail because the checksum is wrong
  BAD_FIN_HTTP=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X PUT \
    -H "$(auth_header)" \
    -H "Content-Type: application/json" \
    "${BASE_URL}/api/v1/uploads/${BAD_SESSION_ID}/complete") || BAD_FIN_HTTP="000"

  echo "  finalize HTTP: ${BAD_FIN_HTTP}"
  if [ "$BAD_FIN_HTTP" = "409" ]; then
    pass
  else
    fail "expected HTTP 409 for bad checksum, got ${BAD_FIN_HTTP}"
  fi

  # Clean up
  curl -s -o /dev/null $CURL_TIMEOUT -X DELETE \
    -H "$(auth_header)" \
    "${BASE_URL}/api/v1/uploads/${BAD_SESSION_ID}" 2>/dev/null || true
else
  skip "could not create session for bad checksum test"
fi

# =========================================================================
# Cleanup
# =========================================================================

echo ""
echo "Cleaning up..."
api_delete "/api/v1/repositories/${REPO_KEY}/artifacts/test/chunked-file.bin" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${REPO_KEY}/artifacts/test/resumed-file.bin" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${REPO_KEY}" > /dev/null 2>&1 || true

end_suite
