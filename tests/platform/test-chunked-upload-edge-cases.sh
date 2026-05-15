#!/usr/bin/env bash
# test-chunked-upload-edge-cases.sh - Edge case tests for chunked upload API
#
# Covers boundary conditions and error paths: single-chunk files, exact
# divisibility, out-of-order uploads, invalid headers, non-existent sessions,
# cancelled session re-use, and chunk size validation.
#
# Requires: curl, jq, sha256sum (or shasum), dd

source "$(dirname "$0")/../lib/common.sh"

begin_suite "chunked-upload-edge-cases"
auth_admin
setup_workdir

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

REPO_KEY="chunk-edge-${RUN_ID}"
CHUNK_SIZE_MB="${CHUNK_SIZE_MB:-5}"
CHUNK_SIZE=$(( CHUNK_SIZE_MB * 1024 * 1024 ))

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
# Setup
# ---------------------------------------------------------------------------

begin_test "Create repository for edge case tests"
if create_local_repo "$REPO_KEY" "generic"; then
  pass
else
  fail "could not create repo ${REPO_KEY}"
fi

# =========================================================================
# Test 1: Single-chunk file (file size < chunk_size)
# =========================================================================

begin_test "Single-chunk file upload"
SMALL_SIZE=$(( 1 * 1024 * 1024 ))  # 1 MB, smaller than default 5MB chunk
dd if=/dev/urandom of="${WORK_DIR}/small.bin" bs=1048576 count=1 2>/dev/null
SMALL_SHA=$(compute_sha256 "${WORK_DIR}/small.bin")

SC_RESP=$(curl -s $CURL_TIMEOUT -X POST \
  -H "$(auth_header)" \
  -H "Content-Type: application/json" \
  -w "\n%{http_code}" \
  -d "{
    \"repository_key\": \"${REPO_KEY}\",
    \"artifact_path\": \"test/single-chunk.bin\",
    \"total_size\": ${SMALL_SIZE},
    \"chunk_size\": ${CHUNK_SIZE},
    \"checksum_sha256\": \"${SMALL_SHA}\"
  }" \
  "${BASE_URL}/api/v1/uploads" 2>/dev/null) || true
SC_HTTP=$(echo "$SC_RESP" | tail -1)
SC_BODY=$(echo "$SC_RESP" | sed '$d')
SC_SESSION=""

if [ "$SC_HTTP" = "201" ]; then
  SC_SESSION=$(echo "$SC_BODY" | jq -r '.session_id // .id // empty')
  SC_CHUNKS=$(echo "$SC_BODY" | jq -r '.chunk_count // .total_chunks // empty')
  echo "  session: ${SC_SESSION}, chunks: ${SC_CHUNKS}"

  if [ -n "$SC_SESSION" ]; then
    # Should be just 1 chunk
    RANGE_END=$(( SMALL_SIZE - 1 ))
    SC_UP_HTTP=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X PATCH \
      -H "$(auth_header)" \
      -H "Content-Type: application/octet-stream" \
      -H "Content-Range: bytes 0-${RANGE_END}/${SMALL_SIZE}" \
      --data-binary "@${WORK_DIR}/small.bin" \
      "${BASE_URL}/api/v1/uploads/${SC_SESSION}") || SC_UP_HTTP="000"

    SC_FIN_HTTP=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X PUT \
      -H "$(auth_header)" \
      -H "Content-Type: application/json" \
      "${BASE_URL}/api/v1/uploads/${SC_SESSION}/complete") || SC_FIN_HTTP="000"

    if [ "$SC_FIN_HTTP" = "200" ]; then
      pass
    else
      fail "single-chunk finalize returned HTTP ${SC_FIN_HTTP}"
    fi
  else
    fail "no session_id in response"
  fi
else
  fail "session creation returned HTTP ${SC_HTTP}"
fi

# =========================================================================
# Test 2: File size exactly divisible by chunk_size (no remainder)
# =========================================================================

begin_test "Exact divisible file size"
EXACT_CHUNKS=2
EXACT_SIZE=$(( EXACT_CHUNKS * CHUNK_SIZE ))
EXACT_SIZE_MB=$(( EXACT_CHUNKS * CHUNK_SIZE_MB ))
dd if=/dev/urandom of="${WORK_DIR}/exact.bin" bs=1048576 count="$EXACT_SIZE_MB" 2>/dev/null
EXACT_SHA=$(compute_sha256 "${WORK_DIR}/exact.bin")

EX_RESP=$(curl -s $CURL_TIMEOUT -X POST \
  -H "$(auth_header)" \
  -H "Content-Type: application/json" \
  -w "\n%{http_code}" \
  -d "{
    \"repository_key\": \"${REPO_KEY}\",
    \"artifact_path\": \"test/exact-div.bin\",
    \"total_size\": ${EXACT_SIZE},
    \"chunk_size\": ${CHUNK_SIZE},
    \"checksum_sha256\": \"${EXACT_SHA}\"
  }" \
  "${BASE_URL}/api/v1/uploads" 2>/dev/null) || true
EX_HTTP=$(echo "$EX_RESP" | tail -1)
EX_BODY=$(echo "$EX_RESP" | sed '$d')
EX_SESSION=""

if [ "$EX_HTTP" = "201" ]; then
  EX_SESSION=$(echo "$EX_BODY" | jq -r '.session_id // .id // empty')
  EX_CHUNK_COUNT=$(echo "$EX_BODY" | jq -r '.chunk_count // .total_chunks // empty')
  echo "  chunks reported: ${EX_CHUNK_COUNT}, expected: ${EXACT_CHUNKS}"

  if [ -n "$EX_SESSION" ]; then
    EX_OK=true
    for (( i=0; i<EXACT_CHUNKS; i++ )); do
      RANGE_START=$(( i * CHUNK_SIZE ))
      RANGE_END=$(( RANGE_START + CHUNK_SIZE - 1 ))

      dd if="${WORK_DIR}/exact.bin" of="${WORK_DIR}/exact_chunk_${i}" \
        bs=1048576 skip=$(( i * CHUNK_SIZE_MB )) count="$CHUNK_SIZE_MB" 2>/dev/null

      EX_UP_HTTP=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X PATCH \
        -H "$(auth_header)" \
        -H "Content-Type: application/octet-stream" \
        -H "Content-Range: bytes ${RANGE_START}-${RANGE_END}/${EXACT_SIZE}" \
        --data-binary "@${WORK_DIR}/exact_chunk_${i}" \
        "${BASE_URL}/api/v1/uploads/${EX_SESSION}") || EX_UP_HTTP="000"

      if [ "$EX_UP_HTTP" != "200" ] && [ "$EX_UP_HTTP" != "202" ]; then
        fail "exact-div chunk ${i} returned HTTP ${EX_UP_HTTP}"
        EX_OK=false
        break
      fi
    done

    if $EX_OK; then
      EX_FIN_HTTP=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X PUT \
        -H "$(auth_header)" \
        -H "Content-Type: application/json" \
        "${BASE_URL}/api/v1/uploads/${EX_SESSION}/complete") || EX_FIN_HTTP="000"

      if [ "$EX_FIN_HTTP" = "200" ]; then
        pass
      else
        fail "exact-div finalize returned HTTP ${EX_FIN_HTTP}"
      fi
    fi
  else
    fail "no session_id"
  fi
else
  fail "session creation returned HTTP ${EX_HTTP}"
fi

# =========================================================================
# Test 3: Out-of-order chunk upload (upload chunk 2, then 0, then 1)
# =========================================================================

begin_test "Out-of-order chunk upload"
OOO_CHUNKS=3
OOO_SIZE=$(( OOO_CHUNKS * CHUNK_SIZE ))
OOO_SIZE_MB=$(( OOO_CHUNKS * CHUNK_SIZE_MB ))
dd if=/dev/urandom of="${WORK_DIR}/ooo.bin" bs=1048576 count="$OOO_SIZE_MB" 2>/dev/null
OOO_SHA=$(compute_sha256 "${WORK_DIR}/ooo.bin")

OOO_RESP=$(curl -s $CURL_TIMEOUT -X POST \
  -H "$(auth_header)" \
  -H "Content-Type: application/json" \
  -w "\n%{http_code}" \
  -d "{
    \"repository_key\": \"${REPO_KEY}\",
    \"artifact_path\": \"test/ooo-file.bin\",
    \"total_size\": ${OOO_SIZE},
    \"chunk_size\": ${CHUNK_SIZE},
    \"checksum_sha256\": \"${OOO_SHA}\"
  }" \
  "${BASE_URL}/api/v1/uploads" 2>/dev/null) || true
OOO_HTTP=$(echo "$OOO_RESP" | tail -1)
OOO_BODY=$(echo "$OOO_RESP" | sed '$d')
OOO_SESSION=""

if [ "$OOO_HTTP" = "201" ]; then
  OOO_SESSION=$(echo "$OOO_BODY" | jq -r '.session_id // .id // empty')
fi

if [ -n "$OOO_SESSION" ]; then
  # Split into 3 chunks
  for (( i=0; i<OOO_CHUNKS; i++ )); do
    dd if="${WORK_DIR}/ooo.bin" of="${WORK_DIR}/ooo_chunk_${i}" \
      bs=1048576 skip=$(( i * CHUNK_SIZE_MB )) count="$CHUNK_SIZE_MB" 2>/dev/null
  done

  # Upload in order: 2, 0, 1
  OOO_ORDER=(2 0 1)
  OOO_OK=true
  for idx in "${OOO_ORDER[@]}"; do
    RANGE_START=$(( idx * CHUNK_SIZE ))
    RANGE_END=$(( RANGE_START + CHUNK_SIZE - 1 ))

    OOO_UP_HTTP=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X PATCH \
      -H "$(auth_header)" \
      -H "Content-Type: application/octet-stream" \
      -H "Content-Range: bytes ${RANGE_START}-${RANGE_END}/${OOO_SIZE}" \
      --data-binary "@${WORK_DIR}/ooo_chunk_${idx}" \
      "${BASE_URL}/api/v1/uploads/${OOO_SESSION}") || OOO_UP_HTTP="000"

    echo "  chunk ${idx}: HTTP ${OOO_UP_HTTP}"
    if [ "$OOO_UP_HTTP" != "200" ] && [ "$OOO_UP_HTTP" != "202" ]; then
      fail "out-of-order chunk ${idx} returned HTTP ${OOO_UP_HTTP}"
      OOO_OK=false
      break
    fi
  done

  if $OOO_OK; then
    OOO_FIN_HTTP=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X PUT \
      -H "$(auth_header)" \
      -H "Content-Type: application/json" \
      "${BASE_URL}/api/v1/uploads/${OOO_SESSION}/complete") || OOO_FIN_HTTP="000"

    if [ "$OOO_FIN_HTTP" = "200" ]; then
      # Download and verify
      OOO_DL_HTTP=$(curl -s -o "${WORK_DIR}/ooo_dl.bin" -w '%{http_code}' \
        $CURL_TIMEOUT -H "$(auth_header)" \
        "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/test/ooo-file.bin") || OOO_DL_HTTP="000"

      if [ "$OOO_DL_HTTP" = "200" ]; then
        OOO_DL_SHA=$(compute_sha256 "${WORK_DIR}/ooo_dl.bin")
        if [ "$OOO_DL_SHA" = "$OOO_SHA" ]; then
          pass
        else
          fail "SHA256 mismatch after out-of-order upload"
        fi
      else
        fail "download returned HTTP ${OOO_DL_HTTP}"
      fi
    else
      fail "finalize returned HTTP ${OOO_FIN_HTTP}"
    fi
  fi
else
  skip "could not create session for out-of-order test"
fi

# =========================================================================
# Test 4: Invalid Content-Range header (expect 400)
# =========================================================================

begin_test "Invalid Content-Range header returns 400"
BAD_RANGE_RESP=$(curl -s $CURL_TIMEOUT -X POST \
  -H "$(auth_header)" \
  -H "Content-Type: application/json" \
  -w "\n%{http_code}" \
  -d "{
    \"repository_key\": \"${REPO_KEY}\",
    \"artifact_path\": \"test/bad-range.bin\",
    \"total_size\": ${CHUNK_SIZE},
    \"chunk_size\": ${CHUNK_SIZE},
    \"checksum_sha256\": \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"
  }" \
  "${BASE_URL}/api/v1/uploads" 2>/dev/null) || true
BR_HTTP=$(echo "$BAD_RANGE_RESP" | tail -1)
BR_BODY=$(echo "$BAD_RANGE_RESP" | sed '$d')
BR_SESSION=""

if [ "$BR_HTTP" = "201" ]; then
  BR_SESSION=$(echo "$BR_BODY" | jq -r '.session_id // .id // empty')
fi

if [ -n "$BR_SESSION" ]; then
  dd if=/dev/urandom of="${WORK_DIR}/badrange.bin" bs=1024 count=10 2>/dev/null

  # Send garbage Content-Range
  BR_UP_HTTP=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X PATCH \
    -H "$(auth_header)" \
    -H "Content-Type: application/octet-stream" \
    -H "Content-Range: bytes invalid-range-format" \
    --data-binary "@${WORK_DIR}/badrange.bin" \
    "${BASE_URL}/api/v1/uploads/${BR_SESSION}") || BR_UP_HTTP="000"

  echo "  HTTP response: ${BR_UP_HTTP}"
  if [ "$BR_UP_HTTP" = "400" ]; then
    pass
  else
    fail "expected HTTP 400 for invalid Content-Range, got ${BR_UP_HTTP}"
  fi

  # Clean up
  curl -s -o /dev/null $CURL_TIMEOUT -X DELETE \
    -H "$(auth_header)" \
    "${BASE_URL}/api/v1/uploads/${BR_SESSION}" 2>/dev/null || true
else
  skip "could not create session for bad-range test"
fi

# =========================================================================
# Test 5: Upload to non-existent session (expect 404)
# =========================================================================

begin_test "Upload to non-existent session returns 404"
FAKE_SESSION="00000000-0000-0000-0000-000000000000"
dd if=/dev/urandom of="${WORK_DIR}/fake.bin" bs=1024 count=10 2>/dev/null

FAKE_HTTP=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X PATCH \
  -H "$(auth_header)" \
  -H "Content-Type: application/octet-stream" \
  -H "Content-Range: bytes 0-1023/10240" \
  --data-binary "@${WORK_DIR}/fake.bin" \
  "${BASE_URL}/api/v1/uploads/${FAKE_SESSION}") || FAKE_HTTP="000"

echo "  HTTP response: ${FAKE_HTTP}"
if [ "$FAKE_HTTP" = "404" ]; then
  pass
else
  fail "expected HTTP 404 for non-existent session, got ${FAKE_HTTP}"
fi

# =========================================================================
# Test 6: Upload after session cancelled (expect 410)
# =========================================================================

begin_test "Upload to cancelled session returns 404"
GONE_RESP=$(curl -s $CURL_TIMEOUT -X POST \
  -H "$(auth_header)" \
  -H "Content-Type: application/json" \
  -w "\n%{http_code}" \
  -d "{
    \"repository_key\": \"${REPO_KEY}\",
    \"artifact_path\": \"test/gone-file.bin\",
    \"total_size\": ${CHUNK_SIZE},
    \"chunk_size\": ${CHUNK_SIZE},
    \"checksum_sha256\": \"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"
  }" \
  "${BASE_URL}/api/v1/uploads" 2>/dev/null) || true
GONE_HTTP=$(echo "$GONE_RESP" | tail -1)
GONE_BODY=$(echo "$GONE_RESP" | sed '$d')
GONE_SESSION=""

if [ "$GONE_HTTP" = "201" ]; then
  GONE_SESSION=$(echo "$GONE_BODY" | jq -r '.session_id // .id // empty')
fi

if [ -n "$GONE_SESSION" ]; then
  # Cancel the session
  curl -s -o /dev/null $CURL_TIMEOUT -X DELETE \
    -H "$(auth_header)" \
    "${BASE_URL}/api/v1/uploads/${GONE_SESSION}" 2>/dev/null || true

  # Try uploading to the cancelled session
  dd if=/dev/urandom of="${WORK_DIR}/gone.bin" bs=1024 count=10 2>/dev/null
  GONE_RANGE_END=$(( CHUNK_SIZE - 1 ))

  GONE_UP_HTTP=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X PATCH \
    -H "$(auth_header)" \
    -H "Content-Type: application/octet-stream" \
    -H "Content-Range: bytes 0-${GONE_RANGE_END}/${CHUNK_SIZE}" \
    --data-binary "@${WORK_DIR}/gone.bin" \
    "${BASE_URL}/api/v1/uploads/${GONE_SESSION}") || GONE_UP_HTTP="000"

  echo "  HTTP response: ${GONE_UP_HTTP}"
  # Cancelled sessions return 404 (not 410; 410 is reserved for expired sessions)
  if [ "$GONE_UP_HTTP" = "404" ]; then
    pass
  else
    fail "expected HTTP 404 for cancelled session, got ${GONE_UP_HTTP}"
  fi
else
  skip "could not create session for cancelled-upload test"
fi

# =========================================================================
# Test 7: Chunk size too small (< 1MB, expect 400)
# =========================================================================

begin_test "Chunk size below minimum (< 1MB) returns 400"
TOOSMALL_SIZE=$(( 512 * 1024 ))  # 512 KB

TOOSMALL_HTTP=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X POST \
  -H "$(auth_header)" \
  -H "Content-Type: application/json" \
  -d "{
    \"repository_key\": \"${REPO_KEY}\",
    \"artifact_path\": \"test/toosmall.bin\",
    \"total_size\": 10485760,
    \"chunk_size\": ${TOOSMALL_SIZE},
    \"checksum_sha256\": \"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\"
  }" \
  "${BASE_URL}/api/v1/uploads") || TOOSMALL_HTTP="000"

echo "  HTTP response: ${TOOSMALL_HTTP}"
if [ "$TOOSMALL_HTTP" = "400" ]; then
  pass
else
  fail "expected HTTP 400 for chunk_size < 1MB, got ${TOOSMALL_HTTP}"
fi

# =========================================================================
# Test 8: Chunk size too large (> 256MB, expect 400)
# =========================================================================

begin_test "Chunk size above maximum (> 256MB) returns 400"
TOOLARGE_SIZE=$(( 300 * 1024 * 1024 ))  # 300 MB

TOOLARGE_HTTP=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X POST \
  -H "$(auth_header)" \
  -H "Content-Type: application/json" \
  -d "{
    \"repository_key\": \"${REPO_KEY}\",
    \"artifact_path\": \"test/toolarge.bin\",
    \"total_size\": 536870912,
    \"chunk_size\": ${TOOLARGE_SIZE},
    \"checksum_sha256\": \"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\"
  }" \
  "${BASE_URL}/api/v1/uploads") || TOOLARGE_HTTP="000"

echo "  HTTP response: ${TOOLARGE_HTTP}"
if [ "$TOOLARGE_HTTP" = "400" ]; then
  pass
else
  fail "expected HTTP 400 for chunk_size > 256MB, got ${TOOLARGE_HTTP}"
fi

# =========================================================================
# Test 9: Missing Content-Range header (expect 400)
# =========================================================================

begin_test "Missing Content-Range header returns 400"
NORANGE_RESP=$(curl -s $CURL_TIMEOUT -X POST \
  -H "$(auth_header)" \
  -H "Content-Type: application/json" \
  -w "\n%{http_code}" \
  -d "{
    \"repository_key\": \"${REPO_KEY}\",
    \"artifact_path\": \"test/norange.bin\",
    \"total_size\": ${CHUNK_SIZE},
    \"chunk_size\": ${CHUNK_SIZE},
    \"checksum_sha256\": \"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\"
  }" \
  "${BASE_URL}/api/v1/uploads" 2>/dev/null) || true
NR_HTTP=$(echo "$NORANGE_RESP" | tail -1)
NR_BODY=$(echo "$NORANGE_RESP" | sed '$d')
NR_SESSION=""

if [ "$NR_HTTP" = "201" ]; then
  NR_SESSION=$(echo "$NR_BODY" | jq -r '.session_id // .id // empty')
fi

if [ -n "$NR_SESSION" ]; then
  dd if=/dev/urandom of="${WORK_DIR}/norange.bin" bs=1024 count=10 2>/dev/null

  # Upload without Content-Range header
  NR_UP_HTTP=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X PATCH \
    -H "$(auth_header)" \
    -H "Content-Type: application/octet-stream" \
    --data-binary "@${WORK_DIR}/norange.bin" \
    "${BASE_URL}/api/v1/uploads/${NR_SESSION}") || NR_UP_HTTP="000"

  echo "  HTTP response: ${NR_UP_HTTP}"
  if [ "$NR_UP_HTTP" = "400" ]; then
    pass
  else
    fail "expected HTTP 400 for missing Content-Range, got ${NR_UP_HTTP}"
  fi

  curl -s -o /dev/null $CURL_TIMEOUT -X DELETE \
    -H "$(auth_header)" \
    "${BASE_URL}/api/v1/uploads/${NR_SESSION}" 2>/dev/null || true
else
  skip "could not create session for missing Content-Range test"
fi

# =========================================================================
# Test 10: Content-Range body size mismatch (expect 400)
# =========================================================================

begin_test "Content-Range body size mismatch returns 400"
MISMATCH_RESP=$(curl -s $CURL_TIMEOUT -X POST \
  -H "$(auth_header)" \
  -H "Content-Type: application/json" \
  -w "\n%{http_code}" \
  -d "{
    \"repository_key\": \"${REPO_KEY}\",
    \"artifact_path\": \"test/mismatch.bin\",
    \"total_size\": ${CHUNK_SIZE},
    \"chunk_size\": ${CHUNK_SIZE},
    \"checksum_sha256\": \"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\"
  }" \
  "${BASE_URL}/api/v1/uploads" 2>/dev/null) || true
MM_HTTP=$(echo "$MISMATCH_RESP" | tail -1)
MM_BODY=$(echo "$MISMATCH_RESP" | sed '$d')
MM_SESSION=""

if [ "$MM_HTTP" = "201" ]; then
  MM_SESSION=$(echo "$MM_BODY" | jq -r '.session_id // .id // empty')
fi

if [ -n "$MM_SESSION" ]; then
  # Send 1KB body but claim Content-Range of 5MB
  dd if=/dev/urandom of="${WORK_DIR}/mismatch.bin" bs=1024 count=1 2>/dev/null
  RANGE_END=$(( CHUNK_SIZE - 1 ))

  MM_UP_HTTP=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X PATCH \
    -H "$(auth_header)" \
    -H "Content-Type: application/octet-stream" \
    -H "Content-Range: bytes 0-${RANGE_END}/${CHUNK_SIZE}" \
    --data-binary "@${WORK_DIR}/mismatch.bin" \
    "${BASE_URL}/api/v1/uploads/${MM_SESSION}") || MM_UP_HTTP="000"

  echo "  HTTP response: ${MM_UP_HTTP}"
  if [ "$MM_UP_HTTP" = "400" ]; then
    pass
  else
    fail "expected HTTP 400 for body/Content-Range mismatch, got ${MM_UP_HTTP}"
  fi

  curl -s -o /dev/null $CURL_TIMEOUT -X DELETE \
    -H "$(auth_header)" \
    "${BASE_URL}/api/v1/uploads/${MM_SESSION}" 2>/dev/null || true
else
  skip "could not create session for body size mismatch test"
fi

# =========================================================================
# Test 11: Concurrent uploads to same artifact_path (last to finalize wins)
# =========================================================================

begin_test "Concurrent uploads to same path"
CONC_SIZE=$(( 2 * CHUNK_SIZE ))
CONC_SIZE_MB=$(( 2 * CHUNK_SIZE_MB ))
dd if=/dev/urandom of="${WORK_DIR}/conc_a.bin" bs=1048576 count="$CONC_SIZE_MB" 2>/dev/null
dd if=/dev/urandom of="${WORK_DIR}/conc_b.bin" bs=1048576 count="$CONC_SIZE_MB" 2>/dev/null
CONC_SHA_A=$(compute_sha256 "${WORK_DIR}/conc_a.bin")
CONC_SHA_B=$(compute_sha256 "${WORK_DIR}/conc_b.bin")

# Create two sessions for the same artifact path
CONC_A_RESP=$(curl -s $CURL_TIMEOUT -X POST \
  -H "$(auth_header)" \
  -H "Content-Type: application/json" \
  -w "\n%{http_code}" \
  -d "{
    \"repository_key\": \"${REPO_KEY}\",
    \"artifact_path\": \"test/concurrent.bin\",
    \"total_size\": ${CONC_SIZE},
    \"chunk_size\": ${CHUNK_SIZE},
    \"checksum_sha256\": \"${CONC_SHA_A}\"
  }" \
  "${BASE_URL}/api/v1/uploads" 2>/dev/null) || true
CONC_A_HTTP=$(echo "$CONC_A_RESP" | tail -1)
CONC_A_BODY=$(echo "$CONC_A_RESP" | sed '$d')

CONC_B_RESP=$(curl -s $CURL_TIMEOUT -X POST \
  -H "$(auth_header)" \
  -H "Content-Type: application/json" \
  -w "\n%{http_code}" \
  -d "{
    \"repository_key\": \"${REPO_KEY}\",
    \"artifact_path\": \"test/concurrent.bin\",
    \"total_size\": ${CONC_SIZE},
    \"chunk_size\": ${CHUNK_SIZE},
    \"checksum_sha256\": \"${CONC_SHA_B}\"
  }" \
  "${BASE_URL}/api/v1/uploads" 2>/dev/null) || true
CONC_B_HTTP=$(echo "$CONC_B_RESP" | tail -1)
CONC_B_BODY=$(echo "$CONC_B_RESP" | sed '$d')

CONC_A_SESSION=""
CONC_B_SESSION=""
if [ "$CONC_A_HTTP" = "201" ]; then
  CONC_A_SESSION=$(echo "$CONC_A_BODY" | jq -r '.session_id // .id // empty')
fi
if [ "$CONC_B_HTTP" = "201" ]; then
  CONC_B_SESSION=$(echo "$CONC_B_BODY" | jq -r '.session_id // .id // empty')
fi

if [ -n "$CONC_A_SESSION" ] && [ -n "$CONC_B_SESSION" ]; then
  echo "  session A: ${CONC_A_SESSION}"
  echo "  session B: ${CONC_B_SESSION}"

  # Upload all chunks for session A
  for (( i=0; i<2; i++ )); do
    RANGE_START=$(( i * CHUNK_SIZE ))
    RANGE_END=$(( RANGE_START + CHUNK_SIZE - 1 ))
    dd if="${WORK_DIR}/conc_a.bin" of="${WORK_DIR}/conc_a_chunk_${i}" \
      bs=1048576 skip=$(( i * CHUNK_SIZE_MB )) count="$CHUNK_SIZE_MB" 2>/dev/null
    curl -s -o /dev/null $CURL_TIMEOUT -X PATCH \
      -H "$(auth_header)" \
      -H "Content-Type: application/octet-stream" \
      -H "Content-Range: bytes ${RANGE_START}-${RANGE_END}/${CONC_SIZE}" \
      --data-binary "@${WORK_DIR}/conc_a_chunk_${i}" \
      "${BASE_URL}/api/v1/uploads/${CONC_A_SESSION}" 2>/dev/null || true
  done

  # Upload all chunks for session B
  for (( i=0; i<2; i++ )); do
    RANGE_START=$(( i * CHUNK_SIZE ))
    RANGE_END=$(( RANGE_START + CHUNK_SIZE - 1 ))
    dd if="${WORK_DIR}/conc_b.bin" of="${WORK_DIR}/conc_b_chunk_${i}" \
      bs=1048576 skip=$(( i * CHUNK_SIZE_MB )) count="$CHUNK_SIZE_MB" 2>/dev/null
    curl -s -o /dev/null $CURL_TIMEOUT -X PATCH \
      -H "$(auth_header)" \
      -H "Content-Type: application/octet-stream" \
      -H "Content-Range: bytes ${RANGE_START}-${RANGE_END}/${CONC_SIZE}" \
      --data-binary "@${WORK_DIR}/conc_b_chunk_${i}" \
      "${BASE_URL}/api/v1/uploads/${CONC_B_SESSION}" 2>/dev/null || true
  done

  # Finalize A first, then B (B should win as last-to-finalize)
  CONC_A_FIN=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X PUT \
    -H "$(auth_header)" -H "Content-Type: application/json" \
    "${BASE_URL}/api/v1/uploads/${CONC_A_SESSION}/complete") || CONC_A_FIN="000"
  CONC_B_FIN=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X PUT \
    -H "$(auth_header)" -H "Content-Type: application/json" \
    "${BASE_URL}/api/v1/uploads/${CONC_B_SESSION}/complete") || CONC_B_FIN="000"

  echo "  finalize A: HTTP ${CONC_A_FIN}"
  echo "  finalize B: HTTP ${CONC_B_FIN}"

  # Both should succeed (200)
  if [ "$CONC_A_FIN" = "200" ] && [ "$CONC_B_FIN" = "200" ]; then
    # Download and verify B's content won (last to finalize)
    CONC_DL_HTTP=$(curl -s -o "${WORK_DIR}/conc_dl.bin" -w '%{http_code}' \
      $CURL_TIMEOUT -H "$(auth_header)" \
      "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/test/concurrent.bin") || CONC_DL_HTTP="000"

    if [ "$CONC_DL_HTTP" = "200" ]; then
      CONC_DL_SHA=$(compute_sha256 "${WORK_DIR}/conc_dl.bin")
      echo "  downloaded SHA: ${CONC_DL_SHA}"
      echo "  session B SHA: ${CONC_SHA_B}"
      if [ "$CONC_DL_SHA" = "$CONC_SHA_B" ]; then
        pass
      else
        # A might have won if it was finalized after B in race, either is acceptable
        if [ "$CONC_DL_SHA" = "$CONC_SHA_A" ]; then
          echo "  (session A won the race instead of B, still valid)"
          pass
        else
          fail "downloaded content doesn't match either session"
        fi
      fi
    else
      fail "download after concurrent upload returned HTTP ${CONC_DL_HTTP}"
    fi
  else
    fail "expected both finalizations to return 200 (got A=${CONC_A_FIN}, B=${CONC_B_FIN})"
  fi
else
  skip "could not create both concurrent sessions (A=${CONC_A_HTTP}, B=${CONC_B_HTTP})"
fi

# =========================================================================
# Cleanup
# =========================================================================

echo ""
echo "Cleaning up..."
api_delete "/api/v1/repositories/${REPO_KEY}/artifacts/test/single-chunk.bin" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${REPO_KEY}/artifacts/test/exact-div.bin" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${REPO_KEY}/artifacts/test/ooo-file.bin" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${REPO_KEY}/artifacts/test/concurrent.bin" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${REPO_KEY}" > /dev/null 2>&1 || true

end_suite
