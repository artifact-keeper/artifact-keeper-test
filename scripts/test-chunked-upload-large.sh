#!/usr/bin/env bash
# test-chunked-upload-large.sh - Large file chunked upload test (local only)
#
# Spins up backend + postgres + meilisearch via docker compose, creates a 2GB
# test file, uploads it in chunks, finalizes, downloads, and verifies SHA256
# integrity. Intended for local validation, not CI.
#
# Usage:
#   ./scripts/test-chunked-upload-large.sh [--size-gb N] [--chunk-mb N] [--skip-compose]
#
# Options:
#   --size-gb N       File size in GB (default: 2)
#   --chunk-mb N      Chunk size in MB (default: 10)
#   --skip-compose    Skip docker compose up/down (use existing stack)

set -euo pipefail

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

SIZE_GB=2
CHUNK_MB=10
SKIP_COMPOSE=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --size-gb)    SIZE_GB="$2"; shift 2 ;;
    --chunk-mb)   CHUNK_MB="$2"; shift 2 ;;
    --skip-compose) SKIP_COMPOSE=true; shift ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

SIZE_BYTES=$(( SIZE_GB * 1024 * 1024 * 1024 ))
CHUNK_BYTES=$(( CHUNK_MB * 1024 * 1024 ))
SIZE_MB=$(( SIZE_GB * 1024 ))

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BACKEND_ROOT="${REPO_ROOT}/../artifact-keeper"

export BASE_URL="${BASE_URL:-http://localhost:8080}"
export ADMIN_USER="${ADMIN_USER:-admin}"
export ADMIN_PASS="${ADMIN_PASS:-admin123}"
export RUN_ID="large-$(date +%s)"

WORK_DIR="$(mktemp -d)"
trap 'echo "Cleaning up ${WORK_DIR}..."; rm -rf "$WORK_DIR"' EXIT

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
# Docker compose lifecycle
# ---------------------------------------------------------------------------

compose_up() {
  if [ ! -f "${BACKEND_ROOT}/docker-compose.local-dev.yml" ]; then
    echo "FATAL: ${BACKEND_ROOT}/docker-compose.local-dev.yml not found"
    echo "This script must be run from the artifact-keeper-test repo with"
    echo "the backend repo at ../artifact-keeper/"
    exit 1
  fi

  echo "Starting backend stack..."
  cd "$BACKEND_ROOT"
  docker compose -f docker-compose.local-dev.yml up -d postgres meilisearch
  sleep 3
  docker compose -f docker-compose.local-dev.yml up -d backend
  cd "$REPO_ROOT"

  echo "Waiting for backend to be ready..."
  for i in $(seq 1 30); do
    if curl -sf --max-time 5 "${BASE_URL}/readyz" >/dev/null 2>&1 || \
       curl -sf --max-time 5 "${BASE_URL}/health" >/dev/null 2>&1; then
      echo "  backend ready after ${i}s"
      return 0
    fi
    sleep 2
  done
  echo "FATAL: backend not ready after 60s"
  exit 1
}

compose_down() {
  echo "Stopping backend stack..."
  cd "$BACKEND_ROOT"
  docker compose -f docker-compose.local-dev.yml down
  cd "$REPO_ROOT"
}

# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

get_token() {
  local resp
  resp=$(curl -sf --max-time 10 -X POST "${BASE_URL}/api/v1/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASS}\"}" 2>/dev/null) || {
    echo "FATAL: failed to authenticate"
    exit 1
  }
  echo "$resp" | jq -r '.token // .access_token // empty'
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

echo "============================================"
echo "  Large File Chunked Upload Test"
echo "  File size: ${SIZE_GB} GB (${SIZE_BYTES} bytes)"
echo "  Chunk size: ${CHUNK_MB} MB (${CHUNK_BYTES} bytes)"
echo "  Run ID: ${RUN_ID}"
echo "============================================"
echo ""

if ! $SKIP_COMPOSE; then
  compose_up
fi

TOKEN=$(get_token)
AUTH="Authorization: Bearer ${TOKEN}"
CURL_TIMEOUT="--max-time 300 --connect-timeout 10"
REPO_KEY="large-upload-${RUN_ID}"

# Create repo
echo "Creating repository ${REPO_KEY}..."
curl -sf $CURL_TIMEOUT -X POST \
  -H "$AUTH" -H "Content-Type: application/json" \
  -d "{\"key\":\"${REPO_KEY}\",\"name\":\"${REPO_KEY}\",\"format\":\"generic\",\"repo_type\":\"local\",\"is_public\":true}" \
  "${BASE_URL}/api/v1/repositories" > /dev/null

# Generate test file
echo "Generating ${SIZE_GB}GB test file (this may take a moment)..."
dd if=/dev/urandom of="${WORK_DIR}/large.bin" bs=1048576 count="$SIZE_MB" 2>/dev/null
echo "Computing SHA256..."
FILE_SHA=$(compute_sha256 "${WORK_DIR}/large.bin")
echo "  SHA256: ${FILE_SHA}"

# Create upload session
echo "Creating upload session..."
SESSION_RESP=$(curl -sf $CURL_TIMEOUT -X POST \
  -H "$AUTH" -H "Content-Type: application/json" \
  -d "{
    \"repository_key\": \"${REPO_KEY}\",
    \"artifact_path\": \"test/large-file.bin\",
    \"total_size\": ${SIZE_BYTES},
    \"chunk_size\": ${CHUNK_BYTES},
    \"checksum_sha256\": \"${FILE_SHA}\"
  }" \
  "${BASE_URL}/api/v1/uploads")

SESSION_ID=$(echo "$SESSION_RESP" | jq -r '.session_id // .id // empty')
CHUNK_COUNT=$(echo "$SESSION_RESP" | jq -r '.chunk_count // .total_chunks // empty')
echo "  session_id: ${SESSION_ID}"
echo "  chunk_count: ${CHUNK_COUNT}"

if [ -z "$SESSION_ID" ]; then
  echo "FATAL: no session_id returned"
  exit 1
fi

# Upload chunks
EXPECTED_CHUNKS=$(( (SIZE_BYTES + CHUNK_BYTES - 1) / CHUNK_BYTES ))
echo ""
echo "Uploading ${EXPECTED_CHUNKS} chunks..."
UPLOAD_START=$(date +%s)

for (( i=0; i<EXPECTED_CHUNKS; i++ )); do
  RANGE_START=$(( i * CHUNK_BYTES ))
  REMAINING=$(( SIZE_BYTES - RANGE_START ))
  THIS_CHUNK=$(( REMAINING < CHUNK_BYTES ? REMAINING : CHUNK_BYTES ))
  RANGE_END=$(( RANGE_START + THIS_CHUNK - 1 ))
  THIS_CHUNK_MB=$(( THIS_CHUNK / 1048576 ))

  # Extract chunk
  dd if="${WORK_DIR}/large.bin" of="${WORK_DIR}/chunk.bin" \
    bs=1048576 skip=$(( i * CHUNK_MB )) count="$THIS_CHUNK_MB" 2>/dev/null

  CHUNK_HTTP=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X PATCH \
    -H "$AUTH" \
    -H "Content-Type: application/octet-stream" \
    -H "Content-Range: bytes ${RANGE_START}-${RANGE_END}/${SIZE_BYTES}" \
    --data-binary "@${WORK_DIR}/chunk.bin" \
    "${BASE_URL}/api/v1/uploads/${SESSION_ID}") || CHUNK_HTTP="000"

  PCT=$(( (i + 1) * 100 / EXPECTED_CHUNKS ))
  printf "  [%3d%%] chunk %d/%d: bytes %d-%d -> HTTP %s\n" \
    "$PCT" "$((i+1))" "$EXPECTED_CHUNKS" "$RANGE_START" "$RANGE_END" "$CHUNK_HTTP"

  if [ "$CHUNK_HTTP" != "200" ] && [ "$CHUNK_HTTP" != "202" ]; then
    echo "FATAL: chunk upload failed with HTTP ${CHUNK_HTTP}"
    exit 1
  fi
done

UPLOAD_END=$(date +%s)
UPLOAD_DURATION=$(( UPLOAD_END - UPLOAD_START ))
UPLOAD_SPEED=$(( SIZE_MB / (UPLOAD_DURATION > 0 ? UPLOAD_DURATION : 1) ))
echo ""
echo "  Upload completed in ${UPLOAD_DURATION}s (~${UPLOAD_SPEED} MB/s)"

# Finalize
echo ""
echo "Finalizing upload..."
FIN_HTTP=$(curl -s -o "${WORK_DIR}/finalize.json" -w '%{http_code}' $CURL_TIMEOUT -X PUT \
  -H "$AUTH" -H "Content-Type: application/json" \
  "${BASE_URL}/api/v1/uploads/${SESSION_ID}/complete") || FIN_HTTP="000"

if [ "$FIN_HTTP" != "200" ]; then
  echo "FATAL: finalize returned HTTP ${FIN_HTTP}"
  cat "${WORK_DIR}/finalize.json" 2>/dev/null
  exit 1
fi
echo "  Finalized successfully"

# Download and verify
echo ""
echo "Downloading artifact for integrity check..."
DL_START=$(date +%s)
DL_HTTP=$(curl -s -o "${WORK_DIR}/downloaded.bin" -w '%{http_code}' \
  --max-time 600 --connect-timeout 10 \
  -H "$AUTH" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/test/large-file.bin") || DL_HTTP="000"
DL_END=$(date +%s)
DL_DURATION=$(( DL_END - DL_START ))

if [ "$DL_HTTP" != "200" ]; then
  echo "FATAL: download returned HTTP ${DL_HTTP}"
  exit 1
fi

echo "  Downloaded in ${DL_DURATION}s"
echo "Computing download SHA256..."
DL_SHA=$(compute_sha256 "${WORK_DIR}/downloaded.bin")

echo "  Original: ${FILE_SHA}"
echo "  Download: ${DL_SHA}"

if [ "$DL_SHA" = "$FILE_SHA" ]; then
  echo ""
  echo "============================================"
  echo "  PASS: ${SIZE_GB}GB file integrity verified"
  echo "  Upload: ${UPLOAD_DURATION}s, Download: ${DL_DURATION}s"
  echo "============================================"
else
  echo ""
  echo "============================================"
  echo "  FAIL: SHA256 mismatch"
  echo "============================================"
  exit 1
fi

# Cleanup
echo ""
echo "Cleaning up..."
curl -sf $CURL_TIMEOUT -X DELETE -H "$AUTH" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/test/large-file.bin" > /dev/null 2>&1 || true
curl -sf $CURL_TIMEOUT -X DELETE -H "$AUTH" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}" > /dev/null 2>&1 || true

if ! $SKIP_COMPOSE; then
  compose_down
fi

echo "Done."
