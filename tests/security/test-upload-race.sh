#!/usr/bin/env bash
# test-upload-race.sh - T2-22: Concurrent same-version upload race condition
#
# Verifies that two concurrent uploads of different content to the same artifact
# path result in a consistent, non-corrupted artifact. One upload should win and
# the stored content should match that upload exactly.

source "$(dirname "$0")/../lib/common.sh"

begin_suite "upload-race"
auth_admin
setup_workdir

REPO_KEY="sec-uploadrace-${RUN_ID}"

# ---------------------------------------------------------------------------
# Create a generic repository
# ---------------------------------------------------------------------------

begin_test "Create generic local repo"
if create_local_repo "$REPO_KEY" "generic"; then
  pass
else
  fail "could not create generic repo"
fi

# ---------------------------------------------------------------------------
# Create two distinct files for concurrent upload
# ---------------------------------------------------------------------------

begin_test "Prepare two distinct artifact files"
# Generate 1KB files with distinct content so we can verify which one won
dd if=/dev/urandom bs=1024 count=1 2>/dev/null > "${WORK_DIR}/file-a.bin"
dd if=/dev/urandom bs=1024 count=1 2>/dev/null > "${WORK_DIR}/file-b.bin"

SHA_A=$(shasum -a 256 "${WORK_DIR}/file-a.bin" | awk '{print $1}')
SHA_B=$(shasum -a 256 "${WORK_DIR}/file-b.bin" | awk '{print $1}')

if [ "$SHA_A" != "$SHA_B" ] && [ -n "$SHA_A" ] && [ -n "$SHA_B" ]; then
  pass
else
  fail "could not generate two distinct files"
fi

# ---------------------------------------------------------------------------
# Upload both files simultaneously to the same path
# ---------------------------------------------------------------------------

ARTIFACT_PATH="/api/v1/repositories/${REPO_KEY}/artifacts/race-pkg/v1/payload.bin"

begin_test "Concurrent upload of two different files to same path"
# Launch both uploads in background
status_a_file="${WORK_DIR}/status-a.txt"
status_b_file="${WORK_DIR}/status-b.txt"

curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X PUT \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@${WORK_DIR}/file-a.bin" \
  "${BASE_URL}${ARTIFACT_PATH}" > "$status_a_file" 2>/dev/null &
pid_a=$!

curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X PUT \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@${WORK_DIR}/file-b.bin" \
  "${BASE_URL}${ARTIFACT_PATH}" > "$status_b_file" 2>/dev/null &
pid_b=$!

# Wait for both to complete
wait "$pid_a" 2>/dev/null || true
wait "$pid_b" 2>/dev/null || true

status_a=$(cat "$status_a_file" 2>/dev/null) || status_a="000"
status_b=$(cat "$status_b_file" 2>/dev/null) || status_b="000"

echo "  Upload A status: ${status_a}"
echo "  Upload B status: ${status_b}"

# At least one should succeed. The other may get 409 (conflict) or also succeed.
a_ok=false
b_ok=false
if [ "$status_a" -ge 200 ] 2>/dev/null && [ "$status_a" -lt 300 ] 2>/dev/null; then a_ok=true; fi
if [ "$status_b" -ge 200 ] 2>/dev/null && [ "$status_b" -lt 300 ] 2>/dev/null; then b_ok=true; fi

if $a_ok || $b_ok; then
  pass
elif [ "$status_a" = "409" ] || [ "$status_b" = "409" ]; then
  # Server detected the conflict and rejected one, which is also correct
  pass
else
  fail "neither upload succeeded (A=${status_a}, B=${status_b})"
fi

# ---------------------------------------------------------------------------
# Download and verify integrity
# ---------------------------------------------------------------------------

sleep 1

begin_test "Downloaded artifact matches one of the uploaded files"
DOWNLOAD_PATH="/api/v1/repositories/${REPO_KEY}/download/race-pkg/v1/payload.bin"
if curl -sf $CURL_TIMEOUT -H "$(auth_header)" \
    -o "${WORK_DIR}/downloaded.bin" \
    "${BASE_URL}${DOWNLOAD_PATH}" 2>/dev/null; then
  DL_SHA=$(shasum -a 256 "${WORK_DIR}/downloaded.bin" | awk '{print $1}')

  if [ "$DL_SHA" = "$SHA_A" ]; then
    echo "  Downloaded artifact matches file A"
    pass
  elif [ "$DL_SHA" = "$SHA_B" ]; then
    echo "  Downloaded artifact matches file B"
    pass
  else
    fail "downloaded artifact checksum (${DL_SHA}) matches neither file A (${SHA_A}) nor file B (${SHA_B}) - possible corruption"
  fi
else
  # Try format-level download
  if curl -sf $CURL_TIMEOUT -H "$(auth_header)" \
      -o "${WORK_DIR}/downloaded2.bin" \
      "${BASE_URL}/generic/${REPO_KEY}/race-pkg/v1/payload.bin" 2>/dev/null; then
    DL_SHA=$(shasum -a 256 "${WORK_DIR}/downloaded2.bin" | awk '{print $1}')
    if [ "$DL_SHA" = "$SHA_A" ] || [ "$DL_SHA" = "$SHA_B" ]; then
      pass
    else
      fail "downloaded artifact does not match either upload (possible corruption)"
    fi
  else
    skip "could not download artifact to verify integrity"
  fi
fi

# ---------------------------------------------------------------------------
# Run multiple concurrent uploads to stress test
# ---------------------------------------------------------------------------

begin_test "Five concurrent uploads to different paths"
pids=()
for i in $(seq 1 5); do
  echo "stress-content-${i}-${RUN_ID}" > "${WORK_DIR}/stress-${i}.bin"
  curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X PUT \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/octet-stream" \
    --data-binary "@${WORK_DIR}/stress-${i}.bin" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/stress/v${i}/payload.bin" \
    > "${WORK_DIR}/stress-status-${i}.txt" 2>/dev/null &
  pids+=($!)
done

# Wait for all
all_ok=true
for pid in "${pids[@]}"; do
  wait "$pid" 2>/dev/null || true
done

success_count=0
for i in $(seq 1 5); do
  s=$(cat "${WORK_DIR}/stress-status-${i}.txt" 2>/dev/null) || s="000"
  if [ "$s" -ge 200 ] 2>/dev/null && [ "$s" -lt 300 ] 2>/dev/null; then
    success_count=$((success_count + 1))
  fi
done

echo "  ${success_count}/5 concurrent uploads succeeded"
if [ "$success_count" -ge 3 ]; then
  pass
else
  fail "only ${success_count}/5 concurrent uploads succeeded"
fi

# ---------------------------------------------------------------------------
# Verify backend health after concurrent uploads
# ---------------------------------------------------------------------------

begin_test "Backend still healthy after concurrent upload tests"
health_ok=false
if curl -sf --max-time 10 "${BASE_URL}/readyz" >/dev/null 2>&1; then
  health_ok=true
elif curl -sf --max-time 10 "${BASE_URL}/health" >/dev/null 2>&1; then
  health_ok=true
fi

if $health_ok; then
  pass
else
  fail "backend health check failed after concurrent upload tests"
fi

end_suite
