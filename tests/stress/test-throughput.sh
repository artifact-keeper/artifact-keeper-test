#!/usr/bin/env bash
# test-throughput.sh - Upload/download throughput measurement
#
# Generates a 10MB file and measures sequential upload and download throughput
# over multiple iterations. Reports average MB/s for both directions and
# asserts a baseline minimum.

source "$(dirname "$0")/../lib/common.sh"

begin_suite "throughput"
auth_admin
setup_workdir

REPO_KEY="test-throughput-${RUN_ID}"
FILE_SIZE_MB=10
ITERATIONS=5
MIN_THROUGHPUT_MBS=1   # minimum acceptable MB/s

# ---------------------------------------------------------------------------
# Create repository
# ---------------------------------------------------------------------------

begin_test "Create generic local repository"
if create_local_repo "$REPO_KEY" "generic"; then
  pass
else
  fail "could not create generic repo"
fi

# ---------------------------------------------------------------------------
# Generate test file
# ---------------------------------------------------------------------------

begin_test "Generate ${FILE_SIZE_MB}MB test file"
dd if=/dev/urandom bs=1048576 count="$FILE_SIZE_MB" of="${WORK_DIR}/payload.bin" 2>/dev/null
actual_size=$(wc -c < "${WORK_DIR}/payload.bin" | tr -d ' ')
expected_size=$((FILE_SIZE_MB * 1048576))

if [ "$actual_size" -eq "$expected_size" ]; then
  pass
else
  fail "expected ${expected_size} bytes, got ${actual_size}"
fi

# ---------------------------------------------------------------------------
# Upload throughput
# ---------------------------------------------------------------------------

begin_test "Measure upload throughput (${ITERATIONS} iterations)"
upload_total_time=0
upload_failures=0

for i in $(seq 1 "$ITERATIONS"); do
  artifact_path="/api/v1/repositories/${REPO_KEY}/artifacts/bench/iteration-${i}/payload.bin"

  # Use curl's write-out to get total transfer time in seconds (with decimals)
  timing=$(curl -s -o /dev/null -w '%{time_total}' \
    -X PUT \
    -H "$(auth_header)" \
    -H "Content-Type: application/octet-stream" \
    --data-binary "@${WORK_DIR}/payload.bin" \
    "${BASE_URL}${artifact_path}") || true

  if [ -n "$timing" ] && [ "$timing" != "0.000000" ]; then
    # Use awk for floating point arithmetic
    throughput=$(echo "$FILE_SIZE_MB $timing" | awk '{printf "%.2f", $1 / $2}')
    echo "  upload ${i}: ${timing}s (${throughput} MB/s)"
    upload_total_time=$(echo "$upload_total_time $timing" | awk '{printf "%.6f", $1 + $2}')
  else
    upload_failures=$((upload_failures + 1))
    echo "  upload ${i}: failed"
  fi
done

successful_uploads=$((ITERATIONS - upload_failures))
if [ "$successful_uploads" -gt 0 ]; then
  avg_upload_time=$(echo "$upload_total_time $successful_uploads" | awk '{printf "%.3f", $1 / $2}')
  avg_upload_throughput=$(echo "$FILE_SIZE_MB $avg_upload_time" | awk '{printf "%.2f", $1 / $2}')
  echo "  average upload: ${avg_upload_time}s (${avg_upload_throughput} MB/s)"

  above_min=$(echo "$avg_upload_throughput $MIN_THROUGHPUT_MBS" | awk '{print ($1 >= $2) ? "yes" : "no"}')
  if [ "$above_min" = "yes" ]; then
    pass
  else
    fail "upload throughput ${avg_upload_throughput} MB/s is below minimum ${MIN_THROUGHPUT_MBS} MB/s"
  fi
else
  fail "all ${ITERATIONS} uploads failed"
fi

# ---------------------------------------------------------------------------
# Download throughput
# ---------------------------------------------------------------------------

begin_test "Measure download throughput (${ITERATIONS} iterations)"
download_total_time=0
download_failures=0

for i in $(seq 1 "$ITERATIONS"); do
  download_path="/api/v1/repositories/${REPO_KEY}/download/bench/iteration-${i}/payload.bin"

  timing=$(curl -s -o /dev/null -w '%{time_total}' \
    -H "$(auth_header)" \
    "${BASE_URL}${download_path}") || true

  if [ -n "$timing" ] && [ "$timing" != "0.000000" ]; then
    throughput=$(echo "$FILE_SIZE_MB $timing" | awk '{printf "%.2f", $1 / $2}')
    echo "  download ${i}: ${timing}s (${throughput} MB/s)"
    download_total_time=$(echo "$download_total_time $timing" | awk '{printf "%.6f", $1 + $2}')
  else
    download_failures=$((download_failures + 1))
    echo "  download ${i}: failed"
  fi
done

successful_downloads=$((ITERATIONS - download_failures))
if [ "$successful_downloads" -gt 0 ]; then
  avg_download_time=$(echo "$download_total_time $successful_downloads" | awk '{printf "%.3f", $1 / $2}')
  avg_download_throughput=$(echo "$FILE_SIZE_MB $avg_download_time" | awk '{printf "%.2f", $1 / $2}')
  echo "  average download: ${avg_download_time}s (${avg_download_throughput} MB/s)"

  above_min=$(echo "$avg_download_throughput $MIN_THROUGHPUT_MBS" | awk '{print ($1 >= $2) ? "yes" : "no"}')
  if [ "$above_min" = "yes" ]; then
    pass
  else
    fail "download throughput ${avg_download_throughput} MB/s is below minimum ${MIN_THROUGHPUT_MBS} MB/s"
  fi
else
  fail "all ${ITERATIONS} downloads failed"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

begin_test "Throughput summary"
if [ "$successful_uploads" -gt 0 ] && [ "$successful_downloads" -gt 0 ]; then
  echo "  Upload:   ${avg_upload_throughput} MB/s (avg over ${successful_uploads} runs)"
  echo "  Download: ${avg_download_throughput} MB/s (avg over ${successful_downloads} runs)"
  pass
else
  fail "insufficient data for summary"
fi

end_suite
