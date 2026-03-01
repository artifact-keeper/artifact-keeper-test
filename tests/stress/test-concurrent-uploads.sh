#!/usr/bin/env bash
# test-concurrent-uploads.sh - Concurrent upload stress test
#
# Launches multiple parallel uploads to a single repository and verifies
# that the server handles them without excessive failures. The concurrency
# level is configurable via the CONCURRENCY env var (default 20).

source "$(dirname "$0")/../lib/common.sh"

begin_suite "concurrent-uploads"
auth_admin
setup_workdir

REPO_KEY="test-concurrent-${RUN_ID}"
CONCURRENCY="${CONCURRENCY:-20}"
MIN_SUCCESS_RATE=95

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
# Generate test files
# ---------------------------------------------------------------------------

begin_test "Generate ${CONCURRENCY} test files"
mkdir -p "${WORK_DIR}/files"
for i in $(seq 1 "$CONCURRENCY"); do
  dd if=/dev/urandom bs=1024 count=1 of="${WORK_DIR}/files/file-${i}.bin" 2>/dev/null
done

file_count=$(ls "${WORK_DIR}/files/" | wc -l | tr -d ' ')
if [ "$file_count" -eq "$CONCURRENCY" ]; then
  pass
else
  fail "expected ${CONCURRENCY} files, generated ${file_count}"
fi

# ---------------------------------------------------------------------------
# Upload all files in parallel
# ---------------------------------------------------------------------------

begin_test "Upload ${CONCURRENCY} files concurrently"
mkdir -p "${WORK_DIR}/results"

for i in $(seq 1 "$CONCURRENCY"); do
  (
    status=$(curl -s -o /dev/null -w '%{http_code}' \
      -X PUT \
      -H "$(auth_header)" \
      -H "Content-Type: application/octet-stream" \
      --data-binary "@${WORK_DIR}/files/file-${i}.bin" \
      "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/stress/file-${i}.bin") || true
    echo "$status" > "${WORK_DIR}/results/upload-${i}.status"
  ) &
done

# Wait for all background uploads
wait

success_count=0
failure_count=0
for i in $(seq 1 "$CONCURRENCY"); do
  status_file="${WORK_DIR}/results/upload-${i}.status"
  if [ -f "$status_file" ]; then
    code=$(cat "$status_file")
    if [ "$code" -ge 200 ] 2>/dev/null && [ "$code" -lt 300 ] 2>/dev/null; then
      success_count=$((success_count + 1))
    else
      failure_count=$((failure_count + 1))
      echo "  file-${i}.bin: HTTP ${code}"
    fi
  else
    failure_count=$((failure_count + 1))
    echo "  file-${i}.bin: no status file (upload may have crashed)"
  fi
done

echo "  ${success_count}/${CONCURRENCY} uploads succeeded, ${failure_count} failed"

min_required=$(( CONCURRENCY * MIN_SUCCESS_RATE / 100 ))
if [ "$success_count" -ge "$min_required" ]; then
  pass
else
  fail "only ${success_count}/${CONCURRENCY} uploads succeeded, need at least ${min_required} (${MIN_SUCCESS_RATE}%)"
fi

# ---------------------------------------------------------------------------
# Verify all successful uploads are downloadable
# ---------------------------------------------------------------------------

begin_test "Verify successful uploads are downloadable"
download_ok=0
download_fail=0

for i in $(seq 1 "$CONCURRENCY"); do
  status_file="${WORK_DIR}/results/upload-${i}.status"
  if [ -f "$status_file" ]; then
    code=$(cat "$status_file")
    if [ "$code" -ge 200 ] 2>/dev/null && [ "$code" -lt 300 ] 2>/dev/null; then
      dl_status=$(curl -s -o /dev/null -w '%{http_code}' \
        -H "$(auth_header)" \
        "${BASE_URL}/api/v1/repositories/${REPO_KEY}/download/stress/file-${i}.bin") || true
      if [ "$dl_status" = "200" ]; then
        download_ok=$((download_ok + 1))
      else
        download_fail=$((download_fail + 1))
        echo "  file-${i}.bin: download returned HTTP ${dl_status}"
      fi
    fi
  fi
done

echo "  ${download_ok}/${success_count} successful uploads are downloadable"
if [ "$download_fail" -eq 0 ]; then
  pass
else
  fail "${download_fail} of ${success_count} uploaded files could not be downloaded"
fi

end_suite
