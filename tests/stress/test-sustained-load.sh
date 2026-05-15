#!/usr/bin/env bash
# test-sustained-load.sh - Sustained mixed workload stress test
#
# Runs a continuous mixed workload (auth + upload + download + list) for
# 60 seconds and measures error rate over time. This tests whether the
# backend degrades progressively or hits a cliff under sustained pressure.
#
# Reports: requests/sec, error rate per 10s window, and overall p95 latency.
#
# Requires: curl, jq

source "$(dirname "$0")/../lib/common.sh"

begin_suite "sustained-load"
auth_admin
setup_workdir

REPO_KEY="test-sustained-${RUN_ID}"
DURATION_SECS="${SUSTAINED_DURATION:-60}"
CONCURRENT_WORKERS=5
RESULTS_DIR="${WORK_DIR}/sustained"
mkdir -p "$RESULTS_DIR"

begin_test "Create repo for sustained load"
if create_local_repo "$REPO_KEY" "generic"; then
  pass
else
  fail "could not create repo"
fi

# Seed an artifact for download tests
echo "seed-artifact-for-downloads-${RUN_ID}" > "${WORK_DIR}/seed.bin"
api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/seed/download-target.bin" \
  "${WORK_DIR}/seed.bin" > /dev/null 2>&1 || true

# ---------------------------------------------------------------------------
# Worker: runs mixed operations in a loop until stop file appears
# ---------------------------------------------------------------------------

run_worker() {
  local worker_id="$1"
  local stop_file="${RESULTS_DIR}/stop"
  local log_file="${RESULTS_DIR}/worker-${worker_id}.log"
  local counter=0

  while [ ! -f "$stop_file" ]; do
    counter=$(( counter + 1 ))
    local op=$(( counter % 4 ))
    local start_s=$(date +%s)
    local start_ms
    start_ms=$(date +%s%3N 2>/dev/null || echo "${start_s}000")
    local http_code="000"
    local method="GET"
    local endpoint=""

    case $op in
      0) # auth
        method="POST"
        endpoint="/api/v1/auth/login"
        http_code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
          -X POST "${BASE_URL}${endpoint}" \
          -H "Content-Type: application/json" \
          -d "{\"username\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASS}\"}" 2>/dev/null) || http_code="000"
        ;;
      1) # upload
        method="PUT"
        endpoint="/api/v1/repositories/${REPO_KEY}/artifacts/sustained/w${worker_id}-${counter}.bin"
        echo "sustained-${worker_id}-${counter}-${RUN_ID}" > "${WORK_DIR}/w${worker_id}-${counter}.bin"
        http_code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 \
          -X PUT -H "Authorization: Bearer ${ADMIN_TOKEN}" \
          -H "Content-Type: application/octet-stream" \
          --data-binary "@${WORK_DIR}/w${worker_id}-${counter}.bin" \
          "${BASE_URL}${endpoint}" 2>/dev/null) || http_code="000"
        rm -f "${WORK_DIR}/w${worker_id}-${counter}.bin"
        ;;
      2) # list
        method="GET"
        endpoint="/api/v1/repositories/${REPO_KEY}/artifacts"
        http_code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
          -H "Authorization: Bearer ${ADMIN_TOKEN}" \
          "${BASE_URL}${endpoint}" 2>/dev/null) || http_code="000"
        ;;
      3) # download
        method="GET"
        endpoint="/api/v1/repositories/${REPO_KEY}/artifacts/seed/download-target.bin"
        http_code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
          -H "Authorization: Bearer ${ADMIN_TOKEN}" \
          "${BASE_URL}${endpoint}" 2>/dev/null) || http_code="000"
        ;;
    esac

    local end_s=$(date +%s)
    local end_ms
    end_ms=$(date +%s%3N 2>/dev/null || echo "${end_s}000")
    local elapsed=$(( end_s - start_s ))
    local elapsed_ms=$(( end_ms - start_ms ))
    echo "${end_s} ${http_code} ${elapsed}" >> "$log_file"
    log_request "${method}" "${endpoint}" "${http_code}" "${elapsed_ms}"
  done
}

# ---------------------------------------------------------------------------
# Run sustained load
# ---------------------------------------------------------------------------

begin_test "Sustained ${DURATION_SECS}s mixed workload (${CONCURRENT_WORKERS} workers)"

# Start workers
for w in $(seq 1 "$CONCURRENT_WORKERS"); do
  run_worker "$w" &
done

# Let them run
sleep "$DURATION_SECS"

# Signal stop
touch "${RESULTS_DIR}/stop"
sleep 3
wait 2>/dev/null

# ---------------------------------------------------------------------------
# Analyze results
# ---------------------------------------------------------------------------

total_requests=0
total_success=0
total_error=0
total_timeout=0

for log in "${RESULTS_DIR}"/worker-*.log; do
  [ -f "$log" ] || continue
  while read -r ts code elapsed; do
    total_requests=$(( total_requests + 1 ))
    if [ "$code" -ge 200 ] 2>/dev/null && [ "$code" -lt 400 ] 2>/dev/null; then
      total_success=$(( total_success + 1 ))
    elif [ "$code" = "000" ]; then
      total_timeout=$(( total_timeout + 1 ))
    else
      total_error=$(( total_error + 1 ))
    fi
  done < "$log"
done

if [ "$total_requests" -eq 0 ]; then
  fail "no requests were recorded"
else
  rps=$(( total_requests / DURATION_SECS ))
  error_pct=0
  if [ "$total_requests" -gt 0 ]; then
    error_pct=$(( (total_error + total_timeout) * 100 / total_requests ))
  fi

  echo "  Duration: ${DURATION_SECS}s"
  echo "  Workers: ${CONCURRENT_WORKERS}"
  echo "  Total requests: ${total_requests}"
  echo "  Successful: ${total_success}"
  echo "  Errors (4xx/5xx): ${total_error}"
  echo "  Timeouts: ${total_timeout}"
  echo "  Throughput: ~${rps} req/s"
  echo "  Error rate: ${error_pct}%"

  # Pass criteria: error rate under 30% (mixed workload includes auth
  # requests which are CPU-heavy due to bcrypt, causing some timeouts
  # under sustained concurrent load on a test pod).
  #
  # Threshold history:
  #   - 2026-03 (v1.1.x, Meilisearch): runs measured at 12-20% error, ~27-53 RPS
  #   - 2026-04 (v1.2.x, OpenSearch):  runs measure 21-23% error, ~104-152 RPS
  #
  # v1.2 introduced OpenSearch as a per-upload indexing dependency, which
  # shares the same 4 CPU / 8 Gi namespace quota as the backend. The
  # backend is also faster end-to-end now, so workers issue more requests
  # per second and saturate sooner. Net effect: ~2-3% higher error rate
  # under the same shape of test, even though absolute throughput improved.
  #
  # The 30% threshold is generous on purpose for this constrained CI
  # environment (single 2-CPU backend pod, no HPA, no separate OpenSearch
  # node). Production SLAs are tracked separately, see follow-up issue.
  threshold=${SUSTAINED_ERROR_PCT_THRESHOLD:-30}
  if [ "$error_pct" -le "$threshold" ]; then
    pass
  else
    fail "error rate ${error_pct}% exceeds ${threshold}% threshold (${total_error} errors + ${total_timeout} timeouts out of ${total_requests} requests)"
  fi
fi

# ---------------------------------------------------------------------------
# Recovery check
# ---------------------------------------------------------------------------

begin_test "Backend responsive after sustained load"
# Cool-down window: the previous 25s ceiling was right at the edge of
# observed recovery times in v1.2.x runs. Now that uploads also drive
# OpenSearch indexing in the critical path, the in-flight queue takes
# longer to drain after the stop signal. The throughput suite that
# follows (see test-throughput.sh auth_admin retries) typically clears
# in under 15s, so 60s here is an order of magnitude of headroom while
# still catching a genuinely deadlocked backend.
sleep 10
recovered=false
for _try in $(seq 1 20); do
  if resp=$(curl -sf --max-time 10 -X POST "${BASE_URL}/api/v1/auth/login" \
      -H "Content-Type: application/json" \
      -d "{\"username\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASS}\"}" 2>/dev/null); then
    recovered=true
    break
  fi
  sleep 3
done
if $recovered; then
  pass
else
  fail "backend unresponsive after sustained load (60s+ cool-down)"
fi

end_suite
