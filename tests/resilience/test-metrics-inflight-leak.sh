#!/usr/bin/env bash
# test-metrics-inflight-leak.sh - Verify in-flight gauge doesn't leak on client disconnect
#
# Regression test for:
#   #771 - in-flight gauge leak when client disconnects mid-request
#
# The metrics middleware increments ak_http_requests_in_flight on request
# start and decrements on completion. If the client disconnects mid-request
# (future cancelled), the decrement must still fire (via RAII drop guard).
# Without the fix, the gauge leaks upward and never returns to zero.
#
# Requires: curl, grep

source "$(dirname "$0")/../../lib/common.sh"

begin_suite "metrics-inflight-leak"
auth_admin
setup_workdir

LOCAL_KEY="test-inflight-${RUN_ID}"

# Helper: get the current in-flight gauge value for a given method/path.
# Returns 0 if the metric doesn't exist yet (no requests made to that path).
get_inflight_gauge() {
  local resp
  resp=$(curl -sf --max-time 10 "${BASE_URL}/metrics" 2>/dev/null) || resp=""
  # Prometheus format: ak_http_requests_in_flight{method="...",path="..."} <value>
  # Sum all in-flight values across all method/path combos
  echo "$resp" | grep '^ak_http_requests_in_flight{' | awk '{sum += $2} END {printf "%.0f\n", sum+0}'
}

# =========================================================================
# Section 1: Baseline - verify gauge returns to 0 after normal requests
# =========================================================================

begin_test "Metrics endpoint is available"
if curl -sf --max-time 10 "${BASE_URL}/metrics" > /dev/null 2>&1; then
  pass
else
  fail "GET /metrics returned error"
fi

begin_test "In-flight gauge is zero when idle"
# Make a few normal requests first to ensure metrics are populated
curl -sf --max-time 5 "${BASE_URL}/health" > /dev/null 2>&1 || true
curl -sf --max-time 5 "${BASE_URL}/readyz" > /dev/null 2>&1 || true
sleep 1
GAUGE=$(get_inflight_gauge)
if [ "$GAUGE" -le 1 ] 2>/dev/null; then
  # 1 is acceptable because our own /metrics request is in-flight
  pass
else
  fail "in-flight gauge is $GAUGE when idle (expected 0 or 1)"
fi

# =========================================================================
# Section 2: Client disconnect during upload
# =========================================================================

begin_test "Create local repo for upload test"
if create_local_repo "$LOCAL_KEY" "generic"; then
  pass
else
  fail "could not create local repo"
fi

begin_test "In-flight gauge recovers after aborted upload"
# Create a large file (10MB) to upload
dd if=/dev/urandom of="${WORK_DIR}/large-file.bin" bs=1M count=10 2>/dev/null

# Record gauge before the aborted uploads
BEFORE=$(get_inflight_gauge)

# Start several uploads with very short timeouts so curl disconnects mid-transfer.
# Use --limit-rate to slow the upload so the server is still processing when
# curl gives up.
for i in $(seq 1 5); do
  curl -s --max-time 0.5 --limit-rate 100k \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    -X PUT \
    -T "${WORK_DIR}/large-file.bin" \
    "${BASE_URL}/generic/${LOCAL_KEY}/aborted-${i}/large-file.bin" \
    > /dev/null 2>&1 || true
done

# Give the server a moment to clean up cancelled futures
sleep 3

# Check gauge after aborted uploads
AFTER=$(get_inflight_gauge)

# The gauge should be back near zero (1 is acceptable due to our own metrics request).
# Without the fix, it would be 5+ (one leaked increment per aborted request).
if [ "$AFTER" -le 1 ] 2>/dev/null; then
  pass
elif [ "$AFTER" -le "$((BEFORE + 1))" ] 2>/dev/null; then
  pass
else
  fail "in-flight gauge leaked: before=$BEFORE, after=$AFTER (expected near 0 after aborted uploads)"
fi

# =========================================================================
# Section 3: Rapid connect/disconnect
# =========================================================================

begin_test "In-flight gauge recovers after rapid connect/disconnect"
BEFORE=$(get_inflight_gauge)

# Rapidly connect and immediately close connection (0.1s timeout)
for i in $(seq 1 10); do
  curl -s --max-time 0.1 --connect-timeout 0.1 \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    "${BASE_URL}/api/v1/repositories" \
    > /dev/null 2>&1 || true
done

sleep 2

AFTER=$(get_inflight_gauge)

if [ "$AFTER" -le 1 ] 2>/dev/null; then
  pass
elif [ "$AFTER" -le "$((BEFORE + 1))" ] 2>/dev/null; then
  pass
else
  fail "in-flight gauge leaked after rapid disconnect: before=$BEFORE, after=$AFTER"
fi

# =========================================================================
# Section 4: Normal requests still decrement properly
# =========================================================================

begin_test "In-flight gauge correct after normal request cycle"
# Run 20 normal requests
for i in $(seq 1 20); do
  curl -sf --max-time 5 \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    "${BASE_URL}/health" > /dev/null 2>&1 || true
done

sleep 1
FINAL=$(get_inflight_gauge)

if [ "$FINAL" -le 1 ] 2>/dev/null; then
  pass
else
  fail "in-flight gauge is $FINAL after normal requests (expected 0 or 1)"
fi

# =========================================================================
# Cleanup
# =========================================================================

api_delete "/api/v1/repositories/${LOCAL_KEY}" > /dev/null 2>&1 || true

end_suite
