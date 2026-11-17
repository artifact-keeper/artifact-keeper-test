#!/usr/bin/env bash
# test-latency-injection.sh - Verify operations succeed under high latency
#
# Injects 500ms of egress latency on the backend pod with tc netem, proves
# the delay is in effect (tc qdisc show, ping RTT from the pod, request time
# measured from the runner), confirms that uploads and downloads still
# complete, then removes the delay and proves the request time recovers.
#
# The backend image has no tc, so the delay is applied from the fault-net
# container that tests/lib/k8s.sh attaches to the backend pod (same network
# namespace; artifact-keeper-test#842). A delay that cannot be applied or
# cannot be measured is INFRA (exit 11), never a skip.
#
# Requires: kubectl, NAMESPACE. The node kernel needs the sch_netem module.

source "$(dirname "$0")/../../lib/common.sh"
source "$(dirname "$0")/../../lib/k8s.sh"

begin_suite "network-latency"
require_cmd kubectl
setup_workdir

NAMESPACE="${NAMESPACE:-ak-test-${RUN_ID}}"
REPO_KEY="net-latency-${RUN_ID}"
DELAY_MS=500

# ---------------------------------------------------------------------------
# Fault injector
# ---------------------------------------------------------------------------

begin_test "Attach fault injector to the backend pod"
k8s_fault_injector_attach BACKEND_POD
IFACE=$(k8s_fault_net_iface "$BACKEND_POD" 2>/dev/null || true)
GATEWAY=$(k8s_fault_net_gateway "$BACKEND_POD" 2>/dev/null || true)
if [ -z "$IFACE" ] || [ -z "$GATEWAY" ]; then
  _k8s_fault_abort "could not read the backend pod's default route (iface='${IFACE}', gateway='${GATEWAY}')" \
    "$(k8s_fault_net "$BACKEND_POD" ip route 2>&1)"
fi
echo "  Interface ${IFACE}, gateway ${GATEWAY}"
pass

auth_admin

# Whatever happens below, never leave the backend delayed.
add_exit_handler 'k8s_fault_cleanup_latency "$BACKEND_POD" "$IFACE"'

# ---------------------------------------------------------------------------
# Baseline
# ---------------------------------------------------------------------------

begin_test "Create generic repository"
if create_local_repo "$REPO_KEY" "generic"; then
  pass
else
  fail "could not create generic repo"
fi

begin_test "Measure baseline latency"
k8s_fault_ping "$BACKEND_POD" "$GATEWAY" 5 || true
BASE_PING_MS="${K8S_PING_AVG_MS:-}"
BASE_HTTP_MS=$(k8s_fault_http_median_ms "${BASE_URL}/health" 5 || true)
echo "  Baseline: ping ${BASE_PING_MS:-?}ms, GET /health ${BASE_HTTP_MS:-?}ms (median of 5)"
if [ -z "$BASE_PING_MS" ] || [ -z "$BASE_HTTP_MS" ]; then
  _k8s_fault_abort "could not measure baseline latency (ping '${BASE_PING_MS}', http '${BASE_HTTP_MS}'), so a delay could not be shown to take effect"
fi
pass

begin_test "Upload baseline artifact at normal speed"
dd if=/dev/urandom bs=1024 count=64 of="${WORK_DIR}/baseline.bin" 2>/dev/null
BASELINE_START=$(date +%s)
if api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/files/v1/baseline.bin" \
    "${WORK_DIR}/baseline.bin" "application/octet-stream" > /dev/null; then
  echo "  Baseline upload took $(( $(date +%s) - BASELINE_START ))s"
  pass
else
  fail "baseline upload failed"
fi

# ---------------------------------------------------------------------------
# Inject latency
# ---------------------------------------------------------------------------

begin_test "Inject ${DELAY_MS}ms latency via tc netem"
if ! tc_out=$(k8s_fault_net_latency_add "$BACKEND_POD" "$IFACE" "$DELAY_MS" 2>&1); then
  _k8s_fault_abort "tc netem could not be applied on ${IFACE} in the backend pod" "$tc_out"
fi
echo "  tc qdisc show dev ${IFACE}:"
k8s_fault_net "$BACKEND_POD" tc qdisc show dev "$IFACE" 2>&1 | sed 's/^/    /'
pass

begin_test "Verify the delay is in effect"
k8s_fault_ping "$BACKEND_POD" "$GATEWAY" 3 || true
SLOW_PING_MS="${K8S_PING_AVG_MS:-0}"
SLOW_HTTP_MS=$(k8s_fault_http_median_ms "${BASE_URL}/health" 3 || echo 0)
echo "  Under delay: ping ${SLOW_PING_MS}ms, GET /health ${SLOW_HTTP_MS}ms (baseline ${BASE_PING_MS}ms / ${BASE_HTTP_MS}ms)"
# Every packet the backend sends waits DELAY_MS: a ping's echo request, and
# for a request from the runner, the SYN-ACK and the response.
if [ "$SLOW_PING_MS" -lt $(( DELAY_MS * 9 / 10 )) ] || \
   [ "$SLOW_HTTP_MS" -lt $(( BASE_HTTP_MS + DELAY_MS * 9 / 10 )) ]; then
  _k8s_fault_abort "netem is installed but the measured delay is not (ping ${SLOW_PING_MS}ms, http ${SLOW_HTTP_MS}ms vs baseline ${BASE_HTTP_MS}ms)" \
    "$(k8s_fault_net "$BACKEND_POD" tc -s qdisc show dev "$IFACE" 2>&1)"
fi
echo "  Measured delay: +$(( SLOW_HTTP_MS - BASE_HTTP_MS ))ms per request"
pass

# ---------------------------------------------------------------------------
# Upload/download under latency
# ---------------------------------------------------------------------------

begin_test "Upload under ${DELAY_MS}ms latency"
dd if=/dev/urandom bs=1024 count=16 of="${WORK_DIR}/slow-upload.bin" 2>/dev/null
SLOW_SHA=$(shasum -a 256 "${WORK_DIR}/slow-upload.bin" | awk '{print $1}')
SLOW_START=$(date +%s)
if api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/files/v1/slow-upload.bin" \
    "${WORK_DIR}/slow-upload.bin" "application/octet-stream" > /dev/null; then
  echo "  Upload under latency took $(( $(date +%s) - SLOW_START ))s"
  pass
else
  fail "upload under latency failed"
fi

begin_test "Download under ${DELAY_MS}ms latency"
if curl -sf $CURL_TIMEOUT -H "$(auth_header)" \
    -o "${WORK_DIR}/slow-download.bin" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}/download/files/v1/slow-upload.bin"; then
  DL_SHA=$(shasum -a 256 "${WORK_DIR}/slow-download.bin" | awk '{print $1}')
  if assert_eq "$DL_SHA" "$SLOW_SHA" "checksum mismatch under latency"; then
    pass
  fi
else
  fail "download under latency failed"
fi

# ---------------------------------------------------------------------------
# Remove latency and verify recovery
# ---------------------------------------------------------------------------

begin_test "Remove latency injection"
if ! del_out=$(k8s_fault_net_latency_del "$BACKEND_POD" "$IFACE" 2>&1); then
  _k8s_fault_abort "could not remove the netem qdisc from ${IFACE}" "$del_out"
fi
if k8s_fault_net "$BACKEND_POD" tc qdisc show dev "$IFACE" 2>&1 | grep -q netem; then
  _k8s_fault_abort "netem is still installed on ${IFACE} after removal" \
    "$(k8s_fault_net "$BACKEND_POD" tc qdisc show dev "$IFACE" 2>&1)"
fi
echo "  netem removed"
pass

begin_test "Verify normal latency restored"
FAST_HTTP_MS=$(k8s_fault_http_median_ms "${BASE_URL}/health" 5 || echo 99999)
echo "  After removal: GET /health ${FAST_HTTP_MS}ms (baseline ${BASE_HTTP_MS}ms)"
if [ "$FAST_HTTP_MS" -lt $(( BASE_HTTP_MS + DELAY_MS / 2 )) ]; then
  pass
else
  fail "request time did not recover after removing the delay (${FAST_HTTP_MS}ms vs baseline ${BASE_HTTP_MS}ms)"
fi

begin_test "Upload works after removing latency"
dd if=/dev/urandom bs=1024 count=16 of="${WORK_DIR}/fast-upload.bin" 2>/dev/null
FAST_START=$(date +%s)
if api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/files/v1/fast-upload.bin" \
    "${WORK_DIR}/fast-upload.bin" "application/octet-stream" > /dev/null; then
  echo "  Post-cleanup upload took $(( $(date +%s) - FAST_START ))s"
  pass
else
  fail "upload after removing latency failed"
fi

end_suite
