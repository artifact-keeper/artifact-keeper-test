#!/usr/bin/env bash
# test-partition-heal.sh - Verify recovery after network partition from PostgreSQL
#
# Uploads artifacts, blocks the backend's connectivity to PostgreSQL using
# iptables, verifies that operations fail gracefully, restores connectivity,
# and confirms that the backend resumes normal operation with all data intact.
#
# The backend image has no iptables, so the partition is applied from the
# fault-net container that tests/lib/k8s.sh attaches to the backend pod (same
# network namespace; artifact-keeper-test#842). Before and after the block, a
# TCP connect from the pod to PostgreSQL proves the partition really started
# and really healed. A partition that cannot be applied or verified is INFRA
# (exit 11), never a skip.
#
# Requires: kubectl, NAMESPACE

source "$(dirname "$0")/../../lib/common.sh"
source "$(dirname "$0")/../../lib/k8s.sh"

begin_suite "network-partition-heal"
require_cmd kubectl
setup_workdir

NAMESPACE="${NAMESPACE:-ak-test-${RUN_ID}}"
REPO_KEY="net-partition-${RUN_ID}"

# ---------------------------------------------------------------------------
# Fault injector and PostgreSQL address
# ---------------------------------------------------------------------------

begin_test "Attach fault injector to the backend pod"
k8s_fault_injector_attach BACKEND_POD
pass

begin_test "Locate PostgreSQL pod"
k8s_require_pod PG_POD "$AK_POSTGRES_SELECTOR" postgres
PG_IP=$(kubectl get pod "$PG_POD" -n "${NAMESPACE}" -o jsonpath='{.status.podIP}' 2>/dev/null || true)
if [ -z "$PG_IP" ]; then
  _k8s_fault_abort "PostgreSQL pod ${PG_POD} has no pod IP"
fi
echo "  PostgreSQL pod: ${PG_POD} (${PG_IP})"
if ! k8s_fault_net_tcp_probe "$BACKEND_POD" "$PG_IP" 5432; then
  _k8s_fault_abort "the backend pod cannot reach PostgreSQL at ${PG_IP}:5432 before any fault, so the partition probe cannot tell blocked from unreachable"
fi
echo "  TCP ${PG_IP}:5432 reachable from the backend pod"
pass

auth_admin

add_exit_handler 'k8s_fault_cleanup_partition "$BACKEND_POD"'

# ---------------------------------------------------------------------------
# Upload baseline data
# ---------------------------------------------------------------------------

begin_test "Create generic repository"
if create_local_repo "$REPO_KEY" "generic"; then
  pass
else
  fail "could not create generic repo"
fi

begin_test "Upload baseline artifacts"
baseline_ok=true
for i in $(seq 1 3); do
  dd if=/dev/urandom bs=1024 count=2 of="${WORK_DIR}/part-${i}.bin" 2>/dev/null
  if ! api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/files/v1/part-${i}.bin" \
      "${WORK_DIR}/part-${i}.bin" "application/octet-stream" > /dev/null; then
    fail "upload of part-${i} failed"
    baseline_ok=false
    break
  fi
done
[ "$baseline_ok" = true ] && pass

# ---------------------------------------------------------------------------
# Block connectivity to PostgreSQL
# ---------------------------------------------------------------------------

begin_test "Block backend connectivity to PostgreSQL (port 5432)"
if ! block_out=$(k8s_fault_net_block_port_add "$BACKEND_POD" 5432 2>&1); then
  _k8s_fault_abort "iptables could not add the partition rule in the backend pod" "$block_out"
fi
echo "  iptables -S OUTPUT:"
k8s_fault_net "$BACKEND_POD" iptables -w -S OUTPUT 2>&1 | sed 's/^/    /'
if k8s_fault_net_tcp_probe "$BACKEND_POD" "$PG_IP" 5432; then
  _k8s_fault_abort "the partition rule is installed but ${PG_IP}:5432 is still reachable from the backend pod"
fi
echo "  TCP ${PG_IP}:5432 now unreachable from the backend pod"
RESTARTS_BEFORE=$(kubectl get pod "$BACKEND_POD" -n "${NAMESPACE}" \
  -o jsonpath='{.status.containerStatuses[?(@.name=="backend")].restartCount}' 2>/dev/null || echo "?")
pass

# ---------------------------------------------------------------------------
# Verify operations fail gracefully
# ---------------------------------------------------------------------------

begin_test "Writes fail during partition instead of reporting success"
# Give the connection pool time to notice the break
sleep 5
upload_status=$(curl -s -o "${WORK_DIR}/partition-response.txt" -w '%{http_code}' -X PUT \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "test-during-partition" \
  --max-time 30 \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/files/v1/during-partition.bin" 2>/dev/null || true)
upload_status="${upload_status:-000}"
echo "  Upload during partition returned: ${upload_status} (000 = no response within 30s)"
echo "  Partition rule has dropped $(k8s_fault_net_rule_packets "$BACKEND_POD" OUTPUT ak-fault-partition) packets so far"
# An upload must record a row in PostgreSQL. A 2xx while the database is
# verifiably unreachable reports a write that cannot have been committed.
if [ "$upload_status" -ge 200 ] 2>/dev/null && [ "$upload_status" -lt 300 ] 2>/dev/null; then
  fail "upload returned ${upload_status} while PostgreSQL was unreachable" "$(head -c 2000 "${WORK_DIR}/partition-response.txt" 2>/dev/null)"
elif grep -qi 'panic' "${WORK_DIR}/partition-response.txt" 2>/dev/null; then
  fail "error response during partition contains a panic" "$(head -c 2000 "${WORK_DIR}/partition-response.txt")"
else
  echo "  Operation failed as expected during partition"
  pass
fi

# ---------------------------------------------------------------------------
# Restore connectivity
# ---------------------------------------------------------------------------

begin_test "Restore backend connectivity to PostgreSQL"
k8s_fault_net_block_port_del "$BACKEND_POD" >/dev/null 2>&1 || true
if k8s_fault_net "$BACKEND_POD" iptables -w -S OUTPUT 2>&1 | grep -q 'ak-fault-partition'; then
  _k8s_fault_abort "the partition rule is still installed after removal" \
    "$(k8s_fault_net "$BACKEND_POD" iptables -w -S OUTPUT 2>&1)"
fi
if ! k8s_fault_net_tcp_probe "$BACKEND_POD" "$PG_IP" 5432; then
  _k8s_fault_abort "rule removed but ${PG_IP}:5432 is still unreachable from the backend pod"
fi
echo "  Partition healed: TCP ${PG_IP}:5432 reachable again"
pass

# ---------------------------------------------------------------------------
# Wait for recovery
# ---------------------------------------------------------------------------

begin_test "Wait for backend to recover after partition heal"
# Give the connection pool time to reconnect
sleep 5
elapsed=0
health_ok=false
while [ "$elapsed" -lt 60 ]; do
  h_status=$(curl -s -o /dev/null -w '%{http_code}' "${BASE_URL}/health" 2>/dev/null) || true
  if [ "$h_status" = "200" ] || [ "$h_status" = "503" ]; then
    health_ok=true
    break
  fi
  sleep 2
  elapsed=$(( elapsed + 2 ))
done
if [ "$health_ok" = true ]; then
  echo "  Backend healthy after partition heal"
  pass
else
  fail "backend did not recover within 60s after partition heal"
fi

# ---------------------------------------------------------------------------
# Verify data intact
# ---------------------------------------------------------------------------

begin_test "Writes recover after partition heal"
# The pool may hold connections that died during the partition; give it up
# to 120s to replace them, then require a real write.
dd if=/dev/urandom bs=1024 count=2 of="${WORK_DIR}/post-partition.bin" 2>/dev/null
waited=0
write_ok=false
while [ "$waited" -le 120 ]; do
  if api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/files/v1/post-partition.bin" \
      "${WORK_DIR}/post-partition.bin" "application/octet-stream" > /dev/null 2>&1; then
    write_ok=true
    break
  fi
  sleep 5
  waited=$(( waited + 5 ))
done
RESTARTS_AFTER=$(kubectl get pod "$BACKEND_POD" -n "${NAMESPACE}" \
  -o jsonpath='{.status.containerStatuses[?(@.name=="backend")].restartCount}' 2>/dev/null || echo "?")
echo "  Backend container restarts across the partition: ${RESTARTS_BEFORE} -> ${RESTARTS_AFTER}"
if [ "$write_ok" = true ]; then
  echo "  First successful write ${waited}s after the heal"
  pass
else
  fail "no upload succeeded within 120s of the partition healing"
fi

begin_test "Re-authenticate after partition heal"
if auth_admin 2>/dev/null; then
  pass
else
  fail "re-authentication failed after partition heal"
fi

begin_test "Verify artifacts intact after partition heal"
if resp=$(api_get "/api/v1/repositories/${REPO_KEY}/artifacts"); then
  if assert_contains "$resp" "part-1.bin" "should contain part-1.bin"; then
    pass
  fi
else
  fail "could not list artifacts after partition heal"
fi

begin_test "Recovered artifact is downloadable"
if assert_http_ok "/api/v1/repositories/${REPO_KEY}/download/files/v1/post-partition.bin"; then
  pass
fi

end_suite
