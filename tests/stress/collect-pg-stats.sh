#!/usr/bin/env bash
# collect-pg-stats.sh - Snapshot postgres + pod-resource state after a stress run.
#
# Fresh-Eyes review on PR #148 flagged that the helm CPU rebalance in
# artifact-keeper-test#140 ships a narrative ("postgres CPU starvation
# surfaces as sqlx acquire_timeout, which surfaces as HTTP 500s") without
# direct measurement. This script captures the evidence that would
# confirm or refute the narrative on each stress-tests release-gate run.
#
# Outputs go to $PG_STATS_DIR (default /tmp/pg-stats) as plain text files,
# one per probe. The release-gate stress-tests job is expected to upload
# this directory as a workflow artifact (artifact-keeper-test#154 tracks
# the workflow wire-up).
#
# Usage:
#   tests/stress/collect-pg-stats.sh                   # auto-detect namespace
#   NAMESPACE=test-foo tests/stress/collect-pg-stats.sh
#
# Environment variables:
#   NAMESPACE        - kubectl namespace (default: $TEST_NAMESPACE or current
#                      context's namespace)
#   PG_STATS_DIR     - output directory (default: /tmp/pg-stats)
#   BACKEND_POD_RE   - regex to find the backend pod (default: artifact-keeper-backend)
#   POSTGRES_POD_RE  - regex to find the postgres pod (default: artifact-keeper-postgres)
#
# Exit code is always 0: this is a capture-best-effort tool, not an
# assertion. A missing kubectl binary, missing namespace, or missing
# pg_stat_statements extension should not fail the surrounding stress run.
#
# Requires: kubectl (with cluster access). psql inside the postgres pod.

set -u  # NOT set -e: every probe is best-effort.

NAMESPACE="${NAMESPACE:-${TEST_NAMESPACE:-}}"
PG_STATS_DIR="${PG_STATS_DIR:-/tmp/pg-stats}"
BACKEND_POD_RE="${BACKEND_POD_RE:-artifact-keeper-backend}"
POSTGRES_POD_RE="${POSTGRES_POD_RE:-artifact-keeper-postgres}"

mkdir -p "$PG_STATS_DIR"

if ! command -v kubectl >/dev/null 2>&1; then
  echo "kubectl not on PATH; skipping pg-stats capture" \
    | tee "${PG_STATS_DIR}/SKIPPED.txt"
  exit 0
fi

# Resolve namespace.
if [ -z "$NAMESPACE" ]; then
  NAMESPACE=$(kubectl config view --minify --output 'jsonpath={..namespace}' 2>/dev/null || true)
fi
if [ -z "$NAMESPACE" ]; then
  echo "NAMESPACE not set and no current-context namespace; skipping" \
    | tee "${PG_STATS_DIR}/SKIPPED.txt"
  exit 0
fi

echo "namespace: ${NAMESPACE}" > "${PG_STATS_DIR}/_meta.txt"
echo "captured_at: $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "${PG_STATS_DIR}/_meta.txt"

# ---------------------------------------------------------------------------
# Probe 1: kubectl top pod (CPU/memory at capture time).
# ---------------------------------------------------------------------------
{
  echo "# kubectl top pod -n ${NAMESPACE}"
  kubectl top pod -n "$NAMESPACE" 2>&1 || echo "(metrics-server may be unavailable)"
} > "${PG_STATS_DIR}/kubectl-top-pods.txt"

# ---------------------------------------------------------------------------
# Probe 2: pod descriptions (resource limits actually applied).
# ---------------------------------------------------------------------------
{
  echo "# kubectl get pods -n ${NAMESPACE} -o wide"
  kubectl get pods -n "$NAMESPACE" -o wide 2>&1 || true
} > "${PG_STATS_DIR}/kubectl-get-pods.txt"

# ---------------------------------------------------------------------------
# Probe 3: locate postgres pod.
# ---------------------------------------------------------------------------
PG_POD=$(kubectl get pods -n "$NAMESPACE" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null \
  | tr ' ' '\n' | grep -E "$POSTGRES_POD_RE" | head -1 || true)

if [ -z "$PG_POD" ]; then
  echo "no postgres pod matched /${POSTGRES_POD_RE}/ in ${NAMESPACE}; skipping psql probes" \
    > "${PG_STATS_DIR}/POSTGRES-NOT-FOUND.txt"
  exit 0
fi

echo "postgres_pod: ${PG_POD}" >> "${PG_STATS_DIR}/_meta.txt"

# psql connects via the bundled client inside the pod. We use the env vars
# that the helm chart sets on the postgres container (POSTGRES_USER,
# POSTGRES_DB) plus the password from the chart's secret. The fallback
# values mirror values-test.yaml and values-test-full.yaml.
PSQL="kubectl exec -n ${NAMESPACE} ${PG_POD} -- psql -U registry -d artifact_registry -P pager=off -A -X"

# ---------------------------------------------------------------------------
# Probe 4: pg_stat_activity (active queries, waiters, lock state).
# ---------------------------------------------------------------------------
{
  echo "-- pg_stat_activity (non-idle)"
  $PSQL -c "SELECT pid, state, wait_event_type, wait_event, query_start, \
            substr(query, 1, 200) AS query FROM pg_stat_activity \
            WHERE state IS DISTINCT FROM 'idle' ORDER BY query_start;" 2>&1 || true
} > "${PG_STATS_DIR}/pg_stat_activity.txt"

# ---------------------------------------------------------------------------
# Probe 5: pg_stat_statements (top 20 by total exec time, if extension is on).
# ---------------------------------------------------------------------------
{
  echo "-- pg_stat_statements (top 20 by total_exec_time, if extension loaded)"
  $PSQL -c "SELECT calls, total_exec_time, mean_exec_time, max_exec_time, \
            substr(query, 1, 200) AS query FROM pg_stat_statements \
            ORDER BY total_exec_time DESC LIMIT 20;" 2>&1 \
    || echo "(pg_stat_statements extension is not enabled in this build)"
} > "${PG_STATS_DIR}/pg_stat_statements.txt"

# ---------------------------------------------------------------------------
# Probe 6: connection count vs max_connections (the saturation signal).
# ---------------------------------------------------------------------------
{
  echo "-- connection count vs max_connections"
  $PSQL -c "SELECT (SELECT setting FROM pg_settings WHERE name='max_connections') AS max_conn, \
            (SELECT count(*) FROM pg_stat_activity) AS current_conn, \
            (SELECT count(*) FROM pg_stat_activity WHERE state='active') AS active, \
            (SELECT count(*) FROM pg_stat_activity WHERE wait_event_type='Lock') AS waiting_on_lock;" 2>&1 || true
} > "${PG_STATS_DIR}/pg_connection_count.txt"

# ---------------------------------------------------------------------------
# Probe 7: backend pod logs grep for acquire_timeout / pool exhaustion.
# ---------------------------------------------------------------------------
BACKEND_POD=$(kubectl get pods -n "$NAMESPACE" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null \
  | tr ' ' '\n' | grep -E "$BACKEND_POD_RE" | head -1 || true)
if [ -n "$BACKEND_POD" ]; then
  {
    echo "# backend log lines matching 'acquire_timeout|pool|sqlx|connection refused' (last 500)"
    kubectl logs -n "$NAMESPACE" "$BACKEND_POD" --tail=500 2>&1 \
      | grep -Ei 'acquire_timeout|pool|sqlx|connection refused' \
      | head -200 \
      || echo "(no matching log lines in the tail; absence is itself a data point)"
  } > "${PG_STATS_DIR}/backend-pool-lines.txt"
fi

echo "pg-stats capture complete: ${PG_STATS_DIR}"
ls -la "$PG_STATS_DIR" || true
