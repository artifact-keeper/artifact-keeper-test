#!/usr/bin/env bash
# test-postgres-restart.sh - Verify backend reconnects after PostgreSQL restart
#
# Uploads artifacts, kills the PostgreSQL pod, waits for it to come back,
# then verifies the backend automatically reconnects and can serve data.
#
# Requires: kubectl, NAMESPACE

source "$(dirname "$0")/../../lib/common.sh"

begin_suite "restart-postgres"
require_cmd kubectl
auth_admin
setup_workdir

NAMESPACE="${NAMESPACE:-ak-test-${RUN_ID}}"
REPO_KEY="restart-pg-${RUN_ID}"

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
for i in $(seq 1 3); do
  dd if=/dev/urandom bs=1024 count=2 of="${WORK_DIR}/pg-${i}.bin" 2>/dev/null
  if ! api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/files/v1/pg-${i}.bin" \
      "${WORK_DIR}/pg-${i}.bin" "application/octet-stream" > /dev/null; then
    fail "upload of pg-${i} failed"
    break
  fi
done
if [ "$_FAIL_COUNT" -eq 0 ]; then
  pass
fi

# ---------------------------------------------------------------------------
# Kill the PostgreSQL pod
# ---------------------------------------------------------------------------

begin_test "Delete PostgreSQL pod"
PG_POD=$(kubectl get pods -l app=postgres \
  -n "${NAMESPACE}" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
if [ -z "$PG_POD" ]; then
  # Try alternate label selectors commonly used for PostgreSQL
  PG_POD=$(kubectl get pods -l app.kubernetes.io/name=postgresql \
    -n "${NAMESPACE}" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
fi
if [ -z "$PG_POD" ]; then
  skip "could not find PostgreSQL pod (tried labels app=postgres and app.kubernetes.io/name=postgresql)"
else
  echo "  Deleting PostgreSQL pod: ${PG_POD}"
  if kubectl delete pod "$PG_POD" -n "${NAMESPACE}" 2>&1; then
    pass
  else
    fail "kubectl delete pod ${PG_POD} failed"
  fi
fi

# ---------------------------------------------------------------------------
# Wait for PostgreSQL to come back
# ---------------------------------------------------------------------------

begin_test "Wait for PostgreSQL pod ready"
elapsed=0
pg_ready=false
while [ "$elapsed" -lt 60 ]; do
  # Check both common label patterns
  ready=$(kubectl get pods -l app=postgres \
    -n "${NAMESPACE}" -o jsonpath='{.items[*].status.containerStatuses[0].ready}' 2>/dev/null || true)
  if [ "$ready" != "true" ]; then
    ready=$(kubectl get pods -l app.kubernetes.io/name=postgresql \
      -n "${NAMESPACE}" -o jsonpath='{.items[*].status.containerStatuses[0].ready}' 2>/dev/null || true)
  fi
  if [ "$ready" = "true" ]; then
    pg_ready=true
    break
  fi
  sleep 3
  elapsed=$(( elapsed + 3 ))
done
if [ "$pg_ready" = true ]; then
  echo "  PostgreSQL ready after ${elapsed}s"
  pass
else
  fail "PostgreSQL did not become ready within 60s"
fi

# ---------------------------------------------------------------------------
# Wait for backend to recover its database connection
# ---------------------------------------------------------------------------

begin_test "Wait for backend health after PostgreSQL restart"
elapsed=0
health_ok=false
while [ "$elapsed" -lt 45 ]; do
  if curl -sf -o /dev/null "${BASE_URL}/health" 2>/dev/null; then
    health_ok=true
    break
  fi
  sleep 3
  elapsed=$(( elapsed + 3 ))
done
if [ "$health_ok" = true ]; then
  echo "  Backend healthy after ${elapsed}s"
  pass
else
  fail "backend did not become healthy within 45s after PostgreSQL restart"
fi

# ---------------------------------------------------------------------------
# Verify data is still accessible
# ---------------------------------------------------------------------------

begin_test "Re-authenticate after PostgreSQL restart"
if auth_admin 2>/dev/null; then
  pass
else
  fail "re-authentication failed"
fi

begin_test "Verify artifacts accessible after PostgreSQL restart"
if resp=$(api_get "/api/v1/repositories/${REPO_KEY}/artifacts"); then
  if assert_contains "$resp" "pg-1.bin" "should contain pg-1.bin"; then
    if assert_contains "$resp" "pg-2.bin" "should contain pg-2.bin"; then
      pass
    fi
  fi
else
  fail "could not list artifacts after PostgreSQL restart"
fi

begin_test "Upload new artifact after PostgreSQL restart"
dd if=/dev/urandom bs=1024 count=2 of="${WORK_DIR}/post-pg.bin" 2>/dev/null
if api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/files/v1/post-pg.bin" \
    "${WORK_DIR}/post-pg.bin" "application/octet-stream" > /dev/null; then
  pass
else
  fail "write after PostgreSQL restart failed"
fi

end_suite
