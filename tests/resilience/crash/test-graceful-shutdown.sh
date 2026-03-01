#!/usr/bin/env bash
# test-graceful-shutdown.sh - Verify graceful shutdown handles in-flight requests
#
# Starts a background upload of a large file, initiates a graceful pod
# termination (no --force), and checks that the upload either completed
# successfully or returned a retryable error. Existing artifacts must
# remain intact after the new pod starts.
#
# Requires: kubectl, NAMESPACE

source "$(dirname "$0")/../../lib/common.sh"

begin_suite "crash-graceful-shutdown"
require_cmd kubectl
auth_admin
setup_workdir

NAMESPACE="${NAMESPACE:-ak-test-${RUN_ID}}"
REPO_KEY="crash-graceful-${RUN_ID}"

# ---------------------------------------------------------------------------
# Create repository and upload a known artifact
# ---------------------------------------------------------------------------

begin_test "Create generic repository"
if create_local_repo "$REPO_KEY" "generic"; then
  pass
else
  fail "could not create generic repo"
fi

begin_test "Upload baseline artifact"
dd if=/dev/urandom bs=1024 count=4 of="${WORK_DIR}/baseline.bin" 2>/dev/null
BASELINE_SHA=$(shasum -a 256 "${WORK_DIR}/baseline.bin" | awk '{print $1}')
if api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/files/v1/baseline.bin" \
    "${WORK_DIR}/baseline.bin" "application/octet-stream" > /dev/null; then
  pass
else
  fail "baseline upload failed"
fi

# ---------------------------------------------------------------------------
# Start a background upload, then gracefully terminate the pod
# ---------------------------------------------------------------------------

begin_test "Start background upload and trigger graceful shutdown"
# Generate a larger file to increase the chance it is in-flight during shutdown
dd if=/dev/urandom bs=1048576 count=20 of="${WORK_DIR}/large.bin" 2>/dev/null

# Launch upload in the background and capture its PID
BG_STATUS_FILE="${WORK_DIR}/bg-upload-status"
(
  http_code=$(curl -s -o /dev/null -w '%{http_code}' -X PUT \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/octet-stream" \
    --data-binary "@${WORK_DIR}/large.bin" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/files/v1/large.bin" 2>/dev/null || echo "000")
  echo "$http_code" > "$BG_STATUS_FILE"
) &
BG_PID=$!

# Brief delay so the upload has started transmitting
sleep 2

# Graceful delete (no --force, respects terminationGracePeriodSeconds)
kubectl delete pod -l app=artifact-keeper-backend -n "${NAMESPACE}" 2>&1 || true

# Wait for background upload to finish
wait "$BG_PID" 2>/dev/null || true
pass

# ---------------------------------------------------------------------------
# Check background upload result
# ---------------------------------------------------------------------------

begin_test "Verify background upload result"
if [ -f "$BG_STATUS_FILE" ]; then
  BG_CODE=$(cat "$BG_STATUS_FILE")
  echo "  Background upload HTTP status: ${BG_CODE}"
  # Accept: 2xx (completed), 502/503 (retryable), or 000 (connection reset)
  case "$BG_CODE" in
    2[0-9][0-9])
      echo "  Upload completed before shutdown"
      pass
      ;;
    000|502|503|504)
      echo "  Upload interrupted with retryable error (expected during shutdown)"
      pass
      ;;
    *)
      fail "unexpected HTTP status ${BG_CODE} from in-flight upload"
      ;;
  esac
else
  echo "  No status file (background process may not have written it)"
  skip "could not determine background upload status"
fi

# ---------------------------------------------------------------------------
# Wait for new pod
# ---------------------------------------------------------------------------

begin_test "Wait for new backend pod"
elapsed=0
pod_ready=false
while [ "$elapsed" -lt 60 ]; do
  ready=$(kubectl get pods -l app=artifact-keeper-backend \
    -n "${NAMESPACE}" -o jsonpath='{.items[*].status.containerStatuses[0].ready}' 2>/dev/null || true)
  if [ "$ready" = "true" ]; then
    pod_ready=true
    break
  fi
  sleep 3
  elapsed=$(( elapsed + 3 ))
done
if [ "$pod_ready" = true ]; then
  echo "  Pod ready after ${elapsed}s"
  pass
else
  fail "new pod did not become ready within 60s"
fi

begin_test "Wait for health endpoint"
elapsed=0
health_ok=false
while [ "$elapsed" -lt 30 ]; do
  if curl -sf -o /dev/null "${BASE_URL}/health" 2>/dev/null; then
    health_ok=true
    break
  fi
  sleep 2
  elapsed=$(( elapsed + 2 ))
done
if [ "$health_ok" = true ]; then
  pass
else
  fail "health endpoint did not respond within 30s"
fi

# ---------------------------------------------------------------------------
# Verify existing artifacts survived
# ---------------------------------------------------------------------------

begin_test "Re-authenticate after graceful shutdown"
if auth_admin 2>/dev/null; then
  pass
else
  fail "re-authentication failed"
fi

begin_test "Verify baseline artifact intact"
if curl -sf -H "$(auth_header)" \
    -o "${WORK_DIR}/baseline-dl.bin" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}/download/files/v1/baseline.bin"; then
  DL_SHA=$(shasum -a 256 "${WORK_DIR}/baseline-dl.bin" | awk '{print $1}')
  if assert_eq "$DL_SHA" "$BASELINE_SHA" "baseline SHA256 mismatch after graceful shutdown"; then
    pass
  fi
else
  fail "could not download baseline artifact after graceful shutdown"
fi

end_suite
