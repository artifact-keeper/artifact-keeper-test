#!/usr/bin/env bash
# test-upstream-timeout.sh - Verify remote repos handle unreachable upstreams
#
# Creates a remote/proxy repository pointing at a non-existent upstream,
# attempts to fetch through it, and verifies the server returns a timeout
# or error response within a reasonable time (not an infinite hang).
#
# Requires: kubectl, NAMESPACE

source "$(dirname "$0")/../../lib/common.sh"

begin_suite "network-upstream-timeout"
require_cmd kubectl
auth_admin
setup_workdir

NAMESPACE="${NAMESPACE:-ak-test-${RUN_ID}}"
REPO_KEY="net-timeout-${RUN_ID}"
# Use a hostname that will not resolve or will time out
BOGUS_UPSTREAM="http://does-not-exist.local:9999"

# ---------------------------------------------------------------------------
# Create a remote repo pointing at a non-existent upstream
# ---------------------------------------------------------------------------

begin_test "Create remote repository with unreachable upstream"
if create_remote_repo "$REPO_KEY" "generic" "$BOGUS_UPSTREAM"; then
  pass
else
  fail "could not create remote repo with bogus upstream"
fi

# ---------------------------------------------------------------------------
# Attempt to fetch through the proxy
# ---------------------------------------------------------------------------

begin_test "Fetch through proxy returns error (not hang)"
FETCH_START=$(date +%s)
fetch_status=$(curl -s -o "${WORK_DIR}/fetch-output.txt" -w '%{http_code}' \
  -H "$(auth_header)" \
  --max-time "${TEST_TIMEOUT}" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/download/some/artifact.bin" 2>/dev/null || echo "000")
FETCH_DURATION=$(( $(date +%s) - FETCH_START ))

echo "  Fetch status: ${fetch_status}"
echo "  Fetch duration: ${FETCH_DURATION}s"

# The server should return an error (4xx or 5xx), not 2xx
if [ "$fetch_status" -ge 200 ] 2>/dev/null && [ "$fetch_status" -lt 300 ] 2>/dev/null; then
  fail "expected error status from unreachable upstream, got ${fetch_status}"
elif [ "$fetch_status" = "000" ] && [ "$FETCH_DURATION" -ge "$TEST_TIMEOUT" ]; then
  fail "request hung until timeout (${TEST_TIMEOUT}s) instead of returning an error"
else
  echo "  Server returned error ${fetch_status} in ${FETCH_DURATION}s (as expected)"
  pass
fi

# ---------------------------------------------------------------------------
# Verify the response completed within a reasonable time
# ---------------------------------------------------------------------------

begin_test "Verify timeout happens within TEST_TIMEOUT"
# The request should have resolved well before the full TEST_TIMEOUT
if [ "$FETCH_DURATION" -lt "$TEST_TIMEOUT" ]; then
  echo "  Response returned in ${FETCH_DURATION}s (under ${TEST_TIMEOUT}s limit)"
  pass
else
  fail "response took ${FETCH_DURATION}s, expected it within ${TEST_TIMEOUT}s"
fi

# ---------------------------------------------------------------------------
# Verify local repo operations are unaffected
# ---------------------------------------------------------------------------

begin_test "Local repo unaffected by remote repo timeout"
LOCAL_REPO_KEY="net-timeout-local-${RUN_ID}"
if create_local_repo "$LOCAL_REPO_KEY" "generic"; then
  dd if=/dev/urandom bs=1024 count=2 of="${WORK_DIR}/local-test.bin" 2>/dev/null
  if api_upload "/api/v1/repositories/${LOCAL_REPO_KEY}/artifacts/files/v1/local-test.bin" \
      "${WORK_DIR}/local-test.bin" "application/octet-stream" > /dev/null; then
    pass
  else
    fail "local repo upload failed"
  fi
else
  fail "could not create local repo"
fi

end_suite
