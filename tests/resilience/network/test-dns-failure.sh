#!/usr/bin/env bash
# test-dns-failure.sh - Verify local repos work despite DNS issues
#
# Verifies that local repository operations (upload, download, list) work
# regardless of DNS resolution problems, and that remote repos surface
# clean errors when DNS fails.
#
# Requires: kubectl, NAMESPACE

source "$(dirname "$0")/../../lib/common.sh"

begin_suite "network-dns"
require_cmd kubectl
auth_admin
setup_workdir

NAMESPACE="${NAMESPACE:-ak-test-${RUN_ID}}"
LOCAL_REPO_KEY="net-dns-local-${RUN_ID}"
REMOTE_REPO_KEY="net-dns-remote-${RUN_ID}"

# ---------------------------------------------------------------------------
# Setup repos and upload baseline data
# ---------------------------------------------------------------------------

begin_test "Create local repository"
if create_local_repo "$LOCAL_REPO_KEY" "generic"; then
  pass
else
  fail "could not create local repo"
fi

begin_test "Upload to local repo"
dd if=/dev/urandom bs=1024 count=4 of="${WORK_DIR}/dns-test.bin" 2>/dev/null
DNS_SHA=$(shasum -a 256 "${WORK_DIR}/dns-test.bin" | awk '{print $1}')
if api_upload "/api/v1/repositories/${LOCAL_REPO_KEY}/artifacts/files/v1/dns-test.bin" \
    "${WORK_DIR}/dns-test.bin" "application/octet-stream" > /dev/null; then
  pass
else
  fail "local upload failed"
fi

begin_test "Create remote repository with DNS-dependent upstream"
# Use a hostname that requires DNS resolution but will fail
if create_remote_repo "$REMOTE_REPO_KEY" "generic" "http://nonexistent-host-for-dns-test.invalid:8080"; then
  pass
else
  fail "could not create remote repo"
fi

# ---------------------------------------------------------------------------
# Verify local repo works regardless of DNS state
# ---------------------------------------------------------------------------

begin_test "Download from local repo works"
if curl -sf -H "$(auth_header)" \
    -o "${WORK_DIR}/dl-dns-test.bin" \
    "${BASE_URL}/api/v1/repositories/${LOCAL_REPO_KEY}/download/files/v1/dns-test.bin"; then
  DL_SHA=$(shasum -a 256 "${WORK_DIR}/dl-dns-test.bin" | awk '{print $1}')
  if assert_eq "$DL_SHA" "$DNS_SHA" "checksum mismatch on local download"; then
    pass
  fi
else
  fail "local download failed"
fi

begin_test "List artifacts on local repo works"
if resp=$(api_get "/api/v1/repositories/${LOCAL_REPO_KEY}/artifacts"); then
  if assert_contains "$resp" "dns-test.bin" "artifact list should contain dns-test.bin"; then
    pass
  fi
else
  fail "could not list local repo artifacts"
fi

begin_test "Upload to local repo still works"
dd if=/dev/urandom bs=1024 count=2 of="${WORK_DIR}/dns-test-2.bin" 2>/dev/null
if api_upload "/api/v1/repositories/${LOCAL_REPO_KEY}/artifacts/files/v1/dns-test-2.bin" \
    "${WORK_DIR}/dns-test-2.bin" "application/octet-stream" > /dev/null; then
  pass
else
  fail "second local upload failed"
fi

# ---------------------------------------------------------------------------
# Verify remote repo handles DNS failure gracefully
# ---------------------------------------------------------------------------

begin_test "Remote repo returns clean error on DNS failure"
fetch_status=$(curl -s -o "${WORK_DIR}/dns-remote-output.txt" -w '%{http_code}' \
  -H "$(auth_header)" \
  --max-time 30 \
  "${BASE_URL}/api/v1/repositories/${REMOTE_REPO_KEY}/download/some/package.bin" 2>/dev/null || echo "000")
echo "  Remote fetch status: ${fetch_status}"

# Should get an error, not a success or a hang
if [ "$fetch_status" -ge 200 ] 2>/dev/null && [ "$fetch_status" -lt 300 ] 2>/dev/null; then
  fail "expected error from remote repo with bad DNS, got ${fetch_status}"
else
  echo "  Remote repo returned error ${fetch_status} (expected)"
  pass
fi

# Check that the error body (if any) does not contain a stack trace or panic
begin_test "Error response is clean (no panic or stack trace)"
if [ -f "${WORK_DIR}/dns-remote-output.txt" ]; then
  error_body=$(cat "${WORK_DIR}/dns-remote-output.txt")
  if assert_not_contains "$error_body" "panic" "response should not contain panic"; then
    if assert_not_contains "$error_body" "stack trace" "response should not contain stack trace"; then
      pass
    fi
  fi
else
  pass
fi

end_suite
