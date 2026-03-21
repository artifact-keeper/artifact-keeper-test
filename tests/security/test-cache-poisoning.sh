#!/usr/bin/env bash
# test-cache-poisoning.sh - T2-11: Proxy/remote repo cache poisoning prevention
#
# Verifies that content fetched through a remote (proxy) repo is integrity-checked.
# Without a controllable mock upstream, the test validates the remote repo's behavior
# with an unreachable upstream and checks that cached content is not served from
# unexpected sources.

source "$(dirname "$0")/../lib/common.sh"

begin_suite "cache-poisoning"
auth_admin
setup_workdir

REMOTE_KEY="sec-cache-poison-${RUN_ID}"
LOCAL_KEY="sec-cache-ref-${RUN_ID}"

# ---------------------------------------------------------------------------
# Create a remote repo pointing to a nonexistent upstream
# ---------------------------------------------------------------------------

begin_test "Create remote repo with unreachable upstream"
if create_remote_repo "$REMOTE_KEY" "generic" "https://nonexistent-upstream.invalid/repo"; then
  pass
else
  fail "could not create remote repo"
fi

# ---------------------------------------------------------------------------
# Attempt to fetch through the remote repo (should fail gracefully)
# ---------------------------------------------------------------------------

begin_test "Fetch from remote repo with unreachable upstream returns error"
status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${REMOTE_KEY}/artifacts/nonexistent/pkg.tar.gz") || true

if [ "$status" = "404" ] || [ "$status" = "502" ] || [ "$status" = "503" ] || [ "$status" = "504" ]; then
  pass
elif [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then
  fail "remote repo returned 2xx for artifact from unreachable upstream (possible stale cache)"
else
  # Any other client/server error is acceptable
  pass
fi

# ---------------------------------------------------------------------------
# Create a local repo and upload a reference artifact for comparison
# ---------------------------------------------------------------------------

begin_test "Create local reference repo"
if create_local_repo "$LOCAL_KEY" "generic"; then
  pass
else
  fail "could not create local reference repo"
fi

begin_test "Upload reference artifact to local repo"
echo "reference-content-${RUN_ID}" > "${WORK_DIR}/reference.bin"
REF_SHA256=$(shasum -a 256 "${WORK_DIR}/reference.bin" | awk '{print $1}')
if api_upload "/api/v1/repositories/${LOCAL_KEY}/artifacts/ref-pkg/v1/reference.bin" \
    "${WORK_DIR}/reference.bin"; then
  pass
else
  fail "could not upload reference artifact"
fi

# ---------------------------------------------------------------------------
# Verify that remote repo does not serve local repo content (cross-repo leak)
# ---------------------------------------------------------------------------

begin_test "Remote repo does not serve content from unrelated local repo"
status=$(curl -s -o "${WORK_DIR}/cross-check.bin" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${REMOTE_KEY}/artifacts/ref-pkg/v1/reference.bin") || true

if [ "$status" = "404" ] || [ "$status" = "502" ] || [ "$status" = "503" ]; then
  pass
elif [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then
  # Check if it somehow returned the local repo's content
  if [ -f "${WORK_DIR}/cross-check.bin" ]; then
    cross_sha=$(shasum -a 256 "${WORK_DIR}/cross-check.bin" | awk '{print $1}')
    if [ "$cross_sha" = "$REF_SHA256" ]; then
      fail "remote repo served content from unrelated local repo (cross-repo cache poisoning)"
    else
      fail "remote repo served unknown content for artifact from unreachable upstream"
    fi
  else
    fail "remote repo returned 2xx but no content"
  fi
else
  pass
fi

# ---------------------------------------------------------------------------
# Note: full cache poisoning test requires a controllable mock upstream
# ---------------------------------------------------------------------------

begin_test "Full upstream content tampering verification"
skip "requires a controllable mock HTTP upstream to inject tampered content; deploy a mock server in the test namespace to enable this test"

end_suite
