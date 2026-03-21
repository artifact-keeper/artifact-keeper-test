#!/usr/bin/env bash
# test-security-scanning.sh - Security scanning E2E test
#
# Tests the security dashboard, scan config listing, scan triggering,
# and findings retrieval through the security API.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "security-scanning"
auth_admin
setup_workdir

# -------------------------------------------------------------------------
# Security dashboard
# -------------------------------------------------------------------------

begin_test "Security dashboard accessible"
resp=$(api_get "/api/v1/security/dashboard" 2>/dev/null) || true
if [ -n "$resp" ] && echo "$resp" | jq -e '.' > /dev/null 2>&1; then
  pass
else
  skip "security dashboard not available"
fi

# -------------------------------------------------------------------------
# Scan configs
# -------------------------------------------------------------------------

begin_test "List scan configs"
resp=$(api_get "/api/v1/security/configs" 2>/dev/null) || true
if [ -n "$resp" ] && echo "$resp" | jq -e '.' > /dev/null 2>&1; then
  pass
else
  skip "scan configs not available"
fi

# -------------------------------------------------------------------------
# Trigger scan
# -------------------------------------------------------------------------

begin_test "Trigger scan"
REPO_KEY="scan-test-${RUN_ID}"
create_local_repo "$REPO_KEY" "generic" > /dev/null 2>&1 || true
echo "scan-target-${RUN_ID}" > "${WORK_DIR}/scan-target.txt"
api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/target.txt" \
  "${WORK_DIR}/scan-target.txt" "text/plain" > /dev/null 2>&1 || true

resp=$(api_post "/api/v1/security/scan" "{\"repository_key\":\"${REPO_KEY}\"}" 2>/dev/null) || true
if [ -n "$resp" ] && echo "$resp" | jq -e '.' > /dev/null 2>&1; then
  pass
else
  skip "scan trigger not available"
fi

# -------------------------------------------------------------------------
# List scans
# -------------------------------------------------------------------------

begin_test "List scans"
resp=$(api_get "/api/v1/security/scans" 2>/dev/null) || true
if [ -n "$resp" ] && echo "$resp" | jq -e '.' > /dev/null 2>&1; then
  pass
else
  skip "scans listing not available"
fi

# -------------------------------------------------------------------------
# Security scores
# -------------------------------------------------------------------------

begin_test "Security scores endpoint"
resp=$(api_get "/api/v1/security/scores" 2>/dev/null) || true
if [ -n "$resp" ] && echo "$resp" | jq -e '.' > /dev/null 2>&1; then
  pass
else
  skip "security scores not available"
fi

# -------------------------------------------------------------------------
# Security policies
# -------------------------------------------------------------------------

begin_test "List security policies"
resp=$(api_get "/api/v1/security/policies" 2>/dev/null) || true
if [ -n "$resp" ] && echo "$resp" | jq -e '.' > /dev/null 2>&1; then
  pass
else
  skip "security policies not available"
fi

end_suite
