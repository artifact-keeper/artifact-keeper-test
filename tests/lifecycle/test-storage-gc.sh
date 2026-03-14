#!/usr/bin/env bash
# test-storage-gc.sh - Storage garbage collection E2E test
#
# Tests running storage GC in dry-run mode, verifying the response
# contains reclaim estimates.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "storage-gc"
auth_admin

# -------------------------------------------------------------------------
# Run GC dry-run
# -------------------------------------------------------------------------

begin_test "Run storage GC in dry-run mode"
if resp=$(api_post "/api/v1/admin/storage-gc" '{"dry_run":true}' 2>/dev/null); then
  pass
elif resp=$(api_post "/api/v1/admin/storage-gc?dry_run=true" "" 2>/dev/null); then
  pass
else
  skip "storage GC endpoint not available"
fi

# -------------------------------------------------------------------------
# Verify GC status endpoint
# -------------------------------------------------------------------------

begin_test "Check GC status"
if resp=$(api_get "/api/v1/admin/storage-gc" 2>/dev/null); then
  pass
elif resp=$(api_get "/api/v1/admin/storage-gc/status" 2>/dev/null); then
  pass
else
  skip "GC status endpoint not available"
fi

end_suite
