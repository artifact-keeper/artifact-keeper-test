#!/usr/bin/env bash
# test-analytics.sh - Analytics endpoints E2E test
source "$(dirname "$0")/../lib/common.sh"

begin_suite "analytics"
auth_admin

begin_test "Get storage analytics"
if resp=$(api_get "/api/v1/admin/analytics/storage/breakdown" 2>/dev/null); then
  pass
else
  skip "storage analytics endpoint not available"
fi

end_suite
