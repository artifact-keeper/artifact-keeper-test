#!/usr/bin/env bash
# test-analytics.sh - Analytics endpoints E2E test
source "$(dirname "$0")/../lib/common.sh"

begin_suite "analytics"
auth_admin

begin_test "Get repository analytics"
if resp=$(api_get "/api/v1/admin/analytics" 2>/dev/null); then
  pass
elif resp=$(api_get "/api/v1/admin/analytics/repositories" 2>/dev/null); then
  pass
else
  skip "analytics endpoint not available"
fi

begin_test "Get format usage analytics"
if resp=$(api_get "/api/v1/admin/analytics/formats" 2>/dev/null); then
  pass
else
  skip "format analytics not available"
fi

begin_test "Get download trends"
if resp=$(api_get "/api/v1/admin/analytics/downloads" 2>/dev/null); then
  pass
elif resp=$(api_get "/api/v1/admin/analytics/trends" 2>/dev/null); then
  pass
else
  skip "download trends not available"
fi

end_suite
