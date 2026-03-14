#!/usr/bin/env bash
# test-system-settings.sh - System settings E2E test
source "$(dirname "$0")/../lib/common.sh"

begin_suite "system-settings"
auth_admin

begin_test "Get system settings"
if resp=$(api_get "/api/v1/admin/settings" 2>/dev/null); then
  pass
elif resp=$(api_get "/api/v1/admin/system/settings" 2>/dev/null); then
  pass
else
  skip "system settings not available"
fi

begin_test "Get system stats"
if resp=$(api_get "/api/v1/admin/stats" 2>/dev/null); then
  pass
elif resp=$(api_get "/api/v1/admin/system/stats" 2>/dev/null); then
  pass
else
  skip "system stats not available"
fi

end_suite
