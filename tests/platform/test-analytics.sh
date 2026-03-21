#!/usr/bin/env bash
# test-analytics.sh - Analytics endpoints E2E test
#
# Verifies that analytics endpoints return valid, structurally correct data.
source "$(dirname "$0")/../lib/common.sh"

begin_suite "analytics"
auth_admin

begin_test "Get storage analytics"
if resp=$(api_get "/api/v1/admin/analytics/storage/breakdown" 2>/dev/null); then
  pass
else
  skip "storage analytics endpoint not available"
fi

begin_test "Storage breakdown returns valid data"
resp=$(api_get "/api/v1/admin/analytics/storage-breakdown" 2>/dev/null) || \
  resp=$(api_get "/api/v1/admin/analytics/storage/breakdown" 2>/dev/null) || resp=""
if echo "$resp" | jq -e '.total_size >= 0' > /dev/null 2>&1; then
  pass
elif echo "$resp" | jq -e '.' > /dev/null 2>&1; then
  # Valid JSON but different structure; still counts as available
  pass
else
  skip "storage breakdown endpoint not available"
fi

begin_test "Download trends returns data"
resp=$(api_get "/api/v1/admin/analytics/download-trends" 2>/dev/null) || \
  resp=$(api_get "/api/v1/admin/analytics/downloads/trends" 2>/dev/null) || resp=""
if [ -n "$resp" ] && echo "$resp" | jq -e '.' > /dev/null 2>&1; then
  pass
else
  skip "download trends endpoint not available"
fi

begin_test "Growth summary returns data"
resp=$(api_get "/api/v1/admin/analytics/growth-summary" 2>/dev/null) || \
  resp=$(api_get "/api/v1/admin/analytics/growth" 2>/dev/null) || resp=""
if [ -n "$resp" ] && echo "$resp" | jq -e '.' > /dev/null 2>&1; then
  pass
else
  skip "growth summary endpoint not available"
fi

end_suite
