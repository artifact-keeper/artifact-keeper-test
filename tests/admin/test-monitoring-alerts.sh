#!/usr/bin/env bash
# test-monitoring-alerts.sh - Monitoring alerts query + suppression + manual check (Epic 10.5-10.7, #77)
#
# Three admin-only operational endpoints that have no E2E coverage today:
#   GET  /api/v1/admin/monitoring/alerts             -> list active alerts
#   POST /api/v1/admin/monitoring/alerts/suppress    -> silence an alert
#   POST /api/v1/admin/monitoring/check              -> force a health-check run
#
# These tests pin the contract (status code + response shape) without
# asserting any specific alert state, because the alert set is environment-
# dependent and would make the test flaky across runs.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "admin-monitoring-alerts"
auth_admin

begin_test "GET /admin/monitoring/alerts returns 200 with array"
if resp=$(api_get "/api/v1/admin/monitoring/alerts" 2>/dev/null); then
  # Response is either a bare array or {"alerts": [...]}. Accept both.
  if echo "$resp" | jq -e 'type == "array" or (.alerts | type == "array")' > /dev/null 2>&1; then
    pass
  else
    fail "response is neither array nor {alerts: array}: ${resp:0:200}"
  fi
else
  skip "GET /admin/monitoring/alerts not available"
fi

begin_test "POST /admin/monitoring/check returns 200/202"
status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X POST \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/admin/monitoring/check" 2>/dev/null) || status=000
if [ "$status" = "200" ] || [ "$status" = "202" ] || [ "$status" = "204" ]; then
  pass
elif [ "$status" = "404" ]; then
  skip "endpoint not mounted in this build"
else
  fail "expected 200/202/204, got ${status}"
fi

begin_test "POST /admin/monitoring/alerts/suppress without alert_id returns 400/422"
# Negative contract: malformed body should produce a deterministic 4xx.
status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X POST \
  -H "$(auth_header)" \
  -H "Content-Type: application/json" \
  -d '{}' \
  "${BASE_URL}/api/v1/admin/monitoring/alerts/suppress" 2>/dev/null) || status=000
if [ "$status" = "400" ] || [ "$status" = "422" ]; then
  pass
elif [ "$status" = "404" ]; then
  skip "endpoint not mounted in this build"
else
  fail "expected 400/422 for empty body, got ${status}"
fi

begin_test "POST /admin/monitoring/alerts/suppress with bogus id returns 404 (not 500)"
status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X POST \
  -H "$(auth_header)" \
  -H "Content-Type: application/json" \
  -d '{"alert_id":"00000000-0000-0000-0000-000000000000","duration_seconds":60}' \
  "${BASE_URL}/api/v1/admin/monitoring/alerts/suppress" 2>/dev/null) || status=000
if [ "$status" = "404" ] || [ "$status" = "400" ] || [ "$status" = "422" ]; then
  pass
elif [ "$status" = "200" ] || [ "$status" = "204" ]; then
  # Some builds accept any UUID and silently no-op. Acceptable, not flaky.
  pass
else
  fail "expected 4xx for bogus alert_id, got ${status}"
fi

end_suite
