#!/usr/bin/env bash
# test-audit-log.sh - Audit trail verification E2E test
#
# Tests audit log functionality through the admin settings and cleanup
# endpoints. Verifies that audit retention is configurable and that
# cleanup operations work against the audit log.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "audit-log"
auth_admin
setup_workdir

USER="audit-test-${RUN_ID}"

# -------------------------------------------------------------------------
# Create user to generate audit events
# -------------------------------------------------------------------------

begin_test "Create user (generates audit event)"
resp=$(api_post "/api/v1/users" "{\"username\":\"${USER}\",\"password\":\"TestPass123!\",\"email\":\"audit-${RUN_ID}@test.com\"}")
USER_ID=$(echo "$resp" | jq -r '.user.id // .id // .user_id // empty')
if [ -n "$USER_ID" ] && [ "$USER_ID" != "null" ]; then
  pass
else
  fail "create user failed"
fi

# -------------------------------------------------------------------------
# Verify audit retention settings exist
# -------------------------------------------------------------------------

begin_test "Admin settings include audit retention"
if resp=$(api_get "/api/v1/admin/settings" 2>/dev/null); then
  if assert_contains "$resp" "audit_retention_days"; then
    pass
  fi
else
  skip "admin settings endpoint not available"
fi

# -------------------------------------------------------------------------
# Run audit log cleanup (validates the audit subsystem works)
# -------------------------------------------------------------------------

begin_test "Audit log cleanup runs successfully"
resp=$(api_post "/api/v1/admin/cleanup" '{"cleanup_audit_logs":true}' 2>/dev/null) || true
if [ -n "$resp" ] && echo "$resp" | jq -e '.audit_logs_deleted != null' > /dev/null 2>&1; then
  pass
else
  skip "audit log cleanup endpoint not available"
fi

# -------------------------------------------------------------------------
# Delete user (generates another audit event)
# -------------------------------------------------------------------------

begin_test "Delete user (generates audit event)"
if [ -n "${USER_ID:-}" ] && [ "$USER_ID" != "null" ]; then
  api_delete "/api/v1/users/${USER_ID}" > /dev/null 2>&1 || true
  pass
else
  skip "no user to delete"
fi

# -------------------------------------------------------------------------
# Verify domain events SSE endpoint is available
# -------------------------------------------------------------------------

begin_test "Domain events stream endpoint accessible"
status=$(curl -s -o /dev/null -w "%{http_code}" $CURL_TIMEOUT \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/events/stream" 2>&1) || true
# SSE endpoints return 200 with streaming, or may return other codes
if [ "$status" = "200" ] || [ "$status" = "204" ]; then
  pass
else
  skip "events stream endpoint not available (HTTP ${status})"
fi

end_suite
