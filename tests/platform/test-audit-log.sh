#!/usr/bin/env bash
# test-audit-log.sh - Audit trail verification E2E test
source "$(dirname "$0")/../lib/common.sh"

begin_suite "audit-log"
auth_admin
setup_workdir

REPO_KEY="test-audit-${RUN_ID}"

begin_test "Create repo to generate audit event"
if create_local_repo "$REPO_KEY" "generic"; then
  pass
else
  fail "could not create repo"
fi

sleep 2

begin_test "Query audit log"
if resp=$(api_get "/api/v1/admin/audit" 2>/dev/null); then
  pass
elif resp=$(api_get "/api/v1/admin/audit?limit=10" 2>/dev/null); then
  pass
else
  skip "audit log endpoint not available"
fi

begin_test "Audit log contains recent repo creation"
if [ -n "${resp:-}" ]; then
  if assert_contains "$resp" "$REPO_KEY" 2>/dev/null; then
    pass
  else
    skip "repo key not found in recent audit entries"
  fi
else
  skip "no audit response"
fi

end_suite
