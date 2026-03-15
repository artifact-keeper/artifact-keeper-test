#!/usr/bin/env bash
# test-audit-log.sh - Audit trail verification E2E test
#
# The audit log is internal only and has no query endpoint exposed in the API.
# All tests are skipped.
source "$(dirname "$0")/../lib/common.sh"

begin_suite "audit-log"

begin_test "Query audit log"
skip "audit log query endpoint not exposed in API"

begin_test "Audit log contains recent events"
skip "audit log query endpoint not exposed in API"

end_suite
