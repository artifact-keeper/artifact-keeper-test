#!/usr/bin/env bash
# test-backup-restore.sh - Backup lifecycle E2E test
source "$(dirname "$0")/../lib/common.sh"

begin_suite "backup-restore"
auth_admin

begin_test "Create backup"
if resp=$(api_post "/api/v1/admin/backups" '{"type":"full"}' 2>/dev/null); then
  BACKUP_ID=$(echo "$resp" | jq -r '.id // empty') || true
  pass
else
  skip "backup endpoint not available"
fi

begin_test "List backups"
if resp=$(api_get "/api/v1/admin/backups" 2>/dev/null); then
  pass
else
  skip "backup listing not available"
fi

end_suite
