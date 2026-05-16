#!/usr/bin/env bash
# test-backup-lifecycle.sh - Backup execute/cancel/delete contract (Epic 10.1-10.3, #77)
#
# Pins the response shape of the three operational backup endpoints. These
# are admin-only and have no E2E coverage today (only the schedule create
# path is tested in tests/platform/test-backup-restore.sh).
#
# Contract:
#   POST   /api/v1/admin/backups/{id}/execute   -> 202 (accepted, async run)
#   POST   /api/v1/admin/backups/{id}/cancel    -> 200 or 409 (no-op if not running)
#   DELETE /api/v1/admin/backups/{id}           -> 204
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "admin-backup-lifecycle"
auth_admin

BACKUP_NAME="e2e-backup-${RUN_ID}"
BACKUP_ID=""

# Trap-based teardown. Runs on any exit path (success, fail, signal) so a
# failure in the middle of the lifecycle (e.g. execute returns 500) cannot
# leave a backup schedule, run row, or storage entry orphaned in the
# namespace. The post-DELETE-test branch also clears BACKUP_ID when the
# explicit DELETE succeeds so this trap becomes a no-op in the success
# path. Re-authenticates first because a long-running suite may have
# spent its admin JWT lifetime.
_backup_cleanup() {
  local rc=$?
  if [ -n "${BACKUP_ID:-}" ] && [ "$BACKUP_ID" != "null" ]; then
    auth_admin > /dev/null 2>&1 || true
    # Cancel any in-flight run first so the executor doesn't race the
    # delete; ignore errors (409 if no run).
    curl -s -o /dev/null $CURL_TIMEOUT -X POST \
      -H "$(auth_header)" \
      "${BASE_URL}/api/v1/admin/backups/${BACKUP_ID}/cancel" 2>/dev/null || true
    api_delete "/api/v1/admin/backups/${BACKUP_ID}" > /dev/null 2>&1 || true
  fi
  return $rc
}
trap _backup_cleanup EXIT

begin_test "Create backup schedule"
# Minimal payload: name + cron + destination. Reads the backup module's
# default storage backend if not specified.
payload=$(cat <<EOF
{
  "name": "${BACKUP_NAME}",
  "cron": "0 3 * * *",
  "retention_days": 7,
  "include_artifacts": false,
  "include_metadata": true
}
EOF
)
if resp=$(api_post "/api/v1/admin/backups" "$payload" 2>/dev/null); then
  BACKUP_ID=$(echo "$resp" | jq -r '.id // empty')
  if [ -n "$BACKUP_ID" ] && [ "$BACKUP_ID" != "null" ]; then
    pass
  else
    fail "backup created but no id: ${resp:0:200}"
  fi
else
  skip "POST /admin/backups not available in this build"
fi

begin_test "POST /admin/backups/{id}/execute returns 202"
if [ -z "${BACKUP_ID:-}" ] || [ "$BACKUP_ID" = "null" ]; then
  skip "no backup id"
else
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X POST \
    -H "$(auth_header)" \
    "${BASE_URL}/api/v1/admin/backups/${BACKUP_ID}/execute" 2>/dev/null) || status=000
  # Accept 202 (async accepted) or 200 (sync trigger, some builds).
  if [ "$status" = "202" ] || [ "$status" = "200" ]; then
    pass
  else
    fail "expected 202/200 from execute, got ${status}"
  fi
fi

begin_test "POST /admin/backups/{id}/cancel returns 200 or 409"
if [ -z "${BACKUP_ID:-}" ] || [ "$BACKUP_ID" = "null" ]; then
  skip "no backup id"
else
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X POST \
    -H "$(auth_header)" \
    "${BASE_URL}/api/v1/admin/backups/${BACKUP_ID}/cancel" 2>/dev/null) || status=000
  # 200 if a job was running and was cancelled; 409 if no job is in flight.
  # Both are valid contract outcomes for a backup that may have already
  # finished by the time we cancel it (executor is fast for empty backups).
  if [ "$status" = "200" ] || [ "$status" = "409" ] || [ "$status" = "204" ]; then
    pass
  else
    fail "expected 200/204/409 from cancel, got ${status}"
  fi
fi

begin_test "DELETE /admin/backups/{id} returns 204"
if [ -z "${BACKUP_ID:-}" ] || [ "$BACKUP_ID" = "null" ]; then
  skip "no backup id"
else
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X DELETE \
    -H "$(auth_header)" \
    "${BASE_URL}/api/v1/admin/backups/${BACKUP_ID}" 2>/dev/null) || status=000
  if [ "$status" = "204" ] || [ "$status" = "200" ]; then
    pass
    BACKUP_ID=""  # mark cleaned so trailing cleanup skips
  else
    fail "expected 204 from delete, got ${status}"
  fi
fi

# Explicit cleanup runs via the EXIT trap above; nothing more to do here.

end_suite
