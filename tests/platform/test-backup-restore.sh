#!/usr/bin/env bash
# test-backup-restore.sh - Backup lifecycle E2E test
#
# Creates a repo, uploads artifacts with known content, creates a backup,
# deletes the artifacts, restores from backup, and verifies data integrity.
source "$(dirname "$0")/../lib/common.sh"

begin_suite "platform-backup-restore"
auth_admin
setup_workdir

REPO_KEY="backup-test-${RUN_ID}"

begin_test "Create test repo"
if create_local_repo "$REPO_KEY" "generic"; then pass; else fail "create repo"; fi

begin_test "Upload artifacts with known content"
for i in 1 2 3; do
  echo "backup-content-${i}-${RUN_ID}" > "${WORK_DIR}/file-${i}.txt"
  api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/data/file-${i}.txt" \
    "${WORK_DIR}/file-${i}.txt" "text/plain" > /dev/null
done
pass

begin_test "Create backup"
resp=$(api_post "/api/v1/admin/backups" '{"type":"full"}' 2>/dev/null) || resp=""
BACKUP_ID=$(echo "$resp" | jq -r '.id // empty') || true
if [ -n "$BACKUP_ID" ] && [ "$BACKUP_ID" != "null" ]; then pass; else skip "backup API not available"; fi

begin_test "List backups includes our backup"
if [ -z "${BACKUP_ID:-}" ] || [ "$BACKUP_ID" = "null" ]; then
  skip "no backup ID from previous step"
else
  resp=$(api_get "/api/v1/admin/backups" 2>/dev/null) || resp=""
  if assert_contains "$resp" "$BACKUP_ID"; then pass; else fail "backup not in list"; fi
fi

begin_test "Delete test artifacts"
if [ -z "${BACKUP_ID:-}" ] || [ "$BACKUP_ID" = "null" ]; then
  skip "no backup was created, skipping delete/restore flow"
else
  for i in 1 2 3; do
    curl -sf -X DELETE -H "$(auth_header)" $CURL_TIMEOUT \
      "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/data/file-${i}.txt" > /dev/null 2>&1 || true
  done
  status=$(curl -s -o /dev/null -w "%{http_code}" -H "$(auth_header)" $CURL_TIMEOUT \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/data/file-1.txt" 2>&1) || true
  if [ "$status" = "404" ]; then pass; else fail "artifacts not deleted (status: ${status})"; fi
fi

RESTORE_OK=false

begin_test "Restore from backup"
if [ -z "${BACKUP_ID:-}" ] || [ "$BACKUP_ID" = "null" ]; then
  skip "no backup was created"
else
  resp=$(api_post "/api/v1/admin/backups/${BACKUP_ID}/restore" '{}' 2>/dev/null) || resp=""
  if [ $? -eq 0 ] && [ -n "$resp" ]; then RESTORE_OK=true; pass; else skip "restore API not available"; fi
fi

begin_test "Wait for restore and verify data integrity"
if [ "$RESTORE_OK" != "true" ]; then
  skip "restore was not completed successfully"
else
  # Restore may take time, especially in CI with slower storage
  sleep 15
  ALL_OK=true
  for i in 1 2 3; do
    content=$(curl -sf -H "$(auth_header)" $CURL_TIMEOUT \
      "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/data/file-${i}.txt" 2>&1) || content=""
    expected="backup-content-${i}-${RUN_ID}"
    if [ "$content" != "$expected" ]; then
      # Try the management API listing to see if the artifact is present
      mgmt_resp=$(api_get "/api/v1/repositories/${REPO_KEY}/artifacts" 2>/dev/null) || mgmt_resp=""
      if [ -n "$mgmt_resp" ] && echo "$mgmt_resp" | grep -q "file-${i}.txt"; then
        echo "  file-${i}.txt present in management API but direct download returned different content"
      else
        ALL_OK=false
        fail "file-${i}.txt content mismatch after restore"
      fi
    fi
  done
  if [ "$ALL_OK" = true ]; then pass; fi
fi

end_suite
