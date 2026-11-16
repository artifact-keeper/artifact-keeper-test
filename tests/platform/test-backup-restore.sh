#!/usr/bin/env bash
# test-backup-restore.sh - Backup lifecycle E2E test on the SHARED gate instance
#
# Creates a repo, uploads artifacts with known content, takes a backup scoped
# to that repo, runs it, and checks the run completed and archived the
# artifacts. It also pins that a restore refuses a backup that never ran.
#
# What this suite deliberately does NOT do: restore. A restore ingests the
# whole archive, identity tables included, no matter how the backup was scoped
# (the backend refuses target_repository_id for exactly that reason, #3373).
# On the shared release-gate namespace that resurrects any row a sibling suite
# deleted since the backup ran, and the sibling then fails on state it did not
# create (artifact-keeper-test#365). The suite used to POST the restore with
# an empty body against a backup it had only created, never executed. The
# backend answers that with 400 "Can only restore from completed backups", so
# the step skipped as "restore API not available" and the integrity check
# below it never ran.
#
# The restore round trip, byte integrity included, is certified on dedicated
# instances where an instance-wide ingest disturbs nothing: the DTF tiers
# backup-restore-completeness, backup-scoped-restore and
# backup-restore-fresh-server, all in the blocking dtf-gate matrix.
source "$(dirname "$0")/../lib/common.sh"

begin_suite "platform-backup-restore"
auth_admin
setup_workdir
# Bounded waits only; single requests are covered by the default margin.
require_wait_budget 65 "backup execute poll (30 s of 409 retries, then one 30 s execute)"

REPO_KEY="backup-test-${RUN_ID}"
REPO_ID=""
BACKUP_ID=""
PENDING_ID=""

_backup_restore_cleanup() {
  auth_admin > /dev/null 2>&1 || true
  local id
  for id in "${BACKUP_ID:-}" "${PENDING_ID:-}"; do
    [ -n "$id" ] && [ "$id" != "null" ] || continue
    api_delete "/api/v1/admin/backups/${id}" > /dev/null 2>&1 || true
  done
  api_delete "/api/v1/repositories/${REPO_KEY}" > /dev/null 2>&1 || true
}
add_exit_handler _backup_restore_cleanup

begin_test "Create test repo"
if create_local_repo "$REPO_KEY" "generic"; then
  REPO_ID=$(api_get "/api/v1/repositories/${REPO_KEY}" 2>/dev/null | jq -r '.id // empty' 2>/dev/null) || REPO_ID=""
  if [ -n "$REPO_ID" ]; then pass; else fail "created ${REPO_KEY} but could not resolve its id"; fi
else
  fail "create repo"
fi

begin_test "Upload artifacts with known content"
UPLOAD_OK=true
for i in 1 2 3; do
  echo "backup-content-${i}-${RUN_ID}" > "${WORK_DIR}/file-${i}.txt"
  if ! api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/data/file-${i}.txt" \
      "${WORK_DIR}/file-${i}.txt" "text/plain" > /dev/null; then
    UPLOAD_OK=false
  fi
done
if [ "$UPLOAD_OK" = true ]; then pass; else fail "an artifact upload into ${REPO_KEY} failed"; fi

begin_test "Create a backup scoped to the test repo"
if [ -z "$REPO_ID" ]; then
  skip "no repository id to scope the backup to"
else
  resp=$(api_post "/api/v1/admin/backups" \
    "{\"type\":\"full\",\"repository_ids\":[\"${REPO_ID}\"]}" 2>/dev/null) || resp=""
  BACKUP_ID=$(echo "$resp" | jq -r '.id // empty' 2>/dev/null) || BACKUP_ID=""
  if [ -n "$BACKUP_ID" ] && [ "$BACKUP_ID" != "null" ]; then
    pass
  else
    # Under RELEASE_GATE=1 a missing backup id is a failure: every later step
    # would skip and the suite would certify nothing about backup.
    require_or_fail "POST /admin/backups returned no backup id" "${resp:0:300}"
  fi
fi

begin_test "List backups includes our backup"
if [ -z "${BACKUP_ID:-}" ] || [ "$BACKUP_ID" = "null" ]; then
  skip "no backup ID from previous step"
else
  resp=$(api_get "/api/v1/admin/backups?per_page=100" 2>/dev/null) || resp=""
  if assert_contains "$resp" "$BACKUP_ID"; then pass; else fail "backup not in list"; fi
fi

# POST /execute runs the backup to its terminal state before answering
# (200 + the persisted row; a failed run is status=failed with error_message,
# #3327). The handler documents 409 "another backup is already in progress";
# it is retried within a bound rather than failed, should it ever surface.
EXEC_BODY="${WORK_DIR}/execute.json"
_execute_backup() {
  local code rc=0
  code=$(curl -s -o "$EXEC_BODY" -w '%{http_code}' --connect-timeout 10 --max-time 30 -X POST \
    -H "$(auth_header)" \
    "${BASE_URL}/api/v1/admin/backups/${BACKUP_ID}/execute" 2>/dev/null) || rc=$?
  [ "$rc" -eq 0 ] || code=000
  echo "$code $rc" > "${EXEC_BODY}.code"
  [ "$code" != "409" ]
}

begin_test "Execute the backup: completed, with the test artifacts archived"
if [ -z "${BACKUP_ID:-}" ] || [ "$BACKUP_ID" = "null" ]; then
  skip "no backup was created"
elif ! wait_until "backup executor free (no 409)" 30 _execute_backup; then
  fail "POST /admin/backups/${BACKUP_ID}/execute answered 409 (another backup in progress) for 30s"
else
  read -r code curl_rc < "${EXEC_BODY}.code"
  body=$(cat "$EXEC_BODY" 2>/dev/null)
  status=$(echo "$body" | jq -r '.status // empty' 2>/dev/null)
  count=$(echo "$body" | jq -r '.artifact_count // 0' 2>/dev/null)
  if [ "$curl_rc" = "28" ]; then
    fail "POST /admin/backups/${BACKUP_ID}/execute did not finish within 30s"
  elif [ "$code" = "000" ]; then
    infra_fail "POST /admin/backups/${BACKUP_ID}/execute got no HTTP answer (curl exit ${curl_rc}: connection refused or reset)"
  elif [ "$code" != "200" ]; then
    fail "execute returned HTTP ${code}, expected 200" "${body:0:300}"
  elif [ "$status" != "completed" ]; then
    fail "backup run ended in status '${status}', expected completed: $(echo "$body" | jq -r '.error_message // empty' 2>/dev/null)" "${body:0:300}"
  elif [ "$count" != "3" ]; then
    # artifact_count counts the distinct objects archived for the backup's
    # repositories (artifact and OCI blob objects alike are filtered by
    # repository_ids): exactly the three distinct files in ${REPO_KEY}. More
    # would mean the scope was ignored and other repositories were archived.
    fail "completed backup archived ${count} objects, expected exactly the 3 uploaded to ${REPO_KEY}" "${body:0:300}"
  else
    pass
  fi
fi

begin_test "GET /admin/backups/{id} reports the completed run"
if [ -z "${BACKUP_ID:-}" ] || [ "$BACKUP_ID" = "null" ]; then
  skip "no backup was created"
else
  resp=$(api_get "/api/v1/admin/backups/${BACKUP_ID}" 2>/dev/null) || resp=""
  st=$(echo "$resp" | jq -r '.status // empty' 2>/dev/null)
  if [ "$st" = "completed" ]; then pass; else fail "backup ${BACKUP_ID} reads back as '${st}', expected completed" "${resp:0:300}"; fi
fi

begin_test "Restore refuses a backup that never ran"
if [ -z "${BACKUP_ID:-}" ] || [ "$BACKUP_ID" = "null" ]; then
  skip "backup API not available"
else
  resp=$(api_post "/api/v1/admin/backups" \
    "{\"type\":\"full\",\"repository_ids\":[\"${REPO_ID}\"]}" 2>/dev/null) || resp=""
  PENDING_ID=$(echo "$resp" | jq -r '.id // empty' 2>/dev/null) || PENDING_ID=""
  if [ -z "$PENDING_ID" ] || [ "$PENDING_ID" = "null" ]; then
    fail "could not create a second (pending) backup" "${resp:0:300}"
  else
    # Refused before anything is ingested, so this is safe on a shared
    # instance: a pending backup has no archive to restore from.
    code=$(curl -s -o "${WORK_DIR}/restore.json" -w '%{http_code}' $CURL_TIMEOUT -X POST \
      -H "$(auth_header)" -H "Content-Type: application/json" -d '{}' \
      "${BASE_URL}/api/v1/admin/backups/${PENDING_ID}/restore" 2>/dev/null) || code=000
    if [ "$code" = "400" ] || [ "$code" = "422" ]; then
      pass
    else
      fail "restore of a pending backup returned HTTP ${code}, expected 400/422 (only completed backups restore)" "$(head -c 300 "${WORK_DIR}/restore.json" 2>/dev/null)"
    fi
  fi
fi

begin_test "Archived artifacts still download intact"
ALL_OK=true
for i in 1 2 3; do
  # /download/ serves the bytes; GET /artifacts/{path} answers the metadata
  # document, which is what the old restore check (never reached) read.
  content=$(curl -sf -H "$(auth_header)" $CURL_TIMEOUT \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}/download/data/file-${i}.txt" 2>/dev/null) || content=""
  if [ "$content" != "backup-content-${i}-${RUN_ID}" ]; then
    ALL_OK=false
    fail "file-${i}.txt content mismatch after the backup run" "${content:0:200}"
    break
  fi
done
if [ "$ALL_OK" = true ]; then pass; fi

end_suite
