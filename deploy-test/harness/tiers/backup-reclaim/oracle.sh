#!/usr/bin/env bash
# =============================================================================
# tiers/backup-reclaim/oracle.sh — backup retention storage-reclaim gate (#2787)
# =============================================================================
# Discriminating oracle for the backup-retention storage leak.
#
# Background (backup_service.rs::cleanup): retention cleanup ran a bare
# `DELETE FROM backups WHERE ... status='completed'` and NEVER deleted the
# .tar.gz archive object, so aged-out backups leaked their storage forever.
# #2787 makes cleanup delete the archive object first, then the row.
#
# The archive is written by StorageService (filesystem backend rooted at
# STORAGE_PATH=/data/storage) at key `backups/YYYY/MM/DD/<uuid>.tar.gz`, i.e.
# on disk inside the backend container at /data/storage/<storage_path>. We
# inspect it directly with `docker exec` (the CIS-hardened runtime image has no
# shell, but ships /bin/test + /usr/bin/find).
#
# Flow:
#   1. POST /api/v1/admin/backups            -> pending row + storage_path
#   2. POST /api/v1/admin/backups/{id}/execute -> completed row + archive on disk
#      ASSERT: completed row exists AND archive file exists.
#   3. backup_retention_count=0 (system_settings) + age created_at past
#      retention_days, then POST /api/v1/admin/cleanup {cleanup_old_backups:true}
#      ASSERT: backups_deleted>=1, the row is gone, AND the archive is gone.
#      Pre-#2787 the archive survives -> the object-absent assertion fails.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RELEASE_GATE=1,
# JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

BASE="$BASE_URL"
DBC="$DB_CONTAINER"
BC="${DB_CONTAINER%-db}-backend"   # ak-dtf<slot>-backend (same slot namespace)

jqr(){ jq -r "$1" 2>/dev/null; }
login(){ curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"$1\",\"password\":\"$2\"}" | jqr '.access_token // .token // empty'; }
psql_q(){ docker exec "$DBC" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null; }
# Archive present on the backend's storage volume? (/bin/test ships in the
# hardened runtime image; no shell is available for `test -f X && echo`.)
arch_present(){ docker exec "$BC" /bin/test -f "$1" >/dev/null 2>&1; }

begin_suite "backup-reclaim-filesystem"

# ---------------------------------------------------------------------------
begin_test "Backup create+execute writes a .tar.gz archive on the storage backend and a completed backups row"
FAILS=0
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); }

TOK=$(login admin "$ADMIN_PASS")
if [ -z "$TOK" ]; then fail "admin login failed at $BASE"; end_suite; exit 1; fi

CREATE=$(curl -s -X POST "$BASE/api/v1/admin/backups" -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' -d '{"backup_type":"full"}')
BID=$(echo "$CREATE" | jqr '.id // empty')
echo "-- create backup id: '${BID:-<none>}'"
if [ -z "$BID" ]; then fail "create backup failed: $CREATE"; end_suite; exit 1; fi

EXEC=$(curl -s -X POST "$BASE/api/v1/admin/backups/$BID/execute" -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json')
EST=$(echo "$EXEC" | jqr '.status // empty')
echo "-- execute status: '$EST'"

# storage_path is relative to the filesystem backend root (/data/storage).
SP=$(psql_q "SELECT storage_path FROM backups WHERE id='$BID';" | tr -d '[:space:]')
APATH="/data/storage/$SP"
ST=$(psql_q "SELECT status FROM backups WHERE id='$BID';" | tr -d '[:space:]')
echo "-- backups row status='$ST' storage_path='$SP'"
echo "-- archive path (in $BC): '$APATH'"

[ "$ST" = "completed" ] || fail_g "backup did not reach 'completed' (status='$ST'); execute resp=$EXEC"
if [ -n "$SP" ] && arch_present "$APATH"; then
  echo "   OK: archive present on storage backend"
else
  fail_g "archive .tar.gz not found on storage backend at $APATH"
  echo "   (dir listing:)"; docker exec "$BC" /usr/bin/find /data/storage/backups -type f 2>/dev/null | sed 's/^/     /' || true
fi

if [ "$FAILS" -eq 0 ]; then pass; else fail "backup create/execute did not produce a completed row + on-disk archive"; fi

# ---------------------------------------------------------------------------
begin_test "Retention cleanup reclaims BOTH the backups row AND the .tar.gz archive object (#2787 no storage leak)"
FAILS=0

if [ -z "${BID:-}" ] || [ -z "${SP:-}" ]; then
  fail "prerequisite backup/archive missing; cannot run reclaim gate"
  end_suite; exit 1
fi

# Make a single aged, completed backup eligible for retention deletion:
#   * backup_retention_count = 0  -> keep-most-recent-N window is empty
#   * created_at aged well past retention_days (default 365)
psql_q "INSERT INTO system_settings (key, value) VALUES ('backup_retention_count', '0'::jsonb)
        ON CONFLICT (key) DO UPDATE SET value='0'::jsonb;" >/dev/null
psql_q "UPDATE backups SET created_at = NOW() - interval '3650 days' WHERE id='$BID';" >/dev/null
AGED=$(psql_q "SELECT to_char(created_at,'YYYY') FROM backups WHERE id='$BID';" | tr -d '[:space:]')
echo "-- aged backup created_at year='$AGED'; backup_retention_count set to 0"

# Sanity: archive is still present right before cleanup (else the post-check is
# vacuous).
if arch_present "$APATH"; then
  echo "-- pre-cleanup: archive still present (good, the reclaim check is meaningful)"
else
  fail_g "pre-cleanup: archive vanished before retention ran; cannot discriminate the leak"
fi

CLEAN=$(curl -s -X POST "$BASE/api/v1/admin/cleanup" -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' -d '{"cleanup_old_backups":true}')
DELN=$(echo "$CLEAN" | jqr '.backups_deleted // 0')
echo "-- cleanup response backups_deleted=$DELN ($CLEAN)"
[ "${DELN:-0}" -ge 1 ] 2>/dev/null || fail_g "cleanup did not delete the aged backup (backups_deleted=$DELN)"

# Row must be gone (both pre- and post-fix delete the row).
ROWLEFT=$(psql_q "SELECT count(*) FROM backups WHERE id='$BID';" | tr -d '[:space:]')
echo "-- backups rows remaining for id: $ROWLEFT (expect 0)"
[ "${ROWLEFT:-1}" = "0" ] || fail_g "backups DB row was NOT deleted (remaining=$ROWLEFT)"

# THE DISCRIMINATOR: the archive object must ALSO be gone. Pre-#2787 it leaks.
if arch_present "$APATH"; then
  fail_g "STORAGE LEAK (#2787): backups row deleted but .tar.gz archive REMAINS at $APATH"
  docker exec "$BC" /usr/bin/find /data/storage/backups -type f 2>/dev/null | sed 's/^/     leaked: /' || true
else
  echo "   OK: archive object reclaimed from storage backend"
fi

if [ "$FAILS" -eq 0 ]; then
  pass
else
  fail "retention cleanup left a leaked backup archive and/or did not reclaim the row (#2787)" \
       "backup_id=$BID archive=$APATH backups_deleted=$DELN rows_remaining=${ROWLEFT:-?}"
fi

end_suite
