#!/usr/bin/env bash
# =============================================================================
# tiers/backup-s3-bucket/oracle.sh — separate S3 bucket for backups gate
# (#2507), S3/MinIO storage.
# =============================================================================
# Discriminating oracle for BACKUP_S3_BUCKET.
#
# Background (backup_service.rs + storage_service.rs::backup_archive_from_config):
# when BACKUP_S3_BUCKET is set on an S3 deployment, the backup subsystem reads
# and writes backup ARCHIVES to that dedicated bucket instead of the primary
# artifact bucket (S3_BUCKET). Source artifacts and restores keep using primary
# storage, so a separate backup bucket never changes where artifacts live. When
# BACKUP_S3_BUCKET is unset, behavior is byte-identical (archives live in the
# primary bucket).
#
# This tier runs on the S3 profile plus the storage.s3-backup-bucket overlay,
# which provisions a second bucket `ak-backups` and sets BACKUP_S3_BUCKET to it.
# The routing is only observable on a real object store — on filesystem the var
# resolves to "reuse primary" — hence the S3 profile is mandatory.
#
# Asserts (HTTP + object store):
#   POSITIVE   — create + execute a backup -> the archive (.tar.gz) appears in
#                the `ak-backups` bucket.
#                Pre-#2507: BACKUP_S3_BUCKET is ignored -> `ak-backups` empty ->
#                FAIL.
#   ISOLATION  — the `ak-artifacts` bucket contains NO backup archive under
#                backups/.
#                Pre-#2507: the archive lands in `ak-artifacts` -> FAIL.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RELEASE_GATE=1,
# JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

BASE="$BASE_URL"
# The minio container shares the slot prefix with the DB container
# (ak-dtf<slot>-db -> ak-dtf<slot>-minio). Joining a transient mc container to
# minio's network namespace lets us reach it at localhost:9000 without needing
# the compose network name.
MINIO_CTR="${DB_CONTAINER%-db}-minio"
ART_BUCKET="ak-artifacts"
BKP_BUCKET="ak-backups"

jqr(){ jq -r "$1" 2>/dev/null; }
login(){ curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"$1\",\"password\":\"$2\"}" | jqr '.access_token // .token // empty'; }

# Recursively list a bucket via a throwaway mc container in minio's netns.
mc_ls(){
  docker run --rm --network "container:$MINIO_CTR" --entrypoint sh minio/mc:latest -c \
    "mc alias set local http://localhost:9000 minioadmin minioadmin >/dev/null 2>&1 && \
     mc ls --recursive \"local/$1\" 2>/dev/null"
}

begin_suite "backup-s3-bucket-s3"

TOK=$(login admin "$ADMIN_PASS")
if [ -z "$TOK" ]; then
  begin_test "admin login"; fail "admin login failed at $BASE"; end_suite; exit 1
fi

# ---------------------------------------------------------------------------
begin_test "create + execute a backup writes the archive into the dedicated BACKUP_S3_BUCKET (#2507)"
CREATE=$(curl -s -X POST "$BASE/api/v1/admin/backups" -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' -d '{"backup_type":"full"}')
BID=$(echo "$CREATE" | jqr '.id // empty')
echo "-- create resp id: '${BID:-<none>}'"
if [ -z "$BID" ]; then
  fail "create backup failed: $CREATE"
  end_suite; exit 1
fi

EXEC_HTTP=$(curl -s -o /tmp/dtf-2507-exec.json -w '%{http_code}' -X POST \
  "$BASE/api/v1/admin/backups/$BID/execute" -H "Authorization: Bearer $TOK")
echo "-- execute -> HTTP $EXEC_HTTP  body: $(cat /tmp/dtf-2507-exec.json 2>/dev/null)"

# execute() is synchronous, but retry the object-store listing a few times to
# absorb any container/mc startup latency.
BKP_LS=""
for _ in 1 2 3 4 5; do
  BKP_LS=$(mc_ls "$BKP_BUCKET")
  echo "$BKP_LS" | grep -q '\.tar\.gz' && break
  sleep 2
done
echo "-- ${BKP_BUCKET} listing:"; echo "${BKP_LS:-<empty>}"
if echo "$BKP_LS" | grep -q '\.tar\.gz'; then
  pass
else
  fail "no backup archive found in the dedicated '$BKP_BUCKET' bucket (pre-#2507 the archive is written to the primary '$ART_BUCKET' bucket because BACKUP_S3_BUCKET is ignored)"
fi

# ---------------------------------------------------------------------------
begin_test "ISOLATION: the primary artifact bucket holds NO backup archive under backups/ (#2507)"
ART_LS=$(mc_ls "$ART_BUCKET")
echo "-- ${ART_BUCKET} listing (backups-related lines):"
echo "$ART_LS" | grep -E 'backups/|\.tar\.gz' || echo "  <none>"
if echo "$ART_LS" | grep -qE 'backups/.*\.tar\.gz'; then
  fail "backup archive leaked into the primary '$ART_BUCKET' bucket (pre-#2507 behavior: BACKUP_S3_BUCKET ignored)"
else
  pass
fi

end_suite
