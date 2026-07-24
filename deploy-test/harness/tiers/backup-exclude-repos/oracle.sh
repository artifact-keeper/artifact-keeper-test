#!/usr/bin/env bash
# =============================================================================
# tiers/backup-exclude-repos/oracle.sh — exclude repositories from backups
# (#2772 / feat/2772-backup-exclude-repos), filesystem storage.
# =============================================================================
# Discriminating oracle for the backup repository-exclude capability.
#
# Background (backup_service.rs): CreateBackupRequest gained an optional
# `exclude_repositories` (repository ids). When set, BackupService drops those
# repositories' artifacts from the archive -- both the artifact bytes and their
# rows in the `database/artifacts.json` table dump. When omitted, every
# repository is backed up exactly as before.
#
# The archive is written by StorageService (filesystem backend rooted at
# STORAGE_PATH=/data/storage) at key `backups/YYYY/MM/DD/<uuid>.tar.gz`, i.e.
# on disk inside the backend container at /data/storage/<storage_path>. The
# CIS-hardened runtime image has no shell/tar, so the archive is pulled out with
# `docker cp` (which needs no in-container shell) and inspected with host
# tar + jq.
#
# Two maven/local repos are seeded -- "keep" and "drop" -- each with one
# artifact. artifacts.json in the archive always carries the artifact ROWS
# (independent of whether repo-scoped artifact BYTES resolve on this backend),
# so it is the stable discriminating signal.
#
# Asserts (archive contents):
#   POSITIVE (full)        -- exclude=[drop]: keep artifact PRESENT, drop ABSENT.
#                             Pre-#2772: exclude ignored -> drop present -> FAIL.
#   POSITIVE (incremental) -- same, backup_type=incremental.
#   CONTROL (no exclude)   -- both keep and drop PRESENT (feature is additive).
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
SUF="$RANDOM$RANDOM"
KEEP="keeprepo$SUF"
DROP="droprepo$SUF"

jqr(){ jq -r "$1" 2>/dev/null; }
login(){ curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"$1\",\"password\":\"$2\"}" | jqr '.access_token // .token // empty'; }
psql_q(){ docker exec "$DBC" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null; }

# Create + execute a backup, pull its archive out with docker cp, and print the
# repository_ids recorded in database/artifacts.json (one per line). Matching on
# repository_id (not storage_key) is collision-proof: maven's flat storage_key
# is identical across repos, so only the id distinguishes the seeded "keep"/"drop"
# repos from any leftover data. Emits nothing on failure. $1 = request body.
backup_artifact_repo_ids(){
  local body="$1" create bid sp tmp
  create=$(curl -s -X POST "$BASE/api/v1/admin/backups" -H "Authorization: Bearer $TOK" \
    -H 'Content-Type: application/json' -d "$body")
  bid=$(echo "$create" | jqr '.id // empty')
  [ -z "$bid" ] && { echo "CREATE_FAILED: $create" >&2; return 1; }
  curl -s -X POST "$BASE/api/v1/admin/backups/$bid/execute" -H "Authorization: Bearer $TOK" \
    -H 'Content-Type: application/json' >/dev/null
  sp=$(psql_q "SELECT storage_path FROM backups WHERE id='$bid';" | tr -d '[:space:]')
  [ -z "$sp" ] && { echo "NO_STORAGE_PATH for $bid" >&2; return 1; }
  tmp=$(mktemp --suffix=.tar.gz)
  if ! docker cp "$BC:/data/storage/$sp" "$tmp" >/dev/null 2>&1; then
    echo "DOCKER_CP_FAILED $BC:/data/storage/$sp" >&2; rm -f "$tmp"; return 1
  fi
  tar -xzOf "$tmp" database/artifacts.json 2>/dev/null | jqr '.[]|.repository_id'
  rm -f "$tmp"
}

begin_suite "backup-exclude-repos-filesystem"

TOK=$(login admin "$ADMIN_PASS")
if [ -z "$TOK" ]; then
  begin_test "admin login"; fail "admin login failed at $BASE"; end_suite; exit 1
fi

# --- Seed: two maven/local repos, one artifact each --------------------------
for k in "$KEEP" "$DROP"; do
  curl -s -X POST "$BASE/api/v1/repositories" -H "Authorization: Bearer $TOK" \
    -H 'Content-Type: application/json' \
    -d "{\"key\":\"$k\",\"name\":\"$k\",\"format\":\"maven\",\"repo_type\":\"local\"}" >/dev/null
done
KP="com/ex/keep/1.0/keep-1.0.jar"
DP="com/ex/drop/1.0/drop-1.0.jar"
KPUT=$(curl -s -o /dev/null -w '%{http_code}' -X PUT "$BASE/maven/$KEEP/$KP" \
  -H "Authorization: Bearer $TOK" --data-binary "keepdata$SUF")
DPUT=$(curl -s -o /dev/null -w '%{http_code}' -X PUT "$BASE/maven/$DROP/$DP" \
  -H "Authorization: Bearer $TOK" --data-binary "dropdata$SUF")
echo "-- seed uploads: keep=$KPUT drop=$DPUT"
DROP_ID=$(psql_q "SELECT id FROM repositories WHERE key='$DROP';" | tr -d '[:space:]')
KEEP_ID=$(psql_q "SELECT id FROM repositories WHERE key='$KEEP';" | tr -d '[:space:]')
echo "-- KEEP_ID='$KEEP_ID' DROP_ID='$DROP_ID'"
if [ -z "$KEEP_ID" ] || [ -z "$DROP_ID" ]; then
  begin_test "seed repositories"; fail "could not seed keep/drop repos (keep='$KEEP_ID' drop='$DROP_ID')"
  end_suite; exit 1
fi

# ---------------------------------------------------------------------------
begin_test "FULL backup with exclude_repositories omits the excluded repo's artifacts and keeps the others (#2772)"
RIDS=$(backup_artifact_repo_ids "{\"type\":\"full\",\"exclude_repositories\":[\"$DROP_ID\"]}")
echo "-- full/exclude artifacts.json repo_ids (kept):"; echo "$RIDS" | sort -u | sed 's/^/     /'
if echo "$RIDS" | grep -qF "$KEEP_ID" && ! echo "$RIDS" | grep -qF "$DROP_ID"; then
  pass
else
  fail "excluded repo ($DROP_ID) still present (or kept repo $KEEP_ID missing) in full backup; exclude_repositories was ignored (pre-#2772 the field does not exist)"
fi

# ---------------------------------------------------------------------------
begin_test "INCREMENTAL backup with exclude_repositories omits the excluded repo's artifacts (#2772)"
IRIDS=$(backup_artifact_repo_ids "{\"type\":\"incremental\",\"exclude_repositories\":[\"$DROP_ID\"]}")
echo "-- incremental/exclude artifacts.json repo_ids (kept):"; echo "$IRIDS" | sort -u | sed 's/^/     /'
if echo "$IRIDS" | grep -qF "$KEEP_ID" && ! echo "$IRIDS" | grep -qF "$DROP_ID"; then
  pass
else
  fail "excluded repo ($DROP_ID) still present (or kept repo $KEEP_ID missing) in incremental backup; exclude_repositories was ignored"
fi

# ---------------------------------------------------------------------------
begin_test "CONTROL: a backup with NO exclude still contains BOTH repositories (additive feature)"
CRIDS=$(backup_artifact_repo_ids '{"type":"full"}')
echo "-- control/no-exclude artifacts.json repo_ids:"; echo "$CRIDS" | sort -u | sed 's/^/     /'
if echo "$CRIDS" | grep -qF "$KEEP_ID" && echo "$CRIDS" | grep -qF "$DROP_ID"; then
  pass
else
  fail "default (no-exclude) backup did not contain both repositories (keep=$KEEP_ID + drop=$DROP_ID expected)"
fi

end_suite
