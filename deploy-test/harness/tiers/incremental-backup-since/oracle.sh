#!/usr/bin/env bash
# =============================================================================
# tiers/incremental-backup-since/oracle.sh — incremental "changes since" backup
# (#2789 / feat/2789-incremental-backup-since), filesystem storage.
# =============================================================================
# Discriminating oracle for the backup "from a given date to now" capability.
#
# Background (backup_service.rs): CreateBackupRequest gained an optional `since`
# (an RFC3339 timestamp). When set, BackupService includes only artifacts whose
# `updated_at >= since` in the archive -- both the artifact bytes and their rows
# in the `database/artifacts.json` table dump. When omitted, every artifact is
# backed up exactly as before.
#
# The archive is written by StorageService (filesystem backend rooted at
# STORAGE_PATH=/data/storage) at key `backups/YYYY/MM/DD/<uuid|name>.tar.gz`, on
# disk inside the backend container at /data/storage/<storage_path>. The
# CIS-hardened runtime image has no shell/tar, so the archive is pulled out with
# `docker cp` (which needs no in-container shell) and inspected with host
# tar + jq.
#
# One maven/local repo is seeded with two artifacts, "old" and "new". The "old"
# artifact's `updated_at` is moved to 2000-01-01 via SQL (no updated_at trigger
# exists on `artifacts`, so the backdate sticks), and the cutoff is 2020-01-01,
# so `since` cleanly separates them. artifacts.json carries the artifact ROWS
# (independent of whether artifact BYTES resolve on this backend), so the row's
# `id` is the stable discriminating signal. Each backup is scoped with
# `repository_ids` to the seeded repo so seed/leftover artifacts never blur the
# signal; the `since` predicate is ANDed with that scope.
#
# Asserts (archive contents):
#   POSITIVE (incremental) -- since=2020: NEW artifact PRESENT, OLD ABSENT.
#                             Pre-#2789: since ignored -> OLD present -> FAIL.
#   POSITIVE (full)        -- same, backup_type=full.
#   CONTROL (no since)     -- both OLD and NEW PRESENT (feature is additive).
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
REPO="sincerepo$SUF"
CUTOFF="2020-01-01T00:00:00Z"      # since cutoff: OLD (2000) excluded, NEW (now) kept

jqr(){ jq -r "$1" 2>/dev/null; }
login(){ curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"$1\",\"password\":\"$2\"}" | jqr '.access_token // .token // empty'; }
psql_q(){ docker exec "$DBC" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null; }

# Create + execute a backup, pull its archive out with docker cp, and print the
# artifact ids recorded in database/artifacts.json (one per line). Matching on
# artifact id is collision-proof: OLD and NEW share a repo, so only the id
# distinguishes them. Emits nothing on failure. $1 = request body.
backup_artifact_ids(){
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
  tar -xzOf "$tmp" database/artifacts.json 2>/dev/null | jqr '.[]|.id'
  rm -f "$tmp"
}

begin_suite "incremental-backup-since-filesystem"

TOK=$(login admin "$ADMIN_PASS")
if [ -z "$TOK" ]; then
  begin_test "admin login"; fail "admin login failed at $BASE"; end_suite; exit 1
fi

# --- Seed: one maven/local repo with two artifacts (old + new) ---------------
curl -s -X POST "$BASE/api/v1/repositories" -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' \
  -d "{\"key\":\"$REPO\",\"name\":\"$REPO\",\"format\":\"maven\",\"repo_type\":\"local\"}" >/dev/null
OP="com/ex/old/1.0/old-1.0.jar"
NP="com/ex/new/1.0/new-1.0.jar"
OPUT=$(curl -s -o /dev/null -w '%{http_code}' -X PUT "$BASE/maven/$REPO/$OP" \
  -H "Authorization: Bearer $TOK" --data-binary "olddata$SUF")
NPUT=$(curl -s -o /dev/null -w '%{http_code}' -X PUT "$BASE/maven/$REPO/$NP" \
  -H "Authorization: Bearer $TOK" --data-binary "newdata$SUF")
echo "-- seed uploads: old=$OPUT new=$NPUT"
REPO_ID=$(psql_q "SELECT id FROM repositories WHERE key='$REPO';" | tr -d '[:space:]')
OLD_ID=$(psql_q "SELECT id FROM artifacts WHERE repository_id='$REPO_ID' AND path='$OP';" | tr -d '[:space:]')
NEW_ID=$(psql_q "SELECT id FROM artifacts WHERE repository_id='$REPO_ID' AND path='$NP';" | tr -d '[:space:]')
echo "-- REPO_ID='$REPO_ID' OLD_ID='$OLD_ID' NEW_ID='$NEW_ID'"
if [ -z "$REPO_ID" ] || [ -z "$OLD_ID" ] || [ -z "$NEW_ID" ]; then
  begin_test "seed repo + two artifacts"
  fail "could not seed repo/artifacts (repo='$REPO_ID' old='$OLD_ID' new='$NEW_ID')"
  end_suite; exit 1
fi

# Move the OLD artifact well before the cutoff so `since` must exclude it.
# (No updated_at trigger exists on `artifacts`, so this backdate persists.)
psql_q "UPDATE artifacts SET updated_at='2000-01-01T00:00:00Z' WHERE id='$OLD_ID';" >/dev/null
OLD_TS=$(psql_q "SELECT updated_at FROM artifacts WHERE id='$OLD_ID';" | tr -d '[:space:]')
echo "-- backdated OLD updated_at='$OLD_TS' (cutoff=$CUTOFF)"

# ---------------------------------------------------------------------------
begin_test "INCREMENTAL backup with since excludes the older artifact and keeps the newer (#2789)"
IIDS=$(backup_artifact_ids "{\"type\":\"incremental\",\"repository_ids\":[\"$REPO_ID\"],\"since\":\"$CUTOFF\"}")
echo "-- incremental/since artifacts.json ids:"; echo "$IIDS" | sort -u | sed 's/^/     /'
if echo "$IIDS" | grep -qF "$NEW_ID" && ! echo "$IIDS" | grep -qF "$OLD_ID"; then
  pass
else
  fail "older artifact ($OLD_ID) still present (or newer $NEW_ID missing) in since-scoped incremental backup; the since cutoff was ignored (pre-#2789 the field does not exist)"
fi

# ---------------------------------------------------------------------------
begin_test "FULL backup with since also excludes the older artifact (#2789)"
FIDS=$(backup_artifact_ids "{\"type\":\"full\",\"repository_ids\":[\"$REPO_ID\"],\"since\":\"$CUTOFF\"}")
echo "-- full/since artifacts.json ids:"; echo "$FIDS" | sort -u | sed 's/^/     /'
if echo "$FIDS" | grep -qF "$NEW_ID" && ! echo "$FIDS" | grep -qF "$OLD_ID"; then
  pass
else
  fail "older artifact ($OLD_ID) still present (or newer $NEW_ID missing) in since-scoped full backup; the since cutoff was ignored"
fi

# ---------------------------------------------------------------------------
begin_test "CONTROL: a backup with NO since still contains BOTH artifacts (additive feature)"
CIDS=$(backup_artifact_ids "{\"type\":\"incremental\",\"repository_ids\":[\"$REPO_ID\"]}")
echo "-- control/no-since artifacts.json ids:"; echo "$CIDS" | sort -u | sed 's/^/     /'
if echo "$CIDS" | grep -qF "$NEW_ID" && echo "$CIDS" | grep -qF "$OLD_ID"; then
  pass
else
  fail "default (no-since) backup did not contain both artifacts (old=$OLD_ID + new=$NEW_ID expected)"
fi

end_suite
