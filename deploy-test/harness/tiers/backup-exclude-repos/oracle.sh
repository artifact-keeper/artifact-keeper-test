#!/usr/bin/env bash
# =============================================================================
# tiers/backup-exclude-repos/oracle.sh — backup repository-exclusion gate
# (#2772), filesystem storage.
# =============================================================================
# Discriminating oracle for the "exclude repositories from a backup" feature.
#
# Background (backup_service.rs::create + get_artifact_storage_keys): the set of
# artifacts written into a backup archive is selected straight from the
# `artifacts` table. #2772 adds an optional `exclude_repository_ids` to
# CreateBackupRequest: artifacts belonging to those repositories are skipped,
# the exclusion is recorded on the `backups` row metadata, and a repository may
# not appear in both the include (`repository_ids`) and exclude lists (400).
# When the field is absent/empty every repository is backed up (unchanged).
#
# The oracle seeds two maven local repos with one real .jar each, so the backend
# has real artifacts + storage objects to include/exclude, then asserts:
#
#   BEHAVIOURAL — a full backup counts N artifacts; a backup excluding one repo
#                 counts strictly fewer, dropping exactly that repo's stored
#                 artifacts.
#                 Pre-#2772: the exclude list is ignored -> same N -> FAIL.
#   METADATA    — the excluding backup's `backups.metadata` records the excluded
#                 repo id. Pre-#2772: no exclusion key present -> FAIL.
#   REJECTION   — create-backup naming the same repo in BOTH include and exclude
#                 -> 400. Pre-#2772: unknown field ignored -> accepted -> FAIL.
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
SUF="$RANDOM$RANDOM"
KEEP="dtfkeep$SUF"            # repo whose artifact stays in every backup
SKIP="dtfskip$SUF"           # repo excluded from the exclusion backup

jqr(){ jq -r "$1" 2>/dev/null; }
psql_q(){ docker exec "$DBC" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]'; }

# Create a backup of the given JSON body and execute it synchronously; echoes
# "<backup_id> <artifact_count>" on success, empty on failure.
create_and_execute(){ # JSON_BODY
  local body="$1" resp bid ex
  resp=$(curl -s -X POST "$BASE/api/v1/admin/backups" -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H 'Content-Type: application/json' -d "$body")
  bid=$(echo "$resp" | jqr '.id // empty')
  [ -z "$bid" ] && { echo ""; return 1; }
  ex=$(curl -s -X POST "$BASE/api/v1/admin/backups/$bid/execute" \
    -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json')
  echo "$bid $(echo "$ex" | jqr '.artifact_count // empty')"
}

begin_suite "backup-exclude-repos-filesystem"

# --- setup: admin token -----------------------------------------------------
auth_admin   # sets ADMIN_TOKEN (waits for readiness, fatal on failure)

# --- setup: two maven local repos, one real .jar each -----------------------
JAR=$(mktemp); printf 'PK\003\004dtf-exclude-%s-payload' "$SUF" > "$JAR"

SETUP_OK=1
for R in "$KEEP" "$SKIP"; do
  if ! create_repo "$R" "maven" "local"; then SETUP_OK=0; fi
  PC=$(format_put_with_retry "$BASE/maven/$R/com/dtf/app/1.0/app-1.0.jar" "$JAR")
  echo "-- seed PUT $R/com/dtf/app/1.0/app-1.0.jar -> HTTP $PC"
  [ "$PC" -ge 200 ] 2>/dev/null && [ "$PC" -lt 300 ] 2>/dev/null || SETUP_OK=0
done
rm -f "$JAR"

SKIP_ID=$(psql_q "SELECT id FROM repositories WHERE key='$SKIP';")
KEEP_ID=$(psql_q "SELECT id FROM repositories WHERE key='$KEEP';")

# The maven upload writes each object under a repo-scoped storage key
# (<repo_key>/maven/...) while artifacts.storage_key records the unscoped
# `maven/...` path. BackupService reads storage_key verbatim, so without this
# realignment the archive can never retrieve the bytes and counts zero for
# every repo (a separate, pre-existing repo-scoped-backup concern, out of scope
# for #2772). Point storage_key at the on-disk scoped key so the archive
# actually captures the seeded artifacts and the exclusion is observable.
psql_q "UPDATE artifacts a SET storage_key = r.key || '/' || a.storage_key \
  FROM repositories r \
  WHERE a.repository_id = r.id \
    AND a.repository_id IN ('$KEEP_ID','$SKIP_ID') \
    AND a.storage_key NOT LIKE r.key || '/%';" >/dev/null

SKIP_ARTIFACTS=$(psql_q "SELECT count(*) FROM artifacts WHERE repository_id='$SKIP_ID' AND storage_key IS NOT NULL;")
echo "-- KEEP_ID=$KEEP_ID SKIP_ID=$SKIP_ID SKIP_ARTIFACTS=$SKIP_ARTIFACTS"

if [ "$SETUP_OK" != 1 ] || [ -z "$SKIP_ID" ] || [ -z "$KEEP_ID" ] || \
   [ -z "$SKIP_ARTIFACTS" ] || [ "$SKIP_ARTIFACTS" -lt 1 ] 2>/dev/null; then
  begin_test "setup: two maven repos each with a stored artifact"
  fail "seed failed (SETUP_OK=$SETUP_OK KEEP_ID=$KEEP_ID SKIP_ID=$SKIP_ID SKIP_ARTIFACTS=$SKIP_ARTIFACTS)"
  end_suite
  exit 1
fi

# ---------------------------------------------------------------------------
# Baseline: a full backup (no exclusion) counts every stored artifact.
begin_test "CONTROL: full backup with no exclusion includes every repository's artifacts (#2772 is additive)"
read -r FULL_BID FULL_CNT <<<"$(create_and_execute '{"backup_type":"full"}')"
echo "-- full backup id=$FULL_BID artifact_count=$FULL_CNT"
if [ -n "$FULL_BID" ] && [ -n "$FULL_CNT" ] && [ "$FULL_CNT" -ge 2 ] 2>/dev/null; then
  pass
else
  fail "full backup did not count both seeded artifacts (id='$FULL_BID' count='$FULL_CNT', expected >=2)"
fi

# ---------------------------------------------------------------------------
# BEHAVIOURAL: excluding SKIP drops exactly its stored artifacts.
begin_test "BEHAVIOURAL: backup excluding a repository skips that repo's artifacts (#2772)"
read -r EXC_BID EXC_CNT <<<"$(create_and_execute "{\"backup_type\":\"full\",\"exclude_repository_ids\":[\"$SKIP_ID\"]}")"
echo "-- excluding backup id=$EXC_BID artifact_count=$EXC_CNT (full=$FULL_CNT, skip_artifacts=$SKIP_ARTIFACTS)"
if [ -z "$EXC_BID" ] || [ -z "$EXC_CNT" ]; then
  fail "excluding backup did not complete (id='$EXC_BID' count='$EXC_CNT')"
elif [ "$EXC_CNT" -lt "$FULL_CNT" ] 2>/dev/null && \
     [ "$EXC_CNT" -eq "$((FULL_CNT - SKIP_ARTIFACTS))" ] 2>/dev/null; then
  pass
else
  fail "excluded backup count $EXC_CNT != full $FULL_CNT minus skipped $SKIP_ARTIFACTS (pre-#2772 the exclude list is ignored so the count is unchanged)"
fi

# ---------------------------------------------------------------------------
# METADATA: the exclusion is recorded on the backups row.
begin_test "METADATA: excluding backup records the excluded repository id in backups.metadata (#2772)"
META=$(psql_q "SELECT metadata->'exclude_repository_ids' FROM backups WHERE id='$EXC_BID';")
echo "-- backups.metadata->exclude_repository_ids = '$META'"
if echo "$META" | grep -q "$SKIP_ID"; then
  pass
else
  fail "backups.metadata does not record excluded repo '$SKIP_ID' (got '$META'; pre-#2772 the field is ignored and never persisted)"
fi

# ---------------------------------------------------------------------------
# REJECTION: a repo in both include and exclude is a contradiction -> 400.
begin_test "REJECTION: a repository named in BOTH include and exclude is rejected 400 (#2772)"
RHTTP=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/v1/admin/backups" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d "{\"backup_type\":\"full\",\"repository_ids\":[\"$SKIP_ID\"],\"exclude_repository_ids\":[\"$SKIP_ID\"]}")
echo "-- contradictory include/exclude create -> HTTP $RHTTP"
if [ "$RHTTP" = "400" ]; then
  pass
else
  fail "contradictory include/exclude expected HTTP 400, got $RHTTP (pre-#2772 the unknown exclude field is ignored and the request is accepted)"
fi

end_suite
