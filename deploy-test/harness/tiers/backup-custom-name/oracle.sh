#!/usr/bin/env bash
# =============================================================================
# tiers/backup-custom-name/oracle.sh — custom backup archive name gate
# (#2790 / PR #2840), filesystem storage.
# =============================================================================
# Discriminating oracle for the operator-supplied backup archive name.
#
# Background (backup_service.rs::create + resolve_backup_filename): the archive
# storage key is chosen at create time and stored on the `backups` row as
# `storage_path`. #2790 adds an optional `name` to CreateBackupRequest: when set
# it becomes the identifying part of the filename (`{name}-{suffix}.tar.gz`);
# when omitted the historical `{uuid}.tar.gz` name is kept. The name is
# sanitized to `[A-Za-z0-9._-]` — path separators, `..`, whitespace and control
# characters are rejected with 400.
#
# Asserts (DB + HTTP):
#   POSITIVE   — POST create-backup with a custom label -> the row's
#                storage_path filename CONTAINS the label.
#                Pre-#2790: the `name` field is ignored -> storage_path is
#                `.../{uuid}.tar.gz` (no label) -> FAIL.
#   REJECTION  — POST create-backup with an unsafe label (path separator) -> 400.
#                Pre-#2790: the unknown field is ignored -> the request is
#                accepted (2xx) -> FAIL.
#   CONTROL    — POST create-backup with NO name -> still succeeds and the
#                default `{uuid}.tar.gz` name is used (feature is additive).
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
LABEL="dtflabel$SUF"          # sanitizer-safe custom name
UNSAFE="../evil$SUF"          # path-traversal name; must be rejected

jqr(){ jq -r "$1" 2>/dev/null; }
login(){ curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"$1\",\"password\":\"$2\"}" | jqr '.access_token // .token // empty'; }
psql_q(){ docker exec "$DBC" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null; }

begin_suite "backup-custom-name-filesystem"

TOK=$(login admin "$ADMIN_PASS")
if [ -z "$TOK" ]; then
  begin_test "admin login"; fail "admin login failed at $BASE"; end_suite; exit 1
fi

# ---------------------------------------------------------------------------
begin_test "POST create-backup with a custom name yields an archive filename containing that name (#2790)"
CREATE=$(curl -s -X POST "$BASE/api/v1/admin/backups" -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' -d "{\"backup_type\":\"full\",\"name\":\"$LABEL\"}")
BID=$(echo "$CREATE" | jqr '.id // empty')
echo "-- create resp id: '${BID:-<none>}'"
if [ -z "$BID" ]; then
  fail "create backup (custom name) failed: $CREATE"
else
  SP=$(psql_q "SELECT storage_path FROM backups WHERE id='$BID';" | tr -d '[:space:]')
  echo "-- storage_path: '$SP'"
  if echo "$SP" | grep -q "$LABEL"; then
    pass
  else
    fail "storage_path '$SP' does not contain the custom label '$LABEL' (pre-#2790 the name field is ignored and the key is the default {uuid}.tar.gz)"
  fi
fi

# ---------------------------------------------------------------------------
begin_test "POST create-backup with an unsafe name (path separator) is rejected 400 (#2790)"
UHTTP=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/v1/admin/backups" \
  -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
  -d "{\"backup_type\":\"full\",\"name\":\"$UNSAFE\"}")
echo "-- unsafe-name create -> HTTP $UHTTP"
if [ "$UHTTP" = "400" ]; then
  pass
else
  fail "unsafe backup name expected HTTP 400, got $UHTTP (pre-#2790 the unknown 'name' field is ignored and the request is accepted)"
fi

# ---------------------------------------------------------------------------
begin_test "CONTROL: create-backup with NO name still succeeds with the default {uuid}.tar.gz key (additive feature)"
DEF=$(curl -s -X POST "$BASE/api/v1/admin/backups" -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' -d '{"backup_type":"full"}')
DBID=$(echo "$DEF" | jqr '.id // empty')
DSP=$(psql_q "SELECT storage_path FROM backups WHERE id='$DBID';" | tr -d '[:space:]')
echo "-- default create id='${DBID:-<none>}' storage_path='$DSP'"
if [ -n "$DBID" ] && echo "$DSP" | grep -qE 'backups/.*\.tar\.gz$' && ! echo "$DSP" | grep -q "$LABEL"; then
  pass
else
  fail "default (no-name) backup did not produce a default .tar.gz key (id='$DBID', storage_path='$DSP')"
fi

end_suite
