#!/usr/bin/env bash
# =============================================================================
# tiers/backup-scoped-restore/oracle.sh
#   #5884 a backup scoped to one repository archives that repository's row and
#         its artifacts' download statistics only, and its restore never
#         brings back a repository outside the scope
# See the manifest for THE BUG and the gates.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID,
# DTF_SLOT, DTF_DIR, RELEASE_GATE=1, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"; : "${DB_CONTAINER:?}"
: "${ADMIN_PASS:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# shellcheck source=../../lib/repo_delete.sh
source "${DTF_DIR:?}/harness/lib/repo_delete.sh"

# common.sh enables errexit; every probe below guards its own failure so a
# miss records a JUnit case instead of killing the oracle.
set +e

SLOT="${DTF_SLOT}"
SUF="${RUN_ID##*-}-$$"
A="${BASE_URL}"
CTR="ak-dtf${SLOT}-backend"
AUTH="${ADMIN_USER:-admin}:${ADMIN_PASS}"
IN="bsr-in-${SUF}"
OUT="bsr-out-${SUF}"

W="$(mktemp -d -t dtf-bsr-XXXXXX)"
trap 'rm -rf "$W"' EXIT

psql_q() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -Atc "$1" 2>/dev/null || true; }
code() { curl -s -o "$W/last" -w '%{http_code}' --max-time 300 "$@" 2>/dev/null || echo 000; }
body() { cat "$W/last" 2>/dev/null; }
sha() { sha256sum "$1" | cut -d' ' -f1; }

create_repo() { # key -> http code
  code -u "$AUTH" -X POST -H 'Content-Type: application/json' \
    -d "{\"key\":\"$1\",\"name\":\"$1\",\"format\":\"generic\",\"repo_type\":\"local\",\"is_public\":false}" \
    "${A}/api/v1/repositories"
}

# Upload, then download once so the artifact has a download_statistics row.
# The row is written by a background dispatcher, so wait for it.
seed() { # key -> "" or an error
  local key="$1" c id n
  head -c 20000 /dev/urandom > "$W/${key}.bin"
  c="$(code -u "$AUTH" -T "$W/${key}.bin" "${A}/api/v1/repositories/${key}/artifacts/f/${key}.bin")"
  [[ "$c" == 20? ]] || { echo "PUT ${key} -> ${c} $(body | head -c 200)"; return 1; }
  c="$(code -u "$AUTH" "${A}/api/v1/repositories/${key}/download/f/${key}.bin")"
  [ "$c" = "200" ] || { echo "GET ${key} -> ${c}"; return 1; }
  id="$(psql_q "SELECT a.id FROM artifacts a JOIN repositories r ON r.id = a.repository_id WHERE r.key = '${key}'")"
  [ -n "$id" ] || { echo "no artifact row for ${key}"; return 1; }
  for _ in $(seq 1 30); do
    n="$(psql_q "SELECT count(*) FROM download_statistics WHERE artifact_id = '${id}'")"
    [ "${n:-0}" -ge 1 ] && return 0
    sleep 1
  done
  echo "no download_statistics row for ${key} after 30s"; return 1
}

begin_suite "backup-scoped-restore"
auth_admin

# =============================================================================
# SETUP
# =============================================================================
begin_test "SETUP: repositories IN and OUT each hold a downloaded artifact; a full backup scoped to IN completes"
SETUP_ERR=""
for key in "$IN" "$OUT"; do
  c="$(create_repo "$key")"; [[ "$c" == 20? ]] || SETUP_ERR="${SETUP_ERR} create ${key} -> ${c};"
done
for key in "$IN" "$OUT"; do
  [ -z "$SETUP_ERR" ] && { err="$(seed "$key")" || SETUP_ERR="${SETUP_ERR} ${err};"; }
done
IN_ID="$(psql_q "SELECT id FROM repositories WHERE key = '${IN}'")"
OUT_ID="$(psql_q "SELECT id FROM repositories WHERE key = '${OUT}'")"
IN_ART="$(psql_q "SELECT a.id FROM artifacts a WHERE a.repository_id = '${IN_ID}'")"
OUT_ART="$(psql_q "SELECT a.id FROM artifacts a WHERE a.repository_id = '${OUT_ID}'")"
BID=""
if [ -z "$SETUP_ERR" ]; then
  BID="$(curl -s --max-time 30 -u "$AUTH" -X POST -H 'Content-Type: application/json' \
    -d "{\"backup_type\":\"full\",\"repository_ids\":[\"${IN_ID}\"]}" \
    "${A}/api/v1/admin/backups" | jq -r '.id // empty' 2>/dev/null)"
  [ -n "$BID" ] || SETUP_ERR="${SETUP_ERR} create backup failed;"
fi
if [ -z "$SETUP_ERR" ]; then
  c="$(code -u "$AUTH" -X POST "${A}/api/v1/admin/backups/${BID}/execute")"
  [ "$c" = "200" ] || SETUP_ERR="${SETUP_ERR} execute -> ${c} $(body | head -c 300);"
  st="$(psql_q "SELECT status FROM backups WHERE id = '${BID}'")"
  [ "$st" = "completed" ] || SETUP_ERR="${SETUP_ERR} backup status ${st:-?};"
fi
if [ -z "$SETUP_ERR" ]; then
  path="$(psql_q "SELECT storage_path FROM backups WHERE id = '${BID}'")"
  mkdir -p "$W/arch"
  if docker cp "${CTR}:/data/storage/${path}" "$W/archive.tar.gz" >/dev/null 2>&1 \
     && tar -xzf "$W/archive.tar.gz" -C "$W/arch" 2>/dev/null; then :; else
    SETUP_ERR="${SETUP_ERR} could not read the archive (${path});"
  fi
fi
REPOS_JSON="$(find "$W/arch" -name repositories.json -path '*database*' 2>/dev/null | head -1)"
STATS_JSON="$(find "$W/arch" -name download_statistics.json -path '*database*' 2>/dev/null | head -1)"
[ -z "$SETUP_ERR" ] && { [ -n "$REPOS_JSON" ] && [ -n "$STATS_JSON" ] \
  || SETUP_ERR="${SETUP_ERR} archive lacks database/repositories.json or download_statistics.json;"; }
if [ -z "$SETUP_ERR" ]; then pass; else
  infra_fail "setup could not complete: ${SETUP_ERR}"; end_suite; exit $?
fi

# =============================================================================
# FIX: the archive holds only the scope
# =============================================================================
begin_test "FIX(#5884): the scoped archive holds IN's repository row and only the download of IN's artifact"
got_repos="$(jq -r '.[].key' "$REPOS_JSON" 2>/dev/null | grep -c . )"
has_out="$(jq -r --arg k "$OUT" '[.[] | select(.key == $k)] | length' "$REPOS_JSON" 2>/dev/null)"
has_in="$(jq -r --arg k "$IN" '[.[] | select(.key == $k)] | length' "$REPOS_JSON" 2>/dev/null)"
stats_arts="$(jq -r '[.[].artifact_id] | unique | join(",")' "$STATS_JSON" 2>/dev/null)"
if [ "$got_repos" = "1" ] && [ "$has_in" = "1" ] && [ "$has_out" = "0" ] && [ "$stats_arts" = "$IN_ART" ]; then pass; else
  fail "archive repositories=${got_repos:-?} (IN=${has_in:-?}, OUT=${has_out:-?}; want 1, 1, 0); download_statistics artifacts=[${stats_arts}] (want [${IN_ART}], OUT's is ${OUT_ART}) (pre-#5884: every repository row and every download is archived)"
fi

# =============================================================================
# FIX: the restore brings back IN and nothing else
# =============================================================================
begin_test "FIX(#5884): after OUT and IN are deleted, restoring IN's backup answers completed, brings IN back with its bytes, and leaves OUT deleted"
DEL_ERR=""
for key in "$OUT" "$IN"; do
  delete_repository_and_wait "$A" "$ADMIN_TOKEN" "$key" 120 \
    || DEL_ERR="${DEL_ERR} delete ${key}: ${REPO_DELETE_ERROR:-code ${REPO_DELETE_CODE:-?}};"
done
left="$(psql_q "SELECT count(*) FROM repositories WHERE id IN ('${IN_ID}','${OUT_ID}')")"
[ "$left" = "0" ] || DEL_ERR="${DEL_ERR} ${left} of the two repositories still exist;"
if [ -n "$DEL_ERR" ]; then
  infra_fail "could not delete the repositories: ${DEL_ERR}"
else
  c="$(code -u "$AUTH" -X POST -H 'Content-Type: application/json' -d '{}' \
    "${A}/api/v1/admin/backups/${BID}/restore")"
  cp "$W/last" "$W/restore.json"
  echo "-- restore -> HTTP ${c}: $(head -c 1500 "$W/restore.json")"
  st="$(jq -r '.status // empty' "$W/restore.json" 2>/dev/null)"
  nerr="$(jq -r '.errors | length' "$W/restore.json" 2>/dev/null)"
  in_back="$(psql_q "SELECT count(*) FROM repositories WHERE id = '${IN_ID}'")"
  out_back="$(psql_q "SELECT count(*) FROM repositories WHERE id = '${OUT_ID}'")"
  rm -f "$W/dl"
  dl="$(curl -s -o "$W/dl" -w '%{http_code}' --max-time 60 -u "$AUTH" \
    "${A}/api/v1/repositories/${IN}/download/f/${IN}.bin" 2>/dev/null || echo 000)"
  same="no"; [ -f "$W/dl" ] && [ "$(sha "$W/dl")" = "$(sha "$W/${IN}.bin")" ] && same="yes"
  if [ "$c" = "200" ] && [ "$st" = "completed" ] && [ "$nerr" = "0" ] \
     && [ "$in_back" = "1" ] && [ "$dl" = "200" ] && [ "$same" = "yes" ] && [ "$out_back" = "0" ]; then pass; else
    fail "restore -> HTTP ${c} status=${st:-?} errors=${nerr:-?}; IN back=${in_back:-?} download=${dl} same bytes=${same}; OUT back=${out_back:-?} (want 200 completed 0, 1 200 yes, 0; pre-#5884: OUT comes back as an empty repository)"
  fi
fi

end_suite
