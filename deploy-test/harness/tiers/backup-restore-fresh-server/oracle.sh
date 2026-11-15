#!/usr/bin/env bash
# =============================================================================
# tiers/backup-restore-fresh-server/oracle.sh
#   #5856 a full backup restored into a fresh server brings back every
#         repository, artifact and webhook, and a restore that cannot insert
#         every row reports `partial`, never `completed`
# See the manifest for THE BUG, how the archive reaches B, and the gates.
#
# run.sh exported BASE_URL (instance A), DB_CONTAINER (A's postgres),
# ADMIN_USER, ADMIN_PASS, RUN_ID, DTF_SLOT, TRIVY_PORT (instance B's published
# HTTP port, profiles/peer.second-instance.yml), RELEASE_GATE=1, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"; : "${DB_CONTAINER:?}"
: "${TRIVY_PORT:?}"; : "${ADMIN_PASS:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

# common.sh enables errexit; every probe below guards its own failure so a
# miss records a JUnit case instead of killing the oracle.
set +e

SLOT="${DTF_SLOT}"
SUF="${RUN_ID##*-}-$$"
A="${BASE_URL}"
B="http://127.0.0.1:${TRIVY_PORT}"
A_DB="${DB_CONTAINER}"
B_DB="ak-dtf${SLOT}-peer-db"
A_CTR="ak-dtf${SLOT}-backend"
B_CTR="ak-dtf${SLOT}-peer-backend"
AUTH="${ADMIN_USER:-admin}:${ADMIN_PASS}"

GEN_A="rfs-gen-a-${SUF}"
GEN_B="rfs-gen-b-${SUF}"
MVN="rfs-mvn-${SUF}"
CONFLICT="rfs-conflict-${SUF}"
USER_NAME="rfs-user-${SUF}"
GROUP_NAME="rfs-group-${SUF}"
HOOK_GLOBAL="rfs-hook-global-${SUF}"
HOOK_REPO="rfs-hook-repo-${SUF}"

W="$(mktemp -d -t dtf-rfs-XXXXXX)"
trap 'rm -rf "$W"' EXIT

# --- helpers -----------------------------------------------------------------
psql_a() { docker exec "$A_DB" psql -U registry -d artifact_registry -Atc "$1" 2>/dev/null || true; }
psql_b() { docker exec "$B_DB" psql -U registry -d artifact_registry -Atc "$1" 2>/dev/null || true; }

# HTTP code of a request; body -> $W/last.
code() { curl -s -o "$W/last" -w '%{http_code}' --max-time 300 "$@" 2>/dev/null || echo 000; }
body() { cat "$W/last" 2>/dev/null; }
sha() { sha256sum "$1" | cut -d' ' -f1; }

create_repo_on() { # base key format -> http code
  code -u "$AUTH" -X POST -H 'Content-Type: application/json' \
    -d "{\"key\":\"$2\",\"name\":\"$2\",\"format\":\"$3\",\"repo_type\":\"local\",\"is_public\":false}" \
    "$1/api/v1/repositories"
}

# Random content per run, so a byte match proves the restore carried it.
make_file() { head -c "$2" /dev/urandom > "$W/$1"; }

# key|path|sha256 of every artifact the oracle put on A.
: > "$W/expected"
put_generic() { # repo path file
  local c; c="$(code -u "$AUTH" -T "$W/$3" "${A}/api/v1/repositories/$1/artifacts/$2")"
  [[ "$c" == 20? ]] || { echo "PUT $1/$2 -> $c $(body | head -c 200)"; return 1; }
  echo "$1|$2|$(sha "$W/$3")" >> "$W/expected"
}
put_maven() { # repo path file
  local c; c="$(code -u "$AUTH" -T "$W/$3" "${A}/maven/$1/$2")"
  [[ "$c" == 20? ]] || { echo "PUT maven $1/$2 -> $c $(body | head -c 200)"; return 1; }
  echo "$1|maven:$2|$(sha "$W/$3")" >> "$W/expected"
}

backup_on_a() { # json body -> backup id, or empty
  local id
  id="$(curl -s --max-time 30 -u "$AUTH" -X POST -H 'Content-Type: application/json' \
    -d "$1" "${A}/api/v1/admin/backups" | jq -r '.id // empty' 2>/dev/null)"
  [ -n "$id" ] || return 1
  local c; c="$(code -u "$AUTH" -X POST "${A}/api/v1/admin/backups/${id}/execute")"
  [ "$c" = "200" ] || { echo "execute -> $c $(body | head -c 300)" >&2; return 1; }
  [ "$(psql_a "SELECT status FROM backups WHERE id = '${id}'")" = "completed" ] || return 1
  echo "$id"
}

# Move backup $1 from A to B: its row (created_by cleared, B has no such
# user) and its archive file under the same storage path.
move_backup_to_b() {
  local id="$1" path
  path="$(psql_a "SELECT storage_path FROM backups WHERE id = '${id}'")"
  [ -n "$path" ] || { echo "no storage_path for ${id}"; return 1; }
  docker exec "$A_DB" psql -U registry -d artifact_registry -Atc \
    "COPY (SELECT id, backup_type, status, storage_path, size_bytes, artifact_count, started_at,
                  completed_at, error_message, metadata, NULL::uuid AS created_by, created_at,
                  payload_checksum
             FROM backups WHERE id = '${id}') TO STDOUT" > "$W/backup-${id}.row" \
    || { echo "export backups row failed"; return 1; }
  docker exec -i "$B_DB" psql -U registry -d artifact_registry -qc \
    "COPY backups (id, backup_type, status, storage_path, size_bytes, artifact_count, started_at,
                   completed_at, error_message, metadata, created_by, created_at, payload_checksum)
     FROM STDIN" < "$W/backup-${id}.row" || { echo "import backups row failed"; return 1; }
  rm -rf "$W/arch" && mkdir -p "$W/arch"
  docker cp "${A_CTR}:/data/storage/${path}" "$W/arch/archive.tar.gz" \
    || { echo "copy archive out of A failed (${path})"; return 1; }
  docker exec "$B_CTR" mkdir -p "/data/storage/$(dirname "$path")" \
    || { echo "mkdir on B failed"; return 1; }
  docker cp "$W/arch/archive.tar.gz" "${B_CTR}:/data/storage/${path}" \
    || { echo "copy archive into B failed"; return 1; }
}

restore_on_b() { # id -> http code, body in $W/last
  code -u "$AUTH" -X POST -H 'Content-Type: application/json' -d '{}' \
    "${B}/api/v1/admin/backups/$1/restore"
}

begin_suite "backup-restore-fresh-server"
auth_admin

# =============================================================================
# SETUP: populate A, back it up, hand the archive to B
# =============================================================================
begin_test "SETUP: A holds generic and maven repositories with artifacts, a user, a group and two webhooks; a full backup of A completes"
SETUP_ERR=""
curl -sf --max-time 10 "${B}/health" >/dev/null 2>&1 || SETUP_ERR="instance B not healthy at ${B};"
for spec in "${GEN_A}:generic" "${GEN_B}:generic" "${MVN}:maven"; do
  c="$(create_repo_on "$A" "${spec%%:*}" "${spec##*:}")"
  [[ "$c" == 20? ]] || SETUP_ERR="${SETUP_ERR} create ${spec} on A -> ${c};"
done
make_file big.bin 3145728; make_file mid.bin 262144
for i in 1 2 3 4 5; do make_file "small-$i.bin" $((1000 + i * 37)); done
make_file lib.jar 40960
printf '<project><modelVersion>4.0.0</modelVersion><groupId>dtf.rfs</groupId><artifactId>lib</artifactId><version>1.0.%s</version></project>\n' "$$" > "$W/lib.pom"
err="$(put_generic "$GEN_A" "big/big.bin" big.bin)" || SETUP_ERR="${SETUP_ERR} ${err};"
err="$(put_generic "$GEN_A" "mid/mid.bin" mid.bin)" || SETUP_ERR="${SETUP_ERR} ${err};"
for i in 1 2 3 4 5; do
  err="$(put_generic "$GEN_A" "small/small-$i.bin" "small-$i.bin")" || SETUP_ERR="${SETUP_ERR} ${err};"
done
# The same bytes in a second repository (content-addressed, shared key).
err="$(put_generic "$GEN_B" "copies/mid.bin" mid.bin)" || SETUP_ERR="${SETUP_ERR} ${err};"
err="$(put_generic "$GEN_B" "copies/small-1.bin" small-1.bin)" || SETUP_ERR="${SETUP_ERR} ${err};"
err="$(put_maven "$MVN" "dtf/rfs/lib/1.0.$$/lib-1.0.$$.jar" lib.jar)" || SETUP_ERR="${SETUP_ERR} ${err};"
err="$(put_maven "$MVN" "dtf/rfs/lib/1.0.$$/lib-1.0.$$.pom" lib.pom)" || SETUP_ERR="${SETUP_ERR} ${err};"

USER_PW="Rfs-$(head -c 9 /dev/urandom | base64 | tr -d '/+=')-9a"
c="$(code -u "$AUTH" -X POST -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg u "$USER_NAME" --arg p "$USER_PW" '{username:$u,email:($u+"@example.test"),password:$p,display_name:$u}')" \
  "${A}/api/v1/users")"
[[ "$c" == 20? ]] || SETUP_ERR="${SETUP_ERR} create user -> ${c} $(body | head -c 160);"
USER_ID="$(psql_a "SELECT id FROM users WHERE username = '${USER_NAME}'")"
GROUP_ID="$(curl -s --max-time 30 -u "$AUTH" -X POST -H 'Content-Type: application/json' \
  -d "{\"name\":\"${GROUP_NAME}\",\"description\":\"dtf restore\"}" "${A}/api/v1/groups" | jq -r '.id // empty' 2>/dev/null)"
[ -n "$GROUP_ID" ] || SETUP_ERR="${SETUP_ERR} create group failed;"
c="$(code -u "$AUTH" -X POST -H 'Content-Type: application/json' -d "{\"user_ids\":[\"${USER_ID}\"]}" \
  "${A}/api/v1/groups/${GROUP_ID}/members")"
[[ "$c" == 20? ]] || SETUP_ERR="${SETUP_ERR} add group member -> ${c};"
GEN_A_ID="$(psql_a "SELECT id FROM repositories WHERE key = '${GEN_A}'")"
c="$(code -u "$AUTH" -X POST -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg n "$HOOK_GLOBAL" '{name:$n,url:"https://hooks.example.com/rfs-global",events:["artifact_uploaded"]}')" \
  "${A}/api/v1/webhooks")"
[[ "$c" == 20? ]] || SETUP_ERR="${SETUP_ERR} create global webhook -> ${c} $(body | head -c 160);"
c="$(code -u "$AUTH" -X POST -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg n "$HOOK_REPO" --arg r "$GEN_A_ID" '{name:$n,url:"https://hooks.example.com/rfs-repo",events:["artifact_uploaded","artifact_deleted"],repository_id:$r}')" \
  "${A}/api/v1/webhooks")"
[[ "$c" == 20? ]] || SETUP_ERR="${SETUP_ERR} create repo webhook -> ${c} $(body | head -c 160);"

# What B must end up with, read from A's own database.
psql_a "SELECT key || '|' || format FROM repositories WHERE key IN ('${GEN_A}','${GEN_B}','${MVN}') ORDER BY 1" > "$W/repos.expected"
psql_a "SELECT w.name || '|' || w.url || '|' || array_to_string(w.events, ',') || '|' || coalesce(r.key, '-')
          FROM webhooks w LEFT JOIN repositories r ON r.id = w.repository_id
         WHERE w.name IN ('${HOOK_GLOBAL}','${HOOK_REPO}') ORDER BY 1" > "$W/hooks.expected"
[ "$(wc -l < "$W/repos.expected")" = "3" ] || SETUP_ERR="${SETUP_ERR} A has $(wc -l < "$W/repos.expected") of 3 repositories;"
[ "$(wc -l < "$W/hooks.expected")" = "2" ] || SETUP_ERR="${SETUP_ERR} A has $(wc -l < "$W/hooks.expected") of 2 webhooks;"
[ "$(wc -l < "$W/expected")" = "11" ] || SETUP_ERR="${SETUP_ERR} $(wc -l < "$W/expected") of 11 artifacts uploaded;"

FULL_ID=""
if [ -z "$SETUP_ERR" ]; then
  FULL_ID="$(backup_on_a '{"backup_type":"full"}')" || SETUP_ERR="${SETUP_ERR} full backup of A did not complete;"
fi
if [ -z "$SETUP_ERR" ]; then
  err="$(move_backup_to_b "$FULL_ID")" || SETUP_ERR="${SETUP_ERR} ${err};"
fi
B_REPOS_BEFORE="$(psql_b "SELECT count(*) FROM repositories WHERE key LIKE 'rfs-%'")"
[ "$B_REPOS_BEFORE" = "0" ] || SETUP_ERR="${SETUP_ERR} B is not fresh (${B_REPOS_BEFORE} rfs repositories);"
if [ -z "$SETUP_ERR" ]; then pass; else
  infra_fail "setup could not complete: ${SETUP_ERR}"; end_suite; exit $?
fi

# =============================================================================
# FIX: everything comes back on the fresh server
# =============================================================================
begin_test "FIX(#5856): restoring A's full backup into fresh server B answers 200 completed with no errors"
c="$(restore_on_b "$FULL_ID")"
cp "$W/last" "$W/restore-full.json"
st="$(jq -r '.status // empty' "$W/restore-full.json" 2>/dev/null)"
nerr="$(jq -r '.errors | length' "$W/restore-full.json" 2>/dev/null)"
echo "-- restore -> HTTP ${c}: $(head -c 1500 "$W/restore-full.json")"
if [ "$c" = "200" ] && [ "$st" = "completed" ] && [ "$nerr" = "0" ]; then pass; else
  fail "restore -> HTTP ${c} status=${st:-?} errors=${nerr:-?}: $(jq -c '.errors' "$W/restore-full.json" 2>/dev/null | head -c 600)"
fi

begin_test "FIX(#5856): every repository of A exists on B with its format"
psql_b "SELECT key || '|' || format FROM repositories WHERE key IN ('${GEN_A}','${GEN_B}','${MVN}') ORDER BY 1" > "$W/repos.got"
if diff -q "$W/repos.expected" "$W/repos.got" >/dev/null; then pass; else
  fail "B has [$(tr '\n' ' ' < "$W/repos.got")], want [$(tr '\n' ' ' < "$W/repos.expected")] (pre-#5856: the rows fail their created_by foreign key)"
fi

begin_test "FIX(#5856): every artifact of A downloads from B with A's sha256"
ok=0; bad=""
while IFS='|' read -r repo path want; do
  case "$path" in
    maven:*) url="${B}/maven/${repo}/${path#maven:}" ;;
    *) url="${B}/api/v1/repositories/${repo}/download/${path}" ;;
  esac
  rm -f "$W/dl"
  c="$(curl -s -o "$W/dl" -w '%{http_code}' --max-time 120 -u "$AUTH" "$url" 2>/dev/null || echo 000)"
  got="$( [ -f "$W/dl" ] && sha "$W/dl" )"
  if [ "$c" = "200" ] && [ "$got" = "$want" ]; then ok=$((ok + 1)); else bad="${bad} ${repo}/${path}=${c}"; fi
done < "$W/expected"
total="$(wc -l < "$W/expected")"
if [ "$ok" = "$total" ]; then pass; else
  fail "${ok}/${total} artifacts match; missing or wrong:${bad}"
fi

begin_test "FIX(#5856): both webhooks of A exist on B with their url, events and repository"
psql_b "SELECT w.name || '|' || w.url || '|' || array_to_string(w.events, ',') || '|' || coalesce(r.key, '-')
          FROM webhooks w LEFT JOIN repositories r ON r.id = w.repository_id
         WHERE w.name IN ('${HOOK_GLOBAL}','${HOOK_REPO}') ORDER BY 1" > "$W/hooks.got"
if diff -q "$W/hooks.expected" "$W/hooks.got" >/dev/null; then pass; else
  fail "B has [$(tr '\n' ' ' < "$W/hooks.got")], want [$(tr '\n' ' ' < "$W/hooks.expected")]"
fi

begin_test "FIX(#5856): the archived user and its group membership exist on B, and B's own admin owns the archived admin's repositories"
member="$(psql_b "SELECT count(*) FROM user_group_members m JOIN users u ON u.id = m.user_id
                    JOIN groups g ON g.id = m.group_id
                   WHERE u.username = '${USER_NAME}' AND g.name = '${GROUP_NAME}'")"
owner="$(psql_b "SELECT u.username FROM repositories r JOIN users u ON u.id = r.created_by WHERE r.key = '${GEN_A}'")"
if [ "$member" = "1" ] && [ "$owner" = "${ADMIN_USER:-admin}" ]; then pass; else
  fail "membership rows=${member:-?} (want 1); ${GEN_A} created_by=${owner:-<none>} (want B's ${ADMIN_USER:-admin})"
fi

# =============================================================================
# FIX: a restore that cannot insert every row is never `completed`
# =============================================================================
begin_test "FIX(#5856): a restore whose artifact rows cannot be inserted reports partial (or fails), never completed"
SCOPED_ERR=""
c="$(create_repo_on "$A" "$CONFLICT" generic)"; [[ "$c" == 20? ]] || SCOPED_ERR="create ${CONFLICT} on A -> ${c};"
make_file conflict-1.bin 4096; make_file conflict-2.bin 8192
for i in 1 2; do
  c="$(code -u "$AUTH" -T "$W/conflict-$i.bin" "${A}/api/v1/repositories/${CONFLICT}/artifacts/c/conflict-$i.bin")"
  [[ "$c" == 20? ]] || SCOPED_ERR="${SCOPED_ERR} PUT conflict-$i -> ${c};"
done
CONFLICT_ID="$(psql_a "SELECT id FROM repositories WHERE key = '${CONFLICT}'")"
SCOPED_ID=""
[ -z "$SCOPED_ERR" ] && { SCOPED_ID="$(backup_on_a "{\"backup_type\":\"full\",\"repository_ids\":[\"${CONFLICT_ID}\"]}")" \
  || SCOPED_ERR="${SCOPED_ERR} scoped backup did not complete;"; }
[ -z "$SCOPED_ERR" ] && { err="$(move_backup_to_b "$SCOPED_ID")" || SCOPED_ERR="${SCOPED_ERR} ${err};"; }
# B already has a repository under that key, with an id of its own.
c="$(create_repo_on "$B" "$CONFLICT" generic)"; [[ "$c" == 20? ]] || SCOPED_ERR="${SCOPED_ERR} create ${CONFLICT} on B -> ${c};"
if [ -n "$SCOPED_ERR" ]; then
  infra_fail "forced-failure setup could not complete: ${SCOPED_ERR}"
else
  c="$(restore_on_b "$SCOPED_ID")"
  st="$(body | jq -r '.status // empty' 2>/dev/null)"
  echo "-- scoped restore -> HTTP ${c}: $(body | head -c 1500)"
  names_rows="$(body | jq -r '.errors[]?' 2>/dev/null | grep -c "into 'artifacts'")"
  if [ "$c" = "200" ] && [ "$st" = "partial" ] && [ "${names_rows:-0}" -ge 1 ]; then pass
  elif [ "$c" != "200" ] && [ "$c" != "000" ]; then pass
  else
    fail "restore -> HTTP ${c} status=${st:-?}, errors naming the artifacts rows: ${names_rows:-0} (pre-#5856: 200 completed with errors [], the rows silently dropped)"
  fi
fi

end_suite
