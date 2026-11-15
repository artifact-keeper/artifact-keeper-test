#!/usr/bin/env bash
# =============================================================================
# tiers/backup-restore-s3-faults/oracle.sh
#   #5858 a backup through a slow store opens each artifact only when the
#         archive writer is ready for it, so every object keeps its whole
#         S3_BULK_TIMEOUT_SECS
#   #5857 a restore that stops in its object pass leaves no database rows
#         behind, says so, and can be re-run
# See the manifest for THE BUGS and the gates.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID,
# DTF_SLOT, TRIVY_PORT (the fault proxy's control port,
# profiles/storage.s3-fault-proxy.yml), RELEASE_GATE=1, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"; : "${DB_CONTAINER:?}"
: "${TRIVY_PORT:?}"; : "${ADMIN_PASS:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

# common.sh enables errexit; every probe below guards its own failure so a
# miss records a JUnit case instead of killing the oracle.
set +e

SUF="${RUN_ID##*-}-$$"
BASE="${BASE_URL}"
CTL="http://127.0.0.1:${TRIVY_PORT}"
MINIO_CTR="${DB_CONTAINER%-db}-minio"
BUCKET="ak-artifacts"
AUTH="${ADMIN_USER:-admin}:${ADMIN_PASS}"
SLOW="rsf-slow-${SUF}"
INT="rsf-int-${SUF}"
BPS=$((4 * 1024 * 1024))
BULK_TIMEOUT="${S3_BULK_TIMEOUT_SECS:-10}"

W="$(mktemp -d -t dtf-rsf-XXXXXX)"
trap 'curl -s --max-time 5 "${CTL}/reset" >/dev/null 2>&1; rm -rf "$W"' EXIT

# --- helpers -----------------------------------------------------------------
psql_a() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -Atc "$1" 2>/dev/null || true; }
code() { curl -s -o "$W/last" -w '%{http_code}' --max-time 600 "$@" 2>/dev/null || echo 000; }
body() { cat "$W/last" 2>/dev/null; }
sha() { sha256sum "$1" | cut -d' ' -f1; }
ctl() { curl -s --max-time 10 "${CTL}/$1" 2>/dev/null; }
# mc against MinIO directly (not through the proxy), stdin/stdout passed through.
mc_() {
  docker run --rm -i --network "container:${MINIO_CTR}" --entrypoint sh \
    ghcr.io/artifact-keeper/ci-mirror/mc:RELEASE.2025-08-13T08-35-41Z -c \
    "mc alias set local http://localhost:9000 minioadmin minioadmin >/dev/null 2>&1 && $1"
}

create_repo() {
  code -u "$AUTH" -X POST -H 'Content-Type: application/json' \
    -d "{\"key\":\"$1\",\"name\":\"$1\",\"format\":\"generic\",\"repo_type\":\"local\",\"is_public\":false}" \
    "${BASE}/api/v1/repositories"
}
put_file() { # repo path file -> appends repo|path|sha to $W/expected-<repo>
  local c; c="$(code -u "$AUTH" -T "$W/$3" "${BASE}/api/v1/repositories/$1/artifacts/$2")"
  [[ "$c" == 20? ]] || { echo "PUT $1/$2 -> $c $(body | head -c 200)"; return 1; }
  echo "$1|$2|$(sha "$W/$3")" >> "$W/expected-$1"
}
# Create and run a backup of one repository; prints "id status".
backup_repo() {
  local id st
  id="$(curl -s --max-time 30 -u "$AUTH" -X POST -H 'Content-Type: application/json' \
    -d "{\"backup_type\":\"full\",\"repository_ids\":[\"$1\"]}" "${BASE}/api/v1/admin/backups" \
    | jq -r '.id // empty' 2>/dev/null)"
  [ -n "$id" ] || { echo " none"; return 1; }
  code -u "$AUTH" -X POST "${BASE}/api/v1/admin/backups/${id}/execute" >/dev/null
  cp "$W/last" "$W/execute-${id}.json"
  st="$(psql_a "SELECT status FROM backups WHERE id = '${id}'")"
  echo "${id} ${st}"
}
downloads_match() { # repo -> "ok/total" and the misses in $W/misses
  local ok=0 total=0
  : > "$W/misses"
  while IFS='|' read -r repo path want; do
    total=$((total + 1)); rm -f "$W/dl"
    c="$(curl -s -o "$W/dl" -w '%{http_code}' --max-time 120 -u "$AUTH" \
      "${BASE}/api/v1/repositories/${repo}/download/${path}" 2>/dev/null || echo 000)"
    if [ "$c" = "200" ] && [ "$(sha "$W/dl")" = "$want" ]; then ok=$((ok + 1)); else echo "${path}=${c}" >> "$W/misses"; fi
  done < "$W/expected-$1"
  echo "${ok}/${total}"
}

begin_suite "backup-restore-s3-faults"
auth_admin

begin_test "SETUP: the fault proxy is up and the backend stores objects through it"
SETUP_ERR=""
[ "$(ctl __readyz)" = "ok" ] || SETUP_ERR="fault proxy control port not answering at ${CTL};"
ctl reset >/dev/null
for r in "$SLOW" "$INT"; do
  c="$(create_repo "$r")"; [[ "$c" == 20? ]] || SETUP_ERR="${SETUP_ERR} create ${r} -> ${c};"
done
for i in 1 2 3; do
  head -c $((24 * 1024 * 1024)) /dev/urandom > "$W/slow-$i.bin"
  err="$(put_file "$SLOW" "big/slow-$i.bin" "slow-$i.bin")" || SETUP_ERR="${SETUP_ERR} ${err};"
done
for n in a b c d e f; do
  head -c 65536 /dev/urandom > "$W/int-$n.bin"
  err="$(put_file "$INT" "files/int-$n.bin" "int-$n.bin")" || SETUP_ERR="${SETUP_ERR} ${err};"
done
SLOW_ID="$(psql_a "SELECT id FROM repositories WHERE key = '${SLOW}'")"
INT_ID="$(psql_a "SELECT id FROM repositories WHERE key = '${INT}'")"
gets_seen="$(ctl state | jq -r '.log | length' 2>/dev/null)"
[ -n "$SLOW_ID" ] && [ -n "$INT_ID" ] || SETUP_ERR="${SETUP_ERR} repository ids not found;"
if [ -z "$SETUP_ERR" ]; then pass; else
  infra_fail "setup could not complete: ${SETUP_ERR} (proxy log entries: ${gets_seen:-?})"; end_suite; exit $?
fi

# =============================================================================
# #5858: queued artifact streams and the bulk timeout
# =============================================================================
ctl "throttle?match=/${BUCKET}/&bps=${BPS}" >/dev/null

begin_test "CONTROL: with the store throttled to 4 MiB/s one 24 MiB object downloads intact inside the ${BULK_TIMEOUT} s bulk timeout"
t0="$(date +%s.%N)"
rm -f "$W/dl"
c="$(curl -s -o "$W/dl" -w '%{http_code}' --max-time 120 -u "$AUTH" \
  "${BASE}/api/v1/repositories/${SLOW}/download/big/slow-1.bin" 2>/dev/null || echo 000)"
took="$(echo "$(date +%s.%N) - $t0" | bc)"
echo "-- one object: HTTP ${c} in ${took}s"
if [ "$c" = "200" ] && [ "$(sha "$W/dl")" = "$(sha "$W/slow-1.bin")" ] \
   && [ "$(echo "$took > 3 && $took < $BULK_TIMEOUT" | bc)" = "1" ]; then pass; else
  infra_fail "one throttled object: HTTP ${c} in ${took}s (want 200, the right bytes, 3s < t < ${BULK_TIMEOUT}s); the store is not slow enough or too slow for the gate below to mean anything"
fi

begin_test "FIX(#5858): a backup of three such objects completes, and each object is read with one GET inside its timeout"
# Fresh GET counters for the backup alone.
ctl reset >/dev/null
ctl "throttle?match=/${BUCKET}/&bps=${BPS}" >/dev/null
t0="$(date +%s)"
read -r SLOW_BACKUP SLOW_STATUS < <(backup_repo "$SLOW_ID")
took=$(( $(date +%s) - t0 ))
ctl state > "$W/state-5858.json"
objects="$(jq -r '.throttled | length' "$W/state-5858.json" 2>/dev/null)"
most="$(jq -r '[.throttled[]] | max // 0' "$W/state-5858.json" 2>/dev/null)"
echo "-- backup ${SLOW_BACKUP} -> ${SLOW_STATUS:-?} in ${took}s: $(head -c 400 "$W/execute-${SLOW_BACKUP}.json" 2>/dev/null)"
echo "-- GETs per object: $(jq -c '.throttled' "$W/state-5858.json" 2>/dev/null)"
jq -r '.log[]' "$W/state-5858.json" 2>/dev/null | grep 'throttled GET' | sed 's/^/   /'
# A GET that times out mid-body is retried by object_store with a Range
# request for the rest, so a queued object shows up as a second GET (or, once
# the retries run out, as a failed backup).
if [ "$SLOW_STATUS" = "completed" ] && [ "$objects" = "3" ] && [ "$most" = "1" ]; then pass; else
  fail "backup ${SLOW_BACKUP} ended '${SLOW_STATUS:-?}' after ${took}s ($(psql_a "SELECT left(error_message, 300) FROM backups WHERE id = '${SLOW_BACKUP}'")); ${objects:-?} objects read, at most ${most:-?} GETs for one (want completed, 3 objects, 1 GET each; pre-#5858: a GET opened ahead of the writer times out while it waits in the queue and is retried or fails the backup)"
fi
ctl reset >/dev/null

# =============================================================================
# #5857: a restore that stops in its object pass
# =============================================================================
begin_test "SETUP: a backup of ${INT} completes, then the repository is deleted from the database and its objects from the store"
SETUP_ERR=""
read -r INT_BACKUP INT_STATUS < <(backup_repo "$INT_ID")
[ "$INT_STATUS" = "completed" ] || SETUP_ERR="backup of ${INT} ended '${INT_STATUS:-?}';"
ARCHIVE_KEY="$(psql_a "SELECT storage_path FROM backups WHERE id = '${INT_BACKUP}'")"
mc_ "mc cat local/${BUCKET}/${ARCHIVE_KEY}" > "$W/orig.tar.gz" || SETUP_ERR="${SETUP_ERR} cannot read the archive ${ARCHIVE_KEY};"
# The same archive with the bytes of its last artifact entry flipped: every
# entry the verify pass checked before it is unchanged, so the write pass
# writes those objects and then meets the changed one.
python3 -I - "$W/orig.tar.gz" "$W/tampered.tar.gz" <<'PY' || SETUP_ERR="${SETUP_ERR} cannot build the changed archive;"
import io, sys, tarfile
src, dst = sys.argv[1], sys.argv[2]
with tarfile.open(src, "r:gz") as tin:
    members = [(m, tin.extractfile(m).read() if m.isfile() else None) for m in tin.getmembers()]
last = max(i for i, (m, _) in enumerate(members) if m.name.startswith("artifacts/"))
with tarfile.open(dst, "w:gz", format=tarfile.GNU_FORMAT) as tout:
    for i, (m, data) in enumerate(members):
        if i == last:
            data = bytes(b ^ 0xFF for b in data)
        tout.addfile(m, io.BytesIO(data) if data is not None else None)
PY
psql_a "SELECT storage_key FROM artifacts WHERE repository_id = '${INT_ID}'" > "$W/int-keys"
psql_a "DELETE FROM repositories WHERE id = '${INT_ID}'" >/dev/null
while read -r k; do [ -n "$k" ] && mc_ "mc rm -q local/${BUCKET}/${k}" >/dev/null; done < "$W/int-keys"
left="$(psql_a "SELECT count(*) FROM repositories WHERE key = '${INT}'")"
[ "$left" = "0" ] || SETUP_ERR="${SETUP_ERR} ${INT} still present (${left});"
[ "$(wc -l < "$W/int-keys")" = "6" ] || SETUP_ERR="${SETUP_ERR} $(wc -l < "$W/int-keys") of 6 artifact keys;"
if [ -z "$SETUP_ERR" ]; then pass; else
  infra_fail "setup could not complete: ${SETUP_ERR}"; end_suite; exit $?
fi

begin_test "FIX(#5857): a restore whose archive changes between its verify pass and its write pass fails without restoring a database row, and says so"
ctl "hold?match=${ARCHIVE_KEY##*/}&nth=2" >/dev/null
( curl -s -o "$W/restore-swap.json" -w '%{http_code}' --max-time 600 -u "$AUTH" -X POST \
    -H 'Content-Type: application/json' -d '{}' \
    "${BASE}/api/v1/admin/backups/${INT_BACKUP}/restore" > "$W/restore-swap.code" 2>/dev/null ) &
RESTORE_PID=$!
held=""
for _ in $(seq 1 300); do
  [ "$(ctl state | jq -r '.held' 2>/dev/null)" = "true" ] && { held=1; break; }
  kill -0 "$RESTORE_PID" 2>/dev/null || break
  sleep 0.2
done
if [ -z "$held" ]; then
  ctl release >/dev/null; wait "$RESTORE_PID"
  infra_fail "the restore never reached its second read of the archive (HTTP $(cat "$W/restore-swap.code" 2>/dev/null)): $(head -c 400 "$W/restore-swap.json" 2>/dev/null); proxy: $(ctl state | jq -c '.log[-5:]' 2>/dev/null)"
else
  rows_while_held="$(psql_a "SELECT count(*) FROM repositories WHERE key = '${INT}'")"
  mc_ "mc pipe -q local/${BUCKET}/${ARCHIVE_KEY}" < "$W/tampered.tar.gz" >/dev/null
  ctl release >/dev/null
  wait "$RESTORE_PID"
  c="$(cat "$W/restore-swap.code" 2>/dev/null)"
  msg="$(jq -r '.message // .error // empty' "$W/restore-swap.json" 2>/dev/null)"
  repos="$(psql_a "SELECT count(*) FROM repositories WHERE key = '${INT}'")"
  arts="$(psql_a "SELECT count(*) FROM artifacts WHERE repository_id = '${INT_ID}'")"
  echo "-- swapped restore -> HTTP ${c}: $(head -c 800 "$W/restore-swap.json")"
  echo "-- rows: repositories=${repos} artifacts=${arts} (repositories while held: ${rows_while_held})"
  if [ "$c" != "200" ] && [ "$c" != "000" ] && echo "$msg" | grep -q "changed after it was verified" \
     && echo "$msg" | grep -q "No database rows were restored" && [ "$repos" = "0" ] && [ "$arts" = "0" ]; then
    pass
  else
    fail "HTTP ${c}, repositories=${repos} artifacts=${arts} (want a refusal, 0 and 0), message: ${msg:0:400} (pre-#5857: the tables were committed before the object pass, so the rows are back and the changed object is not)"
  fi
fi
ctl reset >/dev/null
mc_ "mc pipe -q local/${BUCKET}/${ARCHIVE_KEY}" < "$W/orig.tar.gz" >/dev/null

begin_test "CONTROL: re-running the restore from the intact archive answers completed and every artifact downloads with its sha256"
c="$(code -u "$AUTH" -X POST -H 'Content-Type: application/json' -d '{}' \
  "${BASE}/api/v1/admin/backups/${INT_BACKUP}/restore")"
st="$(body | jq -r '.status // empty' 2>/dev/null)"
echo "-- re-run -> HTTP ${c}: $(body | head -c 600)"
got="$(downloads_match "$INT")"
if [ "$c" = "200" ] && [ "$st" = "completed" ] && [ "$got" = "6/6" ]; then pass; else
  fail "re-run -> HTTP ${c} status=${st:-?}; downloads ${got}: $(tr '\n' ' ' < "$W/misses")"
fi

end_suite
