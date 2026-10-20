#!/usr/bin/env bash
# =============================================================================
# tiers/upload-staging-object-store/oracle.sh
#   Uploads into an object-storage repository need no local disk: raw PUT and
#   multipart POST stage on the repository's backend (artifact-keeper#3916,
#   #4404); chunked-session chunks are storage objects, purged on cancel and on
#   a failed completion (#3918, #3922).
# =============================================================================
# run.sh has stood up `storage.s3` (MinIO, bucket ak-artifacts) with
# RATE_LIMIT_ENABLED=false and exported BASE_URL, DB_CONTAINER, ADMIN_USER,
# ADMIN_PASS, RUN_ID, DTF_SLOT, RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
# See the manifest for the bugs and the gates.
#
# Local scratch is looked for under the backend's /data volume (STORAGE_PATH
# is /data/storage): `ak-incus-upload-*` (the pre-fix spool for raw and
# multipart uploads, under .incoming) and anything under `.uploads/` named
# after a session id (the pre-fix chunked-session file).
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on `set -e`; every probe is judged by the assertion that
# reads it, so a failing probe must not end the oracle early.
set +e

SUF="${RUN_ID##*-}-$$"
SLOT="$DTF_SLOT"
BACKEND_CTR="ak-dtf${SLOT}-backend"
MINIO_CTR="ak-dtf${SLOT}-minio"
PROBE_CTR="ak-dtf${SLOT}-usos-probe-$$"
BUCKET="ak-artifacts"
MC_IMAGE="${USOS_MC_IMAGE:-ghcr.io/artifact-keeper/ci-mirror/mc:RELEASE.2025-08-13T08-35-41Z}"
PROBE_IMAGE="${USOS_PROBE_IMAGE:-postgres:16-alpine}"
REPO="usos-${SLOT}-${SUF}"
MIB=1048576
RATE="${USOS_RATE:-256k}"          # 3 MiB at 256 KiB/s: about 12 s in flight

WORK="$(mktemp -d -t dtf-usos-XXXXXX)"
cleanup() { docker rm -f "$PROBE_CTR" >/dev/null 2>&1; rm -rf "$WORK"; }
trap cleanup EXIT

# --- helpers -----------------------------------------------------------------
psqlq() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -qAtc "$1" 2>&1; }
mcx() {
  docker run --rm -i --network "container:${MINIO_CTR}" --entrypoint sh "$MC_IMAGE" -c \
    "mc alias set local http://localhost:9000 minioadmin minioadmin >/dev/null 2>&1 && $1"
}
# Object keys under a bucket prefix, one per line, relative to the bucket.
s3_keys() { mcx "mc find local/${BUCKET}/$1" 2>/dev/null | sed "s#^local/${BUCKET}/##" | grep -v '^$'; }
s3_count() { s3_keys "$1" | grep -c . ; }
# Local scratch files on the backend's /data volume (pre-fix spool shapes).
local_scratch() {
  docker exec "$PROBE_CTR" sh -c \
    "find /data -type f \( -name 'ak-incus-upload-*' -o -path '*/.uploads/*' \) 2>/dev/null" 2>/dev/null
}
local_scratch_count() { local_scratch | grep -c . ; }
code_to_file() { # URL OUTFILE [curl args...]
  local url="$1" out="$2"; shift 2
  local c; c="$(curl -s -o "$out" -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" "$@" "$url" 2>/dev/null)"
  echo "${c:-000}"
}
is_2xx() { case "$1" in 2??) return 0 ;; *) return 1 ;; esac; }
sha_of() { sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }
staging_rows_zero() { [ "$(psqlq "SELECT count(*) FROM generic_upload_staging")" = "0" ]; }
session_purged() { [ "$(psqlq "SELECT 1 FROM upload_sessions WHERE id='$1' AND staging_purged_at IS NOT NULL")" = "1" ]; }
AUTHZ=()

# watch_upload TAG -- run while a background upload (pid in UP_PID) is in
# flight; samples local scratch files and generic_upload_staging rows every
# 0.4 s. Sets W_SAMPLES, W_MAX_LOCAL, W_MAX_ROWS, W_ROWS_ERR, W_LOCAL_SEEN.
watch_upload() {
  W_SAMPLES=0; W_MAX_LOCAL=0; W_MAX_ROWS=0; W_ROWS_ERR=""; W_LOCAL_SEEN=""
  local n r
  while kill -0 "$UP_PID" 2>/dev/null; do
    n="$(local_scratch_count)"
    [ "${n:-0}" -gt "$W_MAX_LOCAL" ] && { W_MAX_LOCAL="$n"; W_LOCAL_SEEN="$(local_scratch | head -3 | tr '\n' ' ')"; }
    r="$(psqlq "SELECT count(*) FROM generic_upload_staging WHERE storage_key LIKE 'generic-upload-staging/%'")"
    if [[ "$r" =~ ^[0-9]+$ ]]; then
      [ "$r" -gt "$W_MAX_ROWS" ] && W_MAX_ROWS="$r"
    else
      W_ROWS_ERR="$(printf '%s' "$r" | head -1 | cut -c1-120)"
    fi
    W_SAMPLES=$((W_SAMPLES + 1))
    sleep 0.4
  done
}

begin_suite "upload-staging-object-store"

# =============================================================================
# SETUP
# =============================================================================
auth_admin
AUTHZ=(-H "Authorization: Bearer ${ADMIN_TOKEN}")
SF=""
c="$(code_to_file "${BASE_URL}/api/v1/repositories" "${WORK}/mk.json" -X POST "${AUTHZ[@]}" \
      -H 'Content-Type: application/json' \
      -d "{\"key\":\"${REPO}\",\"name\":\"${REPO}\",\"format\":\"generic\",\"repo_type\":\"local\",\"is_public\":false}")"
is_2xx "$c" || SF="${SF} create-repo=${c}"
RB="$(psqlq "SELECT storage_backend FROM repositories WHERE key='${REPO}'")"
[ "$RB" = "s3" ] || SF="${SF} repo-backend=${RB}"
docker run -d --name "$PROBE_CTR" --volumes-from "$BACKEND_CTR" --entrypoint sleep "$PROBE_IMAGE" 900 >/dev/null 2>"${WORK}/probe.err" \
  || SF="${SF} probe=$(head -c 120 "${WORK}/probe.err")"
docker exec "$PROBE_CTR" test -d /data || SF="${SF} probe-no-/data"
mcx "mc ls local/${BUCKET}" >/dev/null 2>&1 || SF="${SF} mc"
head -c $((3 * MIB)) /dev/urandom > "${WORK}/raw.bin"
head -c $((3 * MIB)) /dev/urandom > "${WORK}/mp.bin"
head -c $((2 * MIB)) /dev/urandom > "${WORK}/chunked.bin"
head -c "$MIB" /dev/urandom > "${WORK}/one.bin"
if [ -n "$SF" ]; then
  begin_test "setup: S3-backed generic repository, /data probe container, mc"
  infra_fail "setup failed:${SF}" "$(head -c 300 "${WORK}/mk.json" 2>/dev/null)"
  end_suite
fi
BASE_LOCAL="$(local_scratch_count)"

# =============================================================================
# #3916: raw PUT into the S3 repository
# =============================================================================
curl -s -o "${WORK}/raw.put" -w '%{http_code}' --max-time 120 --limit-rate "$RATE" -X PUT "${AUTHZ[@]}" \
  -H 'Content-Type: application/octet-stream' --data-binary "@${WORK}/raw.bin" \
  "${BASE_URL}/api/v1/repositories/${REPO}/artifacts/raw/1.0/raw-${SUF}.bin" > "${WORK}/raw.code" 2>/dev/null &
UP_PID=$!
sleep 1
watch_upload
wait "$UP_PID" 2>/dev/null
RAW_CODE="$(cat "${WORK}/raw.code" 2>/dev/null)"
RAW_SAMPLES="$W_SAMPLES"; RAW_LOCAL="$W_MAX_LOCAL"; RAW_ROWS="$W_MAX_ROWS"; RAW_ERR="$W_ROWS_ERR"; RAW_SEEN="$W_LOCAL_SEEN"

begin_test "CONTROL: a 3 MiB raw PUT into the S3 repository is 201 and downloads byte-exact; its storage_key is an object in MinIO"
dc="$(code_to_file "${BASE_URL}/api/v1/repositories/${REPO}/download/raw/1.0/raw-${SUF}.bin" "${WORK}/raw.out" "${AUTHZ[@]}" -L)"
RAW_KEY="$(psqlq "SELECT storage_key FROM artifacts a JOIN repositories r ON r.id=a.repository_id WHERE r.key='${REPO}' AND a.path='raw/1.0/raw-${SUF}.bin' AND NOT a.is_deleted")"
RAW_OBJ="$(s3_count "${RAW_KEY}")"
if [ "$RAW_CODE" = "201" ] && [ "$dc" = "200" ] && [ "$(sha_of "${WORK}/raw.out")" = "$(sha_of "${WORK}/raw.bin")" ] \
   && [ -n "$RAW_KEY" ] && [ "${RAW_OBJ:-0}" -ge 1 ]; then pass; else
  fail "PUT=${RAW_CODE} download=${dc} sha match=$([ "$(sha_of "${WORK}/raw.out")" = "$(sha_of "${WORK}/raw.bin")" ] && echo yes || echo no) storage_key='${RAW_KEY}' objects at key=${RAW_OBJ}" \
    "$(head -c 300 "${WORK}/raw.put" 2>/dev/null)"
fi

begin_test "#3916: while the raw PUT is in flight no scratch file exists under STORAGE_PATH and a generic_upload_staging row tracks the staging object"
if [ "$RAW_SAMPLES" -ge 5 ] && [ "$RAW_LOCAL" -le "$BASE_LOCAL" ] && [ "$RAW_ROWS" -ge 1 ] && [ -z "$RAW_ERR" ]; then pass; else
  fail "over ${RAW_SAMPLES} in-flight samples: max local scratch files=${RAW_LOCAL} (baseline ${BASE_LOCAL}; seen: ${RAW_SEEN:-none}), max generic_upload_staging rows=${RAW_ROWS}${RAW_ERR:+ (query: ${RAW_ERR})}. Pre-#3916 the body spooled to <STORAGE_PATH>/.incoming/ak-incus-upload-<uuid> whatever the repository's backend"
fi

begin_test "#3916: after the raw PUT the staging row is gone and MinIO's generic-upload-staging/ prefix is empty"
wait_until "generic_upload_staging empty" 10 staging_rows_zero
ROWS_AFTER="$(psqlq "SELECT count(*) FROM generic_upload_staging")"
STG_AFTER="$(s3_count generic-upload-staging)"
if [ "$ROWS_AFTER" = "0" ] && [ "${STG_AFTER:-x}" = "0" ] && [ "$RAW_ROWS" -ge 1 ]; then pass; else
  fail "generic_upload_staging rows after='${ROWS_AFTER:0:120}', objects under generic-upload-staging/=${STG_AFTER}, rows seen in flight=${RAW_ROWS} (want 0, 0, >=1: the stager tracked and then deleted its object)"
fi

# =============================================================================
# #4404: multipart POST into the S3 repository
# =============================================================================
curl -s -o "${WORK}/mp.post" -w '%{http_code}' --max-time 120 --limit-rate "$RATE" -X POST "${AUTHZ[@]}" \
  -F "file=@${WORK}/mp.bin;filename=mp-${SUF}.bin;type=application/octet-stream" -F "path=mp/1.0/mp-${SUF}.bin" \
  "${BASE_URL}/api/v1/repositories/${REPO}/artifacts" > "${WORK}/mp.code" 2>/dev/null &
UP_PID=$!
sleep 1
watch_upload
wait "$UP_PID" 2>/dev/null
MP_CODE="$(cat "${WORK}/mp.code" 2>/dev/null)"
MP_SAMPLES="$W_SAMPLES"; MP_LOCAL="$W_MAX_LOCAL"; MP_ROWS="$W_MAX_ROWS"; MP_ERR="$W_ROWS_ERR"; MP_SEEN="$W_LOCAL_SEEN"

begin_test "CONTROL: a 3 MiB multipart POST (file field, then path field) into the S3 repository is 2xx and downloads byte-exact"
dc="$(code_to_file "${BASE_URL}/api/v1/repositories/${REPO}/download/mp/1.0/mp-${SUF}.bin" "${WORK}/mp.out" "${AUTHZ[@]}" -L)"
if is_2xx "$MP_CODE" && [ "$dc" = "200" ] && [ "$(sha_of "${WORK}/mp.out")" = "$(sha_of "${WORK}/mp.bin")" ]; then pass; else
  fail "POST=${MP_CODE} download=${dc} sha match=$([ "$(sha_of "${WORK}/mp.out")" = "$(sha_of "${WORK}/mp.bin")" ] && echo yes || echo no)" \
    "$(head -c 300 "${WORK}/mp.post" 2>/dev/null)"
fi

begin_test "#4404: while the multipart POST is in flight no scratch file exists under STORAGE_PATH and a generic_upload_staging row tracks the staged file field; both are gone afterwards"
wait_until "generic_upload_staging empty" 10 staging_rows_zero
MP_ROWS_AFTER="$(psqlq "SELECT count(*) FROM generic_upload_staging")"
MP_STG_AFTER="$(s3_count generic-upload-staging)"
if [ "$MP_SAMPLES" -ge 5 ] && [ "$MP_LOCAL" -le "$BASE_LOCAL" ] && [ "$MP_ROWS" -ge 1 ] && [ -z "$MP_ERR" ] \
   && [ "$MP_ROWS_AFTER" = "0" ] && [ "${MP_STG_AFTER:-x}" = "0" ]; then pass; else
  fail "over ${MP_SAMPLES} in-flight samples: max local scratch files=${MP_LOCAL} (baseline ${BASE_LOCAL}; seen: ${MP_SEEN:-none}), max staging rows=${MP_ROWS}${MP_ERR:+ (query: ${MP_ERR})}; after: rows='${MP_ROWS_AFTER:0:120}', generic-upload-staging/ objects=${MP_STG_AFTER}. Pre-#4404 the form file spooled to local scratch"
fi

# =============================================================================
# Chunked sessions (#3918 single-instance staging, #3922 purge)
# =============================================================================
# new_session PATH SIZE SHA -> session id (empty on failure); body in $WORK/sess.json
new_session() {
  local c
  c="$(code_to_file "${BASE_URL}/api/v1/uploads" "${WORK}/sess.json" -X POST "${AUTHZ[@]}" -H 'Content-Type: application/json' \
        -d "{\"repository_key\":\"${REPO}\",\"artifact_path\":\"$1\",\"total_size\":$2,\"chunk_size\":${MIB},\"checksum_sha256\":\"$3\"}")"
  [ "$c" = "201" ] && jq -r '.session_id // .id // empty' "${WORK}/sess.json" 2>/dev/null
}
# patch_chunk SID FILE INDEX TOTAL -> code
patch_chunk() {
  local sid="$1" f="$2" i="$3" total="$4" start end len
  start=$(( i * MIB )); len=$(( total - start < MIB ? total - start : MIB )); end=$(( start + len - 1 ))
  tail -c +$((start + 1)) "$f" | head -c "$len" > "${WORK}/chunk.part"
  code_to_file "${BASE_URL}/api/v1/uploads/${sid}" "${WORK}/patch.json" -X PATCH "${AUTHZ[@]}" \
    -H 'Content-Type: application/octet-stream' -H "Content-Range: bytes ${start}-${end}/${total}" \
    --data-binary "@${WORK}/chunk.part"
}
local_session_files() { local_scratch | grep -c -- "$1"; }

begin_test "CONTROL: a two-chunk session (2 MiB, 1 MiB chunks) completes and the artifact downloads byte-exact"
SID_OK="$(new_session "chunked/1.0/ok-${SUF}.bin" $((2 * MIB)) "$(sha_of "${WORK}/chunked.bin")")"
p0="$(patch_chunk "$SID_OK" "${WORK}/chunked.bin" 0 $((2 * MIB)))"
p1="$(patch_chunk "$SID_OK" "${WORK}/chunked.bin" 1 $((2 * MIB)))"
cc="$(code_to_file "${BASE_URL}/api/v1/uploads/${SID_OK}/complete" "${WORK}/complete-ok.json" -X PUT "${AUTHZ[@]}" -H 'Content-Type: application/json')"
dc="$(code_to_file "${BASE_URL}/api/v1/repositories/${REPO}/download/chunked/1.0/ok-${SUF}.bin" "${WORK}/chunked.out" "${AUTHZ[@]}" -L)"
if [ -n "$SID_OK" ] && is_2xx "$p0" && is_2xx "$p1" && is_2xx "$cc" && [ "$dc" = "200" ] \
   && [ "$(sha_of "${WORK}/chunked.out")" = "$(sha_of "${WORK}/chunked.bin")" ]; then pass; else
  fail "session='${SID_OK}' patch0=${p0} patch1=${p1} complete=${cc} download=${dc} sha match=$([ "$(sha_of "${WORK}/chunked.out")" = "$(sha_of "${WORK}/chunked.bin")" ] && echo yes || echo no)" \
    "$(head -c 300 "${WORK}/complete-ok.json" 2>/dev/null)"
fi

begin_test "#3918/#3922: a PATCHed chunk is the object upload-staging/<session>/00000000 in MinIO (no local session file); cancel deletes it and stamps staging_purged_at"
SID_C="$(new_session "chunked/1.0/cancel-${SUF}.bin" $((2 * MIB)) "$(sha_of "${WORK}/chunked.bin")")"
pc="$(patch_chunk "$SID_C" "${WORK}/chunked.bin" 0 $((2 * MIB)))"
OBJ_BEFORE="$(s3_keys "upload-staging/${SID_C}" | tr '\n' ' ')"
LOC_BEFORE="$(local_session_files "${SID_C:-none}")"
dl="$(code_to_file "${BASE_URL}/api/v1/uploads/${SID_C}" "${WORK}/cancel.json" -X DELETE "${AUTHZ[@]}")"
wait_until "session ${SID_C} purged" 15 session_purged "$SID_C"
PURGED="$(psqlq "SELECT status || '|' || coalesce(staging_purged_at::text,'NULL') FROM upload_sessions WHERE id='${SID_C}'")"
OBJ_AFTER="$(s3_count "upload-staging/${SID_C}")"
LOC_AFTER="$(local_session_files "${SID_C:-none}")"
if [ -n "$SID_C" ] && is_2xx "$pc" && printf '%s' "$OBJ_BEFORE" | grep -q "upload-staging/${SID_C}/00000000" \
   && [ "$LOC_BEFORE" = "0" ] && is_2xx "$dl" && [ "${OBJ_AFTER:-x}" = "0" ] && [ "$LOC_AFTER" = "0" ] \
   && [[ "$PURGED" == cancelled\|2* ]]; then pass; else
  fail "session='${SID_C}' patch=${pc}; before cancel: MinIO objects='${OBJ_BEFORE}' local session files=${LOC_BEFORE}; cancel=${dl}; after: MinIO objects=${OBJ_AFTER} local=${LOC_AFTER} status|staging_purged_at='${PURGED:0:160}'. Pre-#3918 the chunk went to <STORAGE_PATH>/.uploads/<session> on the creating replica and nothing was staged in the repository's backend"
fi

begin_test "#3922: a completion with the wrong checksum is 409 and leaves nothing staged: no .uploads/<session> file, no upload-staging/<session>/ object, staging_purged_at set"
SID_F="$(new_session "chunked/1.0/bad-${SUF}.bin" "$MIB" "0000000000000000000000000000000000000000000000000000000000000000")"
pf="$(patch_chunk "$SID_F" "${WORK}/one.bin" 0 "$MIB")"
cf="$(code_to_file "${BASE_URL}/api/v1/uploads/${SID_F}/complete" "${WORK}/complete-bad.json" -X PUT "${AUTHZ[@]}" -H 'Content-Type: application/json')"
wait_until "session ${SID_F} purged" 15 session_purged "$SID_F"
F_STATE="$(psqlq "SELECT status || '|' || coalesce(staging_purged_at::text,'NULL') FROM upload_sessions WHERE id='${SID_F}'")"
F_OBJ="$(s3_count "upload-staging/${SID_F}")"
F_LOC="$(local_scratch | grep -- "${SID_F:-none}" | head -2 | tr '\n' ' ')"
if [ -n "$SID_F" ] && is_2xx "$pf" && [ "$cf" = "409" ] && [ "${F_OBJ:-x}" = "0" ] && [ -z "$F_LOC" ] \
   && [[ "$F_STATE" == failed\|2* ]]; then pass; else
  fail "session='${SID_F}' patch=${pf} complete=${cf} (want 409); after: local files='${F_LOC}' MinIO upload-staging/<session> objects=${F_OBJ} status|staging_purged_at='${F_STATE:0:160}'. Pre-#3922 the assembled session file stayed under <STORAGE_PATH>/.uploads/<session> with nothing to reclaim it" \
    "$(head -c 300 "${WORK}/complete-bad.json" 2>/dev/null)"
fi

begin_test "CONTROL: after every upload above, the backend's /data volume holds no scratch upload file"
LEFT="$(local_scratch | grep -v -- "${SID_F:-none}" | head -3 | tr '\n' ' ')"
if [ -z "$LEFT" ]; then pass; else
  fail "scratch files left on /data: ${LEFT}"
fi

end_suite
