#!/usr/bin/env bash
# =============================================================================
# tiers/oci-blob-journal-per-repo/oracle.sh
#   Per-repository OCI upload cleanup journal (artifact-keeper#3851): a valid
#   push is not refused because another repository cleared a shared journal
#   row, and a repository delete on S3 does not remove a blob another
#   repository committed.
# =============================================================================
# run.sh has stood up `storage.s3` (MinIO) with RATE_LIMIT_ENABLED=false and
# exported BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH. See the manifest for the bug and
# how the race windows are opened (docker pause of MinIO, a backend restart).
# The EXIT trap always unpauses MinIO.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# shellcheck source=../../lib/repo_delete.sh
source "${DTF_DIR:?}/harness/lib/repo_delete.sh"
# common.sh turns on `set -e`; every probe is judged by the assertion that
# reads it.
set +e

SUF="${RUN_ID##*-}-$$"
SLOT="$DTF_SLOT"
BACKEND_CTR="ak-dtf${SLOT}-backend"
MINIO_CTR="ak-dtf${SLOT}-minio"
BUCKET="ak-artifacts"
MC_IMAGE="${OBJ_MC_IMAGE:-ghcr.io/artifact-keeper/ci-mirror/mc:RELEASE.2025-08-13T08-35-41Z}"
IMG="app"

RB="objb-${SLOT}-${SUF}"      # S3 repository B (the push that must survive)
RA_FS="objafs-${SLOT}-${SUF}" # filesystem repository A, scenario (a)
RA_S3="objas3-${SLOT}-${SUF}" # S3 repository A, scenario (b)

WORK="$(mktemp -d -t dtf-obj-XXXXXX)"
cleanup() { docker unpause "$MINIO_CTR" >/dev/null 2>&1; rm -rf "$WORK"; }
trap cleanup EXIT

psqlq() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -qAtc "$1" 2>&1; }
mcx() {
  docker run --rm -i --network "container:${MINIO_CTR}" --entrypoint sh "$MC_IMAGE" -c \
    "mc alias set local http://localhost:9000 minioadmin minioadmin >/dev/null 2>&1 && $1"
}
s3_has() { mcx "mc stat local/${BUCKET}/$1" >/dev/null 2>&1; }
code_to_file() { # URL OUTFILE [curl args...]
  local url="$1" out="$2"; shift 2
  local c; c="$(curl -s -o "$out" -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" "$@" "$url" 2>/dev/null)"
  echo "${c:-000}"
}
is_2xx() { case "$1" in 2??) return 0 ;; *) return 1 ;; esac; }
AUTHZ=()
relogin() { auth_admin >/dev/null 2>&1; AUTHZ=(-H "Authorization: Bearer ${ADMIN_TOKEN}"); }
mk_repo() { # KEY [extra-json] -> code
  local extra="${2:-}"
  code_to_file "${BASE_URL}/api/v1/repositories" "${WORK}/mk-$1.json" -X POST "${AUTHZ[@]}" -H 'Content-Type: application/json' \
    -d "{\"key\":\"$1\",\"name\":\"$1\",\"format\":\"docker\",\"repo_type\":\"local\",\"is_public\":false${extra}}"
}
push_mono() { # REPO FILE DIGEST -> code
  code_to_file "${BASE_URL}/v2/$1/${IMG}/blobs/uploads/?digest=$3" "${WORK}/push.body" -X POST "${AUTHZ[@]}" \
    -H 'Content-Type: application/octet-stream' --data-binary "@$2"
}
# open_session REPO FILE -> upload URL with one PATCHed part (empty on failure)
open_session() {
  local loc c
  loc="$(curl -s -D - -o /dev/null "${CURL_TIMEOUT_ARGS[@]}" "${AUTHZ[@]}" -X POST "${BASE_URL}/v2/$1/${IMG}/blobs/uploads/" \
    | grep -i '^location:' | head -1 | cut -d' ' -f2 | tr -d '\r')"
  [ -n "$loc" ] || return 0
  case "$loc" in http*) ;; *) loc="${BASE_URL}${loc}" ;; esac
  c="$(code_to_file "$loc" /dev/null -X PATCH "${AUTHZ[@]}" -H 'Content-Type: application/octet-stream' --data-binary "@$2")"
  [ "$c" = "202" ] && echo "$loc"
}
blob_get_exact() { # REPO DIGEST FILE -> "code exact|differs"
  local c; c="$(code_to_file "${BASE_URL}/v2/$1/${IMG}/blobs/$2" "${WORK}/get.out" "${AUTHZ[@]}" -L)"
  if cmp -s "${WORK}/get.out" "$3"; then echo "$c exact"; else echo "$c differs"; fi
}
journal_owner() { # DIGEST -> "repo_key" lines owning a journal row for oci-blobs/<digest>
  psqlq "SELECT r.key FROM oci_upload_cleanup_keys c JOIN repositories r ON r.id = c.repository_id WHERE c.storage_key = 'oci-blobs/$1' ORDER BY 1"
}
wait_healthy() { local _i; for _i in $(seq 1 60); do curl -sf --max-time 3 "${BASE_URL}/health" >/dev/null 2>&1 && return 0; sleep 2; done; return 1; }

begin_suite "oci-blob-journal-per-repo"

# =============================================================================
# SETUP
# =============================================================================
relogin
SF=""
c="$(mk_repo "$RB")"; is_2xx "$c" || SF="${SF} B=${c}"
c="$(mk_repo "$RA_FS" ',"storage_backend":"filesystem"')"; is_2xx "$c" || SF="${SF} A-fs=${c}"
c="$(mk_repo "$RA_S3")"; is_2xx "$c" || SF="${SF} A-s3=${c}"
BK="$(psqlq "SELECT string_agg(key || '=' || storage_backend, ' ' ORDER BY key) FROM repositories WHERE key IN ('${RB}','${RA_FS}','${RA_S3}')")"
[ "$BK" = "${RA_FS}=filesystem ${RA_S3}=s3 ${RB}=s3" ] || SF="${SF} backends='${BK}'"
mcx "mc ls local/${BUCKET}" >/dev/null 2>&1 || SF="${SF} mc"
if [ -n "$SF" ]; then
  begin_test "setup: docker repositories (B on s3, A pinned to filesystem, A' on s3) and mc"
  infra_fail "setup failed:${SF}" "$(head -c 300 "${WORK}/mk-${RA_FS}.json" 2>/dev/null)"
  end_suite
fi
for f in ctl x y; do head -c 1048576 /dev/urandom > "${WORK}/${f}.bin"; done
DCTL="sha256:$(sha256sum "${WORK}/ctl.bin" | cut -d' ' -f1)"
DX="sha256:$(sha256sum "${WORK}/x.bin" | cut -d' ' -f1)"
DY="sha256:$(sha256sum "${WORK}/y.bin" | cut -d' ' -f1)"

# =============================================================================
# CONTROLS
# =============================================================================
begin_test "CONTROL: a monolithic blob push to the S3 repository is 201, lands at oci-blobs/<digest> in MinIO and pulls byte-exact"
c="$(push_mono "$RB" "${WORK}/ctl.bin" "$DCTL")"
g="$(blob_get_exact "$RB" "$DCTL" "${WORK}/ctl.bin")"
if [ "$c" = "201" ] && [ "$g" = "200 exact" ] && s3_has "oci-blobs/${DCTL}"; then pass; else
  fail "push=${c} get='${g}' object in MinIO=$(s3_has "oci-blobs/${DCTL}" && echo yes || echo no)" "$(head -c 300 "${WORK}/push.body" 2>/dev/null)"
fi

# =============================================================================
# (a) B completes while A (another repository) pushes the digest and is deleted
# =============================================================================
LOC_B="$(open_session "$RB" "${WORK}/x.bin")"
SEP='?'; case "$LOC_B" in *\?*) SEP='&' ;; esac
docker pause "$MINIO_CTR" >/dev/null 2>&1
curl -s -o "${WORK}/b-final.body" -w '%{http_code}' --max-time 120 "${AUTHZ[@]}" -X PUT -H 'Content-Length: 0' \
  "${LOC_B}${SEP}digest=${DX}" > "${WORK}/b-final.code" 2>/dev/null &
BPID=$!
sleep 2
A_PUSH="$(push_mono "$RA_FS" "${WORK}/x.bin" "$DX")"
OWNERS_MID="$(journal_owner "$DX" | tr '\n' ' ')"
A_DEL="$(code_to_file "${BASE_URL}/api/v1/repositories/${RA_FS}" "${WORK}/del-a.json" -X DELETE "${AUTHZ[@]}")"
sleep 1
docker unpause "$MINIO_CTR" >/dev/null 2>&1
wait "$BPID" 2>/dev/null
B_FINAL="$(cat "${WORK}/b-final.code" 2>/dev/null)"
# 1.12.0 answers the delete 202 and removes A in a job (#4311): let it finish
# before (b) so the two scenarios do not overlap. A no-op on a 1.11.x 200.
A_DEL_WAIT=ok
repo_delete_wait "$BASE_URL" "$ADMIN_TOKEN" "$A_DEL" "${WORK}/del-a.json" || A_DEL_WAIT="$REPO_DELETE_ERROR"

begin_test "CONTROL: while B's completion is in flight, the filesystem repository A accepts a push of the same digest and is deleted (both 2xx)"
if [ -n "$LOC_B" ] && [ "$A_PUSH" = "201" ] && is_2xx "$A_DEL" && [ "$A_DEL_WAIT" = "ok" ]; then pass; else
  fail "B session='${LOC_B}' A push=${A_PUSH} A delete=${A_DEL} (${A_DEL_WAIT})" "$(head -c 300 "${WORK}/push.body" 2>/dev/null)"
fi

begin_test "#3851: B's journal row for oci-blobs/<digest> survives A's commit of the same digest (rows are per repository)"
if [ "$OWNERS_MID" = "${RB} " ]; then pass; else
  fail "journal rows for oci-blobs/${DX} after A's commit: owners='${OWNERS_MID}' (want exactly ${RB}). Pre-#3851 one row was shared database-wide and A's commit deleted it"
fi

begin_test "#3851: B's completion is 201 (not 503 BLOB_UPLOAD_INVALID) and the blob pulls byte-exact from B"
G="$(blob_get_exact "$RB" "$DX" "${WORK}/x.bin")"
if [ "$B_FINAL" = "201" ] && [ "$G" = "200 exact" ]; then pass; else
  fail "B final PUT=${B_FINAL} body='$(head -c 200 "${WORK}/b-final.body" 2>/dev/null)' blob GET='${G}'. Pre-#3851 the claim found the shared row gone and no peer oci_blobs row (A was deleted) and refused a valid push"
fi

# =============================================================================
# (b) deleting A on S3 with an abandoned journaled completion of a digest B holds
# =============================================================================
c="$(push_mono "$RB" "${WORK}/y.bin" "$DY")"
B_PUSH_Y="$c"
LOC_A="$(open_session "$RA_S3" "${WORK}/y.bin")"
SEP='?'; case "$LOC_A" in *\?*) SEP='&' ;; esac
docker pause "$MINIO_CTR" >/dev/null 2>&1
curl -s -o /dev/null --max-time 60 "${AUTHZ[@]}" -X PUT -H 'Content-Length: 0' "${LOC_A}${SEP}digest=${DY}" >/dev/null 2>&1 &
APID=$!
sleep 2
OWNERS_A="$(journal_owner "$DY" | tr '\n' ' ')"
docker restart -t 2 "$BACKEND_CTR" >/dev/null 2>&1
docker unpause "$MINIO_CTR" >/dev/null 2>&1
wait "$APID" 2>/dev/null
HEALTHY=no; wait_healthy && HEALTHY=yes
relogin
OWNERS_AFTER="$(journal_owner "$DY" | tr '\n' ' ')"
OBJ_BEFORE="$(s3_has "oci-blobs/${DY}" && echo yes || echo no)"

begin_test "CONTROL: B holds a second digest; A's completion of it, interrupted by a backend restart, leaves A's journal row and the object in MinIO"
if [ "$B_PUSH_Y" = "201" ] && [ -n "$LOC_A" ] && [ "$HEALTHY" = "yes" ] && [ "$OWNERS_A" = "${RA_S3} " ] \
   && [ "$OWNERS_AFTER" = "${RA_S3} " ] && [ "$OBJ_BEFORE" = "yes" ]; then pass; else
  fail "B push=${B_PUSH_Y} A session='${LOC_A}' journal owners in flight='${OWNERS_A}' after restart='${OWNERS_AFTER}' (want ${RA_S3}) healthy=${HEALTHY} object present=${OBJ_BEFORE}"
fi

A_DEL2="$(code_to_file "${BASE_URL}/api/v1/repositories/${RA_S3}" "${WORK}/del-a2.json" -X DELETE "${AUTHZ[@]}")"
# 1.11.x: the purge runs in a background task after the 200. 1.12.0: a job
# does the delete after the 202 (#4311); wait for it to be terminal.
A_DEL2_WAIT=ok
repo_delete_wait "$BASE_URL" "$ADMIN_TOKEN" "$A_DEL2" "${WORK}/del-a2.json" || A_DEL2_WAIT="$REPO_DELETE_ERROR"
sleep 3
OBJ_AFTER="$(s3_has "oci-blobs/${DY}" && echo yes || echo no)"
G2="$(blob_get_exact "$RB" "$DY" "${WORK}/y.bin")"
CAND="$(psqlq "SELECT count(*) FROM oci_gc_candidates WHERE storage_key = 'oci-blobs/${DY}'")"

begin_test "#3851: deleting A on S3 keeps oci-blobs/<digest> (B still references it): object in MinIO, B pulls byte-exact, the key is recorded in oci_gc_candidates"
if is_2xx "$A_DEL2" && [ "$A_DEL2_WAIT" = "ok" ] && [ "$OBJ_AFTER" = "yes" ] && [ "$G2" = "200 exact" ] && [ "$CAND" = "1" ]; then pass; else
  fail "delete A=${A_DEL2} (${A_DEL2_WAIT}) object still in MinIO=${OBJ_AFTER} B blob GET='${G2}' oci_gc_candidates rows='${CAND:0:120}'. Pre-#3851 the delete purged every journaled key of A from the shared namespace, including the object B had committed"
fi

end_suite
