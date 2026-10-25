#!/usr/bin/env bash
# =============================================================================
# tiers/repo-delete-reclaims-storage-job/oracle.sh
#   #4311 a large repository delete behind a 30 s proxy answers 202 with a
#   job that completes, and keeps an object another repository uploaded
#   during the delete.
# See the manifest for the gaps and the gates.
#
# run.sh exported BASE_URL (backend, direct), DB_CONTAINER, ADMIN_USER,
# ADMIN_PASS, RUN_ID, DTF_SLOT, TRIVY_PORT (the route-timeout proxy),
# RELEASE_GATE=1, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"; : "${TRIVY_PORT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh enables errexit; every probe below is judged by its assertion.
set +e

SUF="${RUN_ID##*-}-$$"
SLOT="$DTF_SLOT"
PROXY="http://127.0.0.1:${TRIVY_PORT}"
MINIO_CTR="ak-dtf${SLOT}-minio"
BUCKET="ak-artifacts"
MC_IMAGE="${RDRS_MC_IMAGE:-ghcr.io/artifact-keeper/ci-mirror/mc:RELEASE.2025-08-13T08-35-41Z}"
N="${RDRS_ARTIFACTS:-10000}"
R_A="rdrs-a-${SLOT}-${SUF}"; R_B="rdrs-b-${SLOT}-${SUF}"; R_E="rdrs-e-${SLOT}-${SUF}"
W="$(mktemp -d -t dtf-rdrs-XXXXXX)"
trap 'rm -rf "$W"' EXIT

psqlq() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -qAtc "$1" 2>/dev/null; }
code() { curl -s -o "$W/last" -w '%{http_code}' --max-time 120 "$@" 2>/dev/null || echo 000; }
is_2xx() { case "$1" in 2??) return 0 ;; *) return 1 ;; esac; }
note() { echo "   $1"; }
sha() { sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }
mcx() { # cmd [extra docker args...]
  local cmd="$1"; shift
  docker run --rm -i --network "container:${MINIO_CTR}" --security-opt label=disable "$@" \
    --entrypoint sh "$MC_IMAGE" -c \
    "mc alias set local http://localhost:9000 minioadmin minioadmin >/dev/null 2>&1 && ${cmd}"
}
# How many of the 25 sampled seeded keys are in the bucket (one listing).
sampled_present() {
  mcx "mc find local/${BUCKET}" </dev/null 2>/dev/null | sed "s#^local/${BUCKET}/${PREFIX}##" > "$W/objects"
  grep -cxF -f "$W/sample-keys" "$W/objects"
}
mk_repo() {
  local body
  body="$(jq -nc --arg k "$1" '{key:$k,name:$k,format:"generic",repo_type:"local",is_public:false}')"
  code -X POST "${AUTHZ[@]}" -H 'Content-Type: application/json' -d "$body" "${BASE_URL}/api/v1/repositories"
}

begin_suite "repo-delete-reclaims-storage-job"
auth_admin
AUTHZ=(-H "Authorization: Bearer ${ADMIN_TOKEN}")

# =============================================================================
# SETUP: repository A with N artifacts (rows + objects), B and an empty E
# =============================================================================
begin_test "CONTROL: seed ${N} artifacts into an S3 repository; the shared payload is uploaded through the API"
SF=""
for r in "$R_A" "$R_B" "$R_E"; do c="$(mk_repo "$r")"; is_2xx "$c" || SF="${SF} create-${r}=${c}"; done
RID_A="$(psqlq "SELECT id FROM repositories WHERE key='${R_A}'")"
[ "$(psqlq "SELECT storage_backend FROM repositories WHERE key='${R_A}'")" = "s3" ] || SF="${SF} not-s3"
# The shared payload: random bytes whose SHA-256 starts with "ff", so its
# content-addressed key sorts after every seeded key.
python3 -I - "$W/shared.bin" <<'PY' || SF="${SF} shared-payload"
import hashlib, os, sys
while True:
    b = os.urandom(4096)
    if hashlib.sha256(b).hexdigest().startswith("ff"):
        open(sys.argv[1], "wb").write(b); break
PY
c="$(code "${AUTHZ[@]}" -X PUT --data-binary @"$W/shared.bin" "${BASE_URL}/api/v1/repositories/${R_A}/artifacts/shared/payload.bin")"
is_2xx "$c" || SF="${SF} shared-put=${c}"
SHARED_KEY="$(psqlq "SELECT storage_key FROM artifacts WHERE repository_id='${RID_A}' AND path='shared/payload.bin'")"
# Where the backend puts a key in the bucket: find the shared object.
SHARED_OBJ="$(mcx "mc find local/${BUCKET} --name '$(basename "$SHARED_KEY")'" </dev/null 2>/dev/null | head -1)"
PREFIX="${SHARED_OBJ#local/${BUCKET}/}"; PREFIX="${PREFIX%"$SHARED_KEY"}"
[ -n "$SHARED_OBJ" ] || SF="${SF} shared-object-not-in-bucket"
# N more artifacts: rows straight into the database, objects mirrored into
# the bucket under the same layout (seeding through the API would take
# minutes and is not what this tier is about).
mkdir -p "$W/seed"
python3 -I - "$W" "$N" "$RID_A" "$SUF" <<'PY' || SF="${SF} seed-gen"
import hashlib, os, sys
w, n, rid, suf = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
rows = []
for i in range(n):
    d = f"dtf rdrs {suf} {i}\n".encode()
    h = hashlib.sha256(d).hexdigest()
    key = f"{h[:2]}/{h[2:4]}/{h}"
    os.makedirs(f"{w}/seed/{h[:2]}/{h[2:4]}", exist_ok=True)
    open(f"{w}/seed/{key}", "wb").write(d)
    rows.append(f"('{rid}','bulk/{i}.txt','{i}.txt',{len(d)},'{h}','text/plain','{key}')")
    if i < 25:
        open(f"{w}/sample-keys", "a").write(key + "\n")
with open(f"{w}/seed.sql", "w") as f:
    for j in range(0, len(rows), 2000):
        f.write("INSERT INTO artifacts (repository_id, path, name, size_bytes, checksum_sha256, content_type, storage_key) VALUES\n")
        f.write(",\n".join(rows[j:j + 2000]) + ";\n")
PY
docker exec -i "$DB_CONTAINER" psql -U registry -d artifact_registry -q -v ON_ERROR_STOP=1 < "$W/seed.sql" >/dev/null 2>"$W/seed.err" \
  || SF="${SF} seed-sql=$(head -c 160 "$W/seed.err")"
mcx "mc mirror --quiet /seed local/${BUCKET}/${PREFIX%/}/ >/dev/null 2>&1; mc find local/${BUCKET} | wc -l" -v "$W/seed:/seed:ro" > "$W/mirror.out" 2>&1 \
  || SF="${SF} mirror"
ROWS_A="$(psqlq "SELECT count(*) FROM artifacts WHERE repository_id='${RID_A}'")"
SAMPLE_PRESENT="$(sampled_present)"
[ "$ROWS_A" = "$((N + 1))" ] || SF="${SF} rows=${ROWS_A}"
[ "$SAMPLE_PRESENT" = "25" ] || SF="${SF} seeded-objects=${SAMPLE_PRESENT}/25"
if [ -n "$SF" ]; then infra_fail "setup failed:${SF}" "$(cat "$W/mirror.out" 2>/dev/null | tail -2)"; end_suite; fi
note "A=${R_A} rows=${ROWS_A} prefix='${PREFIX}' shared=${SHARED_KEY}"
pass

begin_test "CONTROL: deleting an empty repository through the proxy succeeds"
c="$(code "${AUTHZ[@]}" -X DELETE "${PROXY}/api/v1/repositories/${R_E}")"
if is_2xx "$c"; then pass; else fail "DELETE of an empty repository through the proxy: HTTP ${c}"; fi

# =============================================================================
# FIX: the delete of A, with an identical upload into B right after it
# =============================================================================
begin_test "#4311 DELETE of a ${N}-artifact repository through a 30 s proxy answers 202 with a job"
T0="$(date +%s)"
DEL="$(curl -s -D "$W/del.h" -o "$W/del" -w '%{http_code}' --max-time 90 "${AUTHZ[@]}" -X DELETE \
  "${PROXY}/api/v1/repositories/${R_A}" 2>/dev/null || echo 000)"
T1="$(date +%s)"
# The same bytes arrive in B the moment the delete has answered.
UPB="$(curl -s -o "$W/upb" -w '%{http_code}' --max-time 120 "${AUTHZ[@]}" -X PUT --data-binary @"$W/shared.bin" \
  "${BASE_URL}/api/v1/repositories/${R_B}/artifacts/copy/payload.bin" 2>/dev/null || echo 000)"
JOB="$(jq -r '.id // empty' "$W/del" 2>/dev/null)"
LOC="$(grep -i '^location:' "$W/del.h" 2>/dev/null | tr -d '\r' | awk '{print $2}')"
GONE="$(curl -s -o /dev/null -w '%{http_code}' --max-time 30 "${AUTHZ[@]}" "${BASE_URL}/api/v1/repositories/${R_A}" 2>/dev/null)"
note "DELETE HTTP ${DEL} after $((T1 - T0)) s ($(head -c 160 "$W/del")); B upload HTTP ${UPB}"
if [ "$DEL" = 202 ] && [ -n "$JOB" ] && [ "$LOC" = "/api/v1/repository-deletions/${JOB}" ] && [ "$GONE" = 404 ]; then
  pass
else
  fail "DELETE answered HTTP ${DEL} after $((T1 - T0)) s, job '${JOB}', Location '${LOC}', GET of the key afterwards ${GONE}"
fi

begin_test "#4311 the delete job completes, reported through the status endpoint"
ST=""; DONE=""
if [ -n "$JOB" ]; then
  for _ in $(seq 1 300); do
    curl -s -o "$W/job" --max-time 20 "${AUTHZ[@]}" "${PROXY}/api/v1/repository-deletions/${JOB}" 2>/dev/null
    ST="$(jq -r '.status // empty' "$W/job" 2>/dev/null)"
    case "$ST" in completed|failed) break ;; esac
    sleep 2
  done
  DONE="$(jq -r '.completed_items // empty' "$W/job" 2>/dev/null)"
fi
if [ "$ST" = completed ] && [ "$DONE" = "$((N + 1))" ]; then
  pass
else
  fail "job '${JOB}' status '${ST}', completed_items '${DONE}' ($(head -c 300 "$W/job" 2>/dev/null))"
fi

begin_test "#4311 the repository's objects are reclaimed from the bucket"
# On the pre-fix image the purge runs in the background after the DELETE;
# give it the same time the job gets.
LEFT=25
for _ in $(seq 1 60); do
  LEFT="$(sampled_present)"
  [ "$LEFT" = 0 ] && break
  sleep 5
done
ROWS_LEFT="$(psqlq "SELECT count(*) FROM artifacts WHERE repository_id='${RID_A}'")"
if [ "$LEFT" = 0 ] && [ "$ROWS_LEFT" = 0 ]; then pass; else fail "${LEFT}/25 sampled objects and ${ROWS_LEFT} rows of A remain"; fi

begin_test "#4311 an identical upload into another repository during the delete still downloads"
DLB="$(curl -s -o "$W/dlb" -w '%{http_code}' --max-time 60 "${AUTHZ[@]}" \
  "${BASE_URL}/api/v1/repositories/${R_B}/download/copy/payload.bin" 2>/dev/null || echo 000)"
OBJ="$(mcx "mc stat local/${BUCKET}/${PREFIX}${SHARED_KEY}" </dev/null >/dev/null 2>&1 && echo present || echo missing)"
if is_2xx "$UPB" && [ "$DLB" = 200 ] && [ "$(sha "$W/dlb")" = "$(sha "$W/shared.bin")" ] && [ "$OBJ" = present ]; then
  pass
else
  fail "B upload HTTP ${UPB}; B download HTTP ${DLB} (sha $(sha "$W/dlb")); shared object ${OBJ}"
fi

end_suite
