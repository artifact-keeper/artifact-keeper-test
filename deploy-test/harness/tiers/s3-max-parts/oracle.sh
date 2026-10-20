#!/usr/bin/env bash
# =============================================================================
# tiers/s3-max-parts/oracle.sh
#   #4805 / #4806: S3_MAX_PARTS sets the S3 multipart part budget, and the
#   streamed part schedule derives from it: 5 MiB doubling every
#   max(S3_MAX_PARTS / 10, 1) parts. With S3_MAX_PARTS=10 a 40 MiB streamed
#   upload goes up as four parts of 5, 10, 20 and 5 MiB; with the variable
#   unset (and on 1.11.3, which ignores it) as eight parts of 5 MiB.
# The parts are counted from MinIO's own trace (mc admin trace --json, run in
# the MinIO container), so the assertion is on what the store received.
# See the manifest for THE BUG, the primitives and the gates.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# DTF_DIR, BACKEND_IMAGE, the slot port block (HTTP_PORT, S3_PORT, ...),
# RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH. The manifest exported
# S3_MAX_PARTS=10.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"
: "${DTF_SLOT:?}"; : "${RUN_ID:?}"; : "${DTF_DIR:?}"; : "${BACKEND_IMAGE:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

BASE="$BASE_URL"
BACKEND_CTR="${DB_CONTAINER%-db}-backend"
MINIO_CTR="${DB_CONTAINER%-db}-minio"
TRACE=/tmp/dtf-s3-trace.json
MIB=1048576
BIG_MIB=40
# The schedule the fix derives from S3_MAX_PARTS=10 for a 40 MiB stream:
# parts_per_tier = max(10 / 10, 1) = 1, so the part size doubles every part
# (5, 10, 20 MiB) and the 5 MiB remainder goes up as the last part.
WANT_BUDGET="5 10 20 5"
# The historical schedule (S3_MAX_PARTS unset, or any image before #4806).
WANT_DEFAULT="5 5 5 5 5 5 5 5"

setup_workdir
W="$WORK_DIR"

jqr(){ jq -r "$1" 2>/dev/null || true; }
sha_of(){ sha256sum "$1" 2>/dev/null | awk '{print $1}' || true; }

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

login(){
  curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
    -d "{\"username\":\"admin\",\"password\":\"${ADMIN_PASS}\"}" | jqr '.access_token // .token // empty'
}
gen_put(){ # <path> <file> <out> -> HTTP code
  curl -s --max-time 300 -o "$3" -w '%{http_code}' -X PUT -H "Authorization: Bearer $TOK" \
    -H 'Content-Type: application/octet-stream' -T "$2" "$BASE/api/v1/repositories/${R_GEN}/artifacts/$1" || true
}
gen_get(){ # <path> <out> <headers> -> HTTP code
  rm -f "$2"
  curl -s --max-time 300 -D "$3" -o "$2" -w '%{http_code}' -H "Authorization: Bearer $TOK" \
    "$BASE/api/v1/repositories/${R_GEN}/download/$1" || true
}

# --- MinIO trace -------------------------------------------------------------
trace_start(){
  docker exec -d "$MINIO_CTR" sh -c "mc alias set dtf http://127.0.0.1:9000 minioadmin minioadmin >/dev/null 2>&1; mc admin trace --json dtf >> ${TRACE} 2>&1" 2>/dev/null || true
}
trace_lines(){ docker exec "$MINIO_CTR" sh -c "wc -l < ${TRACE} 2>/dev/null || echo 0" 2>/dev/null | tr -d '[:space:]' || true; }
trace_since(){ docker exec "$MINIO_CTR" sh -c "tail -n +$(( $1 + 1 )) ${TRACE}" 2>/dev/null || true; }
# parts_of <since-line> -> the part sizes (MiB, in partNumber order) of the one
# multipart upload completed after that line, e.g. "5 10 20 5". `rx` is the
# request bytes MinIO received for the part (payload plus ~100 bytes of
# headers), so floor(rx / MiB) is the payload size in whole MiB.
parts_of(){
  local since="$1" _i dump path
  for _i in $(seq 1 40); do
    dump="$(trace_since "$since")"
    path="$(printf '%s\n' "$dump" | jq -r 'select(.api == "s3.CompleteMultipartUpload") | .path' 2>/dev/null | tail -1)"
    [ -n "$path" ] && break
    sleep 0.5
  done
  [ -n "$path" ] || { echo ""; return 0; }
  printf '%s\n' "$dump" | jq -r --arg p "$path" --argjson mib "$MIB" '
    select(.api == "s3.PutObjectPart" and .path == $p)
    | [((.query | capture("partNumber=(?<n>[0-9]+)").n) | tonumber), ((.callStats.rx // .size) / $mib | floor)]
    | @tsv' 2>/dev/null | sort -n | awk '{printf "%s%s", (NR>1?" ":""), $2} END{print ""}'
}

# traced_upload <name> <path> <file>: upload while tracing; sets UP_CODE, UP_PARTS.
traced_upload(){
  local before
  before="$(trace_lines)"
  UP_CODE="$(gen_put "$2" "$3" "$W/$1.put")"
  UP_PARTS="$(parts_of "${before:-0}")"
}

backend_env(){ docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$BACKEND_CTR" 2>/dev/null | grep '^S3_MAX_PARTS=' || true; }

# =============================================================================
begin_suite "s3-max-parts"

begin_test "setup: admin login, a generic repository on S3 (MinIO), MinIO trace running"
TOK="$(login)"
if [ -z "$TOK" ]; then infra_fail "admin login failed at $BASE"; end_suite; fi
SUF="${RUN_ID##*-}-$$"
R_GEN="s3mp-${DTF_SLOT}-${SUF}"
r="$(curl -s -X POST "$BASE/api/v1/repositories" -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg k "$R_GEN" '{key:$k,name:$k,format:"generic",repo_type:"local",is_public:false}')" | jqr '.key // empty')"
[ "$r" = "$R_GEN" ] || { infra_fail "could not create generic repository ${R_GEN}"; end_suite; }
trace_start
for _i in $(seq 1 20); do docker exec "$MINIO_CTR" test -s "$TRACE" 2>/dev/null && break; sleep 0.5; done
if ! docker exec "$MINIO_CTR" test -e "$TRACE" 2>/dev/null; then infra_fail "mc admin trace did not start in ${MINIO_CTR}"; end_suite; fi
ENV_NOW="$(backend_env)"
echo "-- repo ${R_GEN}; backend ${ENV_NOW:-S3_MAX_PARTS unset}"
[ "$ENV_NOW" = "S3_MAX_PARTS=10" ] || { infra_fail "the backend was not started with S3_MAX_PARTS=10 (got '${ENV_NOW}')"; end_suite; }
pass

begin_test "CONTROL: a small (1 MiB) upload on S3 downloads byte-exact with the right X-Checksum-Sha256"
reset_case
head -c "$MIB" /dev/urandom > "$W/small.bin"
c="$(gen_put small/small.bin "$W/small.bin" "$W/small.put")"
g="$(gen_get small/small.bin "$W/small.get" "$W/small.hdr")"
x="$(awk 'tolower($1)=="x-checksum-sha256:"{print $2}' "$W/small.hdr" | tr -d '\r')"
note "upload HTTP ${c}, download HTTP ${g}, sha $(sha_of "$W/small.get"), X-Checksum-Sha256 ${x:-absent}"
[ "$c" = "201" ] || fail_g "small upload was HTTP ${c}: $(head -c 300 "$W/small.put")"
[ "$g" = "200" ] && [ "$(sha_of "$W/small.get")" = "$(sha_of "$W/small.bin")" ] || fail_g "small download is not byte-exact"
[ "$x" = "$(sha_of "$W/small.bin")" ] || fail_g "X-Checksum-Sha256 ${x:-absent} != $(sha_of "$W/small.bin")"
finish_case "a small S3 upload does not round-trip byte-exact"

head -c $(( BIG_MIB * MIB )) /dev/urandom > "$W/big1.bin"
begin_test "FIX #4805: with S3_MAX_PARTS=10 a ${BIG_MIB} MiB streamed upload reaches MinIO as parts of ${WANT_BUDGET// //} MiB (the budget doubles the part size every part)"
reset_case
traced_upload big1 big/big1.bin "$W/big1.bin"
note "upload HTTP ${UP_CODE}; MinIO PutObjectPart sizes (MiB, by partNumber): ${UP_PARTS:-<no completed multipart upload in the trace>}"
[ "$UP_CODE" = "201" ] || fail_g "upload was HTTP ${UP_CODE}: $(head -c 300 "$W/big1.put")"
[ -n "$UP_PARTS" ] || fail_g "MinIO's trace shows no completed multipart upload for the streamed body"
n_parts="$(wc -w <<<"$UP_PARTS" | tr -d '[:space:]')"
[ "$UP_PARTS" = "$WANT_BUDGET" ] || fail_g "parts were [${UP_PARTS}] (${n_parts} parts), expected [${WANT_BUDGET}] (4 parts); [${WANT_DEFAULT}] is the 10,000-part schedule, i.e. S3_MAX_PARTS ignored"
finish_case "#4805: S3_MAX_PARTS does not set the streamed part schedule"

begin_test "CONTROL: the ${BIG_MIB} MiB upload made under S3_MAX_PARTS=10 downloads byte-exact"
reset_case
g="$(gen_get big/big1.bin "$W/big1.get" "$W/big1.hdr")"
note "download HTTP ${g}, $(wc -c < "$W/big1.get" | tr -d '[:space:]') bytes, sha $(sha_of "$W/big1.get")"
[ "$g" = "200" ] && [ "$(sha_of "$W/big1.get")" = "$(sha_of "$W/big1.bin")" ] || fail_g "the large download is not byte-exact"
finish_case "a large streamed S3 upload does not round-trip byte-exact"

# =============================================================================
# Same image, S3_MAX_PARTS unset: recreate only the backend (postgres, MinIO
# and its trace stay up) and repeat. The schedule must be the historical one.
# =============================================================================
begin_test "CONTROL: with S3_MAX_PARTS unset the same image streams ${BIG_MIB} MiB as eight 5 MiB parts (the default schedule) and round-trips byte-exact"
reset_case
S3_MAX_PARTS="" docker compose -p "ak-dtf${DTF_SLOT}" \
  -f "${DTF_DIR}/compose.base.yml" -f "${DTF_DIR}/profiles/storage.s3.yml" -f "${DTF_DIR}/profiles/storage.s3-max-parts.yml" \
  up -d --wait --no-deps backend >"$W/recreate.log" 2>&1 || true
ENV_NOW="$(backend_env)"
TOK="$(login)"
if [ -z "$TOK" ] || { [ -n "$ENV_NOW" ] && [ "$ENV_NOW" != "S3_MAX_PARTS=" ]; }; then
  infra_fail "could not recreate the backend without S3_MAX_PARTS (env '${ENV_NOW}', login ${TOK:+ok}): $(tail -5 "$W/recreate.log")"; end_suite
fi
note "backend recreated: ${ENV_NOW:-S3_MAX_PARTS absent} (empty is not a number, so the 10,000 default)"
head -c $(( BIG_MIB * MIB )) /dev/urandom > "$W/big2.bin"
traced_upload big2 big/big2.bin "$W/big2.bin"
note "upload HTTP ${UP_CODE}; MinIO PutObjectPart sizes (MiB): ${UP_PARTS:-<none>}"
[ "$UP_CODE" = "201" ] || fail_g "upload was HTTP ${UP_CODE}"
[ "$UP_PARTS" = "$WANT_DEFAULT" ] || fail_g "parts were [${UP_PARTS}], expected the default [${WANT_DEFAULT}]"
g="$(gen_get big/big2.bin "$W/big2.get" "$W/big2.hdr")"
[ "$g" = "200" ] && [ "$(sha_of "$W/big2.get")" = "$(sha_of "$W/big2.bin")" ] || fail_g "download after the recreate is not byte-exact (HTTP ${g})"
g="$(gen_get big/big1.bin "$W/big1.get2" "$W/big1.hdr2")"
[ "$g" = "200" ] && [ "$(sha_of "$W/big1.get2")" = "$(sha_of "$W/big1.bin")" ] || fail_g "the object uploaded under the 10-part budget no longer downloads byte-exact (HTTP ${g})"
finish_case "the unset S3_MAX_PARTS schedule differs from the historical 5 MiB one"

end_suite
