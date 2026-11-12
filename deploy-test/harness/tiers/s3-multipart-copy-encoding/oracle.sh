#!/usr/bin/env bash
# =============================================================================
# tiers/s3-multipart-copy-encoding/oracle.sh
#   #4838 the S3 multipart server-side copy names its source in the encoding
#         the object was stored under (non-ASCII keys)
# See the manifest for the bug and the gates.
#
# run.sh exported BASE_URL, ADMIN_PASS, RUN_ID, DTF_SLOT, RELEASE_GATE=1,
# JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"; : "${DTF_SLOT:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
set +e

BASE="$BASE_URL"
MINIO_CTR="ak-dtf${DTF_SLOT}-minio"
MC_IMAGE="${SMC_MC_IMAGE:-ghcr.io/artifact-keeper/ci-mirror/mc:RELEASE.2025-08-13T08-35-41Z}"
MC_CTR="l2-s${DTF_SLOT}-mc"
BIG_MIB="${SMC_BIG_MIB:-12}"    # above S3_MAX_SINGLE_COPY_BYTES (5 MiB)

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

mcx(){
  docker rm -f "$MC_CTR" >/dev/null 2>&1
  docker run --rm -i --name "$MC_CTR" --network "container:${MINIO_CTR}" --entrypoint sh "$MC_IMAGE" -c \
    "mc alias set local http://localhost:9000 minioadmin minioadmin >/dev/null 2>&1 && $1"
}
add_exit_handler 'docker rm -f "'"$MC_CTR"'" >/dev/null 2>&1'

BASIC="Authorization: Basic $(printf 'admin:%s' "$ADMIN_PASS" | base64 | tr -d '\n')"

# push_chunked <file> <chunks>: an OCI blob push the way a chunking client
# does it: POST a session, PATCH the body in <chunks> parts, then an empty
# PUT ?digest=. Completing a multi-part session concatenates the parts into a
# staging object and server-side copies it to the blob key. Sets PUSH_CODE and
# PUSH_BODY (the final PUT's response).
push_chunked(){
  local f="$1" parts="$2" size loc sep off=0 i n c
  size="$(stat -c %s "$f")"; PUSH_CODE=000; PUSH_BODY=""
  loc="$(curl -s -D- -o /dev/null -X POST -H "$BASIC" "$BASE/v2/${OCI}/app/blobs/uploads/" \
    | tr -d '\r' | awk 'tolower($1)=="location:"{print $2}')"
  [ -n "$loc" ] || { PUSH_BODY="no upload session"; return 0; }
  case "$loc" in http*) ;; *) loc="${BASE}${loc}" ;; esac
  for i in $(seq 1 "$parts"); do
    if [ "$i" -eq "$parts" ]; then n=$(( size - off )); else n=$(( size / parts )); fi
    dd if="$f" of="$W/part" iflag=skip_bytes,count_bytes skip="$off" count="$n" status=none
    : > "$W/ph"
    c="$(curl -s -D "$W/ph" -o /dev/null -w '%{http_code}' --max-time 120 -X PATCH -H "$BASIC" \
      -H 'Content-Type: application/octet-stream' -H "Content-Range: ${off}-$(( off + n - 1 ))" \
      --data-binary @"$W/part" "$loc" || true)"
    [ "$c" = "202" ] || { PUSH_BODY="PATCH ${i} answered ${c}"; return 0; }
    loc="$(tr -d '\r' < "$W/ph" | awk 'tolower($1)=="location:"{print $2}')"
    case "$loc" in http*) ;; *) loc="${BASE}${loc}" ;; esac
    off=$(( off + n ))
  done
  case "$loc" in *\?*) sep='&' ;; *) sep='?' ;; esac
  PUSH_CODE="$(curl -s -o "$W/put.out" -w '%{http_code}' --max-time 300 -X PUT -H "$BASIC" \
    -H 'Content-Length: 0' "${loc}${sep}digest=sha256:$(sha_of "$f")" || true)"
  PUSH_BODY="$(head -c 300 "$W/put.out")"
}
pull_sha(){ # <digest-hex> -> "<code> <sha>"
  local c; c="$(curl -s --max-time 120 -H "$BASIC" -o "$W/pull" -w '%{http_code}' "$BASE/v2/${OCI}/app/blobs/sha256:$1" || true)"
  echo "$c $(sha_of "$W/pull")"; rm -f "$W/pull"
}

# =============================================================================
begin_suite "s3-multipart-copy-encoding"

begin_test "setup: admin login, a docker repository, the backend's S3 prefix is stored percent-encoded"
TOK="$(curl -s --max-time 20 -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg p "$ADMIN_PASS" '{username:"admin",password:$p}')" | jqr '.access_token // .token // empty')"
if [ -z "$TOK" ]; then infra_fail "admin login failed at $BASE"; end_suite; fi
OCI="smc-oci-${DTF_SLOT}x${RUN_ID##*-}"
c="$(curl -s -o "$W/c.json" -w '%{http_code}' -X POST "$BASE/api/v1/repositories" -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' -d "$(jq -nc --arg k "$OCI" '{key:$k,name:$k,format:"docker",repo_type:"local"}')")"
case "$c" in 2??) ;; *) infra_fail "docker repository create answered ${c}: $(head -c 200 "$W/c.json")"; end_suite ;; esac
head -c $((2 * 1048576)) /dev/urandom > "$W/small.bin"
head -c $((BIG_MIB * 1048576)) /dev/urandom > "$W/big.bin"
pass "repository ${OCI}; blobs of 2 MiB and ${BIG_MIB} MiB"

begin_test "CONTROL: a 2 MiB blob pushed in two PATCH chunks (single-request server-side copy) is 201 and pulls byte-exact"
reset_case
push_chunked "$W/small.bin" 2
note "final PUT -> ${PUSH_CODE} ${PUSH_BODY:0:160}"
[ "$PUSH_CODE" = "201" ] || fail_g "chunked push of the 2 MiB blob answered ${PUSH_CODE}: ${PUSH_BODY}"
read -r c s <<<"$(pull_sha "$(sha_of "$W/small.bin")")"
[ "$c" = "200" ] && [ "$s" = "$(sha_of "$W/small.bin")" ] || fail_g "pull of the 2 MiB blob: ${c}, bytes differ"
keys="$(mcx "mc ls --recursive local/ak-artifacts/" 2>/dev/null | awk '{print $NF}' | grep -c '^dtf-caf%C3%A9/' || true)"
note "objects under the encoded prefix dtf-caf%C3%A9/: ${keys}"
[ "${keys:-0}" -gt 0 ] || fail_g "no object is stored under the percent-encoded prefix 'dtf-caf%C3%A9/' (is storage.s3-prefix-nonascii applied?)"
finish_case "a small chunked push under a non-ASCII prefix failed"

begin_test "FIX #4838: a ${BIG_MIB} MiB blob pushed in three PATCH chunks (multipart UploadPartCopy of a non-ASCII key) is 201 and pulls byte-exact"
reset_case
push_chunked "$W/big.bin" 3
note "final PUT -> ${PUSH_CODE} ${PUSH_BODY:0:200}"
[ "$PUSH_CODE" = "201" ] || fail_g "chunked push of the ${BIG_MIB} MiB blob answered ${PUSH_CODE} (the multipart copy named its source by the unencoded key): ${PUSH_BODY}"
read -r c s <<<"$(pull_sha "$(sha_of "$W/big.bin")")"
note "pull -> ${c}"
[ "$c" = "200" ] && [ "$s" = "$(sha_of "$W/big.bin")" ] || fail_g "pull of the ${BIG_MIB} MiB blob: ${c}, bytes differ"
finish_case "the multipart server-side copy of a non-ASCII key failed"

end_suite
