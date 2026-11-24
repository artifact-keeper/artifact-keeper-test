#!/usr/bin/env bash
# =============================================================================
# tiers/verify-skip-client-verified-oci/oracle.sh: DOWNLOAD_VERIFY_SKIP_CLIENT_VERIFIED=oci
# skips serve-time verification on OCI blob GETs only (artifact-keeper#6468).
# See the manifest. run.sh exports BASE_URL, DB_CONTAINER, ADMIN_PASS, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"
# shellcheck source=/dev/null
source "$COMMON_SH"
set +e

BASE="$BASE_URL"
BACKEND_CTR="${DB_CONTAINER%-db}-backend"
FS_HELPER_IMAGE="postgres:16-alpine"
SFX="$RANDOM$RANDOM"
setup_workdir
W="$WORK_DIR"
jqr(){ jq -r "$1" 2>/dev/null || true; }
psql_q(){ docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]'; }
fsx(){ docker run --rm -i --volumes-from "$BACKEND_CTR" --entrypoint sh "$FS_HELPER_IMAGE" -c "$1"; }
sha_of(){ sha256sum "$1" | awk '{print $1}'; }

FAILS=0; DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

# flip_stored <repo-key> <hex>: flip byte 1000 of the stored object whose path
# contains <hex>, under the repository's storage root. Echoes the file.
flip_stored(){
  local root; root="$(psql_q "SELECT storage_path FROM repositories WHERE key = '$1'")"
  fsx "set -e; f=\$(find '$root' -type f -path '*$2*' | head -n1); [ -n \"\$f\" ]; \
       b=\$(od -An -tu1 -j 1000 -N1 \"\$f\" | tr -d ' '); \
       if [ \"\$b\" = 0 ]; then printf '\\001'; else printf '\\000'; fi | dd of=\"\$f\" bs=1 seek=1000 conv=notrunc 2>/dev/null; echo \"\$f\""
}
get(){ # <url> <out> -> "<http> <bytes> <sha>"
  local m; m="$(curl -s --max-time 60 -o "$2" -w '%{http_code} %{size_download}' -H "Authorization: Bearer $TOK" "$1")"
  echo "$m $(sha_of "$2")"
}

begin_suite "verify-skip-client-verified-oci"
begin_test "setup: login, an OCI repository with two pushed blobs, a generic repository with one artifact"
TOK="$(curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"${ADMIN_PASS}\"}" | jqr '.access_token // .token // empty')"
[ -n "$TOK" ] || { infra_fail "admin login failed"; end_suite; exit 1; }
O="vsko${SFX}"; G="vskg${SFX}"
for r in "$O:docker" "$G:generic"; do
  curl -s -o /dev/null -X POST "$BASE/api/v1/repositories" -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
    -d "{\"key\":\"${r%%:*}\",\"name\":\"${r%%:*}\",\"format\":\"${r##*:}\",\"repo_type\":\"local\"}"
done
push_blob(){ # <file> -> digest hex
  local hex loc sep c
  hex="$(sha_of "$1")"
  loc="$(curl -s -D - -o /dev/null -X POST -H "Authorization: Bearer $TOK" "$BASE/v2/$O/img/blobs/uploads/" \
    | awk 'tolower($1)=="location:"{print $2}' | tr -d '\r')"
  case "$loc" in http*) ;; *) loc="$BASE$loc" ;; esac
  sep='?'; [[ "$loc" == *\?* ]] && sep='&'
  c="$(curl -s -o /dev/null -w '%{http_code}' -X PUT -H "Authorization: Bearer $TOK" \
    -H 'Content-Type: application/octet-stream' --data-binary "@$1" "${loc}${sep}digest=sha256:${hex}")"
  [ "$c" = 201 ] && echo "$hex"
}
head -c 65536 /dev/urandom > "$W/bad.bin"; head -c 65536 /dev/urandom > "$W/good.bin"
BAD="$(push_blob "$W/bad.bin")"; GOOD="$(push_blob "$W/good.bin")"
head -c 65536 /dev/urandom > "$W/gen.bin"
GC="$(curl -s -o /dev/null -w '%{http_code}' -X PUT -H "Authorization: Bearer $TOK" --data-binary "@$W/gen.bin" \
  "$BASE/api/v1/repositories/$G/artifacts/vsk/gen.bin")"
GHEX="$(sha_of "$W/gen.bin")"
echo "-- blobs bad=${BAD:-?} good=${GOOD:-?}; generic PUT ${GC}"
{ [ -n "$BAD" ] && [ -n "$GOOD" ] && [ "$GC" = 201 ]; } || { infra_fail "fixture push failed"; end_suite; exit 1; }
F1="$(flip_stored "$O" "$BAD")"; F2="$(psql_q "SELECT storage_key FROM artifacts a JOIN repositories r ON r.id = a.repository_id WHERE r.key = '$G' AND a.path = 'vsk/gen.bin'")"
F2="$(flip_stored "$G" "${F2##*/}")"
echo "-- flipped: ${F1:-NONE} ${F2:-NONE}"
{ [ -n "$F1" ] && [ -n "$F2" ]; } || { infra_fail "could not corrupt the stored objects"; end_suite; exit 1; }
pass

read -r B_CODE B_LEN B_SHA <<<"$(get "$BASE/v2/$O/img/blobs/sha256:$BAD" "$W/b.out")"
read -r OK_CODE OK_LEN OK_SHA <<<"$(get "$BASE/v2/$O/img/blobs/sha256:$GOOD" "$W/ok.out")"
read -r G_CODE G_LEN G_SHA <<<"$(get "$BASE/api/v1/repositories/$G/download/vsk/gen.bin" "$W/g.out")"

begin_test "CONTROL: an intact OCI blob is served whole and matches its digest"
reset_case
note "intact blob: ${OK_CODE} ${OK_LEN} bytes sha ${OK_SHA:0:16}"
{ [ "$OK_CODE" = 200 ] && [ "$OK_SHA" = "$GOOD" ]; } || fail_g "the intact blob answered ${OK_CODE} with sha ${OK_SHA:0:16}"
finish_case "an intact blob is not served"

begin_test "CONTROL: a corrupted generic artifact on the same backend is still refused (the knob reaches OCI blobs only)"
reset_case
note "corrupt generic: ${G_CODE} ${G_LEN} bytes"
[ "$G_CODE" = 502 ] || fail_g "the corrupted generic artifact answered ${G_CODE}, want 502 STORED_OBJECT_INTEGRITY"
[ "$G_SHA" = "$GHEX" ] && fail_g "the corrupted generic artifact hashed to its record?"
finish_case "the generic route stopped verifying"

# The same oracle runs on two deployments: this tier's (the option set) and
# verify-skip-client-verified-oci-default's (unset). Which one this is comes
# from the backend container's own environment, not from a variable the
# harness could carry from one tier to the next.
SKIP_ENV="$(docker inspect "$BACKEND_CTR" --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null \
  | awk -F= '$1=="DOWNLOAD_VERIFY_SKIP_CLIENT_VERIFIED"{print $2}')"
echo "-- backend DOWNLOAD_VERIFY_SKIP_CLIENT_VERIFIED=${SKIP_ENV:-<unset>}"

if [ "$SKIP_ENV" != "oci" ]; then
  begin_test "DEFAULT #6468: with DOWNLOAD_VERIFY_SKIP_CLIENT_VERIFIED unset a corrupted OCI blob is still refused 502 STORED_OBJECT_INTEGRITY"
  reset_case
  note "corrupt blob: ${B_CODE} ${B_LEN} bytes; body $(head -c 200 "$W/b.out" | tr -d '\n')"
  [ -z "$SKIP_ENV" ] || fail_g "the default deployment set DOWNLOAD_VERIFY_SKIP_CLIENT_VERIFIED=${SKIP_ENV}"
  [ "$B_CODE" = 502 ] || fail_g "the corrupted blob answered ${B_CODE}, want 502 (verification is on by default)"
  grep -q STORED_OBJECT_INTEGRITY "$W/b.out" || fail_g "the refusal does not name STORED_OBJECT_INTEGRITY"
  [ "$B_SHA" != "$BAD" ] || fail_g "the corrupted blob hashed to its digest: the flip did not take"
  finish_case "the default stopped verifying OCI blobs"
  end_suite
  exit 0
fi

begin_test "FIX #6468: with DOWNLOAD_VERIFY_SKIP_CLIENT_VERIFIED=oci a corrupted blob is served unverified, whole, for the client to reject by digest"
reset_case
note "corrupt blob: ${B_CODE} ${B_LEN} bytes sha ${B_SHA:0:16} (digest ${BAD:0:16})"
[ "$B_CODE" = 200 ] || fail_g "the corrupted blob answered ${B_CODE}, want 200 (the knob is ignored: verified and refused)"
[ "$B_LEN" = 65536 ] || fail_g "the corrupted blob was cut at ${B_LEN} of 65536 bytes"
[ "$B_SHA" != "$BAD" ] || fail_g "the corrupted blob hashed to its digest: the flip did not take"
finish_case "the OCI blob route still verifies with the skip configured"
end_suite
