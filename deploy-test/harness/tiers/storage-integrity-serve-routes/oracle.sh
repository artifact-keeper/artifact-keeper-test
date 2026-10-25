#!/usr/bin/env bash
# =============================================================================
# tiers/storage-integrity-serve-routes/oracle.sh: corrupted stored objects fail
#   closed on the format-native and virtual serve routes (artifact-keeper#4323)
# =============================================================================
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RELEASE_GATE=1,
# JUNIT_OUTPUT_DIR, COMMON_SH. See the manifest for the contract.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
set +e

BASE="$BASE_URL"
DBC="$DB_CONTAINER"
SLOT_PREFIX="${DB_CONTAINER%-db}"
BACKEND_CTR="${SLOT_PREFIX}-backend"
FS_HELPER_IMAGE="${SI_FS_HELPER_IMAGE:-postgres:16-alpine}"

setup_workdir
W="$WORK_DIR"

jqr(){ jq -r "$1" 2>/dev/null || true; }
psql_q(){ docker exec "$DBC" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null || true; }
login(){ curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"$1\",\"password\":\"$2\"}" | jqr '.access_token // .token // empty' || true; }
sha_of(){ sha256sum "$1" 2>/dev/null | awk '{print $1}' || true; }

FAILS=0
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); }
DETAIL=""
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

# --- storage access (filesystem volume of the backend) ----------------------
fsx(){ docker run --rm -i --volumes-from "$BACKEND_CTR" --entrypoint sh "$FS_HELPER_IMAGE" -c "$1"; }
repo_root(){ psql_q "SELECT storage_path FROM repositories WHERE key='$1';" | tr -d '[:space:]'; }
storage_key_like(){ # <repo> <path LIKE pattern>
  psql_q "SELECT a.storage_key FROM artifacts a JOIN repositories r ON r.id=a.repository_id
          WHERE r.key='$1' AND a.path LIKE '$2' AND NOT a.is_deleted LIMIT 1;" | tr -d '[:space:]'
}
obj_put(){ # <repo> <key> <infile>: overwrite the stored object, keep ownership
  local root; root="$(repo_root "$1")"
  fsx "set -e; f='$root/$2'; o=\$(stat -c %u:%g \"\$f\"); cat > \"\$f\"; chown \"\$o\" \"\$f\"" < "$3"
}
obj_sha(){ local f="$W/objsha.$$"; fsx "cat '$(repo_root "$1")/$2'" > "$f" 2>/dev/null; sha_of "$f"; }
# flip <repo> <key> <original>: rewrite the object with one byte changed and
# confirm the store now holds different bytes (non-zero: INFRA, not a verdict).
flip(){
  local bad="$W/bad.$$"; cp "$3" "$bad"
  local b; b="$(od -An -tu1 -j 100 -N1 "$bad" | tr -d '[:space:]')"
  if [ "$b" = "0" ]; then printf '\001'; else printf '\000'; fi | dd of="$bad" bs=1 seek=100 conv=notrunc 2>/dev/null
  obj_put "$1" "$2" "$bad" || return 1
  local now; now="$(obj_sha "$1" "$2")"
  [ -n "$now" ] && [ "$now" = "$(sha_of "$bad")" ] && [ "$now" != "$(sha_of "$3")" ]
}

# --- HTTP ---------------------------------------------------------------------
# dl <outfile> <url> [curl args] -> DL_RC DL_CODE DL_SIZE DL_SHA
dl(){
  local out="$1" url="$2"; shift 2
  local meta; rm -f "$out"
  meta="$(curl -sS --max-time 120 -o "$out" -w '%{http_code} %{size_download}' "${AUTH[@]}" "$@" "$url" 2>"$W/curl.err")" \
    && DL_RC=0 || DL_RC=$?
  DL_CODE="${meta%% *}"; DL_SIZE="${meta##* }"; DL_SHA="$(sha_of "$out")"
}
dl_desc(){ echo "curl_exit=$DL_RC http=$DL_CODE bytes=$DL_SIZE body_sha=${DL_SHA:0:16} body=$(head -c 120 "$1" 2>/dev/null | tr -dc '[:print:]')"; }
# expect_502 <label> <url> <original-file>: 502 STORED_OBJECT_INTEGRITY and no
# byte of the object.
expect_502(){
  dl "$W/r.out" "$2"; note "$1: $(dl_desc "$W/r.out")"
  [ "$DL_CODE" = "502" ] || fail_g "$1 answered HTTP $DL_CODE (curl exit $DL_RC), want 502"
  [ "$(jqr '.code' < "$W/r.out")" = "STORED_OBJECT_INTEGRITY" ] || fail_g "$1: body is not {code: STORED_OBJECT_INTEGRITY}"
  [ "$DL_SHA" != "$(sha_of "$3")" ] || fail_g "$1 delivered the original bytes"
}
mkrepo(){ # <key> <format> [repo_type]
  curl -s -X POST "$BASE/api/v1/repositories" "${AUTH[@]}" -H 'Content-Type: application/json' \
    -d "{\"key\":\"$1\",\"name\":\"$1\",\"format\":\"$2\",\"repo_type\":\"${3:-local}\",\"is_public\":false}" \
    | jqr '.key // empty'
}
add_member(){ # <virtual> <member> <priority> -> HTTP code
  curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/v1/repositories/$1/members" "${AUTH[@]}" \
    -H 'Content-Type: application/json' -d "{\"member_key\":\"$2\",\"priority\":$3}" || true
}
put_generic(){ curl -s -o /dev/null -w '%{http_code}' -X PUT "$BASE/api/v1/repositories/$1/artifacts/$2" \
  "${AUTH[@]}" -H 'Content-Type: application/octet-stream' --data-binary "@$3" || true; }
put_module(){ # <repo> <ns/name/provider/version> <file>
  curl -s -o /dev/null -w '%{http_code}' -X PUT "$BASE/terraform/$1/v1/modules/$2" \
    "${AUTH[@]}" -H 'Content-Type: application/gzip' --data-binary "@$3" || true; }
# A gzip-magic payload of N bytes (the module upload checks the archive magic).
mkmodule(){ { printf '\037\213\010\000'; head -c $(( $2 - 4 )) /dev/urandom; } > "$1"; }

begin_suite "storage-integrity-serve-routes (#4323)"

begin_test "setup: admin login, generic hosted x2 + virtual, terraform hosted, fixtures"
TOK="$(login admin "$ADMIN_PASS")"
if [ -z "$TOK" ]; then infra_fail "admin login failed at $BASE"; end_suite; fi
AUTH=(-H "Authorization: Bearer $TOK")
SUF="$(( RANDOM % 90000 + 10000 ))$$"
G1="sisr-g1-$SUF"; G2="sisr-g2-$SUF"; V="sisr-v-$SUF"; T="sisr-tf-$SUF"
ERR=""
for spec in "$G1 generic local" "$G2 generic local" "$V generic virtual" "$T terraform local"; do
  set -- $spec
  [ "$(mkrepo "$1" "$2" "$3")" = "$1" ] || ERR="${ERR} create $1;"
done
c="$(add_member "$V" "$G1" 1)"; case "$c" in 2*) ;; *) ERR="${ERR} member $G1=HTTP$c;";; esac
c="$(add_member "$V" "$G2" 2)"; case "$c" in 2*) ;; *) ERR="${ERR} member $G2=HTTP$c;";; esac
head -c 200000 /dev/urandom > "$W/gen.bin"
head -c 200000 /dev/urandom > "$W/v1.bin"; head -c 200000 /dev/urandom > "$W/v2.bin"
head -c 200000 /dev/urandom > "$W/intact.bin"
mkmodule "$W/mod.tgz" 200000; mkmodule "$W/big.tgz" $(( 6 * 1024 * 1024 )); mkmodule "$W/okmod.tgz" 50000
for spec in "$G1 si/gen.bin gen" "$G1 shared/x.bin v1" "$G2 shared/x.bin v2" "$G1 si/intact.bin intact"; do
  set -- $spec
  c="$(put_generic "$1" "$2" "$W/$3.bin")"; case "$c" in 2*) ;; *) ERR="${ERR} put $1/$2=HTTP$c;";; esac
done
for spec in "sisr/net/aws/1.0.0 mod" "sisr/big/aws/1.0.0 big" "sisr/ok/aws/1.0.0 okmod"; do
  set -- $spec
  c="$(put_module "$T" "$1" "$W/$2.tgz")"; case "$c" in 2*) ;; *) ERR="${ERR} module $1=HTTP$c;";; esac
done
K_GEN="$(storage_key_like "$G1" si/gen.bin)"
K_V1="$(storage_key_like "$G1" shared/x.bin)"
K_MOD="$(storage_key_like "$T" '%sisr/net/aws/1.0.0%')"
K_BIG="$(storage_key_like "$T" '%sisr/big/aws/1.0.0%')"
for k in K_GEN K_V1 K_MOD K_BIG; do [ -n "${!k}" ] || ERR="${ERR} no storage key for $k;"; done
if [ -n "$ERR" ]; then infra_fail "fixture setup failed:${ERR}"; end_suite; fi
pass

U_GEN="$BASE/api/v1/repositories/$G1/download/si/gen.bin"
U_VIRT="$BASE/api/v1/repositories/$V/download/shared/x.bin"
U_MOD="$BASE/terraform/$T/v1/modules/sisr/net/aws/1.0.0/archive"
U_BIG="$BASE/terraform/$T/v1/modules/sisr/big/aws/1.0.0/archive"

begin_test "CONTROL: intact objects download byte-identical on the generic, virtual and Terraform routes"
reset_case
dl "$W/i1" "$BASE/api/v1/repositories/$G1/download/si/intact.bin"; note "generic: $(dl_desc "$W/i1")"
[ "$DL_CODE" = "200" ] && [ "$DL_SHA" = "$(sha_of "$W/intact.bin")" ] || fail_g "generic intact download"
dl "$W/i2" "$U_VIRT"; note "virtual: $(dl_desc "$W/i2")"
[ "$DL_CODE" = "200" ] && [ "$DL_SHA" = "$(sha_of "$W/v1.bin")" ] || fail_g "virtual serves the first member's bytes"
dl "$W/i3" "$BASE/terraform/$T/v1/modules/sisr/ok/aws/1.0.0/archive"; note "terraform: $(dl_desc "$W/i3")"
[ "$DL_CODE" = "200" ] && [ "$DL_SHA" = "$(sha_of "$W/okmod.tgz")" ] || fail_g "terraform intact archive"
finish_case "an intact download regressed"

begin_test "FIX #4323: a corrupted small object is 502 STORED_OBJECT_INTEGRITY with none of its bytes on the generic route"
reset_case
if ! flip "$G1" "$K_GEN" "$W/gen.bin"; then infra_fail "could not corrupt $K_GEN"; else
  expect_502 "generic GET" "$U_GEN" "$W/gen.bin"
  finish_case "the generic route did not fail closed with 502"
fi

begin_test "FIX #4323: a corrupted Terraform module archive (format route, shared hosted fetch) is 502"
reset_case
if ! flip "$T" "$K_MOD" "$W/mod.tgz"; then infra_fail "could not corrupt $K_MOD"; else
  expect_502 "terraform archive GET" "$U_MOD" "$W/mod.tgz"
  finish_case "the format route served a corrupted object"
fi

begin_test "FIX #4323: a virtual repository whose first member's object is corrupted answers 502, not the corrupt bytes and not the second member's"
reset_case
if ! flip "$G1" "$K_V1" "$W/v1.bin"; then infra_fail "could not corrupt $K_V1"; else
  expect_502 "virtual GET" "$U_VIRT" "$W/v1.bin"
  [ "$DL_SHA" != "$(sha_of "$W/v2.bin")" ] || fail_g "the virtual fell through to the second member's bytes"
  finish_case "the virtual did not fail closed"
fi

begin_test "FIX #4323: a corrupted object above the 4 MiB pre-check (format route) is never delivered complete"
reset_case
if ! flip "$T" "$K_BIG" "$W/big.tgz"; then infra_fail "could not corrupt $K_BIG"; else
  dl "$W/big.out" "$U_BIG"; note "terraform big archive: $(dl_desc /dev/null)"
  if [ "$DL_RC" -eq 0 ] && [ "$DL_CODE" = "200" ]; then
    fail_g "delivered as a complete 200 transfer (${DL_SIZE} bytes, sha ${DL_SHA:0:16})"
  fi
  finish_case "a large corrupted object was delivered complete"
fi

begin_test "CONTROL: a proper sub-range of the corrupted generic object is still served (206)"
reset_case
dl "$W/sub" "$U_GEN" -H 'Range: bytes=0-49'; note "Range 0-49: $(dl_desc /dev/null)"
[ "$DL_CODE" = "206" ] && [ "$DL_SHA" = "$(head -c 50 "$W/gen.bin" | sha256sum | awk '{print $1}')" ] \
  || fail_g "sub-range not served"
finish_case "sub-range regressed"

begin_test "setup (#4323 OCI): a docker repository with two layer blobs pushed over /v2"
reset_case
D="sisr-oci-$SUF"
ERR=""
[ "$(mkrepo "$D" docker)" = "$D" ] || ERR="${ERR} create $D;"
head -c 300000 /dev/urandom > "$W/layer-ok.bin"; head -c 300000 /dev/urandom > "$W/layer-bad.bin"
for f in layer-ok layer-bad; do
  c="$(curl -s -o /dev/null -w '%{http_code}' "${AUTH[@]}" -X POST -H 'Content-Type: application/octet-stream' \
    --data-binary "@$W/$f.bin" "$BASE/v2/$D/app/blobs/uploads/?digest=sha256:$(sha_of "$W/$f.bin")" || true)"
  [ "$c" = "201" ] || ERR="${ERR} blob $f=HTTP$c;"
done
K_OCI_BAD="$(psql_q "SELECT ob.storage_key FROM oci_blobs ob JOIN repositories r ON r.id=ob.repository_id
  WHERE r.key='$D' AND ob.digest='sha256:$(sha_of "$W/layer-bad.bin")' LIMIT 1;" | tr -d '[:space:]')"
[ -n "$K_OCI_BAD" ] || ERR="${ERR} no oci_blobs row for the blob to corrupt;"
if [ -n "$ERR" ]; then infra_fail "OCI fixture setup failed:${ERR}"; else pass; fi
U_OCI_OK="$BASE/v2/$D/app/blobs/sha256:$(sha_of "$W/layer-ok.bin")"
U_OCI_BAD="$BASE/v2/$D/app/blobs/sha256:$(sha_of "$W/layer-bad.bin")"

begin_test "CONTROL (#4323 OCI): an intact layer blob pulls byte-identical over /v2"
reset_case
dl "$W/oci-ok" "$U_OCI_OK"; note "GET intact blob: $(dl_desc /dev/null)"
[ "$DL_RC" -eq 0 ] && [ "$DL_CODE" = "200" ] && [ "$DL_SHA" = "$(sha_of "$W/layer-ok.bin")" ] || fail_g "intact blob pull"
finish_case "an intact OCI blob pull regressed"

begin_test "FIX #4323: a layer blob whose stored bytes no longer match its digest is never delivered complete over /v2"
reset_case
if [ -z "${K_OCI_BAD:-}" ] || ! flip "$D" "$K_OCI_BAD" "$W/layer-bad.bin"; then infra_fail "could not corrupt the OCI blob ${K_OCI_BAD:-}"; else
  dl "$W/oci-bad" "$U_OCI_BAD"; note "GET corrupted blob: $(dl_desc /dev/null)"
  if [ "$DL_RC" -eq 0 ] && [ "$DL_CODE" = "200" ] && [ "$DL_SIZE" = "300000" ]; then
    fail_g "the corrupted blob was delivered as a complete 200 transfer (sha ${DL_SHA:0:16}, the digest names $(sha_of "$W/layer-bad.bin" | cut -c1-16))"
  fi
  finish_case "a corrupted OCI blob was served to completion"
fi

end_suite
