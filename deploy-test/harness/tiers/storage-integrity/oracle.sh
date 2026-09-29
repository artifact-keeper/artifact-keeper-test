#!/usr/bin/env bash
# =============================================================================
# tiers/storage-integrity/oracle.sh: stored-object integrity gate
#   #3919 verify-on-download, #3910 admin storage scrub/repair,
#   #1570 ghost-object reindex (artifact-keeper#4322)
# =============================================================================
# The oracle damages objects DIRECTLY on the backend's storage (the filesystem
# volume, or the MinIO bucket when SI_STORAGE=s3: see the storage-integrity-s3
# tier), exactly as bit rot, a truncated write or an operator touching the
# bucket would, and then asserts what the product does about it.
#
#   #3919  A corrupted object (same length, longer, shorter) must NOT reach the
#          client as a complete transfer under the original X-Checksum-Sha256:
#          the plain GET and a whole-object Range (bytes=0-, bytes=-N,
#          bytes=0-(N-1)) must end in a curl transfer error. A proper
#          sub-range is still served, and intact objects are byte-identical.
#          Pre-fix: same-length and longer corruption stream as a clean 200 /
#          206 (curl exit 0) -> RED.
#   #3910  POST /api/v1/admin/storage-scrub {"repair":false} records the
#          damaged objects as `corrupt` findings (GET .../findings) and writes
#          nothing; {"repair":true} restores a content-addressed object from a
#          verified second copy (it then downloads clean) but only REPORTS a
#          path-keyed (Maven) object, leaving its bytes alone; protobuf commit
#          bundles are not flagged; bounded runs resume from the persisted
#          cursor; non-admins get 403; runs are audited.
#          Pre-fix: the routes do not exist (404) -> RED.
#   #1570  POST /api/v1/admin/repositories/{key}/reindex-storage registers a
#          settled Maven object that has no row (dry run first, then real) with
#          its real sha256/size, skips an object younger than 5 minutes,
#          reports a row whose object is gone, and is idempotent; the ghost
#          then downloads through the row-backed API route.
#          Pre-fix: the route does not exist (404) -> RED.
#   B1 / regression  a protobuf module push + commit-bundle download completes
#          with verification on (its row records the commit digest, not the
#          bundle's), and plain generic / Maven round-trips are unaffected.
#
# Not covered here (and why): DOWNLOAD_VERIFY_CHECKSUMS=false (the opt-out)
# needs a second backend env and compose.base.yml does not pass it through;
# a scrub cut off by the 120 s admin timeout (needs a very large store); the
# format-native download routes (follow-up artifact-keeper#4323).
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RELEASE_GATE=1,
# JUNIT_OUTPUT_DIR, COMMON_SH. SI_STORAGE (filesystem|s3) selects the tamper
# backend; the storage-integrity-s3 tier sets it.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

SI_STORAGE="${SI_STORAGE:-filesystem}"
BASE="$BASE_URL"
DBC="$DB_CONTAINER"
SLOT_PREFIX="${DB_CONTAINER%-db}"
BACKEND_CTR="${SLOT_PREFIX}-backend"
MINIO_CTR="${SLOT_PREFIX}-minio"
# Tamper helpers run in throwaway containers. Both images are already pulled by
# the profile (postgres = compose.base.yml, mc = storage.s3.yml): no network.
FS_HELPER_IMAGE="${SI_FS_HELPER_IMAGE:-postgres:16-alpine}"
MC_IMAGE="${SI_MC_IMAGE:-ghcr.io/artifact-keeper/ci-mirror/mc:RELEASE.2025-08-13T08-35-41Z}"
BUCKET="ak-artifacts"
# The reindex guard (RECENT_OBJECT_GUARD_MINUTES = 5) plus slack.
SETTLE_SECS=310

setup_workdir
W="$WORK_DIR"

# common.sh runs under `set -euo pipefail`: every probe helper below swallows
# its own failure (an empty value is then judged by the assertion that reads it)
# so a refused request can never abort the oracle mid-suite.
jqr(){ jq -r "$1" 2>/dev/null || true; }
psql_q(){ docker exec "$DBC" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null || true; }
login(){ curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"$1\",\"password\":\"$2\"}" | jqr '.access_token // .token // empty' || true; }
sha_of(){ sha256sum "$1" 2>/dev/null | awk '{print $1}' || true; }
size_of(){ wc -c < "$1" 2>/dev/null | tr -d '[:space:]'; }

FAILS=0
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); }
DETAIL=""
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ # <failure message>
  if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi
}

# --- storage access (the only backend-specific part) ------------------------
fsx(){ docker run --rm -i --volumes-from "$BACKEND_CTR" --entrypoint sh "$FS_HELPER_IMAGE" -c "$1"; }
mcx(){ docker run --rm -i --network "container:$MINIO_CTR" --entrypoint sh "$MC_IMAGE" -c \
  "mc alias set local http://localhost:9000 minioadmin minioadmin >/dev/null 2>&1 && $1"; }

# repo_root <repo-key>: the filesystem root of a repository (its storage_path).
repo_root(){ psql_q "SELECT storage_path FROM repositories WHERE key='$1';" | tr -d '[:space:]'; }
repo_id(){ psql_q "SELECT id FROM repositories WHERE key='$1';" | tr -d '[:space:]'; }

# obj_ref <repo-key> <storage-key>: where the object physically lives.
obj_ref(){
  if [ "$SI_STORAGE" = "s3" ]; then echo "local/${BUCKET}/$2"; else echo "$(repo_root "$1")/$2"; fi
}
obj_get(){ # <repo> <key> <outfile>
  local ref; ref="$(obj_ref "$1" "$2")"
  if [ "$SI_STORAGE" = "s3" ]; then mcx "mc cat '$ref'" > "$3"; else fsx "cat '$ref'" > "$3"; fi
}
obj_put(){ # <repo> <key> <infile>  (creates parent dirs; keeps backend ownership)
  local ref; ref="$(obj_ref "$1" "$2")"
  if [ "$SI_STORAGE" = "s3" ]; then
    mcx "mc pipe '$ref' >/dev/null" < "$3"
  else
    local root; root="$(repo_root "$1")"
    fsx "set -e; o=\$(stat -c %u:%g '$root'); d=\$(dirname '$ref'); mkdir -p \"\$d\"; cat > '$ref'; \
         chown \"\$o\" '$ref'; while [ \"\$d\" != '$root' ] && [ \"\$d\" != / ]; do chown \"\$o\" \"\$d\"; d=\$(dirname \"\$d\"); done" < "$3"
  fi
}
obj_rm(){ # <repo> <key>
  local ref; ref="$(obj_ref "$1" "$2")"
  if [ "$SI_STORAGE" = "s3" ]; then mcx "mc rm '$ref' >/dev/null"; else fsx "rm -f '$ref'"; fi
}
obj_backdate(){ # <repo> <key> <seconds-ago>   (filesystem only)
  local ref; ref="$(obj_ref "$1" "$2")"
  fsx "touch -d \"@\$(( \$(date +%s) - $3 ))\" '$ref'"
}
obj_sha(){ # <repo> <key> -> sha256 of the stored bytes ("" if unreadable)
  local f="$W/objsha.$$"; rm -f "$f"
  if obj_get "$1" "$2" "$f"; then sha_of "$f"; fi
  return 0
}

# damage <repo> <key> <flip|extend|truncate> <original-file>
# Rewrites the stored object from a damaged copy of the original and confirms
# the store now holds different bytes. Returns non-zero if the tamper did not
# take (an INFRA problem, not a product verdict).
damage(){
  local repo="$1" key="$2" mode="$3" orig="$4" bad="$W/bad.$$" n
  cp "$orig" "$bad"; n="$(size_of "$orig")"
  case "$mode" in
    flip)
      local b; b="$(od -An -tu1 -j 1000 -N1 "$bad" | tr -d '[:space:]')"
      if [ "$b" = "0" ]; then printf '\001'; else printf '\000'; fi \
        | dd of="$bad" bs=1 seek=1000 conv=notrunc 2>/dev/null ;;
    extend)   printf 'TRAILING-GARBAGE-NOT-IN-THE-RECORD' >> "$bad" ;;
    truncate) truncate -s $(( n - 4096 )) "$bad" ;;
  esac
  obj_put "$repo" "$key" "$bad" || return 1
  local now; now="$(obj_sha "$repo" "$key")"
  [ -n "$now" ] && [ "$now" = "$(sha_of "$bad")" ] && [ "$now" != "$(sha_of "$orig")" ]
}

# --- HTTP helpers ------------------------------------------------------------
# dl <outfile> <url> [curl args...] -> DL_RC DL_CODE DL_SIZE DL_HDR_SHA DL_SHA
dl(){
  local out="$1" url="$2"; shift 2
  local hdr="$W/hdr.$$" meta
  rm -f "$out" "$hdr"
  meta="$(curl -sS --fail --max-time 120 -o "$out" -D "$hdr" -w '%{http_code} %{size_download}' \
    "${AUTH[@]}" "$@" "$url" 2>"$W/curl.err")" && DL_RC=0 || DL_RC=$?
  DL_CODE="${meta%% *}"; DL_SIZE="${meta##* }"
  DL_HDR_SHA="$(grep -i '^x-checksum-sha256:' "$hdr" 2>/dev/null | awk '{print $2}' | tr -d '\r' || true)"
  DL_SHA="$(sha_of "$out")"
}
dl_desc(){ echo "curl_exit=$DL_RC http=$DL_CODE bytes=$DL_SIZE body_sha=${DL_SHA:0:16} hdr_sha=${DL_HDR_SHA:0:16} ($(head -c 200 "$W/curl.err" 2>/dev/null | tr '\n' ' ' || true))"; }

# expect_not_complete <label> <recorded-size> <url> [curl args]
# The client must NOT end with a successful transfer: curl --fail exits
# non-zero (the response was aborted short of Content-Length, or refused).
expect_not_complete(){
  local label="$1" n="$2" url="$3"; shift 3
  dl "$W/corrupt.out" "$url" "$@"
  note "$label: $(dl_desc)"
  if [ "$DL_RC" -eq 0 ]; then
    fail_g "$label was delivered as a COMPLETE, clean transfer (curl exit 0, HTTP $DL_CODE, $DL_SIZE of $n bytes, body sha ${DL_SHA:0:16}, X-Checksum-Sha256 ${DL_HDR_SHA:0:16}): the stored object no longer matches its record and the client cannot tell"
  fi
}

api(){ # <METHOD> <path> [json-body] -> body on stdout, HTTP code in $W/code
  local m="$1" p="$2" d="${3:-}"
  if [ -n "$d" ]; then
    curl -s --max-time 170 -o "$W/api.out" -w '%{http_code}' -X "$m" "$BASE$p" "${AUTH[@]}" \
      -H 'Content-Type: application/json' -d "$d" > "$W/code" || true
  else
    curl -s --max-time 170 -o "$W/api.out" -w '%{http_code}' -X "$m" "$BASE$p" "${AUTH[@]}" > "$W/code" || true
  fi
  cat "$W/api.out"
}
code(){ cat "$W/code" 2>/dev/null; }

mkrepo(){ # <key> <format>
  curl -s -X POST "$BASE/api/v1/repositories" "${AUTH[@]}" -H 'Content-Type: application/json' \
    -d "{\"key\":\"$1\",\"name\":\"$1\",\"format\":\"$2\",\"repo_type\":\"local\",\"is_public\":false}" \
    | jqr '.key // empty' || true
}
put_generic(){ # <repo> <path> <file> -> HTTP code
  curl -s -o /dev/null -w '%{http_code}' -X PUT "$BASE/api/v1/repositories/$1/artifacts/$2" \
    "${AUTH[@]}" -H 'Content-Type: application/octet-stream' --data-binary "@$3" || true
}
put_maven(){ # <repo> <path> <file> -> HTTP code
  curl -s -o /dev/null -w '%{http_code}' -X PUT "$BASE/maven/$1/$2" \
    "${AUTH[@]}" -H 'Content-Type: application/java-archive' --data-binary "@$3" || true
}
art_col(){ # <repo> <path> <column>
  psql_q "SELECT a.$3 FROM artifacts a JOIN repositories r ON r.id=a.repository_id
          WHERE r.key='$1' AND a.path='$2' AND a.is_deleted=false LIMIT 1;" | tr -d '[:space:]'
}
maven_key(){ # <repo> <path>: the physical key a Maven object lives under
  if [ "$SI_STORAGE" = "s3" ]; then echo "maven/$(repo_id "$1")/$2"; else echo "maven/$2"; fi
}
scrub(){ api POST /api/v1/admin/storage-scrub "$1"; }
findings(){ api GET "/api/v1/admin/storage-scrub/findings?limit=1000${1:+&status=$1}"; }
finding(){ # <findings-json> <object-id> <field> -> that finding's field ("" if none)
  echo "$1" | jq -r --arg id "$2" --arg f "$3" '[.[] | select(.object_id==$id)][0][$f] // empty' 2>/dev/null || true
}
finding_count(){ # <findings-json> <object-id>
  echo "$1" | jq -r --arg id "$2" '[.[] | select(.object_id==$id)] | length' 2>/dev/null || true
}
audit_phase(){ # <action> <phase>
  psql_q "SELECT count(*) FROM audit_log WHERE action='$1' AND details->>'phase'='$2';" | tr -d '[:space:]'
}
audit_count(){ psql_q "SELECT count(*) FROM audit_log WHERE action='$1';" | tr -d '[:space:]'; }
mkfile(){ head -c "$2" /dev/urandom > "$1"; }

# =============================================================================
begin_suite "storage-integrity-${SI_STORAGE}"

begin_test "setup: admin login, repositories and fixtures (${SI_STORAGE})"
TOK="$(login admin "$ADMIN_PASS")"
if [ -z "$TOK" ]; then infra_fail "admin login failed at $BASE"; end_suite; fi
AUTH=(-H "Authorization: Bearer $TOK")

SUF="$(( RANDOM % 90000 + 10000 ))$$"
R_GEN="si-gen-$SUF"; R_MVN="si-mvn-$SUF"; R_RIDX="si-ridx-$SUF"; R_PB="si-pb-$SUF"
for spec in "$R_GEN generic" "$R_MVN maven" "$R_RIDX maven" "$R_PB protobuf"; do
  k="${spec% *}"; f="${spec#* }"
  if [ "$(mkrepo "$k" "$f")" != "$k" ]; then infra_fail "could not create $f repository $k"; end_suite; fi
done

# One random payload per scenario so no two scenarios share a digest (and so
# no scenario accidentally donates a repair copy to another).
N=300000
for c in intact flip long short repairme pathkeyed mvnrt ghost young real gone; do
  mkfile "$W/$c.bin" "$N"
done
SETUP_ERR=""
for c in intact flip long short repairme; do
  rc="$(put_generic "$R_GEN" "si/$c.bin" "$W/$c.bin")"
  case "$rc" in 2*) ;; *) SETUP_ERR="${SETUP_ERR} generic $c=HTTP$rc";; esac
done
# Verified second copies: `repairme` also lives in the Maven repo (a donor for
# the CAS repair); `pathkeyed` lives in both too, but it is the MAVEN copy that
# gets damaged, so a good copy exists and still must not be used.
MVN_REPAIR_PATH="com/si/donor/1.0/donor-1.0.jar"
MVN_PK_PATH="com/si/pathkeyed/1.0/pathkeyed-1.0.jar"
MVN_RT_PATH="com/si/roundtrip/1.0/roundtrip-1.0.jar"
rc="$(put_maven "$R_MVN" "$MVN_REPAIR_PATH" "$W/repairme.bin")"; case "$rc" in 2*) ;; *) SETUP_ERR="${SETUP_ERR} maven donor=HTTP$rc";; esac
rc="$(put_maven "$R_MVN" "$MVN_PK_PATH" "$W/pathkeyed.bin")";   case "$rc" in 2*) ;; *) SETUP_ERR="${SETUP_ERR} maven pathkeyed=HTTP$rc";; esac
rc="$(put_generic "$R_GEN" "si/pathkeyed-good-copy.bin" "$W/pathkeyed.bin")"; case "$rc" in 2*) ;; *) SETUP_ERR="${SETUP_ERR} generic pathkeyed copy=HTTP$rc";; esac

declare -A KEY ID
for c in intact flip long short repairme; do
  KEY[$c]="$(art_col "$R_GEN" "si/$c.bin" storage_key)"
  ID[$c]="$(art_col "$R_GEN" "si/$c.bin" id)"
  [ -n "${KEY[$c]}" ] || SETUP_ERR="${SETUP_ERR} no row for si/$c.bin"
done
KEY[pathkeyed]="$(art_col "$R_MVN" "$MVN_PK_PATH" storage_key)"
ID[pathkeyed]="$(art_col "$R_MVN" "$MVN_PK_PATH" id)"
[ -n "${KEY[pathkeyed]}" ] || SETUP_ERR="${SETUP_ERR} no row for maven $MVN_PK_PATH"
echo "-- storage keys: flip=${KEY[flip]:-?} pathkeyed=${KEY[pathkeyed]:-?}"

# #1570 fixtures that must be in place EARLY on s3 (object age cannot be
# backdated in MinIO, so the ghost has to be written now and allowed to settle
# while the other scenarios run).
GHOST_PATH="com/si/ghost/1.0/ghost-1.0.jar"
YOUNG_PATH="com/si/young/1.0/young-1.0.jar"
REAL_PATH="com/si/real/1.0/real-1.0.jar"
GONE_PATH="com/si/gone/1.0/gone-1.0.jar"
rc="$(put_maven "$R_RIDX" "$REAL_PATH" "$W/real.bin")"; case "$rc" in 2*) ;; *) SETUP_ERR="${SETUP_ERR} maven real=HTTP$rc";; esac
rc="$(put_maven "$R_RIDX" "$GONE_PATH" "$W/gone.bin")"; case "$rc" in 2*) ;; *) SETUP_ERR="${SETUP_ERR} maven gone=HTTP$rc";; esac
GHOST_KEY="$(maven_key "$R_RIDX" "$GHOST_PATH")"
YOUNG_KEY="$(maven_key "$R_RIDX" "$YOUNG_PATH")"
GONE_KEY="$(art_col "$R_RIDX" "$GONE_PATH" storage_key)"
obj_put "$R_RIDX" "$GHOST_KEY" "$W/ghost.bin" || SETUP_ERR="${SETUP_ERR} ghost drop failed"
sha1sum "$W/ghost.bin" | awk '{printf "%s", $1}' > "$W/ghost.sha1"
obj_put "$R_RIDX" "$GHOST_KEY.sha1" "$W/ghost.sha1" || SETUP_ERR="${SETUP_ERR} ghost sidecar drop failed"
GHOST_DROPPED_AT="$(date +%s)"
if [ "$SI_STORAGE" != "s3" ]; then
  obj_backdate "$R_RIDX" "$GHOST_KEY" 900 && obj_backdate "$R_RIDX" "$GHOST_KEY.sha1" 900 \
    || SETUP_ERR="${SETUP_ERR} ghost backdate failed"
fi
if [ -z "$GONE_KEY" ] || ! obj_rm "$R_RIDX" "$GONE_KEY"; then SETUP_ERR="${SETUP_ERR} could not remove the 'gone' object"; fi
[ "$(obj_sha "$R_RIDX" "$GHOST_KEY")" = "$(sha_of "$W/ghost.bin")" ] || SETUP_ERR="${SETUP_ERR} ghost not readable back from the store"

if [ -n "$SETUP_ERR" ]; then infra_fail "fixture setup failed:${SETUP_ERR}"; end_suite; fi
pass

# =============================================================================
begin_test "regression: intact generic artifact downloads byte-identical, digest header matches, sub-range served"
reset_case
U_INTACT="$BASE/api/v1/repositories/$R_GEN/download/si/intact.bin"
dl "$W/intact.out" "$U_INTACT"; note "GET intact: $(dl_desc)"
[ "$DL_RC" -eq 0 ] && [ "$DL_CODE" = "200" ] || fail_g "intact download failed ($(dl_desc))"
[ "$DL_SHA" = "$(sha_of "$W/intact.bin")" ] || fail_g "intact body is not byte-identical"
[ "$DL_HDR_SHA" = "$(sha_of "$W/intact.bin")" ] || fail_g "X-Checksum-Sha256 ($DL_HDR_SHA) != sha of uploaded bytes"
dl "$W/intact.r.out" "$U_INTACT" -H 'Range: bytes=0-'; note "GET intact bytes=0-: $(dl_desc)"
[ "$DL_RC" -eq 0 ] && [ "$DL_SHA" = "$(sha_of "$W/intact.bin")" ] || fail_g "intact whole-object Range failed ($(dl_desc))"
dl "$W/intact.s.out" "$U_INTACT" -H 'Range: bytes=100-199'; note "GET intact bytes=100-199: $(dl_desc)"
[ "$DL_RC" -eq 0 ] && [ "$DL_CODE" = "206" ] && [ "$DL_SHA" = "$(tail -c +101 "$W/intact.bin" | head -c 100 | sha256sum | awk '{print $1}')" ] \
  || fail_g "intact sub-range not served correctly ($(dl_desc))"
finish_case "intact download regressed"

# =============================================================================
begin_test "#3919: same-length corruption is NOT delivered as a complete body under the original X-Checksum-Sha256"
reset_case
U_FLIP="$BASE/api/v1/repositories/$R_GEN/download/si/flip.bin"
if ! damage "$R_GEN" "${KEY[flip]}" flip "$W/flip.bin"; then
  infra_fail "could not corrupt ${KEY[flip]} on the ${SI_STORAGE} store"
else
  expect_not_complete "GET (1 byte flipped)" "$N" "$U_FLIP"
  finish_case "corrupted object served as a clean, complete download (pre-#3919 behaviour)"
fi

begin_test "#3919: a whole-object Range (bytes=0-, bytes=-N, bytes=0-(N-1)) of the corrupted object is verified too"
reset_case
expect_not_complete "Range bytes=0-" "$N" "$U_FLIP" -H 'Range: bytes=0-'
expect_not_complete "Range bytes=-$N" "$N" "$U_FLIP" -H "Range: bytes=-$N"
expect_not_complete "Range bytes=0-$((N-1))" "$N" "$U_FLIP" -H "Range: bytes=0-$((N-1))"
finish_case "a Range covering the whole corrupted object was delivered complete"

begin_test "#3919: a proper sub-range of the corrupted object is still served (206, exact window)"
reset_case
dl "$W/flip.sub" "$U_FLIP" -H 'Range: bytes=0-99'; note "Range bytes=0-99: $(dl_desc)"
if [ "$DL_RC" -ne 0 ] || [ "$DL_CODE" != "206" ] || [ "$DL_SIZE" != "100" ] \
   || [ "$DL_SHA" != "$(head -c 100 "$W/flip.bin" | sha256sum | awk '{print $1}')" ]; then
  fail_g "sub-range 0-99 (before the damaged byte) not served as the exact 100-byte window"
fi
finish_case "sub-range serving regressed"

begin_test "#3919: an object LONGER than recorded is not delivered as a clean download"
reset_case
if ! damage "$R_GEN" "${KEY[long]}" extend "$W/long.bin"; then
  infra_fail "could not extend ${KEY[long]} on the ${SI_STORAGE} store"
else
  expect_not_complete "GET (trailing bytes appended)" "$N" "$BASE/api/v1/repositories/$R_GEN/download/si/long.bin"
  finish_case "an object longer than its record was delivered as a clean, complete download"
fi

begin_test "#3919: an object SHORTER than recorded is not delivered complete"
reset_case
if ! damage "$R_GEN" "${KEY[short]}" truncate "$W/short.bin"; then
  infra_fail "could not truncate ${KEY[short]} on the ${SI_STORAGE} store"
else
  expect_not_complete "GET (truncated by 4096 bytes)" "$N" "$BASE/api/v1/repositories/$R_GEN/download/si/short.bin"
  finish_case "a truncated object was delivered as a complete download"
fi

# =============================================================================
begin_test "regression: Maven upload/download round-trip (native and API routes)"
reset_case
rc="$(put_maven "$R_MVN" "$MVN_RT_PATH" "$W/mvnrt.bin")"; note "PUT maven: HTTP $rc"
case "$rc" in 2*) ;; *) fail_g "maven PUT failed (HTTP $rc)";; esac
dl "$W/mvnrt.n" "$BASE/maven/$R_MVN/$MVN_RT_PATH"; note "GET /maven: $(dl_desc)"
[ "$DL_RC" -eq 0 ] && [ "$DL_SHA" = "$(sha_of "$W/mvnrt.bin")" ] || fail_g "maven native GET not byte-identical"
dl "$W/mvnrt.a" "$BASE/api/v1/repositories/$R_MVN/download/$MVN_RT_PATH"; note "GET API: $(dl_desc)"
[ "$DL_RC" -eq 0 ] && [ "$DL_SHA" = "$(sha_of "$W/mvnrt.bin")" ] || fail_g "maven API download not byte-identical"
finish_case "Maven round-trip regressed"

begin_test "regression (B1): protobuf module push + commit-bundle download completes with verification on"
reset_case
PROTO_B64="$(printf 'syntax = "proto3";\npackage si.v1;\nmessage Thing { string id = 1; int64 n = 2; }\n' | base64 | tr -d '\n')"
PB_RESP="$(api POST "/proto/$R_PB/buf.registry.module.v1beta1.UploadService/Upload" \
  "{\"contents\":[{\"moduleRef\":{\"owner\":\"acme\",\"module\":\"si$SUF\"},\"files\":[{\"path\":\"acme/si/v1/thing.proto\",\"content\":\"$PROTO_B64\"}]}]}")"
note "BSR Upload: HTTP $(code) $(echo "$PB_RESP" | head -c 200)"
PB_PATH="$(psql_q "SELECT a.path FROM artifacts a JOIN repositories r ON r.id=a.repository_id
                   WHERE r.key='$R_PB' AND a.path LIKE 'modules/%/commits/%' LIMIT 1;" | tr -d '[:space:]')"
PB_SIZE="$(art_col "$R_PB" "$PB_PATH" size_bytes)"
if [ "$(code)" != "200" ] || [ -z "$PB_PATH" ]; then
  fail_g "protobuf module push failed (HTTP $(code), commit row '$PB_PATH')"
else
  dl "$W/pb.out" "$BASE/api/v1/repositories/$R_PB/download/$PB_PATH"; note "GET commit bundle: $(dl_desc) (row size $PB_SIZE)"
  [ "$DL_RC" -eq 0 ] && [ "$DL_CODE" = "200" ] && [ "$DL_SIZE" = "$PB_SIZE" ] \
    || fail_g "protobuf commit bundle download did not complete (its row records the commit digest, not the bundle digest: verification must not abort it)"
fi
finish_case "protobuf commit download aborted or failed"

# =============================================================================
begin_test "#3910: non-admin is refused (403) on scrub, findings and reindex"
reset_case
NA_USER="si-user-$SUF"; NA_PASS="SiUserPass!2026x$SUF"
curl -s -o /dev/null -X POST "$BASE/api/v1/users" "${AUTH[@]}" -H 'Content-Type: application/json' \
  -d "{\"username\":\"$NA_USER\",\"email\":\"$NA_USER@t.test\",\"password\":\"$NA_PASS\",\"is_admin\":false}"
NA_TOK="$(login "$NA_USER" "$NA_PASS")"
if [ -z "$NA_TOK" ]; then
  infra_fail "could not create/login the non-admin user $NA_USER"
else
  for spec in "POST /api/v1/admin/storage-scrub {\"repair\":false}" \
              "GET /api/v1/admin/storage-scrub/findings -" \
              "POST /api/v1/admin/repositories/$R_RIDX/reindex-storage {\"dry_run\":true}"; do
    read -r m p d <<<"$spec"
    if [ "$d" = "-" ]; then
      rc="$(curl -s -o /dev/null -w '%{http_code}' -X "$m" "$BASE$p" -H "Authorization: Bearer $NA_TOK" || true)"
    else
      rc="$(curl -s -o /dev/null -w '%{http_code}' -X "$m" "$BASE$p" -H "Authorization: Bearer $NA_TOK" \
        -H 'Content-Type: application/json' -d "$d" || true)"
    fi
    note "non-admin $m $p -> HTTP $rc"
    [ "$rc" = "403" ] || fail_g "non-admin $m $p -> HTTP $rc (want 403)"
  done
  finish_case "admin storage-integrity routes are not admin-gated with 403 (or do not exist: pre-#3910/#1570)"
fi

# =============================================================================
begin_test "#3910: report-only scrub (repair:false) records every damaged object and writes nothing"
reset_case
PRE_REPAIRME_OK=1
damage "$R_GEN" "${KEY[repairme]}" flip "$W/repairme.bin" || PRE_REPAIRME_OK=0
if [ "$PRE_REPAIRME_OK" -ne 1 ]; then
  infra_fail "could not corrupt ${KEY[repairme]} on the ${SI_STORAGE} store"
else
  BAD_REPAIRME_SHA="$(obj_sha "$R_GEN" "${KEY[repairme]}")"
  RES="$(scrub "{\"repair\":false,\"repository\":\"$R_GEN\"}")"
  note "scrub repair=false repo=$R_GEN: HTTP $(code) $(echo "$RES" | jq -c 'del(.findings)' 2>/dev/null || echo "$RES" | head -c 200)"
  if [ "$(code)" != "200" ]; then
    fail_g "POST /api/v1/admin/storage-scrub -> HTTP $(code) (route missing: pre-#3910 image?)"
  else
    C="$(echo "$RES" | jqr '.corrupt')"; R="$(echo "$RES" | jqr '.repaired')"
    [ "$C" = "4" ] || fail_g "corrupt=$C (want 4: flip, long, short, repairme)"
    [ "$R" = "0" ] || fail_g "repaired=$R on a repair:false run (want 0)"
    [ "$(echo "$RES" | jqr '.intact')" -ge 2 ] 2>/dev/null || fail_g "intact objects not counted as intact"
    FJ="$(findings corrupt)"; note "GET findings?status=corrupt: HTTP $(code), $(echo "$FJ" | jq 'length' 2>/dev/null) rows"
    for c in flip long short repairme; do
      st="$(finding "$FJ" "${ID[$c]}" status)"
      [ "$st" = "corrupt" ] || fail_g "no 'corrupt' finding for $c (${ID[$c]})"
    done
    # A length change is part of the verdict: the truncated object's finding
    # carries its real size.
    AS="$(finding "$FJ" "${ID[short]}" actual_size)"
    [ "$AS" = "$((N-4096))" ] || fail_g "truncated object's finding actual_size=$AS (want $((N-4096)))"
    ok="$(finding_count "$FJ" "${ID[intact]}")"
    [ "$ok" = "0" ] || fail_g "the intact object has a finding"
    [ "$(obj_sha "$R_GEN" "${KEY[repairme]}")" = "$BAD_REPAIRME_SHA" ] || fail_g "a repair:false run rewrote stored bytes"
  fi
  finish_case "report-only scrub missing, wrong, or it wrote to storage"
fi

begin_test "#3910: repair:true restores a content-addressed object from a verified copy; it then downloads clean"
reset_case
RES="$(scrub "{\"repair\":true,\"repository\":\"$R_GEN\"}")"
note "scrub repair=true repo=$R_GEN: HTTP $(code) $(echo "$RES" | jq -c 'del(.findings)' 2>/dev/null || echo "$RES" | head -c 200)"
if [ "$(code)" != "200" ]; then
  fail_g "POST /api/v1/admin/storage-scrub -> HTTP $(code) (route missing: pre-#3910 image?)"
else
  R="$(echo "$RES" | jqr '.repaired')"; C="$(echo "$RES" | jqr '.corrupt')"
  [ "$R" = "1" ] || fail_g "repaired=$R (want 1: repairme, whose bytes also live in $R_MVN)"
  [ "$C" = "3" ] || fail_g "corrupt=$C after repair (want 3: flip/long/short have no good copy)"
  [ "$(obj_sha "$R_GEN" "${KEY[repairme]}")" = "$(sha_of "$W/repairme.bin")" ] \
    || fail_g "stored repairme bytes were not restored"
  FJ="$(findings repaired)"
  st="$(finding "$FJ" "${ID[repairme]}" status)"
  [ "$st" = "repaired" ] || fail_g "no 'repaired' finding for repairme (${ID[repairme]})"
  FJ="$(findings corrupt)"
  dt="$(finding "$FJ" "${ID[flip]}" detail)"
  note "flip finding detail: $dt"
  echo "$dt" | grep -qi 'no verified good copy' || fail_g "flip (no donor) finding detail='$dt' (want 'no verified good copy')"
  dl "$W/repairme.out" "$BASE/api/v1/repositories/$R_GEN/download/si/repairme.bin"; note "GET repaired: $(dl_desc)"
  [ "$DL_RC" -eq 0 ] && [ "$DL_SHA" = "$(sha_of "$W/repairme.bin")" ] || fail_g "repaired object does not download byte-identical"
  expect_not_complete "GET flip after repair run (still no good copy)" "$N" "$U_FLIP"
fi
finish_case "CAS repair from a verified copy missing or wrong"

begin_test "#3910: a path-keyed (Maven) object is reported but NOT rewritten, even with a good copy available"
reset_case
if ! damage "$R_MVN" "${KEY[pathkeyed]}" flip "$W/pathkeyed.bin"; then
  infra_fail "could not corrupt ${KEY[pathkeyed]} on the ${SI_STORAGE} store"
else
  BAD_PK_SHA="$(obj_sha "$R_MVN" "${KEY[pathkeyed]}")"
  RES="$(scrub "{\"repair\":true,\"repository\":\"$R_MVN\"}")"
  note "scrub repair=true repo=$R_MVN: HTTP $(code) $(echo "$RES" | jq -c 'del(.findings)' 2>/dev/null || echo "$RES" | head -c 200)"
  if [ "$(code)" != "200" ]; then
    fail_g "POST /api/v1/admin/storage-scrub -> HTTP $(code) (route missing: pre-#3910 image?)"
  else
    [ "$(echo "$RES" | jqr '.repaired')" = "0" ] || fail_g "repaired=$(echo "$RES" | jqr '.repaired') for a path-keyed object (want 0)"
    [ "$(echo "$RES" | jqr '.corrupt')" = "1" ] || fail_g "corrupt=$(echo "$RES" | jqr '.corrupt') (want 1)"
    FJ="$(findings corrupt)"
    dt="$(finding "$FJ" "${ID[pathkeyed]}" detail)"
    note "path-keyed finding detail: $dt"
    echo "$dt" | grep -qi 'path-keyed' || fail_g "path-keyed finding missing or detail='$dt' (want 'path-keyed ... reported only')"
    [ "$(obj_sha "$R_MVN" "${KEY[pathkeyed]}")" = "$BAD_PK_SHA" ] || fail_g "the path-keyed object was REWRITTEN (a republish could have been overwritten)"
  fi
  finish_case "path-keyed object not reported, or rewritten"
fi

begin_test "#3910: protobuf commit bundles are not flagged by the scrub (B1)"
reset_case
RES="$(scrub "{\"repair\":true,\"repository\":\"$R_PB\"}")"
note "scrub repair=true repo=$R_PB: HTTP $(code) $(echo "$RES" | jq -c 'del(.findings)' 2>/dev/null || echo "$RES" | head -c 200)"
if [ "$(code)" != "200" ]; then
  fail_g "POST /api/v1/admin/storage-scrub -> HTTP $(code) (route missing: pre-#3910 image?)"
else
  bad="$(echo "$RES" | jqr '.corrupt + .missing + .repaired')"
  [ "$bad" = "0" ] || fail_g "protobuf repo produced $bad corrupt/missing/repaired findings"
  PBR="$(repo_id "$R_PB")"
  nf="$(psql_q "SELECT count(*) FROM storage_scrub_findings WHERE repository_id='$PBR';" | tr -d '[:space:]')"
  [ "$nf" = "0" ] || fail_g "storage_scrub_findings has $nf rows for the protobuf repo"
  dl "$W/pb2.out" "$BASE/api/v1/repositories/$R_PB/download/$PB_PATH"; note "GET commit bundle after scrub: $(dl_desc)"
  [ "$DL_RC" -eq 0 ] && [ "$DL_SIZE" = "$PB_SIZE" ] || fail_g "protobuf commit bundle no longer downloads after the scrub (repair touched it?)"
fi
finish_case "protobuf commit bundles flagged or damaged by the scrub"

begin_test "#3910: bounded instance-wide runs resume from the persisted cursor"
reset_case
RES1="$(scrub '{"repair":false,"max_objects":1}')"; C1CODE="$(code)"
CUR1="$(psql_q "SELECT artifact_cursor FROM storage_scrub_state WHERE scope='instance';" | tr -d '[:space:]')"
RES2="$(scrub '{"repair":false,"max_objects":1}')"; C2CODE="$(code)"
CUR2="$(psql_q "SELECT artifact_cursor FROM storage_scrub_state WHERE scope='instance';" | tr -d '[:space:]')"
note "run1: HTTP $C1CODE checked=$(echo "$RES1" | jqr '.objects_checked') cursor=$CUR1"
note "run2: HTTP $C2CODE checked=$(echo "$RES2" | jqr '.objects_checked') cursor=$CUR2"
if [ "$C1CODE" != "200" ] || [ "$C2CODE" != "200" ]; then
  fail_g "bounded scrub runs failed (HTTP $C1CODE / $C2CODE; route missing: pre-#3910 image?)"
else
  [ "$(echo "$RES1" | jqr '.objects_checked')" = "1" ] && [ "$(echo "$RES2" | jqr '.objects_checked')" = "1" ] \
    || fail_g "max_objects=1 not honoured"
  [ "$(echo "$RES1" | jqr '.cycle_completed')" = "false" ] || fail_g "a 1-object run claims cycle_completed"
  if [ -z "$CUR1" ] || [ -z "$CUR2" ]; then
    fail_g "no instance cursor persisted in storage_scrub_state"
  else
    adv="$(psql_q "SELECT '$CUR2'::uuid > '$CUR1'::uuid;" | tr -d '[:space:]')"
    [ "$adv" = "t" ] || fail_g "cursor did not advance ($CUR1 -> $CUR2): the second run restarted instead of resuming"
  fi
fi
finish_case "scrub cursor resume missing or wrong"

begin_test "#3910: every admin scrub run is audited (STORAGE_SCRUB_RUN, started before the walk and completed after)"
reset_case
# 6 admin runs above (3 scoped R_GEN/R_MVN/R_PB + repair:false + 2 bounded).
# A run cut off mid-walk (the 120 s admin timeout) must still leave a trace, so
# each run is audited once as it starts and again with its outcome.
AS_START=""; AS_DONE=""
for _ in 1 2 3 4 5 6 7 8 9 10; do
  AS_START="$(audit_phase STORAGE_SCRUB_RUN started)"; AS_DONE="$(audit_phase STORAGE_SCRUB_RUN completed)"
  [ "${AS_START:-0}" -ge 6 ] 2>/dev/null && [ "${AS_DONE:-0}" -ge 6 ] 2>/dev/null && break; sleep 1
done
note "audit_log STORAGE_SCRUB_RUN rows: total=$(audit_count STORAGE_SCRUB_RUN) started=${AS_START:-?} completed=${AS_DONE:-?}"
[ "${AS_START:-0}" -ge 6 ] 2>/dev/null || fail_g "only ${AS_START:-0} 'started' STORAGE_SCRUB_RUN audit rows for 6 runs (a cut-off run would leave no trace)"
[ "${AS_DONE:-0}" -ge 6 ] 2>/dev/null || fail_g "only ${AS_DONE:-0} 'completed' STORAGE_SCRUB_RUN audit rows for 6 runs"
finish_case "scrub runs not audited"

# =============================================================================
# #1570. On s3 the ghost was written during setup and must first age past the
# 5-minute in-flight guard, which is itself an assertion (a fresh run must
# hold it back).
reindex(){ api POST "/api/v1/admin/repositories/$R_RIDX/reindex-storage" "$1"; }
ghost_rows(){ psql_q "SELECT count(*) FROM artifacts a JOIN repositories r ON r.id=a.repository_id WHERE r.key='$R_RIDX' AND a.path='$1';" | tr -d '[:space:]'; }

if [ "$SI_STORAGE" = "s3" ]; then
  begin_test "#1570: an unregistered object younger than 5 minutes is held back (s3: the fresh ghost)"
  reset_case
  RES="$(reindex '{"dry_run":false}')"
  note "reindex (ghost age $(( $(date +%s) - GHOST_DROPPED_AT ))s): HTTP $(code) $(echo "$RES" | head -c 400)"
  if [ "$(code)" != "200" ]; then
    fail_g "reindex-storage -> HTTP $(code) (route missing: pre-#1570 image?)"
  else
    [ "$(echo "$RES" | jqr '.registered')" = "0" ] || fail_g "a <5-minute-old object was registered"
    [ "$(echo "$RES" | jqr '.skipped_recent')" -ge 1 ] 2>/dev/null || fail_g "skipped_recent=$(echo "$RES" | jqr '.skipped_recent') (want >=1)"
    [ "$(ghost_rows "$GHOST_PATH")" = "0" ] || fail_g "the fresh ghost got a row"
  fi
  RIDX_ROUTE="$(code)"
  finish_case "recent-object guard missing"
  WAIT=$(( GHOST_DROPPED_AT + SETTLE_SECS - $(date +%s) ))
  # Only worth waiting when the route exists (a pre-#1570 image answers 404
  # here and every reindex assertion below fails regardless).
  if [ "$RIDX_ROUTE" = "200" ] && [ "$WAIT" -gt 0 ]; then echo "-- waiting ${WAIT}s for the ghost to age past the 5-minute guard"; sleep "$WAIT"; fi
fi

# The young object is written right before the run on both backends.
obj_put "$R_RIDX" "$YOUNG_KEY" "$W/young.bin" || true

begin_test "#1570: reindex dry run reports the settled ghost, holds back the young object, reports the missing object, writes nothing"
reset_case
PRE="$(curl -s -o /dev/null -w '%{http_code}' "${AUTH[@]}" "$BASE/api/v1/repositories/$R_RIDX/download/$GHOST_PATH" || true)"
note "pre-reindex API GET ghost: HTTP $PRE (row-backed route; the ghost has no row)"
[ "$PRE" = "404" ] || fail_g "ghost already served by the row-backed route before reindex (HTTP $PRE): fixture broken?"
RES="$(reindex '{"dry_run":true}')"
note "reindex dry_run: HTTP $(code) $(echo "$RES" | head -c 600)"
if [ "$(code)" != "200" ]; then
  fail_g "POST /api/v1/admin/repositories/$R_RIDX/reindex-storage -> HTTP $(code) (route missing: pre-#1570 image?)"
else
  [ "$(echo "$RES" | jqr '.registered')" = "1" ] || fail_g "dry run registered=$(echo "$RES" | jqr '.registered') (want 1: the ghost only)"
  echo "$RES" | jq -e --arg p "$GHOST_PATH" '.registered_paths | index($p)' >/dev/null 2>&1 \
    || fail_g "registered_paths does not name $GHOST_PATH"
  [ "$(echo "$RES" | jqr '.skipped_recent')" -ge 1 ] 2>/dev/null || fail_g "young object not counted in skipped_recent"
  [ "$(echo "$RES" | jqr '.missing_objects')" = "1" ] || fail_g "missing_objects=$(echo "$RES" | jqr '.missing_objects') (want 1: $GONE_PATH)"
  echo "$RES" | jq -e --arg p "$GONE_PATH" '.missing_object_paths | index($p)' >/dev/null 2>&1 \
    || fail_g "missing_object_paths does not name $GONE_PATH"
  [ "$(ghost_rows "$GHOST_PATH")" = "0" ] || fail_g "dry run wrote a row"
fi
finish_case "reindex dry run missing or wrong"

begin_test "#1570: reindex registers the ghost with its real sha256/size; it then downloads; young object skipped; re-run is a no-op"
reset_case
RES="$(reindex '{"dry_run":false}')"
note "reindex: HTTP $(code) $(echo "$RES" | head -c 600)"
if [ "$(code)" != "200" ]; then
  fail_g "reindex-storage -> HTTP $(code) (route missing: pre-#1570 image?)"
else
  [ "$(echo "$RES" | jqr '.registered')" = "1" ] || fail_g "registered=$(echo "$RES" | jqr '.registered') (want 1)"
  RS="$(art_col "$R_RIDX" "$GHOST_PATH" checksum_sha256)"; RZ="$(art_col "$R_RIDX" "$GHOST_PATH" size_bytes)"
  note "ghost row: sha256=$RS size=$RZ"
  [ "$RS" = "$(sha_of "$W/ghost.bin")" ] || fail_g "registered sha256 '$RS' != real $(sha_of "$W/ghost.bin")"
  [ "$RZ" = "$N" ] || fail_g "registered size '$RZ' != $N"
  [ "$(ghost_rows "$YOUNG_PATH")" = "0" ] || fail_g "the <5-minute-old object was registered"
  [ "$(ghost_rows "$GHOST_PATH.sha1")" = "0" ] || fail_g "the .sha1 sidecar was registered as an artifact"
  dl "$W/ghost.out" "$BASE/api/v1/repositories/$R_RIDX/download/$GHOST_PATH"; note "API GET ghost: $(dl_desc)"
  [ "$DL_RC" -eq 0 ] && [ "$DL_SHA" = "$(sha_of "$W/ghost.bin")" ] && [ "$DL_HDR_SHA" = "$(sha_of "$W/ghost.bin")" ] \
    || fail_g "reindexed ghost does not download byte-identical with its digest header"
  RES2="$(reindex '{"dry_run":false}')"; note "re-run: HTTP $(code) registered=$(echo "$RES2" | jqr '.registered')"
  [ "$(echo "$RES2" | jqr '.registered')" = "0" ] || fail_g "re-run registered again (not idempotent)"
  RC="$(ghost_rows "$GHOST_PATH")"; [ "$RC" = "1" ] || fail_g "ghost has $RC rows after two runs (want 1)"
  AC=""
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    AC="$(audit_count STORAGE_REINDEX_RUN)"; [ "${AC:-0}" -ge 3 ] 2>/dev/null && break; sleep 1
  done
  note "audit_log STORAGE_REINDEX_RUN rows: ${AC:-?}"
  [ "${AC:-0}" -ge 3 ] 2>/dev/null || fail_g "reindex runs not audited (${AC:-0} rows)"
fi
finish_case "ghost-object reindex missing or wrong"

end_suite
