#!/usr/bin/env bash
# =============================================================================
# tiers/oci-usage-counts-layers-once/oracle.sh
#   #4483 a Docker/OCI repository's usage, ledger and quota count each layer
#         once: the manifest row (which records the image size) adds 0
#   #4505 a virtual created WITH members reports their storage in the create
#         response's member_storage_used_bytes, equal to the next GET
# See the manifest for the bugs, the primitives and the gates.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"
: "${DTF_SLOT:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

BASE="$BASE_URL"
DBC="$DB_CONTAINER"
MCT="application/vnd.docker.distribution.manifest.v2+json"

setup_workdir
W="$WORK_DIR"

jqr(){ jq -r "$1" 2>/dev/null || true; }
psql_q(){ docker exec "$DBC" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]' || true; }
sha_of(){ sha256sum "$1" 2>/dev/null | awk '{print $1}' || true; }
size_of(){ wc -c < "$1" 2>/dev/null | tr -d '[:space:]' || true; }

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

auth(){ printf 'Authorization: Bearer %s' "$TOK"; }
repo_get(){ curl -s -H "$(auth)" "$BASE/api/v1/repositories/$1"; }
used_of(){ repo_get "$1" | jqr '.storage_used_bytes // empty'; }
ledger_of(){ # <key> -> "hosted|proxy|oci" from repository_usage_ledger
  docker exec "$DBC" psql -U registry -d artifact_registry -tAc \
    "SELECT l.hosted_bytes || '|' || l.proxy_bytes || '|' || l.oci_bytes FROM repository_usage_ledger l JOIN repositories r ON r.id = l.repository_id WHERE r.key = '$1'" \
    2>/dev/null | tr -d '[:space:]' || true
}

# --- the real /v2 push sequence, no docker daemon ------------------------------
# blob_up <repo> <image> <file> -> http code of the monolithic upload
blob_up(){
  curl -s -o "$W/blob.resp" -w '%{http_code}' -X POST -H "$(auth)" \
    -H 'Content-Type: application/octet-stream' --data-binary "@$3" \
    "$BASE/v2/$1/$2/blobs/uploads/?digest=sha256:$(sha_of "$3")" || true
}
# make_image <name> <layer bytes...>: writes $W/<name>.cfg, $W/<name>.l<i>,
# $W/<name>.manifest and echoes the summed blob bytes (config + layers).
make_image(){
  local name="$1" i=0 total layers="" sz
  shift
  printf '{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]},"dtf":"%s-%s"}' \
    "$name" "$RUN_ID" > "$W/${name}.cfg"
  total="$(size_of "$W/${name}.cfg")"
  for sz in "$@"; do
    i=$((i+1))
    head -c "$sz" /dev/urandom > "$W/${name}.l${i}"
    layers="${layers}${layers:+,}{\"mediaType\":\"application/vnd.docker.image.rootfs.diff.tar.gzip\",\"size\":${sz},\"digest\":\"sha256:$(sha_of "$W/${name}.l${i}")\"}"
    total=$((total + sz))
  done
  printf '{"schemaVersion":2,"mediaType":"%s","config":{"mediaType":"application/vnd.docker.container.image.v1+json","size":%s,"digest":"sha256:%s"},"layers":[%s]}' \
    "$MCT" "$(size_of "$W/${name}.cfg")" "$(sha_of "$W/${name}.cfg")" "$layers" > "$W/${name}.manifest"
  echo "$total"
}
# push_blobs <repo> <image> <name> -> "" when every blob answered 201, else a diagnostic
push_blobs(){
  local f c out=""
  for f in "$W/$3.cfg" "$W/$3".l*; do
    c="$(blob_up "$1" "$2" "$f")"
    [ "$c" = "201" ] || out="${out} $(basename "$f")=${c}"
  done
  echo "$out"
}
put_manifest(){ # <repo> <image> <tag> <name> -> http code
  curl -s -o "$W/manifest.resp" -w '%{http_code}' -X PUT -H "$(auth)" -H "Content-Type: ${MCT}" \
    --data-binary "@$W/$4.manifest" "$BASE/v2/$1/$2/manifests/$3" || true
}

# =============================================================================
begin_suite "oci-usage-counts-layers-once"

begin_test "setup: admin login, Docker and generic hosted repositories"
TOK="$(curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"${ADMIN_PASS}\"}" | jqr '.access_token // .token // empty')"
if [ -z "$TOK" ]; then infra_fail "admin login failed at $BASE"; end_suite; fi
SUF="${RUN_ID##*-}-$$"
D="ouc-docker-${SUF}"      # Docker hosted, no quota
DQ="ouc-quota-${SUF}"      # Docker hosted, quota_bytes 240000
G="ouc-gen-${SUF}"         # generic hosted with one 7000-byte file
DV="ouc-dvirt-${SUF}"      # Docker virtual created with member_repos [D]
GV="ouc-gvirt-${SUF}"      # generic virtual created with member_repos [G]
GV0="ouc-gvirt0-${SUF}"    # generic virtual created with no members
QUOTA=240000
mk(){ # <key> <format> <type> [quota] [member] -> the create response body
  local body
  body="$(jq -n --arg k "$1" --arg f "$2" --arg t "$3" --arg q "${4:-}" --arg m "${5:-}" \
    '{key:$k,name:$k,format:$f,repo_type:$t,is_public:false}
     + (if $q == "" then {} else {quota_bytes:($q|tonumber)} end)
     + (if $m == "" then {} else {member_repos:[{repo_key:$m,priority:1}]} end)')"
  curl -s -X POST "$BASE/api/v1/repositories" -H "$(auth)" -H 'Content-Type: application/json' -d "$body"
}
SETUP_ERR=""
[ "$(mk "$D" docker local | jqr '.key // empty')" = "$D" ] || SETUP_ERR="${SETUP_ERR} ${D}"
[ "$(mk "$DQ" docker local "$QUOTA" | jqr '.key // empty')" = "$DQ" ] || SETUP_ERR="${SETUP_ERR} ${DQ}"
[ "$(mk "$G" generic local | jqr '.key // empty')" = "$G" ] || SETUP_ERR="${SETUP_ERR} ${G}"
head -c 7000 /dev/urandom > "$W/gen.bin"
code="$(curl -s -o /dev/null -w '%{http_code}' -X PUT -H "$(auth)" -H 'Content-Type: application/octet-stream' \
  --data-binary "@$W/gen.bin" "$BASE/api/v1/repositories/${G}/artifacts/ouc/gen.bin" || true)"
case "$code" in 2*) ;; *) SETUP_ERR="${SETUP_ERR} generic-upload:${code}";; esac
if [ -n "$SETUP_ERR" ]; then infra_fail "setup failed:${SETUP_ERR}"; end_suite; fi
pass

# =============================================================================
# CONTROL (both images): the push itself, and the blob bytes it stored.
# =============================================================================
begin_test "CONTROL: an image (config + 2 layers) pushes over /v2, pulls back by tag, and stores each blob once in oci_blobs"
reset_case
IMG_BYTES="$(make_image app 100000 60000)"
MAN_DIGEST="sha256:$(sha_of "$W/app.manifest")"
errs="$(push_blobs "$D" app app)"
[ -z "$errs" ] || fail_g "blob uploads refused:${errs}"
code="$(put_manifest "$D" app v1 app)"
[ "$code" = "201" ] || fail_g "manifest PUT app:v1 answered ${code}: $(head -c 200 "$W/manifest.resp")"
got="$(curl -s -D "$W/pull.h" -o "$W/pull.json" -w '%{http_code}' -H "$(auth)" -H "Accept: ${MCT}" "$BASE/v2/${D}/app/manifests/v1" || true)"
[ "$got" = "200" ] || fail_g "pull app:v1 answered ${got}"
[ "sha256:$(sha_of "$W/pull.json")" = "$MAN_DIGEST" ] || fail_g "pulled manifest is not the pushed one"
curl -s -L -o "$W/l1.pull" -H "$(auth)" "$BASE/v2/${D}/app/blobs/sha256:$(sha_of "$W/app.l1")" || true
[ "$(sha_of "$W/l1.pull")" = "$(sha_of "$W/app.l1")" ] || fail_g "layer 1 did not read back by digest"
blobs="$(psql_q "SELECT count(*) || '|' || COALESCE(sum(b.size_bytes),0) FROM oci_blobs b JOIN repositories r ON r.id = b.repository_id WHERE r.key = '${D}'")"
[ "$blobs" = "3|${IMG_BYTES}" ] || fail_g "oci_blobs for ${D} = '${blobs}' (count|bytes), expected '3|${IMG_BYTES}'"
note "image blob bytes ${IMG_BYTES}; manifest ${MAN_DIGEST}; oci_blobs ${blobs}"
finish_case "the OCI push baseline did not hold"

begin_test "CONTROL: a generic hosted repository reports its uploaded bytes as storage_used_bytes"
reset_case
u="$(used_of "$G")"
[ "$u" = "7000" ] || fail_g "${G} storage_used_bytes = '${u}', expected 7000"
finish_case "generic hosted usage is wrong"

# =============================================================================
# FIX #4483 (RED on 1.10.0).
# =============================================================================
begin_test "FIX #4483: after the push, storage_used_bytes equals the image's blob bytes (the manifest row adds 0)"
reset_case
u="$(used_of "$D")"
note "storage_used_bytes=${u} blob bytes=${IMG_BYTES}"
[ "$u" = "$IMG_BYTES" ] || fail_g "storage_used_bytes = ${u}, expected ${IMG_BYTES} (1.10.0 adds the manifest row's image size too: #4483)"
finish_case "OCI usage counts the image more than once"

begin_test "FIX #4483: the usage ledger charges the layers to oci_bytes and nothing to hosted_bytes"
reset_case
l="$(ledger_of "$D")"
note "ledger hosted|proxy|oci = ${l}"
[ "$l" = "0|0|${IMG_BYTES}" ] || fail_g "repository_usage_ledger = '${l}', expected '0|0|${IMG_BYTES}' (1.10.0 charges the manifest row's image size to hosted_bytes: #4483)"
finish_case "the usage ledger counts the image twice"

begin_test "FIX #4483: a second tag of the same image leaves usage and the ledger unchanged; the manifest rows keep the image size"
reset_case
code="$(put_manifest "$D" app v2 app)"
[ "$code" = "201" ] || fail_g "manifest PUT app:v2 answered ${code}"
u="$(used_of "$D")"; l="$(ledger_of "$D")"
note "after tag v2: storage_used_bytes=${u} ledger=${l}"
[ "$u" = "$IMG_BYTES" ] || fail_g "storage_used_bytes after a second tag = ${u}, expected still ${IMG_BYTES} (1.10.0 adds the image size once per tag: #4483)"
[ "$l" = "0|0|${IMG_BYTES}" ] || fail_g "ledger after a second tag = '${l}', expected '0|0|${IMG_BYTES}'"
rows="$(psql_q "SELECT count(*) FILTER (WHERE a.size_bytes = ${IMG_BYTES}) || '|' || count(*) FROM artifacts a JOIN repositories r ON r.id = a.repository_id WHERE r.key = '${D}' AND NOT a.is_deleted AND a.storage_key LIKE 'oci-manifests/%'")"
case "$rows" in
  0\|*|*\|0) fail_g "manifest artifact rows (with image size|total) = '${rows}': the listing size must stay the image size";;
esac
note "manifest rows carrying the image size|total: ${rows}"
finish_case "an extra tag is charged to usage again"

begin_test "FIX #4483: a Docker quota admits an image at its real bytes and refuses the layer that crosses it"
reset_case
A_BYTES="$(make_image qa 150000)"
errs="$(push_blobs "$DQ" qa qa)"
[ -z "$errs" ] || fail_g "the ${A_BYTES}-byte image's blobs were refused under a ${QUOTA}-byte quota:${errs}"
code="$(put_manifest "$DQ" qa v1 qa)"
[ "$code" = "201" ] || fail_g "manifest PUT qa:v1 answered ${code}: $(head -c 200 "$W/manifest.resp")"
code="$(put_manifest "$DQ" qa v2 qa)"
[ "$code" = "201" ] || fail_g "manifest PUT qa:v2 (same image) answered ${code}: $(head -c 200 "$W/manifest.resp")"
u="$(used_of "$DQ")"
[ "$u" = "$A_BYTES" ] || fail_g "usage under quota = ${u}, expected ${A_BYTES} (#4483 counts manifest rows on 1.10.0)"
make_image qb 100000 >/dev/null
c="$(blob_up "$DQ" qb "$W/qb.l1")"
denied="$(jqr '.errors[0].code // empty' < "$W/blob.resp")"
note "image A ${A_BYTES} bytes -> usage ${u}; image B 100000-byte layer -> ${c} ${denied}"
if [ "$c" != "507" ] || [ "$denied" != "DENIED" ]; then
  fail_g "a layer taking usage from ${u} past the ${QUOTA}-byte quota answered ${c} ${denied}, expected 507 DENIED"
fi
finish_case "the Docker quota is not enforced at the image's real bytes"

# =============================================================================
# FIX #4505 (RED on 1.10.0, where the field does not exist).
# =============================================================================
begin_test "FIX #4505: a Docker virtual created with a populated member reports member_storage_used_bytes = blob bytes in the create response and the next GET"
reset_case
resp="$(mk "$DV" docker virtual "" "$D")"
c_key="$(echo "$resp" | jqr '.key // empty')"
c_member="$(echo "$resp" | jqr '.member_storage_used_bytes // empty')"
c_used="$(echo "$resp" | jqr '.storage_used_bytes // empty')"
g_member="$(repo_get "$DV" | jqr '.member_storage_used_bytes // empty')"
note "create: key=${c_key} storage_used_bytes=${c_used} member_storage_used_bytes=${c_member:-absent}; GET member_storage_used_bytes=${g_member:-absent}"
[ "$c_key" = "$DV" ] || fail_g "virtual create failed: $(echo "$resp" | head -c 200)"
[ "$c_member" = "$IMG_BYTES" ] || fail_g "create response member_storage_used_bytes = '${c_member}', expected ${IMG_BYTES} (#4505; the member's real bytes per #4483)"
[ "$g_member" = "$c_member" ] || fail_g "GET member_storage_used_bytes '${g_member}' differs from the create response '${c_member}'"
[ "$c_used" = "0" ] || fail_g "the virtual's own storage_used_bytes = '${c_used}', expected 0 (member bytes are reported separately)"
finish_case "the virtual create response does not report its members' storage"

begin_test "FIX #4505: a generic virtual created with a member reports its bytes on create; one created without members reports 0"
reset_case
resp="$(mk "$GV" generic virtual "" "$G")"
c_member="$(echo "$resp" | jqr '.member_storage_used_bytes // empty')"
g_member="$(repo_get "$GV" | jqr '.member_storage_used_bytes // empty')"
resp0="$(mk "$GV0" generic virtual)"
c0="$(echo "$resp0" | jqr '.member_storage_used_bytes // empty')"
note "with member: create=${c_member:-absent} GET=${g_member:-absent}; without members: create=${c0:-absent}"
[ "$c_member" = "7000" ] || fail_g "create response member_storage_used_bytes = '${c_member}', expected 7000 (#4505)"
[ "$g_member" = "7000" ] || fail_g "GET member_storage_used_bytes = '${g_member}', expected 7000"
[ "$c0" = "0" ] || fail_g "a virtual created without members reports member_storage_used_bytes '${c0}', expected 0"
finish_case "the generic virtual create response does not report its member's storage"

end_suite
