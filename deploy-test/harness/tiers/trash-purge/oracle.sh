#!/usr/bin/env bash
# =============================================================================
# tiers/trash-purge/oracle.sh
#   #4700 / #4701: an admin can permanently delete a trashed artifact, by id
#   (DELETE /api/v1/admin/trash/{id}) or in the same call as the delete
#   (DELETE /api/v1/repositories/{key}/artifacts/{path}?permanent=true), so a
#   deleted release can be re-uploaded with different bytes at once. A shared
#   stored object survives the purge; a repository-restricted admin token stays
#   inside its repositories; OCI content is refused with 409, and only after
#   the access gates.
# See the manifest for THE BUG, the primitives and the gates.
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
BACKEND_CTR="${DB_CONTAINER%-db}-backend"
FS_HELPER_IMAGE="postgres:16-alpine"   # already pulled by compose.base.yml

setup_workdir
W="$WORK_DIR"

# common.sh may run under `set -e`: every probe swallows its own failure and
# the assertion that reads the (possibly empty) value judges it.
jqr(){ jq -r "$1" 2>/dev/null || true; }
psql_q(){ docker exec "$DBC" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]' || true; }
fsx(){ docker run --rm -i --volumes-from "$BACKEND_CTR" --entrypoint sh "$FS_HELPER_IMAGE" -c "$1" 2>/dev/null || true; }
sha_of(){ sha256sum "$1" 2>/dev/null | awk '{print $1}' || true; }

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

# http <method> <url> <token> <outfile> [curl args...] -> HTTP code
http(){
  local m="$1" u="$2" t="$3" o="$4"
  shift 4
  rm -f "$o"
  curl -s --max-time 60 -o "$o" -w '%{http_code}' -X "$m" -H "Authorization: Bearer $t" "$@" "$u" || true
  [ -f "$o" ] || : > "$o"
}
body(){ head -c 400 "$1" 2>/dev/null | tr -d '\n' || true; }

# Row facts, by repository key and path, or by id.
row_id(){ psql_q "SELECT a.id FROM artifacts a JOIN repositories r ON r.id=a.repository_id WHERE r.key='$1' AND a.path='$2' ORDER BY a.created_at DESC LIMIT 1;"; }
row_state(){ # <id> -> live | trashed | gone
  local d; d="$(psql_q "SELECT is_deleted FROM artifacts WHERE id='$1';")"
  case "$d" in t) echo trashed;; f) echo live;; *) echo gone;; esac
}
key_of(){ psql_q "SELECT storage_key FROM artifacts WHERE id='$1';"; }
root_of(){ psql_q "SELECT storage_path FROM repositories WHERE key='$1';"; }
obj_exists(){ # <root> <storage_key> -> yes | no
  fsx "[ -f '$1/$2' ] && echo yes || echo no" | tr -d '[:space:]'
}
purged_audit(){ # <id> -> number of ARTIFACT_PURGED rows for it (fire-and-forget: poll)
  local n="" _i
  for _i in $(seq 1 20); do
    n="$(psql_q "SELECT count(*) FROM audit_log WHERE action='ARTIFACT_PURGED' AND resource_id='$1';")"
    [ "${n:-0}" -ge 1 ] 2>/dev/null && break
    sleep 0.5
  done
  echo "${n:-0}"
}

mvn_put(){ http PUT "$BASE/maven/$1/$2" "$3" "$4" -H 'Content-Type: application/java-archive' --data-binary "@$5"; }
mvn_get(){ http GET "$BASE/maven/$1/$2" "$3" "$4"; }
gen_put(){ http PUT "$BASE/api/v1/repositories/$1/artifacts/$2" "$3" "$4" -H 'Content-Type: application/octet-stream' --data-binary "@$5"; }
gen_get(){ http GET "$BASE/api/v1/repositories/$1/download/$2" "$3" "$4"; }
art_delete(){ # <repo> <path> <token> <out> [query]
  http DELETE "$BASE/api/v1/repositories/$1/artifacts/$2${5:-}" "$3" "$4"
}
trash_purge(){ http DELETE "$BASE/api/v1/admin/trash/$1" "$2" "$3"; }

# =============================================================================
begin_suite "trash-purge"

begin_test "setup: admin login, Maven + generic + OCI repositories, a non-admin writer, a repository-restricted admin token"
TOK="$(curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"${ADMIN_PASS}\"}" | jqr '.access_token // .token // empty')"
if [ -z "$TOK" ]; then infra_fail "admin login failed at $BASE"; end_suite; fi
SUF="${RUN_ID##*-}-$$"
R_MVN="tp-mvn-${DTF_SLOT}-${SUF}"; R_GA="tp-ga-${DTF_SLOT}-${SUF}"; R_GB="tp-gb-${DTF_SLOT}-${SUF}"; R_OCI="tp-oci-${DTF_SLOT}-${SUF}"
mk(){ # <key> <format>
  curl -s -X POST "$BASE/api/v1/repositories" -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg k "$1" --arg f "$2" '{key:$k,name:$k,format:$f,repo_type:"local",is_public:false}')" | jqr '.id // empty'
}
SETUP_ERR=""
ID_MVN="$(mk "$R_MVN" maven)"; [ -n "$ID_MVN" ] || SETUP_ERR="${SETUP_ERR} maven"
ID_GA="$(mk "$R_GA" generic)"; [ -n "$ID_GA" ] || SETUP_ERR="${SETUP_ERR} generic-A"
ID_GB="$(mk "$R_GB" generic)"; [ -n "$ID_GB" ] || SETUP_ERR="${SETUP_ERR} generic-B"
ID_OCI="$(mk "$R_OCI" docker)"; [ -n "$ID_OCI" ] || SETUP_ERR="${SETUP_ERR} docker"
if [ -n "$SETUP_ERR" ]; then infra_fail "could not create repositories:${SETUP_ERR}"; end_suite; fi
# A non-admin with read, write and delete on generic repository A (a generic
# path is mutable, so the release-immutability guard does not refuse its delete).
U_W="tp-writer-${DTF_SLOT}-${SUF}"; U_W_PASS="Writer!2026-${SUF}-dtf"
U_W_ID="$(curl -s -X POST "$BASE/api/v1/users" -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg u "$U_W" --arg p "$U_W_PASS" '{username:$u,password:$p,email:($u+"@example.test")}')" | jqr '.user.id // .id // empty')"
[ -n "$U_W_ID" ] || { infra_fail "could not create user ${U_W}"; end_suite; }
g="$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/v1/permissions" -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg u "$U_W_ID" --arg r "$ID_GA" '{principal_type:"user",principal_id:$u,target_type:"repository",target_id:$r,actions:["read","write","delete"]}')" || true)"
case "$g" in 2*) ;; *) infra_fail "could not grant ${U_W} read,write,delete on ${R_GA} (HTTP ${g})"; end_suite;; esac
WTOK="$(login_as "$U_W" "$U_W_PASS")" || true
[ -n "$WTOK" ] || { infra_fail "could not log in as ${U_W}"; end_suite; }
# An admin-owned, admin-scoped API token restricted to repository B (#4219/#4225).
STOK="$(curl -s -X POST "$BASE/api/v1/auth/tokens" -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg r "$ID_GB" --arg n "tp-scoped-${SUF}" '{name:$n,scopes:["*"],repo_selector:{match_repos:[$r]}}')" | jqr '.token // empty')"
[ -n "$STOK" ] || { infra_fail "could not mint a repository-restricted admin token"; end_suite; }
echo "-- repos: ${R_MVN} ${R_GA} ${R_GB} (scoped token) ${R_OCI}; writer ${U_W}"
pass

# =============================================================================
# CONTROL (both images): the ordinary trash. A delete soft-deletes into the
# trash, the trash lists it, restore brings it back live and serving, and a
# non-admin with the delete grant can soft-delete.
# =============================================================================
begin_test "CONTROL: delete moves an artifact to the trash, restore brings it back byte-exact; a non-admin with delete can soft-delete"
reset_case
head -c 4096 /dev/urandom > "$W/ctl.bin"
c="$(gen_put "$R_GA" ctl/ctl.bin "$TOK" "$W/o" "$W/ctl.bin")"
[ "$c" = "201" ] || { infra_fail "generic upload was HTTP ${c}: $(body "$W/o")"; end_suite; }
CID="$(row_id "$R_GA" ctl/ctl.bin)"
c="$(art_delete "$R_GA" ctl/ctl.bin "$TOK" "$W/o")"
note "delete: HTTP ${c}, row ${CID} $(row_state "$CID")"
[ "$c" = "200" ] && [ "$(row_state "$CID")" = "trashed" ] || fail_g "a plain delete was HTTP ${c} and left the row $(row_state "$CID"), expected 200 and trashed"
c="$(http GET "$BASE/api/v1/admin/trash?per_page=100" "$TOK" "$W/o")"
in_list="$(jq -r --arg i "$CID" '[.items[]? | select(.id == $i)] | length' < "$W/o" 2>/dev/null || true)"
note "trash list: HTTP ${c}, contains ${CID}: ${in_list}"
[ "$c" = "200" ] && [ "$in_list" = "1" ] || fail_g "the trash does not list the deleted artifact (HTTP ${c})"
c="$(http POST "$BASE/api/v1/admin/trash/${CID}/restore" "$TOK" "$W/o")"
note "restore: HTTP ${c}, row now $(row_state "$CID")"
[ "$c" = "200" ] && [ "$(row_state "$CID")" = "live" ] || fail_g "restore was HTTP ${c}, row $(row_state "$CID"): $(body "$W/o")"
c="$(gen_get "$R_GA" ctl/ctl.bin "$TOK" "$W/ctl.get")"
[ "$c" = "200" ] && [ "$(sha_of "$W/ctl.get")" = "$(sha_of "$W/ctl.bin")" ] || fail_g "the restored artifact does not download byte-exact (HTTP ${c})"
head -c 2048 /dev/urandom > "$W/wctl.bin"
c="$(gen_put "$R_GA" w/wctl.bin "$WTOK" "$W/o" "$W/wctl.bin")"
WID="$(row_id "$R_GA" w/wctl.bin)"
c2="$(art_delete "$R_GA" w/wctl.bin "$WTOK" "$W/o")"
note "writer upload HTTP ${c}, writer plain delete HTTP ${c2}, row $(row_state "$WID")"
[ "$c" = "201" ] && [ "$c2" = "200" ] && [ "$(row_state "$WID")" = "trashed" ] || fail_g "the writer could not upload (${c}) and soft-delete (${c2}) in ${R_GA}"
finish_case "ordinary trash / restore broken"

# =============================================================================
# CONTROL (both images): the #4700 precondition. A deleted Maven release
# stays in the trash and refuses a different-bytes re-upload (409).
# FIX: DELETE /api/v1/admin/trash/{id} purges it: row and object gone,
# ARTIFACT_PURGED recorded, and the re-upload succeeds and serves new bytes.
# =============================================================================
P1="org/dtf/rel/1.0/rel-1.0.jar"
head -c 3000 /dev/urandom > "$W/rel1.jar"; head -c 3000 /dev/urandom > "$W/rel1b.jar"
begin_test "CONTROL (#4700 precondition): a trashed Maven release refuses a different-bytes re-upload at its path (409)"
reset_case
c="$(mvn_put "$R_MVN" "$P1" "$TOK" "$W/o" "$W/rel1.jar")"
[ "$c" = "201" ] || { infra_fail "Maven upload was HTTP ${c}: $(body "$W/o")"; end_suite; }
ID1="$(row_id "$R_MVN" "$P1")"; KEY1="$(key_of "$ID1")"; ROOT_MVN="$(root_of "$R_MVN")"
c="$(art_delete "$R_MVN" "$P1" "$TOK" "$W/o")"
note "delete HTTP ${c}, row ${ID1} $(row_state "$ID1"), object ${ROOT_MVN}/${KEY1} $(obj_exists "$ROOT_MVN" "$KEY1")"
[ "$c" = "200" ] && [ "$(row_state "$ID1")" = "trashed" ] || fail_g "delete did not trash the release (HTTP ${c}, row $(row_state "$ID1"))"
c="$(mvn_put "$R_MVN" "$P1" "$TOK" "$W/o" "$W/rel1b.jar")"
note "re-upload of different bytes while trashed: HTTP ${c} $(body "$W/o")"
[ "$c" = "409" ] || fail_g "re-upload over a trashed release was HTTP ${c}, expected 409 (the #4700 tombstone)"
finish_case "#4700 precondition does not hold"

begin_test "FIX #4700: DELETE /api/v1/admin/trash/{id} purges the trashed release (row, object, ARTIFACT_PURGED) and a different-bytes re-upload then succeeds"
reset_case
[ "$(obj_exists "$ROOT_MVN" "$KEY1")" = "yes" ] || note "precondition: stored object ${ROOT_MVN}/${KEY1} already absent before the purge"
c="$(trash_purge "$ID1" "$TOK" "$W/o")"
note "purge: HTTP ${c} $(body "$W/o")"
[ "$c" = "200" ] || fail_g "DELETE /api/v1/admin/trash/${ID1} was HTTP ${c}, expected 200"
[ "$(jqr '.id // empty' < "$W/o")" = "$ID1" ] && [ "$(jqr '.storage_reclaimed' < "$W/o")" = "true" ] || fail_g "purge response does not name ${ID1} with storage_reclaimed=true"
st="$(row_state "$ID1")"; ob="$(obj_exists "$ROOT_MVN" "$KEY1")"; au="$(purged_audit "$ID1")"
note "after purge: row ${st}, object ${ob}, ARTIFACT_PURGED rows ${au}"
[ "$st" = "gone" ] || fail_g "the artifacts row is still there (${st})"
[ "$ob" = "no" ] || fail_g "the stored object ${ROOT_MVN}/${KEY1} is still there"
[ "${au:-0}" -ge 1 ] 2>/dev/null || fail_g "no ARTIFACT_PURGED audit row for ${ID1}"
c="$(mvn_put "$R_MVN" "$P1" "$TOK" "$W/o" "$W/rel1b.jar")"
note "re-upload of different bytes: HTTP ${c}"
[ "$c" = "201" ] || fail_g "re-upload after the purge was HTTP ${c}, expected 201: $(body "$W/o")"
c="$(mvn_get "$R_MVN" "$P1" "$TOK" "$W/rel1.get")"
[ "$c" = "200" ] && [ "$(sha_of "$W/rel1.get")" = "$(sha_of "$W/rel1b.jar")" ] || fail_g "the path does not serve the new bytes (HTTP ${c}, sha $(sha_of "$W/rel1.get"))"
finish_case "#4700: the by-id trash purge does not free a deleted release's path"

# =============================================================================
# FIX: DELETE ...?permanent=true as admin: soft delete and purge in one call.
# =============================================================================
begin_test "FIX #4700: DELETE /api/v1/repositories/{key}/artifacts/{path}?permanent=true (admin) removes row and object, audits, and frees the path"
reset_case
P2="org/dtf/rel/2.0/rel-2.0.jar"
head -c 3000 /dev/urandom > "$W/rel2.jar"; head -c 3000 /dev/urandom > "$W/rel2b.jar"
c="$(mvn_put "$R_MVN" "$P2" "$TOK" "$W/o" "$W/rel2.jar")"
[ "$c" = "201" ] || { infra_fail "Maven upload was HTTP ${c}"; end_suite; }
ID2="$(row_id "$R_MVN" "$P2")"; KEY2="$(key_of "$ID2")"
c="$(art_delete "$R_MVN" "$P2" "$TOK" "$W/o" "?permanent=true")"
st="$(row_state "$ID2")"; ob="$(obj_exists "$ROOT_MVN" "$KEY2")"; au="$(purged_audit "$ID2")"
note "permanent delete: HTTP ${c}; row ${st}, object ${ob}, ARTIFACT_PURGED rows ${au}"
[ "$c" = "200" ] || fail_g "permanent delete was HTTP ${c}: $(body "$W/o")"
[ "$st" = "gone" ] || fail_g "the row is ${st} after ?permanent=true, expected gone (1.11.3 ignores the flag and only trashes it)"
[ "$ob" = "no" ] || fail_g "the stored object is still there"
[ "${au:-0}" -ge 1 ] 2>/dev/null || fail_g "no ARTIFACT_PURGED audit row for ${ID2}"
c="$(mvn_put "$R_MVN" "$P2" "$TOK" "$W/o" "$W/rel2b.jar")"
note "re-upload of different bytes: HTTP ${c}"
[ "$c" = "201" ] || fail_g "re-upload after the permanent delete was HTTP ${c}, expected 201: $(body "$W/o")"
c="$(mvn_get "$R_MVN" "$P2" "$TOK" "$W/rel2.get")"
[ "$c" = "200" ] && [ "$(sha_of "$W/rel2.get")" = "$(sha_of "$W/rel2b.jar")" ] || fail_g "the path does not serve the new bytes (HTTP ${c})"
finish_case "#4700: ?permanent=true does not purge the artifact"

begin_test "FIX #4700: ?permanent=true from a non-admin with delete on the repository is refused (403) and deletes nothing"
reset_case
P3="w/perm.bin"
head -c 3000 /dev/urandom > "$W/rel3.jar"
c="$(gen_put "$R_GA" "$P3" "$WTOK" "$W/o" "$W/rel3.jar")"
[ "$c" = "201" ] || { infra_fail "writer generic upload was HTTP ${c}"; end_suite; }
ID3="$(row_id "$R_GA" "$P3")"
c="$(art_delete "$R_GA" "$P3" "$WTOK" "$W/o" "?permanent=true")"
note "writer permanent delete: HTTP ${c} $(body "$W/o"); row $(row_state "$ID3")"
case "$c" in 403|404) ;; *) fail_g "a non-admin ?permanent=true was HTTP ${c}, expected 403";; esac
[ "$(row_state "$ID3")" = "live" ] || fail_g "the refused request still changed the row ($(row_state "$ID3")): it must end before the soft delete"
c="$(gen_get "$R_GA" "$P3" "$TOK" "$W/rel3.get")"
[ "$c" = "200" ] && [ "$(sha_of "$W/rel3.get")" = "$(sha_of "$W/rel3.jar")" ] || fail_g "the artifact no longer downloads (HTTP ${c})"
finish_case "#4700: a non-admin ?permanent=true is not refused before the delete"

# =============================================================================
# Blob safety: two generic paths with the same bytes share one
# content-addressed object. Purging one leaves the object for the other.
# =============================================================================
begin_test "FIX #4700 (blob safety): purging one of two artifacts that share a stored object keeps the object; the other downloads byte-exact"
reset_case
head -c 8192 /dev/urandom > "$W/shared.bin"
c1="$(gen_put "$R_GA" s/one.bin "$TOK" "$W/o" "$W/shared.bin")"
c2="$(gen_put "$R_GA" s/two.bin "$TOK" "$W/o" "$W/shared.bin")"
[ "$c1" = "201" ] && [ "$c2" = "201" ] || { infra_fail "shared-bytes uploads were HTTP ${c1}/${c2}"; end_suite; }
SID1="$(row_id "$R_GA" s/one.bin)"; SID2="$(row_id "$R_GA" s/two.bin)"
SKEY="$(key_of "$SID1")"; ROOT_GA="$(root_of "$R_GA")"
note "rows ${SID1} / ${SID2}, storage keys ${SKEY} / $(key_of "$SID2")"
[ -n "$SKEY" ] && [ "$SKEY" = "$(key_of "$SID2")" ] || { infra_fail "the two uploads do not share a storage key"; end_suite; }
c="$(art_delete "$R_GA" s/one.bin "$TOK" "$W/o")"
[ "$c" = "200" ] && [ "$(row_state "$SID1")" = "trashed" ] || { infra_fail "could not trash s/one.bin (HTTP ${c})"; end_suite; }
c="$(trash_purge "$SID1" "$TOK" "$W/o")"
note "purge s/one.bin: HTTP ${c} $(body "$W/o")"
[ "$c" = "200" ] || fail_g "purge of the trashed s/one.bin was HTTP ${c}, expected 200"
[ "$(jqr '.storage_reclaimed' < "$W/o")" = "false" ] || fail_g "purge did not report storage_reclaimed=false for a shared object"
st1="$(row_state "$SID1")"; st2="$(row_state "$SID2")"; ob="$(obj_exists "$ROOT_GA" "$SKEY")"
note "after purge: s/one.bin ${st1}, s/two.bin ${st2}, shared object ${ob}"
[ "$st1" = "gone" ] || fail_g "the purged row is ${st1}"
[ "$st2" = "live" ] || fail_g "the other artifact's row is ${st2}"
[ "$ob" = "yes" ] || fail_g "the shared stored object was deleted while s/two.bin still references it"
c="$(gen_get "$R_GA" s/two.bin "$TOK" "$W/two.get")"
note "download s/two.bin: HTTP ${c}, sha $(sha_of "$W/two.get")"
[ "$c" = "200" ] && [ "$(sha_of "$W/two.get")" = "$(sha_of "$W/shared.bin")" ] || fail_g "s/two.bin does not download byte-exact after its twin was purged"
finish_case "#4700 blob safety: purge of a shared object is broken"

# =============================================================================
# Scope: an admin token restricted to repository B (#4225).
# =============================================================================
begin_test "FIX #4701 (scope): a repository-restricted admin token gets 404 purging another repository's trashed artifact (row kept) and 200 inside its own"
reset_case
head -c 1024 /dev/urandom > "$W/sa.bin"; head -c 1024 /dev/urandom > "$W/sb.bin"
ca="$(gen_put "$R_GA" scope/a.bin "$TOK" "$W/o" "$W/sa.bin")"; cb="$(gen_put "$R_GB" scope/b.bin "$TOK" "$W/o" "$W/sb.bin")"
SA="$(row_id "$R_GA" scope/a.bin)"; SB="$(row_id "$R_GB" scope/b.bin)"
art_delete "$R_GA" scope/a.bin "$TOK" "$W/o" >/dev/null; art_delete "$R_GB" scope/b.bin "$TOK" "$W/o" >/dev/null
if [ "$ca" != "201" ] || [ "$cb" != "201" ] || [ "$(row_state "$SA")" != "trashed" ] || [ "$(row_state "$SB")" != "trashed" ]; then
  infra_fail "could not seed trashed artifacts in ${R_GA}/${R_GB} (${ca}/${cb})"; end_suite
fi
c="$(trash_purge "$SA" "$STOK" "$W/o")"
note "scoped token purges ${R_GA} artifact: HTTP ${c} $(body "$W/o"); row $(row_state "$SA")"
case "$c" in 404) ;; *) fail_g "out-of-scope purge was HTTP ${c}, expected 404 (reads like an unknown id)";; esac
[ "$(row_state "$SA")" = "trashed" ] || fail_g "the out-of-scope artifact's row is $(row_state "$SA"), expected still trashed"
c="$(trash_purge "$SB" "$STOK" "$W/o")"
note "scoped token purges ${R_GB} artifact: HTTP ${c}; row $(row_state "$SB")"
[ "$c" = "200" ] && [ "$(row_state "$SB")" = "gone" ] || fail_g "in-scope purge was HTTP ${c} and left the row $(row_state "$SB"), expected 200 and gone"
finish_case "#4701 scope: a repository-restricted admin token is not held to its repositories, or cannot purge in them"

# =============================================================================
# OCI: refused with 409, and only after the access gates.
# =============================================================================
OCI_AUTH=(-u "admin:${ADMIN_PASS}")
printf '{"dtf":"%s"}' "$SUF" > "$W/cfg.json"; CD="sha256:$(sha_of "$W/cfg.json")"
cfg_sz="$(wc -c < "$W/cfg.json" | tr -d '[:space:]')"
cb="$(curl -s -o /dev/null -w '%{http_code}' "${OCI_AUTH[@]}" -X POST -H 'Content-Type: application/octet-stream' \
  --data-binary "@$W/cfg.json" "$BASE/v2/${R_OCI}/img/blobs/uploads/?digest=${CD}" || true)"
jq -nc --arg d "$CD" --argjson s "$cfg_sz" '{schemaVersion:2,mediaType:"application/vnd.oci.image.manifest.v1+json",config:{mediaType:"application/vnd.oci.image.config.v1+json",digest:$d,size:$s},layers:[]}' > "$W/m.json"
cm="$(curl -s -o /dev/null -w '%{http_code}' "${OCI_AUTH[@]}" -X PUT -H 'Content-Type: application/vnd.oci.image.manifest.v1+json' \
  --data-binary "@$W/m.json" "$BASE/v2/${R_OCI}/img/manifests/v1" || true)"
OID="$(psql_q "SELECT a.id FROM artifacts a WHERE a.repository_id='${ID_OCI}' AND a.storage_key LIKE 'oci-manifests/%' LIMIT 1;")"
OPATH="$(psql_q "SELECT a.path FROM artifacts a WHERE a.id='${OID}';")"

begin_test "ORDER (both images): ?permanent=true on an OCI artifact by an admin token restricted to another repository is an access denial, not 409"
reset_case
if [ "$cb" != "201" ] || [ "$cm" != "201" ] || [ -z "$OID" ]; then infra_fail "could not push an OCI manifest (${cb}/${cm})"; end_suite; fi
c="$(art_delete "$R_OCI" "$OPATH" "$STOK" "$W/o" "?permanent=true")"
note "scoped token ?permanent=true on ${R_OCI}/${OPATH}: HTTP ${c} $(body "$W/o"); row $(row_state "$OID")"
case "$c" in 403|404) ;; *) fail_g "HTTP ${c}, expected 403/404 (the 409 must not reveal the format of a repository the caller cannot write to)";; esac
[ "$(row_state "$OID")" = "live" ] || fail_g "the OCI manifest row is $(row_state "$OID")"
finish_case "a caller without access to the OCI repository sees something other than the access denial"

begin_test "FIX #4700: ?permanent=true on an OCI manifest by an admin is 409 and deletes nothing; DELETE /admin/trash/{id} on a trashed one is 409"
reset_case
c="$(art_delete "$R_OCI" "$OPATH" "$TOK" "$W/o" "?permanent=true")"
msg="$(jqr '.message // empty' < "$W/o")"
note "admin ?permanent=true: HTTP ${c} ${msg}; row $(row_state "$OID")"
[ "$c" = "409" ] || fail_g "admin ?permanent=true on an OCI manifest was HTTP ${c}, expected 409"
case "$msg" in *"cannot be purged"*) ;; *) fail_g "the 409 does not carry the OCI purge refusal: ${msg}";; esac
[ "$(row_state "$OID")" = "live" ] || fail_g "the OCI manifest row is $(row_state "$OID") after a refused permanent delete (1.11.3 ignores the flag and trashes it)"
# Bring it into the trash the ordinary way, then try the by-id purge.
[ "$(row_state "$OID")" = "live" ] && art_delete "$R_OCI" "$OPATH" "$TOK" "$W/o" >/dev/null
c="$(trash_purge "$OID" "$TOK" "$W/o")"
note "by-id purge of the trashed manifest: HTTP ${c} $(body "$W/o"); row $(row_state "$OID")"
[ "$c" = "409" ] || fail_g "DELETE /admin/trash/${OID} on OCI content was HTTP ${c}, expected 409"
[ "$(row_state "$OID")" = "trashed" ] || fail_g "the OCI manifest row is $(row_state "$OID") after a refused purge"
finish_case "#4700: OCI content is not refused by the permanent delete"

end_suite
