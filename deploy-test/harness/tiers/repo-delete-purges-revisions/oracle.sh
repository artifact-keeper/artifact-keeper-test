#!/usr/bin/env bash
# =============================================================================
# tiers/repo-delete-purges-revisions/oracle.sh: deleting a versioned repository
#   purges its older revisions' objects, or hands a shared one to storage GC
#   (artifact-keeper#4865)
# =============================================================================
# run.sh has stood up `storage.filesystem` and exported BASE_URL,
# DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID, DTF_SLOT, RELEASE_GATE=1,
# JUNIT_OUTPUT_DIR, COMMON_SH. See the manifest for the bug and the gates.
#
# Topology (keys suffixed per run):
#   A   generic hosted, versioning_enabled=true (deleted by the test)
#   B   generic hosted, storage_path = A's root, shares one object with A
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every probe here is judged, never fatal.
set +e

DBC="$DB_CONTAINER"
BACKEND_CTR="${DB_CONTAINER%-db}-backend"
FS_HELPER_IMAGE="postgres:16-alpine"   # already pulled by compose.base.yml
SUF="${RUN_ID##*-}$$"
A="rdp-a-${SUF}"; B="rdp-b-${SUF}"

setup_workdir
W="$WORK_DIR"

psql_q(){ docker exec "$DBC" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]' || true; }
fsx(){ docker run --rm -i --volumes-from "$BACKEND_CTR" --entrypoint sh "$FS_HELPER_IMAGE" -c "$1" 2>/dev/null || true; }
obj_exists(){ fsx "[ -f '$1/$2' ] && echo yes || echo no" | tr -d '[:space:]'; }
sha(){ sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }
mkbody(){ head -c 32768 /dev/urandom > "$1"; }

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

send(){  # send METHOD PATH [JSON] -> HTTP status, body in $W/send.out
  curl -s --max-time 60 -o "$W/send.out" -w '%{http_code}' -X "$1" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" -H 'Content-Type: application/json' \
    ${3:+-d "$3"} "${BASE_URL}$2" 2>/dev/null || echo 000
}
put(){  # put KEY PATH FILE -> HTTP status, body in $W/put.out
  curl -s --max-time 120 -o "$W/put.out" -w '%{http_code}' -X PUT \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" -H 'Content-Type: application/octet-stream' \
    --data-binary "@$3" "${BASE_URL}/api/v1/repositories/$1/artifacts/$2" 2>/dev/null || echo 000
}
download(){  # download KEY PATH OUT -> HTTP status
  curl -s --max-time 60 -o "$3" -w '%{http_code}' -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    "${BASE_URL}/api/v1/repositories/$1/download/$2" 2>/dev/null || echo 000
}
ok2xx(){ [ "$1" -ge 200 ] 2>/dev/null && [ "$1" -lt 300 ]; }
rev_key(){  # rev_key REPO_ID PATH REVISION -> storage_key
  psql_q "SELECT storage_key FROM artifact_versions WHERE repository_id = '$1' AND path = '$2' AND revision = $3"
}
head_key(){  # head_key REPO_KEY PATH -> storage_key of the live row
  psql_q "SELECT a.storage_key FROM artifacts a JOIN repositories r ON r.id = a.repository_id \
          WHERE r.key = '$1' AND a.path = '$2' AND NOT a.is_deleted"
}
wait_gone(){  # wait_gone ROOT KEY SECONDS -> yes when the object is gone
  local _i
  for _i in $(seq 1 "$3"); do
    [ "$(obj_exists "$1" "$2")" = "no" ] && { echo yes; return; }
    sleep 1
  done
  echo no
}

begin_suite "repo-delete-purges-revisions (#4865)"

# =============================================================================
# SETUP
# =============================================================================
begin_test "setup: a versioning-enabled generic repository with two revisions of two paths, and a second repository sharing one revision's object"
auth_admin
err=""
st="$(send POST /api/v1/repositories "{\"key\":\"${A}\",\"name\":\"${A}\",\"format\":\"generic\",\"repo_type\":\"local\",\"versioning_enabled\":true}")"
ok2xx "$st" || err+="create ${A} -> ${st} $(head -c 160 "$W/send.out"); "
st="$(send POST /api/v1/repositories "{\"key\":\"${B}\",\"name\":\"${B}\",\"format\":\"generic\",\"repo_type\":\"local\"}")"
ok2xx "$st" || err+="create ${B} -> ${st} $(head -c 160 "$W/send.out"); "
if [ -n "$err" ]; then infra_fail "could not create the repositories" "$err"; end_suite; fi
A_ID="$(psql_q "SELECT id FROM repositories WHERE key = '${A}'")"
ROOT_A="$(psql_q "SELECT storage_path FROM repositories WHERE key = '${A}'")"
ver="$(psql_q "SELECT versioning_enabled FROM repositories WHERE key = '${A}'")"
[ "$ver" = "t" ] || { infra_fail "${A} has versioning_enabled='${ver}', expected t"; end_suite; }
# B shares A's storage root, so a content-addressed key both hold resolves to
# one file. Set before B stores anything.
psql_q "UPDATE repositories SET storage_path = '${ROOT_A}' WHERE key = '${B}'" >/dev/null

mkbody "$W/m1"; mkbody "$W/m2"; mkbody "$W/s1"; mkbody "$W/s2"
codes=""
for f in m1:p/model.bin m2:p/model.bin s1:s/shared.bin s2:s/shared.bin; do
  c="$(put "$A" "${f#*:}" "$W/${f%%:*}")"; codes+="${f}=${c} "
  ok2xx "$c" || err+="PUT ${A}/${f#*:} (${f%%:*}) -> ${c} $(head -c 160 "$W/put.out"); "
done
c="$(put "$B" b/twin.bin "$W/s1")"; codes+="B:s1=${c}"
ok2xx "$c" || err+="PUT ${B}/b/twin.bin -> ${c} $(head -c 160 "$W/put.out"); "
echo "  uploads: ${codes}"
if [ -n "$err" ]; then infra_fail "uploads failed" "$err"; end_suite; fi

M_OLD="$(rev_key "$A_ID" p/model.bin 1)"; M_HEAD="$(head_key "$A" p/model.bin)"
S_OLD="$(rev_key "$A_ID" s/shared.bin 1)"; S_HEAD="$(head_key "$A" s/shared.bin)"
B_KEY="$(head_key "$B" b/twin.bin)"
nrev="$(psql_q "SELECT count(*) FROM artifact_versions WHERE repository_id = '${A_ID}'")"
echo "  ${A} (${A_ID}) root ${ROOT_A}, ${nrev} artifact_versions rows"
echo "  p/model.bin rev1 ${M_OLD} head ${M_HEAD}; s/shared.bin rev1 ${S_OLD} head ${S_HEAD}; ${B} twin ${B_KEY}"
err=""
[ "$nrev" = "4" ] || err+="expected 4 artifact_versions rows for ${A}, got ${nrev}; "
{ [ -n "$M_OLD" ] && [ -n "$M_HEAD" ] && [ "$M_OLD" != "$M_HEAD" ]; } || err+="p/model.bin revision keys are not two distinct keys; "
{ [ -n "$S_OLD" ] && [ "$S_OLD" != "$S_HEAD" ]; } || err+="s/shared.bin revision keys are not two distinct keys; "
[ "$B_KEY" = "$S_OLD" ] || err+="${B}'s twin does not share s/shared.bin revision 1's key (${B_KEY} vs ${S_OLD}); "
for k in "$M_OLD" "$M_HEAD" "$S_OLD" "$S_HEAD"; do
  [ "$(obj_exists "$ROOT_A" "$k")" = "yes" ] || err+="object ${ROOT_A}/${k} is not on the volume before the delete; "
done
if [ -n "$err" ]; then infra_fail "preconditions do not hold" "$err"; end_suite; fi
pass

# =============================================================================
# DELETE
# =============================================================================
begin_test "CONTROL: DELETE of the versioned repository succeeds and its artifact_versions rows cascade away"
reset_case
st="$(send DELETE "/api/v1/repositories/${A}")"
note "DELETE ${A}: ${st} $(head -c 160 "$W/send.out")"
ok2xx "$st" || fail_g "the repository delete answered ${st}"
left="$(psql_q "SELECT count(*) FROM artifact_versions WHERE repository_id = '${A_ID}'")"
note "artifact_versions rows left for ${A_ID}: ${left}"
[ "$left" = "0" ] || fail_g "${left} artifact_versions rows survived the repository delete"
finish_case "repository delete control failed"

begin_test "CONTROL: the HEAD revision objects of the deleted repository are purged from storage"
reset_case
g1="$(wait_gone "$ROOT_A" "$M_HEAD" 30)"; g2="$(wait_gone "$ROOT_A" "$S_HEAD" 10)"
note "p/model.bin head object gone: ${g1}; s/shared.bin head object gone: ${g2}"
[ "$g1" = "yes" ] || fail_g "the HEAD object ${M_HEAD} of p/model.bin is still on storage 30 s after the delete"
[ "$g2" = "yes" ] || fail_g "the HEAD object ${S_HEAD} of s/shared.bin is still on storage after the delete"
finish_case "HEAD objects were not purged"

# =============================================================================
# FIX
# =============================================================================
begin_test "FIX #4865: the older revision's object of a versioned path is purged with the repository"
reset_case
# The HEAD purge above already waited for the background purge to run; give
# the older revision a further window of its own.
g="$(wait_gone "$ROOT_A" "$M_OLD" 15)"
note "p/model.bin revision 1 object ${ROOT_A}/${M_OLD} gone: ${g}"
[ "$g" = "yes" ] || fail_g "the older revision's object ${M_OLD} leaked on storage after the repository delete"
finish_case "#4865 older revision object leaked"

begin_test "CONTROL: the older revision object another repository still references survives and still downloads"
reset_case
ob="$(obj_exists "$ROOT_A" "$S_OLD")"
c="$(download "$B" b/twin.bin "$W/twin.dl")"
note "shared object ${S_OLD} present: ${ob}; ${B}/b/twin.bin download ${c} sha $(sha "$W/twin.dl" | head -c 12)"
[ "$ob" = "yes" ] || fail_g "the shared object was deleted although ${B} still references it"
{ [ "$c" = "200" ] && [ "$(sha "$W/twin.dl")" = "$(sha "$W/s1")" ]; } || fail_g "${B}/b/twin.bin no longer downloads byte-for-byte (HTTP ${c})"
finish_case "shared object safety control failed"

begin_test "FIX #4865: the spared older revision key is recorded as a storage GC candidate"
reset_case
cand="$(psql_q "SELECT count(*) FROM oci_gc_candidates WHERE storage_key = '${S_OLD}' AND source_repository_id = '${A_ID}'")"
note "oci_gc_candidates rows for ${S_OLD} from ${A_ID}: ${cand}"
[ "${cand:-0}" -ge 1 ] 2>/dev/null || fail_g "the spared revision key ${S_OLD} was not handed to the GC candidate set; it leaks once ${B} lets go of it"
finish_case "#4865 spared revision key not recorded for GC"

# Cleanup: B (its rows only; the candidate row is left for the GC like any other).
send DELETE "/api/v1/repositories/${B}" >/dev/null

end_suite
