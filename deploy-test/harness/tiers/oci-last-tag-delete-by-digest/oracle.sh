#!/usr/bin/env bash
# =============================================================================
# tiers/oci-last-tag-delete-by-digest/oracle.sh
#   artifact-keeper#1683 (1.12.0): manifest reads by digest, the referrers API
#   and the storage GC key on the oci_manifests existence table.
# See the manifest for the primitives and the gates.
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
SLOT_PREFIX="${DB_CONTAINER%-db}"
BACKEND_CTR="${SLOT_PREFIX}-backend"
FS_HELPER_IMAGE="${OLT_FS_HELPER_IMAGE:-postgres:16-alpine}"
INTERVAL=15        # OCI_MANIFESTS_RECONCILE_INTERVAL_SECS in profiles/gc.oci-manifests-reconcile-fast.yml
WAIT_SECS=75       # five intervals for the reconcile to act

setup_workdir
W="$WORK_DIR"

# common.sh may run under `set -e`: every probe swallows its own failure and
# the assertion that reads the (possibly empty) value judges it.
jqr(){ jq -r "$1" 2>/dev/null || true; }
psql_q(){ docker exec "$DBC" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]' || true; }
psql_x(){ docker exec "$DBC" psql -U registry -d artifact_registry -v ON_ERROR_STOP=1 -tAc "$1" >/dev/null 2>&1; }
sha_of(){ sha256sum "$1" 2>/dev/null | awk '{print $1}' || true; }

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

post_json(){ # <path> <outfile> <json> -> HTTP code (admin bearer)
  rm -f "$2"
  curl -s --max-time 120 -o "$2" -w '%{http_code}' -X POST -H "Authorization: Bearer $TOK" \
    -H 'Content-Type: application/json' -d "$3" "$BASE$1" || true
  [ -f "$2" ] || : > "$2"
}
body(){ head -c 400 "$1" 2>/dev/null | tr -d '\n' || true; }

# --- OCI over /v2 with curl-built manifests ---------------------------------
OCI_AUTH=()
MT='application/vnd.oci.image.manifest.v1+json'
IT='application/vnd.oci.image.index.v1+json'
oci_blob_push(){ # <image> <file> -> HTTP code (monolithic POST ?digest=)
  curl -s -o /dev/null -w '%{http_code}' "${OCI_AUTH[@]}" -X POST -H 'Content-Type: application/octet-stream' \
    --data-binary "@$2" "$BASE/v2/$REPO/$1/blobs/uploads/?digest=sha256:$(sha_of "$2")" || true
}
put_manifest(){ # <image> <reference> <media type> <file> -> HTTP code
  curl -s -o /dev/null -w '%{http_code}' "${OCI_AUTH[@]}" -X PUT -H "Content-Type: $3" \
    --data-binary "@$4" "$BASE/v2/$REPO/$1/manifests/$2" || true
}
# oci_image <name>: config + one layer pushed under image "app"; the manifest
# body is left in $W/<name>.man.json. Extra jq args add fields (a subject).
oci_image(){
  local n="$1" cfg="$W/$1.cfg.json" layer="$W/$1.layer" man="$W/$1.man.json" c1 c2
  shift
  printf '{"dtf":"%s","img":"%s"}' "$SUF" "$n" > "$cfg"
  printf 'olt-layer-%s-%s\n' "$n" "$SUF" > "$layer"
  c1="$(oci_blob_push app "$cfg")"; c2="$(oci_blob_push app "$layer")"
  jq -nc --arg cd "sha256:$(sha_of "$cfg")" --argjson cs "$(wc -c < "$cfg" | tr -d ' ')" \
         --arg ld "sha256:$(sha_of "$layer")" --argjson ls "$(wc -c < "$layer" | tr -d ' ')" "$@" \
    '{schemaVersion:2,mediaType:"application/vnd.oci.image.manifest.v1+json",
      config:{mediaType:"application/vnd.oci.image.config.v1+json",digest:$cd,size:$cs},
      layers:[{mediaType:"application/vnd.oci.image.layer.v1.tar",digest:$ld,size:$ls}]}
     + (if $ARGS.named.subj then {artifactType:"application/vnd.example.sig",subject:{mediaType:"application/vnd.oci.image.manifest.v1+json",digest:$ARGS.named.subj,size:10}} else {} end)' \
    | tr -d '\n' > "$man"
  echo "$c1 $c2"
}
# oci_index <name> <child digest>...: an index body in $W/<name>.man.json
oci_index(){
  local n="$1"; shift
  printf '%s\n' "$@" | jq -R . | jq -sc '{schemaVersion:2,mediaType:"application/vnd.oci.image.index.v1+json",
    manifests:[.[] | {mediaType:"application/vnd.oci.image.manifest.v1+json",digest:.,size:10,platform:{architecture:"amd64",os:"linux"}}]}' \
    | tr -d '\n' > "$W/$n.man.json"
}
man_digest(){ echo "sha256:$(sha_of "$W/$1.man.json")"; }
man_req(){ # <method> <reference> -> HTTP code of <method> /v2/<repo>/app/manifests/<reference>
  curl -s -o /dev/null -w '%{http_code}' --max-time 30 "${OCI_AUTH[@]}" -X "$1" \
    -H "Accept: $MT, $IT" "$BASE/v2/$REPO/app/manifests/$2" || true
}
referrers_n(){ # <subject digest> -> "<HTTP> <count>"
  local c
  c="$(curl -s -o "$W/ref.json" -w '%{http_code}' --max-time 30 "${OCI_AUTH[@]}" "$BASE/v2/$REPO/app/referrers/$1" || true)"
  echo "$c $(jq -r '.manifests | length' < "$W/ref.json" 2>/dev/null || echo '?')"
}
om_rows(){ psql_q "SELECT count(*) FROM oci_manifests WHERE repository_id='${REPO_ID}' AND digest='$1';"; }
gc_run(){ post_json /api/v1/admin/storage-gc "$1" '{"dry_run":false}'; }
repo_root(){ psql_q "SELECT storage_path FROM repositories WHERE id='${REPO_ID}';"; }
obj_present(){ # <digest> -> yes|no for oci-manifests/<digest> on the backend volume
  docker run --rm --volumes-from "$BACKEND_CTR" --entrypoint sh "$FS_HELPER_IMAGE" \
    -c "test -f '$(repo_root)/oci-manifests/$1' && echo yes || echo no" 2>/dev/null || echo "?"
}

# =============================================================================
begin_suite "oci-last-tag-delete-by-digest"

begin_test "setup: admin login, a docker repository, images, indexes and a signature pushed"
TOK="$(curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"${ADMIN_PASS}\"}" | jqr '.access_token // .token // empty')"
if [ -z "$TOK" ]; then infra_fail "admin login failed at $BASE"; end_suite; fi
OCI_AUTH=(-u "admin:${ADMIN_PASS}")
SUF="${RUN_ID##*-}-$$"
REPO="olt-${DTF_SLOT}-${SUF}"
REPO_ID="$(curl -s -X POST "$BASE/api/v1/repositories" -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg k "$REPO" '{key:$k,name:$k,format:"docker",repo_type:"local",is_public:false}')" | jqr '.id // empty')"
[ -n "$REPO_ID" ] || { infra_fail "could not create the docker repository ${REPO}"; end_suite; }
docker image inspect "$FS_HELPER_IMAGE" >/dev/null 2>&1 || docker pull -q "$FS_HELPER_IMAGE" >/dev/null 2>&1 || true
ERR=""
push(){ # <ref> <media type> <name>: record a failed push in ERR
  local c; c="$(put_manifest app "$1" "$2" "$W/$3.man.json")"
  [ "$c" = "201" ] || ERR="${ERR} PUT app:$1 (${3})=HTTP${c};"
}
# only:    pushed as app:only, its only tag deleted          (CONTROL + reconcile FIX)
# subject: pushed as app:subject, signed, its only tag deleted (referrers FIX)
# child1:  pushed as app:c1, referenced by index idx1 (app:idx1), c1 deleted
# child2:  pushed as app:c2, referenced by index idx2 (app:idx2), c2 deleted,
#          then app:idx2 moved to the image "moved"
# child3:  pushed as app:c3, referenced by index idx3 (app:idx3), then
#          deleted BY DIGEST while app:idx3 stays tagged
for n in only subject child1 child2 child3 moved; do
  codes="$(oci_image "$n")"
  [ "$codes" = "201 201" ] || ERR="${ERR} blobs of ${n}=${codes};"
done
D_ONLY="$(man_digest only)"; D_SUBJ="$(man_digest subject)"; D_C1="$(man_digest child1)"; D_C2="$(man_digest child2)"; D_C3="$(man_digest child3)"
oci_image sig --arg subj "$D_SUBJ" >/dev/null
D_SIG="$(man_digest sig)"
oci_index idx1 "$D_C1"; oci_index idx2 "$D_C2"; oci_index idx3 "$D_C3"
D_IDX1="$(man_digest idx1)"; D_IDX2="$(man_digest idx2)"; D_IDX3="$(man_digest idx3)"
push only "$MT" only; push subject "$MT" subject; push "$D_SIG" "$MT" sig
push c1 "$MT" child1; push idx1 "$IT" idx1
push c2 "$MT" child2; push idx2 "$IT" idx2
push c3 "$MT" child3; push idx3 "$IT" idx3
[ -z "$ERR" ] || { infra_fail "fixture pushes failed:${ERR}"; end_suite; }
echo "-- repo ${REPO} (${REPO_ID}): only ${D_ONLY}, subject ${D_SUBJ}, sig ${D_SIG}, child1 ${D_C1} (idx1 ${D_IDX1}), child2 ${D_C2} (idx2 ${D_IDX2})"
pass

# =============================================================================
begin_test "CONTROL: deleting an image's only tag answers 404 by digest (GET and HEAD) and removes its oci_manifests row"
reset_case
c="$(man_req DELETE only)"
g="$(man_req GET "$D_ONLY")"; h="$(man_req HEAD "$D_ONLY")"
note "DELETE manifests/only HTTP ${c}; GET by digest ${g}, HEAD ${h}; oci_manifests rows $(om_rows "$D_ONLY")"
case "$c" in 200|202|204) ;; *) fail_g "tag delete was HTTP ${c}";; esac
[ "$g" = "404" ] || fail_g "GET by digest after the last-tag delete was HTTP ${g}, expected 404"
[ "$h" = "404" ] || fail_g "HEAD by digest after the last-tag delete was HTTP ${h}, expected 404"
[ "$(om_rows "$D_ONLY")" = "0" ] || fail_g "the last-tag delete left the oci_manifests row"
finish_case "the last-tag delete leaves a manifest addressable by digest"

# The row a 1.11.0-era replica's last-tag delete left behind (#4449): put it
# back and age it past the reconcile's 600 s minimum row age.
psql_x "INSERT INTO oci_manifests (repository_id, digest, content_type, size_bytes, last_referenced_at)
        VALUES ('${REPO_ID}', '${D_ONLY}', '${MT}', $(wc -c < "$W/only.man.json" | tr -d ' '), NOW() - interval '1 hour')
        ON CONFLICT DO NOTHING;" || { infra_fail "could not re-insert the stale row"; end_suite; }

begin_test "CONTROL: the referrers listing follows the referrer: a subject's signature stays listed after the subject's only tag is deleted and after the subject is pushed again"
reset_case
before="$(referrers_n "$D_SUBJ")"
c="$(man_req DELETE subject)"
after="$(referrers_n "$D_SUBJ")"
sg="$(man_req GET "$D_SIG")"
ERR=""; push subject "$MT" subject
again="$(referrers_n "$D_SUBJ")"
note "referrers of the subject before: ${before}; DELETE manifests/subject HTTP ${c}; after: ${after}; GET signature by digest ${sg}; re-push ${ERR:-201}; after the re-push: ${again}"
[ "$before" = "200 1" ] || fail_g "the signature was not listed as a referrer before the delete (${before})"
case "$c" in 200|202|204) ;; *) fail_g "tag delete was HTTP ${c}";; esac
[ "$after" = "200 1" ] || fail_g "GET referrers of the deleted subject is '${after}', expected the signature (it still exists and names the subject)"
[ "$sg" = "200" ] || fail_g "the signature no longer pulls by digest (HTTP ${sg})"
[ -z "$ERR" ] || fail_g "re-pushing the subject failed:${ERR}"
[ "$again" = "200 1" ] || fail_g "GET referrers of the re-pushed subject is '${again}', expected the signature"
finish_case "the referrers of a deleted or re-pushed subject are no longer listed"

begin_test "FIX #1683: the untagged child of a tagged index still pulls by digest after its own tag is deleted, and after a storage GC run"
reset_case
c="$(man_req DELETE c1)"
g1="$(man_req GET "$D_C1")"
# The second untagged child: its index loses its tag too (moved to another image).
c2="$(man_req DELETE c2)"
m="$(put_manifest app idx2 "$MT" "$W/moved.man.json")"
gi2="$(man_req GET "$D_IDX2")"; gc2_before="$(man_req GET "$D_C2")"
gcode="$(gc_run "$W/gc")"
g1_after="$(man_req GET "$D_C1")"; gi1="$(man_req GET "$D_IDX1")"
note "DELETE c1 HTTP ${c}; child1 by digest ${g1}, after GC ${g1_after} (GC HTTP ${gcode}: $(jq -c '{deleted_keys:(.deleted_keys // .storage_keys_deleted // null)}' < "$W/gc" 2>/dev/null)); idx1 by digest ${gi1}; child1 object $(obj_present "$D_C1")"
case "$c" in 200|202|204) ;; *) fail_g "tag delete of c1 was HTTP ${c}";; esac
[ "$gcode" = "200" ] || fail_g "storage GC was HTTP ${gcode}: $(body "$W/gc")"
[ "$g1" = "200" ] || fail_g "the untagged child of a tagged index answers ${g1} by digest, expected 200"
[ "$g1_after" = "200" ] || fail_g "after a storage GC run the child answers ${g1_after} by digest, expected 200"
[ "$(obj_present "$D_C1")" = "yes" ] || fail_g "storage GC removed the child's manifest object"
[ "$gi1" = "200" ] || fail_g "the tagged index answers ${gi1} by digest"
finish_case "#1683: the untagged child of a tagged index is lost"

begin_test "FIX #1683: storage GC keeps the child of an index whose tag moved away (the index still pulls by digest)"
reset_case
g2_after="$(man_req GET "$D_C2")"; gi2_after="$(man_req GET "$D_IDX2")"
o2="$(obj_present "$D_C2")"
note "DELETE c2 HTTP ${c2}; PUT app:idx2 (moved) HTTP ${m}; idx2 by digest ${gi2} -> ${gi2_after} after GC; child2 by digest ${gc2_before} -> ${g2_after}; child2 object ${o2}"
[ "$m" = "201" ] || fail_g "moving app:idx2 was HTTP ${m}"
[ "$gi2_after" = "200" ] || fail_g "the untagged index no longer pulls by digest (HTTP ${gi2_after})"
[ "$o2" = "yes" ] || fail_g "storage GC removed the manifest object of a child its index still serves"
[ "$g2_after" = "200" ] || fail_g "the child of the untagged index answers ${g2_after} by digest after GC, expected 200"
finish_case "#1683: storage GC reclaims the child of an untagged index that still pulls by digest"

begin_test "FIX #1683: a child pushed under a tag and deleted BY DIGEST answers 404 by digest while its index stays tagged, and its row is gone"
reset_case
c="$(man_req DELETE "$D_C3")"
g="$(man_req GET "$D_C3")"; h="$(man_req HEAD "$D_C3")"; gi3="$(man_req GET "$D_IDX3")"
note "DELETE manifests/<child3 digest> HTTP ${c}; GET by digest ${g}, HEAD ${h}; oci_manifests rows $(om_rows "$D_C3"); idx3 by digest ${gi3}"
case "$c" in 200|202|204) ;; *) fail_g "delete by digest was HTTP ${c}";; esac
[ "$g" = "404" ] || fail_g "GET by digest after a delete by digest was HTTP ${g}, expected 404"
[ "$h" = "404" ] || fail_g "HEAD by digest after a delete by digest was HTTP ${h}, expected 404"
[ "$(om_rows "$D_C3")" = "0" ] || fail_g "the delete by digest left the oci_manifests row"
[ "$gi3" = "200" ] || fail_g "the tagged index answers ${gi3} by digest"
finish_case "a manifest deleted by digest is still served"

# Let the reconcile run on the stale row of the "only" image.
T0="$(date +%s)"
while :; do
  [ "$(om_rows "$D_ONLY")" = "0" ] && break
  [ $(( $(date +%s) - T0 )) -ge "$WAIT_SECS" ] && break
  sleep 2
done
WAITED=$(( $(date +%s) - T0 ))

begin_test "FIX #1683: a stale row left by a last-tag delete answers 404 by digest and the reconcile removes it"
reset_case
g="$(man_req GET "$D_ONLY")"
note "after ${WAITED}s (interval ${INTERVAL}s): oci_manifests rows $(om_rows "$D_ONLY"); GET by digest ${g}"
[ "$(om_rows "$D_ONLY")" = "0" ] || fail_g "the stale row of a manifest whose last tag was deleted is still in oci_manifests after ${WAITED}s"
[ "$g" = "404" ] || fail_g "GET by digest of the deleted manifest was HTTP ${g}, expected 404"
finish_case "#1683: the row of a manifest whose last tag was deleted stays"

end_suite
