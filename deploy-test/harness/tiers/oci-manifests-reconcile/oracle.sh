#!/usr/bin/env bash
# =============================================================================
# tiers/oci-manifests-reconcile/oracle.sh
#   artifact-keeper#1683 (1.12.0): the backend reconciles the oci_manifests
#   existence table at startup and every OCI_MANIFESTS_RECONCILE_INTERVAL_SECS:
#   it removes rows of manifests that are no longer addressable and adds rows
#   for tagged manifests that have none.
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
INTERVAL=15        # OCI_MANIFESTS_RECONCILE_INTERVAL_SECS in profiles/gc.oci-manifests-reconcile-fast.yml
WAIT_SECS=75       # five intervals for the reconcile to act on the prepared rows
SETTLE_SECS=35     # two more intervals before the "row stays" controls are read

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

# http <method> <path> <outfile> [curl args...] -> HTTP code (admin bearer)
http(){
  local m="$1" u="$2" o="$3"
  shift 3
  rm -f "$o"
  curl -s --max-time 60 -o "$o" -w '%{http_code}' -X "$m" -H "Authorization: Bearer $TOK" "$@" "$BASE$u" || true
  [ -f "$o" ] || : > "$o"
}
body(){ head -c 400 "$1" 2>/dev/null | tr -d '\n' || true; }
post_json(){ http POST "$1" "$2" -H 'Content-Type: application/json' -d "$3"; }

# --- OCI over /v2 with curl-built manifests (as trash-blob-gc-remote-cache) ---
OCI_AUTH=()
MT='application/vnd.oci.image.manifest.v1+json'
oci_blob_push(){ # <image> <file> -> HTTP code (monolithic POST ?digest=)
  curl -s -o /dev/null -w '%{http_code}' "${OCI_AUTH[@]}" -X POST -H 'Content-Type: application/octet-stream' \
    --data-binary "@$2" "$BASE/v2/$REPO/$1/blobs/uploads/?digest=sha256:$(sha_of "$2")" || true
}
# oci_push <image> <reference> -> "<cfg> <layer> <manifest>" HTTP codes;
# the manifest body is left in $W/<image>.man.json
oci_push(){
  local img="$1" ref="$2" cfg="$W/$1.cfg.json" layer="$W/$1.layer" man="$W/$1.man.json" c1 c2 c3
  printf '{"dtf":"%s","img":"%s"}' "$SUF" "$img" > "$cfg"
  printf 'omr-layer-%s-%s\n' "$img" "$SUF" > "$layer"
  c1="$(oci_blob_push "$img" "$cfg")"
  c2="$(oci_blob_push "$img" "$layer")"
  jq -nc --arg cd "sha256:$(sha_of "$cfg")" --argjson cs "$(wc -c < "$cfg" | tr -d ' ')" \
         --arg ld "sha256:$(sha_of "$layer")" --argjson ls "$(wc -c < "$layer" | tr -d ' ')" \
    '{schemaVersion:2,mediaType:"application/vnd.oci.image.manifest.v1+json",
      config:{mediaType:"application/vnd.oci.image.config.v1+json",digest:$cd,size:$cs},
      layers:[{mediaType:"application/vnd.oci.image.layer.v1.tar",digest:$ld,size:$ls}]}' | tr -d '\n' > "$man"
  [ "$ref" = "@digest" ] && ref="sha256:$(sha_of "$man")"
  c3="$(curl -s -o /dev/null -w '%{http_code}' "${OCI_AUTH[@]}" -X PUT -H "Content-Type: $MT" \
    --data-binary "@$man" "$BASE/v2/$REPO/$img/manifests/$ref" || true)"
  echo "$c1 $c2 $c3"
}
man_digest(){ echo "sha256:$(sha_of "$W/$1.man.json")"; }
man_get(){ # <image> <reference> -> HTTP code of GET /v2/<repo>/<image>/manifests/<reference>
  curl -s -o /dev/null -w '%{http_code}' "${OCI_AUTH[@]}" -H "Accept: $MT" "$BASE/v2/$REPO/$1/manifests/$2" || true
}
om_rows(){ psql_q "SELECT count(*) FROM oci_manifests WHERE repository_id='${REPO_ID}' AND digest='$1';"; }
om_size(){ psql_q "SELECT size_bytes FROM oci_manifests WHERE repository_id='${REPO_ID}' AND digest='$1';"; }
tag_rows(){ psql_q "SELECT count(*) FROM oci_tags WHERE repository_id='${REPO_ID}' AND manifest_digest='$1';"; }
live_rows(){ psql_q "SELECT count(*) FROM artifacts WHERE repository_id='${REPO_ID}' AND storage_key='oci-manifests/$1' AND NOT is_deleted;"; }
# The reconcile only removes a row whose last_referenced_at is older than
# 600 s (RECONCILE_MIN_ROW_AGE_SECS). Moving it back an hour with SQL stands
# in for that time passing; nothing else about the row changes.
age_row(){ psql_x "UPDATE oci_manifests SET last_referenced_at = NOW() - interval '1 hour' WHERE repository_id='${REPO_ID}' AND digest='$1';"; }
metric(){ # <name> -> value (0 when absent)
  local v
  v="$(curl -s --max-time 10 -H "Authorization: Bearer $TOK" "$BASE/api/v1/admin/metrics" \
       | awk -v n="$1" '$1 == n || index($1, n "{") == 1 {print $NF}' | tail -1 || true)"
  echo "${v:-0}"
}

POLICIES=()
policy_cleanup(){ local p; for p in "${POLICIES[@]:-}"; do [ -n "$p" ] && http DELETE "/api/v1/admin/lifecycle/$p" "$W/del" >/dev/null; done; POLICIES=(); }
trap policy_cleanup EXIT

# =============================================================================
begin_suite "oci-manifests-reconcile"

begin_test "setup: admin login, a docker repository, five tagged images pushed"
TOK="$(curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"${ADMIN_PASS}\"}" | jqr '.access_token // .token // empty')"
if [ -z "$TOK" ]; then infra_fail "admin login failed at $BASE"; end_suite; fi
OCI_AUTH=(-u "admin:${ADMIN_PASS}")
SUF="${RUN_ID##*-}-$$"
REPO="omr-${DTF_SLOT}-${SUF}"
REPO_ID="$(curl -s -X POST "$BASE/api/v1/repositories" -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg k "$REPO" '{key:$k,name:$k,format:"docker",repo_type:"local",is_public:false}')" | jqr '.id // empty')"
[ -n "$REPO_ID" ] || { infra_fail "could not create the docker repository ${REPO}"; end_suite; }
# live:   tagged, stays tagged                         (CONTROL, row kept)
# untag:  its only tag deleted over /v2                (CONTROL, #4512 unwind)
# notag:  its oci_tags row deleted with SQL, artifacts row live (CONTROL, row kept)
# expire: its tag pruned by a lifecycle policy         (FIX, row removed)
# lost:   tagged, its row deleted with SQL             (FIX, row re-added)
for img in live untag notag expire lost; do
  codes="$(oci_push "$img" v1)"
  [ "$codes" = "201 201 201" ] || { infra_fail "push of ${img} was (config layer manifest) ${codes}"; end_suite; }
done
D_LIVE="$(man_digest live)"; D_UNTAG="$(man_digest untag)"; D_NOTAG="$(man_digest notag)"
D_EXP="$(man_digest expire)"; D_LOST="$(man_digest lost)"
missing=""
for d in "$D_LIVE" "$D_UNTAG" "$D_NOTAG" "$D_EXP" "$D_LOST"; do [ "$(om_rows "$d")" = "1" ] || missing="${missing} ${d}"; done
[ -z "$missing" ] || { infra_fail "pushes recorded no oci_manifests row for:${missing}"; end_suite; }
echo "-- repo ${REPO} (${REPO_ID}): live ${D_LIVE}, untag ${D_UNTAG}, notag ${D_NOTAG}, expire ${D_EXP}, lost ${D_LOST}"
pass

# =============================================================================
# CONTROL (both images, #4512 in 1.11.0): deleting a manifest's only tag over
# /v2 removes its oci_manifests row in the same transaction.
# =============================================================================
begin_test "CONTROL: deleting an image's only tag removes its oci_manifests row; GET by digest is 404"
reset_case
c="$(curl -s -o /dev/null -w '%{http_code}' "${OCI_AUTH[@]}" -X DELETE "$BASE/v2/$REPO/untag/manifests/v1" || true)"
g="$(man_get untag "$D_UNTAG")"
note "DELETE manifests/v1 HTTP ${c}; tags $(tag_rows "$D_UNTAG"), oci_manifests rows $(om_rows "$D_UNTAG"); GET by digest HTTP ${g}"
case "$c" in 200|202|204) ;; *) fail_g "tag delete was HTTP ${c}";; esac
[ "$(om_rows "$D_UNTAG")" = "0" ] || fail_g "the last-tag delete left the oci_manifests row"
[ "$g" = "404" ] || fail_g "GET by digest after the last-tag delete was HTTP ${g}, expected 404"
finish_case "the last-tag delete does not unwind oci_manifests"

# =============================================================================
# The lifecycle tag prune: a max_age_days policy explicitly assigned to the
# repository soft-deletes the expired manifest artifact and its cascade
# (CASCADE_OCI_TAGS_SQL) deletes the tag. Nothing in that path touches
# oci_manifests, so the row is left behind for the reconcile.
# =============================================================================
begin_test "CONTROL: a max_age_days policy assigned to the repository expires one image: tag pruned, manifest artifact soft-deleted, GET by digest 404; the other images stay"
reset_case
# The policy's clock is COALESCE(oci_tags.updated_at, artifacts.created_at);
# both are moved ten days back for the expire image only.
psql_x "UPDATE oci_tags SET updated_at = NOW() - interval '10 days' WHERE repository_id='${REPO_ID}' AND manifest_digest='${D_EXP}';" \
  && psql_x "UPDATE artifacts SET created_at = NOW() - interval '10 days' WHERE repository_id='${REPO_ID}' AND storage_key='oci-manifests/${D_EXP}';" \
  || { infra_fail "could not backdate the expire image"; end_suite; }
PCODE="$(post_json /api/v1/admin/lifecycle "$W/pol" "$(jq -nc --arg n "omr-expire-${SUF}" --arg r "$REPO_ID" \
  '{name:$n,repository_ids:[$r],policy_type:"max_age_days",config:{days:5}}')")"
PID="$(jqr '.id // empty' < "$W/pol")"
[ -n "$PID" ] && POLICIES+=("$PID")
[ -n "$PID" ] || { infra_fail "lifecycle policy create was HTTP ${PCODE}: $(body "$W/pol")"; end_suite; }
c="$(http POST "/api/v1/admin/lifecycle/${PID}/execute" "$W/ex")"
g="$(man_get expire "$D_EXP")"
note "execute HTTP ${c} $(jq -c '{artifacts_removed:(.artifacts_removed // .removed // null)}' < "$W/ex" 2>/dev/null || body "$W/ex")"
note "expire: tags $(tag_rows "$D_EXP"), live artifacts rows $(live_rows "$D_EXP"), oci_manifests rows $(om_rows "$D_EXP"); GET by digest HTTP ${g}"
[ "$c" = "200" ] || fail_g "policy execute was HTTP ${c}: $(body "$W/ex")"
[ "$(tag_rows "$D_EXP")" = "0" ] || fail_g "the lifecycle cascade did not prune the expired image's tag"
[ "$(live_rows "$D_EXP")" = "0" ] || fail_g "the expired manifest artifact is still live"
[ "$g" = "404" ] || fail_g "GET by digest of the expired manifest was HTTP ${g}, expected 404"
for i in live notag lost; do
  d="$(man_digest "$i")"
  [ "$(live_rows "$d")" = "1" ] || fail_g "the policy expired ${i} too"
done
policy_cleanup
finish_case "the lifecycle expiry precondition did not hold"

# Prepare the reconcile's work, then let it run.
# The expire row and the two keep-controls are aged past the 600 s minimum
# row age (see age_row); the notag image loses its oci_tags row but keeps
# its live artifacts row (the third way a manifest stays addressable); the
# lost image's row is deleted, which is what a push served by a pre-268
# replica during a rolling upgrade leaves.
psql_x "DELETE FROM oci_tags WHERE repository_id='${REPO_ID}' AND manifest_digest='${D_NOTAG}';" || { infra_fail "could not delete the notag image's tag"; end_suite; }
age_row "$D_EXP"; age_row "$D_LIVE"; age_row "$D_NOTAG"
psql_x "DELETE FROM oci_manifests WHERE repository_id='${REPO_ID}' AND digest='${D_LOST}';" || { infra_fail "could not delete the lost image's row"; end_suite; }
M_RM0="$(metric ak_oci_manifests_reconcile_rows_removed_total)"
T0="$(date +%s)"
while :; do
  [ "$(om_rows "$D_EXP")" = "0" ] && [ "$(om_rows "$D_LOST")" = "1" ] && break
  [ $(( $(date +%s) - T0 )) -ge "$WAIT_SECS" ] && break
  sleep 2
done
WAITED=$(( $(date +%s) - T0 ))
EXP_ROWS="$(om_rows "$D_EXP")"; LOST_ROWS="$(om_rows "$D_LOST")"
# Two more intervals, so a keep-control is read after passes that saw it aged.
sleep "$SETTLE_SECS"

begin_test "FIX #1683: the reconcile removes the oci_manifests row of the image a lifecycle policy expired"
reset_case
note "after ${WAITED}s (interval ${INTERVAL}s): expire oci_manifests rows ${EXP_ROWS}, now $(om_rows "$D_EXP"); GET by digest HTTP $(man_get expire "$D_EXP")"
[ "$EXP_ROWS" = "0" ] && [ "$(om_rows "$D_EXP")" = "0" ] || fail_g "the row of the unaddressable expired manifest is still in oci_manifests after ${WAITED}s (no tag, no live artifacts row, GET by digest 404)"
[ "$(man_get expire "$D_EXP")" = "404" ] || fail_g "the expired manifest answers GET by digest"
finish_case "#1683: oci_manifests keeps rows of manifests a lifecycle tag prune made unaddressable"

begin_test "FIX #1683: the reconcile re-adds the oci_manifests row of a tagged image that lost it, without a restart"
reset_case
BODY_LEN="$(wc -c < "$W/lost.man.json" | tr -d ' ')"
note "after ${WAITED}s: lost oci_manifests rows ${LOST_ROWS}, size_bytes $(om_size "$D_LOST") (body ${BODY_LEN}); GET by tag HTTP $(man_get lost v1)"
[ "$LOST_ROWS" = "1" ] || fail_g "no oci_manifests row for the still-tagged image ${WAITED}s after it was lost (the backfill runs only at startup)"
[ "$(om_size "$D_LOST")" = "$BODY_LEN" ] || fail_g "the re-added row's size_bytes is '$(om_size "$D_LOST")', expected the body length ${BODY_LEN}"
[ "$(man_get lost v1)" = "200" ] || fail_g "the lost image no longer pulls by tag"
finish_case "#1683: oci_manifests rows missing for tagged images are not re-added"

begin_test "CONTROL: rows of addressable manifests stay through the passes (a tagged image; an untagged image whose artifacts row is live)"
reset_case
note "live: rows $(om_rows "$D_LIVE"), GET by digest $(man_get live "$D_LIVE"); notag: rows $(om_rows "$D_NOTAG"), tags $(tag_rows "$D_NOTAG"), live artifacts rows $(live_rows "$D_NOTAG")"
[ "$(om_rows "$D_LIVE")" = "1" ] && [ "$(man_get live "$D_LIVE")" = "200" ] || fail_g "the tagged image lost its row or stopped serving"
[ "$(om_rows "$D_NOTAG")" = "1" ] || fail_g "the reconcile removed the row of an untagged manifest whose artifacts row is live"
M_RM1="$(metric ak_oci_manifests_reconcile_rows_removed_total)"
note "ak_oci_manifests_reconcile_rows_removed_total ${M_RM0} -> ${M_RM1} (reported, not gated)"
finish_case "the reconcile removed the row of an addressable manifest"

end_suite
