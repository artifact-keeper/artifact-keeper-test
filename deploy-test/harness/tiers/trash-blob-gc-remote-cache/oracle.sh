#!/usr/bin/env bash
# =============================================================================
# tiers/trash-blob-gc-remote-cache/oracle.sh
#   1.11.0 storage reclaim features: the soft-delete trash with
#   GC_TRASH_RETENTION_DAYS, list and restore (#2072); the configurable
#   unreferenced-blob age shield BLOB_GC_MIN_AGE_SECS (#2906); lifecycle
#   eviction of a Remote repository's proxy cache (#3734); and 1.11.2's
#   scheduled-run accounting of those evictions (#4451).
# See the manifest for the primitives and the gates.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# TRIVY_PORT (the mock's control port), RELEASE_GATE=1, JUNIT_OUTPUT_DIR,
# COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"
: "${DTF_SLOT:?}"; : "${TRIVY_PORT:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

BASE="$BASE_URL"
DBC="$DB_CONTAINER"
BACKEND_CTR="${DB_CONTAINER%-db}-backend"
MOCK="http://127.0.0.1:${TRIVY_PORT}"
UPSTREAM="http://172.16.${DTF_SLOT}.70/"   # profiles/upstreams.mock-static.yml
FS_HELPER_IMAGE="postgres:16-alpine"       # already pulled by compose.base.yml
BLOB_MIN_AGE=60                            # BLOB_GC_MIN_AGE_SECS in profiles/gc.trash-blob-fast.yml

setup_workdir
W="$WORK_DIR"

# common.sh may run under `set -e`: every probe swallows its own failure and
# the assertion that reads the (possibly empty) value judges it.
jqr(){ jq -r "$1" 2>/dev/null || true; }
psql_q(){ docker exec "$DBC" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]' || true; }
psql_x(){ docker exec "$DBC" psql -U registry -d artifact_registry -v ON_ERROR_STOP=1 -tAc "$1" >/dev/null 2>&1; }
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
gc_run(){ post_json /api/v1/admin/storage-gc "$1" '{"dry_run":false}'; }

# --- hosted generic artifacts -------------------------------------------------
gen_put(){ http PUT "/api/v1/repositories/$1/artifacts/$2" "$W/o" -H 'Content-Type: application/octet-stream' --data-binary "@$3"; }
gen_get(){ http GET "/api/v1/repositories/$1/download/$2" "$3"; }
row_id(){ psql_q "SELECT a.id FROM artifacts a JOIN repositories r ON r.id=a.repository_id WHERE r.key='$1' AND a.path='$2' ORDER BY a.created_at DESC LIMIT 1;"; }
row_state(){ # <id> -> live | trashed | gone
  local d; d="$(psql_q "SELECT is_deleted FROM artifacts WHERE id='$1';")"
  case "$d" in t) echo trashed;; f) echo live;; *) echo gone;; esac
}
key_of(){ psql_q "SELECT storage_key FROM artifacts WHERE id='$1';"; }
root_of(){ psql_q "SELECT storage_path FROM repositories WHERE key='$1';"; }
obj_exists(){ fsx "[ -f '$1/$2' ] && echo yes || echo no" | tr -d '[:space:]'; }

# --- OCI ----------------------------------------------------------------------
OCI_AUTH=()
oci_blob_push(){ # <repo> <image> <file> -> HTTP code
  curl -s -o /dev/null -w '%{http_code}' "${OCI_AUTH[@]}" -X POST -H 'Content-Type: application/octet-stream' \
    --data-binary "@$3" "$BASE/v2/$1/$2/blobs/uploads/?digest=sha256:$(sha_of "$3")" || true
}
# oci_push_image <repo> <image> <tag> <layer-file> -> "<cfg> <layer> <manifest>" codes
oci_push_image(){
  local repo="$1" img="$2" tag="$3" layer="$4" cfg="$W/$2.cfg.json" man="$W/$2.man.json" c1 c2 c3
  printf '{"dtf":"%s","img":"%s"}' "$SUF" "$img" > "$cfg"
  c1="$(oci_blob_push "$repo" "$img" "$cfg")"
  c2="$(oci_blob_push "$repo" "$img" "$layer")"
  jq -nc --arg cd "sha256:$(sha_of "$cfg")" --argjson cs "$(wc -c < "$cfg" | tr -d ' ')" \
         --arg ld "sha256:$(sha_of "$layer")" --argjson ls "$(wc -c < "$layer" | tr -d ' ')" \
    '{schemaVersion:2,mediaType:"application/vnd.oci.image.manifest.v1+json",
      config:{mediaType:"application/vnd.oci.image.config.v1+json",digest:$cd,size:$cs},
      layers:[{mediaType:"application/vnd.oci.image.layer.v1.tar",digest:$ld,size:$ls}]}' > "$man"
  c3="$(curl -s -o /dev/null -w '%{http_code}' "${OCI_AUTH[@]}" -X PUT -H 'Content-Type: application/vnd.oci.image.manifest.v1+json' \
    --data-binary "@$man" "$BASE/v2/$repo/$img/manifests/$tag" || true)"
  echo "$c1 $c2 $c3"
}
oci_blob_status(){ curl -s -o /dev/null -w '%{http_code}' "${OCI_AUTH[@]}" "$BASE/v2/$1/$2/blobs/$3" || true; }
oci_manifest_status(){ curl -s -o /dev/null -w '%{http_code}' "${OCI_AUTH[@]}" -H 'Accept: application/vnd.oci.image.manifest.v1+json' "$BASE/v2/$1/$2/manifests/$3" || true; }

# --- the Remote repositories and the mock upstream ----------------------------
mock_count(){ curl -s --max-time 5 "${MOCK}/__requests?path=/f/$1" | jqr '.count // empty'; }
remote_get(){ # <repo> <name> <outfile> -> HTTP code
  rm -f "$3"
  curl -s --max-time 30 -o "$3" -w '%{http_code}' -H "Authorization: Bearer $TOK" \
    "$BASE/api/v1/repositories/$1/download/f/$2" || true
}
cache_rows(){ # <repo> <name> -> number of proxy_cache_artifacts rows for f/<name>
  psql_q "SELECT count(*) FROM proxy_cache_artifacts p JOIN repositories r ON r.id=p.repository_id WHERE r.key='$1' AND p.path='f/$2';"
}
wait_cache_row(){ local _i; for _i in $(seq 1 40); do [ "$(cache_rows "$1" "$2")" = "1" ] && return 0; sleep 0.5; done; return 1; }
cache_content(){ # <repo> <name> -> yes | no: a __content__ object on disk
  fsx "ls /data/storage/proxy-cache/*/$1/f/$2/__content__ >/dev/null 2>&1 && echo yes || echo no" | tr -d '[:space:]'
}
cache_age(){ psql_x "UPDATE proxy_cache_artifacts p SET cached_at = NOW() - make_interval(days => $3) FROM repositories r WHERE r.id=p.repository_id AND r.key='$1' AND p.path='f/$2';"; }

# Lifecycle policies created here are deleted on exit.
POLICIES=()
policy_cleanup(){ local p; for p in "${POLICIES[@]:-}"; do [ -n "$p" ] && http DELETE "/api/v1/admin/lifecycle/$p" "$W/del" >/dev/null; done; POLICIES=(); }
trap policy_cleanup EXIT
mkpol(){ # <json> -> PCODE, PID; response in $W/pol
  PCODE="$(post_json /api/v1/admin/lifecycle "$W/pol" "$1")"
  PID="$(jqr '.id // empty' < "$W/pol")"
  [ -n "$PID" ] && POLICIES+=("$PID")
  return 0
}
metric_lifecycle(){ # current ak_cleanup_items_removed_total{type="lifecycle"} (0 when absent)
  local v
  v="$(curl -s --max-time 10 -H "Authorization: Bearer $TOK" "$BASE/api/v1/admin/metrics" \
       | awk '/^ak_cleanup_items_removed_total\{/ && /type="lifecycle"/ {print $NF}' | tail -1 || true)"
  echo "${v:-0}"
}

# =============================================================================
begin_suite "trash-blob-gc-remote-cache"

begin_test "setup: admin login, hosted generic + docker repositories, two generic Remotes on the mock upstream; push two OCI images"
TOK="$(curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"${ADMIN_PASS}\"}" | jqr '.access_token // .token // empty')"
if [ -z "$TOK" ]; then infra_fail "admin login failed at $BASE"; end_suite; fi
if [ "$(curl -s --max-time 5 "${MOCK}/__readyz" || true)" != "ok" ]; then
  infra_fail "mock upstream not reachable on ${MOCK} (profiles/upstreams.mock-static.yml)"; end_suite
fi
OCI_AUTH=(-u "admin:${ADMIN_PASS}")
SUF="${RUN_ID##*-}-$$"
R_GEN="tb-gen-${DTF_SLOT}-${SUF}"; R_OCI="tb-oci-${DTF_SLOT}-${SUF}"
R_RM="tb-rm-${DTF_SLOT}-${SUF}"; R_RS="tb-rs-${DTF_SLOT}-${SUF}"
mk(){ # <key> <format> <type> [upstream] -> id
  curl -s -X POST "$BASE/api/v1/repositories" -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg k "$1" --arg f "$2" --arg t "$3" --arg u "${4:-}" \
      '{key:$k,name:$k,format:$f,repo_type:$t,is_public:false} + (if $u == "" then {} else {upstream_url:$u} end)')" \
    | jqr '.id // empty'
}
SETUP_ERR=""
ID_GEN="$(mk "$R_GEN" generic local)"; [ -n "$ID_GEN" ] || SETUP_ERR="${SETUP_ERR} generic"
ID_OCI="$(mk "$R_OCI" docker local)"; [ -n "$ID_OCI" ] || SETUP_ERR="${SETUP_ERR} docker"
ID_RM="$(mk "$R_RM" generic remote "$UPSTREAM")"; [ -n "$ID_RM" ] || SETUP_ERR="${SETUP_ERR} remote-1"
ID_RS="$(mk "$R_RS" generic remote "$UPSTREAM")"; [ -n "$ID_RS" ] || SETUP_ERR="${SETUP_ERR} remote-2"
if [ -n "$SETUP_ERR" ]; then infra_fail "could not create repositories:${SETUP_ERR}"; end_suite; fi
# Two images early, so the blob-shield case waits out the age floor while the
# other cases run. Image A's layer B1 becomes unreferenced; image B stays live.
printf 'tb-layer-b1-%s\n' "$SUF" > "$W/b1.bin"; printf 'tb-layer-b2-%s\n' "$SUF" > "$W/b2.bin"
B1="sha256:$(sha_of "$W/b1.bin")"; B2="sha256:$(sha_of "$W/b2.bin")"
pa="$(oci_push_image "$R_OCI" img-a v1 "$W/b1.bin")"; pb="$(oci_push_image "$R_OCI" img-b v1 "$W/b2.bin")"
B1_PUSHED_AT="$(date +%s)"
case "$pa $pb" in "201 201 201 201 201 201") ;; *) infra_fail "OCI pushes were (cfg layer manifest) ${pa} / ${pb}"; end_suite;; esac
echo "-- repos: ${R_GEN} ${R_OCI} ${R_RM} ${R_RS} -> ${UPSTREAM}"
pass

# =============================================================================
# CONTROL (both images): a delete soft-deletes and the path stops serving.
# FIX #2072: with GC_TRASH_RETENTION_DAYS=1, storage GC keeps the trashed row
# and its object; GET /admin/trash lists it with purge_eligible_at about a
# day after deleted_at; restore brings it back serving byte-exact.
# =============================================================================
head -c 4096 /dev/urandom > "$W/t1.bin"
begin_test "CONTROL: an uploaded generic artifact deleted through the API is soft-deleted and no longer downloads"
reset_case
c="$(gen_put "$R_GEN" keep/t1.bin "$W/t1.bin")"
[ "$c" = "201" ] || { infra_fail "generic upload was HTTP ${c}: $(body "$W/o")"; end_suite; }
T1="$(row_id "$R_GEN" keep/t1.bin)"; K1="$(key_of "$T1")"; ROOT_GEN="$(root_of "$R_GEN")"
c="$(http DELETE "/api/v1/repositories/${R_GEN}/artifacts/keep/t1.bin" "$W/o")"
c2="$(gen_get "$R_GEN" keep/t1.bin "$W/t1.get")"
note "delete HTTP ${c}, row $(row_state "$T1"), download after delete HTTP ${c2}"
[ "$c" = "200" ] || [ "$c" = "204" ] || fail_g "delete was HTTP ${c}"
[ "$(row_state "$T1")" = "trashed" ] || fail_g "the row is $(row_state "$T1"), expected soft-deleted"
[ "$c2" = "404" ] || fail_g "the deleted artifact still downloads (HTTP ${c2})"
finish_case "soft delete broken"

begin_test "FIX #2072: storage GC keeps a trashed artifact inside GC_TRASH_RETENTION_DAYS; /admin/trash lists it with purge_eligible_at = deleted_at + 1 day; restore serves it byte-exact"
reset_case
c="$(gc_run "$W/gc")"
st="$(row_state "$T1")"; ob="$(obj_exists "$ROOT_GEN" "$K1")"
note "storage GC: HTTP ${c}; row ${st}, object ${ROOT_GEN}/${K1} ${ob}"
[ "$c" = "200" ] || fail_g "storage GC was HTTP ${c}: $(body "$W/gc")"
[ "$st" = "trashed" ] || fail_g "GC reclaimed the trashed row inside the retention window (row ${st}; 1.10.0 has no retention)"
[ "$ob" = "yes" ] || fail_g "GC deleted the trashed artifact's object inside the retention window"
c="$(http GET "/api/v1/admin/trash?repository=${R_GEN}&per_page=100" "$W/tr")"
item="$(jq -c --arg i "$T1" '[.items[]? | select(.id == $i)][0] // empty' < "$W/tr" 2>/dev/null || true)"
note "trash list: HTTP ${c}, retention_days $(jqr '.retention_days' < "$W/tr"), item ${item:0:300}"
[ "$c" = "200" ] && [ -n "$item" ] || fail_g "GET /admin/trash does not list the trashed artifact (HTTP ${c})"
[ "$(jqr '.retention_days' < "$W/tr")" = "1" ] || fail_g "retention_days is '$(jqr '.retention_days' < "$W/tr")', expected 1"
if [ -n "$item" ]; then
  gap="$(jq -r '((.purge_eligible_at | sub("\\.[0-9]+";"") | sub("\\+00:00$";"Z") | fromdateiso8601) - (.deleted_at | sub("\\.[0-9]+";"") | sub("\\+00:00$";"Z") | fromdateiso8601))' <<<"$item" 2>/dev/null || true)"
  note "purge_eligible_at - deleted_at = ${gap}s; restorable $(jqr '.restorable' <<<"$item")"
  [ "$gap" = "86400" ] || fail_g "purge_eligible_at is not deleted_at + 1 day (gap ${gap:-?}s)"
  [ "$(jqr '.restorable' <<<"$item")" = "true" ] || fail_g "the item is not restorable"
fi
c="$(http POST "/api/v1/admin/trash/${T1}/restore" "$W/rs")"
c2="$(gen_get "$R_GEN" keep/t1.bin "$W/t1.get")"
note "restore HTTP ${c}, row $(row_state "$T1"); download HTTP ${c2}"
[ "$c" = "200" ] && [ "$(row_state "$T1")" = "live" ] || fail_g "restore was HTTP ${c}, row $(row_state "$T1"): $(body "$W/rs")"
[ "$c2" = "200" ] && [ "$(sha_of "$W/t1.get")" = "$(sha_of "$W/t1.bin")" ] || fail_g "the restored artifact does not download byte-exact (HTTP ${c2})"
finish_case "#2072: the trash does not hold, list or restore a deleted artifact"

# CONTROL (both images): once the retention window has passed (deleted_at
# moved back with SQL; on a release without the column only the GC runs),
# storage GC reclaims the row and the object.
begin_test "CONTROL: a trashed artifact past the retention window is reclaimed by storage GC (row and object)"
reset_case
head -c 2048 /dev/urandom > "$W/t2.bin"
c="$(gen_put "$R_GEN" expire/t2.bin "$W/t2.bin")"
[ "$c" = "201" ] || { infra_fail "generic upload was HTTP ${c}"; end_suite; }
T2="$(row_id "$R_GEN" expire/t2.bin)"; K2="$(key_of "$T2")"
http DELETE "/api/v1/repositories/${R_GEN}/artifacts/expire/t2.bin" "$W/o" >/dev/null
psql_x "UPDATE artifacts SET deleted_at = NOW() - interval '2 days' WHERE id='${T2}';" || note "(no artifacts.deleted_at column on this image)"
c="$(gc_run "$W/gc")"
st="$(row_state "$T2")"; ob="$(obj_exists "$ROOT_GEN" "$K2")"
note "GC HTTP ${c}: row ${st}, object ${ob}"
[ "$st" = "gone" ] || fail_g "the expired trash row is ${st}, expected reclaimed"
[ "$ob" = "no" ] || fail_g "the expired trash object is still on disk"
finish_case "storage GC does not reclaim an expired trashed artifact"

# =============================================================================
# FIX #2072: restoring an OCI manifest is refused (409): its tags are not
# restored. Image A's manifest goes to the trash here.
# =============================================================================
begin_test "FIX #2072: restoring a trashed OCI manifest is 409 and leaves it trashed"
reset_case
c="$(curl -s -o /dev/null -w '%{http_code}' "${OCI_AUTH[@]}" -X DELETE "$BASE/v2/${R_OCI}/img-a/manifests/v1" || true)"
MA="$(psql_q "SELECT id FROM artifacts WHERE repository_id='${ID_OCI}' AND storage_key LIKE 'oci-manifests/%' AND path LIKE '%img-a%' ORDER BY created_at LIMIT 1;")"
note "manifest DELETE HTTP ${c}; manifest row ${MA:-none} $( [ -n "$MA" ] && row_state "$MA")"
[ -n "$MA" ] || { infra_fail "no artifacts row for image A's manifest"; end_suite; }
if [ "$(row_state "$MA")" = "trashed" ]; then
  c="$(http POST "/api/v1/admin/trash/${MA}/restore" "$W/rs")"
  note "restore: HTTP ${c} $(body "$W/rs"); row $(row_state "$MA")"
  [ "$c" = "409" ] || fail_g "restore of an OCI manifest was HTTP ${c}, expected 409"
  [ "$(row_state "$MA")" = "trashed" ] || fail_g "the refused restore changed the row ($(row_state "$MA"))"
else
  fail_g "the deleted manifest's row is $(row_state "$MA"), expected trashed"
fi
finish_case "#2072: OCI manifest restore not refused"

# =============================================================================
# FIX #3734: a max_age_days policy explicitly assigned to a Remote evicts the
# expired proxy-cache entries (catalogue row and objects), reports them under
# proxy_cache, and leaves young entries.
# =============================================================================
begin_test "FIX #3734: max_age_days assigned to a Remote evicts the expired proxy-cache entry (row and __content__), reports proxy_cache.entries_removed; the young entry stays"
reset_case
N_OLD="old-${SUF}.bin"; N_NEW="new-${SUF}.bin"
c1="$(remote_get "$R_RM" "$N_OLD" "$W/old.1")"; c2="$(remote_get "$R_RM" "$N_NEW" "$W/new.1")"
{ wait_cache_row "$R_RM" "$N_OLD" && wait_cache_row "$R_RM" "$N_NEW"; } || { infra_fail "Remote fetches (${c1}/${c2}) left no proxy_cache_artifacts rows"; end_suite; }
cache_age "$R_RM" "$N_OLD" 10 || { infra_fail "could not backdate cached_at"; end_suite; }
# Created disabled and marked as just run, then enabled: the 10 s scheduler
# tick must not run it before the manual run below.
mkpol "$(jq -nc --arg n "tb-evict-${SUF}" --arg r "$ID_RM" '{name:$n,repository_ids:[$r],policy_type:"max_age_days",config:{days:5},enabled:false}')"
if [ -z "$PID" ]; then
  fail_g "max_age_days assigned to a Remote was refused (HTTP ${PCODE}: $(body "$W/pol"))"
else
  psql_x "UPDATE lifecycle_policies SET last_run_at = NOW() WHERE id='${PID}';" || true
  http PATCH "/api/v1/admin/lifecycle/${PID}" "$W/pa" -H 'Content-Type: application/json' -d '{"enabled":true}' >/dev/null
  c="$(http POST "/api/v1/admin/lifecycle/${PID}/preview" "$W/pv")"
  pm="$(jqr '.proxy_cache.entries_matched' < "$W/pv")"
  c="$(http POST "/api/v1/admin/lifecycle/${PID}/execute" "$W/ex")"
  er="$(jqr '.proxy_cache.entries_removed' < "$W/ex")"; bf="$(jqr '.proxy_cache.bytes_freed' < "$W/ex")"
  note "preview proxy_cache.entries_matched=${pm}; execute HTTP ${c} proxy_cache=$(jq -c '.proxy_cache' < "$W/ex" 2>/dev/null || true)"
  note "old: rows $(cache_rows "$R_RM" "$N_OLD"), __content__ $(cache_content "$R_RM" "$N_OLD"); new: rows $(cache_rows "$R_RM" "$N_NEW"), __content__ $(cache_content "$R_RM" "$N_NEW")"
  [ "$pm" = "1" ] || fail_g "preview proxy_cache.entries_matched=${pm}, expected 1"
  [ "$c" = "200" ] && [ "$er" = "1" ] || fail_g "execute HTTP ${c} proxy_cache.entries_removed=${er}, expected 1"
  [ "${bf:-0}" -gt 0 ] 2>/dev/null || fail_g "proxy_cache.bytes_freed=${bf}, expected > 0"
  [ "$(cache_rows "$R_RM" "$N_OLD")" = "0" ] || fail_g "the expired entry's proxy_cache_artifacts row is still there"
  [ "$(cache_content "$R_RM" "$N_OLD")" = "no" ] || fail_g "the expired entry's __content__ is still on disk"
  [ "$(cache_rows "$R_RM" "$N_NEW")" = "1" ] && [ "$(cache_content "$R_RM" "$N_NEW")" = "yes" ] || fail_g "the young entry was evicted"
  before="$(mock_count "$N_OLD")"; c="$(remote_get "$R_RM" "$N_OLD" "$W/old.2")"; after="$(mock_count "$N_OLD")"
  note "re-fetch of the evicted entry: HTTP ${c}, upstream GETs ${before} -> ${after}"
  [ "$c" = "200" ] && [ "$(sha_of "$W/old.2")" = "$(sha_of "$W/old.1")" ] || fail_g "the evicted path no longer serves the upstream bytes (HTTP ${c})"
  [ "${after:-0}" -gt "${before:-0}" ] 2>/dev/null || fail_g "the re-fetch did not reach the upstream (evicted entry still served from cache)"
fi
finish_case "#3734: lifecycle does not evict a Remote's expired proxy-cache entry"

begin_test "FIX #3734: an applies_to_all policy skips Remote caches with proxy_cache.skipped_reason and evicts nothing"
reset_case
cache_age "$R_RM" "$N_NEW" 10 || true
mkpol "$(jq -nc --arg n "tb-glob-${SUF}" '{name:$n,applies_to_all:true,policy_type:"max_age_days",config:{days:5},enabled:false}')"
[ -n "$PID" ] || fail_g "applies_to_all policy create was HTTP ${PCODE}"
c="$(http POST "/api/v1/admin/lifecycle/${PID}/preview" "$W/pv")"
sr="$(jqr '.proxy_cache.skipped_reason // empty' < "$W/pv")"
note "preview HTTP ${c} proxy_cache=$(jq -c '.proxy_cache' < "$W/pv" 2>/dev/null || true); new entry rows $(cache_rows "$R_RM" "$N_NEW")"
[ "$c" = "200" ] || fail_g "preview was HTTP ${c}"
[ -n "$sr" ] || fail_g "no proxy_cache.skipped_reason for a global policy over a Remote"
[ "$(jqr '.proxy_cache.entries_matched' < "$W/pv")" = "0" ] || fail_g "proxy_cache.entries_matched is '$(jqr '.proxy_cache.entries_matched' < "$W/pv")', expected 0 (absent before 1.11.0)"
[ "$(cache_rows "$R_RM" "$N_NEW")" = "1" ] || fail_g "the cache entry is gone"
policy_cleanup
finish_case "#3734: a global policy is not kept out of Remote caches"

# =============================================================================
# FIX #4451 (1.11.2): a SCHEDULED run that only evicts proxy-cache entries is
# counted on ak_cleanup_items_removed_total{type="lifecycle"} and logged.
# Set up here; the lifecycle scheduler starts 60 to 90 s after boot and then
# ticks every LIFECYCLE_CHECK_INTERVAL_SECS (10 s), so the assertion runs
# after the blob-shield wait below.
# =============================================================================
N_S="sched-${SUF}.bin"
c="$(remote_get "$R_RS" "$N_S" "$W/s.1")"
wait_cache_row "$R_RS" "$N_S" || { infra_fail "Remote fetch (${c}) left no proxy_cache_artifacts row"; end_suite; }
cache_age "$R_RS" "$N_S" 10 || { infra_fail "could not backdate cached_at"; end_suite; }
M0="$(metric_lifecycle)"
LOG_SINCE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
mkpol "$(jq -nc --arg n "tb-sched-${SUF}" --arg r "$ID_RS" '{name:$n,repository_ids:[$r],policy_type:"max_age_days",config:{days:5}}')"
SCHED_PID="$PID"; SCHED_PCODE="$PCODE"; SCHED_BODY="$(body "$W/pol")"

# =============================================================================
# FIX #2906: BLOB_GC_MIN_AGE_SECS=60 lowers the unreferenced-blob shield, so a
# blob unreferenced this session is reclaimed a minute after its push. Image
# B's manifest and blob stay (no dangling reference).
# =============================================================================
begin_test "FIX #2906: with BLOB_GC_MIN_AGE_SECS=60 an unreferenced OCI blob is reclaimed about a minute after its push; the live image is untouched"
reset_case
# Image A's manifest is in the trash (the 409 case above). Its trash row is
# moved past the retention window so only the age shield decides.
psql_x "UPDATE artifacts SET deleted_at = NOW() - interval '2 days' WHERE id='${MA}';" || true
s0="$(oci_blob_status "$R_OCI" img-a "$B1")"
note "B1 before: HTTP ${s0}"
# OCI blob mark-and-sweep runs only on the scheduled GC tick (GC_SCHEDULE,
# every 10 s in this profile), never from the admin storage-gc endpoint, and
# the GC scheduler starts 120 to 150 s after boot. Wait until the first ticks
# past both the age floor and that startup delay have run.
STARTED="$(date -d "$(docker inspect -f '{{.State.StartedAt}}' "$BACKEND_CTR" 2>/dev/null)" +%s 2>/dev/null || date +%s)"
deadline=$(( STARTED + 180 )); [ "$deadline" -lt $(( B1_PUSHED_AT + BLOB_MIN_AGE + 40 )) ] && deadline=$(( B1_PUSHED_AT + BLOB_MIN_AGE + 40 ))
b1=""
while :; do
  b1="$(oci_blob_status "$R_OCI" img-a "$B1")"
  [ "$b1" = "404" ] && break
  [ "$(date +%s)" -ge "$deadline" ] && break
  sleep 3
done
SWEPT="$(docker logs --since 5m "$BACKEND_CTR" 2>&1 | grep -a -c 'Blob GC: swept' || true)"
note "B1 after the scheduled GC ticks: HTTP ${b1} (blob age $(( $(date +%s) - B1_PUSHED_AT ))s, backend up $(( $(date +%s) - STARTED ))s); 'Blob GC: swept' lines in the last 5 min: ${SWEPT}"
[ "$b1" = "404" ] || fail_g "unreferenced blob B1 still answers ${b1} $(( $(date +%s) - B1_PUSHED_AT ))s after its push (the 24 h default shield: 1.10.0 ignores BLOB_GC_MIN_AGE_SECS)"
mb="$(oci_manifest_status "$R_OCI" img-b v1)"; b2="$(oci_blob_status "$R_OCI" img-b "$B2")"
note "image B: manifest HTTP ${mb}, blob B2 HTTP ${b2}"
[ "$mb" = "200" ] && [ "$b2" = "200" ] || fail_g "GC broke the live image B (manifest ${mb}, blob ${b2})"
finish_case "#2906: BLOB_GC_MIN_AGE_SECS does not lower the blob age shield"

begin_test "FIX #4451: a scheduled cache-only lifecycle run increments ak_cleanup_items_removed_total{type=\"lifecycle\"} and logs the evictions"
reset_case
PID="$SCHED_PID"
[ -n "$PID" ] || fail_g "scheduled policy create was HTTP ${SCHED_PCODE}: ${SCHED_BODY}"
STARTED="$(date -d "$(docker inspect -f '{{.State.StartedAt}}' "$BACKEND_CTR" 2>/dev/null)" +%s 2>/dev/null || date +%s)"
deadline=$(( STARTED + 135 )); [ "$deadline" -lt $(( $(date +%s) + 30 )) ] && deadline=$(( $(date +%s) + 30 ))
ran=""
while :; do
  ran="$(psql_q "SELECT last_run_at IS NOT NULL FROM lifecycle_policies WHERE id='${PID}';")"
  [ "$ran" = "t" ] && break
  [ "$(date +%s)" -ge "$deadline" ] && break
  sleep 2
done
sleep 1
M1="$(metric_lifecycle)"
LOGL="$(docker logs --since "$LOG_SINCE" "$BACKEND_CTR" 2>&1 | grep -a 'Lifecycle cleanup: removed' | tail -1 || true)"
note "scheduler ran the policy: ${ran:-?} (backend up $(( $(date +%s) - STARTED ))s); last_run_items_removed $(psql_q "SELECT last_run_items_removed FROM lifecycle_policies WHERE id='${PID}';"); entry rows $(cache_rows "$R_RS" "$N_S")"
note "metric lifecycle ${M0} -> ${M1}; log: ${LOGL:-none}"
[ "$ran" = "t" ] || fail_g "the scheduler did not run the due policy by $(( deadline - STARTED ))s after boot"
[ "$(cache_rows "$R_RS" "$N_S")" = "0" ] || fail_g "the scheduled run did not evict the expired entry"
awk -v a="$M0" -v b="$M1" 'BEGIN{exit !(b - a >= 1)}' || fail_g "ak_cleanup_items_removed_total{type=\"lifecycle\"} did not grow (${M0} -> ${M1}); releases before 1.11.2 count only artifacts"
case "$LOGL" in *"1 proxy-cache entries"*) ;; *) fail_g "no scheduler summary line counting the proxy-cache eviction";; esac
policy_cleanup
finish_case "#4451: scheduled cache-only evictions are not counted"

end_suite
