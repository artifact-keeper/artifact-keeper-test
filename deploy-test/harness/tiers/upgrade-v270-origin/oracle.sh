#!/usr/bin/env bash
# =============================================================================
# tiers/upgrade-v270-origin/oracle.sh: what a 1.11.0+ candidate's data
# migrations and startup repairs make of rows written by 1.10.0
# (artifact-keeper#4153, #4465, #4228/#4271/#4270, #4483/#4545, #4557/#4152)
# =============================================================================
# Two-phase, driven by this oracle (the upgrade-v156/v158-origin pattern):
# run.sh health-gates an initial `up`; we tear that down (down -v), stand the
# same profile set up on the 1.10.0 ORIGIN image on a fresh volume, write the
# pre-upgrade state through the 1.10.0 API, then swap ONLY the backend to the
# candidate (--backend-image) on the same Postgres volume and assert.
#
# Pre-upgrade state written on 1.10.0:
#   * a migration job from the mock Artifactory imports `dtfcat-gen`
#     (upg/alpha.bin, upg/beta.txt) and `dtfcat-docker` (image dtfmig:1.0);
#     then a hand upload of alpha.bin's exact bytes and file name at another
#     path of the same repository (manual/alpha.bin);
#   * the migrated image's `oci_tags` row is removed, which is what an import
#     from before the OCI index (#2457) left: a manifest row nobody indexed;
#   * a Docker repository with image `tagonly:v1`, pushed by tag only and
#     deleted by digest (1.10.0 leaves the tag's artifacts row live, #4450);
#     a second image `kept:v1` that is not touched;
#   * repository tokens TA (on repo A) and TC (on repo C) and an unrestricted
#     user token TU, all `read:artifacts`; repo A is then deleted, so TA's
#     only pin row cascades away and 1.10.0 treats TA as unrestricted. TA is
#     never used before that delete (1.10.0 caches a token's validation for
#     300 s, which would mask the widening);
#   * an upload into a staging repository.
#
# Assertions after the swap (FIX = red on a 1.10.0 "candidate", which is the
# origin image re-created on its own volume):
#   FIX #4153  the migrated generic rows and the migrated manifest row carry
#              origin {kind: migration, upstream_url: http://mock-artifactory};
#              the same-bytes hand upload stays {kind: hosted}.
#   FIX #4465  `tagonly:v1` and its digest still answer 404 after the restart
#              and no oci_tags row came back.
#   CONTROL    the migrated, never-indexed `dtfmig:1.0` IS repaired by the
#              same startup reindex (pullable; proves the reindex ran and that
#              #4465 did not stop repairs of migrated images). Both images.
#   FIX #4271  TA is marked repository_restricted and is refused repo B
#              (404/403) where it read B on 1.10.0.
#   CONTROL    TC still reads repo C, TU still reads repo B. Both images.
#   FIX #4483  the Docker repository's storage_used_bytes and ledger equal
#              the blob bytes (1.10.0: blobs + manifest image size, >= 2x).
#   FIX #4557  the staging upload's origin is {kind: hosted, repository_key:
#              <staging repo>}, not virtual.
#   CONTROL    every seeded artifact still downloads byte-identical.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${DTF_DIR:?}"
: "${BACKEND_IMAGE:?candidate image (run.sh exports it from --backend-image)}"
: "${DTF_SLOT:?}"; : "${HTTP_PORT:?}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=/dev/null
source "$COMMON_SH"
# Pick up UPGRADE_OLD_IMAGE (single source of truth = the manifest).
# shellcheck source=/dev/null
source "${HERE}/manifest"
export RATE_LIMIT_ENABLED UPSTREAM_ALLOW_PRIVATE_IPS

CAND_IMAGE="$BACKEND_IMAGE"
OLD_IMAGE="${UPGRADE_OLD_IMAGE:?manifest must set UPGRADE_OLD_IMAGE}"
PROJECT="ak-dtf${DTF_SLOT}"
BACKEND_CTR="ak-dtf${DTF_SLOT}-backend"
MOCK="ak-dtf${DTF_SLOT}-mock-artifactory"
COMPOSE=(-f "${DTF_DIR}/compose.base.yml")
for p in $PROFILES; do COMPOSE+=(-f "${DTF_DIR}/profiles/${p}.yml"); done
ADMPASS="${ADMIN_PASS:-TestRunner!2026secure}"
MCT="application/vnd.docker.distribution.manifest.v2+json"
UPSTREAM="http://mock-artifactory"
read -r -a CURLF <<< "--path-as-is ${CURL_TIMEOUT}"

W="$(mktemp -d -t dtf-upg270-XXXXXX)"
add_exit_handler "rm -rf '${W}'"

compose() { docker compose -p "$PROJECT" "${COMPOSE[@]}" "$@"; }
psq() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]' || true; }
psq_raw() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null || true; }
blog() { docker logs "$BACKEND_CTR" 2>&1 | sed 's/\x1b\[[0-9;]*m//g'; }
sha_of() { sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }
size_of() { wc -c < "$1" 2>/dev/null | tr -d '[:space:]'; }
jqr() { jq -r "$1" 2>/dev/null || true; }
login() {
  curl -s "${CURLF[@]}" -X POST "$BASE_URL/api/v1/auth/login" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg u "$1" --arg p "$2" '{username:$u,password:$p}')" | jqr '.access_token // empty'
}
aj() { # METHOD PATH [BODY] (admin) -> body
  if [ -n "${3:-}" ]; then
    curl -s "${CURLF[@]}" -X "$1" "$BASE_URL$2" -H "Authorization: Bearer $TOK" \
      -H 'Content-Type: application/json' -d "$3" || true
  else
    curl -s "${CURLF[@]}" -X "$1" "$BASE_URL$2" -H "Authorization: Bearer $TOK" || true
  fi
}
code_as() { # BEARER METHOD PATH [OUTFILE] -> http code
  curl -s "${CURLF[@]}" -o "${4:-/dev/null}" -w '%{http_code}' -X "$2" "$BASE_URL$3" \
    -H "Authorization: Bearer $1" -H "Accept: ${MCT}" || echo 000
}
put_file() { # REPO PATH FILE -> http code (admin, generic upload)
  curl -s "${CURLF[@]}" -o /dev/null -w '%{http_code}' -X PUT -H "Authorization: Bearer $TOK" \
    -H 'Content-Type: application/octet-stream' --data-binary "@$3" \
    "$BASE_URL/api/v1/repositories/$1/artifacts/$2" || echo 000
}
mk_repo() { # KEY FORMAT TYPE -> the key on success
  aj POST /api/v1/repositories "$(jq -nc --arg k "$1" --arg f "$2" --arg t "$3" \
    '{key:$k,name:$k,format:$f,repo_type:$t,is_public:false}')" | jqr '.key // empty'
}
wait_health() { # <tries x 3 s>
  for _ in $(seq 1 "$1"); do
    [ "$(curl -s -o /dev/null -w '%{http_code}' "$BASE_URL/health" 2>/dev/null)" = "200" ] && return 0
    sleep 3
  done
  return 1
}
origin_of() { # REPO PATH -> origin jsonb as compact text ("" when absent)
  psq_raw "SELECT a.origin::text FROM artifacts a JOIN repositories r ON r.id = a.repository_id
    WHERE r.key='$1' AND a.path='$2' AND a.is_deleted=false;" | head -1
}
okind() { echo "$1" | jq -r '.kind // empty' 2>/dev/null; }
ourl() { echo "$1" | jq -r '.upstream_url // empty' 2>/dev/null; }
orepo() { echo "$1" | jq -r '.repository_key // empty' 2>/dev/null; }

# --- the /v2 push sequence, no docker daemon ---------------------------------
blob_up() { # REPO IMAGE FILE -> http code
  curl -s "${CURLF[@]}" -o /dev/null -w '%{http_code}' -X POST -H "Authorization: Bearer $TOK" \
    -H 'Content-Type: application/octet-stream' --data-binary "@$3" \
    "$BASE_URL/v2/$1/$2/blobs/uploads/?digest=sha256:$(sha_of "$3")" || echo 000
}
make_image() { # NAME LAYER_BYTES -> writes $W/NAME.{cfg,l1,manifest}, echoes blob bytes
  printf '{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]},"dtf":"%s-%s"}' \
    "$1" "${RUN_ID:-r}" > "$W/$1.cfg"
  head -c "$2" /dev/urandom > "$W/$1.l1"
  printf '{"schemaVersion":2,"mediaType":"%s","config":{"mediaType":"application/vnd.docker.container.image.v1+json","size":%s,"digest":"sha256:%s"},"layers":[{"mediaType":"application/vnd.docker.image.rootfs.diff.tar.gzip","size":%s,"digest":"sha256:%s"}]}' \
    "$MCT" "$(size_of "$W/$1.cfg")" "$(sha_of "$W/$1.cfg")" "$2" "$(sha_of "$W/$1.l1")" > "$W/$1.manifest"
  echo $(( $(size_of "$W/$1.cfg") + $2 ))
}
push_image() { # REPO IMAGE TAG NAME -> "" on success, else a diagnostic
  local out="" c
  for f in "$W/$4.cfg" "$W/$4.l1"; do
    c="$(blob_up "$1" "$2" "$f")"; [ "$c" = "201" ] || out="${out} blob $(basename "$f")=${c}"
  done
  c="$(curl -s "${CURLF[@]}" -o /dev/null -w '%{http_code}' -X PUT -H "Authorization: Bearer $TOK" \
    -H "Content-Type: ${MCT}" --data-binary "@$W/$4.manifest" "$BASE_URL/v2/$1/$2/manifests/$3" || echo 000)"
  [ "$c" = "201" ] || out="${out} manifest=${c}"
  echo "$out"
}

phase1_abort() { # MESSAGE [DETAIL]
  infra_fail "PHASE 1 (origin ${OLD_IMAGE}): $1" "${2:-}"
  end_suite; exit 1
}

echo "############ UPGRADE-V270-ORIGIN tier (slot ${DTF_SLOT})"
echo "   origin image (1.10.0)        : ${OLD_IMAGE}"
echo "   candidate image (upgrade to) : ${CAND_IMAGE}"

begin_suite "upgrade-v270-origin"

# =============================================================================
# PHASE 1: the origin image on a fresh volume, pre-upgrade state via its API
# =============================================================================
echo "== PHASE 1: stand up ${OLD_IMAGE} and write the pre-upgrade state =="
compose down -v >/dev/null 2>&1
BACKEND_IMAGE="$OLD_IMAGE" compose up -d --wait >/dev/null 2>&1 || true
begin_test "PHASE1: origin ${OLD_IMAGE} healthy, ledger is 1.10.0's (max 221, no artifacts.origin)"
G_MAX="$(psq "SELECT max(version) FROM _sqlx_migrations;")"
G_ORIGIN="$(psq "SELECT count(*) FROM information_schema.columns WHERE table_name='artifacts' AND column_name='origin';")"
if ! wait_health 40; then
  phase1_abort "origin image did not become healthy" "$(docker logs "$BACKEND_CTR" 2>&1 | tail -20)"
elif [ "$G_MAX" != "221" ] || [ "$G_ORIGIN" != "0" ]; then
  phase1_abort "origin ledger is not 1.10.0's (max=${G_MAX}, artifacts.origin columns=${G_ORIGIN}); wrong UPGRADE_OLD_IMAGE?"
else
  pass
fi

TOK="$(login admin "$ADMPASS")"
[ -n "$TOK" ] || phase1_abort "admin login failed on the origin"
SUF="${RUN_ID##*-}$$"

# --- #4153 / #4465 control: a migration from the mock Artifactory ------------
SRC="${W}/source"
python3 -I "${HERE}/fixtures/build_source.py" "$SRC" 2>"${W}/build.err" \
  || phase1_abort "fixtures/build_source.py failed" "$(cat "${W}/build.err")"
docker cp "${SRC}/." "${MOCK}:/srv/catalog/" >"${W}/cp.err" 2>&1 \
  || phase1_abort "docker cp into ${MOCK} failed" "$(cat "${W}/cp.err")"
CONN_ID="$(aj POST /api/v1/migrations/connections "$(jq -nc --arg n "upg270-${SUF}" --arg u "$UPSTREAM" '{
  name: $n, url: $u, auth_type: "basic_auth", source_type: "artifactory",
  credentials: {username: "dtf", password: "dtf"}}')" | jqr '.id // empty')"
[ -n "$CONN_ID" ] || phase1_abort "could not create the migration source connection"
JOB="$(aj POST /api/v1/migrations "$(jq -nc --arg cid "$CONN_ID" '{
  source_connection_id: $cid, job_type: "full",
  config: { include_repos: ["dtfcat-gen", "dtfcat-docker"], dry_run: false,
            conflict_resolution: "overwrite", verify_checksums: true,
            include_users: false, include_groups: false, include_permissions: false,
            concurrent_transfers: 1, throttle_delay_ms: 0 }}')" | jqr '.id // empty')"
[ -n "$JOB" ] || phase1_abort "could not create the migration job"
aj POST "/api/v1/migrations/${JOB}/start" >/dev/null
J_ST=""
for _ in $(seq 1 90); do
  J_ST="$(aj GET "/api/v1/migrations/${JOB}" | jqr '.status // empty')"
  case "$J_ST" in completed|completed_with_errors|failed|cancelled) break ;; esac
  sleep 1
done
J_ROW="$(aj GET "/api/v1/migrations/${JOB}")"
MIG_ALPHA="upg/alpha.bin"; MIG_BETA="upg/beta.txt"; MIG_MANIFEST="v2/dtfmig/manifests/1.0"
HAND_ALPHA="manual/alpha.bin"
begin_test "PHASE1: the 1.10.0 migration imports dtfcat-gen (2 files) and the dtfcat-docker image dtfmig:1.0"
P_ROWS="$(psq "SELECT count(*) FROM artifacts a JOIN repositories r ON r.id = a.repository_id
  WHERE a.is_deleted=false AND ((r.key='dtfcat-gen' AND a.path IN ('${MIG_ALPHA}','${MIG_BETA}'))
  OR (r.key='dtfcat-docker' AND a.path='${MIG_MANIFEST}'));")"
if [ "$J_ST" = "completed" ] && [ "$P_ROWS" = "3" ] \
   && [ "$(code_as "$TOK" GET /v2/dtfcat-docker/dtfmig/manifests/1.0)" = "200" ]; then
  pass
else
  phase1_abort "migration status=${J_ST}, imported rows=${P_ROWS} (want completed, 3)" \
    "$(echo "$J_ROW" | jq -c '{status,total_items,completed_items,failed_items}' 2>/dev/null)
$(aj GET "/api/v1/migrations/${JOB}/items" | jq -c '.items[]? | {source_path,status,error_message}' 2>/dev/null)"
fi
# A hand upload of alpha.bin's exact bytes and file name, after the import.
H_CODE="$(put_file dtfcat-gen "$HAND_ALPHA" "${SRC}/dtfcat-gen/upg/alpha.bin")"
# Strip the migrated image's index rows: a manifest nobody indexed.
psq "DELETE FROM oci_tags WHERE name='dtfmig';" >/dev/null
MIG_UNINDEXED="$(code_as "$TOK" GET /v2/dtfcat-docker/dtfmig/manifests/1.0)"

# --- #4465 / #4483: a hosted Docker repository --------------------------------
D="upg270-docker-${SUF}"
[ "$(mk_repo "$D" docker local)" = "$D" ] || phase1_abort "could not create Docker repo ${D}"
BYTES_TAGONLY="$(make_image tagonly 30000)"
BYTES_KEPT="$(make_image kept 20000)"
E1="$(push_image "$D" tagonly v1 tagonly)"
E2="$(push_image "$D" kept v1 kept)"
DG_TAGONLY="sha256:$(sha_of "$W/tagonly.manifest")"
DEL_CODE="$(code_as "$TOK" DELETE "/v2/${D}/tagonly/manifests/${DG_TAGONLY}")"
TAG_AFTER_DEL="$(code_as "$TOK" GET "/v2/${D}/tagonly/manifests/v1")"
TAG_ROW_LIVE="$(psq "SELECT count(*) FROM artifacts a JOIN repositories r ON r.id = a.repository_id
  WHERE r.key='${D}' AND a.path='v2/tagonly/manifests/v1' AND a.is_deleted=false;")"
USED_ORIGIN="$(aj GET "/api/v1/repositories/${D}" | jqr '.storage_used_bytes // empty')"

# --- #4271: repository tokens --------------------------------------------------
RA="upg270-a-${SUF}"; RB="upg270-b-${SUF}"; RC="upg270-c-${SUF}"
for r in "$RA" "$RB" "$RC"; do [ "$(mk_repo "$r" generic local)" = "$r" ] || phase1_abort "could not create repo ${r}"; done
printf 'repo B private payload %s\n' "$SUF" > "$W/b.txt"
printf 'repo C payload %s\n' "$SUF" > "$W/c.txt"
PB="$(put_file "$RB" b/b.txt "$W/b.txt")"; PC="$(put_file "$RC" c/c.txt "$W/c.txt")"
TA="$(aj POST "/api/v1/repositories/${RA}/tokens" '{"name":"upg270-ta","scopes":["read:artifacts"]}' | jqr '.token // empty')"
TC="$(aj POST "/api/v1/repositories/${RC}/tokens" '{"name":"upg270-tc","scopes":["read:artifacts"]}' | jqr '.token // empty')"
ADMIN_ID="$(psq "SELECT id FROM users WHERE username='admin';")"
TU="$(aj POST "/api/v1/users/${ADMIN_ID}/tokens" '{"name":"upg270-tu","scopes":["read:artifacts"]}' | jqr '.token // empty')"
DEL_A="$(aj DELETE "/api/v1/repositories/${RA}" >/dev/null; psq "SELECT count(*) FROM repositories WHERE key='${RA}';")"
# First use of TA, after its repository is gone: 1.10.0 lets it read B.
TA_B_ORIGIN="$(code_as "$TA" GET "/api/v1/repositories/${RB}/download/b/b.txt")"

# --- #4557: a staging upload ---------------------------------------------------
RS="upg270-stage-${SUF}"
[ "$(mk_repo "$RS" generic staging)" = "$RS" ] || phase1_abort "could not create staging repo ${RS}"
printf 'staged payload %s\n' "$SUF" > "$W/s.txt"
PS="$(put_file "$RS" st/s.txt "$W/s.txt")"

begin_test "PHASE1: pre-upgrade state written (hand upload, un-indexed migrated image, tag-only push deleted by digest, widened token, staging upload)"
P1_ERR=""
[ "$H_CODE" = "201" ] || [ "$H_CODE" = "200" ] || P1_ERR="${P1_ERR} hand-upload=${H_CODE}"
[ "$MIG_UNINDEXED" = "404" ] || P1_ERR="${P1_ERR} un-indexed-migrated-image-GET=${MIG_UNINDEXED}(want 404)"
[ -z "$E1$E2" ] || P1_ERR="${P1_ERR} push:${E1}${E2}"
[ "$DEL_CODE" = "202" ] || P1_ERR="${P1_ERR} delete-by-digest=${DEL_CODE}"
[ "$TAG_AFTER_DEL" = "404" ] || P1_ERR="${P1_ERR} tag-after-delete=${TAG_AFTER_DEL}"
[ "$TAG_ROW_LIVE" = "1" ] || P1_ERR="${P1_ERR} tag-row-live=${TAG_ROW_LIVE}(the 1.10.0 #4450 state)"
[ -n "$TA" ] && [ -n "$TC" ] && [ -n "$TU" ] || P1_ERR="${P1_ERR} token-mint"
[ "$DEL_A" = "0" ] || P1_ERR="${P1_ERR} delete-repo-A"
[ "$TA_B_ORIGIN" = "200" ] || P1_ERR="${P1_ERR} TA-reads-B-on-origin=${TA_B_ORIGIN}(want 200: the #4228 widening)"
case "$PB$PC$PS" in 201201201) ;; *) P1_ERR="${P1_ERR} uploads=${PB}/${PC}/${PS}" ;; esac
if [ -z "$P1_ERR" ]; then
  pass
  echo "   [observe] origin: ${D} storage_used_bytes=${USED_ORIGIN} for $((BYTES_TAGONLY + BYTES_KEPT)) blob bytes (tagonly deleted, kept live)"
else
  phase1_abort "pre-upgrade state incomplete:${P1_ERR}"
fi

# =============================================================================
# PHASE 2: swap the backend to the candidate on the same volume
# =============================================================================
echo "== PHASE 2: swap backend -> ${CAND_IMAGE} (same volume) =="
BACKEND_IMAGE="$CAND_IMAGE" compose up -d --no-deps --force-recreate backend >/dev/null 2>&1
begin_test "POST-UPGRADE: candidate healthy on the 1.10.0 volume"
if wait_health 80; then
  pass
else
  fail "candidate did not become healthy on the upgraded volume" "$(docker logs "$BACKEND_CTR" 2>&1 | tail -15)"
  end_suite; exit 1
fi
# The OCI reindex is spawned in the background after startup. Its log line is
# not a reliable signal (the container log is size-capped and rotates under a
# migration's output), so wait for its visible effect instead: the migrated
# image whose index rows were stripped becomes pullable once the pass has run
# (on every image; that is the repair CONTROL below). Then a short settle for
# the rest of the same pass.
TOK="$(login admin "$ADMPASS")"
REINDEX_SECS=""
for s in $(seq 1 60); do
  if [ "$(code_as "$TOK" GET /v2/dtfcat-docker/dtfmig/manifests/1.0)" = "200" ]; then REINDEX_SECS="$s"; break; fi
  sleep 1
done
sleep 3
REINDEX_LINE="$(blog | grep "OCI migration reindex complete" | tail -1 | cut -c1-300 || true)"
echo "   [observe] migrated image repaired after ${REINDEX_SECS:-more than 60} s; ${REINDEX_LINE:-reindex log line not in the (rotated) log}"
TOK="$(login admin "$ADMPASS")"

# --- #4153 ---------------------------------------------------------------------
O_ALPHA="$(origin_of dtfcat-gen "$MIG_ALPHA")"
O_BETA="$(origin_of dtfcat-gen "$MIG_BETA")"
O_MAN="$(origin_of dtfcat-docker "$MIG_MANIFEST")"
O_HAND="$(origin_of dtfcat-gen "$HAND_ALPHA")"
begin_test "FIX #4153: artifacts a 1.10.0 migration imported are re-stamped origin kind=migration with the source URL"
if [ "$(okind "$O_ALPHA")" = "migration" ] && [ "$(ourl "$O_ALPHA")" = "$UPSTREAM" ] \
   && [ "$(okind "$O_BETA")" = "migration" ] && [ "$(ourl "$O_BETA")" = "$UPSTREAM" ] \
   && [ "$(orepo "$O_ALPHA")" = "dtfcat-gen" ] \
   && [ "$(okind "$O_MAN")" = "migration" ] && [ "$(ourl "$O_MAN")" = "$UPSTREAM" ]; then
  pass
else
  fail "migrated rows' origin after the upgrade: ${MIG_ALPHA}=${O_ALPHA:-<none>}, ${MIG_BETA}=${O_BETA:-<none>}, \
dtfcat-docker ${MIG_MANIFEST}=${O_MAN:-<none>}; want kind=migration, upstream_url=${UPSTREAM}. Migration 228 \
backfilled pre-origin rows as hosted; migration 270 must re-stamp the ones its completed migration items match (#4153)."
fi
begin_test "FIX #4153 (boundary): a later hand upload of the same bytes and file name stays origin kind=hosted"
if [ "$(okind "$O_HAND")" = "hosted" ] && [ -z "$(ourl "$O_HAND")" ] && [ "$(orepo "$O_HAND")" = "dtfcat-gen" ]; then
  pass
else
  fail "dtfcat-gen ${HAND_ALPHA} (uploaded by hand after the import, same sha256 and file name as ${MIG_ALPHA}): \
origin=${O_HAND:-<none>}, want {kind: hosted, repository_key: dtfcat-gen} with no upstream_url"
fi

# --- #4465 ---------------------------------------------------------------------
TAG_GET="$(code_as "$TOK" GET "/v2/${D}/tagonly/manifests/v1")"
DIG_GET="$(code_as "$TOK" GET "/v2/${D}/tagonly/manifests/${DG_TAGONLY}")"
TAG_IDX="$(psq "SELECT count(*) FROM oci_tags t JOIN repositories r ON r.id = t.repository_id
  WHERE r.key='${D}' AND t.name='tagonly';")"
begin_test "FIX #4465: an image pushed by tag and deleted by digest on 1.10.0 stays deleted after the upgrade restart"
if [ -z "$REINDEX_SECS" ]; then
  fail "the startup reindex did not repair the migrated image within 60 s, so its pass cannot be judged (see the CONTROL below)"
elif [ "$TAG_GET" = "404" ] && [ "$DIG_GET" = "404" ] && [ "$TAG_IDX" = "0" ]; then
  pass
else
  fail "after the upgrade restart: GET /v2/${D}/tagonly/manifests/v1 -> ${TAG_GET}, by digest -> ${DIG_GET}, \
oci_tags rows=${TAG_IDX} (want 404, 404, 0). The startup reindex took the live tag row 1.10.0 left behind for a \
never-indexed migrated manifest and re-registered a deleted image; it must repair only rows whose origin is a \
migration import (#4465)."
fi
MIG_REPAIRED="$(code_as "$TOK" GET /v2/dtfcat-docker/dtfmig/manifests/1.0 "$W/dtfmig.manifest")"
begin_test "CONTROL: the migrated image whose index rows were missing is repaired by the same reindex"
if [ "$MIG_REPAIRED" = "200" ] && [ "$(sha_of "$W/dtfmig.manifest")" = "$(sha_of "${SRC}/dtfcat-docker/dtfmig/1.0/manifest.json")" ]; then
  pass
else
  fail "GET /v2/dtfcat-docker/dtfmig/manifests/1.0 -> ${MIG_REPAIRED} (want 200 with the source manifest bytes). \
The reindex must still repair migrated, never-indexed manifests."
fi

# --- #4271 ---------------------------------------------------------------------
TA_B="$(code_as "$TA" GET "/api/v1/repositories/${RB}/download/b/b.txt")"
TA_RESTRICTED="$(psq "SELECT repository_restricted FROM api_tokens WHERE name='upg270-ta';")"
begin_test "FIX #4271: a repository token emptied by a 1.10.0 repository delete is recovered as restricted and refused repo B"
if { [ "$TA_B" = "404" ] || [ "$TA_B" = "403" ]; } && [ "$TA_RESTRICTED" = "t" ]; then
  pass
else
  fail "TA (minted on ${RA}, which was deleted on 1.10.0): GET ${RB}/download -> ${TA_B} (want 404/403; it was \
${TA_B_ORIGIN} on the origin), repository_restricted=${TA_RESTRICTED:-<no column>} (want t). Migration 237 must \
recover it from its API_TOKEN_CREATED surface=repo audit row (#4271, #4270)."
fi
TC_C="$(code_as "$TC" GET "/api/v1/repositories/${RC}/download/c/c.txt" "$W/c.out")"
TU_B="$(code_as "$TU" GET "/api/v1/repositories/${RB}/download/b/b.txt" "$W/b.out")"
TC_RESTRICTED="$(psq "SELECT repository_restricted FROM api_tokens WHERE name='upg270-tc';")"
begin_test "CONTROL: a repository token whose repository survives still reads it, and an unrestricted token still reads B"
if [ "$TC_C" = "200" ] && cmp -s "$W/c.out" "$W/c.txt" && [ "$TU_B" = "200" ] && cmp -s "$W/b.out" "$W/b.txt"; then
  pass
else
  fail "TC -> ${RC}: ${TC_C} (want 200), TU (unrestricted) -> ${RB}: ${TU_B} (want 200); TC restricted=${TC_RESTRICTED}"
fi

# --- #4483 ---------------------------------------------------------------------
USED_AFTER="$(aj GET "/api/v1/repositories/${D}" | jqr '.storage_used_bytes // empty')"
LEDGER="$(psq "SELECT l.hosted_bytes || '|' || l.oci_bytes FROM repository_usage_ledger l
  JOIN repositories r ON r.id = l.repository_id WHERE r.key='${D}';")"
LIVE_BLOBS="$(psq "SELECT COALESCE(SUM(b.size_bytes),0) FROM oci_blobs b JOIN repositories r ON r.id = b.repository_id
  WHERE r.key='${D}';")"
begin_test "FIX #4483: the Docker repository's usage counts its blobs once (no manifest rows on top)"
if [ -n "$USED_AFTER" ] && [ "$USED_AFTER" = "$LIVE_BLOBS" ] && [ "${LEDGER%%|*}" = "0" ] \
   && [ "${LIVE_BLOBS:-0}" -ge "$((BYTES_TAGONLY + BYTES_KEPT))" ]; then
  pass
else
  fail "${D}: storage_used_bytes=${USED_AFTER:-?} (1.10.0 reported ${USED_ORIGIN}), oci_blobs bytes=${LIVE_BLOBS}, \
ledger hosted|oci=${LEDGER}. Want storage_used_bytes == the blob bytes and hosted_bytes 0: each manifest row records \
the image size, whose bytes oci_blobs already counts; migration 288 recomputes the ledger (#4483, #4545)."
fi

# --- #4557 ---------------------------------------------------------------------
O_STAGE="$(origin_of "$RS" st/s.txt)"
begin_test "FIX #4557: an upload into a staging repository made on 1.10.0 has origin kind=hosted after the upgrade"
if [ "$(okind "$O_STAGE")" = "hosted" ] && [ "$(orepo "$O_STAGE")" = "$RS" ]; then
  pass
else
  fail "${RS} st/s.txt origin=${O_STAGE:-<none>}; want {kind: hosted, repository_key: ${RS}}. The origin backfill \
mapped every non-local, non-remote repository to virtual; migration 284 re-stamps staging rows as hosted (#4557, #4152)."
fi

# --- data survival -------------------------------------------------------------
S_ERR=""
for spec in "dtfcat-gen|${MIG_ALPHA}|${SRC}/dtfcat-gen/upg/alpha.bin" \
            "dtfcat-gen|${HAND_ALPHA}|${SRC}/dtfcat-gen/upg/alpha.bin" \
            "${RS}|st/s.txt|${W}/s.txt"; do
  IFS='|' read -r r p f <<< "$spec"
  c="$(code_as "$TOK" GET "/api/v1/repositories/${r}/download/${p}" "$W/dl.out")"
  { [ "$c" = "200" ] && cmp -s "$W/dl.out" "$f"; } || S_ERR="${S_ERR} ${r}/${p}=${c}"
done
KEPT_GET="$(code_as "$TOK" GET "/v2/${D}/kept/manifests/v1" "$W/kept.out")"
{ [ "$KEPT_GET" = "200" ] && cmp -s "$W/kept.out" "$W/kept.manifest"; } || S_ERR="${S_ERR} kept:v1=${KEPT_GET}"
begin_test "CONTROL: every artifact written on 1.10.0 still downloads byte-identical"
if [ -z "$S_ERR" ]; then pass; else fail "after the upgrade:${S_ERR}"; fi

end_suite
# Teardown is left to run.sh (dtf_down / --keep).
