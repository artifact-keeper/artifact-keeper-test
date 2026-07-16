#!/usr/bin/env bash
# =============================================================================
# tiers/migration/assert.sh — the #2457 ORACLE (migration source -> native pull)
# =============================================================================
# VENDORED + adapted from rig/harness/nexus_migrate_assert.sh. Deviations
# (flagged):
#   * No pool-slot claim/deploy and no `docker network connect`: under the DTF
#     contract run.sh already stood the backend up on this slot and the
#     upstreams.nexus profile put Nexus on the SAME slot network, so the backend
#     reaches the source at http://nexus:8081 natively.
#   * No TEARDOWN block: run.sh owns teardown (`down -v`). We only clean the
#     host docker-login credentials we created.
#   * Finding 3 is STRENGTHENED: the rig oracle counted a finding only when
#     BOTH docker pulls fail; here each image is asserted individually, so a
#     single-arch-only fix still fails the tier on the multi-arch leg (the leg
#     #2457/v1.5.5 missed).
# Assertion logic, diagnostics, and the real orphan/fidelity invariants are
# otherwise verbatim. NON-ZERO-WHILE-BUG: exit = number of findings; a correct
# image exits 0.
#
#   Finding 1  single-arch config blob unresolvable after migration
#              GET /v2/<repo>/single-arch/blobs/<config-digest>  == 404
#   Finding 2  multi-arch child manifest unresolvable (no index recursion)
#              GET /v2/<repo>/multi-arch/manifests/<child-digest> == 404
#   Finding 3  real `docker pull` fails (asserted PER image: single AND multi)
#   DB         oci_blobs count for the migrated repo == 0 (hollow state)
#   Orphan     delete-tag + re-migrate leaves a tag resolving to nothing
#   Invariants hollow images / unresolved index children must be 0
#
# Requires (exported by run.sh + nexus_lib.sh): BASE_URL, DB_CONTAINER,
# BACKEND_IMAGE, DTF_SLOT, ADMIN_USER/ADMIN_PASS; fixtures seeded.
# =============================================================================
set -uo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/nexus_lib.sh"

: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${BACKEND_IMAGE:?}"
AK_ADMIN_USER="${ADMIN_USER:-admin}"
AK_ADMIN_PASS="${ADMIN_PASS:-TestRunner!2026secure}"
AK_BASE="${BASE_URL}"
AK_REGISTRY="${AK_BASE#http://}"          # host:port for docker login/pull
BE_CTR="ak-dtf${DTF_SLOT}-backend"
DB_CTR="${DB_CONTAINER}"

[ -f "${NEXUS_FIXTURES_FILE}" ] || die "no fixtures at ${NEXUS_FIXTURES_FILE} — run nexus_seed.sh first"
nexus_is_up || die "Nexus not up — profile/run.sh problem"

# --- fixture digests ----------------------------------------------------------
FX="${NEXUS_FIXTURES_FILE}"
SA_CONFIG=$(jq -r '.single_arch.config_digest' "$FX")
MA_CHILD0=$(jq -r '.multi_arch.child0' "$FX")
MA_CHILD0_CFG=$(jq -r '.multi_arch.child0_config' "$FX")
REPO="${NEXUS_DOCKER_REPO}"
log "Fixtures: single-arch config=${SA_CONFIG}  multi-arch child0=${MA_CHILD0}"
log "Slot ${DTF_SLOT}: AK=${AK_BASE}  DB=${DB_CTR}  image=${BACKEND_IMAGE}"

# --- image-fidelity guard: deployed sha must equal the requested image --------
want=$(docker inspect "${BACKEND_IMAGE}" --format '{{.Id}}' 2>/dev/null || true)
got=$(docker inspect "${BE_CTR}" --format '{{.Image}}' 2>/dev/null || true)
log "image check: requested=${want} deployed=${got}"
[ -n "$want" ] && [ "$want" = "$got" ] || warn "deployed image sha != requested — requested=${want} got=${got}"

# --- AK REST helpers -----------------------------------------------------------
ak_login() {
  curl -s -X POST "${AK_BASE}/api/v1/auth/login" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg u "$AK_ADMIN_USER" --arg p "$AK_ADMIN_PASS" '{username:$u,password:$p}')" \
    | jq -r '.access_token // empty'
}
TOK="$(ak_login)"; [ -n "$TOK" ] || die "AK admin login failed on ${AK_BASE}"
akj() { local m="$1" p="$2" b="${3:-}"; if [ -n "$b" ]; then
    curl -s -X "$m" "${AK_BASE}$p" -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' -d "$b";
  else curl -s -X "$m" "${AK_BASE}$p" -H "Authorization: Bearer $TOK"; fi; }

psql_ak() { docker exec "${DB_CTR}" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]'; }

# --- 1. create + test + enumerate the Nexus source connection ------------------
log "Creating Nexus source connection (${NEXUS_API_INTERNAL}) ..."
conn_body=$(jq -nc --arg url "${NEXUS_API_INTERNAL}" --arg u "${NEXUS_ADMIN_USER}" --arg p "$(nx_pass)" '{
  name:"dtf-migration-nexus-source", url:$url, auth_type:"basic_auth", source_type:"nexus",
  credentials:{username:$u, password:$p}
}')
conn=$(akj POST /api/v1/migrations/connections "$conn_body")
CONN_ID=$(echo "$conn" | jq -r '.id // empty')
[ -n "$CONN_ID" ] || die "connection create failed: $conn"
log "connection id=${CONN_ID}"

test_res=$(akj POST "/api/v1/migrations/connections/${CONN_ID}/test")
log "connection test: $(echo "$test_res" | jq -c '{success,message,artifactory_version}')"

repos=$(akj GET "/api/v1/migrations/connections/${CONN_ID}/repositories")
log "source repositories: $(echo "$repos" | jq -c '[.items[]?|{key,package_type}]' 2>/dev/null || echo "$repos")"

# --- 2. create + assess + start the migration job ------------------------------
log "Creating migration job (full, overwrite, verify_checksums=true) ..."
job_body=$(jq -nc --arg cid "${CONN_ID}" --arg repo "${REPO}" '{
  source_connection_id:$cid, job_type:"full",
  config:{ include_repos:[$repo], conflict_resolution:"overwrite", verify_checksums:true,
           include_users:false, include_groups:false, include_permissions:false }
}')
job=$(akj POST /api/v1/migrations "$job_body")
JOB_ID=$(echo "$job" | jq -r '.id // empty')
[ -n "$JOB_ID" ] || die "job create failed: $job"
log "job id=${JOB_ID}"

# assess is async (status->assessing); wait for it to settle before /start,
# otherwise /start races the assessment and 409s (job stuck).
akj POST "/api/v1/migrations/${JOB_ID}/assess" >/dev/null 2>&1 || true
adl=$(( $(date +%s) + 60 ))
while [ "$(date +%s)" -lt "$adl" ]; do
  st=$(akj GET "/api/v1/migrations/${JOB_ID}" | jq -r '.status')
  [ "$st" = "assessing" ] || break
  sleep 3
done
assess=$(akj GET "/api/v1/migrations/${JOB_ID}/assessment")
log "assessment (preview): $(echo "$assess" | jq -c '{total_repositories,total_artifacts,total_size_bytes}' 2>/dev/null || echo "$assess" | head -c 300)"
PREVIEW_ARTIFACTS=$(echo "$assess" | jq -r '.total_artifacts // 0' 2>/dev/null || echo 0)

log "Starting migration ..."
akj POST "/api/v1/migrations/${JOB_ID}/start" >/dev/null 2>&1 || true

# --- poll to a TERMINAL state (completed|failed|cancelled) ----------------------
status=""; deadline=$(( $(date +%s) + 240 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  jr=$(akj GET "/api/v1/migrations/${JOB_ID}")
  status=$(echo "$jr" | jq -r '.status')
  case "$status" in
    completed|completed_with_errors|failed|cancelled) break;;
  esac
  sleep 4
done
jr=$(akj GET "/api/v1/migrations/${JOB_ID}")
ESUMMARY=$(echo "$jr" | jq -r '.error_summary // ""')
log "final job status=${status}  counters=$(echo "$jr" | jq -c '{total_items,completed_items,failed_items,skipped_items,transferred_bytes}')  error_summary=${ESUMMARY}"

# --- diagnostics: worker log + OCI registration counts --------------------------
ROOT=$(docker logs "${BE_CTR}" 2>&1 | grep -iE "Unknown repository type|prepare repository migration|Migration worker failed" | tail -3)
[ -n "$ROOT" ] && echo "[ROOT] worker log: $(echo "$ROOT" | sed 's/\x1b\[[0-9;]*m//g' | tail -1 | tr -s ' ')" >&2
echo "[PREVIEW] assessment total_artifacts=${PREVIEW_ARTIFACTS}" >&2

MA_INDEX=$(jq -r '.multi_arch.index_digest' "$FX")
c_oci_tags=$(psql_ak "SELECT count(*) FROM oci_tags ot JOIN repositories r ON r.id=ot.repository_id WHERE r.name='${REPO}';")
c_oci_blobs=$(psql_ak "SELECT count(*) FROM oci_blobs ob JOIN repositories r ON r.id=ob.repository_id WHERE r.name='${REPO}';")
c_mrefs=$(psql_ak "SELECT count(*) FROM oci_manifest_refs mr JOIN repositories r ON r.id=mr.repository_id WHERE r.name='${REPO}';")
c_brefs=$(psql_ak "SELECT count(*) FROM manifest_blob_refs br JOIN repositories r ON r.id=br.repository_id WHERE r.name='${REPO}';")
c_art=$(psql_ak "SELECT count(*) FROM artifacts a JOIN repositories r ON r.id=a.repository_id WHERE r.name='${REPO}';")
echo "[DIAG] oci_tags=${c_oci_tags:-0}  oci_blobs=${c_oci_blobs:-0}  oci_manifest_refs=${c_mrefs:-0}  manifest_blob_refs=${c_brefs:-0}  artifacts=${c_art:-0}" >&2
child_in_refs=$(psql_ak "SELECT count(*) FROM oci_manifest_refs mr JOIN repositories r ON r.id=mr.repository_id WHERE r.name='${REPO}' AND mr.parent_digest='${MA_INDEX}';")
echo "[DIAG] multi-arch index=${MA_INDEX}: children_in_oci_manifest_refs=${child_in_refs:-0}" >&2

# --- OCI docker-token helper (replicates docker's bearer flow) -------------------
oci_token() {  # $1 = scope
  local scope="$1" chal realm service
  chal=$(curl -s -o /dev/null -D - "${AK_BASE}/v2/" | tr -d '\r' | grep -i '^WWW-Authenticate:' || true)
  realm=$(echo "$chal" | sed -n 's/.*realm="\([^"]*\)".*/\1/p')
  service=$(echo "$chal" | sed -n 's/.*service="\([^"]*\)".*/\1/p')
  [ -n "$realm" ] || realm="${AK_BASE}/v2/token"
  curl -s -u "${AK_ADMIN_USER}:${AK_ADMIN_PASS}" \
    --data-urlencode "service=${service}" --data-urlencode "scope=${scope}" \
    -G "${realm}" | jq -r '.token // .access_token // empty'
}
# oci_get <name> <kind:blobs|manifests> <ref>  -> prints HTTP status
oci_get() {
  local name="$1" kind="$2" ref="$3"
  local tok; tok=$(oci_token "repository:${name}:pull")
  curl -s -o /dev/null -w '%{http_code}' \
    -H "Authorization: Bearer ${tok}" \
    -H 'Accept: application/vnd.oci.image.manifest.v1+json' \
    -H 'Accept: application/vnd.docker.distribution.manifest.v2+json' \
    -H 'Accept: application/vnd.oci.image.index.v1+json' \
    "${AK_BASE}/v2/${name}/${kind}/${ref}"
}

echo "================ #2457 ASSERTIONS (slot ${DTF_SLOT}, image ${BACKEND_IMAGE}) ================" >&2
REPRO=0

# --- Finding 1: single-arch config blob 404 --------------------------------------
sa_blob=$(oci_get "${REPO}/single-arch" blobs "${SA_CONFIG}")
echo "[F1] GET /v2/${REPO}/single-arch/blobs/${SA_CONFIG} -> HTTP ${sa_blob}  (404 = bug)" >&2
[ "$sa_blob" = "404" ] && { REPRO=$((REPRO+1)); echo "     => Finding 1 REPRODUCED (config blob missing / hollow image)" >&2; }

# --- Finding 2: multi-arch child manifest 404 (THE missed leg) --------------------
ma_child=$(oci_get "${REPO}/multi-arch" manifests "${MA_CHILD0}")
echo "[F2] GET /v2/${REPO}/multi-arch/manifests/${MA_CHILD0} -> HTTP ${ma_child}  (404 = bug)" >&2
[ "$ma_child" = "404" ] && { REPRO=$((REPRO+1)); echo "     => Finding 2 REPRODUCED (child manifest not recursed / missing)" >&2; }
ma_child_cfg=$(oci_get "${REPO}/multi-arch" blobs "${MA_CHILD0_CFG}")
echo "[F2b] GET /v2/${REPO}/multi-arch/blobs/${MA_CHILD0_CFG} -> HTTP ${ma_child_cfg}  (404 = bug evidence)" >&2

# --- Finding 3: real docker pull, asserted PER image ------------------------------
echo "$AK_ADMIN_PASS" | docker login "${AK_REGISTRY}" -u "$AK_ADMIN_USER" --password-stdin >/dev/null 2>&1 || true
pull_sa=1; docker pull "${AK_REGISTRY}/${REPO}/single-arch:latest" >/dev/null 2>&1 && pull_sa=0
pull_ma=1; docker pull "${AK_REGISTRY}/${REPO}/multi-arch:latest"  >/dev/null 2>&1 && pull_ma=0
echo "[F3] docker pull single-arch exit=${pull_sa}  multi-arch exit=${pull_ma}  (non-zero = pull fails = bug)" >&2
[ "$pull_sa" != "0" ] && { REPRO=$((REPRO+1)); echo "     => Finding 3a REPRODUCED (single-arch unpullable)" >&2; }
[ "$pull_ma" != "0" ] && { REPRO=$((REPRO+1)); echo "     => Finding 3b REPRODUCED (multi-arch unpullable)" >&2; }
# clean up pulled images + login creds on the host
docker rmi "${AK_REGISTRY}/${REPO}/single-arch:latest" "${AK_REGISTRY}/${REPO}/multi-arch:latest" >/dev/null 2>&1 || true
docker logout "${AK_REGISTRY}" >/dev/null 2>&1 || true
docker logout "${NEXUS_DOCKER}" >/dev/null 2>&1 || true

# --- DB: oci_blobs count for the repo == 0 -----------------------------------------
blob_ct=$(psql_ak "SELECT count(*) FROM oci_blobs ob JOIN repositories r ON r.id=ob.repository_id WHERE r.name='${REPO}';")
tag_ct=$(psql_ak "SELECT count(*) FROM oci_tags ot JOIN repositories r ON r.id=ot.repository_id WHERE r.name='${REPO}';")
art_ct=$(psql_ak "SELECT count(*) FROM artifacts a JOIN repositories r ON r.id=a.repository_id WHERE r.name='${REPO}';")
echo "[DB] oci_blobs(${REPO})=${blob_ct:-?}  oci_tags(${REPO})=${tag_ct:-?}  artifacts(${REPO})=${art_ct:-?}" >&2
echo "     (oci_blobs==0 while artifacts>0 = manifests stored as dumb files, never OCI-registered)" >&2
[ "${blob_ct:-0}" = "0" ] && { REPRO=$((REPRO+1)); echo "     => DB REPRODUCED (oci_blobs==0 for migrated docker repo)" >&2; }

# --- Orphan-tag probe: delete-tag + re-migrate --------------------------------------
# (Corrected orphan invariant, verbatim from the rig oracle 2026-07-15 rev: a tag
# is orphan ONLY if its manifest has NO blob edge, NO child edge, AND no manifest
# bytes in the store.)
echo "[ORPHAN] deleting a tag + re-migrating, then checking orphan/fidelity invariants ..." >&2
del_tok=$(oci_token "repository:${REPO}/single-arch:*")
curl -s -o /dev/null -X DELETE -H "Authorization: Bearer ${del_tok}" \
  "${AK_BASE}/v2/${REPO}/single-arch/manifests/latest" || true
akj POST "/api/v1/migrations/${JOB_ID}/start" >/dev/null 2>&1 || true
sleep 8

orphan_ct=$(psql_ak "SELECT count(*) FROM oci_tags ot JOIN repositories r ON r.id=ot.repository_id WHERE r.name='${REPO}'
  AND NOT EXISTS (SELECT 1 FROM manifest_blob_refs br WHERE br.repository_id=ot.repository_id AND br.manifest_digest=ot.manifest_digest)
  AND NOT EXISTS (SELECT 1 FROM oci_manifest_refs mr WHERE mr.repository_id=ot.repository_id AND mr.parent_digest=ot.manifest_digest)
  AND NOT EXISTS (SELECT 1 FROM artifacts a WHERE a.repository_id=ot.repository_id AND a.storage_key='oci-manifests/'||ot.manifest_digest AND a.is_deleted=false);")
echo "[ORPHAN] REAL orphan oci_tags (no blob edge, no child edge, no manifest bytes) = ${orphan_ct:-0}  (expect 0)" >&2
[ "${orphan_ct:-0}" != "0" ] && { REPRO=$((REPRO+1)); echo "     => ORPHAN REPRODUCED (tag resolves to nothing pullable)" >&2; }

hollow_img=$(psql_ak "SELECT count(*) FROM manifest_blob_refs br JOIN repositories r ON r.id=br.repository_id WHERE r.name='${REPO}' AND NOT EXISTS (SELECT 1 FROM oci_blobs ob WHERE ob.repository_id=br.repository_id AND ob.digest=br.blob_digest);")
unresolved_child=$(psql_ak "SELECT count(*) FROM oci_manifest_refs mr JOIN repositories r ON r.id=mr.repository_id WHERE r.name='${REPO}' AND NOT EXISTS (SELECT 1 FROM oci_tags c WHERE c.repository_id=mr.repository_id AND c.manifest_digest=mr.child_digest);")
echo "[INVARIANT] hollow images (manifest_blob_refs -> missing oci_blob) = ${hollow_img:-0}  (expect 0)" >&2
echo "[INVARIANT] unresolved index children (child not a registered tag) = ${unresolved_child:-0}  (expect 0)" >&2
[ "${hollow_img:-0}" != "0" ] && { REPRO=$((REPRO+1)); echo "     => HOLLOW-IMAGE REPRODUCED (referenced blob not registered)" >&2; }
[ "${unresolved_child:-0}" != "0" ] && { REPRO=$((REPRO+1)); echo "     => UNRESOLVED-CHILD REPRODUCED (index child manifest not registered)" >&2; }

echo "=======================================================================================" >&2
echo "REPRO_FINDINGS=${REPRO}" >&2

# Non-zero while ANY core finding reproduces (post-fix -> 0 = green).
if [ "${REPRO}" -gt 0 ]; then
  err "#2457 REPRODUCES: ${REPRO} finding(s) present -> exit ${REPRO}"
  exit "${REPRO}"
fi
log "GREEN: no #2457 findings reproduced (single-arch AND multi-arch migrated images pull natively) -> exit 0"
exit 0
