#!/usr/bin/env bash
# =============================================================================
# tiers/virtual-no-transfer/assert.sh -- the #2821 ORACLE (virtual != byte copy)
# =============================================================================
# run.sh has stood up backend+postgres+nexus on this slot and exported BASE_URL,
# DB_CONTAINER, BACKEND_IMAGE, DTF_SLOT, ADMIN_USER/ADMIN_PASS; nexus_seed.sh has
# put two raw hosted members + a raw group over them into Nexus. This drives a
# REAL AK migration of both members + the group and asserts the #2821 fix: the
# group provisions as an AK virtual repo whose members are correlated, but the
# virtual repo accrues ZERO artifact rows / storage objects of its own -- no
# member bytes copied in -- while the member hosted repos DID transfer normally.
#
# POSITIVE oracle (NON-ZERO-WHILE-BUG): exit = number of FAILED checks; a fully
# fixed image exits 0. Pre-#2821 the virtual repo accrues the members' aggregated
# bytes (V3 fails), so the oracle is discriminating.
#
#   V1  the group migrates to an AK repo with repo_type='virtual'
#   V2  virtual_repo_members correlated (>=2 members; provisioning + #2783 intact)
#   V3  the virtual repo has ZERO artifact rows / storage objects of its own
#       (artifacts + oci_blobs + proxy_cache_artifacts WHERE repository_id =
#       the virtual repo id == 0)  <-- the #2821 discriminator
#   V4  positive control: each member hosted repo DID transfer its bytes
#       (artifacts WHERE repository_id = member id >= 1) -- the fix must not
#       suppress legitimate hosted transfers
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
DB_CTR="${DB_CONTAINER}"
VNT_FIXTURES_FILE="${NEXUS_STATE_DIR}/virtualnotransfer_fixtures.json"

[ -f "${VNT_FIXTURES_FILE}" ] || die "no fixtures at ${VNT_FIXTURES_FILE} -- run nexus_seed.sh first"
nexus_is_up || die "Nexus not up -- profile/run.sh problem"

FX="${VNT_FIXTURES_FILE}"
GROUP_REPO=$(jq -r '.group' "$FX")
MEM_A=$(jq -r '.members[0]' "$FX")
MEM_B=$(jq -r '.members[1]' "$FX")
log "Fixtures: group=${GROUP_REPO}  members=[${MEM_A}, ${MEM_B}]"
log "Slot ${DTF_SLOT}: AK=${AK_BASE}  DB=${DB_CTR}  image=${BACKEND_IMAGE}"

# --- AK REST helpers ----------------------------------------------------------
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

# --- 1. connection ------------------------------------------------------------
log "Creating Nexus source connection (${NEXUS_API_INTERNAL}) ..."
conn_body=$(jq -nc --arg url "${NEXUS_API_INTERNAL}" --arg u "${NEXUS_ADMIN_USER}" --arg p "$(nx_pass)" '{
  name:"dtf-virtualnotransfer-nexus-source", url:$url, auth_type:"basic_auth", source_type:"nexus",
  credentials:{username:$u, password:$p}
}')
conn=$(akj POST /api/v1/migrations/connections "$conn_body")
CONN_ID=$(echo "$conn" | jq -r '.id // empty')
[ -n "$CONN_ID" ] || die "connection create failed: $conn"
log "connection test: $(akj POST "/api/v1/migrations/connections/${CONN_ID}/test" | jq -c '{success,message}')"

# --- 2. migrate members a+b + the group ---------------------------------------
# order_repositories_for_migration migrates locals (members) before virtuals
# (the group), so member ids exist when the group's members are correlated.
job_body=$(jq -nc --arg cid "${CONN_ID}" --arg a "${MEM_A}" --arg b "${MEM_B}" --arg g "${GROUP_REPO}" '{
  source_connection_id:$cid, job_type:"full",
  config:{ include_repos:[$a,$b,$g], conflict_resolution:"overwrite", verify_checksums:true,
           include_users:false, include_groups:false, include_permissions:false }
}')
job=$(akj POST /api/v1/migrations "$job_body")
JOB_ID=$(echo "$job" | jq -r '.id // empty')
[ -n "$JOB_ID" ] || die "job create failed: $job"
log "job id=${JOB_ID}"

akj POST "/api/v1/migrations/${JOB_ID}/assess" >/dev/null 2>&1 || true
adl=$(( $(date +%s) + 60 ))
while [ "$(date +%s)" -lt "$adl" ]; do
  st=$(akj GET "/api/v1/migrations/${JOB_ID}" | jq -r '.status'); [ "$st" = "assessing" ] || break; sleep 3
done
log "Starting migration ..."
akj POST "/api/v1/migrations/${JOB_ID}/start" >/dev/null 2>&1 || true
status=""; deadline=$(( $(date +%s) + 240 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  jr=$(akj GET "/api/v1/migrations/${JOB_ID}"); status=$(echo "$jr" | jq -r '.status')
  case "$status" in completed|completed_with_errors|failed|cancelled) break;; esac; sleep 4
done
jr=$(akj GET "/api/v1/migrations/${JOB_ID}")
log "final job status=${status}  counters=$(echo "$jr" | jq -c '{total_items,completed_items,failed_items,skipped_items}')  error_summary=$(echo "$jr" | jq -r '.error_summary // ""')"

# --- resolve the migrated repo ids -------------------------------------------
GROUP_ID=$(psql_ak "SELECT id FROM repositories WHERE key='${GROUP_REPO}';")
A_ID=$(psql_ak "SELECT id FROM repositories WHERE key='${MEM_A}';")
B_ID=$(psql_ak "SELECT id FROM repositories WHERE key='${MEM_B}';")
log "ids: group=${GROUP_ID:-<none>} A=${A_ID:-<none>} B=${B_ID:-<none>}"

echo "================ #2821 POSITIVE ASSERTIONS (slot ${DTF_SLOT}, image ${BACKEND_IMAGE}) ================" >&2
FAILS=0

# --- V1: group -> virtual -----------------------------------------------------
grp_type=$(psql_ak "SELECT repo_type::text FROM repositories WHERE key='${GROUP_REPO}';")
echo "[V1] repositories '${GROUP_REPO}' repo_type='${grp_type:-<none>}' (want virtual)" >&2
if [ "$grp_type" = "virtual" ]; then echo "     => V1 OK" >&2
else FAILS=$((FAILS+1)); echo "     => V1 FAIL (group not migrated as an AK virtual repo)" >&2; fi

# --- V2: members correlated (provisioning + #2783 intact) --------------------
member_count=$(psql_ak "SELECT count(*) FROM virtual_repo_members vrm JOIN repositories vr ON vr.id=vrm.virtual_repo_id WHERE vr.key='${GROUP_REPO}';")
echo "[V2] virtual_repo_members(${GROUP_REPO}) count=${member_count:-0} (want >=2; provisioning + #2783 member correlation intact)" >&2
if [ "${member_count:-0}" -ge 2 ]; then echo "     => V2 OK (members correlated)" >&2
else FAILS=$((FAILS+1)); echo "     => V2 FAIL (member correlation missing; #2783 regressed or group not provisioned)" >&2; fi

# --- V3: virtual repo owns ZERO artifacts / storage objects (the #2821 gate) --
if [ -n "${GROUP_ID}" ]; then
  v_art=$(psql_ak "SELECT count(*) FROM artifacts WHERE repository_id='${GROUP_ID}' AND is_deleted=false;")
  v_oci=$(psql_ak "SELECT count(*) FROM oci_blobs WHERE repository_id='${GROUP_ID}';")
  v_prx=$(psql_ak "SELECT count(*) FROM proxy_cache_artifacts WHERE repository_id='${GROUP_ID}';")
else
  v_art="<no-repo>"; v_oci="<no-repo>"; v_prx="<no-repo>"
fi
echo "[V3] virtual repo '${GROUP_REPO}' own storage: artifacts=${v_art} oci_blobs=${v_oci} proxy_cache_artifacts=${v_prx} (want all 0 -- a virtual repo aggregates, it must not copy member bytes)" >&2
if [ "${v_art:-1}" = "0" ] && [ "${v_oci:-1}" = "0" ] && [ "${v_prx:-1}" = "0" ]; then
  echo "     => V3 OK (no member bytes copied into the virtual repo)" >&2
else
  FAILS=$((FAILS+1)); echo "     => V3 FAIL (virtual repo accrued its own artifact rows/storage -- pre-#2821 the members' aggregated bytes were transferred in)" >&2
fi

# --- V4: positive control -- members transferred their bytes normally ---------
a_art=$(psql_ak "SELECT count(*) FROM artifacts a JOIN repositories r ON r.id=a.repository_id WHERE r.key='${MEM_A}' AND a.is_deleted=false;")
b_art=$(psql_ak "SELECT count(*) FROM artifacts a JOIN repositories r ON r.id=a.repository_id WHERE r.key='${MEM_B}' AND a.is_deleted=false;")
echo "[V4] member artifacts: ${MEM_A}=${a_art:-0} ${MEM_B}=${b_art:-0} (want each >=1 -- hosted members still transfer)" >&2
if [ "${a_art:-0}" -ge 1 ] && [ "${b_art:-0}" -ge 1 ]; then echo "     => V4 OK (member hosted repos transferred normally)" >&2
else FAILS=$((FAILS+1)); echo "     => V4 FAIL (a hosted member did not transfer -- fix over-suppressed, or seed/migration broke)" >&2; fi

echo "===============================================================================================" >&2
echo "POSITIVE_CHECKS_FAILED=${FAILS}" >&2
if [ "${FAILS}" -gt 0 ]; then
  err "#2821 NOT satisfied: ${FAILS} positive check(s) failed -> exit ${FAILS}"
  exit "${FAILS}"
fi
log "GREEN: group provisioned as a virtual repo with correlated members and ZERO own bytes; members transferred normally -> exit 0"
exit 0
