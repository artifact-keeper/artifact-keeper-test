#!/usr/bin/env bash
# =============================================================================
# tiers/nexus-group-virtual/assert.sh — the #2783 ORACLE (group -> virtual)
# =============================================================================
# run.sh has stood up backend+postgres+nexus on this slot and exported BASE_URL,
# DB_CONTAINER, BACKEND_IMAGE, DTF_SLOT, ADMIN_USER/ADMIN_PASS; nexus_seed.sh has
# put three raw hosted members + a raw group into Nexus. This drives a REAL AK
# migration of the two members-to-keep + the group (deliberately EXCLUDING the
# third member) and asserts the #2783 fixed correlation.
#
# POSITIVE oracle (NON-ZERO-WHILE-BUG): exit = number of FAILED checks; a fully
# fixed image exits 0. Pre-#2783 the group migrates to an AK virtual repo with
# ZERO members -> every membership check below fails -> discriminating.
#
#   V1  the group migrates to an AK repo with repo_type='virtual'
#   V2  virtual_repo_members are EXACTLY the migrated member repo ids, in order
#       (grp-mem-a @ priority 1, grp-mem-b @ priority 2)
#   V3  the excluded member (grp-mem-c) is SKIPPED — not written as a member
#   V4  no DANGLING member rows (every member_repo_id resolves to a real repo)
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
GV_FIXTURES_FILE="${NEXUS_STATE_DIR}/groupvirtual_fixtures.json"

[ -f "${GV_FIXTURES_FILE}" ] || die "no fixtures at ${GV_FIXTURES_FILE} — run nexus_seed.sh first"
nexus_is_up || die "Nexus not up — profile/run.sh problem"

FX="${GV_FIXTURES_FILE}"
GROUP_REPO=$(jq -r '.group' "$FX")
MEM_A=$(jq -r '.migrated_members[0]' "$FX")
MEM_B=$(jq -r '.migrated_members[1]' "$FX")
MEM_C=$(jq -r '.excluded_member' "$FX")
log "Fixtures: group=${GROUP_REPO}  migrated members=[${MEM_A}, ${MEM_B}]  excluded=${MEM_C}"
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
  name:"dtf-groupvirtual-nexus-source", url:$url, auth_type:"basic_auth", source_type:"nexus",
  credentials:{username:$u, password:$p}
}')
conn=$(akj POST /api/v1/migrations/connections "$conn_body")
CONN_ID=$(echo "$conn" | jq -r '.id // empty')
[ -n "$CONN_ID" ] || die "connection create failed: $conn"
log "connection test: $(akj POST "/api/v1/migrations/connections/${CONN_ID}/test" | jq -c '{success,message}')"

# --- 2. migrate members a+b + the group (exclude c) ---------------------------
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
C_ID=$(psql_ak "SELECT id FROM repositories WHERE key='${MEM_C}';")   # should be empty (not migrated)
log "ids: group=${GROUP_ID:-<none>} A=${A_ID:-<none>} B=${B_ID:-<none>} C(excluded, expect empty)='${C_ID}'"

echo "================ #2783 POSITIVE ASSERTIONS (slot ${DTF_SLOT}, image ${BACKEND_IMAGE}) ================" >&2
FAILS=0

# --- V1: group -> virtual -----------------------------------------------------
grp_type=$(psql_ak "SELECT repo_type::text FROM repositories WHERE key='${GROUP_REPO}';")
echo "[V1] repositories '${GROUP_REPO}' repo_type='${grp_type:-<none>}' (want virtual)" >&2
if [ "$grp_type" = "virtual" ]; then echo "     => V1 OK" >&2
else FAILS=$((FAILS+1)); echo "     => V1 FAIL (group not migrated as an AK virtual repo)" >&2; fi

# --- V2: members are exactly [A,B] in order (by priority) ---------------------
# ordered "member_key:priority" lines
members_ordered=$(psql_ak "SELECT string_agg(m.key||':'||vrm.priority, ',' ORDER BY vrm.priority) FROM virtual_repo_members vrm JOIN repositories vr ON vr.id=vrm.virtual_repo_id JOIN repositories m ON m.id=vrm.member_repo_id WHERE vr.key='${GROUP_REPO}';")
member_count=$(psql_ak "SELECT count(*) FROM virtual_repo_members vrm JOIN repositories vr ON vr.id=vrm.virtual_repo_id WHERE vr.key='${GROUP_REPO}';")
echo "[V2] virtual_repo_members(${GROUP_REPO}) count=${member_count:-0} ordered='${members_ordered:-<none>}' (want ${MEM_A}:1,${MEM_B}:2)" >&2
# first member (priority 1) must be A, second (priority 2) must be B
first_member=$(psql_ak "SELECT m.key FROM virtual_repo_members vrm JOIN repositories vr ON vr.id=vrm.virtual_repo_id JOIN repositories m ON m.id=vrm.member_repo_id WHERE vr.key='${GROUP_REPO}' ORDER BY vrm.priority LIMIT 1;")
second_member=$(psql_ak "SELECT m.key FROM virtual_repo_members vrm JOIN repositories vr ON vr.id=vrm.virtual_repo_id JOIN repositories m ON m.id=vrm.member_repo_id WHERE vr.key='${GROUP_REPO}' ORDER BY vrm.priority OFFSET 1 LIMIT 1;")
if [ "${member_count:-0}" = "2" ] && [ "$first_member" = "${MEM_A}" ] && [ "$second_member" = "${MEM_B}" ]; then
  echo "     => V2 OK (members correlated to migrated repo ids, in order)" >&2
else
  FAILS=$((FAILS+1)); echo "     => V2 FAIL (expected exactly [${MEM_A},${MEM_B}] in order; pre-#2783 the virtual has ZERO members)" >&2
fi

# --- V3: excluded member (C) is not a member ---------------------------------
c_as_member=$(psql_ak "SELECT count(*) FROM virtual_repo_members vrm JOIN repositories vr ON vr.id=vrm.virtual_repo_id JOIN repositories m ON m.id=vrm.member_repo_id WHERE vr.key='${GROUP_REPO}' AND m.key='${MEM_C}';")
echo "[V3] excluded member '${MEM_C}' present as a virtual member = ${c_as_member:-0} (want 0 — absent members skipped)" >&2
if [ "${c_as_member:-0}" = "0" ]; then echo "     => V3 OK (absent member skipped)" >&2
else FAILS=$((FAILS+1)); echo "     => V3 FAIL (a non-migrated group member was written as a member)" >&2; fi

# --- V4: no dangling member rows ---------------------------------------------
dangling=$(psql_ak "SELECT count(*) FROM virtual_repo_members vrm JOIN repositories vr ON vr.id=vrm.virtual_repo_id WHERE vr.key='${GROUP_REPO}' AND NOT EXISTS (SELECT 1 FROM repositories r WHERE r.id=vrm.member_repo_id);")
echo "[V4] dangling member rows (member_repo_id not a real repo) = ${dangling:-0} (want 0)" >&2
if [ "${dangling:-0}" = "0" ]; then echo "     => V4 OK (no dangling rows)" >&2
else FAILS=$((FAILS+1)); echo "     => V4 FAIL (dangling member row present)" >&2; fi

echo "===============================================================================================" >&2
echo "POSITIVE_CHECKS_FAILED=${FAILS}" >&2
if [ "${FAILS}" -gt 0 ]; then
  err "#2783 NOT fully satisfied: ${FAILS} positive check(s) failed -> exit ${FAILS}"
  exit "${FAILS}"
fi
log "GREEN: group migrated to an AK virtual repo whose members are exactly the migrated member ids in order (absent member skipped, no dangling) -> exit 0"
exit 0
