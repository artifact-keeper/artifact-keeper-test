#!/usr/bin/env bash
# =============================================================================
# tiers/nexus-group-virtual/nexus_seed.sh — seed the #2783 group->virtual fixture
# =============================================================================
# Seeds three `raw` HOSTED member repos and one `raw` GROUP repo whose
# memberNames reference them, in a deterministic order:
#
#   grp-mem-a, grp-mem-b, grp-mem-c   (raw hosted, one file each)
#   grp-virtual  (raw group)  memberNames = [grp-mem-a, grp-mem-b, grp-mem-c]
#
# The tier's migration then imports only a+b+group (NOT c) so the "absent member
# is skipped, no dangling row" half of the #2783 fix is exercised too: c is a
# real Nexus group member that is simply not migrated, and must not appear in
# the AK virtual repo's member list.
#
# Raw repos are used because the group->virtual member correlation is
# format-agnostic and raw hosted needs no signing key / toolchain — the file
# body is a plain PUT. Records the member order + the deliberately-excluded
# member to the per-run state file for assert.sh.
# =============================================================================
set -uo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/nexus_lib.sh"

MEM_A="${MEM_A:-grp-mem-a}"
MEM_B="${MEM_B:-grp-mem-b}"
MEM_C="${MEM_C:-grp-mem-c}"     # a real group member that is NOT migrated
GROUP_REPO="${GROUP_REPO:-grp-virtual}"
GV_FIXTURES_FILE="${NEXUS_STATE_DIR}/groupvirtual_fixtures.json"

nexus_is_up || die "Nexus is not running — run nexus_bootstrap.sh first."
[ -f "${NEXUS_PASS_FILE}" ] || die "No resolved admin password — run nexus_bootstrap.sh first."

repo_exists() {
  nx_curl GET "/service/rest/v1/repositories" \
    | jq -e --arg n "$1" '.[]|select(.name==$n)' >/dev/null 2>&1
}

# --- 1. create the three raw hosted member repos -----------------------------
create_raw_hosted() {  # $1 = name
  local name="$1" body code
  repo_exists "$name" && { log "member '${name}' already present."; return 0; }
  body=$(jq -nc --arg n "$name" '{
    name:$n, online:true,
    storage:{blobStoreName:"default", strictContentTypeValidation:false, writePolicy:"ALLOW"},
    raw:{contentDisposition:"ATTACHMENT"}
  }')
  code=$(nx_curl POST "/service/rest/v1/repositories/raw/hosted" \
    -H 'Content-Type: application/json' --data "$body" -o /dev/null -w '%{http_code}')
  log "create raw/hosted '${name}' -> HTTP ${code}"
  [ "$code" = "201" ] || warn "unexpected create status ${code} for ${name}"
}
create_raw_hosted "${MEM_A}"
create_raw_hosted "${MEM_B}"
create_raw_hosted "${MEM_C}"

# --- 2. create the raw group referencing the members (in order) --------------
if repo_exists "${GROUP_REPO}"; then
  log "group '${GROUP_REPO}' already present."
else
  gbody=$(jq -nc --arg n "${GROUP_REPO}" --arg a "${MEM_A}" --arg b "${MEM_B}" --arg c "${MEM_C}" '{
    name:$n, online:true,
    storage:{blobStoreName:"default", strictContentTypeValidation:false},
    group:{memberNames:[$a,$b,$c]}
  }')
  code=$(nx_curl POST "/service/rest/v1/repositories/raw/group" \
    -H 'Content-Type: application/json' --data "$gbody" -o /dev/null -w '%{http_code}')
  log "create raw/group '${GROUP_REPO}' (members ${MEM_A},${MEM_B},${MEM_C}) -> HTTP ${code}"
  [ "$code" = "201" ] || warn "unexpected group create status ${code}"
fi

# --- 3. seed one file into each member so they carry content -----------------
for m in "${MEM_A}" "${MEM_B}" "${MEM_C}"; do
  code=$(nx_curl PUT "/repository/${m}/dtf/marker-${m}.txt" \
    --data-binary "dtf-group-virtual member ${m}" -o /dev/null -w '%{http_code}')
  log "  PUT ${m}/dtf/marker-${m}.txt -> HTTP ${code}"
done

# --- 4. confirm + record fixture state ---------------------------------------
sleep 2
present=$(nx_curl GET "/service/rest/v1/repositories" | jq -r '[.[].name]|join(",")')
for r in "${MEM_A}" "${MEM_B}" "${MEM_C}" "${GROUP_REPO}"; do
  echo "$present" | tr ',' '\n' | grep -qx "$r" || die "repo '${r}' missing after seed (present: ${present})"
done

# migrated_members = the ordered members we WILL migrate (a,b); excluded = c
jq -n \
  --arg group "${GROUP_REPO}" \
  --arg a "${MEM_A}" --arg b "${MEM_B}" --arg c "${MEM_C}" \
  '{group:$group,
    migrated_members:[$a,$b],
    excluded_member:$c,
    all_group_members:[$a,$b,$c]}' \
  > "${GV_FIXTURES_FILE}"
log "Fixtures recorded at ${GV_FIXTURES_FILE}:"
cat "${GV_FIXTURES_FILE}" >&2
echo "${GV_FIXTURES_FILE}"
