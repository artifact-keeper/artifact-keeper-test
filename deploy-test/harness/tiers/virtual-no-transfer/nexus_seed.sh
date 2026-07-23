#!/usr/bin/env bash
# =============================================================================
# tiers/virtual-no-transfer/nexus_seed.sh -- seed the #2821 group->virtual fixture
# =============================================================================
# Seeds two `raw` HOSTED member repos and one `raw` GROUP repo whose memberNames
# reference them, in a deterministic order:
#
#   vnt-mem-a, vnt-mem-b   (raw hosted, one marker file each)
#   vnt-group  (raw group)  memberNames = [vnt-mem-a, vnt-mem-b]
#
# A raw group is the smallest fixture that reproduces #2821: the members carry
# real bytes, and the group aggregates them at read time. When AK migrates the
# group as a `virtual` repo, the pre-#2821 worker runs the same transfer loop it
# runs for a local repo -- list_artifacts on the Nexus group returns the members'
# aggregated components, and each is copied into the virtual repo's own storage
# (the bug). Raw is used because the group->virtual transfer misbehaviour is
# format-agnostic and raw hosted needs no signing key / toolchain (a plain PUT).
#
# Records the group name + the ordered members to the per-run state file so
# assert.sh can drive the migration and assert exact rows. All steps idempotent
# (run.sh gives a fresh `down -v` Nexus per run, but --keep re-runs must not
# double-fail).
# =============================================================================
set -uo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/nexus_lib.sh"

MEM_A="${MEM_A:-vnt-mem-a}"
MEM_B="${MEM_B:-vnt-mem-b}"
GROUP_REPO="${GROUP_REPO:-vnt-group}"
VNT_FIXTURES_FILE="${NEXUS_STATE_DIR}/virtualnotransfer_fixtures.json"

nexus_is_up || die "Nexus is not running -- run nexus_bootstrap.sh first."
[ -f "${NEXUS_PASS_FILE}" ] || die "No resolved admin password -- run nexus_bootstrap.sh first."

repo_exists() {
  nx_curl GET "/service/rest/v1/repositories" \
    | jq -e --arg n "$1" '.[]|select(.name==$n)' >/dev/null 2>&1
}

# --- 1. create the two raw hosted member repos -------------------------------
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

# --- 2. create the raw group referencing the members (in order) --------------
if repo_exists "${GROUP_REPO}"; then
  log "group '${GROUP_REPO}' already present."
else
  gbody=$(jq -nc --arg n "${GROUP_REPO}" --arg a "${MEM_A}" --arg b "${MEM_B}" '{
    name:$n, online:true,
    storage:{blobStoreName:"default", strictContentTypeValidation:false},
    group:{memberNames:[$a,$b]}
  }')
  code=$(nx_curl POST "/service/rest/v1/repositories/raw/group" \
    -H 'Content-Type: application/json' --data "$gbody" -o /dev/null -w '%{http_code}')
  log "create raw/group '${GROUP_REPO}' (members ${MEM_A},${MEM_B}) -> HTTP ${code}"
  [ "$code" = "201" ] || warn "unexpected group create status ${code}"
fi

# --- 3. seed marker files into each member so they carry real bytes ----------
# Two files per member so a byte-copy bug would leave an obvious count in the
# virtual repo (>=4 aggregated components), not just a single ambiguous row.
for m in "${MEM_A}" "${MEM_B}"; do
  for f in one two; do
    code=$(nx_curl PUT "/repository/${m}/dtf/marker-${m}-${f}.txt" \
      --data-binary "dtf-virtual-no-transfer member ${m} file ${f}" -o /dev/null -w '%{http_code}')
    log "  PUT ${m}/dtf/marker-${m}-${f}.txt -> HTTP ${code}"
  done
done

# --- 4. confirm + record fixture state ---------------------------------------
sleep 2
present=$(nx_curl GET "/service/rest/v1/repositories" | jq -r '[.[].name]|join(",")')
for r in "${MEM_A}" "${MEM_B}" "${GROUP_REPO}"; do
  echo "$present" | tr ',' '\n' | grep -qx "$r" || die "repo '${r}' missing after seed (present: ${present})"
done

# Log how many components the GROUP aggregates via the components API (the same
# path the AK migration reads) so the RED byte-copy path's input is visible.
grp_n=$(nx_curl GET "/service/rest/v1/components?repository=${GROUP_REPO}" | jq '[.items[]?]|length' 2>/dev/null || echo 0)
a_n=$(nx_curl GET "/service/rest/v1/components?repository=${MEM_A}" | jq '[.items[]?]|length' 2>/dev/null || echo 0)
b_n=$(nx_curl GET "/service/rest/v1/components?repository=${MEM_B}" | jq '[.items[]?]|length' 2>/dev/null || echo 0)
log "Nexus components after seed: ${MEM_A}=${a_n} ${MEM_B}=${b_n} ${GROUP_REPO}(aggregated)=${grp_n}"
[ "${a_n:-0}" -ge 1 ] || die "member '${MEM_A}' has no components after seed"
[ "${b_n:-0}" -ge 1 ] || die "member '${MEM_B}' has no components after seed"

jq -n \
  --arg group "${GROUP_REPO}" \
  --arg a "${MEM_A}" --arg b "${MEM_B}" \
  '{group:$group, members:[$a,$b]}' \
  > "${VNT_FIXTURES_FILE}"
log "Fixtures recorded at ${VNT_FIXTURES_FILE}:"
cat "${VNT_FIXTURES_FILE}" >&2
echo "${VNT_FIXTURES_FILE}"
