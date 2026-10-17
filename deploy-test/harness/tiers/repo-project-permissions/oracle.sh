#!/usr/bin/env bash
# =============================================================================
# tiers/repo-project-permissions/oracle.sh — repository project unassignment,
#   permission target names, and the virtual-members notice
#   (artifact-keeper#4026 / #4730, #4639 / #4737, #4690 / #4753)
# =============================================================================
# run.sh has stood up the `filesystem` profile-set with RATE_LIMIT_ENABLED=false
# and exported BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID,
# DTF_SLOT, RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
#
# Three independent legs, each with a control half that holds on BOTH images
# and a fix half that is RED on 1.11.1 (see the manifest for the bugs):
#   #4026  PATCH {"project_id": null} clears (response + DB); a repository-only
#          admin is refused 403 for the clear; omitting the field is unchanged.
#   #4639  target_name for group / project / artifact permission targets in
#          the create response, the filtered listing and the detail route;
#          a deleted group target reports null.
#   #4690  X-AK-Virtual-Members-Notice on /members and /artifacts for a caller
#          granted read on the virtual only. Access itself does NOT widen: the
#          listings stay empty and the member stays 404 on both images.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"
: "${DTF_SLOT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

SUF="${RUN_ID##*-}-$$"
SLOT="$DTF_SLOT"

# Repository keys deliberately do NOT start with "<project key>-": a project
# key claims that prefix (#2473), which is a separate rule from this tier's.
PROJ_KEY="rpp-proj-${SLOT}-${SUF}"
PROJ_NAME="RPP Project ${SUF}"
REPO="rpp-repo-${SLOT}-${SUF}"            # #4026 subject
TREPO="rpp-trepo-${SLOT}-${SUF}"          # #4639 repository + artifact target
TGROUP="rpp-tgroup-${SLOT}-${SUF}"        # #4639 group target (deleted later)
PGROUP="rpp-pgroup-${SLOT}-${SUF}"        # #4639 principal of every rule
TPROJ_KEY="rpp-tproj-${SLOT}-${SUF}"
TPROJ_NAME="RPP Target Project ${SUF}"
ART_PATH="rpptool/2.4.1/rpptool-2.4.1.bin"
ART_NAME="rpptool"
ART_VER="2.4.1"

VMEMBER="rpp-member-${SLOT}-${SUF}"       # #4690 private hosted member
VIRT="rpp-virtual-${SLOT}-${SUF}"         # #4690 private virtual over it
VGROUP="rpp-vgroup-${SLOT}-${SUF}"        # holds read on the virtual only
VART_PATH="vtool/1.0.0/vtool-1.0.0.bin"

PASS_SUFFIX="Rpp_${SUF}_Aa1!"
RA_USER="rpp-repoadmin-${SLOT}-${SUF}"    # repository admin, not project admin
RD_USER="rpp-reader-${SLOT}-${SUF}"       # member of VGROUP
NG_USER="rpp-nogrant-${SLOT}-${SUF}"      # no grant at all

# The exact notice text #4753 ships (NO_READABLE_MEMBERS_NOTICE).
NOTICE_HDR="x-ak-virtual-members-notice"
NOTICE_TEXT="No member of this virtual repository is readable by you. Reading through a virtual repository requires read access on each member repository; a grant on the virtual repository alone does not include its members."

WORK="$(mktemp -d -t dtf-rpp-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

# --- HTTP helpers -------------------------------------------------------------
# req METHOD PATH TOKEN [JSON]  -> HTTP code on stdout; body in $WORK/body,
# response headers in $WORK/hdr. TOKEN may be empty (anonymous).
req() {
  local method="$1" path="$2" tok="$3" data="${4:-}"
  local -a args=(-s "${CURL_TIMEOUT_ARGS[@]}" -X "$method" -o "$WORK/body" -D "$WORK/hdr" -w '%{http_code}')
  [ -n "$tok" ] && args+=(-H "Authorization: Bearer ${tok}")
  [ -n "$data" ] && args+=(-H 'Content-Type: application/json' --data "$data")
  : > "$WORK/body"; : > "$WORK/hdr"
  curl "${args[@]}" "${BASE_URL}${path}" 2>/dev/null || echo 000
}
body() { cat "$WORK/body" 2>/dev/null || true; }
# notice -> the X-AK-Virtual-Members-Notice value of the last response, or "".
notice() {
  grep -i "^${NOTICE_HDR}:" "$WORK/hdr" 2>/dev/null | head -n1 \
    | sed -e 's/^[^:]*:[[:space:]]*//' -e 's/\r$//' || true
}
db() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -Atc "$1" 2>/dev/null | tr -d '[:space:]' || echo "?"; }
db_project_of() { db "SELECT coalesce(project_id::text, 'NULL') FROM repositories WHERE key = '${1}';"; }

# setup_or_die NAME CODE BODY: infra_fail + end_suite unless CODE is 2xx.
setup_ok() {
  local what="$1" code="$2"
  if [ "${code:0:1}" != "2" ]; then
    begin_test "setup: ${what}"
    infra_fail "${what}: HTTP ${code}" "$(body | head -c 400)"
    end_suite
  fi
}

begin_suite "repo-project-permissions"

# =============================================================================
# SETUP (shared)
# =============================================================================
auth_admin   # sets ADMIN_TOKEN
AT="$ADMIN_TOKEN"

for u in "$RA_USER" "$RD_USER" "$NG_USER"; do
  if ! create_test_user_with_retry "$u" "$PASS_SUFFIX" "${u}@t.test" >/dev/null; then
    begin_test "setup: create user ${u}"; infra_fail "could not create user ${u}"; end_suite
  fi
done
RA_ID="$(resolve_user_id_by_username "$RA_USER" || true)"
[ -n "$RA_ID" ] || { begin_test "setup: resolve ${RA_USER}"; infra_fail "no id for ${RA_USER}"; end_suite; }
RA_TOKEN="$(login_as "$RA_USER" "$PASS_SUFFIX")" || true
RD_TOKEN="$(login_as "$RD_USER" "$PASS_SUFFIX")" || true
NG_TOKEN="$(login_as "$NG_USER" "$PASS_SUFFIX")" || true
if [ -z "$RA_TOKEN" ] || [ -z "$RD_TOKEN" ] || [ -z "$NG_TOKEN" ]; then
  begin_test "setup: log in the three test users"; infra_fail "a user login returned no token"; end_suite
fi

mkrepo() { # KEY TYPE -> private generic repository
  req POST /api/v1/repositories "$AT" \
    "$(jq -nc --arg k "$1" --arg t "$2" '{key:$k,name:$k,format:"generic",repo_type:$t,is_public:false}')"
}
mkgroup() { req POST /api/v1/groups "$AT" "$(jq -nc --arg n "$1" '{name:$n}')"; }
grant() { # PRINCIPAL_TYPE PRINCIPAL_ID TARGET_TYPE TARGET_ID ACTIONS_CSV
  req POST /api/v1/permissions "$AT" "$(jq -nc --arg pt "$1" --arg pid "$2" --arg tt "$3" --arg tid "$4" --arg a "$5" \
    '{principal_type:$pt,principal_id:$pid,target_type:$tt,target_id:$tid,actions:($a|split(","))}')"
}

# =============================================================================
# #4026 — PATCH project_id null clears the assignment
# =============================================================================
c="$(req POST /api/v1/projects "$AT" "$(jq -nc --arg k "$PROJ_KEY" --arg n "$PROJ_NAME" '{key:$k,name:$n}')")"
setup_ok "create project ${PROJ_KEY}" "$c"
PROJ_ID="$(body | jq -r '.id // empty')"
c="$(mkrepo "$REPO" local)"; setup_ok "create repository ${REPO}" "$c"
REPO_ID="$(body | jq -r '.id // empty')"
c="$(grant user "$RA_ID" repository "$REPO_ID" "read,write,admin")"
setup_ok "grant ${RA_USER} admin on ${REPO}" "$c"

begin_test "#4026 control: description PATCH works and the repository starts unassigned"
c="$(req PATCH "/api/v1/repositories/${REPO}" "$AT" '{"description":"rpp-desc-1"}')"
if [ "$c" = "200" ] && [ "$(body | jq -r '.description')" = "rpp-desc-1" ] \
   && [ "$(db_project_of "$REPO")" = "NULL" ]; then pass
else fail "description PATCH: HTTP ${c}, db project=$(db_project_of "$REPO")" "$(body | head -c 300)"; fi

begin_test "#4026 control: PATCH project_id=<id> assigns (response and DB)"
c="$(req PATCH "/api/v1/repositories/${REPO}" "$AT" "$(jq -nc --arg p "$PROJ_ID" '{project_id:$p}')")"
if [ "$c" = "200" ] && [ "$(body | jq -r '.project_id')" = "$PROJ_ID" ] \
   && [ "$(db_project_of "$REPO")" = "$PROJ_ID" ]; then pass
else fail "assign: HTTP ${c}, response project_id=$(body | jq -r '.project_id' 2>/dev/null), db=$(db_project_of "$REPO")" "$(body | head -c 300)"; fi

begin_test "#4026 control: a PATCH without project_id leaves the assignment unchanged"
c="$(req PATCH "/api/v1/repositories/${REPO}" "$AT" '{"description":"rpp-desc-2"}')"
if [ "$c" = "200" ] && [ "$(body | jq -r '.project_id')" = "$PROJ_ID" ] \
   && [ "$(body | jq -r '.description')" = "rpp-desc-2" ] \
   && [ "$(db_project_of "$REPO")" = "$PROJ_ID" ]; then pass
else fail "omitted field: HTTP ${c}, response project_id=$(body | jq -r '.project_id' 2>/dev/null), db=$(db_project_of "$REPO")" "$(body | head -c 300)"; fi

begin_test "#4026 control: the repository-level admin can PATCH the description (it really is repo admin)"
c="$(req PATCH "/api/v1/repositories/${REPO}" "$RA_TOKEN" '{"description":"rpp-desc-ra"}')"
if [ "$c" = "200" ] && [ "$(body | jq -r '.description')" = "rpp-desc-ra" ] \
   && [ "$(db_project_of "$REPO")" = "$PROJ_ID" ]; then pass
else fail "repo admin description PATCH: HTTP ${c}, db=$(db_project_of "$REPO")" "$(body | head -c 300)"; fi

begin_test "#4026 fix: a repository-only admin gets 403 on {\"project_id\": null} and the row keeps its project"
c="$(req PATCH "/api/v1/repositories/${REPO}" "$RA_TOKEN" '{"project_id":null}')"
after="$(db_project_of "$REPO")"
if [ "$c" = "403" ] && [ "$after" = "$PROJ_ID" ]; then pass
else fail "expected 403 with project_id kept; got HTTP ${c}, db=${after} (1.11.1 answers 200 and ignores the null)" "$(body | head -c 300)"; fi

begin_test "#4026 fix: admin PATCH {\"project_id\": null} answers project_id null AND the DB column is NULL"
c="$(req PATCH "/api/v1/repositories/${REPO}" "$AT" '{"project_id":null}')"
resp_pid="$(body | jq -r 'if has("project_id") then (.project_id // "NULL") else "ABSENT" end' 2>/dev/null)"
after="$(db_project_of "$REPO")"
if [ "$c" = "200" ] && [ "$resp_pid" = "NULL" ] && [ "$after" = "NULL" ]; then pass
else fail "clear: HTTP ${c}, response project_id=${resp_pid}, db=${after} (1.11.1: 200 with the project unchanged)" "$(body | head -c 300)"; fi

begin_test "#4026 fix: clearing an unassigned repository again is an idempotent 200"
c="$(req PATCH "/api/v1/repositories/${REPO}" "$AT" '{"project_id":null}')"
if [ "$c" = "200" ] && [ "$(body | jq -r '.project_id // "NULL"')" = "NULL" ] \
   && [ "$(db_project_of "$REPO")" = "NULL" ]; then pass
else fail "second clear: HTTP ${c}, db=$(db_project_of "$REPO")" "$(body | head -c 300)"; fi

# =============================================================================
# #4639 — permission target_name for group / project / artifact targets
# =============================================================================
c="$(mkgroup "$PGROUP")"; setup_ok "create principal group" "$c"; PGROUP_ID="$(body | jq -r '.id // empty')"
c="$(mkgroup "$TGROUP")"; setup_ok "create target group" "$c";    TGROUP_ID="$(body | jq -r '.id // empty')"
c="$(req POST /api/v1/projects "$AT" "$(jq -nc --arg k "$TPROJ_KEY" --arg n "$TPROJ_NAME" '{key:$k,name:$n}')")"
setup_ok "create target project" "$c"; TPROJ_ID="$(body | jq -r '.id // empty')"
c="$(mkrepo "$TREPO" local)"; setup_ok "create target repository" "$c"; TREPO_ID="$(body | jq -r '.id // empty')"
c="$(curl -s "${CURL_TIMEOUT_ARGS[@]}" -X PUT -o "$WORK/body" -w '%{http_code}' -H "Authorization: Bearer ${AT}" \
      --data-binary "rpp-artifact-${SUF}" "${BASE_URL}/api/v1/repositories/${TREPO}/artifacts/${ART_PATH}" 2>/dev/null || echo 000)"
setup_ok "upload target artifact" "$c"; ART_ID="$(body | jq -r '.id // empty')"
# The artifact's stored identity, so the expected name is the row's, not a guess.
ART_ROW="$(docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -Atc \
  "SELECT name || '|' || coalesce(version, '') FROM artifacts WHERE id = '${ART_ID}';" 2>/dev/null | tr -d '\r')"
if [ "$ART_ROW" != "${ART_NAME}|${ART_VER}" ]; then
  begin_test "setup: the uploaded artifact is stored as ${ART_NAME}@${ART_VER}"
  infra_fail "artifact row is '${ART_ROW}'"; end_suite
fi
EXP_ART="${ART_NAME}@${ART_VER}"

declare -A RULE_ID=() CREATE_NAME=() EXPECT=()
EXPECT[repository]="$TREPO"; EXPECT[group]="$TGROUP"; EXPECT[project]="$TPROJ_NAME"; EXPECT[artifact]="$EXP_ART"
declare -A TID=([repository]="$TREPO_ID" [group]="$TGROUP_ID" [project]="$TPROJ_ID" [artifact]="$ART_ID")
for tt in repository group project artifact; do
  c="$(grant group "$PGROUP_ID" "$tt" "${TID[$tt]}" "read")"
  setup_ok "grant ${PGROUP} read on the ${tt} target" "$c"
  RULE_ID[$tt]="$(body | jq -r '.id // empty')"
  CREATE_NAME[$tt]="$(body | jq -r '.target_name // "null"')"
done
LIST="$WORK/perm-list.json"
c="$(req GET "/api/v1/permissions?principal_id=${PGROUP_ID}&per_page=100" "$AT")"
setup_ok "list ${PGROUP}'s permissions" "$c"
body > "$LIST"
list_name() { jq -r --arg id "$1" '.items[] | select(.id == $id) | (.target_name // "null")' "$LIST" 2>/dev/null; }
detail_name() { req GET "/api/v1/permissions/${1}" "$AT" >/dev/null; body | jq -r '.target_name // "null"' 2>/dev/null; }

check_target() { # TARGET_TYPE
  local tt="$1" exp="${EXPECT[$1]}" ln dn
  ln="$(list_name "${RULE_ID[$tt]}")"; dn="$(detail_name "${RULE_ID[$tt]}")"
  if [ "${CREATE_NAME[$tt]}" = "$exp" ] && [ "$ln" = "$exp" ] && [ "$dn" = "$exp" ]; then pass
  else fail "${tt} target_name expected '${exp}': create='${CREATE_NAME[$tt]}' list='${ln}' detail='${dn}' (1.11.1: null for non-repository targets)"; fi
}

begin_test "#4639 control: a repository-target rule reports the repository name (create, list, detail)"
check_target repository
begin_test "#4639 fix: a group-target rule reports the group name (create, list, detail)"
check_target group
begin_test "#4639 fix: a project-target rule reports the project name (create, list, detail)"
check_target project
begin_test "#4639 fix: an artifact-target rule reports name@version (create, list, detail)"
check_target artifact

begin_test "#4639 control: after the target group is deleted its rule survives and reports target_name null"
c="$(req DELETE "/api/v1/groups/${TGROUP_ID}" "$AT")"
if [ "${c:0:1}" != "2" ]; then
  infra_fail "delete target group: HTTP ${c}" "$(body | head -c 300)"
else
  c="$(req GET "/api/v1/permissions/${RULE_ID[group]}" "$AT")"
  dn="$(body | jq -r 'if has("target_name") then (.target_name // "null") else "ABSENT" end' 2>/dev/null)"
  tid="$(body | jq -r '.target_id // empty' 2>/dev/null)"
  if [ "$c" = "200" ] && [ "$dn" = "null" ] && [ "$tid" = "$TGROUP_ID" ]; then pass
  else fail "deleted-group rule: HTTP ${c}, target_name='${dn}', target_id='${tid}'" "$(body | head -c 300)"; fi
fi

# =============================================================================
# #4690 — notice on an empty virtual listing for a virtual-only grant
# =============================================================================
c="$(mkrepo "$VMEMBER" local)"; setup_ok "create private hosted member" "$c"; VMEMBER_ID="$(body | jq -r '.id // empty')"
c="$(curl -s "${CURL_TIMEOUT_ARGS[@]}" -X PUT -o "$WORK/body" -w '%{http_code}' -H "Authorization: Bearer ${AT}" \
      --data-binary "rpp-virtual-member-bytes-${SUF}" "${BASE_URL}/api/v1/repositories/${VMEMBER}/artifacts/${VART_PATH}" 2>/dev/null || echo 000)"
setup_ok "upload an artifact into the member" "$c"
c="$(mkrepo "$VIRT" virtual)"; setup_ok "create private virtual" "$c"; VIRT_ID="$(body | jq -r '.id // empty')"
c="$(req POST "/api/v1/repositories/${VIRT}/members" "$AT" "$(jq -nc --arg k "$VMEMBER" '{member_key:$k}')")"
setup_ok "add the member to the virtual" "$c"
c="$(mkgroup "$VGROUP")"; setup_ok "create the virtual-reader group" "$c"; VGROUP_ID="$(body | jq -r '.id // empty')"
if ! add_group_members "$VGROUP_ID" "$RD_USER" >/dev/null; then
  begin_test "setup: add ${RD_USER} to ${VGROUP}"; infra_fail "add_group_members failed"; end_suite
fi
c="$(grant group "$VGROUP_ID" repository "$VIRT_ID" "read")"; setup_ok "grant ${VGROUP} read on the virtual only" "$c"

begin_test "#4690 control: an admin lists the member through the virtual, with no notice"
c="$(req GET "/api/v1/repositories/${VIRT}/members" "$AT")"
keys="$(body | jq -r '[.members[]?.member_repo_key // .members[]?.key // empty] | join(",")' 2>/dev/null)"
n="$(notice)"
if [ "$c" = "200" ] && [[ ",${keys}," == *",${VMEMBER},"* ]] && [ -z "$n" ]; then pass
else fail "admin /members: HTTP ${c}, members='${keys}', notice='${n}'" "$(body | head -c 300)"; fi

begin_test "#4690 fix: virtual-only reader: /members is 200, empty, and carries the notice header"
c="$(req GET "/api/v1/repositories/${VIRT}/members" "$RD_TOKEN")"
cnt="$(body | jq -r '(.members // []) | length' 2>/dev/null)"
n="$(notice)"
if [ "$c" = "200" ] && [ "$cnt" = "0" ] && [ "$n" = "$NOTICE_TEXT" ]; then pass
else fail "reader /members: HTTP ${c}, members=${cnt}, notice='${n}' (1.11.1: no notice header)" "$(body | head -c 300)"; fi

begin_test "#4690 fix: virtual-only reader: /artifacts is 200, empty, and carries the notice header"
c="$(req GET "/api/v1/repositories/${VIRT}/artifacts" "$RD_TOKEN")"
cnt="$(body | jq -r '(.items // []) | length' 2>/dev/null)"
n="$(notice)"
if [ "$c" = "200" ] && [ "$cnt" = "0" ] && [ "$n" = "$NOTICE_TEXT" ]; then pass
else fail "reader /artifacts: HTTP ${c}, items=${cnt}, notice='${n}' (1.11.1: no notice header)" "$(body | head -c 300)"; fi

begin_test "#4690 control: no grant widening, the reader still gets 404 on the member and on the content through the virtual"
c1="$(req GET "/api/v1/repositories/${VMEMBER}/artifacts" "$RD_TOKEN")"
c2="$(req GET "/api/v1/repositories/${VMEMBER}/download/${VART_PATH}" "$RD_TOKEN")"
leak2="$(body)"
c3="$(req GET "/api/v1/repositories/${VIRT}/download/${VART_PATH}" "$RD_TOKEN")"
leak3="$(body)"
if [ "$c1" = "404" ] && [ "$c2" = "404" ] && [ "$c3" = "404" ] \
   && [[ "$leak2" != *"rpp-virtual-member-bytes"* ]] && [[ "$leak3" != *"rpp-virtual-member-bytes"* ]]; then pass
else fail "member listing=${c1}, member download=${c2}, virtual download=${c3} (all must be 404 with no member bytes)"; fi

begin_test "#4690 control: a user with no grant is refused as before and gets no notice"
c1="$(req GET "/api/v1/repositories/${VIRT}/members" "$NG_TOKEN")"; n1="$(notice)"
c2="$(req GET "/api/v1/repositories/${VIRT}/artifacts" "$NG_TOKEN")"; n2="$(notice)"
if [ "$c1" = "404" ] && [ "$c2" = "404" ] && [ -z "$n1" ] && [ -z "$n2" ]; then pass
else fail "no-grant user: /members=${c1} notice='${n1}', /artifacts=${c2} notice='${n2}' (expected 404 and no notice)"; fi

begin_test "#4690 control: once the member is granted too, it is listed through the virtual and the notice is gone"
c="$(grant group "$VGROUP_ID" repository "$VMEMBER_ID" "read")"
if [ "${c:0:1}" != "2" ]; then
  infra_fail "grant ${VGROUP} read on the member: HTTP ${c}" "$(body | head -c 300)"
else
  # The permission cache is invalidated on a rule write; the TTL (30 s) is the
  # backstop, so poll briefly rather than assume the first read is fresh.
  ok=0
  for _ in $(seq 1 20); do
    c1="$(req GET "/api/v1/repositories/${VIRT}/members" "$RD_TOKEN")"; n1="$(notice)"
    keys="$(body | jq -r '[.members[]?.member_repo_key // .members[]?.key // empty] | join(",")' 2>/dev/null)"
    c2="$(req GET "/api/v1/repositories/${VIRT}/artifacts" "$RD_TOKEN")"; n2="$(notice)"
    paths="$(body | jq -r '[.items[]?.path] | join(",")' 2>/dev/null)"
    if [ "$c1" = "200" ] && [[ ",${keys}," == *",${VMEMBER},"* ]] && [ -z "$n1" ] \
       && [ "$c2" = "200" ] && [[ ",${paths}," == *",${VART_PATH},"* ]] && [ -z "$n2" ]; then ok=1; break; fi
    sleep 2
  done
  if [ "$ok" = 1 ]; then pass
  else fail "after the member grant: /members=${c1} members='${keys}' notice='${n1}'; /artifacts=${c2} paths='${paths}' notice='${n2}'"; fi
fi

end_suite
