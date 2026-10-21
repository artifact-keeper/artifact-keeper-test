#!/usr/bin/env bash
# =============================================================================
# tiers/project-admin-and-project-quota/oracle.sh
#   Project admins (artifact-keeper#2473) and the project storage quota
#   (#2474, npm publish #2475). See the manifest for the features and gates.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID,
# DTF_SLOT, RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"
: "${DTF_SLOT:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

SLOT="$DTF_SLOT"
SUF="${RUN_ID##*-}$$"                      # digits only: also used in project keys
PKEY="pp${SLOT}x${SUF}"                    # the project PA administers
QKEY="pq${SLOT}x${SUF}"                    # another project
QPKEY="pqa${SLOT}x${SUF}"                  # quota project (generic)
QNKEY="pqn${SLOT}x${SUF}"                  # quota project (npm)
R0="par0-${SLOT}-${SUF}"                   # repo in P, RA is its repository admin
RPA="parpa-${SLOT}-${SUF}"                 # created by PA in P
RQ="parq-${SLOT}-${SUF}"                   # attempted by PA in Q
RNONE="parnone-${SLOT}-${SUF}"             # attempted by PA without a project
QA="parqa-${SLOT}-${SUF}"; QB="parqb-${SLOT}-${SUF}"; QC="parqc-${SLOT}-${SUF}"
NG="parng-${SLOT}-${SUF}"                  # generic filler in the npm quota project
NP="parnp-${SLOT}-${SUF}"                  # npm hosted in the npm quota project
NF="parnf-${SLOT}-${SUF}"                  # npm hosted outside any project
NPM_PKG="par-pkg-${SUF}"

PW="Par_${SUF}_Aa1!"
PA_USER="par-pa-${SLOT}-${SUF}"            # project admin of P
U2_USER="par-u2-${SLOT}-${SUF}"            # no grant; member added/removed by PA
RA_USER="par-ra-${SLOT}-${SUF}"            # repository admin of R0 only

WORK="$(mktemp -d -t dtf-par-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

# req METHOD PATH TOKEN [JSON] -> HTTP code; body in $WORK/body.
req() {
  local method="$1" path="$2" tok="$3" data="${4:-}"
  local -a args=(-s "${CURL_TIMEOUT_ARGS[@]}" -X "$method" -o "$WORK/body" -w '%{http_code}')
  [ -n "$tok" ] && args+=(-H "Authorization: Bearer ${tok}")
  [ -n "$data" ] && args+=(-H 'Content-Type: application/json' --data "$data")
  : > "$WORK/body"
  curl "${args[@]}" "${BASE_URL}${path}" 2>/dev/null || echo 000
}
# put_file TOKEN PATH FILE [CONTENT_TYPE] -> HTTP code; body in $WORK/body.
put_file() {
  : > "$WORK/body"
  curl -s "${CURL_TIMEOUT_ARGS[@]}" -o "$WORK/body" -w '%{http_code}' -X PUT \
    -H "Authorization: Bearer $1" -H "Content-Type: ${4:-application/octet-stream}" \
    --data-binary "@$3" "${BASE_URL}$2" 2>/dev/null || echo 000
}
upload() { put_file "$1" "/api/v1/repositories/$2/artifacts/$3" "$4"; }
body() { cat "$WORK/body" 2>/dev/null || true; }
snip() { body | head -c 300 | tr '\n' ' ' || true; }
jr() { body | jq -r "$1" 2>/dev/null || true; }
is_2xx() { case "$1" in 2??) return 0 ;; *) return 1 ;; esac; }
is_denied() { case "$1" in 403|404) return 0 ;; *) return 1 ;; esac; }
db() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -Atc "$1" 2>/dev/null || echo "?"; }
rid() { db "SELECT id FROM repositories WHERE key = '$1'"; }
# random (incompressible) file of N bytes
rnd() { head -c "$2" /dev/urandom > "$1"; }

FAILS=0
DETAIL=""
gate(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

mkproj() { # KEY [QUOTA] -> id (empty on failure)
  local q="${2:-}"
  if [ -n "$q" ]; then
    req POST /api/v1/projects "$ADMIN_TOKEN" "$(jq -nc --arg k "$1" --argjson q "$q" '{key:$k,name:$k,quota_bytes:$q}')" >/dev/null
  else
    req POST /api/v1/projects "$ADMIN_TOKEN" "$(jq -nc --arg k "$1" '{key:$k,name:$k}')" >/dev/null
  fi
  jr '.id // empty'
}
# mkrepo TOKEN KEY FORMAT [PROJECT_ID] [QUOTA] -> HTTP code
mkrepo() {
  req POST /api/v1/repositories "$1" "$(jq -nc --arg k "$2" --arg f "$3" --arg p "${4:-}" --arg q "${5:-}" \
    '{key:$k,name:$k,format:$f,repo_type:"local",is_public:false}
     + (if $p == "" then {} else {project_id:$p} end)
     + (if $q == "" then {} else {quota_bytes:($q|tonumber)} end)')"
}
member() { # METHOD PROJECT_ID TOKEN USER_ID [ACTIONS_CSV] -> HTTP code
  req "$1" "/api/v1/projects/$2/members" "$3" "$(jq -nc --arg u "$4" --arg a "${5:-}" \
    '{principal_type:"user",principal_id:$u} + (if $a == "" then {} else {actions:($a|split(","))} end)')"
}
npm_payload() { # NAME OUT_JSON PAD_BYTES -> publish document with a tarball padded by random bytes
  mkdir -p "$WORK/npm/package"
  printf '{"name":"%s","version":"1.0.0"}\n' "$1" > "$WORK/npm/package/package.json"
  head -c "$3" /dev/urandom > "$WORK/npm/package/blob.bin"
  tar czf "$WORK/npm.tgz" -C "$WORK/npm" package
  base64 < "$WORK/npm.tgz" | tr -d '\n' > "$WORK/npm.b64"
  jq -n --arg name "$1" --arg tarball "http://x/$1/-/$1-1.0.0.tgz" --rawfile data "$WORK/npm.b64" \
    --argjson length "$(wc -c < "$WORK/npm.tgz" | tr -d ' ')" \
    '{name:$name,"dist-tags":{latest:"1.0.0"},versions:{"1.0.0":{name:$name,version:"1.0.0",dist:{tarball:$tarball}}},
      "_attachments":{("\($name)-1.0.0.tgz"):{content_type:"application/octet-stream",data:$data,length:$length}}}' > "$2"
}

# =============================================================================
begin_suite "project-admin-and-project-quota"

begin_test "setup: users, projects P/Q, the project admin grant, repository R0 in P with a repository admin"
auth_admin
SETUP_ERR=""
for u in "$PA_USER" "$U2_USER" "$RA_USER"; do
  create_test_user_with_retry "$u" "$PW" "${u}@t.test" >/dev/null || SETUP_ERR="${SETUP_ERR} user(${u})"
done
PA_ID="$(resolve_user_id_by_username "$PA_USER" || true)"
U2_ID="$(resolve_user_id_by_username "$U2_USER" || true)"
RA_ID="$(resolve_user_id_by_username "$RA_USER" || true)"
PA_T="$(login_as "$PA_USER" "$PW" || true)"; U2_T="$(login_as "$U2_USER" "$PW" || true)"; RA_T="$(login_as "$RA_USER" "$PW" || true)"
[ -n "$PA_T" ] && [ -n "$U2_T" ] && [ -n "$RA_T" ] && [ -n "$PA_ID" ] && [ -n "$U2_ID" ] && [ -n "$RA_ID" ] || SETUP_ERR="${SETUP_ERR} logins"
P_ID="$(mkproj "$PKEY")"; Q_ID="$(mkproj "$QKEY")"
[ -n "$P_ID" ] && [ -n "$Q_ID" ] || SETUP_ERR="${SETUP_ERR} projects"
is_2xx "$(member POST "$P_ID" "$ADMIN_TOKEN" "$PA_ID" admin,read,write,delete)" || SETUP_ERR="${SETUP_ERR} pa-grant($(snip))"
is_2xx "$(mkrepo "$ADMIN_TOKEN" "$R0" generic "$P_ID")" || SETUP_ERR="${SETUP_ERR} r0($(snip))"
R0_ID="$(rid "$R0")"
is_2xx "$(req POST /api/v1/permissions "$ADMIN_TOKEN" "$(jq -nc --arg u "$RA_ID" --arg r "$R0_ID" \
  '{principal_type:"user",principal_id:$u,target_type:"repository",target_id:$r,actions:["read","write","admin"]}')")" \
  || SETUP_ERR="${SETUP_ERR} ra-grant($(snip))"
if [ -n "$SETUP_ERR" ]; then infra_fail "setup failed:${SETUP_ERR}"; end_suite; fi
echo "-- P=${PKEY} (${P_ID}) Q=${QKEY} (${Q_ID}) PA=${PA_USER} RA=${RA_USER} R0=${R0}"
pass

# =============================================================================
# CONTROLS (every image)
# =============================================================================
begin_test "CONTROL: the global admin reads the project and lists its members (the project admin grant is there)"
reset_case
code="$(req GET "/api/v1/projects/${P_ID}" "$ADMIN_TOKEN")"
[ "$code" = "200" ] && [ "$(jr '.key')" = "$PKEY" ] || gate "admin GET project answered ${code}: $(snip)"
code="$(req GET "/api/v1/projects/${P_ID}/members" "$ADMIN_TOKEN")"
acts="$(body | jq -r --arg u "$PA_ID" '.items[] | select(.principal_id == $u) | .actions | sort | join(",")' 2>/dev/null || true)"
note "admin members list: ${code}; PA actions=${acts}"
[ "$code" = "200" ] && [ "$acts" = "admin,delete,read,write" ] || gate "members list answered ${code}, PA actions '${acts}'"
finish_case "the global admin cannot manage projects"

begin_test "CONTROL: a grant-less user is refused the project and its members"
reset_case
c1="$(req GET "/api/v1/projects/${P_ID}" "$U2_T")"; c2="$(req GET "/api/v1/projects/${P_ID}/members" "$U2_T")"
c3="$(req PUT "/api/v1/projects/${P_ID}" "$U2_T" '{"description":"u2"}')"
note "grant-less: GET ${c1}, members ${c2}, PUT ${c3}"
{ is_denied "$c1" && is_denied "$c2" && is_denied "$c3"; } || gate "a grant-less user reached the project (${c1}/${c2}/${c3})"
finish_case "a grant-less user can manage a project"

begin_test "CONTROL: the project admin stays refused the global-admin surface (project list/create, quota change, /permissions, project Q)"
reset_case
c1="$(req GET /api/v1/projects "$PA_T")"
c2="$(req POST /api/v1/projects "$PA_T" "$(jq -nc --arg k "ppx${SUF}" '{key:$k,name:$k}')")"
c3="$(req PUT "/api/v1/projects/${P_ID}" "$PA_T" '{"quota_bytes":999999999}')"
c4="$(req POST /api/v1/permissions "$PA_T" "$(jq -nc --arg u "$U2_ID" --arg r "$R0_ID" \
  '{principal_type:"user",principal_id:$u,target_type:"repository",target_id:$r,actions:["read"]}')")"
c5="$(req GET "/api/v1/projects/${Q_ID}" "$PA_T")"
c6="$(req POST "/api/v1/projects/${Q_ID}/members" "$PA_T" "$(jq -nc --arg u "$U2_ID" '{principal_type:"user",principal_id:$u,actions:["read"]}')")"
note "PA: list ${c1}, create ${c2}, quota ${c3}, /permissions ${c4}, GET Q ${c5}, add member to Q ${c6}"
for c in "$c1" "$c2" "$c3" "$c4" "$c5" "$c6"; do is_denied "$c" || gate "a project admin got ${c} on a global-admin-only call"; done
[ "$(db "SELECT coalesce(quota_bytes::text,'NULL') FROM projects WHERE id = '${P_ID}'")" = "NULL" ] || gate "the quota was changed"
[ "$(db "SELECT count(*) FROM projects WHERE key = 'ppx${SUF}'")" = "0" ] || gate "a project was created"
finish_case "a project admin escalated beyond its project"

begin_test "CONTROL: the project admin cannot create a repository in another project or in none"
reset_case
c1="$(mkrepo "$PA_T" "$RQ" generic "$Q_ID")"; c2="$(mkrepo "$PA_T" "$RNONE" generic)"
note "PA create in Q: ${c1}; without a project: ${c2}"
{ is_denied "$c1" && is_denied "$c2"; } || gate "project admin created outside its project (${c1}/${c2})"
[ "$(db "SELECT count(*) FROM repositories WHERE key IN ('${RQ}','${RNONE}')")" = "0" ] || gate "a repository row was written"
finish_case "a project admin creates repositories outside its project"

begin_test "CONTROL: a repository-restricted token of the project admin is refused the project"
reset_case
code="$(req POST /api/v1/auth/tokens "$PA_T" "$(jq -nc --arg n "par-rt-${SUF}" --arg r "$R0_ID" \
  '{name:$n,scopes:["read:artifacts","write:repositories"],repo_selector:{match_repos:[$r]}}')")"
RT="$(jr '.token // empty')"
note "restricted token mint: ${code}"
if [ -n "$RT" ]; then
  c1="$(req GET "/api/v1/projects/${P_ID}" "$RT")"; note "restricted token GET project: ${c1}"
  is_denied "$c1" || gate "a repository-restricted token was treated as project admin (${c1})"
else
  note "no restricted token minted (${code}: $(snip | head -c 120)); refusal of the anonymous call stands in"
  c1="$(req GET "/api/v1/projects/${P_ID}" "")"
  case "$c1" in 401|403|404) ;; *) gate "anonymous GET project answered ${c1}";; esac
fi
finish_case "a restricted credential acts as project admin"

begin_test "CONTROL: the global admin may use the project's OWN key prefix and an unprefixed key"
reset_case
c1="$(mkrepo "$ADMIN_TOKEN" "${PKEY}-ok" generic "$P_ID")"; c2="$(mkrepo "$ADMIN_TOKEN" "parflat-${SLOT}-${SUF}" generic "$P_ID")"
note "own prefix: ${c1}; unprefixed: ${c2}"
{ is_2xx "$c1" && is_2xx "$c2"; } || gate "own-prefix/unprefixed create answered ${c1}/${c2}: $(snip)"
finish_case "the key-prefix rule refuses legitimate keys"

begin_test "CONTROL: the repository admin of R0 can still PATCH its description"
reset_case
code="$(req PATCH "/api/v1/repositories/${R0}" "$RA_T" '{"description":"par-ra-desc"}')"
note "RA description PATCH: ${code}"
[ "$code" = "200" ] && [ "$(db "SELECT description FROM repositories WHERE key = '${R0}'")" = "par-ra-desc" ] || gate "RA description PATCH answered ${code}: $(snip)"
finish_case "the repository admin is not one"

# =============================================================================
# FIX #2473 (RED on 1.10.0)
# =============================================================================
begin_test "FIX #2473: the project admin reads and updates its project"
reset_case
c1="$(req GET "/api/v1/projects/${P_ID}" "$PA_T")"; k="$(jr '.key')"
c2="$(req PUT "/api/v1/projects/${P_ID}" "$PA_T" '{"description":"set-by-project-admin"}')"
d="$(db "SELECT description FROM projects WHERE id = '${P_ID}'")"
note "PA GET: ${c1} key=${k}; PUT: ${c2}; db description=${d}"
[ "$c1" = "200" ] && [ "$k" = "$PKEY" ] || gate "PA GET project answered ${c1}"
[ "$c2" = "200" ] && [ "$d" = "set-by-project-admin" ] || gate "PA PUT project answered ${c2}, description '${d}'"
finish_case "a project admin cannot read or update its own project"

begin_test "FIX #2473: the project admin lists, adds and removes members of its project"
reset_case
c1="$(req GET "/api/v1/projects/${P_ID}/members" "$PA_T")"; n="$(jr '.items | length')"
c2="$(member POST "$P_ID" "$PA_T" "$U2_ID" read)"
rows_after_add="$(db "SELECT count(*) FROM permissions WHERE target_type = 'project' AND target_id = '${P_ID}' AND principal_id = '${U2_ID}'")"
c3="$(member DELETE "$P_ID" "$PA_T" "$U2_ID")"
rows_after_rm="$(db "SELECT count(*) FROM permissions WHERE target_type = 'project' AND target_id = '${P_ID}' AND principal_id = '${U2_ID}'")"
note "PA list ${c1} (${n} items), add ${c2} (rows ${rows_after_add}), remove ${c3} (rows ${rows_after_rm})"
[ "$c1" = "200" ] && [ "${n:-0}" -ge 1 ] 2>/dev/null || gate "PA members list answered ${c1}"
is_2xx "$c2" && [ "$rows_after_add" = "1" ] || gate "PA add member answered ${c2}, rows ${rows_after_add}"
is_2xx "$c3" && [ "$rows_after_rm" = "0" ] || gate "PA remove member answered ${c3}, rows ${rows_after_rm}"
finish_case "a project admin cannot manage its project's membership"

begin_test "FIX #2473: the project admin creates a repository in its project; created_by is recorded, no owner role is granted, and it can write there"
reset_case
code="$(mkrepo "$PA_T" "$RPA" generic "$P_ID")"
note "PA create in P: ${code} $(snip | head -c 120)"
[ "$code" = "200" ] || [ "$code" = "201" ] || gate "PA create in its project answered ${code}"
row="$(db "SELECT coalesce(project_id::text,'NULL') || '|' || coalesce(created_by::text,'NULL') FROM repositories WHERE key = '${RPA}'")"
roles="$(db "SELECT count(*) FROM role_assignments ra JOIN repositories r ON r.id = ra.repository_id WHERE r.key = '${RPA}' AND ra.user_id = '${PA_ID}'")"
note "db project|created_by=${row}; role_assignments for PA on it=${roles}"
[ "$row" = "${P_ID}|${PA_ID}" ] || gate "row is '${row}', expected ${P_ID}|${PA_ID}"
[ "$roles" = "0" ] || gate "the project-admin creator was given ${roles} durable role assignment(s)"
printf 'par-%s' "$SUF" > "$WORK/small"
c="$(upload "$PA_T" "$RPA" a.txt "$WORK/small")"; note "PA upload into it (project inheritance): ${c}"
is_2xx "$c" || gate "PA cannot write its new repository (${c}: $(snip))"
finish_case "a project admin cannot provision repositories in its project"

begin_test "FIX #2473: removing the project admin from the project removes its access to the repository it created"
reset_case
c0="$(req GET "/api/v1/repositories/${RPA}/download/a.txt" "$PA_T")"
c1="$(member DELETE "$P_ID" "$ADMIN_TOKEN" "$PA_ID")"
c2="$(req GET "/api/v1/repositories/${RPA}/download/a.txt" "$PA_T")"
c3="$(req GET "/api/v1/projects/${P_ID}" "$PA_T")"
note "before removal GET ${c0}; removal ${c1}; after: download ${c2}, project ${c3}"
[ "$c0" = "200" ] || gate "the creator could not read before removal (${c0})"
is_2xx "$c1" || gate "admin removal answered ${c1}"
is_denied "$c2" || gate "the removed creator still reads the repository (${c2}); a durable owner role survived"
is_denied "$c3" || gate "the removed project admin still reads the project (${c3})"
# Restore for the later cases.
member POST "$P_ID" "$ADMIN_TOKEN" "$PA_ID" admin,read,write,delete >/dev/null
finish_case "access survives the creator's removal from the project"

begin_test "FIX #2473: a repository key using ANOTHER project's prefix is refused 400, even for the global admin"
reset_case
code="$(mkrepo "$ADMIN_TOKEN" "${QKEY}-squat" generic "$P_ID")"; msg="$(jr '.message // empty')"
note "admin create ${QKEY}-squat in P: ${code} ${msg}"
[ "$code" = "400" ] || gate "prefix squatting answered ${code}"
printf '%s' "$msg" | grep -q "$QKEY" || gate "the global admin's 400 does not name project ${QKEY}"
[ "$(db "SELECT count(*) FROM repositories WHERE key = '${QKEY}-squat'")" = "0" ] || gate "the squatting repository was created"
finish_case "a repository can squat on another project's key prefix"

begin_test "FIX #2473: a repository admin cannot move its repository into another project (403, unchanged)"
reset_case
code="$(req PATCH "/api/v1/repositories/${R0}" "$RA_T" "$(jq -nc --arg q "$Q_ID" '{project_id:$q}')")"
now_p="$(db "SELECT coalesce(project_id::text,'NULL') FROM repositories WHERE key = '${R0}'")"
note "RA PATCH project_id=Q: ${code} $(jr '.message // empty'); db project=${now_p}"
[ "$code" = "403" ] || gate "reassignment by a repository admin answered ${code}"
[ "$now_p" = "$P_ID" ] || gate "the repository moved to ${now_p}"
finish_case "a repository admin pushes a repository into a project it does not administer"

# =============================================================================
# FIX #2474 / #2475 (RED on 1.10.0)
# =============================================================================
begin_test "CONTROL: 5 KiB uploads into a repository outside any project succeed"
reset_case
rnd "$WORK/k5" 5120
c="$(mkrepo "$ADMIN_TOKEN" "$QC" generic "" 1048576)"; is_2xx "$c" || gate "create ${QC}: ${c}"
c1="$(upload "$ADMIN_TOKEN" "$QC" one.bin "$WORK/k5")"; c2="$(upload "$ADMIN_TOKEN" "$QC" two.bin "$WORK/k5")"
note "outside-project uploads: ${c1} ${c2}"
{ is_2xx "$c1" && is_2xx "$c2"; } || gate "uploads outside a project answered ${c1}/${c2}"
finish_case "plain uploads are broken"

begin_test "FIX #2474: the project quota (8192 B) is enforced across two member repositories: second 5 KiB upload 507"
reset_case
QP_ID="$(mkproj "$QPKEY" 8192)"
[ -n "$QP_ID" ] || gate "quota project create: $(snip)"
is_2xx "$(mkrepo "$ADMIN_TOKEN" "$QA" generic "$QP_ID" 1048576)" || gate "create ${QA}: $(snip)"
is_2xx "$(mkrepo "$ADMIN_TOKEN" "$QB" generic "$QP_ID" 1048576)" || gate "create ${QB}: $(snip)"
c1="$(upload "$ADMIN_TOKEN" "$QA" a.bin "$WORK/k5")"
c2="$(upload "$ADMIN_TOKEN" "$QB" b.bin "$WORK/k5")"; b2="$(snip)"
inb="$(db "SELECT count(*) FROM artifacts a JOIN repositories r ON r.id = a.repository_id WHERE r.key = '${QB}' AND NOT a.is_deleted")"
note "A: ${c1}; B: ${c2} ${b2}; live artifacts in B: ${inb}"
is_2xx "$c1" || gate "the first upload (under the cap) answered ${c1}"
[ "$c2" = "507" ] || gate "the second upload (over the project cap, under the repo cap) answered ${c2}"
printf '%s' "$b2" | grep -q "Project storage quota exceeded" || gate "the refusal is not 'Project storage quota exceeded'"
[ "$inb" = "0" ] || gate "${inb} artifact(s) stored in B"
finish_case "the project quota is not enforced across its repositories"

begin_test "CONTROL: an npm publish into an npm repository outside any project succeeds"
reset_case
is_2xx "$(mkrepo "$ADMIN_TOKEN" "$NF" npm)" || gate "create ${NF}: $(snip)"
npm_payload "${NPM_PKG}-free" "$WORK/free.json" 1500
c="$(put_file "$ADMIN_TOKEN" "/npm/${NF}/${NPM_PKG}-free" "$WORK/free.json" application/json)"
note "npm publish outside project: ${c} $(snip | head -c 120)"
is_2xx "$c" || gate "npm publish answered ${c}"
finish_case "npm publish is broken"

begin_test "FIX #2475: an npm publish over the project quota is refused 507 and nothing is stored"
reset_case
QN_ID="$(mkproj "$QNKEY" 4096)"
[ -n "$QN_ID" ] || gate "npm quota project create: $(snip)"
is_2xx "$(mkrepo "$ADMIN_TOKEN" "$NG" generic "$QN_ID")" || gate "create ${NG}: $(snip)"
is_2xx "$(mkrepo "$ADMIN_TOKEN" "$NP" npm "$QN_ID")" || gate "create ${NP}: $(snip)"
rnd "$WORK/k3" 3500
c0="$(upload "$ADMIN_TOKEN" "$NG" fill.bin "$WORK/k3")"; is_2xx "$c0" || gate "filler upload answered ${c0}"
npm_payload "$NPM_PKG" "$WORK/pub.json" 1500
c="$(put_file "$ADMIN_TOKEN" "/npm/${NP}/${NPM_PKG}" "$WORK/pub.json" application/json)"; b="$(snip)"
inp="$(db "SELECT count(*) FROM artifacts a JOIN repositories r ON r.id = a.repository_id WHERE r.key = '${NP}' AND NOT a.is_deleted")"
note "npm publish over the project cap: ${c} ${b}; artifacts in ${NP}: ${inp}"
[ "$c" = "507" ] || gate "npm publish over the project quota answered ${c}"
printf '%s' "$b" | grep -q "Project storage quota exceeded" || gate "the refusal is not 'Project storage quota exceeded'"
[ "$inp" = "0" ] || gate "${inp} artifact(s) stored"
finish_case "npm publish bypasses the storage quota"

end_suite
