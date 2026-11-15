#!/usr/bin/env bash
# shellcheck disable=SC2016  # jq programs use jq $variables, not shell ones
# =============================================================================
# tiers/api-contracts-1120-fixes/oracle.sh
#   REST API contract fixes of 1.12.0, each driven the way an API client or
#   the web UI hits it: migration list totals (#4800), Remote create with
#   upstream credentials (#4825, #4843), repository-owner role members on the
#   inline repo-admin gates (#4834), upstream auth on the repository list
#   (#4851), PATCH that refuses writes nothing (#5201), admin settings in force
#   (#5652), artifacts of a repository under delete by id (#5694), 5-field
#   cron weekdays (#5487), the audited cold HEAD probe (#5347) and releasing a
#   held proxied path straight after its 409 (#5223). See the manifest.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"; : "${DTF_SLOT:?}"; : "${RUN_ID:?}"; : "${DB_CONTAINER:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every probe here records its outcome instead.
set +e

BASE="$BASE_URL"
SFX="${DTF_SLOT}-${RUN_ID##*-}-$$"
setup_workdir
W="$WORK_DIR"
jqr(){ jq -r "$@" 2>/dev/null || true; }
psql_q(){ docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]'; }

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

# req <METHOD> <PATH> <TOKEN or -> [JSON body]: sets CODE and BODY.
req(){
  local m="$1" p="$2" t="$3" d="${4:-}"
  local -a ca=(-s -o "${W}/body" -w '%{http_code}' --max-time 60 -X "$m")
  [ "$t" != "-" ] && ca+=(-H "Authorization: Bearer ${t}")
  [ -n "$d" ] && ca+=(-H 'Content-Type: application/json' --data-binary "$d")
  : >"${W}/body"
  CODE="$(curl "${ca[@]}" "${BASE}${p}")"
  BODY="$(cat "${W}/body" 2>/dev/null || true)"
}
is_2xx(){ case "$1" in 2??) return 0;; *) return 1;; esac; }
# put_file <TOKEN> <repo> <path> <file>: generic upload, sets CODE and BODY.
put_file(){
  : >"${W}/body"
  CODE="$(curl -s -o "${W}/body" -w '%{http_code}' --max-time 120 -X PUT -H "Authorization: Bearer $1" \
    -H 'Content-Type: application/octet-stream' --data-binary "@$4" "${BASE}/api/v1/repositories/$2/artifacts/$3")"
  BODY="$(cat "${W}/body" 2>/dev/null || true)"
}
login(){ curl -s --max-time 15 -X POST "${BASE}/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg u "$1" --arg p "$2" '{username:$u,password:$p}')" | jqr '.access_token // empty'; }
mk_repo(){ # key format type [extra json] -> CODE/BODY
  local x="${4:-}"; [ -n "$x" ] || x='{}'
  req POST /api/v1/repositories "$TOK" "$(jq -nc --arg k "$1" --arg f "$2" --arg t "$3" --argjson x "$x" \
    '{key:$k,name:$k,format:$f,repo_type:$t,is_public:false} + $x')"
}
# The backend reaches itself on its container address (the SSRF guard
# refuses 127.0.0.1; the manifest sets UPSTREAM_ALLOW_PRIVATE_IPS=true).
BACKEND_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' "ak-dtf${DTF_SLOT}-backend" 2>/dev/null | awk '{print $1}')"
SELF="http://${BACKEND_IP}:8080"

begin_suite "api-contracts-1120-fixes"

# =============================================================================
begin_test "setup: admin session and the backend's own address for AK-to-AK Remotes"
TOK="$(login admin "$ADMIN_PASS")"
[ -n "$TOK" ] || { infra_fail "no admin session"; end_suite; }
[ -n "$BACKEND_IP" ] || { infra_fail "could not read the backend container address"; end_suite; }
echo "-- self upstream ${SELF}"
pass

# =============================================================================
# #4800 migration list total follows the status filter
# =============================================================================
begin_test "CONTROL: three migration jobs are listed, one of them cancelled"
reset_case
req POST /api/v1/migrations/connections "$TOK" "$(jq -nc --arg n "ac12f-conn-${SFX}" \
  '{name:$n,url:"https://artifactory.example.com/artifactory",auth_type:"api_token",credentials:{token:"not-a-real-token"}}')"
CONN_ID="$(jqr '.id // empty' <<<"$BODY")"
note "connection: ${CODE} ${CONN_ID}"
is_2xx "$CODE" && [ -n "$CONN_ID" ] || fail_g "creating a migration connection answered ${CODE}: ${BODY:0:200}"
JOBS=()
for _ in 1 2 3; do
  req POST /api/v1/migrations "$TOK" "$(jq -nc --arg c "$CONN_ID" '{source_connection_id:$c,config:{}}')"
  j="$(jqr '.id // empty' <<<"$BODY")"; [ -n "$j" ] && JOBS+=("$j")
done
note "jobs created: ${#JOBS[@]}"
[ "${#JOBS[@]}" = "3" ] || fail_g "created ${#JOBS[@]} of 3 migration jobs: ${BODY:0:200}"
req POST "/api/v1/migrations/${JOBS[0]:-none}/cancel" "$TOK"
note "cancel: ${CODE} status=$(jqr .status <<<"$BODY")"
[ "$(jqr .status <<<"$BODY")" = "cancelled" ] || fail_g "cancel answered ${CODE}: ${BODY:0:200}"
req GET "/api/v1/migrations?per_page=100" "$TOK"
ALL_JOBS="$BODY"
N_ALL="$(jqr '.items | length' <<<"$ALL_JOBS")"
N_CANC="$(jqr '[.items[] | select(.status == "cancelled")] | length' <<<"$ALL_JOBS")"
N_PEND="$(jqr '[.items[] | select(.status == "pending")] | length' <<<"$ALL_JOBS")"
note "unfiltered: ${CODE} total=$(jqr .pagination.total <<<"$ALL_JOBS") rows=${N_ALL} cancelled=${N_CANC} pending=${N_PEND}"
[ "$(jqr .pagination.total <<<"$ALL_JOBS")" = "$N_ALL" ] && [ "${N_ALL:-0}" -ge 3 ] || fail_g "the unfiltered list's total does not match its rows"
[ "${N_CANC:-0}" -ge 1 ] && [ "${N_PEND:-0}" -ge 2 ] || fail_g "the list does not show the cancelled and the pending jobs"
req GET "/api/v1/migrations?status=cancelled&per_page=100" "$TOK"
note "status=cancelled rows: $(jqr -c '[.items[].status] | unique' <<<"$BODY") x$(jqr '.items | length' <<<"$BODY")"
[ "$(jqr -c '[.items[].status] | unique' <<<"$BODY")" = '["cancelled"]' ] && [ "$(jqr '.items | length' <<<"$BODY")" = "$N_CANC" ] \
  || fail_g "the status filter does not narrow the rows to the cancelled jobs"
finish_case "migration job listing broken"

begin_test "FIX #4800: GET /migrations?status= reports a pagination.total that counts only the filtered rows"
reset_case
req GET "/api/v1/migrations?status=cancelled" "$TOK"
note "status=cancelled: rows=$(jqr '.items | length' <<<"$BODY") total=$(jqr .pagination.total <<<"$BODY") (cancelled jobs: ${N_CANC}, all jobs: ${N_ALL})"
[ "$(jqr .pagination.total <<<"$BODY")" = "$N_CANC" ] || fail_g "status=cancelled matches ${N_CANC} jobs but pagination.total is $(jqr .pagination.total <<<"$BODY")"
req GET "/api/v1/migrations?status=pending&per_page=1" "$TOK"
note "status=pending per_page=1: rows=$(jqr '.items | length' <<<"$BODY") total=$(jqr .pagination.total <<<"$BODY") total_pages=$(jqr .pagination.total_pages <<<"$BODY") (pending jobs: ${N_PEND})"
[ "$(jqr .pagination.total <<<"$BODY")" = "$N_PEND" ] && [ "$(jqr .pagination.total_pages <<<"$BODY")" = "$N_PEND" ] \
  || fail_g "status=pending per_page=1 reports total $(jqr .pagination.total <<<"$BODY") / $(jqr .pagination.total_pages <<<"$BODY") pages, expected ${N_PEND} / ${N_PEND}"
finish_case "the filtered migration list's total counts every job"

# =============================================================================
# #4825 / #4843 Remote create with upstream credentials; #4851 list reports auth
# =============================================================================
UP_URL="https://upstream-${SFX}.example.com/generic/"
begin_test "CONTROL: a Remote created with upstream_auth_type basic stores its credentials and the detail reports them"
reset_case
R_OK="ac12f-auth-ok-${SFX}"
mk_repo "$R_OK" generic remote "$(jq -nc --arg u "$UP_URL" '{upstream_url:$u,upstream_auth_type:"basic",upstream_username:"ci-reader",upstream_password:"not-a-real-secret-1"}')"
note "create: ${CODE} upstream_auth_type=$(jqr .upstream_auth_type <<<"$BODY")"
is_2xx "$CODE" || fail_g "creating a basic-auth Remote answered ${CODE}: ${BODY:0:200}"
req GET "/api/v1/repositories/${R_OK}" "$TOK"
note "detail: ${CODE} $(jqr -c '{upstream_auth_type,upstream_auth_configured}' <<<"$BODY")"
[ "$(jqr -c '[.upstream_auth_type,.upstream_auth_configured]' <<<"$BODY")" = '["basic",true]' ] || fail_g "the detail does not report basic auth configured"
finish_case "a basic-auth Remote does not store its credentials"

begin_test "FIX #4825: a Remote create with upstream_username/upstream_password but no upstream_auth_type is refused with 400 and creates nothing"
reset_case
R_NOTYPE="ac12f-auth-notype-${SFX}"
mk_repo "$R_NOTYPE" generic remote "$(jq -nc --arg u "$UP_URL" '{upstream_url:$u,upstream_username:"ci-reader",upstream_password:"not-a-real-secret-2"}')"
note "create: ${CODE} ${BODY:0:200}"
[ "$CODE" = "400" ] || fail_g "the create answered ${CODE} (upstream_auth_configured=$(jqr .upstream_auth_configured <<<"$BODY")), expected 400; the credentials were silently dropped"
req GET "/api/v1/repositories/${R_NOTYPE}" "$TOK"
note "detail after: ${CODE} $(jqr -c '{upstream_auth_type,upstream_auth_configured}' <<<"$BODY")"
[ "$CODE" = "404" ] || fail_g "the repository exists after the create (GET ${CODE})"
finish_case "upstream credentials without upstream_auth_type are silently discarded"

begin_test "FIX #4843: an invalid credential shape on create (basic without password, unknown type) leaves no repository, so a corrected retry succeeds"
reset_case
for shape in nopw badtype; do
  R_BAD="ac12f-auth-${shape}-${SFX}"
  if [ "$shape" = "nopw" ]; then x="$(jq -nc --arg u "$UP_URL" '{upstream_url:$u,upstream_auth_type:"basic",upstream_username:"ci-reader"}')"
  else x="$(jq -nc --arg u "$UP_URL" '{upstream_url:$u,upstream_auth_type:"kerberos",upstream_username:"ci-reader",upstream_password:"not-a-real-secret-3"}')"; fi
  mk_repo "$R_BAD" generic remote "$x"
  note "${shape} create: ${CODE} ${BODY:0:140}"
  [ "$CODE" = "400" ] || fail_g "${shape}: the refused create answered ${CODE}, expected 400"
  req GET "/api/v1/repositories/${R_BAD}" "$TOK"
  note "${shape} detail after: ${CODE}"
  [ "$CODE" = "404" ] || fail_g "${shape}: a refused create left the repository behind (GET ${CODE})"
  mk_repo "$R_BAD" generic remote "$(jq -nc --arg u "$UP_URL" '{upstream_url:$u,upstream_auth_type:"basic",upstream_username:"ci-reader",upstream_password:"not-a-real-secret-4"}')"
  note "${shape} corrected retry: ${CODE} ${BODY:0:100}"
  is_2xx "$CODE" || fail_g "${shape}: the corrected retry answered ${CODE}, expected 201"
done
finish_case "a refused Remote create leaves a half-configured repository behind"

begin_test "FIX #4851: GET /repositories lists a basic-auth Remote with upstream_auth_type basic and upstream_auth_configured true, like the detail"
reset_case
req GET "/api/v1/repositories?per_page=1000" "$TOK"
row="$(jqr -c --arg k "$R_OK" '[.items[] | select(.key == $k) | {upstream_auth_type,upstream_auth_configured}][0]' <<<"$BODY")"
note "list: ${CODE} ${R_OK} -> ${row}"
[ "$row" = '{"upstream_auth_type":"basic","upstream_auth_configured":true}' ] || fail_g "the list row reports ${row}, the detail reports basic/true"
req PATCH "/api/v1/repositories/${R_OK}" "$TOK" '{"description":"patched by api-contracts-1120-fixes"}'
note "PATCH response: ${CODE} $(jqr -c '{upstream_auth_type,upstream_auth_configured}' <<<"$BODY")"
[ "$(jqr -c '[.upstream_auth_type,.upstream_auth_configured]' <<<"$BODY")" = '["basic",true]' ] || fail_g "the PATCH response does not report the stored upstream auth"
finish_case "the repository list hides a Remote's upstream authentication"

# =============================================================================
# #4834 repository-owner role member on the inline repo-admin gates
# =============================================================================
begin_test "setup: a private generic repository and a Remote, a user holding the repository-owner role on both, and a plain user"
reset_case
R_OWN="ac12f-own-${SFX}"; R_OWNR="ac12f-ownr-${SFX}"
mk_repo "$R_OWN" generic local; c1="$CODE"
mk_repo "$R_OWNR" generic remote "$(jq -nc --arg u "$UP_URL" '{upstream_url:$u}')"; c2="$CODE"
O_NAME="ac12f-o-${SFX}"; O_PASS="Ac12fOwner_${SFX}_Aa1!"
P_NAME="ac12f-p-${SFX}"; P_PASS="Ac12fPlain_${SFX}_Aa1!"
req POST /api/v1/users "$TOK" "$(jq -nc --arg u "$O_NAME" --arg p "$O_PASS" '{username:$u,password:$p,email:($u+"@dtf.invalid")}')"; c3="$CODE"
req POST /api/v1/users "$TOK" "$(jq -nc --arg u "$P_NAME" --arg p "$P_PASS" '{username:$u,password:$p,email:($u+"@dtf.invalid")}')"; c4="$CODE"
# No REST route grants a role on one repository (POST /users/{id}/roles is
# global); the creator auto-grant and the web UI's membership write this row.
docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "
  INSERT INTO role_assignments (user_id, role_id, repository_id)
  SELECT u.id, r.id, repo.id FROM users u, roles r, repositories repo
  WHERE u.username='${O_NAME}' AND r.name='repository-owner' AND repo.key IN ('${R_OWN}','${R_OWNR}')
  ON CONFLICT DO NOTHING;" >/dev/null 2>&1
n_role="$(psql_q "SELECT count(*) FROM role_assignments ra JOIN users u ON u.id=ra.user_id WHERE u.username='${O_NAME}' AND ra.repository_id IS NOT NULL")"
n_perm="$(psql_q "SELECT count(*) FROM permissions p JOIN users u ON u.id=p.principal_id WHERE u.username='${O_NAME}'")"
OTOK="$(login "$O_NAME" "$O_PASS")"; PTOK="$(login "$P_NAME" "$P_PASS")"
echo "-- repos ${c1}/${c2} users ${c3}/${c4} role rows ${n_role} permission rows ${n_perm} logins ${OTOK:+o}${PTOK:+p}"
if ! is_2xx "$c1" || ! is_2xx "$c2" || [ "$n_role" != "2" ] || [ -z "$OTOK" ] || [ -z "$PTOK" ]; then
  infra_fail "could not set up the repository-owner member"; end_suite
fi
pass

begin_test "CONTROL: the repository-owner member reads its repository; a plain user cannot change or delete it"
reset_case
req GET "/api/v1/repositories/${R_OWN}" "$OTOK"
note "owner GET: ${CODE}"
[ "$CODE" = "200" ] || fail_g "the repository-owner member cannot read its repository (${CODE})"
req PATCH "/api/v1/repositories/${R_OWN}" "$PTOK" '{"description":"plain user edit"}'
note "plain PATCH: ${CODE}"
case "$CODE" in 403|404) ;; *) fail_g "a plain user's PATCH answered ${CODE}, expected 403/404";; esac
req DELETE "/api/v1/repositories/${R_OWN}" "$PTOK"
note "plain DELETE: ${CODE}"
case "$CODE" in 403|404) ;; *) fail_g "a plain user's DELETE answered ${CODE}, expected 403/404";; esac
finish_case "repository-owner read or plain-user refusal broken"

begin_test "FIX #4834: a repository-owner role member passes the repo-admin gates: PATCH, cache-ttl and DELETE its own repository"
reset_case
req PATCH "/api/v1/repositories/${R_OWN}" "$OTOK" '{"description":"owner edit"}'
note "owner PATCH: ${CODE} ${BODY:0:120}"
[ "$CODE" = "200" ] || fail_g "the repository-owner member's PATCH answered ${CODE}, expected 200"
req PUT "/api/v1/repositories/${R_OWNR}/cache-ttl" "$OTOK" '{"cache_ttl_seconds":600}'
note "owner PUT cache-ttl: ${CODE} ${BODY:0:120}"
is_2xx "$CODE" || fail_g "the repository-owner member's cache-ttl PUT answered ${CODE}, expected 2xx"
req DELETE "/api/v1/repositories/${R_OWN}" "$OTOK"
note "owner DELETE: ${CODE} ${BODY:0:120}"
is_2xx "$CODE" || fail_g "the repository-owner member's DELETE answered ${CODE}, expected 2xx"
finish_case "a repository-owner role member is refused its own repository's admin operations"

# =============================================================================
# #5201 PATCH that is refused writes nothing
# =============================================================================
begin_test "FIX #5201: PATCH {visibility: internal, apt_label} on a private generic repository is 400 and leaves visibility private"
reset_case
R_P="ac12f-patch-${SFX}"
mk_repo "$R_P" generic local
is_2xx "$CODE" || fail_g "create ${R_P} answered ${CODE}"
req GET "/api/v1/repositories/${R_P}" "$TOK"; v0="$(jqr .visibility <<<"$BODY")"
req PATCH "/api/v1/repositories/${R_P}" "$TOK" '{"visibility":"internal","apt_label":"X"}'
note "PATCH: ${CODE} ${BODY:0:160}"
[ "$CODE" = "400" ] || fail_g "the PATCH answered ${CODE}, expected 400"
req GET "/api/v1/repositories/${R_P}" "$TOK"
note "visibility before=${v0} after=$(jqr .visibility <<<"$BODY")"
[ "$(jqr .visibility <<<"$BODY")" = "$v0" ] || fail_g "the refused PATCH changed visibility from ${v0} to $(jqr .visibility <<<"$BODY")"
finish_case "a refused PATCH saves part of the change"

begin_test "CONTROL: a valid PATCH of visibility to internal is applied"
reset_case
req PATCH "/api/v1/repositories/${R_P}" "$TOK" '{"visibility":"internal"}'
note "PATCH: ${CODE}"
req GET "/api/v1/repositories/${R_P}" "$TOK"
[ "$(jqr .visibility <<<"$BODY")" = "internal" ] || fail_g "a valid PATCH left visibility $(jqr .visibility <<<"$BODY")"
finish_case "a valid visibility PATCH is not applied"

# =============================================================================
# #5652 admin settings report and change only what is in force
# =============================================================================
begin_test "CONTROL: POST /admin/settings with an in-range retention_days stores it and GET reads it back"
reset_case
count_setting_rows(){ req GET "/api/v1/admin/audit?per_page=200" "$TOK"
  jqr '[.items[] | select(.action == "SETTING_CHANGED" and .details.key == "retention_days")] | length' <<<"$BODY"; }
AUD0="$(count_setting_rows)"
req GET /api/v1/admin/settings "$TOK"; S0="$BODY"
note "GET: ${CODE} $(jqr -c . <<<"$S0")"
RD0="$(jqr .retention_days <<<"$S0")"; RD1=$(( ${RD0:-365} == 45 ? 46 : 45 ))
req POST /api/v1/admin/settings "$TOK" "$(jq -c --argjson d "$RD1" '.retention_days = $d' <<<"$S0")"
note "POST retention_days=${RD1} (full body as GET returned it): ${CODE} ${BODY:0:160}"
is_2xx "$CODE" || fail_g "posting the GET body back with retention_days=${RD1} answered ${CODE}"
req GET /api/v1/admin/settings "$TOK"
[ "$(jqr .retention_days <<<"$BODY")" = "$RD1" ] || fail_g "retention_days reads $(jqr .retention_days <<<"$BODY"), expected ${RD1}"
finish_case "admin settings round trip broken"

begin_test "FIX #5652: GET /admin/settings reports the upload limit in force (MAX_UPLOAD_SIZE default 10 GiB), not a stored 100 MB"
reset_case
req GET /api/v1/admin/settings "$TOK"
note "max_upload_size_bytes=$(jqr .max_upload_size_bytes <<<"$BODY")"
[ "$(jqr .max_upload_size_bytes <<<"$BODY")" = "10737418240" ] || fail_g "max_upload_size_bytes reads $(jqr .max_upload_size_bytes <<<"$BODY"), the enforced limit is 10737418240"
finish_case "admin settings report an upload limit that is not enforced"

begin_test "FIX #5652: a negative retention_days is refused with 400 and not stored; each accepted change writes one SETTING_CHANGED audit row"
reset_case
req GET /api/v1/admin/settings "$TOK"; S1="$BODY"; RD_NOW="$(jqr .retention_days <<<"$S1")"
req POST /api/v1/admin/settings "$TOK" "$(jq -c '.retention_days = -5' <<<"$S1")"
note "POST retention_days=-5: ${CODE} ${BODY:0:160}"
[ "$CODE" = "400" ] || fail_g "retention_days=-5 answered ${CODE}, expected 400"
req GET /api/v1/admin/settings "$TOK"
note "retention_days after: $(jqr .retention_days <<<"$BODY") (was ${RD_NOW})"
[ "$(jqr .retention_days <<<"$BODY")" = "$RD_NOW" ] || fail_g "the refused value was stored: retention_days $(jqr .retention_days <<<"$BODY")"
n_aud=$(( $(count_setting_rows) - ${AUD0:-0} ))
note "new SETTING_CHANGED rows for retention_days: ${n_aud} (one accepted change in the CONTROL, one refused here)"
[ "$n_aud" = "1" ] || fail_g "the accepted retention_days change wrote ${n_aud} SETTING_CHANGED rows, expected 1"
finish_case "admin settings accept negative values or are not audited"

# =============================================================================
# #5487 5-field cron weekdays
# =============================================================================
R_CRON_ID=""
begin_test "CONTROL: a lifecycle policy with cron '30 3 * * MON' is accepted and an unreadable weekday '8' is refused"
reset_case
mk_repo "ac12f-cron-${SFX}" generic local; R_CRON_ID="$(jqr '.id // empty' <<<"$BODY")"
mk_cron(){ req POST /api/v1/admin/lifecycle "$TOK" "$(jq -nc --arg n "ac12f-cron-$2-${SFX}" --arg c "$1" --arg r "$R_CRON_ID" \
  '{name:$n,policy_type:"tag_pattern_delete",config:{pattern:".*"},repository_ids:[$r],enabled:false,cron_schedule:$c}')"; }
mk_cron "30 3 * * MON" mon
note "MON: ${CODE} cron_schedule=$(jqr .cron_schedule <<<"$BODY")"
is_2xx "$CODE" || fail_g "'30 3 * * MON' answered ${CODE}: ${BODY:0:160}"
mk_cron "30 3 * * 8" eight
note "8: ${CODE}"
[ "$CODE" = "400" ] || fail_g "'30 3 * * 8' answered ${CODE}, expected 400"
finish_case "lifecycle cron validation broken"

begin_test "FIX #5487: standard cron weekday 0 (Sunday) is accepted: a lifecycle policy with '30 3 * * 0' is created"
reset_case
mk_cron "30 3 * * 0" sun
note "'30 3 * * 0': ${CODE} ${BODY:0:160}"
is_2xx "$CODE" || fail_g "'30 3 * * 0' answered ${CODE}, expected 201 (0 is Sunday in standard cron)"
mk_cron "0 3 * * 0-6" week
note "'0 3 * * 0-6': ${CODE} ${BODY:0:120}"
is_2xx "$CODE" || fail_g "'0 3 * * 0-6' answered ${CODE}, expected 201"
finish_case "standard 5-field cron weekday 0 is refused"

# =============================================================================
# #5694 artifacts of a repository under delete are gone by id
# =============================================================================
begin_test "FIX #5694: right after DELETE /repositories/{key} answers 202, its artifacts answer 404 on /artifacts/{id} and /stats"
reset_case
R_DEL="ac12f-del-${SFX}"; R_LIVE="ac12f-live-${SFX}"
mk_repo "$R_DEL" generic local; c1="$CODE"
mk_repo "$R_LIVE" generic local; c2="$CODE"
# Enough artifacts that the delete job is still running when we look.
DEL_IDS=()
for i in $(seq 1 150); do
  printf 'del %s %s\n' "$i" "$SFX" > "${W}/d.txt"
  put_file "$TOK" "$R_DEL" "d/f${i}.txt" "${W}/d.txt"
  [ "$i" -le 3 ] && DEL_IDS+=("$(jqr '.id // empty' <<<"$BODY")")
done
printf 'live %s\n' "$SFX" > "${W}/l.txt"; put_file "$TOK" "$R_LIVE" "l/live.txt" "${W}/l.txt"; LIVE_ID="$(jqr '.id // empty' <<<"$BODY")"
note "repos ${c1}/${c2}; probe ids ${DEL_IDS[*]}; live ${LIVE_ID}"
req GET "/api/v1/artifacts/${DEL_IDS[0]}" "$TOK"; pre="$CODE"
req DELETE "/api/v1/repositories/${R_DEL}" "$TOK"; dcode="$CODE"; STATUS_URL="$(jqr '.status_url // empty' <<<"$BODY")"
codes=""
for id in "${DEL_IDS[@]}"; do
  for sub in "" /stats; do
    c="$(curl -s -o /dev/null -w '%{http_code}' --max-time 30 -H "Authorization: Bearer ${TOK}" "${BASE}/api/v1/artifacts/${id}${sub}")"
    codes="${codes}${sub:-/}=${c} "
  done
done
note "before delete: ${pre}; DELETE: ${dcode} (${STATUS_URL:-no status_url}); right after: ${codes}"
[ "$pre" = "200" ] || fail_g "the artifact did not resolve before the delete (${pre})"
case "$dcode" in 200|202|204) ;; *) fail_g "DELETE answered ${dcode}";; esac
echo "$codes" | grep -qE '=(200|2[0-9][0-9]) ' && fail_g "artifacts of the repository under delete still resolve by id: ${codes}"
finish_case "a deleted repository's artifacts still resolve by id"

begin_test "CONTROL: an artifact in a live repository still answers 200 on /artifacts/{id} and /stats"
reset_case
for sub in "" /stats; do
  c="$(curl -s -o /dev/null -w '%{http_code}' --max-time 30 -H "Authorization: Bearer ${TOK}" "${BASE}/api/v1/artifacts/${LIVE_ID}${sub}")"
  note "live ${sub:-/}: ${c}"
  [ "$c" = "200" ] || fail_g "the live artifact answered ${c} on ${sub:-/}"
done
finish_case "a live repository's artifact does not resolve by id"

# =============================================================================
# #5347 audited cold HEAD; #5223 release a held path right after its 409
# =============================================================================
R_UP="ac12f-up-${SFX}"
begin_test "setup: a public generic repository the Remotes below proxy (AK to AK)"
mk_repo "$R_UP" generic local '{"is_public":true}'
c1="$CODE"
printf 'cold head %s\n' "$SFX" > "${W}/h.txt"; put_file "$TOK" "$R_UP" "src/contrib/ac12fcold_1.0.0.tar.gz" "${W}/h.txt"; c2="$CODE"
put_file "$TOK" "$R_UP" "src/contrib/ac12fwarm_1.0.0.tar.gz" "${W}/h.txt"; c3="$CODE"
head -c 50000000 /dev/urandom > "${W}/big.bin"
c4=""
for i in 1 2 3; do put_file "$TOK" "$R_UP" "q/held${i}.bin" "${W}/big.bin"; c4="${c4}${CODE} "; done
if ! is_2xx "$c1" || ! is_2xx "$c2" || ! is_2xx "$c3"; then infra_fail "upstream setup answered ${c1}/${c2}/${c3}/${c4}"; end_suite; fi
echo "-- ${R_UP}: ${c1} uploads ${c2} ${c3} ${c4}"
pass

# The cold-HEAD probe of #5331 serves the formats whose Remote download goes
# through try_remote_or_virtual_download (CRAN here); the upstream is the
# generic repository above, which serves src/contrib/<file> like a CRAN mirror.
begin_test "CONTROL: a CRAN Remote over the upstream serves a cold GET of a source package with the upstream bytes"
reset_case
R_H="ac12f-head-${SFX}"
mk_repo "$R_H" cran remote "$(jq -nc --arg u "${SELF}/api/v1/repositories/${R_UP}/download/" '{upstream_url:$u}')"
R_H_ID="$(jqr '.id // empty' <<<"$BODY")"
note "remote: ${CODE} ${R_H_ID}"
c="$(curl -s -o "${W}/g" -w '%{http_code}' --max-time 30 -H "Authorization: Bearer ${TOK}" "${BASE}/cran/${R_H}/src/contrib/ac12fwarm_1.0.0.tar.gz")"
note "cold GET: ${c} body=$(head -c 40 "${W}/g")"
[ "$c" = "200" ] && cmp -s "${W}/g" "${W}/h.txt" || fail_g "the cold GET answered ${c} or other bytes"
finish_case "a CRAN Remote does not proxy"

upstream_rows(){ # path -> methods of UPSTREAM_FETCHED rows for R_H and that path
  req GET "/api/v1/admin/audit?action=UPSTREAM_FETCHED&per_page=200" "$TOK"
  jqr -c --arg r "$R_H_ID" --arg p "$1" '[.items[] | select(.action == "UPSTREAM_FETCHED" and .resource_id == $r and ((.details.path // "") | endswith($p))) | .details.method]' <<<"$BODY"
}
begin_test "FIX #5347: a cold HEAD through the CRAN Remote records exactly one UPSTREAM_FETCHED row, method HEAD"
reset_case
: >"${W}/hh"
c="$(curl -s -I -o "${W}/hh" -w '%{http_code}' --max-time 30 -H "Authorization: Bearer ${TOK}" "${BASE}/cran/${R_H}/src/contrib/ac12fcold_1.0.0.tar.gz")"
note "cold HEAD: ${c} content-length=$(grep -i '^content-length:' "${W}/hh" | tr -d '\r' | awk '{print $2}')"
[ "$c" = "200" ] || fail_g "the cold HEAD answered ${c}"
# With AUDIT_UPSTREAM_FETCHES=all (#5286) the cold GET above is one row,
# method GET; the cold HEAD's probe must be one more, method HEAD.
note "UPSTREAM_FETCHED methods for the cold GET of ac12fwarm: $(upstream_rows /ac12fwarm_1.0.0.tar.gz)"
m="[]"
for _ in $(seq 1 20); do m="$(upstream_rows /ac12fcold_1.0.0.tar.gz)"; [ "$m" != "[]" ] && [ -n "$m" ] && break; sleep 0.5; done
sleep 1; m="$(upstream_rows /ac12fcold_1.0.0.tar.gz)"
note "UPSTREAM_FETCHED methods for ac12fcold: ${m}"
[ "$m" = '["HEAD"]' ] || fail_g "the cold HEAD's upstream contact is audited as ${m}, expected exactly [\"HEAD\"]"
finish_case "the cold-HEAD upstream probe is missing from UPSTREAM_FETCHED"

begin_test "CONTROL: a Remote with a 60-minute age hold answers a cold download with 409"
reset_case
R_Q="ac12f-hold-${SFX}"
mk_repo "$R_Q" generic remote "$(jq -nc --arg u "${SELF}/api/v1/repositories/${R_UP}/download/" '{upstream_url:$u}')"
c1="$CODE"
req PATCH "/api/v1/repositories/${R_Q}" "$TOK" '{"quarantine_enabled":true,"quarantine_duration_minutes":60}'
note "remote ${c1}, hold PATCH ${CODE}"
is_2xx "$CODE" || fail_g "enabling the hold answered ${CODE}: ${BODY:0:160}"
c="$(curl -s -o /dev/null -w '%{http_code}' --max-time 60 -H "Authorization: Bearer ${TOK}" "${BASE}/api/v1/repositories/${R_Q}/download/q/held1.bin")"
note "cold GET held1: ${c}"
[ "$c" = "409" ] || fail_g "the cold download of a held path answered ${c}, expected 409"
HELD1_409="$c"
finish_case "the age hold does not refuse a cold download"

begin_test "FIX #5223: POST /quarantine/proxy-cache/{repo}/release straight after the 409 releases the path (not 404), and the path then serves"
reset_case
rel(){ curl -s -o "${W}/rel" -w '%{http_code}' --max-time 30 -X POST -H "Authorization: Bearer ${TOK}" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg p "$1" '{path:$p}')" "${BASE}/api/v1/quarantine/proxy-cache/${R_Q}/release"; }
# held1's 409 was the CONTROL; release it at once, then do held2 and held3 back to back.
r1="$(rel q/held1.bin)"; b1="$(head -c 120 "${W}/rel")"
note "held1: 409=${HELD1_409:-?} release=${r1} ${b1}"
[ "$r1" = "200" ] || fail_g "held1: the release straight after the 409 answered ${r1}"
for i in 2 3; do
  g="$(curl -s -o /dev/null -w '%{http_code}' --max-time 60 -H "Authorization: Bearer ${TOK}" "${BASE}/api/v1/repositories/${R_Q}/download/q/held${i}.bin")"
  r="$(rel "q/held${i}.bin")"
  note "held${i}: GET=${g} release=${r} $(head -c 120 "${W}/rel")"
  [ "$g" = "409" ] || fail_g "held${i}: the cold download answered ${g}, expected 409"
  [ "$r" = "200" ] || fail_g "held${i}: the release straight after the 409 answered ${r}, expected 200"
done
ok=""
for _ in $(seq 1 30); do
  c="$(curl -s -o "${W}/hb" -w '%{http_code}' --max-time 60 -H "Authorization: Bearer ${TOK}" "${BASE}/api/v1/repositories/${R_Q}/download/q/held2.bin")"
  [ "$c" = "200" ] && { ok=1; break; }
  sleep 1
done
note "held2 after release: ${c} $(stat -c %s "${W}/hb" 2>/dev/null) bytes"
[ -n "$ok" ] && cmp -s "${W}/hb" "${W}/big.bin" || fail_g "the released held2 never served the upstream bytes (last ${c})"
finish_case "a held proxied path answers 404 to a release right after its 409"

end_suite
