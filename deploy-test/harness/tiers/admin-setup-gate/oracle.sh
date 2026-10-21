#!/usr/bin/env bash
# =============================================================================
# tiers/admin-setup-gate/oracle.sh
#   #4634 / #4635  only the built-in `admin` arms the first-run setup gate:
#                  another admin's pending password change must not arm it at
#                  boot (nor get `admin`'s password regenerated), re-arm it on
#                  reactivation, or lift it by rotating its own password
# See the manifest for THE BUG, the phases and the gates.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# DTF_DIR, RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"
: "${DTF_SLOT:?}"; : "${DTF_DIR:?}"; : "${RUN_ID:?}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=/dev/null
source "$COMMON_SH"

BASE="$BASE_URL"
DBC="$DB_CONTAINER"
BACKEND_CTR="${DB_CONTAINER%-db}-backend"
PROJECT="ak-dtf${DTF_SLOT}"
FS_HELPER_IMAGE="postgres:16-alpine"   # already pulled by compose.base.yml
PWFILE="/data/storage/admin.password"
SUF="${DTF_SLOT}${RUN_ID##*-}"
P1="sg-p1-${SUF}"     # pending admin: reactivation + restart legs, then the 428 control
P2="sg-p2-${SUF}"     # pending admin: rotates its own password under the gate
NEWPW_P2="SgP2-new!${SUF}x"
NEWPW_ADMIN="SgAdmin-new!${SUF}x"

setup_workdir
W="$WORK_DIR"

jqr(){ jq -r "$1" 2>/dev/null || true; }
psql_q(){ docker exec "$DBC" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null || true; }
fsx(){ docker run --rm -i --volumes-from "$BACKEND_CTR" --entrypoint sh "$FS_HELPER_IMAGE" -c "$1" 2>/dev/null || true; }

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

login_json(){ # <user> <password>
  curl -s --max-time 15 -X POST "${BASE}/api/v1/auth/login" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg u "$1" --arg p "$2" '{username:$u,password:$p}')" 2>/dev/null || true
}
login_tok(){ login_json "$1" "$2" | jqr '.access_token // empty'; }
setup_required(){ curl -s --max-time 10 "${BASE}/api/v1/setup/status" | jqr '.setup_required'; }
# anon_gate -> "<code> <error>" for an anonymous read of a gated route.
anon_gate(){
  local c
  c="$(curl -s -o "${W}/anon" -w '%{http_code}' --max-time 10 "${BASE}/api/v1/repositories")"
  echo "${c} $(jqr '.error // empty' < "${W}/anon")"
}
# req <METHOD> <PATH> <TOKEN> [JSON] -> sets CODE / BODY
req(){
  local m="$1" p="$2" t="$3" d="${4:-}"
  if [ -n "$d" ]; then
    CODE="$(curl -s -o "${W}/body" -w '%{http_code}' --max-time 15 -X "$m" -H "Authorization: Bearer ${t}" \
      -H 'Content-Type: application/json' -d "$d" "${BASE}${p}")"
  else
    CODE="$(curl -s -o "${W}/body" -w '%{http_code}' --max-time 15 -X "$m" -H "Authorization: Bearer ${t}" "${BASE}${p}")"
  fi
  BODY="$(cat "${W}/body" 2>/dev/null || true)"
}
# restart_backend: force-recreate the backend on the same volume + database.
restart_backend(){
  docker compose -p "$PROJECT" -f "${DTF_DIR}/compose.base.yml" -f "${HERE}/fixtures/setup.logs.yml" \
    up -d --no-deps --force-recreate --wait backend >"${W}/restart.log" 2>&1 || true
  LOGS="$(docker logs "$BACKEND_CTR" 2>&1 || true)"
}
# The exact lookup provision_admin_user ran before #4635 (no username filter,
# no ORDER BY): which row it returns is the row whose flag armed the gate.
unordered_first_admin(){ psql_q "SELECT username FROM users WHERE is_admin = true AND external_id IS NULL LIMIT 1"; }

begin_suite "admin-setup-gate"

# =============================================================================
# Setup: the seeded instance (admin from ADMIN_PASSWORD, nothing pending) and
# two more local admins created through the API with a generated temporary
# password (must_change_password = true), as an operator onboarding admins does.
# =============================================================================
begin_test "CONTROL: the seeded instance is past setup, and an admin created with a generated password is held to its own rotation (428), not the instance gate"
reset_case
ATOK="$(login_tok admin "$ADMIN_PASS")"
[ -n "$ATOK" ] || { infra_fail "admin cannot log in with ADMIN_PASSWORD on the seeded instance"; end_suite; }
[ "$(setup_required)" = "false" ] || fail_g "setup_required is not false on the seeded instance"
for u in "$P1" "$P2"; do
  req POST /api/v1/users "$ATOK" "$(jq -nc --arg u "$u" '{username:$u,email:($u+"@dtf.test"),is_admin:true}')"
  [ "$CODE" = "200" ] || [ "$CODE" = "201" ] || { infra_fail "could not create pending admin ${u} (HTTP ${CODE}: ${BODY:0:200})"; end_suite; }
  [ "$(jqr '.user.must_change_password' <<<"$BODY")" = "true" ] || fail_g "${u} was not created with must_change_password = true"
  printf '%s' "$(jqr '.generated_password // empty' <<<"$BODY")" > "${W}/${u}.pw"
  printf '%s' "$(jqr '.user.id // empty' <<<"$BODY")" > "${W}/${u}.id"
done
P1_ID="$(cat "${W}/${P1}.id")"; P2_ID="$(cat "${W}/${P2}.id")"
P1_PW="$(cat "${W}/${P1}.pw")"; P2_PW="$(cat "${W}/${P2}.pw")"
ADMIN_ID="$(psql_q "SELECT id FROM users WHERE username = 'admin'")"
[ -n "$P1_PW" ] && [ -n "$P2_PW" ] && [ -n "$ADMIN_ID" ] || { infra_fail "missing generated passwords or the admin id"; end_suite; }
P1TOK="$(login_tok "$P1" "$P1_PW")"
req GET /api/v1/users "$P1TOK"
note "pending admin ${P1}: GET /api/v1/users -> ${CODE} ${BODY:0:80}"
[ "$CODE" = "428" ] || fail_g "a pending admin's own request answered ${CODE}, expected 428 (per-user rotation)"
[ "$(setup_required)" = "false" ] || fail_g "creating pending admins armed the instance gate"
a="$(anon_gate)"; [ "${a%% *}" = "200" ] || fail_g "an anonymous repository list answered ${a}, expected 200 (no gate)"
finish_case "the seeded instance or the per-user rotation is not as expected"

# =============================================================================
# Post-setup, runtime: reactivating a pending NON-built-in admin.
# =============================================================================
begin_test "FIX #4634: deactivating and reactivating a pending admin other than 'admin' does not re-arm the setup gate (the API keeps answering)"
reset_case
req PATCH "/api/v1/users/${P1_ID}" "$ATOK" '{"is_active":false}'; c1="$CODE"
req PATCH "/api/v1/users/${P1_ID}" "$ATOK" '{"is_active":true}'; c2="$CODE"
note "PATCH ${P1} is_active false -> ${c1}, true -> ${c2}"
{ [ "$c1" = "200" ] && [ "$c2" = "200" ]; } || fail_g "deactivate/reactivate answered ${c1}/${c2}"
req GET /api/v1/users "$ATOK"
note "admin GET /api/v1/users afterwards -> ${CODE} $(jqr '.error // empty' <<<"$BODY")"
[ "$CODE" = "200" ] || fail_g "admin's API answered ${CODE} $(jqr '.error // empty' <<<"$BODY") after the reactivation, expected 200 (gate re-armed)"
a="$(anon_gate)"; note "anonymous GET /api/v1/repositories -> ${a}"
[ "${a%% *}" = "200" ] || fail_g "an anonymous repository list answered ${a} after the reactivation"
[ "$(setup_required)" = "false" ] || fail_g "setup_required turned true after reactivating ${P1}"
finish_case "#4634: reactivating a pending non-built-in admin re-arms the instance gate"

# =============================================================================
# Post-setup, boot: restart with other admins pending and no admin.password.
# =============================================================================
begin_test "FIX #4634: a restart while other admins are pending (admin.password absent) keeps setup_required false and does not regenerate the 'admin' password"
reset_case
has_pw="$(fsx "[ -f ${PWFILE} ] && echo yes || echo no" | tr -d '[:space:]')"
note "before the restart: ${PWFILE} present=${has_pw:-?}"
[ "$has_pw" = "no" ] || note "precondition: ${PWFILE} exists before the restart (the ADMIN_PASSWORD seed should not write one)"
# Make the pre-#4635 lookup (LIMIT 1, no ORDER BY) return a pending admin, as
# it did in the field once the built-in row had been rewritten after the
# others were inserted: re-touch the `admin` row (each UPDATE writes a new heap
# tuple) until the unordered first row is someone else. Image-independent.
first=""
for _ in $(seq 1 30); do
  first="$(unordered_first_admin)"
  [ -n "$first" ] && [ "$first" != "admin" ] && break
  psql_q "UPDATE users SET updated_at = updated_at WHERE username = 'admin'" >/dev/null
done
note "unordered first local admin (the pre-fix gate source): ${first:-?}"
[ -n "$first" ] && [ "$first" != "admin" ] || { infra_fail "could not stage the field condition (the unordered lookup still returns 'admin')"; end_suite; }
restart_backend
sr="$(setup_required)"
c="$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 -X POST "${BASE}/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg p "$ADMIN_PASS" '{username:"admin",password:$p}')")"
a="$(anon_gate)"
has_pw="$(fsx "[ -f ${PWFILE} ] && echo yes || echo no" | tr -d '[:space:]')"
note "after the restart: setup_required=${sr}, admin login with ADMIN_PASSWORD -> ${c}, anonymous list -> ${a}, ${PWFILE} present=${has_pw:-?}"
[ "$sr" = "false" ] || fail_g "setup_required is ${sr:-?} after the restart, expected false"
[ "$c" = "200" ] || fail_g "admin login with ADMIN_PASSWORD answered ${c} after the restart (password regenerated?)"
[ "${a%% *}" = "200" ] || fail_g "an anonymous repository list answered ${a} after the restart (instance gate armed)"
[ "$has_pw" = "no" ] || fail_g "the restart wrote ${PWFILE} (a regenerated 'admin' password)"
grep -q 'Regenerating password' <<<"$LOGS" && fail_g "the backend logged 'Regenerating password' on the restart"
grep -q 'API is locked until password is changed' <<<"$LOGS" && fail_g "the backend logged that the API is locked"
finish_case "#4634: another admin's pending change arms the gate at boot or rewrites the 'admin' password"

# =============================================================================
# Pre-setup: the built-in admin itself is pending, so the gate is armed.
# =============================================================================
begin_test "CONTROL: with the built-in 'admin' pending (must_change_password) a restart arms the gate on both images: setup_required true, gated routes 403 SETUP_REQUIRED, the generated password readable at ${PWFILE}"
reset_case
psql_q "UPDATE users SET must_change_password = true WHERE username = 'admin'" >/dev/null
restart_backend
sr="$(setup_required)"
a="$(anon_gate)"
# The file is the password on line 1, then commented setup instructions.
ADMIN_FILE_PW="$(fsx "head -n 1 ${PWFILE}" | tr -d '\r\n')"
note "setup_required=${sr}, anonymous list -> ${a}, password line in ${PWFILE}: ${ADMIN_FILE_PW:+present}${ADMIN_FILE_PW:-absent}"
[ "$sr" = "true" ] || fail_g "setup_required is ${sr:-?}, expected true"
[ "$a" = "403 SETUP_REQUIRED" ] || fail_g "an anonymous repository list answered ${a}, expected 403 SETUP_REQUIRED"
[ -n "$ADMIN_FILE_PW" ] || fail_g "no admin password at ${PWFILE} to complete setup with"
finish_case "the built-in admin's pending change does not arm the gate"

begin_test "FIX #4634: while 'admin' is still pending, another pending admin rotating its own password does not lift the gate"
reset_case
P2TOK="$(login_tok "$P2" "$P2_PW")"
[ -n "$P2TOK" ] || fail_g "${P2} could not log in under the gate (/api/v1/auth is exempt)"
req POST "/api/v1/users/${P2_ID}/password" "${P2TOK:-none}" "$(jq -nc --arg c "$P2_PW" --arg n "$NEWPW_P2" '{current_password:$c,new_password:$n}')"
note "${P2} POST /api/v1/users/{id}/password -> ${CODE} ${BODY:0:80}"
{ [ "$CODE" = "200" ] || [ "$CODE" = "204" ]; } || fail_g "${P2}'s own password change answered ${CODE}"
[ "$(psql_q "SELECT must_change_password FROM users WHERE id = '${P2_ID}'")" = "f" ] || fail_g "${P2} is still flagged after its rotation"
sr="$(setup_required)"
a="$(anon_gate)"
note "afterwards: setup_required=${sr}, anonymous list -> ${a}, admin still pending=$(psql_q "SELECT must_change_password FROM users WHERE username = 'admin'")"
[ "$sr" = "true" ] || fail_g "setup_required is ${sr:-?} after ${P2} rotated, expected true ('admin' has not rotated)"
[ "$a" = "403 SETUP_REQUIRED" ] || fail_g "an anonymous repository list answered ${a} after ${P2} rotated, expected 403 SETUP_REQUIRED"
finish_case "#4634: a non-built-in admin's rotation lifts the setup gate"

begin_test "CONTROL: the built-in admin completing its rotation lifts the gate on both images; the other pending admin is still held to its own 428"
reset_case
ATOK2="$(login_tok admin "$ADMIN_FILE_PW")"
[ -n "$ATOK2" ] || fail_g "admin could not log in with the password from ${PWFILE}"
req POST "/api/v1/users/${ADMIN_ID}/password" "${ATOK2:-none}" "$(jq -nc --arg c "$ADMIN_FILE_PW" --arg n "$NEWPW_ADMIN" '{current_password:$c,new_password:$n}')"
note "admin POST /api/v1/users/{id}/password -> ${CODE}"
{ [ "$CODE" = "200" ] || [ "$CODE" = "204" ]; } || fail_g "admin's password change answered ${CODE}: ${BODY:0:160}"
sr="$(setup_required)"; a="$(anon_gate)"
note "afterwards: setup_required=${sr}, anonymous list -> ${a}"
[ "$sr" = "false" ] || fail_g "setup_required is ${sr:-?} after admin rotated"
[ "${a%% *}" = "200" ] || fail_g "an anonymous repository list answered ${a} after admin rotated"
ATOK3="$(login_tok admin "$NEWPW_ADMIN")"
req GET /api/v1/users "${ATOK3:-none}"
[ "$CODE" = "200" ] || fail_g "admin's API with the new password answered ${CODE}"
P1TOK="$(login_tok "$P1" "$P1_PW")"
req GET /api/v1/users "${P1TOK:-none}"
note "${P1} (still pending) GET /api/v1/users -> ${CODE}"
[ "$CODE" = "428" ] || fail_g "${P1} answered ${CODE}, expected 428 (its own rotation is still required)"
finish_case "completing setup as the built-in admin does not unlock the API"

end_suite
