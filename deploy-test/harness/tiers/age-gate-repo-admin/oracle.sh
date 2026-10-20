#!/usr/bin/env bash
# =============================================================================
# tiers/age-gate-repo-admin/oracle.sh
#   #4238 / #4239 a repository's own admins operate its age gate: read and set
#   the policy, list / read / approve / reject / reopen its held reviews,
#   scoped to that repository, under an instance-admin lock they cannot
#   relax; every decision names the principal and the actor tier.
# See the manifest for the primitives and the gates.
#
# Egress: like age-gate-review-reopen, the held versions come from proxying
# the real `is-odd` packument from registry.npmjs.org. The gate runs in
# `first_seen` mode, so every version is "young" on a fresh stack and held.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"
: "${DTF_SLOT:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

BASE="$BASE_URL"
DBC="$DB_CONTAINER"
PKG="is-odd"
UPSTREAM="https://registry.npmjs.org"

setup_workdir
W="$WORK_DIR"

# common.sh runs under `set -e`: every probe swallows its own failure and the
# assertion that reads the (possibly empty) value judges it.
jqr(){ jq -r "$1" 2>/dev/null || true; }
psql_q(){ docker exec "$DBC" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]' || true; }

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }
is_denied(){ case "$1" in 403|404) return 0 ;; *) return 1 ;; esac; }

# call <token> <METHOD> <path> <outfile> [json] -> http code
call(){
  local tok="$1" m="$2" p="$3" out="$4" body="${5:-}" code
  rm -f "$out"
  if [ -n "$body" ]; then
    code="$(curl -s --max-time 60 -o "$out" -w '%{http_code}' -X "$m" -H "Authorization: Bearer ${tok}" \
      -H 'Content-Type: application/json' -d "$body" "${BASE}${p}" 2>/dev/null)" || true
  else
    code="$(curl -s --max-time 60 -o "$out" -w '%{http_code}' -X "$m" -H "Authorization: Bearer ${tok}" \
      "${BASE}${p}" 2>/dev/null)" || true
  fi
  [ -f "$out" ] || : > "$out"
  echo "${code:-000}"
}

login(){
  curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
    -d "{\"username\":\"$1\",\"password\":\"$2\"}" | jqr '.access_token // .token // empty'
}

# served <repo> <version> -> SERVED|BLOCKED (fresh packument through the proxy)
served(){
  curl -s --max-time 60 -o "$W/pk.json" -H "Authorization: Bearer $TOK" "${BASE}/npm/$1/${PKG}" 2>/dev/null || true
  if jq -e --arg v "$2" '.versions[$v]' "$W/pk.json" >/dev/null 2>&1; then echo SERVED; else echo BLOCKED; fi
}

# policy <repo-key> -> "enabled|min_age_days|mode|locked" from the DB (the
# lock column only exists on #4239 images; "-" otherwise)
policy(){
  local lock
  lock="$(psql_q "SELECT age_gate_instance_locked::text FROM repositories WHERE key='$1'")"
  echo "$(psql_q "SELECT age_gate_enabled::text||'|'||age_gate_min_age_days||'|'||age_gate_mode FROM repositories WHERE key='$1'")|${lock:--}"
}
review_status(){ psql_q "SELECT status FROM age_gate_reviews WHERE id='$1'"; }
audit_n(){ psql_q "SELECT count(*) FROM audit_log WHERE $1"; }

GATE_ON='{"enabled":true,"min_age_days":30,"mode":"first_seen"}'

# =============================================================================
begin_suite "age-gate-repo-admin"

begin_test "setup: admin, remote npm repos A and B on ${UPSTREAM}, user U granted repository admin on A only"
TOK="$(login admin "$ADMIN_PASS")"
if [ -z "$TOK" ]; then infra_fail "admin login failed at $BASE"; end_suite; fi
SUF="${RUN_ID##*-}"
RA="agra-a-${DTF_SLOT}-${SUF}"; RB="agra-b-${DTF_SLOT}-${SUF}"
U_NAME="agra-u-${DTF_SLOT}-${SUF}"; U_PASS="AgraUser_${SUF}_Aa1!"
SETUP_ERR=""
for k in "$RA" "$RB"; do
  c="$(call "$TOK" POST /api/v1/repositories "$W/r.out" \
    "{\"key\":\"$k\",\"name\":\"$k\",\"format\":\"npm\",\"repo_type\":\"remote\",\"is_public\":true,\"upstream_url\":\"${UPSTREAM}\"}")"
  [ "$(jqr '.key' < "$W/r.out")" = "$k" ] || SETUP_ERR="${SETUP_ERR} repo ${k}=${c}"
done
RA_ID="$(psql_q "SELECT id FROM repositories WHERE key='${RA}'")"
call "$TOK" POST /api/v1/users "$W/u.out" \
  "{\"username\":\"${U_NAME}\",\"password\":\"${U_PASS}\",\"email\":\"${U_NAME}@dtf.invalid\"}" >/dev/null
U_ID="$(psql_q "SELECT id FROM users WHERE username='${U_NAME}'")"
ADMIN_ID="$(psql_q "SELECT id FROM users WHERE username='admin'")"
c="$(call "$TOK" POST /api/v1/permissions "$W/perm.out" \
  "{\"principal_type\":\"user\",\"principal_id\":\"${U_ID}\",\"target_type\":\"repository\",\"target_id\":\"${RA_ID}\",\"actions\":[\"admin\"]}")"
[ "$c" = "200" ] || [ "$c" = "201" ] || SETUP_ERR="${SETUP_ERR} grant=${c}:$(head -c 120 "$W/perm.out")"
UTOK="$(login "$U_NAME" "$U_PASS")"
[ -n "$UTOK" ] || SETUP_ERR="${SETUP_ERR} user-login"
[ "$(psql_q "SELECT is_admin FROM users WHERE id='${U_ID}'")" = "f" ] || SETUP_ERR="${SETUP_ERR} U-is-admin"
if [ -n "$SETUP_ERR" ]; then infra_fail "setup failed:${SETUP_ERR}"; end_suite; fi
echo "-- A=${RA} B=${RB} U=${U_NAME} (${U_ID}), grant: repository ${RA} actions [admin]"
pass

# =============================================================================
# CONTROL (both images): instance-admin gate operation and the hold/release flow.
# =============================================================================
begin_test "CONTROL: instance admin sets B's gate (first_seen), proxying holds every version, the /admin queue lists them"
reset_case
c="$(call "$TOK" PUT "/api/v1/repositories/${RB}/age-gate" "$W/b.put" "$GATE_ON")"
note "admin PUT B: HTTP ${c} $(head -c 200 "$W/b.put")"
[ "$c" = "200" ] && [ "$(jqr '.enabled' < "$W/b.put")" = "true" ] || fail_g "admin PUT B age-gate HTTP ${c}"
c="$(call "$TOK" GET "/api/v1/repositories/${RB}/age-gate" "$W/b.get")"
[ "$c" = "200" ] && [ "$(jqr '.min_age_days' < "$W/b.get")" = "30" ] && [ "$(jqr '.mode' < "$W/b.get")" = "first_seen" ] \
  || fail_g "admin GET B age-gate HTTP ${c}: $(head -c 200 "$W/b.get")"
served "$RB" 0.0.0 >/dev/null   # prime: enqueue reviews
c="$(call "$TOK" GET "/api/v1/admin/age-gate/reviews?repository_key=${RB}&status=pending&per_page=100" "$W/b.q")"
NB="$(jqr '.items | length' < "$W/b.q")"
RB1="$(jqr '.items[0].id // empty' < "$W/b.q")"; VB1="$(jqr '.items[0].package_version // empty' < "$W/b.q")"
RB2="$(jqr '.items[1].id // empty' < "$W/b.q")"
note "admin queue for B: HTTP ${c}, ${NB:-0} pending; first ${VB1:-?}"
if [ "$c" != "200" ] || [ -z "$RB1" ] || [ -z "$RB2" ]; then
  infra_fail "the gate held fewer than two ${PKG} versions on ${RB} (egress to ${UPSTREAM}?)" "$(head -c 400 "$W/b.q")"
  end_suite
fi
[ "$(served "$RB" "$VB1")" = "BLOCKED" ] || fail_g "held version ${VB1} was served on B while pending"
finish_case "instance-admin age-gate configuration regressed"

begin_test "CONTROL: instance admin approve releases a held version on B, reject re-blocks it"
reset_case
c="$(call "$TOK" POST "/api/v1/admin/age-gate/reviews/${RB1}/approve" "$W/b.ap" '{"reason":"dtf control approve"}')"
s1="$(served "$RB" "$VB1")"
c2="$(call "$TOK" POST "/api/v1/admin/age-gate/reviews/${RB1}/reject" "$W/b.rj" '{"reason":"dtf control reject"}')"
s2="$(served "$RB" "$VB1")"
note "approve HTTP ${c} -> ${s1}; reject HTTP ${c2} -> ${s2}"
[ "$c" = "200" ] && [ "$(jqr '.status' < "$W/b.ap")" = "approved" ] && [ "$s1" = "SERVED" ] || fail_g "admin approve did not release ${VB1}"
[ "$c2" = "200" ] && [ "$(jqr '.status' < "$W/b.rj")" = "rejected" ] && [ "$s2" = "BLOCKED" ] || fail_g "admin reject did not re-block ${VB1}"
finish_case "the instance-admin hold/release flow regressed"

begin_test "CONTROL: U (no grant on B) cannot read or change B's gate, list or decide B's reviews, or use the instance queue"
reset_case
pol_b="$(policy "$RB")"; st_b2="$(review_status "$RB2")"
for spec in "GET|/api/v1/repositories/${RB}/age-gate|" \
            "PUT|/api/v1/repositories/${RB}/age-gate|{\"enabled\":false,\"min_age_days\":1,\"mode\":\"first_seen\"}" \
            "GET|/api/v1/repositories/${RB}/age-gate/reviews|" \
            "POST|/api/v1/repositories/${RB}/age-gate/reviews/${RB2}/approve|{\"reason\":\"x\"}" \
            "GET|/api/v1/admin/age-gate/reviews?repository_key=${RB}|" \
            "POST|/api/v1/admin/age-gate/reviews/${RB2}/approve|{\"reason\":\"x\"}"; do
  IFS='|' read -r m p b <<<"$spec"
  c="$(call "$UTOK" "$m" "$p" "$W/ub.out" "$b")"
  note "U ${m} ${p%%\?*}: HTTP ${c}"
  is_denied "$c" || fail_g "U ${m} ${p} answered HTTP ${c}, expected 403/404"
  grep -q '"items"' "$W/ub.out" && fail_g "U ${m} ${p} returned a review list"
done
[ "$(policy "$RB")" = "$pol_b" ] || fail_g "B's policy changed: ${pol_b} -> $(policy "$RB")"
[ "$(review_status "$RB2")" = "$st_b2" ] || fail_g "B's review ${RB2} changed: ${st_b2} -> $(review_status "$RB2")"
finish_case "a principal with no grant on B reached B's age gate"

# =============================================================================
# FIX (#4238): the repository admin operates A's gate.
# =============================================================================
begin_test "FIX #4238: repository admin U reads A's gate and enables it (no instance lock set by U)"
reset_case
c="$(call "$UTOK" GET "/api/v1/repositories/${RA}/age-gate" "$W/a.get")"
note "U GET A: HTTP ${c} $(head -c 200 "$W/a.get")"
[ "$c" = "200" ] && [ "$(jqr '.repository_key' < "$W/a.get")" = "$RA" ] || fail_g "U GET A age-gate HTTP ${c} (pre-#4239: 403 instance admin only)"
[ "$(jqr '.instance_locked' < "$W/a.get")" = "false" ] || fail_g "A's unconfigured policy is not reported unlocked"
c="$(call "$UTOK" PUT "/api/v1/repositories/${RA}/age-gate" "$W/a.put" "$GATE_ON")"
note "U PUT A: HTTP ${c} $(head -c 200 "$W/a.put")"
[ "$c" = "200" ] && [ "$(jqr '.enabled' < "$W/a.put")" = "true" ] || fail_g "U PUT A age-gate HTTP ${c}"
[ "$(policy "$RA")" = "true|30|first_seen|false" ] || fail_g "A's stored policy is $(policy "$RA"), expected true|30|first_seen|false"
finish_case "a repository admin cannot operate its own repository's age gate (#4238)"

begin_test "FIX #4238: U lists and reads A's held reviews; the list is confined to A; a B review id through A's route is 404"
reset_case
served "$RA" 0.0.0 >/dev/null   # prime A
c="$(call "$UTOK" GET "/api/v1/repositories/${RA}/age-gate/reviews?status=pending&per_page=100" "$W/a.q")"
NA="$(jqr '.items | length' < "$W/a.q")"
RA1="$(jqr '.items[0].id // empty' < "$W/a.q")"; VA1="$(jqr '.items[0].package_version // empty' < "$W/a.q")"
RA2="$(jqr '.items[1].id // empty' < "$W/a.q")"; VA2="$(jqr '.items[1].package_version // empty' < "$W/a.q")"
RA3="$(jqr '.items[2].id // empty' < "$W/a.q")"
note "U list A: HTTP ${c}, ${NA:-0} pending, keys $(jqr '[.items[].repository_key] | unique | join(",")' < "$W/a.q")"
[ "$c" = "200" ] && [ -n "$RA1" ] && [ -n "$RA2" ] && [ -n "$RA3" ] || fail_g "U could not list >= 3 pending reviews on A (HTTP ${c})"
[ "$(jqr "[.items[].repository_key] | unique | join(\",\")" < "$W/a.q")" = "$RA" ] || fail_g "A's queue contains other repositories' reviews"
c="$(call "$UTOK" GET "/api/v1/repositories/${RA}/age-gate/reviews?repository_key=${RB}&per_page=100" "$W/a.qx")"
[ "$c" = "200" ] && [ "$(jqr "[.items[].repository_key] | unique | join(\",\")" < "$W/a.qx")" = "$RA" ] \
  || fail_g "?repository_key=${RB} widened A's queue (HTTP ${c}, keys $(jqr '[.items[].repository_key] | unique | join(",")' < "$W/a.qx"))"
c="$(call "$UTOK" GET "/api/v1/repositories/${RA}/age-gate/reviews/${RA1}" "$W/a.r1")"
[ "$c" = "200" ] && [ "$(jqr '.id' < "$W/a.r1")" = "$RA1" ] || fail_g "U GET A review ${RA1} HTTP ${c}"
st_b2="$(review_status "$RB2")"
c="$(call "$UTOK" GET "/api/v1/repositories/${RA}/age-gate/reviews/${RB2}" "$W/a.xr")"
c2="$(call "$UTOK" POST "/api/v1/repositories/${RA}/age-gate/reviews/${RB2}/approve" "$W/a.xa" '{"reason":"cross"}')"
note "B review through A's route: GET ${c}, approve ${c2}"
[ "$c" = "404" ] && [ "$c2" = "404" ] || fail_g "a B review id through A's route answered GET ${c} / approve ${c2}, expected 404/404"
[ "$(review_status "$RB2")" = "$st_b2" ] || fail_g "B's review ${RB2} changed through A's route"
c="$(call "$UTOK" POST "/api/v1/repositories/${RA}/age-gate/reviews/${RA1}/promote" "$W/a.bad" '{"reason":"x"}')"
[ "$c" = "400" ] && [ "$(review_status "$RA1")" = "pending" ] || fail_g "an unknown decision answered HTTP ${c} or moved the review"
finish_case "the repository-scoped review queue is missing or not confined (#4238)"

begin_test "FIX #4238: U approves an A review; the version is released; the instance review list names U as the approver"
reset_case
c="$(call "$UTOK" POST "/api/v1/repositories/${RA}/age-gate/reviews/${RA1}/approve" "$W/a.ap" '{"reason":"dtf repo-admin approve"}')"
note "U approve ${VA1}: HTTP ${c} $(jq -c '{status,reviewed_by_username,reviewed_by_is_service_account,instance_locked}' < "$W/a.ap" 2>/dev/null)"
[ "$c" = "200" ] && [ "$(jqr '.status' < "$W/a.ap")" = "approved" ] || fail_g "U approve HTTP ${c}"
[ "$(jqr '.reviewed_by_username' < "$W/a.ap")" = "$U_NAME" ] || fail_g "reviewed_by_username != ${U_NAME}"
[ "$(jqr '.reviewed_by_is_service_account' < "$W/a.ap")" = "false" ] || fail_g "reviewed_by_is_service_account != false"
[ "$(jqr '.instance_locked' < "$W/a.ap")" = "false" ] || fail_g "a repository admin's decision was instance-locked"
[ "$(served "$RA" "$VA1")" = "SERVED" ] || fail_g "approved ${VA1} is not served on A"
[ "$(served "$RA" "$VA2")" = "BLOCKED" ] || fail_g "still-pending ${VA2} is served on A"
c="$(call "$TOK" GET "/api/v1/admin/age-gate/reviews?repository_key=${RA}&status=approved&per_page=100" "$W/a.adm")"
row="$(jq -r --arg id "$RA1" '.items[] | select(.id==$id) | "\(.status)|\(.reviewed_by)|\(.reviewed_by_username)"' < "$W/a.adm" 2>/dev/null || true)"
note "instance review list row: ${row:-<absent>}"
[ "$row" = "approved|${U_ID}|${U_NAME}" ] || fail_g "the instance review list does not show ${RA1} approved by ${U_NAME}"
finish_case "a repository admin's approval does not take effect or is not attributed (#4238)"

# =============================================================================
# FIX (#4238): the instance-admin lock.
# =============================================================================
begin_test "FIX #4238: an instance-admin decision locks the review: U may not approve or reopen it"
reset_case
c="$(call "$TOK" POST "/api/v1/admin/age-gate/reviews/${RA2}/reject" "$W/l.rj" '{"reason":"dtf instance reject"}')"
note "admin reject ${VA2}: HTTP ${c} instance_locked=$(jqr '.instance_locked' < "$W/l.rj")"
[ "$c" = "200" ] && [ "$(jqr '.instance_locked' < "$W/l.rj")" = "true" ] || fail_g "an instance-admin reject did not lock the review"
for d in approve reopen; do
  c="$(call "$UTOK" POST "/api/v1/repositories/${RA}/age-gate/reviews/${RA2}/${d}" "$W/l.${d}" '{"reason":"relax"}')"
  note "U ${d} the locked review: HTTP ${c} $(head -c 160 "$W/l.${d}")"
  [ "$c" = "403" ] || fail_g "U ${d} on an instance-locked review answered HTTP ${c}, expected 403"
done
[ "$(review_status "$RA2")" = "rejected" ] || fail_g "the locked review moved to $(review_status "$RA2")"
[ "$(served "$RA" "$VA2")" = "BLOCKED" ] || fail_g "rejected ${VA2} is served"
finish_case "a repository admin can overturn an instance-admin decision (#4238)"

begin_test "FIX #4238: an instance-admin policy write locks A's policy: U may tighten it but not relax, disable, re-mode or unlock it"
reset_case
c="$(call "$TOK" PUT "/api/v1/repositories/${RA}/age-gate" "$W/l.put" '{"enabled":true,"min_age_days":60,"mode":"first_seen"}')"
note "admin PUT A (lock omitted): HTTP ${c} instance_locked=$(jqr '.instance_locked' < "$W/l.put")"
[ "$c" = "200" ] && [ "$(jqr '.instance_locked' < "$W/l.put")" = "true" ] || fail_g "an instance-admin policy write did not lock A"
c="$(call "$UTOK" GET "/api/v1/repositories/${RA}/age-gate" "$W/l.get")"
[ "$c" = "200" ] && [ "$(jqr '.instance_locked' < "$W/l.get")" = "true" ] || fail_g "U does not see A's policy as instance_locked (HTTP ${c})"
for spec in "lower the minimum age|{\"enabled\":true,\"min_age_days\":30,\"mode\":\"first_seen\"}" \
            "disable the gate|{\"enabled\":false,\"min_age_days\":60,\"mode\":\"first_seen\"}" \
            "change the mode|{\"enabled\":true,\"min_age_days\":60,\"mode\":\"upstream_publish_time\"}" \
            "hand the lock back|{\"enabled\":true,\"min_age_days\":60,\"mode\":\"first_seen\",\"instance_locked\":false}"; do
  IFS='|' read -r label b <<<"$spec"
  c="$(call "$UTOK" PUT "/api/v1/repositories/${RA}/age-gate" "$W/l.x" "$b")"
  note "U ${label}: HTTP ${c} $(head -c 140 "$W/l.x")"
  [ "$c" = "403" ] || fail_g "U could ${label} on a locked policy (HTTP ${c}, expected 403)"
done
[ "$(policy "$RA")" = "true|60|first_seen|true" ] || fail_g "A's locked policy changed to $(policy "$RA")"
c="$(call "$UTOK" PUT "/api/v1/repositories/${RA}/age-gate" "$W/l.t" '{"enabled":true,"min_age_days":90,"mode":"first_seen"}')"
note "U tighten to 90 days: HTTP ${c}"
[ "$c" = "200" ] && [ "$(policy "$RA")" = "true|90|first_seen|true" ] || fail_g "U could not tighten the locked policy (HTTP ${c}, now $(policy "$RA"))"
finish_case "a repository admin can relax an instance-admin policy (#4238)"

begin_test "FIX #4238: the instance admin unlocks the policy and reopens the review; U may then relax and approve"
reset_case
c="$(call "$TOK" PUT "/api/v1/repositories/${RA}/age-gate" "$W/u.put" '{"enabled":true,"min_age_days":90,"mode":"first_seen","instance_locked":false}')"
note "admin unlock: HTTP ${c} instance_locked=$(jqr '.instance_locked' < "$W/u.put")"
[ "$c" = "200" ] && [ "$(jqr '.instance_locked' < "$W/u.put")" = "false" ] || fail_g "the instance admin could not hand the policy back"
c="$(call "$UTOK" PUT "/api/v1/repositories/${RA}/age-gate" "$W/u.rel" "$GATE_ON")"
[ "$c" = "200" ] && [ "$(policy "$RA")" = "true|30|first_seen|false" ] || fail_g "U could not relax the handed-back policy (HTTP ${c}, now $(policy "$RA"))"
c="$(call "$TOK" POST "/api/v1/admin/age-gate/reviews/${RA2}/reopen" "$W/u.ro" '{"reason":"dtf instance reopen"}')"
note "admin reopen: HTTP ${c} status=$(jqr '.status' < "$W/u.ro") instance_locked=$(jqr '.instance_locked' < "$W/u.ro")"
[ "$c" = "200" ] && [ "$(jqr '.instance_locked' < "$W/u.ro")" = "false" ] || fail_g "an instance-admin reopen did not release the review lock"
c="$(call "$UTOK" POST "/api/v1/repositories/${RA}/age-gate/reviews/${RA2}/approve" "$W/u.ap" '{"reason":"dtf after release"}')"
note "U approve after release: HTTP ${c}"
[ "$c" = "200" ] && [ "$(served "$RA" "$VA2")" = "SERVED" ] || fail_g "U could not approve the released review (HTTP ${c})"
finish_case "the instance admin cannot hand a decision back (#4238)"

begin_test "FIX #4238: audit_log records the actor and the tier for policy writes, decisions and lock transitions"
reset_case
A="resource_id='${RA_ID}'"
chk(){ # <label> <where> <ge|eq> <count>
  local n ok=1
  n="$(audit_n "$2")"
  note "${1}: ${n:-0}"
  case "${3}:${n}" in
    ge:[0-9]*) [ "$n" -ge "$4" ] || ok=0 ;;
    eq:[0-9]*) [ "$n" -eq "$4" ] || ok=0 ;;
    *) ok=0 ;;
  esac
  [ "$ok" -eq 1 ] || fail_g "${1}: ${n:-0} rows (expected ${3} ${4})"
}
chk "REPOSITORY_UPDATED by U, actor_tier=repository_admin, relaxed=false" \
  "action='REPOSITORY_UPDATED' AND ${A} AND user_id='${U_ID}' AND details->'age_gate_change'->>'actor_tier'='repository_admin' AND details->'age_gate_change'->>'relaxed'='false'" ge 2
chk "REPOSITORY_UPDATED by U, relaxed=true (after the hand-back)" \
  "action='REPOSITORY_UPDATED' AND ${A} AND user_id='${U_ID}' AND details->'age_gate_change'->>'relaxed'='true'" eq 1
chk "REPOSITORY_UPDATED by admin, actor_tier=instance_admin" \
  "action='REPOSITORY_UPDATED' AND ${A} AND user_id='${ADMIN_ID}' AND details->'age_gate_change'->>'actor_tier'='instance_admin'" ge 2
chk "AGE_GATE_APPROVED by U, actor_tier=repository_admin" \
  "action='AGE_GATE_APPROVED' AND ${A} AND user_id='${U_ID}' AND details->>'actor_tier'='repository_admin'" eq 2
chk "AGE_GATE_REJECTED by admin, actor_tier=instance_admin" \
  "action='AGE_GATE_REJECTED' AND ${A} AND user_id='${ADMIN_ID}' AND details->>'actor_tier'='instance_admin'" eq 1
chk "AGE_GATE_REOPENED by admin, actor_tier=instance_admin" \
  "action='AGE_GATE_REOPENED' AND ${A} AND user_id='${ADMIN_ID}' AND details->>'actor_tier'='instance_admin'" eq 1
chk "AGE_GATE_LOCK_SET policy by admin" "action='AGE_GATE_LOCK_SET' AND ${A} AND user_id='${ADMIN_ID}' AND details->>'lock'='policy' AND details->>'actor_tier'='instance_admin'" eq 1
chk "AGE_GATE_LOCK_SET review by admin" "action='AGE_GATE_LOCK_SET' AND ${A} AND user_id='${ADMIN_ID}' AND details->>'lock'='review'" eq 1
chk "AGE_GATE_LOCK_RELEASED policy by admin" "action='AGE_GATE_LOCK_RELEASED' AND ${A} AND user_id='${ADMIN_ID}' AND details->>'lock'='policy'" eq 1
chk "AGE_GATE_LOCK_RELEASED review by admin" "action='AGE_GATE_LOCK_RELEASED' AND ${A} AND user_id='${ADMIN_ID}' AND details->>'lock'='review'" eq 1
chk "no lock transition by U" "action LIKE 'AGE_GATE_LOCK_%' AND user_id='${U_ID}'" eq 0
chk "no age-gate audit by U outside A" "(action LIKE 'AGE_GATE_%' OR action='REPOSITORY_UPDATED') AND user_id='${U_ID}' AND resource_id <> '${RA_ID}'" eq 0
finish_case "age-gate actions are not audited with actor and tier (#4238)"

end_suite
