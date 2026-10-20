#!/usr/bin/env bash
# =============================================================================
# tiers/oidc-group-preprovision/oracle.sh
#   #4297 an admin can pre-provision an OIDC-managed group before any login;
#         the row is IdP-managed (no manual membership), a later login joins
#         the same row and a login without the claim leaves it again.
# See the manifest for THE FEATURE and the gates. The headless OIDC login is
# driven exactly as tiers/oidc-group-sync does (three curls: AK /login ->
# mock /authorize with per-login claims -> AK callback).
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# TRIVY_PORT (the mock IdP's host port), RELEASE_GATE=1, JUNIT_OUTPUT_DIR,
# COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"
: "${DTF_SLOT:?}"; : "${TRIVY_PORT:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

BASE="$BASE_URL"
ISSUER="http://mock-oidc"
MOCK="http://127.0.0.1:${TRIVY_PORT}"
# Short, unique per run and per slot (group names are length-capped).
SUF="${DTF_SLOT}-${RUN_ID##*-}"

jqr(){ jq -r "$1" 2>/dev/null || true; }
db(){ docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]' || true; }

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

login_tok(){
  curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
    -d "{\"username\":\"$1\",\"password\":\"$2\"}" | jqr '.access_token // empty'
}

# req <token> <method> <path> [json] -> writes body to $W/body, echoes status
setup_workdir
W="$WORK_DIR"
req(){
  local tok="$1" m="$2" p="$3" d="${4:-}"
  if [ -n "$d" ]; then
    curl -s -o "$W/body" -w '%{http_code}' -X "$m" -H "Authorization: Bearer $tok" \
      -H 'Content-Type: application/json' -d "$d" "$BASE$p" || echo 000
  else
    curl -s -o "$W/body" -w '%{http_code}' -X "$m" -H "Authorization: Bearer $tok" "$BASE$p" || echo 000
  fi
}
body(){ cat "$W/body" 2>/dev/null || true; }

create_oidc_provider(){ # <name> <client_id> <map_groups:true|false> -> id
  local b
  b=$(jq -n --arg name "$1" --arg iss "$ISSUER" --arg cid "$2" --argjson mg "$3" \
    '{name:$name, issuer_url:$iss, client_id:$cid, client_secret:"dtf-oidc-secret",
      is_enabled:true, auto_create_users:true, pkce_enabled:false, map_groups_to_groups:$mg}')
  curl -s -X POST "$BASE/api/v1/admin/sso/oidc" -H "Authorization: Bearer $TOK" \
    -H 'Content-Type: application/json' -d "$b" | jqr '.id // empty'
}

# drive_oidc_login <provider_id> <sub> <groups_csv> -> AK callback status (307 = OK)
drive_oidc_login(){
  local pid="$1" sub="$2" groups="$3" authz cb
  authz=$(curl -s -o /dev/null -w '%{redirect_url}' "$BASE/api/v1/auth/sso/oidc/${pid}/login")
  [ -z "$authz" ] && { echo "000-no-login-redirect"; return; }
  cb=$(curl -s -o /dev/null -w '%{redirect_url}' "${authz}&sub=${sub}&email=${sub}%40dtf.test&groups=${groups}")
  [ -z "$cb" ] && { echo "000-no-authorize-redirect"; return; }
  curl -s -o /dev/null -w '%{http_code}' "$cb"
}

preprovision(){ # <token> <provider_id> <name> -> status, body in $W/body
  req "$1" POST "/api/v1/admin/sso/oidc/$2/groups" "$(jq -nc --arg n "$3" '{name:$n}')"
}

g_rows(){ db "SELECT count(*) FROM groups WHERE name='$1'"; }
g_id(){ db "SELECT id FROM groups WHERE name='$1'"; }
g_src(){ db "SELECT COALESCE(external_source,'NULL')||'/'||COALESCE(external_provider_id::text,'NULL') FROM groups WHERE name='$1'"; }
g_members(){ db "SELECT count(*) FROM user_group_members m JOIN groups g ON g.id=m.group_id WHERE g.name='$1'"; }
oidc_member_of(){ # <sub> <group_id> -> 1 | ''
  db "SELECT 1 FROM user_group_members m JOIN users u ON u.id=m.user_id
      WHERE u.external_id='$1' AND u.auth_provider='oidc' AND m.group_id='$2' LIMIT 1"
}
oidc_uid(){ db "SELECT id FROM users WHERE external_id='$1' AND auth_provider='oidc'"; }

begin_suite "oidc-group-preprovision"

auth_admin
TOK="$ADMIN_TOKEN"

# ---------------------------------------------------------------------------
begin_test "CONTROL setup: mock IdP discovery + JWKS, two group-mapping providers, one non-mapping provider, a local user"
reset_case
# The local user signs in FIRST: once an SSO provider is configured the
# backend refuses local password logins for non-admins, but a session issued
# before that stays valid.
LU="dtf-pp-local-${SUF}"; LP="DtfPp!${SUF}-Strong"
LUID="$(create_test_user_with_retry "$LU" "$LP" "${LU}@dtf.test")" || LUID=""
LTOK=""
[ -n "$LUID" ] && LTOK="$(login_tok "$LU" "$LP")"
[ -n "$LTOK" ] || fail_g "local non-admin user create/login failed (uid='$LUID')"
DISC=$(curl -s --max-time 5 "$MOCK/.well-known/openid-configuration")
echo "$DISC" | jq -e '.issuer and .authorization_endpoint and .token_endpoint and .jwks_uri' >/dev/null 2>&1 \
  || fail_g "mock discovery malformed: $(echo "$DISC" | head -c 200)"
P1="$(create_oidc_provider "dtf-pp-p1-${SUF}" "dtf-pp-c1-${SUF}" true)"
P2="$(create_oidc_provider "dtf-pp-p2-${SUF}" "dtf-pp-c2-${SUF}" true)"
P0="$(create_oidc_provider "dtf-pp-p0-${SUF}" "dtf-pp-c0-${SUF}" false)"
[ -n "$P1" ] && [ -n "$P2" ] && [ -n "$P0" ] || fail_g "provider create failed (p1='$P1' p2='$P2' p0='$P0')"
note "P1=$P1 P2=$P2 P0(no mapping)=$P0 local_user=$LUID"
finish_case "setup failed; every later case depends on it"

# ---------------------------------------------------------------------------
# CONTROL: login-time group sync, unchanged by #4296 (both images).
# ---------------------------------------------------------------------------
begin_test "CONTROL login sync: claim auto-creates an oidc group + member; manual member write 409; claim removed -> membership pruned"
reset_case
GC="dtf-pp-ctl-${SUF}"; SC="dtf-pp-ctl-user-${SUF}"
ST1=$(drive_oidc_login "$P1" "$SC" "$GC")
GCID=$(g_id "$GC")
[ "$ST1" = "307" ] || fail_g "login with claim [$GC] answered $ST1 (expected 307)"
[ "$(g_src "$GC")" = "oidc/$P1" ] || fail_g "auto-created group source='$(g_src "$GC")' (expected oidc/$P1)"
[ -n "$GCID" ] && [ "$(oidc_member_of "$SC" "$GCID")" = "1" ] || fail_g "user not attached to auto-created group '$GC' (id='$GCID')"
if [ -n "$GCID" ] && [ -n "$LUID" ]; then
  C=$(req "$TOK" POST "/api/v1/groups/$GCID/members" "{\"user_ids\":[\"$LUID\"]}")
  note "admin manual add to login-created oidc group -> $C $(body | head -c 160)"
  [ "$C" = "409" ] || fail_g "manual member write on an oidc group answered $C (expected 409)"
  [ "$(g_members "$GC")" = "1" ] || fail_g "members of '$GC' = $(g_members "$GC") after refused write (expected 1)"
fi
ST2=$(drive_oidc_login "$P1" "$SC" "dtf-pp-other-${SUF}")
[ "$ST2" = "307" ] || fail_g "re-login without [$GC] answered $ST2"
[ -z "$(oidc_member_of "$SC" "$GCID")" ] || fail_g "membership in '$GC' not pruned after the claim disappeared"
[ "$(g_id "$GC")" = "$GCID" ] || fail_g "group row '$GC' changed id after prune ('$(g_id "$GC")' vs '$GCID')"
finish_case "login-time OIDC group sync regressed"

# ---------------------------------------------------------------------------
# CONTROL: a non-admin cannot reach the pre-provision route (403 on the fix,
# 404 on 1.11.3 where the route does not exist) and no row appears.
# ---------------------------------------------------------------------------
begin_test "CONTROL non-admin POST pre-provision -> 403/404, no group row"
reset_case
GN="dtf-pp-nonadmin-${SUF}"
C=$(preprovision "$LTOK" "$P1" "$GN")
note "non-admin preprovision -> $C $(body | head -c 160)"
case "$C" in 403|404) ;; *) fail_g "non-admin pre-provision answered $C (expected 403 or 404)";; esac
[ "$(g_rows "$GN")" = "0" ] || fail_g "non-admin call created group '$GN'"
finish_case "non-admin pre-provision not refused"

# ---------------------------------------------------------------------------
# FIX: admin pre-provision -> IdP-managed row with no members.
# ---------------------------------------------------------------------------
G="dtf-pp-grp-${SUF}"
begin_test "FIX #4297 admin pre-provision: 200, row exists (external_source=oidc, provider=P1), zero members"
reset_case
PRE=$(g_rows "$G")
C=$(preprovision "$TOK" "$P1" "$G"); B=$(body)
note "admin preprovision '$G' -> $C $(echo "$B" | head -c 220)"
GID=$(echo "$B" | jqr '.id // empty')
[ "$PRE" = "0" ] || fail_g "group '$G' existed before pre-provision"
[ "$C" = "200" ] || fail_g "pre-provision answered $C (expected 200)"
[ "$(echo "$B" | jqr '.name')" = "$G" ] || fail_g "response name != '$G'"
[ "$(echo "$B" | jqr '.external_source')" = "oidc" ] || fail_g "response external_source != oidc"
[ "$(echo "$B" | jqr '.external_provider_id')" = "$P1" ] || fail_g "response external_provider_id != P1"
[ "$(g_rows "$G")" = "1" ] || fail_g "DB rows named '$G' = $(g_rows "$G") (expected 1)"
[ -n "$GID" ] && [ "$(g_id "$G")" = "$GID" ] || fail_g "DB id '$(g_id "$G")' != response id '$GID'"
[ "$(g_src "$G")" = "oidc/$P1" ] || fail_g "DB source='$(g_src "$G")' (expected oidc/$P1)"
[ "$(g_members "$G")" = "0" ] || fail_g "pre-provisioned group has $(g_members "$G") members (expected 0)"
finish_case "admin pre-provision did not create an IdP-managed, memberless group"

begin_test "FIX #4297 idempotent: the same pre-provision again -> 200, same id, still one row"
reset_case
C=$(preprovision "$TOK" "$P1" "$G"); B=$(body)
note "repeat preprovision -> $C $(echo "$B" | head -c 160)"
[ "$C" = "200" ] || fail_g "repeat answered $C (expected 200)"
[ -n "$GID" ] && [ "$(echo "$B" | jqr '.id')" = "$GID" ] || fail_g "repeat id '$(echo "$B" | jqr '.id')' != first id '$GID'"
[ "$(g_rows "$G")" = "1" ] || fail_g "DB rows named '$G' = $(g_rows "$G") after repeat (expected 1)"
finish_case "pre-provision is not idempotent"

begin_test "FIX #4297 membership stays IdP-managed: admin add -> 409, non-admin self-add -> 403/404, zero members"
reset_case
if [ -z "$GID" ]; then
  fail_g "no pre-provisioned group id (pre-provision failed)"
else
  C=$(req "$TOK" POST "/api/v1/groups/$GID/members" "{\"user_ids\":[\"$LUID\"]}")
  note "admin add local user -> $C $(body | head -c 160)"
  [ "$C" = "409" ] || fail_g "admin manual member write answered $C (expected 409)"
  C=$(req "$LTOK" POST "/api/v1/groups/$GID/members" "{\"user_ids\":[\"$LUID\"]}")
  note "non-admin self-add -> $C $(body | head -c 160)"
  case "$C" in 403|404|409) ;; *) fail_g "non-admin self-add answered $C (expected 403/404/409)";; esac
  [ "$(g_members "$G")" = "0" ] || fail_g "members of '$G' = $(g_members "$G") after refused writes (expected 0)"
fi
finish_case "manual membership write on a pre-provisioned group was not refused"

begin_test "FIX #4297 a later OIDC login with claim G joins THE SAME row; a login without G prunes it"
reset_case
S="dtf-pp-user-${SUF}"
ST=$(drive_oidc_login "$P1" "$S" "$G")
note "login with [$G] -> $ST; group id now '$(g_id "$G")' rows=$(g_rows "$G")"
[ "$ST" = "307" ] || fail_g "login answered $ST (expected 307)"
[ -n "$GID" ] || fail_g "no pre-provisioned id to compare against (pre-provision failed)"
[ "$(g_rows "$G")" = "1" ] || fail_g "rows named '$G' = $(g_rows "$G") after login (expected 1, no duplicate)"
[ -n "$GID" ] && [ "$(g_id "$G")" = "$GID" ] || fail_g "group id after login '$(g_id "$G")' != pre-provisioned '$GID'"
[ -n "$GID" ] && [ "$(oidc_member_of "$S" "$GID")" = "1" ] || fail_g "user '$S' is not a member of the pre-provisioned row"
ST=$(drive_oidc_login "$P1" "$S" "dtf-pp-other-${SUF}")
note "re-login without [$G] -> $ST; members=$(g_members "$G")"
[ "$ST" = "307" ] || fail_g "re-login answered $ST"
[ -n "$GID" ] && [ -z "$(oidc_member_of "$S" "$GID")" ] || fail_g "membership not pruned after claim removed"
[ -n "$GID" ] && [ "$(g_id "$G")" = "$GID" ] && [ "$(g_rows "$G")" = "1" ] || fail_g "pre-provisioned row did not survive the prune unchanged"
finish_case "login did not join the pre-provisioned row (or did not prune)"

begin_test "FIX #4297 guards: local-owned 409, other-provider-owned 409, unknown provider 404, mapping off 400, empty name 400"
reset_case
GL="dtf-pp-local-grp-${SUF}"
CL=$(req "$TOK" POST "/api/v1/groups" "{\"name\":\"$GL\",\"description\":\"dtf local\"}")
[ "$CL" = "200" ] || [ "$CL" = "201" ] || fail_g "local group create answered $CL"
C=$(preprovision "$TOK" "$P1" "$GL"); note "local-owned name -> $C $(body | head -c 140)"
[ "$C" = "409" ] || fail_g "pre-provision of a local group's name answered $C (expected 409)"
[ "$(g_src "$GL")" = "NULL/NULL" ] && [ "$(g_rows "$GL")" = "1" ] || fail_g "local group '$GL' was taken over (source='$(g_src "$GL")')"
GP2="dtf-pp-p2grp-${SUF}"
C2=$(preprovision "$TOK" "$P2" "$GP2"); note "P2 owns '$GP2' -> $C2"
C=$(preprovision "$TOK" "$P1" "$GP2"); note "P1 claims P2's name -> $C $(body | head -c 140)"
[ "$C2" = "200" ] || fail_g "P2 pre-provision answered $C2 (expected 200)"
[ "$C" = "409" ] || fail_g "cross-provider pre-provision answered $C (expected 409)"
[ "$(g_src "$GP2")" = "oidc/$P2" ] || fail_g "P2's group owner changed to '$(g_src "$GP2")'"
C=$(preprovision "$TOK" "00000000-0000-4000-8000-$(printf '%012d' "$DTF_SLOT")" "dtf-pp-nop-${SUF}"); note "unknown provider -> $C"
[ "$C" = "404" ] || fail_g "unknown provider answered $C (expected 404)"
C=$(preprovision "$TOK" "$P0" "dtf-pp-nomap-${SUF}"); note "mapping-off provider -> $C $(body | head -c 140)"
[ "$C" = "400" ] || fail_g "map_groups_to_groups=false provider answered $C (expected 400)"
[ "$(g_rows "dtf-pp-nomap-${SUF}")" = "0" ] || fail_g "mapping-off provider created a group"
C=$(preprovision "$TOK" "$P1" ""); note "empty name -> $C $(body | head -c 140)"
[ "$C" = "400" ] || fail_g "empty name answered $C (expected 400)"
finish_case "pre-provision ownership/provider/name guards"

end_suite
