#!/usr/bin/env bash
# =============================================================================
# tiers/oidc-group-sync/oracle.sh -- OIDC group-sync discriminating oracle
# =============================================================================
# run.sh has stood up filesystem/single + sso=oidc (the headless mock IdP,
# profiles/sso.oidc.yml) and exported BASE_URL, DB_CONTAINER, ADMIN_USER/
# ADMIN_PASS, RELEASE_GATE=1, COMMON_SH, JUNIT_OUTPUT_DIR, HTTP_PORT/PG_PORT/
# TRIVY_PORT, DTF_DIR/DTF_SLOT.
#
# WHAT IT TESTS: AK's OIDC group synchronisation (sync_oidc_groups_to_local_
# groups in backend/src/api/handlers/sso.rs). SAML has DTF coverage via the
# `sso` tier; OIDC had none, which is how the 1.6.1 group-sync regression
# (#2759) shipped. This oracle drives the REAL OIDC login -> callback flow and
# asserts the resulting rows in `groups` / `user_group_members`, not just HTTP
# codes.
#
# HOW THE HEADLESS FLOW IS DRIVEN (no browser):
#   AK mints the CSRF `state` + replay `nonce` at /oidc/{id}/login and redirects
#   to the mock's authorization_endpoint carrying them. The oracle plays the
#   user-agent in three curls:
#     1. GET AK /oidc/{id}/login            -> 307 to mock /authorize?...state,nonce,redirect_uri
#     2. GET that mock /authorize URL, appending this login's claim controls
#        (&sub=&email=&groups=)             -> 302 to AK callback with an opaque
#                                              `code` (mock baked {nonce,sub,
#                                              email,groups} into it, stateless)
#     3. GET AK's callback URL              -> AK server-side exchanges the code
#                                              at the mock /token, verifies the
#                                              RS256 id_token against /jwks,
#                                              extracts `groups`, runs group sync
#                                              -> 307 (login OK) or 4xx (reject)
#   Because the claims ride inside the code, the oracle controls the groups (and
#   which user) PER LOGIN with zero shared state and no container restarts.
#
# See harness/tiers/oidc-group-sync/fixtures/mock_oidc.py for the mock.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"
# shellcheck source=/dev/null
source "$COMMON_SH"

ADMPASS="${ADMIN_PASS:-TestRunner!2026secure}"
ISSUER="http://mock-oidc"
SUF="$(date +%s)-${DTF_SLOT:-x}"
MOCK_PORT="${TRIVY_PORT:-}"   # mock host port (slot spare), see sso.oidc.yml

# --- HTTP helpers ------------------------------------------------------------
login() {
  curl -s -X POST "${BASE_URL}/api/v1/auth/login" -H 'Content-Type: application/json' \
    -d "{\"username\":\"$1\",\"password\":\"$2\"}" | jq -r '.access_token // empty'
}

# create_oidc_provider <name> <client_id> <map_groups:true|false> <extra_json_obj> [issuer_url]
# -> prints the provider UUID. <extra_json_obj> is merged into the request body
# ('{}' for none, '{"trust_group_names":true}' for the Fix-C opt-in probe).
# [issuer_url] defaults to $ISSUER; the userinfo SSRF case passes a sub-path
# issuer whose discovery advertises a blocked userinfo_endpoint.
create_oidc_provider() {
  local name="$1" cid="$2" mg="$3" extra="$4" iss="${5:-$ISSUER}" body
  body=$(jq -n --arg name "$name" --arg iss "$iss" --arg cid "$cid" \
    --argjson mg "$mg" --argjson extra "$extra" \
    '{name:$name, issuer_url:$iss, client_id:$cid, client_secret:"dtf-oidc-secret",
      is_enabled:true, auto_create_users:true, pkce_enabled:false,
      map_groups_to_groups:$mg} + $extra')
  curl -s -X POST "${BASE_URL}/api/v1/admin/sso/oidc" \
    -H "Authorization: Bearer ${TOK}" -H 'Content-Type: application/json' \
    -d "$body" | jq -r '.id // empty'
}

# provider_has_trust_capability <provider_id> -> "yes" | "no"
# Round-trip probe for the pending #2823 field: the admin API silently ignores
# unknown request fields (no deny_unknown_fields), so a rejected-request probe
# would give a false negative. Instead we read the provider back and check
# whether `trust_group_names` round-tripped into the response. Absent on
# release/1.6.x (field not shipped) -> "no"; present on the Fix-C image -> "yes".
provider_has_trust_capability() {
  curl -s "${BASE_URL}/api/v1/admin/sso/oidc/$1" \
    -H "Authorization: Bearer ${TOK}" \
    | jq -r 'if .trust_group_names == true then "yes" else "no" end'
}

# drive_oidc_login <provider_id> <sub> <email> <groups_csv> -> AK callback status
drive_oidc_login() {
  local pid="$1" sub="$2" email="$3" groups="$4" authz cb
  authz=$(curl -s -o /dev/null -w '%{redirect_url}' \
    "${BASE_URL}/api/v1/auth/sso/oidc/${pid}/login")
  [ -z "$authz" ] && { echo "000-no-login-redirect"; return; }
  # Hand /authorize to the mock, appending this login's claim controls. The
  # mock echoes AK's state and returns an opaque signed-claims code.
  cb=$(curl -s -o /dev/null -w '%{redirect_url}' \
    "${authz}&sub=${sub}&email=${email}&groups=${groups}")
  [ -z "$cb" ] && { echo "000-no-authorize-redirect"; return; }
  # Follow to AK's callback: server-side token exchange + id_token verify +
  # group sync run here (synchronously, before the 307), so the DB is settled
  # by the time this returns.
  curl -s -o /dev/null -w '%{http_code}' "$cb"
}

# drive_oidc_login_ex <provider_id> <sub> <email> <extra_authorize_query>
#   -> AK callback status. Same as drive_oidc_login but the caller supplies the
#   full claim-control query fragment (so it can OMIT the `groups` key entirely,
#   set a non-`groups` primary claim, add a second claim, or drive the userinfo
#   params). e.g. extra="groups_claim=groups_direct&groups=platform%2Fbackend".
drive_oidc_login_ex() {
  local pid="$1" sub="$2" email="$3" extra="$4" authz cb
  authz=$(curl -s -o /dev/null -w '%{redirect_url}' \
    "${BASE_URL}/api/v1/auth/sso/oidc/${pid}/login")
  [ -z "$authz" ] && { echo "000-no-login-redirect"; return; }
  cb=$(curl -s -o /dev/null -w '%{redirect_url}' \
    "${authz}&sub=${sub}&email=${email}&${extra}")
  [ -z "$cb" ] && { echo "000-no-authorize-redirect"; return; }
  curl -s -o /dev/null -w '%{http_code}' "$cb"
}

# count of OIDC-source group memberships for external_id=$1 -> integer string
db_oidc_member_count() {
  db "SELECT count(*) FROM user_group_members m
      JOIN users u ON u.id = m.user_id
      JOIN groups g ON g.id = m.group_id
      WHERE u.external_id='$1' AND u.auth_provider='oidc'
        AND g.external_source='oidc'"
}

# --- DB helpers (docker exec psql, prove.sh style) --------------------------
db() {
  docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null \
    | tr -d '[:space:]'
}
# is the oidc user (external_id=$1) a member of group $2? -> "1" | ""
db_member() {
  db "SELECT 1 FROM user_group_members m
      JOIN users u ON u.id = m.user_id
      JOIN groups g ON g.id = m.group_id
      WHERE u.external_id='$1' AND u.auth_provider='oidc' AND g.name='$2' LIMIT 1"
}
# external_source of group $1 -> 'oidc' | 'NULL' | '' (no such group)
db_group_source() {
  db "SELECT COALESCE(external_source,'NULL') FROM groups WHERE name='$1'"
}
# create an operator-managed group (NULL external_source) named $1
db_make_operator_group() {
  db "INSERT INTO groups (name, description) VALUES ('$1','dtf operator managed')
      ON CONFLICT (name) DO NOTHING" >/dev/null
}
# is the oidc user (external_id=$1) an admin? -> "t" | "f" | "" (no such user)
db_is_admin() {
  db "SELECT is_admin FROM users WHERE external_id='$1' AND auth_provider='oidc' LIMIT 1"
}
# directly set is_admin on the oidc user (external_id=$1) to model an operator grant
db_set_admin() {
  db "UPDATE users SET is_admin=true WHERE external_id='$1' AND auth_provider='oidc'" >/dev/null
}

# Backend container name (base compose: ak-dtf<slot>-backend). Used to assert the
# CASE 5 premise that OIDC_ADMIN_GROUP is unset in the profile env.
BACKEND_CONTAINER="${DB_CONTAINER%-db}-backend"

# =============================================================================
begin_suite "oidc-group-sync"

# ---- bootstrap -------------------------------------------------------------
TOK="$(login "${ADMIN_USER:-admin}" "$ADMPASS")"
if [ -z "$TOK" ]; then
  begin_test "admin login"
  fail "admin login to ${BASE_URL} failed (no access_token)"
  end_suite
fi

begin_test "mock OIDC IdP serves discovery + JWKS on host port :${MOCK_PORT}"
if [ -z "$MOCK_PORT" ]; then
  fail "TRIVY_PORT (mock host port) not exported by run.sh"
else
  DISC=$(curl -s "http://127.0.0.1:${MOCK_PORT}/.well-known/openid-configuration")
  JWKS=$(curl -s "http://127.0.0.1:${MOCK_PORT}/jwks")
  if echo "$DISC" | jq -e '.issuer and .authorization_endpoint and .token_endpoint and .jwks_uri' >/dev/null 2>&1 \
     && echo "$JWKS" | jq -e '.keys[0].kty=="RSA" and (.keys[0].n|length>0)' >/dev/null 2>&1; then
    pass
  else
    fail "mock discovery/JWKS malformed on :${MOCK_PORT}" \
         "discovery=$(echo "$DISC" | head -c 300) jwks=$(echo "$JWKS" | head -c 200)"
  fi
fi

# Provider 1: the primary OIDC provider (group mapping ON, trust OFF/default).
P1="$(create_oidc_provider "dtf-oidc-p1-${SUF}" "dtf-client-p1-${SUF}" true '{}')"
begin_test "provision OIDC provider 1 (issuer=${ISSUER}, map_groups_to_groups=true, trust default OFF)"
if [ -n "$P1" ] && [ "$P1" != "null" ]; then
  pass
else
  fail "could not create OIDC provider via POST /api/v1/admin/sso/oidc"
  end_suite
fi

# ---------------------------------------------------------------------------
# CASE 1 -- HAPPY PATH: claim auto-creates an OIDC group and attaches the user.
# ---------------------------------------------------------------------------
begin_test "CASE 1 happy path: claim [gitlab-devs] auto-creates group (external_source=oidc) and attaches user"
G1="gitlab-devs-${SUF}"
SUB1="dev1-${SUF}"
ST=$(drive_oidc_login "$P1" "$SUB1" "${SUB1}@dtf.test" "$G1")
MEM=$(db_member "$SUB1" "$G1")
SRC=$(db_group_source "$G1")
if [ "$ST" = "307" ] && [ "$MEM" = "1" ] && [ "$SRC" = "oidc" ]; then
  pass
else
  fail "happy-path OIDC group sync failed (login_status=$ST member='$MEM' group_source='$SRC')" \
       "Expected 307 + membership row + groups.external_source='oidc' for auto-created '${G1}'."
fi

# ---------------------------------------------------------------------------
# CASE 2 -- #2759 GUARD: an operator (NULL-external_source) group is NOT hijacked
# by a matching OIDC claim when provider trust is OFF (the default).
# ---------------------------------------------------------------------------
begin_test "CASE 2 (#2759 guard): OIDC claim matching an operator NULL-source group does NOT attach the user (trust OFF)"
OPG2="platform-admins-${SUF}"
SUB2="dev2-${SUF}"
db_make_operator_group "$OPG2"
PRE_SRC=$(db_group_source "$OPG2")   # must be NULL before login
ST=$(drive_oidc_login "$P1" "$SUB2" "${SUB2}@dtf.test" "$OPG2")
MEM=$(db_member "$SUB2" "$OPG2")
POST_SRC=$(db_group_source "$OPG2")  # must remain NULL (sync never adopts it)
if [ "$ST" = "307" ] && [ "$PRE_SRC" = "NULL" ] && [ -z "$MEM" ] && [ "$POST_SRC" = "NULL" ]; then
  pass
else
  fail "operator-group guard breached (login_status=$ST pre_source='$PRE_SRC' member='$MEM' post_source='$POST_SRC')" \
       "Pre-#2759 a matching OIDC claim adopted the operator's NULL-source '${OPG2}' and attached the user. The guard must leave it NULL and unattached. On a pre-#2759 image this case is RED (member='1'), which is exactly the regression this tier catches."
fi

# ---------------------------------------------------------------------------
# CASE 3 -- FIX-C OPT-IN (pending #2823): with trust_group_names=true the user
# IS attached to the operator group. The field is not shipped on release/1.6.x,
# so this is authored as a capability-gated SKIP (pending #2823) that flips to a
# HARD ASSERTION the moment the Fix-C image round-trips the field.
#
# WHY A SKIP, NOT AN EXPECTED-RED: the admin API silently ignores unknown body
# fields, so on the current image trust is simply absent -> the user is NOT
# attached -> a bare "assert attached" would be a genuine FAIL, wrongly reddening
# the tier. A capability probe (create with the field, read it back) cleanly
# separates "feature not shipped yet" (skip) from "feature shipped but broken"
# (fail), so the case is inert on 1.6.x and load-bearing on the Fix-C image
# without any edit -- only #2823 landing changes the outcome.
# ---------------------------------------------------------------------------
begin_test "CASE 3 (pending #2823): trust_group_names=true attaches the user to the operator group"
OPG3="platform-admins-fixc-${SUF}"
SUB3="dev3-${SUF}"
db_make_operator_group "$OPG3"
P3="$(create_oidc_provider "dtf-oidc-p3-${SUF}" "dtf-client-p3-${SUF}" true '{"trust_group_names":true}')"
if [ -z "$P3" ] || [ "$P3" = "null" ]; then
  fail "could not create OIDC provider for the trust_group_names probe"
elif [ "$(provider_has_trust_capability "$P3")" != "yes" ]; then
  skip "trust_group_names not shipped on this image (pending #2823); Fix-C opt-in gate is inert until #2823 lands"
else
  ST=$(drive_oidc_login "$P3" "$SUB3" "${SUB3}@dtf.test" "$OPG3")
  MEM=$(db_member "$SUB3" "$OPG3")
  SRC=$(db_group_source "$OPG3")
  if [ "$ST" = "307" ] && [ "$MEM" = "1" ] && [ "$SRC" = "NULL" ]; then
    pass
  else
    fail "trust_group_names opt-in did not attach the user (login_status=$ST member='$MEM' group_source='$SRC')" \
         "With trust_group_names=true the OIDC user MUST be attached to the operator group '${OPG3}', while the group stays operator-owned (external_source NULL)."
  fi
fi

# ---------------------------------------------------------------------------
# CASE 4 -- CROSS-PROVIDER INVARIANT: an OIDC group OWNED by provider 2 is not
# hijacked by a matching claim from provider 1 (refused independent of trust).
# ---------------------------------------------------------------------------
begin_test "CASE 4 cross-provider: a claim matching another OIDC provider's group does NOT attach the user"
P2="$(create_oidc_provider "dtf-oidc-p2-${SUF}" "dtf-client-p2-${SUF}" true '{}')"
OG="other-oidc-grp-${SUF}"
SUBP2="p2user-${SUF}"
SUB4="dev4-${SUF}"
if [ -z "$P2" ] || [ "$P2" = "null" ]; then
  fail "could not create second OIDC provider for the cross-provider case"
else
  # Setup: provider 2 legitimately owns OG (auto-created external_source=oidc,
  # external_provider_id=P2) and attaches its own user.
  ST_SETUP=$(drive_oidc_login "$P2" "$SUBP2" "${SUBP2}@dtf.test" "$OG")
  SETUP_MEM=$(db_member "$SUBP2" "$OG")
  # Attack: provider 1 emits the SAME group name for a different user.
  ST=$(drive_oidc_login "$P1" "$SUB4" "${SUB4}@dtf.test" "$OG")
  MEM=$(db_member "$SUB4" "$OG")
  OWNER=$(db "SELECT external_provider_id FROM groups WHERE name='$OG'")
  if [ "$ST_SETUP" = "307" ] && [ "$SETUP_MEM" = "1" ] && [ "$ST" = "307" ] && [ -z "$MEM" ] && [ "$OWNER" = "$P2" ]; then
    pass
  else
    fail "cross-provider group boundary breached (setup_status=$ST_SETUP setup_member='$SETUP_MEM' p1_status=$ST p1_member='$MEM' group_owner='$OWNER' expected_owner='$P2')" \
         "Provider 2 owns '${OG}'. A provider-1 claim of the same name must NOT attach the provider-1 user; the group's external_provider_id must remain provider 2."
  fi
fi

# ---------------------------------------------------------------------------
# CASE 5 -- #2829 GUARD (default-open admin escalation): with NO admin group
# configured (P1: attribute_mapping={}, OIDC_ADMIN_GROUP unset), a self-asserted
# group claim MUST NOT grant admin. Pre-fix, map_groups_to_roles fell back to a
# case-insensitive substring match against a hardcoded admin-pattern list, so any
# claim containing "admin" (e.g. backend-admins) or matching a pattern set
# users.is_admin=true. RED on the pre-fix image (is_admin='t'), GREEN on the fix.
# Also proves operator-granted admin is PRESERVED across a federated re-login
# (is_admin stays None from the claim -> COALESCE keeps the prior value).
# ---------------------------------------------------------------------------
begin_test "CASE 5 (#2829 guard): OIDC_ADMIN_GROUP unset in profile env (CASE 5 premise)"
OAG=$(docker exec "$BACKEND_CONTAINER" printenv OIDC_ADMIN_GROUP 2>/dev/null || true)
if [ -z "$OAG" ]; then
  pass
else
  fail "OIDC_ADMIN_GROUP is set ('${OAG}') in the backend env; CASE 5's 'no admin group configured' premise is invalid" \
       "The oidc-group-sync profile must not set OIDC_ADMIN_GROUP, otherwise required_admin_group is not None and the default-open path is not exercised."
fi

begin_test "CASE 5 (#2829 guard): no admin group -> claim 'nonadmin-users'/'backend-admins' does NOT grant admin"
SUB5A="dev5a-${SUF}"
SUB5B="dev5b-${SUF}"
ST5A=$(drive_oidc_login "$P1" "$SUB5A" "${SUB5A}@dtf.test" "nonadmin-users")
ADM5A=$(db_is_admin "$SUB5A")
ST5B=$(drive_oidc_login "$P1" "$SUB5B" "${SUB5B}@dtf.test" "backend-admins")
ADM5B=$(db_is_admin "$SUB5B")
if [ "$ST5A" = "307" ] && [ "$ADM5A" != "t" ] && [ "$ST5B" = "307" ] && [ "$ADM5B" != "t" ]; then
  pass
else
  fail "default-open admin escalation (login5a=$ST5A is_admin5a='$ADM5A' login5b=$ST5B is_admin5b='$ADM5B')" \
       "With no admin group configured a self-asserted claim MUST NOT set users.is_admin. On a pre-#2829 image both users are is_admin='t' (RED), which is exactly the escalation this case catches."
fi

begin_test "CASE 5 (#2829): operator-granted admin is PRESERVED across a federated re-login (not demoted)"
SUB5C="dev5c-${SUF}"
# First login (creates the user, no admin group -> not admin).
ST5C1=$(drive_oidc_login "$P1" "$SUB5C" "${SUB5C}@dtf.test" "readonly-users")
# Operator grants admin directly on the user.
db_set_admin "$SUB5C"
PRE5C=$(db_is_admin "$SUB5C")
# Re-login with a non-admin claim: is_admin from the claim is None -> COALESCE
# preserves the operator grant.
ST5C2=$(drive_oidc_login "$P1" "$SUB5C" "${SUB5C}@dtf.test" "readonly-users")
POST5C=$(db_is_admin "$SUB5C")
if [ "$ST5C1" = "307" ] && [ "$PRE5C" = "t" ] && [ "$ST5C2" = "307" ] && [ "$POST5C" = "t" ]; then
  pass
else
  fail "operator-granted admin not preserved (login1=$ST5C1 pre='$PRE5C' login2=$ST5C2 post='$POST5C')" \
       "An operator who set is_admin=true directly must stay admin after a federated re-login (the claim path never clears is_admin)."
fi

# ---------------------------------------------------------------------------
# CASE 6 -- #2829 EXACT-MATCH: with an admin group explicitly configured
# (attribute_mapping.admin_group), admin is granted ONLY on an exact
# (case-insensitive) claim match -- never a substring/prefix/suffix.
# ---------------------------------------------------------------------------
begin_test "CASE 6 (#2829 exact-match): configured admin_group grants admin ONLY on exact claim (no substring)"
AG6="platform-admins-${SUF}"
P6="$(create_oidc_provider "dtf-oidc-p6-${SUF}" "dtf-client-p6-${SUF}" true \
  "{\"attribute_mapping\":{\"admin_group\":\"${AG6}\"}}")"
if [ -z "$P6" ] || [ "$P6" = "null" ]; then
  fail "could not create OIDC provider with configured admin_group for CASE 6"
else
  SUB6A="dev6a-${SUF}"   # exact -> admin
  SUB6B="dev6b-${SUF}"   # suffix -> NOT admin
  SUB6C="dev6c-${SUF}"   # prefix/short -> NOT admin
  ST6A=$(drive_oidc_login "$P6" "$SUB6A" "${SUB6A}@dtf.test" "$AG6")
  ADM6A=$(db_is_admin "$SUB6A")
  ST6B=$(drive_oidc_login "$P6" "$SUB6B" "${SUB6B}@dtf.test" "${AG6}-x")
  ADM6B=$(db_is_admin "$SUB6B")
  ST6C=$(drive_oidc_login "$P6" "$SUB6C" "${SUB6C}@dtf.test" "platform-admin-${SUF}")
  ADM6C=$(db_is_admin "$SUB6C")
  if [ "$ST6A" = "307" ] && [ "$ADM6A" = "t" ] \
     && [ "$ST6B" = "307" ] && [ "$ADM6B" != "t" ] \
     && [ "$ST6C" = "307" ] && [ "$ADM6C" != "t" ]; then
    pass
  else
    fail "admin_group exact-match breached (exact:login=$ST6A adm='$ADM6A' suffix:login=$ST6B adm='$ADM6B' prefix:login=$ST6C adm='$ADM6C')" \
         "Configured admin_group='${AG6}': claim '${AG6}' -> admin; '${AG6}-x' and 'platform-admin-${SUF}' -> NOT admin (exact match only, no substring)."
  fi
fi

# ===========================================================================
# #2831 -- OIDC group memberships from candidate claims (GitLab groups_direct)
# + userinfo merge (inherited subgroups). Provider P1 has no explicit
# groups_claim, so the candidate fallback ["groups","groups_direct","roles"]
# engages. Cases use drive_oidc_login_ex so they can omit the `groups` key,
# set a non-`groups` primary claim, or drive the userinfo params.
# ===========================================================================

# ---------------------------------------------------------------------------
# CASE 7 -- GitLab out-of-box (HEADLINE): groups_direct path values, no explicit
# claim. Mock emits under groups_direct only (no `groups` key), one top-level
# group and one subgroup path.
# ---------------------------------------------------------------------------
begin_test "CASE 7 (#2831 HEADLINE): GitLab groups_direct path values with no explicit claim auto-create both groups + attach"
SUB7="dev7-${SUF}"
G7_TOP="platform-${SUF}"
G7_SUB="platform-${SUF}/backend"
ST7=$(drive_oidc_login_ex "$P1" "$SUB7" "${SUB7}@dtf.test" \
  "groups_claim=groups_direct&groups=platform-${SUF}%2Cplatform-${SUF}%2Fbackend")
MEM7_TOP=$(db_member "$SUB7" "$G7_TOP")
MEM7_SUB=$(db_member "$SUB7" "$G7_SUB")
SRC7_TOP=$(db_group_source "$G7_TOP")
SRC7_SUB=$(db_group_source "$G7_SUB")
if [ "$ST7" = "307" ] \
   && [ "$MEM7_TOP" = "1" ] && [ "$MEM7_SUB" = "1" ] \
   && [ "$SRC7_TOP" = "oidc" ] && [ "$SRC7_SUB" = "oidc" ]; then
  pass
else
  fail "GitLab groups_direct not synced (login=$ST7 top_member='$MEM7_TOP' sub_member='$MEM7_SUB' top_src='$SRC7_TOP' sub_src='$SRC7_SUB')" \
       "P1 has no explicit groups_claim; the id_token carries paths under 'groups_direct'. Candidate fallback must resolve them and auto-create '${G7_TOP}' and '${G7_SUB}' (external_source=oidc) and attach ${SUB7}. RED on a pre-#2831 image (reads only 'groups')."
fi

# ---------------------------------------------------------------------------
# CASE 8 -- Explicit override honored (no accidental multi-name). P8 pins
# groups_claim="groups"; the mock emits ONLY groups_direct (id_token AND
# userinfo), so neither source yields a value for the explicit 'groups' claim.
# ---------------------------------------------------------------------------
begin_test "CASE 8 (#2831): explicit groups_claim='groups' is NOT supplemented by groups_direct (id_token or userinfo)"
SUB8="dev8-${SUF}"
G8="explicit-honored-${SUF}"
P8="$(create_oidc_provider "dtf-oidc-p8-${SUF}" "dtf-client-p8-${SUF}" true \
  '{"attribute_mapping":{"groups_claim":"groups"}}')"
if [ -z "$P8" ] || [ "$P8" = "null" ]; then
  fail "could not create OIDC provider P8 with explicit groups_claim"
else
  ST8=$(drive_oidc_login_ex "$P8" "$SUB8" "${SUB8}@dtf.test" \
    "groups_claim=groups_direct&groups=${G8}&ui_groups_claim=groups_direct&ui_groups=${G8}")
  MEM8=$(db_member "$SUB8" "$G8")
  SRC8=$(db_group_source "$G8")
  if [ "$ST8" = "307" ] && [ -z "$MEM8" ] && [ -z "$SRC8" ]; then
    pass
  else
    fail "explicit groups_claim leaked a groups_direct value (login=$ST8 member='$MEM8' group_src='$SRC8')" \
         "P8 configures groups_claim='groups'. A groups_direct-only login must attach NOTHING and NOT create '${G8}'."
  fi
fi

# ---------------------------------------------------------------------------
# CASE 9 -- Full-path naming rule (no last-segment split). Reuses CASE 7's
# subgroup: the group is named by its FULL path, and a bare last-segment
# 'backend' group is NEVER created for this user.
# ---------------------------------------------------------------------------
begin_test "CASE 9 (#2831): subgroup uses the FULL path name, never the collapsed last segment 'backend'"
MEM9_FULL=$(db_member "$SUB7" "$G7_SUB")
MEM9_LEAF=$(db_member "$SUB7" "backend")
SRC9_LEAF=$(db_group_source "backend")
if [ "$MEM9_FULL" = "1" ] && [ -z "$MEM9_LEAF" ] && { [ "$SRC9_LEAF" = "" ] || [ "$SRC9_LEAF" = "NULL" ]; }; then
  pass
else
  fail "path naming collapsed to last segment (full_member='$MEM9_FULL' leaf_member='$MEM9_LEAF' leaf_src='$SRC9_LEAF')" \
       "The GitLab path '${G7_SUB}' must be stored verbatim as the group name; a last-segment 'backend' group must not exist or hold this user (Option (a) full-path)."
fi

# ---------------------------------------------------------------------------
# CASE 10 -- Precedence (candidate order groups > groups_direct > roles). Same
# login emits BOTH claims with different values; 'groups' must win.
# ---------------------------------------------------------------------------
begin_test "CASE 10 (#2831): candidate precedence -- 'groups' wins over 'groups_direct'"
SUB10="dev10-${SUF}"
G10_WIN="from-groups-${SUF}"
G10_LOSE="from-direct-${SUF}"
ST10=$(drive_oidc_login_ex "$P1" "$SUB10" "${SUB10}@dtf.test" \
  "groups_claim=groups&groups=${G10_WIN}&groups_claim2=groups_direct&groups2=${G10_LOSE}")
MEM10_WIN=$(db_member "$SUB10" "$G10_WIN")
MEM10_LOSE=$(db_member "$SUB10" "$G10_LOSE")
if [ "$ST10" = "307" ] && [ "$MEM10_WIN" = "1" ] && [ -z "$MEM10_LOSE" ]; then
  pass
else
  fail "candidate precedence wrong (login=$ST10 groups_member='$MEM10_WIN' direct_member='$MEM10_LOSE')" \
       "When both 'groups' and 'groups_direct' are present, the first candidate ('groups') wins; '${G10_LOSE}' must NOT attach."
fi

# ---------------------------------------------------------------------------
# CASE 11 -- String-valued claim (single JSON string, not an array). The path
# must survive intact (slash is not a delimiter).
# ---------------------------------------------------------------------------
begin_test "CASE 11 (#2831): single-string groups_direct claim (a GitLab path) is synced intact"
SUB11="dev11-${SUF}"
G11="platform-${SUF}/data"
ST11=$(drive_oidc_login_ex "$P1" "$SUB11" "${SUB11}@dtf.test" \
  "groups_claim=groups_direct&groups_shape=string&groups=platform-${SUF}%2Fdata")
MEM11=$(db_member "$SUB11" "$G11")
SRC11=$(db_group_source "$G11")
if [ "$ST11" = "307" ] && [ "$MEM11" = "1" ] && [ "$SRC11" = "oidc" ]; then
  pass
else
  fail "string-shaped claim not synced intact (login=$ST11 member='$MEM11' src='$SRC11')" \
       "A single JSON-string groups_direct value '${G11}' must create that group (external_source=oidc) and attach ${SUB11}; the slash is preserved."
fi

# ---------------------------------------------------------------------------
# CASE 12 -- Empty / missing group claims -> no groups, no error, login 307.
# ---------------------------------------------------------------------------
begin_test "CASE 12 (#2831): all candidate claims empty/absent -> clean no-op (login 307, zero oidc memberships)"
SUB12="dev12-${SUF}"
ST12=$(drive_oidc_login_ex "$P1" "$SUB12" "${SUB12}@dtf.test" \
  "groups_claim=groups_direct&groups=&ui_groups=")
ADM12=$(db_is_admin "$SUB12")
CNT12=$(db_oidc_member_count "$SUB12")
if [ "$ST12" = "307" ] && [ -n "$ADM12" ] && [ "$CNT12" = "0" ]; then
  pass
else
  fail "empty-claims login not a clean no-op (login=$ST12 user_admin='$ADM12' oidc_member_count='$CNT12')" \
       "With no group values in any candidate claim (and empty userinfo), the user is created but holds ZERO oidc-source memberships; no 500."
fi

# ---------------------------------------------------------------------------
# CASE 13 -- roles third-candidate fallback.
# ---------------------------------------------------------------------------
begin_test "CASE 13 (#2831): 'roles' third-candidate fallback auto-creates + attaches"
SUB13="dev13-${SUF}"
G13="role-team-${SUF}"
ST13=$(drive_oidc_login_ex "$P1" "$SUB13" "${SUB13}@dtf.test" \
  "groups_claim=roles&groups=${G13}")
MEM13=$(db_member "$SUB13" "$G13")
SRC13=$(db_group_source "$G13")
if [ "$ST13" = "307" ] && [ "$MEM13" = "1" ] && [ "$SRC13" = "oidc" ]; then
  pass
else
  fail "roles fallback not synced (login=$ST13 member='$MEM13' src='$SRC13')" \
       "With only 'roles' populated, the third candidate must resolve '${G13}' (external_source=oidc) and attach ${SUB13}."
fi

# ---------------------------------------------------------------------------
# CASE 14 -- INHERITANCE (userinfo HEADLINE): id_token groups_direct carries
# only the DIRECT group, userinfo `groups` carries the effective set incl. the
# inherited subgroup. The user must be attached to BOTH.
# ---------------------------------------------------------------------------
begin_test "CASE 14 (#2831 HEADLINE): inherited subgroup from userinfo -- id_token direct=[platform], userinfo effective=[platform, platform/backend] -> BOTH synced"
SUB14="dev14-${SUF}"
G14_DIRECT="platform-${SUF}"
G14_INHERIT="platform-${SUF}/backend"
ST14=$(drive_oidc_login_ex "$P1" "$SUB14" "${SUB14}@dtf.test" \
  "groups_claim=groups_direct&groups=platform-${SUF}&ui_groups_claim=groups&ui_groups=platform-${SUF}%2Cplatform-${SUF}%2Fbackend")
MEM14_DIRECT=$(db_member "$SUB14" "$G14_DIRECT")
MEM14_INHERIT=$(db_member "$SUB14" "$G14_INHERIT")
SRC14_INHERIT=$(db_group_source "$G14_INHERIT")
if [ "$ST14" = "307" ] \
   && [ "$MEM14_DIRECT" = "1" ] && [ "$MEM14_INHERIT" = "1" ] \
   && [ "$SRC14_INHERIT" = "oidc" ]; then
  pass
else
  fail "inherited subgroup from userinfo not synced (login=$ST14 direct_member='$MEM14_DIRECT' inherited_member='$MEM14_INHERIT' inherited_src='$SRC14_INHERIT')" \
       "id_token carries only the direct group; the inherited '${G14_INHERIT}' arrives ONLY at /oauth/userinfo. Merging both sources must attach the user to BOTH. RED before the userinfo fix (id_token-only -> just '${G14_DIRECT}')."
fi

# ---------------------------------------------------------------------------
# CASE 15 -- userinfo-DOWN graceful: userinfo returns 500; id_token groups
# still sync, login still 307 (NON-FATAL fetch).
# ---------------------------------------------------------------------------
begin_test "CASE 15 (#2831): userinfo 500 -> login still 307 and id_token groups still sync (graceful degrade)"
SUB15="dev15-${SUF}"
G15="platform-${SUF}"
ST15=$(drive_oidc_login_ex "$P1" "$SUB15" "${SUB15}@dtf.test" \
  "groups_claim=groups_direct&groups=platform-${SUF}&ui_status=500")
MEM15=$(db_member "$SUB15" "$G15")
if [ "$ST15" = "307" ] && [ "$MEM15" = "1" ]; then
  pass
else
  fail "userinfo outage broke login or dropped id_token groups (login=$ST15 direct_member='$MEM15')" \
       "A 500 from /oauth/userinfo must be NON-FATAL: login still 307 and the id_token group '${G15}' still syncs."
fi

# ---------------------------------------------------------------------------
# CASE 16 -- userinfo SSRF guard: a provider whose discovery advertises an
# internal/blocked userinfo_endpoint. The fetch must be refused by
# validate_oidc_fetch_url; login still 307 on id_token groups only.
# ---------------------------------------------------------------------------
begin_test "CASE 16 (#2831 SEC-1): userinfo_endpoint on a blocked/internal host is refused; login still 307 with id_token groups only"
SUB16="dev16-${SUF}"
# Provider-unique group names: P16 is a distinct provider, so reusing a P1-owned
# name would be refused by the cross-provider guard (CASE 4) and mask the probe.
G16_DIRECT="ssrf-direct-${SUF}"
G16_LEAK="ssrf-userinfo-leak-${SUF}"
P16="$(create_oidc_provider "dtf-oidc-p16-${SUF}" "dtf-client-p16-${SUF}" true '{}' "${ISSUER}/ssrf")"
if [ -z "$P16" ] || [ "$P16" = "null" ]; then
  fail "could not create OIDC provider P16 for the userinfo SSRF probe"
else
  # id_token carries the direct group; the (blocked) userinfo would add G16_LEAK
  # if it were ever fetched. iss is baked to match the provider's sub-path issuer.
  ST16=$(drive_oidc_login_ex "$P16" "$SUB16" "${SUB16}@dtf.test" \
    "iss=${ISSUER}%2Fssrf&groups_claim=groups_direct&groups=ssrf-direct-${SUF}&ui_groups_claim=groups&ui_groups=ssrf-userinfo-leak-${SUF}")
  MEM16_DIRECT=$(db_member "$SUB16" "$G16_DIRECT")
  MEM16_LEAK=$(db_member "$SUB16" "$G16_LEAK")
  SRC16_LEAK=$(db_group_source "$G16_LEAK")
  if [ "$ST16" = "307" ] && [ "$MEM16_DIRECT" = "1" ] \
     && [ -z "$MEM16_LEAK" ] && { [ "$SRC16_LEAK" = "" ] || [ "$SRC16_LEAK" = "NULL" ]; }; then
    pass
  else
    fail "userinfo SSRF guard breached or login broke (login=$ST16 direct_member='$MEM16_DIRECT' leak_member='$MEM16_LEAK' leak_src='$SRC16_LEAK')" \
         "Discovery advertises userinfo_endpoint on a link-local host; validate_oidc_fetch_url must refuse the fetch so '${G16_LEAK}' is never created, while id_token group '${G16_DIRECT}' still syncs and login is 307."
  fi
fi

# ---------------------------------------------------------------------------
# CASE 17 -- merge dedup: a group present in BOTH id_token and userinfo yields
# exactly ONE membership; the inherited-only group adds a second.
# ---------------------------------------------------------------------------
begin_test "CASE 17 (#2831): overlapping id_token+userinfo group is not double-counted (merge dedup)"
SUB17="dev17-${SUF}"
G17_BOTH="platform-${SUF}"
G17_INHERIT="platform-${SUF}/backend"
ST17=$(drive_oidc_login_ex "$P1" "$SUB17" "${SUB17}@dtf.test" \
  "groups_claim=groups_direct&groups=platform-${SUF}&ui_groups_claim=groups&ui_groups=platform-${SUF}%2Cplatform-${SUF}%2Fbackend")
MEM17_BOTH=$(db_member "$SUB17" "$G17_BOTH")
MEM17_INHERIT=$(db_member "$SUB17" "$G17_INHERIT")
CNT17=$(db_oidc_member_count "$SUB17")
if [ "$ST17" = "307" ] && [ "$MEM17_BOTH" = "1" ] && [ "$MEM17_INHERIT" = "1" ] && [ "$CNT17" = "2" ]; then
  pass
else
  fail "merge dedup wrong (login=$ST17 both_member='$MEM17_BOTH' inherited_member='$MEM17_INHERIT' oidc_member_count='$CNT17')" \
       "'${G17_BOTH}' appears in BOTH id_token and userinfo; the union must dedup to exactly ONE membership, plus one for the inherited '${G17_INHERIT}' -> 2 total."
fi

# ---- discrimination summary (printed, not a gate) --------------------------
echo ""
echo "=== DISCRIMINATION SUMMARY (why this tier catches the OIDC group-sync class) ==="
echo "  One live backend, one mock IdP, claims covering group-sync AND admin mapping:"
echo "    - brand-new name              -> auto-create oidc group + attach   (CASE 1)"
echo "    - operator NULL-source name   -> NOT attached, group stays NULL     (CASE 2, #2759)"
echo "    - operator name + trust ON    -> attached                           (CASE 3, pending #2823)"
echo "    - another provider's oidc name-> NOT attached, owner unchanged       (CASE 4)"
echo "    - no admin group + admin-ish claim -> NOT admin; operator grant kept (CASE 5, #2829)"
echo "    - configured admin group, exact claim only -> admin (no substring)   (CASE 6, #2829)"
echo "    - GitLab groups_direct paths, no explicit claim -> auto-create both   (CASE 7, #2831)"
echo "    - explicit groups_claim -> groups_direct/userinfo NOT supplemented    (CASE 8, #2831)"
echo "    - subgroup stored as FULL path, no last-segment 'backend'             (CASE 9, #2831)"
echo "    - both claims present -> 'groups' wins (candidate precedence)          (CASE 10, #2831)"
echo "    - single-string path claim synced intact                              (CASE 11, #2831)"
echo "    - all candidates empty -> clean no-op, login 307                        (CASE 12, #2831)"
echo "    - 'roles' third-candidate fallback                                     (CASE 13, #2831)"
echo "    - inherited subgroup from /oauth/userinfo -> attached to BOTH          (CASE 14, #2831)"
echo "    - userinfo 500 -> login still 307 + id_token groups (graceful)         (CASE 15, #2831)"
echo "    - userinfo_endpoint on a blocked host -> refused, no leak group        (CASE 16, #2831)"
echo "    - overlapping id_token+userinfo group -> deduped to one membership     (CASE 17, #2831)"
echo "  CASE 2 flips RED (user attached) on a pre-#2759 image; CASE 5 flips RED"
echo "  (is_admin granted) on a pre-#2829 image. CASE 7 flips RED (no groups) and"
echo "  CASE 14 flips RED (inherited subgroup missing) on a pre-#2831 image --"
echo "  those contrasts are the regression guards. CASE 3 stays a clean skip"
echo "  until #2823 ships."

end_suite
