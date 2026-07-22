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

# create_oidc_provider <name> <client_id> <map_groups:true|false> <extra_json_obj>
# -> prints the provider UUID. <extra_json_obj> is merged into the request body
# ('{}' for none, '{"trust_group_names":true}' for the Fix-C opt-in probe).
create_oidc_provider() {
  local name="$1" cid="$2" mg="$3" extra="$4" body
  body=$(jq -n --arg name "$name" --arg iss "$ISSUER" --arg cid "$cid" \
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

# ---- discrimination summary (printed, not a gate) --------------------------
echo ""
echo "=== DISCRIMINATION SUMMARY (why this tier catches the OIDC group-sync class) ==="
echo "  One live backend, one mock IdP, four claims:"
echo "    - brand-new name              -> auto-create oidc group + attach   (CASE 1)"
echo "    - operator NULL-source name   -> NOT attached, group stays NULL     (CASE 2, #2759)"
echo "    - operator name + trust ON    -> attached                           (CASE 3, pending #2823)"
echo "    - another provider's oidc name-> NOT attached, owner unchanged       (CASE 4)"
echo "  CASE 2 flips RED (user attached) on a pre-#2759 image -- that contrast"
echo "  is the regression guard. CASE 3 stays a clean skip until #2823 ships."

end_suite
