#!/usr/bin/env bash
# =============================================================================
# tiers/oidc-env-config/oracle.sh -- OIDC env-bootstrap toggle oracle (#2792)
# =============================================================================
# run.sh has stood up filesystem/single + sso.oidc-bootstrap (backend booted
# with OIDC_ISSUER/CLIENT_ID/SECRET + OIDC_NAME + the three toggle env vars) and
# exported BASE_URL, DB_CONTAINER, ADMIN_USER/ADMIN_PASS, RELEASE_GATE=1,
# COMMON_SH, JUNIT_OUTPUT_DIR.
#
# WHAT IT TESTS: the env-bootstrap provider-toggle wiring added by #2792 /
# PR #2841 (main.rs build_oidc_request_from_values). At boot, AK reconciles an
# env-managed OIDC provider named OIDC_NAME from the OIDC_* env. This oracle
# logs in as admin, reads that provider back through the admin SSO API, and
# asserts its stored config reflects the env toggles:
#   * map_groups_to_groups == true   (OIDC_MAP_GROUPS_TO_GROUPS=true)  HEADLINE
#   * auto_create_users    == false  (OIDC_AUTO_CREATE_USERS=false)
#   * pkce_enabled         == false  (OIDC_PKCE_ENABLED=false)
#
# DISCRIMINATION: pre-#2792 the bootstrap hardcoded
#   auto_create_users: Some(true), pkce_enabled: None, map_groups_to_groups: None
# so the stored provider (via the service-layer create defaults) has
#   map_groups_to_groups=false, auto_create_users=true, pkce_enabled=true
# -- every one of the three assertions flips RED on a pre-fix image. On the fix
# each env var is honored -> GREEN. The stored config is read back both through
# the admin API (primary) AND the oidc_configs DB row (belt-and-suspenders).
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"
# shellcheck source=/dev/null
source "$COMMON_SH"

ADMPASS="${ADMIN_PASS:-TestRunner!2026secure}"
PROVIDER_NAME="dtf-env-bootstrap"   # must match OIDC_NAME in sso.oidc-bootstrap.yml

login() {
  curl -s -X POST "${BASE_URL}/api/v1/auth/login" -H 'Content-Type: application/json' \
    -d "{\"username\":\"$1\",\"password\":\"$2\"}" | jq -r '.access_token // empty'
}

# docker exec psql helper (single scalar).
db() {
  docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null \
    | tr -d '[:space:]'
}

begin_suite "oidc-env-config"

# ---- bootstrap -------------------------------------------------------------
TOK="$(login "${ADMIN_USER:-admin}" "$ADMPASS")"
if [ -z "$TOK" ]; then
  begin_test "admin login"
  fail "admin login to ${BASE_URL} failed (no access_token)"
  end_suite
fi

# Read the env-managed provider back through the admin SSO API. list_oidc
# returns an array of OidcConfigResponse; select the one named OIDC_NAME.
PROVIDER_JSON="$(curl -s "${BASE_URL}/api/v1/admin/sso/oidc" \
  -H "Authorization: Bearer ${TOK}" \
  | jq -c --arg n "$PROVIDER_NAME" '.[] | select(.name==$n)' 2>/dev/null)"

# ---------------------------------------------------------------------------
# CASE 0 -- PREMISE: the env-var bootstrap actually created the provider.
# ---------------------------------------------------------------------------
begin_test "CASE 0 premise: OIDC provider '${PROVIDER_NAME}' bootstrapped from env (OIDC_ISSUER/CLIENT_ID/SECRET)"
if [ -n "$PROVIDER_JSON" ] && [ "$PROVIDER_JSON" != "null" ]; then
  pass
else
  fail "env-bootstrapped OIDC provider '${PROVIDER_NAME}' not found via GET /api/v1/admin/sso/oidc" \
       "The required trio (OIDC_ISSUER/CLIENT_ID/SECRET) is set in the profile, so bootstrap_oidc_from_env must create a provider named '${PROVIDER_NAME}'. Absence means bootstrap did not run."
  end_suite
fi

MG_API="$(echo "$PROVIDER_JSON" | jq -r '.map_groups_to_groups')"
AC_API="$(echo "$PROVIDER_JSON" | jq -r '.auto_create_users')"
PK_API="$(echo "$PROVIDER_JSON" | jq -r '.pkce_enabled')"

# DB read-back (belt-and-suspenders; the admin API is the primary source).
MG_DB="$(db "SELECT map_groups_to_groups FROM oidc_configs WHERE name='${PROVIDER_NAME}' LIMIT 1")"
AC_DB="$(db "SELECT auto_create_users FROM oidc_configs WHERE name='${PROVIDER_NAME}' LIMIT 1")"
PK_DB="$(db "SELECT pkce_enabled FROM oidc_configs WHERE name='${PROVIDER_NAME}' LIMIT 1")"

# ---------------------------------------------------------------------------
# CASE 1 -- HEADLINE (#2792): OIDC_MAP_GROUPS_TO_GROUPS=true -> stored true.
# ---------------------------------------------------------------------------
begin_test "CASE 1 (#2792 HEADLINE): OIDC_MAP_GROUPS_TO_GROUPS=true -> stored map_groups_to_groups=true"
if [ "$MG_API" = "true" ] && [ "$MG_DB" = "t" ]; then
  pass
else
  fail "map_groups_to_groups not honored from env (api='$MG_API' db='$MG_DB', expected true/t)" \
       "OIDC_MAP_GROUPS_TO_GROUPS=true must make the bootstrapped provider store map_groups_to_groups=true. On a pre-#2792 image the env is ignored (hardcoded None -> stored false), which is exactly the gap this tier catches (RED api='false')."
fi

# ---------------------------------------------------------------------------
# CASE 2 (#2792): OIDC_AUTO_CREATE_USERS=false -> stored false (overrides the
# prior hardcoded Some(true) bootstrap default).
# ---------------------------------------------------------------------------
begin_test "CASE 2 (#2792): OIDC_AUTO_CREATE_USERS=false -> stored auto_create_users=false"
if [ "$AC_API" = "false" ] && [ "$AC_DB" = "f" ]; then
  pass
else
  fail "auto_create_users not honored from env (api='$AC_API' db='$AC_DB', expected false/f)" \
       "OIDC_AUTO_CREATE_USERS=false must override the prior hardcoded Some(true). On a pre-#2792 image the value is forced true (RED api='true')."
fi

# ---------------------------------------------------------------------------
# CASE 3 (#2792): OIDC_PKCE_ENABLED=false -> stored false (overrides the
# service-layer create default of true).
# ---------------------------------------------------------------------------
begin_test "CASE 3 (#2792): OIDC_PKCE_ENABLED=false -> stored pkce_enabled=false"
if [ "$PK_API" = "false" ] && [ "$PK_DB" = "f" ]; then
  pass
else
  fail "pkce_enabled not honored from env (api='$PK_API' db='$PK_DB', expected false/f)" \
       "OIDC_PKCE_ENABLED=false must override the service-layer default (true). On a pre-#2792 image the env is ignored (hardcoded None -> stored true) (RED api='true')."
fi

# ---- discrimination summary (printed, not a gate) --------------------------
echo ""
echo "=== DISCRIMINATION SUMMARY (why this tier guards #2792 / PR #2841) ==="
echo "  Backend booted with the OIDC_* bootstrap env; stored provider config:"
echo "    OIDC_MAP_GROUPS_TO_GROUPS=true  -> map_groups_to_groups api='${MG_API}' db='${MG_DB}'  (fix: true/t;  pre-fix: false/f)"
echo "    OIDC_AUTO_CREATE_USERS=false    -> auto_create_users    api='${AC_API}' db='${AC_DB}'  (fix: false/f; pre-fix: true/t)"
echo "    OIDC_PKCE_ENABLED=false         -> pkce_enabled         api='${PK_API}' db='${PK_DB}'  (fix: false/f; pre-fix: true/t)"
echo "  All three flip on a pre-#2792 image (env ignored, hardcoded defaults)."

end_suite
