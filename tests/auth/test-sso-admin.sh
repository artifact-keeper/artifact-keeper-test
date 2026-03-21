#!/usr/bin/env bash
# test-sso-admin.sh - SSO provider CRUD E2E test
#
# Tests OIDC, LDAP, and SAML provider configuration management through
# the admin SSO API. Does not require a running IdP; all providers are
# created with enabled=false.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "auth-sso-admin"
auth_admin
setup_workdir

# -------------------------------------------------------------------------
# OIDC provider CRUD
# -------------------------------------------------------------------------

begin_test "Create OIDC provider"
resp=$(api_post "/api/v1/admin/sso/oidc" "{
  \"name\":\"test-oidc-${RUN_ID}\",
  \"client_id\":\"test-client\",
  \"client_secret\":\"test-secret\",
  \"issuer_url\":\"https://idp.example.com\",
  \"enabled\":false
}" 2>/dev/null) || true
OIDC_ID=$(echo "$resp" | jq -r '.id // empty' 2>/dev/null) || true
if [ -n "$OIDC_ID" ] && [ "$OIDC_ID" != "null" ]; then
  pass
else
  skip "OIDC admin API not available"
fi

begin_test "List OIDC providers"
if [ -z "${OIDC_ID:-}" ] || [ "$OIDC_ID" = "null" ]; then
  skip "OIDC provider was not created"
else
  resp=$(api_get "/api/v1/admin/sso/oidc" 2>/dev/null) || true
  if assert_contains "$resp" "test-oidc-${RUN_ID}"; then
    pass
  fi
fi

begin_test "Get OIDC provider by ID"
if [ -z "${OIDC_ID:-}" ] || [ "$OIDC_ID" = "null" ]; then
  skip "OIDC provider was not created"
else
  if resp=$(api_get "/api/v1/admin/sso/oidc/${OIDC_ID}" 2>/dev/null); then
    if assert_contains "$resp" "test-oidc-${RUN_ID}"; then pass; fi
  else
    fail "could not get OIDC provider by ID"
  fi
fi

begin_test "Delete OIDC provider"
if [ -z "${OIDC_ID:-}" ] || [ "$OIDC_ID" = "null" ]; then
  skip "OIDC provider was not created"
else
  if api_delete "/api/v1/admin/sso/oidc/${OIDC_ID}" > /dev/null 2>&1; then
    pass
  else
    fail "delete OIDC provider failed"
  fi
fi

# -------------------------------------------------------------------------
# LDAP provider CRUD
# -------------------------------------------------------------------------

begin_test "Create LDAP provider"
resp=$(api_post "/api/v1/admin/sso/ldap" "{
  \"name\":\"test-ldap-${RUN_ID}\",
  \"host\":\"ldap.example.com\",
  \"port\":389,
  \"bind_dn\":\"cn=admin,dc=example,dc=com\",
  \"bind_password\":\"secret\",
  \"base_dn\":\"dc=example,dc=com\",
  \"enabled\":false
}" 2>/dev/null) || true
LDAP_ID=$(echo "$resp" | jq -r '.id // empty' 2>/dev/null) || true
if [ -n "$LDAP_ID" ] && [ "$LDAP_ID" != "null" ]; then
  pass
else
  skip "LDAP admin API not available"
fi

begin_test "List LDAP providers"
if [ -z "${LDAP_ID:-}" ] || [ "$LDAP_ID" = "null" ]; then
  skip "LDAP provider was not created"
else
  resp=$(api_get "/api/v1/admin/sso/ldap" 2>/dev/null) || true
  if assert_contains "$resp" "test-ldap-${RUN_ID}"; then
    pass
  fi
fi

begin_test "Delete LDAP provider"
if [ -z "${LDAP_ID:-}" ] || [ "$LDAP_ID" = "null" ]; then
  skip "LDAP provider was not created"
else
  if api_delete "/api/v1/admin/sso/ldap/${LDAP_ID}" > /dev/null 2>&1; then
    pass
  else
    fail "delete LDAP provider failed"
  fi
fi

# -------------------------------------------------------------------------
# SAML provider CRUD
# -------------------------------------------------------------------------

begin_test "Create SAML provider"
resp=$(api_post "/api/v1/admin/sso/saml" "{
  \"name\":\"test-saml-${RUN_ID}\",
  \"idp_entity_id\":\"https://idp.example.com/saml\",
  \"idp_sso_url\":\"https://idp.example.com/sso\",
  \"idp_certificate\":\"-----BEGIN CERTIFICATE-----\nMIIBxTCCAW...\n-----END CERTIFICATE-----\",
  \"enabled\":false
}" 2>/dev/null) || true
SAML_ID=$(echo "$resp" | jq -r '.id // empty' 2>/dev/null) || true
if [ -n "$SAML_ID" ] && [ "$SAML_ID" != "null" ]; then
  pass
else
  skip "SAML admin API not available"
fi

begin_test "List SAML providers"
if [ -z "${SAML_ID:-}" ] || [ "$SAML_ID" = "null" ]; then
  skip "SAML provider was not created"
else
  resp=$(api_get "/api/v1/admin/sso/saml" 2>/dev/null) || true
  if assert_contains "$resp" "test-saml-${RUN_ID}"; then
    pass
  fi
fi

begin_test "Delete SAML provider"
if [ -z "${SAML_ID:-}" ] || [ "$SAML_ID" = "null" ]; then
  skip "SAML provider was not created"
else
  if api_delete "/api/v1/admin/sso/saml/${SAML_ID}" > /dev/null 2>&1; then
    pass
  else
    fail "delete SAML provider failed"
  fi
fi

# -------------------------------------------------------------------------
# List all enabled providers
# -------------------------------------------------------------------------

begin_test "List all SSO providers"
if resp=$(api_get "/api/v1/admin/sso/providers" 2>/dev/null); then
  if echo "$resp" | jq -e '.' > /dev/null 2>&1; then
    pass
  else
    fail "providers endpoint returned invalid JSON"
  fi
else
  skip "providers listing endpoint not available"
fi

end_suite
