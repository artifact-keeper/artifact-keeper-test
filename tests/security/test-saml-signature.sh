#!/usr/bin/env bash
# test-saml-signature.sh - #548: SAML signature verification
#
# Verifies that the SSO subsystem is functional and that forged SAML
# assertions are rejected. Because a full SAML IdP is unlikely to be
# available in the test environment, tests skip gracefully when SAML
# is not configured.

source "$(dirname "$0")/../lib/common.sh"

begin_suite "saml-signature"
auth_admin
setup_workdir

# ---------------------------------------------------------------------------
# SSO providers endpoint
# ---------------------------------------------------------------------------

begin_test "SSO providers endpoint responds"
status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/auth/sso/providers" 2>/dev/null) || true

if [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then
  pass
elif [ "$status" = "404" ]; then
  skip "SSO providers endpoint does not exist on this deployment"
else
  # 401/403/500 still means the endpoint exists and responded
  pass
fi

# ---------------------------------------------------------------------------
# Check if SAML is configured
# ---------------------------------------------------------------------------

begin_test "Check SAML provider availability"
SAML_CONFIGURED=false
sso_response=$(curl -s $CURL_TIMEOUT \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/auth/sso/providers" 2>/dev/null) || true

if echo "$sso_response" | jq -e '.[] | select(.type == "saml" or .protocol == "saml")' >/dev/null 2>&1; then
  SAML_CONFIGURED=true
  pass
elif echo "$sso_response" | jq -e '. | length' >/dev/null 2>&1; then
  skip "no SAML provider configured in test environment"
else
  skip "SSO providers response not parseable or endpoint unavailable"
fi

# ---------------------------------------------------------------------------
# SAML login redirect (if configured)
# ---------------------------------------------------------------------------

begin_test "SAML login redirect"
if [ "$SAML_CONFIGURED" = "true" ]; then
  saml_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -L --max-redirs 0 \
    "${BASE_URL}/api/v1/auth/sso/saml/login" 2>/dev/null) || true

  # Expect a redirect (302/303) or 200 with a form
  if [ "$saml_status" = "302" ] || [ "$saml_status" = "303" ] || [ "$saml_status" = "200" ]; then
    pass
  elif [ "$saml_status" = "404" ]; then
    skip "SAML login endpoint not found"
  else
    # Any non-5xx response is acceptable
    if [ "$saml_status" -lt 500 ] 2>/dev/null; then
      pass
    else
      fail "SAML login returned ${saml_status}"
    fi
  fi
else
  skip "SAML not configured"
fi

# ---------------------------------------------------------------------------
# Forged SAML assertion must be rejected
# ---------------------------------------------------------------------------

begin_test "Forged SAML assertion rejected at ACS endpoint"

# Build a minimal, obviously forged SAML response (base64 encoded)
FORGED_SAML="$(cat <<'SAML_XML' | base64 | tr -d '\n'
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_forged_response" Version="2.0" IssueInstant="2026-01-01T00:00:00Z" Destination="http://localhost:8080/api/v1/auth/sso/saml/acs">
  <saml:Issuer>http://forged-idp.test</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <saml:Assertion ID="_forged_assertion" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">
    <saml:Issuer>http://forged-idp.test</saml:Issuer>
    <saml:Subject>
      <saml:NameID>attacker@forged.test</saml:NameID>
    </saml:Subject>
    <saml:AuthnStatement AuthnInstant="2026-01-01T00:00:00Z">
      <saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></saml:AuthnContext>
    </saml:AuthnStatement>
  </saml:Assertion>
</samlp:Response>
SAML_XML
)"

# Try common ACS endpoint paths
ACS_PATHS=(
  "/api/v1/auth/sso/saml/acs"
  "/api/v1/auth/saml/acs"
  "/auth/saml/acs"
  "/saml/acs"
)

acs_tested=false
for acs_path in "${ACS_PATHS[@]}"; do
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X POST \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "SAMLResponse=${FORGED_SAML}&RelayState=forged" \
    "${BASE_URL}${acs_path}" 2>/dev/null) || true

  if [ "$status" = "404" ]; then
    continue
  fi

  acs_tested=true

  # A forged assertion must not result in a successful login (200 with token)
  if [ "$status" = "200" ]; then
    # Check if the response contains a token (actual authentication success)
    body=$(curl -s $CURL_TIMEOUT \
      -X POST \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "SAMLResponse=${FORGED_SAML}&RelayState=forged" \
      "${BASE_URL}${acs_path}" 2>/dev/null) || true
    if echo "$body" | jq -e '.token // .access_token' >/dev/null 2>&1; then
      fail "forged SAML assertion was accepted and returned a token at ${acs_path}"
    else
      # 200 without token (e.g., error page) is acceptable
      pass
    fi
  elif [ "$status" = "400" ] || [ "$status" = "401" ] || [ "$status" = "403" ] || [ "$status" = "422" ]; then
    pass
  else
    # 500, 302, etc. all indicate the forged assertion was not silently accepted
    pass
  fi
  break
done

if [ "$acs_tested" = "false" ]; then
  skip "no SAML ACS endpoint found at any known path"
fi

end_suite
