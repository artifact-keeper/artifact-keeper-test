#!/usr/bin/env bash
# test-saml-signature.sh - #548 / #2700: SAML signature verification (real oracle)
#
# Verifies that the SAML SSO subsystem cryptographically verifies assertions:
# a validly-signed assertion authenticates, and a FORGED assertion is EXPLICITLY
# rejected. This is a regression guard for the #2449 SAML XML-Signature-Wrapping
# (XSW) CRITICAL auth-bypass class.
#
# #2700 hardening (why this file was rewritten):
#   1. The old forged-assertion oracle counted a 500 crash (and any non-200) as
#      PASS -- only a 200-with-token was a failure. A server that CRASHES on a
#      forged assertion is itself a defect (robustness + a fake-green that hides
#      a broken verifier). This version HARD-FAILS unless the server returns an
#      EXPLICIT rejection (a controlled 4xx / deny). 5xx = FAIL. A 200 or a
#      session-establishing 3xx = FAIL. Only an explicit 4xx rejection passes.
#   2. The old test degraded to "the endpoint exists" (a smoke check) whenever
#      SAML was not pre-configured. This version brings its OWN IdP fixture: it
#      provisions a real SAML provider through the admin API and drives a real
#      signed-vs-forged flow -- the same pattern the DTF `sso` tier uses
#      (deploy-test/harness/tiers/sso/: Keycloak IdP + a bergshamra-backed
#      signer probe). The signed positive control reuses that tier's probe when
#      a Rust toolchain is available on the runner.
#
# Relationship to the DTF sso tier:
#   deploy-test/harness/tiers/sso/oracle.sh is the FULL discriminating oracle
#   (Keycloak in-compose + every XSW variant, DB-asserted). It runs in the DTF
#   harness against a candidate image. THIS script is the release-gate
#   (k8s-deployed backend) counterpart: no compose/Keycloak available here, so
#   it self-provisions a provider via the admin API and exercises the accept
#   (signed) / explicit-reject (forged) contract directly over HTTP.
#
# Skip semantics (load-bearing):
#   The forged-rejection assertion only skips when the backend genuinely does
#   not expose a SAML ACS endpoint at all (SAML not compiled/mounted in this
#   deploy). It NEVER skips-to-green on a crash, and it NEVER treats a 500 as a
#   pass. The signed positive control skips only when the DTF signer probe
#   cannot be built (no Rust toolchain) -- a genuine tooling limit, not a bug.

source "$(dirname "$0")/../lib/common.sh"

begin_suite "saml-signature"
auth_admin
setup_workdir

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SP_ENTITY_ID="artifact-keeper"
ADMIN_GROUP="ak-admins"
SUF="${RUN_ID:-local}-$(date +%s)"
IDP_ENTITY="https://idp.saml-sig-test.local/${SUF}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK" 2>/dev/null || true' EXIT

# ---------------------------------------------------------------------------
# Helpers (mirror deploy-test/harness/tiers/sso/oracle.sh, provider-scoped API)
# ---------------------------------------------------------------------------

# create_saml_provider <cert_pem_file> -> prints provider UUID (empty on failure)
create_saml_provider() {
  local cert_file="$1" body resp
  body=$(jq -n \
    --arg name "saml-sig-${SUF}" \
    --arg eid  "$IDP_ENTITY" \
    --arg sso  "https://idp.saml-sig-test.local/sso" \
    --arg cert "$(cat "$cert_file")" \
    --arg spid "$SP_ENTITY_ID" \
    --arg admg "$ADMIN_GROUP" \
    '{name:$name, entity_id:$eid, sso_url:$sso, certificate:$cert,
      sp_entity_id:$spid, sign_requests:false, require_signed_assertions:true,
      admin_group:$admg, is_enabled:true}')
  resp=$(curl -s $CURL_TIMEOUT -X POST "${BASE_URL}/api/v1/admin/sso/saml" \
    -H "$(auth_header)" -H 'Content-Type: application/json' \
    -d "$body" 2>/dev/null) || return 0
  echo "$resp" | jq -r '.id // empty' 2>/dev/null
}

# saml_admin_api_available -> 0 if POST /api/v1/admin/sso/saml is mounted
saml_admin_api_available() {
  local code
  code=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X POST "${BASE_URL}/api/v1/admin/sso/saml" \
    -H "$(auth_header)" -H 'Content-Type: application/json' \
    -d '{}' 2>/dev/null) || code="000"
  # 404/405 => not mounted. Anything else (400 validation, 422, 200, 401)
  # means the route exists.
  case "$code" in
    404|405|000) return 1 ;;
    *) return 0 ;;
  esac
}

# provider_request_id <pid> -> the AuthnRequest ID to echo as InResponseTo
provider_request_id() {
  local pid="$1" loc
  loc=$(curl -s -o /dev/null -w '%{redirect_url}' $CURL_TIMEOUT \
    "${BASE_URL}/api/v1/auth/sso/saml/${pid}/login" 2>/dev/null) || true
  [ -z "$loc" ] && return 0
  python3 - "$loc" <<'PY' 2>/dev/null || true
import sys, urllib.parse, base64, re
u = sys.argv[1]
try:
    q = urllib.parse.parse_qs(urllib.parse.urlparse(u).query)
    xml = base64.b64decode(q['SAMLRequest'][0]).decode('utf-8', 'replace')
    m = re.search(r'ID="([^"]+)"', xml)
    print(m.group(1) if m else "")
except Exception:
    print("")
PY
}

# post_acs_status <acs_url> <b64payload> -> HTTP status
post_acs_status() {
  curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X POST \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode "SAMLResponse=$2" --data-urlencode 'RelayState=forged' \
    "$1" 2>/dev/null || echo "000"
}

# post_acs_body <acs_url> <b64payload> -> response body
post_acs_body() {
  curl -s $CURL_TIMEOUT -X POST \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode "SAMLResponse=$2" --data-urlencode 'RelayState=forged' \
    "$1" 2>/dev/null || true
}

# forged_unsigned_b64 <name_id> <in_response_to> -> base64 forged SAMLResponse
# A minimal, obviously-forged (UNSIGNED) admin assertion. No crypto required:
# a verifier with require_signed_assertions=true MUST reject it.
forged_unsigned_b64() {
  local nid="$1" irt="$2" irt_attr=""
  [ -n "$irt" ] && irt_attr=" InResponseTo=\"${irt}\""
  cat <<SAML_XML | base64 | tr -d '\n'
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_forged_response_${SUF}"${irt_attr} Version="2.0" IssueInstant="2026-01-01T00:00:00Z" Destination="${BASE_URL}/api/v1/auth/sso/saml/acs">
  <saml:Issuer>${IDP_ENTITY}</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <saml:Assertion ID="_forged_assertion_${SUF}" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">
    <saml:Issuer>${IDP_ENTITY}</saml:Issuer>
    <saml:Subject><saml:NameID>${nid}</saml:NameID></saml:Subject>
    <saml:AuthnStatement AuthnInstant="2026-01-01T00:00:00Z">
      <saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="groups"><saml:AttributeValue>${ADMIN_GROUP}</saml:AttributeValue></saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>
SAML_XML
}

# body_has_session <body> -> 0 if the response looks like a granted session
body_has_session() {
  echo "$1" | jq -e '.token // .access_token // .id_token // .session' >/dev/null 2>&1
}

# assert_forged_rejected <label> <acs_url> <status> <body>
# The #2700 oracle: PASS only on an EXPLICIT rejection (controlled 4xx).
#   - 4xx (400/401/403/422)         -> PASS (explicit rejection)
#   - 5xx (crash on attacker input) -> FAIL
#   - 200 / session-bearing 3xx     -> FAIL (forged assertion accepted)
#   - anything else (bare 200/3xx)  -> FAIL (not an explicit rejection)
assert_forged_rejected() {
  local label="$1" acs="$2" st="$3" body="$4"
  if body_has_session "$body"; then
    fail "${label}: forged assertion ACCEPTED (session/token issued) at ${acs}" \
         "status=${st} body-snip=$(echo "$body" | head -c 300)"
    return
  fi
  case "$st" in
    400|401|403|422)
      pass ;;
    5??)
      fail "${label}: forged assertion CRASHED the verifier (HTTP ${st}) at ${acs}" \
           "A 5xx on attacker input is a defect (robustness + fake-green). The verifier must return a controlled rejection, not crash." ;;
    2??|3??)
      fail "${label}: forged assertion was NOT explicitly rejected (HTTP ${st}) at ${acs}" \
           "Expected a controlled 4xx rejection. A ${st} is not an explicit deny for a forged assertion." ;;
    *)
      fail "${label}: forged assertion produced no controlled rejection (HTTP ${st}) at ${acs}" ;;
  esac
}

# ---------------------------------------------------------------------------
# Locate / build the DTF sso signer probe (optional; needed only for the
# SIGNED positive control). Reused verbatim from the sso tier.
# ---------------------------------------------------------------------------
PROBE_DIR="${REPO_ROOT}/deploy-test/harness/tiers/sso/probe"
PROBE_BIN="${PROBE_DIR}/target/release/dtf-saml-xsw-probe"
PROBE_READY=false
ensure_probe() {
  if [ -x "$PROBE_BIN" ]; then PROBE_READY=true; return 0; fi
  command -v cargo >/dev/null 2>&1 || return 1
  [ -d "$PROBE_DIR" ] || return 1
  ( cd "$PROBE_DIR" && cargo build --release >/dev/null 2>&1 ) || return 1
  [ -x "$PROBE_BIN" ] && PROBE_READY=true
}

# ---------------------------------------------------------------------------
# 1. SSO providers endpoint responds (5xx is now a failure, not a pass)
# ---------------------------------------------------------------------------
begin_test "SSO providers endpoint responds"
status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/auth/sso/providers" 2>/dev/null) || status="000"
if [ "$status" = "404" ]; then
  skip "SSO providers endpoint does not exist on this deployment"
elif [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 500 ] 2>/dev/null; then
  # 2xx/3xx/4xx: the endpoint exists and responded in a controlled way.
  pass
else
  fail "SSO providers endpoint returned ${status} (a 5xx is a server error, not a healthy response)"
fi

# ---------------------------------------------------------------------------
# 2. Real SAML provider fixture + signed-vs-forged flow
# ---------------------------------------------------------------------------
PROVIDER=""
PROVIDER_CERT="${WORK}/idp_cert.pem"
PROVIDER_KEY="${WORK}/idp_key.pem"

begin_test "Provision an ephemeral SAML provider (real IdP fixture) via admin API"
if ! saml_admin_api_available; then
  skip "admin SAML provider API (/api/v1/admin/sso/saml) not mounted on this backend line; falling back to generic-ACS forged-rejection check"
else
  # Prefer the DTF signer probe's keypair (lets us also mint a SIGNED positive).
  if ensure_probe; then
    "$PROBE_BIN" keygen "$WORK" >/dev/null 2>&1 || true
  fi
  # Fall back to an openssl self-signed cert for the provider registration.
  # (For the forged-UNSIGNED negative the cert need not match any real key.)
  if [ ! -s "$PROVIDER_CERT" ] && command -v openssl >/dev/null 2>&1; then
    openssl req -x509 -newkey rsa:2048 -nodes -keyout "$PROVIDER_KEY" \
      -out "$PROVIDER_CERT" -days 2 -subj "/CN=saml-sig-test-${SUF}" >/dev/null 2>&1 || true
  fi
  if [ -s "$PROVIDER_CERT" ]; then
    PROVIDER="$(create_saml_provider "$PROVIDER_CERT")"
  fi
  if [ -n "$PROVIDER" ] && [ "$PROVIDER" != "null" ]; then
    pass
  else
    fail "could not provision a SAML provider via /api/v1/admin/sso/saml" \
         "The admin route reported available but provider creation returned no id. A registry that ships SAML must let the release gate register a test IdP."
  fi
fi

if [ -n "$PROVIDER" ] && [ "$PROVIDER" != "null" ]; then
  ACS_URL="${BASE_URL}/api/v1/auth/sso/saml/${PROVIDER}/acs"

  # ---- SIGNED POSITIVE CONTROL (proves the verifier is not reject-everything)
  begin_test "Validly-signed assertion authenticates (positive control)"
  if [ "$PROBE_READY" = true ] && [ -s "$PROVIDER_KEY" ]; then
    NID="saml-sig-legit-${SUF}"
    RID="$(provider_request_id "$PROVIDER")"
    SIGNED_B64="$("$PROBE_BIN" craft --key "$PROVIDER_KEY" \
      --issuer "$IDP_ENTITY" --audience "$SP_ENTITY_ID" \
      --request-id "$RID" --name-id "$NID" --case positive --groups Developers 2>/dev/null)"
    if [ -z "$SIGNED_B64" ]; then
      fail "signer probe produced no signed assertion (craft failed)"
    else
      st=$(post_acs_status "$ACS_URL" "$SIGNED_B64")
      body=$(post_acs_body "$ACS_URL" "$SIGNED_B64")
      # Accept = authenticated: a redirect/2xx that is NOT a rejection.
      if [ "$st" -ge 200 ] 2>/dev/null && [ "$st" -lt 400 ] 2>/dev/null; then
        pass
      else
        fail "a validly-signed assertion must authenticate (got HTTP ${st})" \
             "If the signer probe and the backend verifier disagree, the positive control breaks. body-snip=$(echo "$body" | head -c 200)"
      fi
    fi
  else
    skip "signed positive control needs the DTF SAML signer (deploy-test/harness/tiers/sso/probe); no Rust toolchain on this runner. Negative (forged-rejection) control below still runs hard."
  fi

  # ---- FORGED NEGATIVE (the #2449 class + the #2700 fake-green fix)
  begin_test "Forged UNSIGNED assertion is explicitly rejected at provider ACS"
  NID="saml-sig-forged-${SUF}"
  RID="$(provider_request_id "$PROVIDER")"
  FORGED_B64="$(forged_unsigned_b64 "$NID" "$RID")"
  st=$(post_acs_status "$ACS_URL" "$FORGED_B64")
  body=$(post_acs_body "$ACS_URL" "$FORGED_B64")
  assert_forged_rejected "provider ACS" "$ACS_URL" "$st" "$body"

else
  # ---- FALLBACK: no provider (old backend line). Still a REAL reject check
  # against the generic ACS, with the corrected hard-fail oracle. Only a
  # genuinely-absent ACS endpoint (all 404) is a legitimate skip.
  begin_test "Forged UNSIGNED assertion is explicitly rejected at ACS endpoint"
  NID="saml-sig-forged-${SUF}"
  FORGED_B64="$(forged_unsigned_b64 "$NID" "")"
  ACS_PATHS=(
    "/api/v1/auth/sso/saml/acs"
    "/api/v1/auth/saml/acs"
    "/auth/saml/acs"
    "/saml/acs"
  )
  acs_tested=false
  for acs_path in "${ACS_PATHS[@]}"; do
    acs="${BASE_URL}${acs_path}"
    st=$(post_acs_status "$acs" "$FORGED_B64")
    [ "$st" = "404" ] && continue
    acs_tested=true
    body=$(post_acs_body "$acs" "$FORGED_B64")
    assert_forged_rejected "generic ACS" "$acs" "$st" "$body"
    break
  done
  if [ "$acs_tested" = false ]; then
    skip "no SAML ACS endpoint mounted at any known path (SAML not compiled/mounted in this deploy)"
  fi
fi

end_suite
