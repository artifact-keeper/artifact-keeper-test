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
#   3. The forged payload was UNSIGNED-only, so the file advertised itself as a
#      #2449 (XSW) regression guard while never sending an XSW payload.
#      Rejecting an assertion with NO signature is strictly easier than
#      defeating signature wrapping: the #2449 verifier checked the signature
#      correctly (so the unsigned forgery was rejected) but then read claims
#      from the WHOLE document last-wins, so a validly-signed BENIGN assertion
#      wrapping an UNSIGNED ADMIN assertion escalated to admin. An
#      XSW-vulnerable backend passed this gate. When the DTF signer probe is
#      available, the gate now also POSTs the `xsw_dual` and `xsw_dup_id`
#      wrapping payloads and requires the same explicit 4xx rejection.
#   4. The forged-rejection assertion soft-skipped to green when SAML was
#      clearly mounted but no ACS could be driven. It now hard-fails under
#      RELEASE_GATE=1 in that case, and it discovers the real provider-scoped
#      ACS (/api/v1/auth/sso/saml/{id}/acs) before falling back to guesses.
#
# Skip semantics (load-bearing):
#   The forged-rejection assertion only skips when the backend genuinely does
#   not ship SAML at all (no admin SAML API AND a non-2xx providers endpoint,
#   with no ACS at any known path). If SAML IS mounted but no ACS is reachable,
#   it HARD-FAILS under RELEASE_GATE=1 -- a security gate that cannot reach the
#   thing it guards must not report green. It NEVER skips-to-green on a crash,
#   and it NEVER treats a 500 as a pass. The signed positive control and the XSW
#   cases skip only when the DTF signer probe cannot be built (no Rust
#   toolchain) -- a genuine tooling limit, not a bug.

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
#
# ASSUMPTION (3xx handling) -- deliberately errs SAFE:
#   Every 3xx is treated as a FAIL, including a bare 302. AK's ACS is a
#   JSON-API-style endpoint: it ACCEPTS with 200/307 + a token/session payload
#   and REJECTS with a 4xx JSON error (see deploy-test/harness/tiers/sso/
#   oracle.sh, which asserts 401 for every rejected XSW/forged case and 307 for
#   an accepted one). So on AK a 3xx from the ACS means "assertion consumed,
#   session established" -- an ACCEPT, i.e. a real failure.
#   Some web-SSO SPs instead reject by 302-redirecting back to a login/error
#   page. If a FUTURE AK ACS ever adopts that style, this branch would
#   false-FAIL a correct backend and MUST be revisited -- but the fix is NOT to
#   blanket-allow 3xx: that would turn accept-via-3xx (the actual #2449
#   escalation shape, which redirects on success) into a false PASS. Any future
#   loosening has to DISCRIMINATE, e.g. follow the redirect and assert the
#   landing page is unauthenticated / no session cookie was set, or assert on
#   the Location target. Until a live ACS confirms otherwise, 3xx stays FAIL.
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

# craft_probe <case> <name_id> [extra probe args...] -> base64 SAMLResponse
# Thin wrapper over the DTF probe's craft CLI, mirroring
# deploy-test/harness/tiers/sso/oracle.sh:craft(). The inner assertion is signed
# with PROVIDER_KEY, whose self-signed cert was registered as the provider
# `certificate`, so the backend verifies with the exact key we sign with.
craft_probe() {
  local case="$1" nid="$2"; shift 2
  local rid
  rid="$(provider_request_id "$PROVIDER")"
  "$PROBE_BIN" craft --key "$PROVIDER_KEY" \
    --issuer "$IDP_ENTITY" --audience "$SP_ENTITY_ID" \
    --request-id "$rid" --name-id "$nid" --case "$case" "$@" 2>/dev/null || true
}

# list_saml_provider_ids -> newline-separated UUID-shaped provider ids advertised
# by the public providers endpoint (shape-agnostic: array, {providers:[...]},
# {data:[...]} all work). Used to build the provider-scoped ACS path in the
# no-admin-API fallback, where we cannot register our own provider.
list_saml_provider_ids() {
  curl -s $CURL_TIMEOUT -H "$(auth_header)" \
    "${BASE_URL}/api/v1/auth/sso/providers" 2>/dev/null \
    | jq -r '[.. | objects | .id? // empty] | unique | .[]' 2>/dev/null \
    | grep -Eio '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' \
    | head -5 || true
}

# ---------------------------------------------------------------------------
# 1. SSO providers endpoint responds (5xx is now a failure, not a pass)
# ---------------------------------------------------------------------------
begin_test "SSO providers endpoint responds"
status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/auth/sso/providers" 2>/dev/null) || status="000"
PROVIDERS_STATUS="$status"
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

SAML_ADMIN_API=false
if saml_admin_api_available; then SAML_ADMIN_API=true; fi

# SAML_PRESENT: does this deployment ship SAML at all? Either the admin
# provisioning route is mounted, or the public providers endpoint answered 2xx
# (the SSO subsystem is compiled in and serving). This distinguishes "SAML is
# not in this build" (a legitimate skip) from "SAML is here but the gate could
# not reach its ACS" (a gate blind spot -- see the fallback branch below).
SAML_PRESENT=false
if [ "$SAML_ADMIN_API" = true ]; then
  SAML_PRESENT=true
elif [ "$PROVIDERS_STATUS" -ge 200 ] 2>/dev/null && [ "$PROVIDERS_STATUS" -lt 300 ] 2>/dev/null; then
  SAML_PRESENT=true
fi

begin_test "Provision an ephemeral SAML provider (real IdP fixture) via admin API"
if [ "$SAML_ADMIN_API" != true ]; then
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

  # ---- XSW NEGATIVES (the actual #2449 defect class) ----
  #
  # Why the UNSIGNED case above is NOT sufficient on its own: rejecting an
  # assertion with NO signature is strictly easier than defeating XSW. The
  # #2449 bug was a verifier that DID check the signature (so it rejected the
  # unsigned forgery just fine) but then extracted claims from the WHOLE
  # document, last-wins -- so a validly-signed BENIGN assertion wrapping an
  # UNSIGNED ADMIN assertion authenticated as admin. An XSW-vulnerable backend
  # passes an unsigned-only oracle. These cases send the real thing.
  #
  # Mirrors deploy-test/harness/tiers/sso/oracle.sh:177-194 (XSW 1 / XSW 2),
  # minus the DB assertion (no psql from the k8s release-gate runner): here the
  # contract is the HTTP one -- an explicit 4xx rejection, no session issued.
  #
  # Only the two REJECT-shaped variants run here. The attribute-splice variants
  # (xsw_attr_before/after, xsw_ds_object, xsw_nameid_comment) are correct-
  # behaviour 307s that authenticate a NON-admin, so they can only be judged by
  # inspecting the resulting user's role in the DB -- that stays in the DTF sso
  # tier, which has DB_CONTAINER. Sending them through assert_forged_rejected
  # would false-FAIL a correct backend.
  for xsw_case in xsw_dual xsw_dup_id; do
    case "$xsw_case" in
      xsw_dual)   xsw_desc="signed benign assertion with an appended UNSIGNED admin assertion (2449 core)" ;;
      *)          xsw_desc="unsigned admin assertion reusing the SIGNED assertion's ID (duplicate-ID wrap)" ;;
    esac
    begin_test "XSW ${xsw_case}: ${xsw_desc} is explicitly rejected at provider ACS"
    if [ "$PROBE_READY" != true ] || [ ! -s "$PROVIDER_KEY" ]; then
      skip "XSW payloads need the DTF SAML signer (deploy-test/harness/tiers/sso/probe) to sign the inner benign assertion; no Rust toolchain on this runner. NOTE: this leaves the XSW class unexercised in this run -- the unsigned-forgery control below/above still runs hard, but it does NOT cover #2449."
      continue
    fi
    VIC="saml-sig-${xsw_case}-victim-${SUF}"
    ATT="saml-sig-${xsw_case}-attacker-${SUF}"
    XSW_B64="$(craft_probe "$xsw_case" "$VIC" \
      --groups Developers --attacker-name-id "$ATT" --admin-group "$ADMIN_GROUP")"
    if [ -z "$XSW_B64" ]; then
      fail "signer probe produced no ${xsw_case} payload (craft failed)" \
           "Without the payload this gate cannot exercise the #2449 XSW class at all."
      continue
    fi
    st=$(post_acs_status "$ACS_URL" "$XSW_B64")
    body=$(post_acs_body "$ACS_URL" "$XSW_B64")
    assert_forged_rejected "XSW ${xsw_case} @ provider ACS" "$ACS_URL" "$st" "$body"
  done

else
  # ---- FALLBACK: no provider (old backend line). Still a REAL reject check
  # against the generic ACS, with the corrected hard-fail oracle. Only a
  # genuinely-absent ACS endpoint (all 404) is a legitimate skip.
  begin_test "Forged UNSIGNED assertion is explicitly rejected at ACS endpoint"
  NID="saml-sig-forged-${SUF}"
  FORGED_B64="$(forged_unsigned_b64 "$NID" "")"
  # The ACS route AK actually mounts is PROVIDER-SCOPED
  # (/api/v1/auth/sso/saml/{id}/acs) -- the un-scoped generic paths below are
  # legacy/other-backend-line guesses and 404 on a current build. Without the
  # admin API we cannot register our own provider, so discover an existing
  # provider id from the public providers endpoint and drive its real ACS.
  # This is what keeps the assertion load-bearing instead of soft-skipping.
  ACS_PATHS=()
  DISCOVERED_IDS="$(list_saml_provider_ids)"
  for pid in $DISCOVERED_IDS; do
    ACS_PATHS+=("/api/v1/auth/sso/saml/${pid}/acs")
  done
  ACS_PATHS+=(
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
  if [ "$acs_tested" = false ] && [ "$SAML_PRESENT" = true ]; then
    # SAML IS shipped on this deployment (providers endpoint 2xx and/or the
    # admin SAML API is mounted) but the gate could not drive ANY ACS. That is
    # not "capability not shipped" -- it is the gate being BLIND to the exact
    # subsystem it exists to guard. Soft-skipping here is how a security gate
    # reports green while never testing anything (#870/#871/#888 class), so
    # under RELEASE_GATE=1 this is a hard failure.
    _acs_detail="providers endpoint HTTP ${PROVIDERS_STATUS}; admin SAML API mounted=${SAML_ADMIN_API}
discovered provider ids: $(echo "$DISCOVERED_IDS" | tr '\n' ' ')
paths tried: ${ACS_PATHS[*]}
Fix by making the ACS reachable to the gate (register a provider via
/api/v1/admin/sso/saml, or add the deployment's real ACS path to ACS_PATHS).
Do NOT downgrade this to a skip: the forged-rejection assertion is the whole
point of this suite."
    if [ "${RELEASE_GATE:-0}" = "1" ]; then
      fail "SAML is mounted on this deployment but NO ACS endpoint could be driven; the forged-rejection assertion did not run" \
           "$_acs_detail"
    else
      skip "SAML appears mounted but no ACS endpoint responded; RELEASE_GATE unset (local dev) so this degrades to a skip. In the gate this is a hard FAIL. ${_acs_detail}"
    fi
  elif [ "$acs_tested" = false ]; then
    skip "no SAML ACS endpoint mounted at any known path (SAML not compiled/mounted in this deploy)"
  fi
fi

# ---------------------------------------------------------------------------
# Cleanup: delete the ephemeral provider (best-effort, does not change the
# suite result). This is load-bearing on a SHARED gate backend: an enabled
# SSO provider left behind disables LOCAL login for every non-admin user
# backend-wide (auth.rs local-login SSO policy), so a leftover fixture from
# this suite would poison any later suite/test that logs a plain user in with
# a password ("Local login is disabled when SSO is configured", 401).
# ---------------------------------------------------------------------------
if [ -n "${PROVIDER:-}" ] && [ "$PROVIDER" != "null" ]; then
  curl -s -o /dev/null $CURL_TIMEOUT -X DELETE \
    "${BASE_URL}/api/v1/admin/sso/saml/${PROVIDER}" \
    -H "$(auth_header)" 2>/dev/null || true
fi

end_suite
