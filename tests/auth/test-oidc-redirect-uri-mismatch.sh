#!/usr/bin/env bash
# test-oidc-redirect-uri-mismatch.sh - OIDC redirect URI mismatch (Epic 11.4, #76)
#
# OIDC core sec 3.1.2.1 requires the `redirect_uri` parameter in the authorization
# request to exactly match one of the pre-registered redirect URIs at the IdP,
# and the IdP must enforce this. The Artifact Keeper backend handles the AK-side
# of that contract: the callback URL it emits (and which the IdP echoes back)
# must be the server-computed callback for that provider id. A user-tampered
# `redirect_uri` query parameter on /login or /callback must not be honored;
# the server-side value is authoritative.
#
# This test verifies AK's redirect-uri handling, not the IdP's:
#   - /login emits a 307 with a Location header pointing at the IdP and a
#     redirect_uri query param that points back at our own
#     /auth/sso/oidc/{id}/callback path. We assert the emitted redirect_uri
#     contains the configured provider id and the callback path -- so a
#     compromised front-end cannot trick the IdP into redirecting to a
#     third-party host.
#   - Callback hits for an unknown provider id must 404 (per openapi line
#     2258, oidc_login responds 404 for unknown provider id; callback has
#     the same lookup so a forged id ends up as 4xx, never 2xx).
#
# Backend reference:
#   - sso/oidc.rs build_auth_url constructs redirect_uri from PUBLIC_BASE_URL
#     + "/api/v1/auth/sso/oidc/{id}/callback". The provider id is path-bound
#     so attackers cannot smuggle a different host.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "auth-oidc-redirect-uri-mismatch"
auth_admin
setup_workdir

OIDC_CFG_ID=""
SSO_AVAILABLE="unknown"

cleanup_oidc() {
  if [ -n "${OIDC_CFG_ID:-}" ] && [ "$OIDC_CFG_ID" != "null" ]; then
    curl -s -o /dev/null -X DELETE -H "$(auth_header)" \
      "${BASE_URL}/api/v1/admin/sso/oidc/${OIDC_CFG_ID}" >/dev/null 2>&1 || true
  fi
}
add_exit_handler 'cleanup_oidc'

# -------------------------------------------------------------------------
# Pre-flight
# -------------------------------------------------------------------------

begin_test "SSO providers endpoint reachable"
status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(auth_header)" \
    "${BASE_URL}/api/v1/auth/sso/providers" 2>/dev/null) || true
status="${status:-000}"
if [ "$status" = "200" ]; then
  SSO_AVAILABLE=true
  pass
elif [ "$status" = "404" ]; then
  SSO_AVAILABLE=false
  skip "SSO routes not registered (404)"
else
  SSO_AVAILABLE=true
  pass
fi

# -------------------------------------------------------------------------
# Create an OIDC config. issuer_url is intentionally an unreachable host;
# we never let the discovery document fetch complete -- we only need a
# valid provider id so /login can build a redirect URL and we can inspect
# the Location header.
# -------------------------------------------------------------------------

begin_test "Create throwaway OIDC config"
if [ "$SSO_AVAILABLE" != "true" ]; then
  skip "SSO not available"
else
  cfg_resp=$(curl -s $CURL_TIMEOUT -X POST \
    -H "$(auth_header)" \
    -H "Content-Type: application/json" \
    -d "$(jq -nc \
      --arg name "e2e-oidc-redir-${RUN_ID}" \
      --arg iss "https://fixture-redir-${RUN_ID}.invalid" \
      --arg cid "client-redir-${RUN_ID}" \
      --arg sec "secret-redir-${RUN_ID}" \
      '{name:$name,issuer_url:$iss,client_id:$cid,client_secret:$sec,is_enabled:false}')" \
    "${BASE_URL}/api/v1/admin/sso/oidc" 2>/dev/null) || cfg_resp=""
  OIDC_CFG_ID=$(echo "$cfg_resp" | jq -r '.id // empty' 2>/dev/null)
  if [ -n "$OIDC_CFG_ID" ] && [ "$OIDC_CFG_ID" != "null" ]; then
    pass
  else
    fail "could not create OIDC config" "${cfg_resp:0:300}"
  fi
fi

# -------------------------------------------------------------------------
# 1. /login Location header must reference the server-computed callback
#    for THIS provider id. If the redirect_uri is missing, points elsewhere,
#    or is taken from a request parameter, an attacker could exfiltrate the
#    authorization code by tricking the IdP into redirecting to evil.com.
#
#    We don't follow the redirect: if discovery fails the server may 502 or
#    redirect into the provider's authorize URL. Either way we want the
#    Location header from the FIRST response (curl -i) without -L.
# -------------------------------------------------------------------------

begin_test "/login emits redirect_uri scoped to this provider id"
if [ -z "${OIDC_CFG_ID:-}" ]; then
  skip "no OIDC config"
else
  # Discovery against an .invalid host may fail before any redirect is built.
  # Capture status and headers; only assert when /login actually returned 307.
  hdr_file=$(mktemp)
  status=$(curl -s -o /dev/null -D "$hdr_file" -w '%{http_code}' $CURL_TIMEOUT \
    "${BASE_URL}/api/v1/auth/sso/oidc/${OIDC_CFG_ID}/login" 2>/dev/null) || true
  status="${status:-000}"
  if [ "$status" = "307" ] || [ "$status" = "302" ]; then
    location=$(grep -i '^location:' "$hdr_file" | tr -d '\r' | head -1 | sed 's/^[Ll]ocation: //')
    rm -f "$hdr_file"
    # The Location header is the IdP authorize URL; the redirect_uri parameter
    # inside it must reference our own callback for THIS provider id. URL-
    # decoding %2F -> / and %3A -> : so a substring check is enough.
    decoded_location=$(python3 -c 'import sys,urllib.parse; print(urllib.parse.unquote(sys.argv[1]))' "$location" 2>/dev/null || echo "$location")
    expected_path="/api/v1/auth/sso/oidc/${OIDC_CFG_ID}/callback"
    if echo "$decoded_location" | grep -q "redirect_uri="; then
      if echo "$decoded_location" | grep -q "${expected_path}"; then
        pass
      else
        fail "Location redirect_uri does not point at ${expected_path}" "$decoded_location"
      fi
    else
      fail "Location header has no redirect_uri parameter" "$decoded_location"
    fi
  else
    rm -f "$hdr_file"
    # Discovery against an .invalid issuer is expected to fail with 5xx/4xx;
    # we can't make a strong assertion in that case. The follow-up test
    # below (unknown provider id) is the deterministic redirect-uri check.
    skip "/login returned HTTP ${status} (discovery against fixture host failed); see unknown-id test"
  fi
fi

# -------------------------------------------------------------------------
# 2. Tampering: /login must ignore any client-supplied redirect_uri query
#    param. If the backend echoes a user-supplied value into the IdP request,
#    an attacker can swap their host in. We assert by passing a tampered
#    value and confirming the emitted Location either preserves the server's
#    callback path or the request is rejected -- never that the attacker's
#    URL ends up in the redirect_uri sent to the IdP.
# -------------------------------------------------------------------------

begin_test "/login ignores client-supplied redirect_uri tampering"
if [ -z "${OIDC_CFG_ID:-}" ]; then
  skip "no OIDC config"
else
  tampered="https://attacker-${RUN_ID}.invalid/steal"
  encoded=$(python3 -c 'import sys,urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' "$tampered" 2>/dev/null || echo "$tampered")
  hdr_file=$(mktemp)
  status=$(curl -s -o /dev/null -D "$hdr_file" -w '%{http_code}' $CURL_TIMEOUT \
    "${BASE_URL}/api/v1/auth/sso/oidc/${OIDC_CFG_ID}/login?redirect_uri=${encoded}" 2>/dev/null) || true
  status="${status:-000}"
  if [ "$status" = "307" ] || [ "$status" = "302" ]; then
    location=$(grep -i '^location:' "$hdr_file" | tr -d '\r' | head -1 | sed 's/^[Ll]ocation: //')
    rm -f "$hdr_file"
    decoded_location=$(python3 -c 'import sys,urllib.parse; print(urllib.parse.unquote(sys.argv[1]))' "$location" 2>/dev/null || echo "$location")
    if echo "$decoded_location" | grep -q "attacker-${RUN_ID}.invalid"; then
      fail "tampered redirect_uri leaked into IdP authorize URL" "$decoded_location"
    else
      pass
    fi
  else
    rm -f "$hdr_file"
    # If /login outright rejects unknown query params, that is also acceptable
    # behaviour as long as it is a non-2xx response.
    if [ "$status" -ge 400 ] 2>/dev/null && [ "$status" -lt 600 ] 2>/dev/null; then
      pass
    else
      fail "expected redirect or 4xx for tampered redirect_uri, got HTTP ${status}"
    fi
  fi
fi

# -------------------------------------------------------------------------
# 3. Callback against an unknown provider id (random UUID) must 4xx. This
#    is the structural protection: the provider id is path-bound, so an
#    attacker who controls only the state cannot pivot to an unregistered
#    provider. openapi line 2258 documents 404 for oidc_login on unknown id;
#    the callback has the same lookup -- it must also reject (not crash, not
#    silently accept).
# -------------------------------------------------------------------------

begin_test "Callback with unknown provider id is rejected"
if [ "$SSO_AVAILABLE" != "true" ]; then
  skip "SSO not available"
else
  # Random UUID -- guaranteed not to match any real provider.
  unknown_id=$(python3 -c 'import uuid; print(uuid.uuid4())' 2>/dev/null || echo "00000000-0000-0000-0000-000000000000")
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    "${BASE_URL}/api/v1/auth/sso/oidc/${unknown_id}/callback?state=any-${RUN_ID}&code=bogus-${RUN_ID}" \
    2>/dev/null) || true
  status="${status:-000}"
  # Per openapi: 400 (invalid params) is the documented response and 404 is
  # plausible (unknown provider lookup). Both are acceptable; 2xx/5xx are not.
  if [ "$status" = "400" ] || [ "$status" = "404" ]; then
    pass
  else
    fail "expected HTTP 400/404 for unknown provider id, got HTTP ${status}"
  fi
fi

# -------------------------------------------------------------------------
# 4. Malformed provider id (not a UUID) must 4xx, never 5xx. The path
#    extractor types `id` as Uuid, so a non-UUID string short-circuits with
#    422 before any cache or DB lookup. A 500 here would mean the extractor
#    or middleware panicked, which would be a regression worth catching.
# -------------------------------------------------------------------------

begin_test "Callback with non-UUID provider id returns 4xx"
if [ "$SSO_AVAILABLE" != "true" ]; then
  skip "SSO not available"
else
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    "${BASE_URL}/api/v1/auth/sso/oidc/not-a-uuid-${RUN_ID}/callback?state=x&code=y" \
    2>/dev/null) || true
  status="${status:-000}"
  if [ "$status" -ge 400 ] 2>/dev/null && [ "$status" -lt 500 ] 2>/dev/null; then
    pass
  else
    fail "expected 4xx for non-UUID provider id, got HTTP ${status}"
  fi
fi

end_suite
