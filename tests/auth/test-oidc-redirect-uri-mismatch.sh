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
#   - The redirect_uri inspection cases require a working OIDC discovery
#     document. Against the `.invalid` fixture host, `sso.rs:101` raises
#     `AppError::Internal` (HTTP 500) before any redirect is built, so the
#     Location-header assertions never run. They are documented here and
#     converted to skip-with-reason; running them needs a stub IdP (mock
#     server, local httpd serving a real-shaped discovery doc, or
#     httpbin-style fixture). Followup: track the discovery-stub plumbing.
#   - Callback hits for an unknown provider id are NOT short-circuited by
#     the path's UUID lookup. `oidc_callback` (sso.rs:165-174) calls
#     `validate_sso_session(state)` BEFORE looking up the provider, and
#     the state we send is never minted, so validate_sso_session raises
#     `AppError::Authentication` -> HTTP 401 (error.rs:89). We assert 401.
#
# Backend reference (read 2026-05-16):
#   - `oidc_callback` validates state first via `AuthConfigService::
#     validate_sso_session`, then delegates to `oidc_callback_inner`. The
#     path-bound provider id is never compared against `session.provider_id`,
#     so the response code for an unknown UUID is driven entirely by the
#     state lookup.
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
# 1. /login Location header redirect_uri inspection -- DEFERRED.
#
# The intent here is to confirm the server-computed redirect_uri inside the
# IdP authorize URL contains the configured provider id and the callback
# path (so a compromised front-end cannot trick the IdP into redirecting to
# a third-party host). Implementing it requires a working OIDC discovery
# endpoint behind the configured issuer_url.
#
# Against an `.invalid` fixture issuer, `sso.rs` (see oidc_login, lines
# 101-108) fails the discovery `reqwest::get(...)` and surfaces
# AppError::Internal -> HTTP 500 before any Location header is built. The
# previous version of this test silently skipped on non-307 status, which
# meant the assertion never ran at all. Skipping explicitly is more honest.
#
# Followup: thread a stub IdP (mock server in tests/lib, local httpd serving
# a fixture .well-known/openid-configuration, or a configured-but-unreachable
# real-shaped issuer URL) before re-enabling these cases.
# -------------------------------------------------------------------------

begin_test "/login emits redirect_uri scoped to this provider id"
skip "requires OIDC discovery stub; see file header for followup"

begin_test "/login ignores client-supplied redirect_uri tampering"
skip "requires OIDC discovery stub; see file header for followup"

# -------------------------------------------------------------------------
# 2. Callback against an unknown provider id (random UUID) is rejected on
#    state validation, NOT on provider lookup. `oidc_callback`
#    (sso.rs:165-174) validates the SSO session FIRST, and since the state
#    we send was never minted, validate_sso_session raises
#    AppError::Authentication -> HTTP 401 (error.rs:89). The path UUID is
#    not compared against session.provider_id at all -- the practical
#    consequence is that the state token itself is the authoritative bind,
#    and any callback with a forged state lands on 401 regardless of the
#    path UUID. 2xx or 5xx here would both be regressions.
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
  # State is checked before provider lookup -> 401 from AppError::Authentication.
  if [ "$status" = "401" ]; then
    pass
  else
    fail "expected HTTP 401 for unknown provider id (state validated first), got HTTP ${status}"
  fi
fi

# -------------------------------------------------------------------------
# 3. Malformed provider id (not a UUID) must 4xx, never 5xx. The path
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
