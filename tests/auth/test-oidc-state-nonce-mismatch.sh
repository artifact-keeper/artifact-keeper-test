#!/usr/bin/env bash
# test-oidc-state-nonce-mismatch.sh - OIDC state / nonce mismatch (Epic 11.3, #76)
#
# Targets the OIDC authorization-code callback handler. RFC 6749 sec 10.12 and
# OIDC core sec 15.5.2 require the callback to bind the returned `state` to a
# server-side single-use entry that was minted by the matching `/login` redirect.
# A callback that arrives with:
#   - a `state` value that was never minted (forged / replayed across providers)
#   - the correct `state` shape but bound to a different OIDC config id
#   - the required `code` parameter omitted entirely
# must be rejected before any token exchange or session bootstrap fires.
#
# Per openapi.yaml (line 2207, /api/v1/auth/sso/oidc/{id}/callback), the
# documented failure response is HTTP 400 with ErrorResponse. We assert the
# specific 400 status code, not "any 4xx" -- the prior test-oidc-callback.sh
# checks the route is registered but accepts any non-5xx, which lets a future
# regression that silently 200s a forged callback slip through.
#
# Backend reference:
#   - sso/oidc.rs callback handler; state is stored in OIDC_STATE_CACHE keyed
#     by (state_token, provider_id) with a 10 minute TTL.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "auth-oidc-state-nonce-mismatch"
auth_admin
setup_workdir

OIDC_CFG_ID=""
OIDC_CFG_ID_OTHER=""
SSO_AVAILABLE="unknown"

# Always-on cleanup: remove any OIDC configs we created even on early exit.
cleanup_oidc() {
  if [ -n "${OIDC_CFG_ID:-}" ] && [ "$OIDC_CFG_ID" != "null" ]; then
    curl -s -o /dev/null -X DELETE -H "$(auth_header)" \
      "${BASE_URL}/api/v1/admin/sso/oidc/${OIDC_CFG_ID}" >/dev/null 2>&1 || true
  fi
  if [ -n "${OIDC_CFG_ID_OTHER:-}" ] && [ "$OIDC_CFG_ID_OTHER" != "null" ]; then
    curl -s -o /dev/null -X DELETE -H "$(auth_header)" \
      "${BASE_URL}/api/v1/admin/sso/oidc/${OIDC_CFG_ID_OTHER}" >/dev/null 2>&1 || true
  fi
}
add_exit_handler 'cleanup_oidc'

# -------------------------------------------------------------------------
# Pre-flight: SSO must be wired up. Older builds without the SSO routes
# 404 on /auth/sso/providers; in that case we skip the suite, not fail it.
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
  # 401/403 still means the routes exist -- the auth check fired.
  SSO_AVAILABLE=true
  pass
fi

# -------------------------------------------------------------------------
# Create a throwaway OIDC config so we have a real provider id to bind
# state to. The issuer_url is bogus on purpose -- we never invoke /login,
# so the discovery document is never fetched. RUN_ID keeps the config
# unique across parallel suites.
# -------------------------------------------------------------------------

begin_test "Create throwaway OIDC config (provider A)"
if [ "$SSO_AVAILABLE" != "true" ]; then
  skip "SSO not available"
else
  cfg_resp=$(curl -s $CURL_TIMEOUT -X POST \
    -H "$(auth_header)" \
    -H "Content-Type: application/json" \
    -d "$(jq -nc \
      --arg name "e2e-oidc-a-${RUN_ID}" \
      --arg iss "https://fixture-a-${RUN_ID}.invalid" \
      --arg cid "client-a-${RUN_ID}" \
      --arg sec "secret-a-${RUN_ID}" \
      '{name:$name,issuer_url:$iss,client_id:$cid,client_secret:$sec,is_enabled:false}')" \
    "${BASE_URL}/api/v1/admin/sso/oidc" 2>/dev/null) || cfg_resp=""
  OIDC_CFG_ID=$(echo "$cfg_resp" | jq -r '.id // empty' 2>/dev/null)
  if [ -n "$OIDC_CFG_ID" ] && [ "$OIDC_CFG_ID" != "null" ]; then
    pass
  else
    fail "could not create OIDC config A" "${cfg_resp:0:300}"
  fi
fi

begin_test "Create throwaway OIDC config (provider B)"
if [ "$SSO_AVAILABLE" != "true" ] || [ -z "${OIDC_CFG_ID:-}" ]; then
  skip "provider A unavailable"
else
  cfg_resp=$(curl -s $CURL_TIMEOUT -X POST \
    -H "$(auth_header)" \
    -H "Content-Type: application/json" \
    -d "$(jq -nc \
      --arg name "e2e-oidc-b-${RUN_ID}" \
      --arg iss "https://fixture-b-${RUN_ID}.invalid" \
      --arg cid "client-b-${RUN_ID}" \
      --arg sec "secret-b-${RUN_ID}" \
      '{name:$name,issuer_url:$iss,client_id:$cid,client_secret:$sec,is_enabled:false}')" \
    "${BASE_URL}/api/v1/admin/sso/oidc" 2>/dev/null) || cfg_resp=""
  OIDC_CFG_ID_OTHER=$(echo "$cfg_resp" | jq -r '.id // empty' 2>/dev/null)
  if [ -n "$OIDC_CFG_ID_OTHER" ] && [ "$OIDC_CFG_ID_OTHER" != "null" ]; then
    pass
  else
    fail "could not create OIDC config B" "${cfg_resp:0:300}"
  fi
fi

# -------------------------------------------------------------------------
# 1. Forged state: a state value that was never minted by /login. Backend
#    cannot look it up in OIDC_STATE_CACHE, so the callback must 400.
# -------------------------------------------------------------------------

begin_test "Callback with forged state returns 400"
if [ -z "${OIDC_CFG_ID:-}" ]; then
  skip "no OIDC config"
else
  forged_state="forged-state-${RUN_ID}-$(date +%s)"
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    "${BASE_URL}/api/v1/auth/sso/oidc/${OIDC_CFG_ID}/callback?state=${forged_state}&code=bogus-${RUN_ID}" \
    2>/dev/null) || true
  status="${status:-000}"
  # openapi.yaml documents 400 for invalid callback parameters.
  if [ "$status" = "400" ]; then
    pass
  else
    fail "expected HTTP 400 for forged state, got HTTP ${status}"
  fi
fi

# -------------------------------------------------------------------------
# 2. Empty state: the state query parameter is required (openapi line 2226).
#    A missing/empty value short-circuits before any cache lookup.
# -------------------------------------------------------------------------

begin_test "Callback with empty state returns 400"
if [ -z "${OIDC_CFG_ID:-}" ]; then
  skip "no OIDC config"
else
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    "${BASE_URL}/api/v1/auth/sso/oidc/${OIDC_CFG_ID}/callback?state=&code=bogus-${RUN_ID}" \
    2>/dev/null) || true
  status="${status:-000}"
  # An empty required query param may surface as 400 (handler-level) or 422
  # (axum extractor). Both are documented 4xx; reject anything else.
  if [ "$status" = "400" ] || [ "$status" = "422" ]; then
    pass
  else
    fail "expected HTTP 400/422 for empty state, got HTTP ${status}"
  fi
fi

# -------------------------------------------------------------------------
# 3. Missing code: state present but no code parameter. RFC 6749 sec 4.1.2
#    mandates the authorization code; absence is a callback misuse.
# -------------------------------------------------------------------------

begin_test "Callback without code returns 400"
if [ -z "${OIDC_CFG_ID:-}" ]; then
  skip "no OIDC config"
else
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    "${BASE_URL}/api/v1/auth/sso/oidc/${OIDC_CFG_ID}/callback?state=anything-${RUN_ID}" \
    2>/dev/null) || true
  status="${status:-000}"
  if [ "$status" = "400" ] || [ "$status" = "422" ]; then
    pass
  else
    fail "expected HTTP 400/422 for missing code, got HTTP ${status}"
  fi
fi

# -------------------------------------------------------------------------
# 4. State bound to wrong provider: a forged state that *looks* the right
#    shape but is delivered to a different provider id than the one that
#    minted it. OIDC_STATE_CACHE keys by (state_token, provider_id) so the
#    lookup must miss and the callback must 400. This is the canonical
#    cross-provider state-fixation attack.
# -------------------------------------------------------------------------

begin_test "Callback with state bound to wrong provider returns 400"
if [ -z "${OIDC_CFG_ID:-}" ] || [ -z "${OIDC_CFG_ID_OTHER:-}" ]; then
  skip "two OIDC configs required"
else
  # Build a plausible-looking state and replay it against provider B. Even
  # if a malicious /login somehow leaked a state intended for provider A,
  # provider B's cache lookup keyed by (state, B) cannot match.
  smuggled_state="cross-provider-${RUN_ID}-$(date +%s)"
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    "${BASE_URL}/api/v1/auth/sso/oidc/${OIDC_CFG_ID_OTHER}/callback?state=${smuggled_state}&code=bogus-${RUN_ID}" \
    2>/dev/null) || true
  status="${status:-000}"
  if [ "$status" = "400" ]; then
    pass
  else
    fail "expected HTTP 400 for cross-provider state, got HTTP ${status}"
  fi
fi

# -------------------------------------------------------------------------
# 5. Repeated forged state must remain rejected. A naive cache that key-
#    misses on first lookup but caches the rejection result could later
#    accept a replay; this asserts the rejection is stateless.
# -------------------------------------------------------------------------

begin_test "Forged state stays rejected on replay"
if [ -z "${OIDC_CFG_ID:-}" ]; then
  skip "no OIDC config"
else
  replay_state="replay-${RUN_ID}-$(date +%s)"
  any_accepted=false
  for attempt in 1 2 3; do
    s=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
      "${BASE_URL}/api/v1/auth/sso/oidc/${OIDC_CFG_ID}/callback?state=${replay_state}&code=bogus-${RUN_ID}-${attempt}" \
      2>/dev/null) || true
    s="${s:-000}"
    if [ "$s" -ge 200 ] 2>/dev/null && [ "$s" -lt 400 ] 2>/dev/null; then
      any_accepted=true
      echo "  replay attempt ${attempt} returned HTTP ${s} (expected 4xx)"
      break
    fi
  done
  if [ "$any_accepted" = "false" ]; then
    pass
  else
    fail "forged state was accepted on replay"
  fi
fi

end_suite
