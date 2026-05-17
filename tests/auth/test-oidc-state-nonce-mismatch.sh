#!/usr/bin/env bash
# test-oidc-state-nonce-mismatch.sh - OIDC state / nonce mismatch (Epic 11.3, #76)
#
# Targets the OIDC authorization-code callback handler. RFC 6749 sec 10.12 and
# OIDC core sec 15.5.2 require the callback to bind the returned `state` to a
# server-side single-use entry that was minted by the matching `/login` redirect.
# A callback that arrives with:
#   - a `state` value that was never minted (forged)
#   - the required `code` parameter omitted entirely
#   - a state that has already been consumed (single-use replay)
# must be rejected before any token exchange or session bootstrap fires.
#
# Backend reference (read 2026-05-16):
#   - `AuthConfigService::validate_sso_session` (auth_config_service.rs:1235)
#     issues `DELETE FROM sso_sessions WHERE state = $1 RETURNING ...`. The
#     lookup ignores `provider_id`, so the only enforced defenses are:
#       (a) the state must exist in the sso_sessions table
#       (b) DELETE...RETURNING makes the row single-use
#       (c) expires_at is checked after the delete
#   - When state is missing/expired, the handler raises `AppError::Authentication`,
#     which maps to HTTP 401 in `error.rs:89`. We assert the specific 401, not
#     "any 4xx" -- the prior test-oidc-callback.sh accepts any non-5xx, which
#     lets a future regression that silently 200s a forged callback slip through.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "auth-oidc-state-nonce-mismatch"
auth_admin
setup_workdir

OIDC_CFG_ID=""
SSO_AVAILABLE="unknown"

# Always-on cleanup: remove any OIDC configs we created even on early exit.
cleanup_oidc() {
  if [ -n "${OIDC_CFG_ID:-}" ] && [ "$OIDC_CFG_ID" != "null" ]; then
    curl -s -o /dev/null -X DELETE -H "$(auth_header)" \
      "${BASE_URL}/api/v1/admin/sso/oidc/${OIDC_CFG_ID}" >/dev/null 2>&1 || true
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

begin_test "Create throwaway OIDC config"
if [ "$SSO_AVAILABLE" != "true" ]; then
  skip "SSO not available"
else
  cfg_resp=$(curl -s $CURL_TIMEOUT -X POST \
    -H "$(auth_header)" \
    -H "Content-Type: application/json" \
    -d "$(jq -nc \
      --arg name "e2e-oidc-state-${RUN_ID}" \
      --arg iss "https://fixture-state-${RUN_ID}.invalid" \
      --arg cid "client-state-${RUN_ID}" \
      --arg sec "secret-state-${RUN_ID}" \
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
# 1. Forged state: a state value that was never minted by /login. Backend
#    cannot find it in the sso_sessions table, so validate_sso_session
#    raises AppError::Authentication -> HTTP 401 (error.rs:89).
# -------------------------------------------------------------------------

begin_test "Callback with forged state returns 401"
if [ -z "${OIDC_CFG_ID:-}" ]; then
  skip "no OIDC config"
else
  forged_state="forged-state-${RUN_ID}-$(date +%s)"
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    "${BASE_URL}/api/v1/auth/sso/oidc/${OIDC_CFG_ID}/callback?state=${forged_state}&code=bogus-${RUN_ID}" \
    2>/dev/null) || true
  status="${status:-000}"
  # Backend maps "Invalid or expired SSO state" -> AppError::Authentication -> 401.
  if [ "$status" = "401" ]; then
    pass
  else
    fail "expected HTTP 401 for forged state, got HTTP ${status}"
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
# 4. Forged state replay is rejected on every attempt. validate_sso_session
#    issues `DELETE...RETURNING` so a missing-state lookup deletes nothing
#    but must still return 401 every time; a naive implementation that
#    caches the negative result could regress to a stale 2xx.
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
