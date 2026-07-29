#!/usr/bin/env bash
# test-deactivated-user-token-1371.sh
#
# Reproducer for artifact-keeper#1371: an API token issued to a user remained
# valid for up to API_TOKEN_CACHE_TTL_SECS (300s) after the user was
# deactivated. The validation query already filtered `is_active = true`, but
# auth_service kept a 5-minute in-process cache keyed on token hash and never
# evicted on user state change. From a security standpoint, "token works for
# 5 more minutes after we revoked access" is the kind of finding that lands
# in a penetration test report.
#
# Fix landed in artifact-keeper PR #1390. After the fix:
#   - PATCH /users/{id} { is_active: false } flushes the API-token cache
#     entries belonging to that user
#   - any subsequent token use returns 401 within seconds, not minutes
#
# Pre-fix backend (1.1.0-rc.2): token accepted for ~300s after deactivation
# Post-fix backend (main):      token rejected with 401 within 5s
#
# The existing test-user-deactivation-revokes-tokens.sh polls for ~30s and
# SKIPs when require_feature("user_deactivation_token_flush") says the
# backend is older than v1.1.9. That suite is intentionally tolerant so it
# can run against older release branches.
#
# This script is the stricter reproducer: a 5-second poll budget that asserts
# the cache flush happened promptly. It targets the SAME feature flag so a
# backend that lacks the fix is still gracefully skipped — but where the fix
# IS present (v1.1.9+, current main), 30s of waiting is too loose to catch a
# half-broken cache flush (e.g. one that only evicts on the next eviction
# tick instead of immediately).
#
# Backend reference:
#   - backend/src/services/auth_service.rs API_TOKEN_CACHE_TTL_SECS / cache
#   - backend/src/api/handlers/users.rs PATCH /users/{id} -> set_user_active
#   - PR #1390: flush_api_token_cache_for_user invoked on is_active flip
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "auth-deactivated-user-token-1371"
auth_admin
setup_workdir

DEACT_USER="e2e-1371-${RUN_ID}"
DEACT_PASS="Deact1371Pass!_strong"
DEACT_EMAIL="e2e-1371-${RUN_ID}@test.local"
USER_ID=""
USER_TOKEN=""
API_TOKEN=""
API_TOKEN_ID=""

# 5-second poll budget, 500ms steps. Total max attempts = 10. We want a
# response within seconds, not minutes — that is the bug being asserted.
POLL_TIMEOUT_SECS=5
POLL_STEP_SECS=0.5

# ---------------------------------------------------------------------------
# Setup: create the user, log in, mint an API token, confirm it works.
# ---------------------------------------------------------------------------

begin_test "Create test user"
USER_ID=$(create_test_user "${DEACT_USER}" "${DEACT_PASS}" "${DEACT_EMAIL}") || true
if [ -n "$USER_ID" ]; then
  pass
else
  fail "could not create user"
fi

begin_test "Login + mint API token in user's session"
if [ -z "${USER_ID:-}" ]; then
  skip "no user"
else
  USER_TOKEN=$(login_as "${DEACT_USER}" "${DEACT_PASS}") || true
  if [ -z "$USER_TOKEN" ]; then
    fail "login failed"
  else
    tok_resp=$(curl -sf $CURL_TIMEOUT -X POST \
      -H "Authorization: Bearer ${USER_TOKEN}" \
      -H "Content-Type: application/json" \
      -d '{"name":"e2e-1371","scopes":["read:artifacts","write:artifacts"]}' \
      "${BASE_URL}/api/v1/auth/tokens" 2>/dev/null) || true
    API_TOKEN=$(echo "$tok_resp" | jq -r '.token // empty')
    API_TOKEN_ID=$(echo "$tok_resp" | jq -r '.id // empty')
    if [ -n "$API_TOKEN" ] && [ "$API_TOKEN" != "null" ]; then
      pass
    else
      fail "could not mint API token: ${tok_resp:0:200}"
    fi
  fi
fi

# Prime the in-process API-token cache by using the token at least once
# before deactivation. Without this prime call, the post-deactivation poll
# could pass for the wrong reason (the cache was simply empty all along).
# Priming guarantees we are testing the FLUSH path, not the COLD-MISS path.
begin_test "API token works before deactivation (and primes cache)"
if [ -z "${API_TOKEN:-}" ] || [ "$API_TOKEN" = "null" ]; then
  skip "no API token"
else
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "Authorization: Bearer ${API_TOKEN}" \
    "${BASE_URL}/api/v1/repositories" 2>/dev/null) || status="000"
  if [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then
    pass
  else
    fail "API token returned HTTP ${status} before deactivation"
  fi
fi

# ---------------------------------------------------------------------------
# Deactivate the user. Backend route is PATCH-only (users.rs uses
# axum::routing::patch). If a regression switches the verb, this assert
# catches it before we get to the cache-flush check.
# ---------------------------------------------------------------------------

begin_test "Admin deactivates user (PATCH /users/{id})"
if [ -z "${USER_ID:-}" ] || [ "$USER_ID" = "null" ]; then
  skip "no user ID"
else
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X PATCH \
    -H "$(auth_header)" \
    -H "Content-Type: application/json" \
    -d '{"is_active":false}' \
    "${BASE_URL}/api/v1/users/${USER_ID}" 2>/dev/null) || status="000"
  if [ "$status" -ge 200 ] && [ "$status" -lt 300 ]; then
    pass
  else
    fail "deactivate returned HTTP ${status}"
  fi
fi

# ---------------------------------------------------------------------------
# THE BUG (#1371): the token used to work for ~5 minutes after deactivation.
# Post-fix, it must be rejected within 5 seconds.
#
# require_feature gates this against backends that lack the fix so the same
# script can run against release/1.1.x without spurious failures. When the
# feature is present (main, v1.1.9+), we hold the backend to the tight SLA.
# ---------------------------------------------------------------------------

begin_test "Deactivated user's API token is rejected within 5s (#1371 SLA)"
if [ -z "${API_TOKEN:-}" ] || [ "$API_TOKEN" = "null" ]; then
  skip "no API token to test"
elif require_feature "user_deactivation_token_flush"; then
  rejected=false
  last_status=""
  attempts=0
  # Wall-clock budget: we want to know how fast the cache flush propagates.
  start_ts=$(date +%s)
  while :; do
    attempts=$(( attempts + 1 ))
    last_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
      -H "Authorization: Bearer ${API_TOKEN}" \
      "${BASE_URL}/api/v1/repositories" 2>/dev/null) || last_status="000"
    if [ "$last_status" = "401" ]; then
      rejected=true
      break
    fi
    now_ts=$(date +%s)
    elapsed=$(( now_ts - start_ts ))
    if [ "$elapsed" -ge "$POLL_TIMEOUT_SECS" ]; then
      break
    fi
    sleep "$POLL_STEP_SECS"
  done
  if [ "$rejected" = "true" ]; then
    pass
  else
    # The pre-fix backend lingers at HTTP 200 because the cache hands out a
    # stale "user.is_active = true" verdict. Surface the actual status so
    # CI logs make the regression obvious instead of opaque.
    fail "token still accepted (HTTP ${last_status}) after ${POLL_TIMEOUT_SECS}s — cache flush did not propagate (#1371)" \
      "attempts=${attempts}, last_status=${last_status}, user_id=${USER_ID}"
  fi
fi

# ---------------------------------------------------------------------------
# Belt-and-suspenders: a fresh login as the deactivated user must fail
# outright. The login query has its own is_active filter, so this catches
# any future refactor that accidentally drops it from the login path while
# leaving the token path "correct".
# ---------------------------------------------------------------------------

begin_test "Login as deactivated user fails with 401"
if [ -z "${USER_ID:-}" ] || [ "$USER_ID" = "null" ]; then
  skip "no user ID"
else
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X POST \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${DEACT_USER}\",\"password\":\"${DEACT_PASS}\"}" \
    "${BASE_URL}/api/v1/auth/login" 2>/dev/null) || status="000"
  if [ "$status" = "401" ]; then
    pass
  else
    fail "expected 401 for deactivated user login, got HTTP ${status}"
  fi
fi

# ---------------------------------------------------------------------------
# Cleanup: reactivate so delete works cleanly, then delete the user.
# Same pattern as test-user-deactivation-revokes-tokens.sh — keep them in
# sync so a future shared helper can replace both.
# ---------------------------------------------------------------------------

if [ -n "${USER_ID:-}" ] && [ "$USER_ID" != "null" ]; then
  curl -s -o /dev/null -X PATCH \
    -H "$(auth_header)" \
    -H "Content-Type: application/json" \
    -d '{"is_active":true}' \
    "${BASE_URL}/api/v1/users/${USER_ID}" > /dev/null 2>&1 || true
  api_delete "/api/v1/users/${USER_ID}" > /dev/null 2>&1 || true
fi

enable_expect_failure_trap

end_suite
