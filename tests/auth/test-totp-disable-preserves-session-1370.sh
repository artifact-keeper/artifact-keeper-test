#!/usr/bin/env bash
# test-totp-disable-preserves-session-1370.sh
#
# Reproducer for artifact-keeper#1370: /auth/totp/disable returned 401 even
# when the caller supplied a correct password AND a current TOTP code. The
# regression was visible because the existing test-totp-disable.sh covered
# the rejection paths (wrong password, wrong code) but did not exercise the
# happy path against a Bearer-authenticated session — so a session/auth
# context check inside disable_totp could silently break without a gate
# catching it.
#
# Fix landed in artifact-keeper PR #1389. After the fix:
#   - disable with correct password + correct TOTP code returns 2xx
#   - /auth/me afterwards reports totp_enabled = false
#   - the original bearer token continues to work (session not invalidated)
#
# Pre-fix backend (1.1.0-rc.2): correct creds -> 401 (bug)
# Post-fix backend (main):      correct creds -> 200 + totp_enabled=false
#
# Backend reference:
#   - backend/src/api/handlers/totp.rs:371-423 disable_totp
#   - bcrypt::verify(password) AND totp.check_current(code) both must pass
#   - response: totp_enabled now reflects DB state, not cached claim
#
# This test deliberately overlaps with test-totp-disable.sh's "correct creds"
# branch so a future refactor that drops the happy-path assertion from the
# older suite still leaves the #1370-specific reproducer in place.
#
# Requires: curl, jq, python3 (for TOTP via totp_code helper)
source "$(dirname "$0")/../lib/common.sh"

begin_suite "auth-totp-disable-preserves-session-1370"
auth_admin
setup_workdir

# RUN_ID scoping prevents collisions when this and test-totp-disable.sh run in
# the same suite (release-gate runs both in parallel against one namespace).
TOTP_USER="totp-1370-${RUN_ID}"
TOTP_PASS="Totp1370Pass!_secure"
TOTP_EMAIL="totp-1370-${RUN_ID}@test.local"
USER_ID=""
USER_TOKEN=""
TOTP_SECRET=""

# ---------------------------------------------------------------------------
# Setup: create user, log in, enable TOTP.
# ---------------------------------------------------------------------------

begin_test "Create test user"
USER_ID=$(create_test_user "${TOTP_USER}" "${TOTP_PASS}" "${TOTP_EMAIL}") || true
if [ -n "$USER_ID" ]; then
  pass
else
  fail "could not create user"
fi

begin_test "Login as test user"
if [ -z "${USER_ID:-}" ]; then
  skip "no user"
else
  USER_TOKEN=$(login_as "${TOTP_USER}" "${TOTP_PASS}") || true
  if [ -n "$USER_TOKEN" ]; then
    pass
  else
    fail "login failed"
  fi
fi

begin_test "Enable TOTP (setup + enable)"
if [ -z "${USER_TOKEN:-}" ]; then
  skip "no user token"
else
  setup_resp=$(curl -sf $CURL_TIMEOUT -X POST \
    -H "Authorization: Bearer ${USER_TOKEN}" \
    "${BASE_URL}/api/v1/auth/totp/setup" 2>/dev/null) || true
  TOTP_SECRET=$(echo "$setup_resp" | jq -r '.secret // empty')
  if [ -z "$TOTP_SECRET" ] || [ "$TOTP_SECRET" = "null" ]; then
    fail "TOTP setup did not return a secret: ${setup_resp:0:200}"
  else
    CODE=$(totp_code "$TOTP_SECRET") || true
    enable_resp=$(curl -sf $CURL_TIMEOUT -X POST \
      -H "Authorization: Bearer ${USER_TOKEN}" \
      -H "Content-Type: application/json" \
      -d "{\"code\":\"${CODE}\"}" \
      "${BASE_URL}/api/v1/auth/totp/enable" 2>/dev/null) || true
    backup_count=$(echo "$enable_resp" | jq '.backup_codes | length // 0' 2>/dev/null)
    if [ "$backup_count" -ge 1 ]; then
      pass
    else
      fail "TOTP enable did not return backup_codes: ${enable_resp:0:200}"
    fi
  fi
fi

# ---------------------------------------------------------------------------
# Confirm TOTP really is enabled before we try to disable it — otherwise a
# "disable succeeded" result would be ambiguous (was it never enabled?).
# ---------------------------------------------------------------------------

begin_test "Confirm totp_enabled = true after enable"
if [ -z "${USER_TOKEN:-}" ] || [ -z "${TOTP_SECRET:-}" ]; then
  skip "TOTP not enabled"
else
  me_resp=$(curl -sf $CURL_TIMEOUT \
    -H "Authorization: Bearer ${USER_TOKEN}" \
    "${BASE_URL}/api/v1/auth/me" 2>/dev/null) || true
  # See test-totp-disable.sh for why we don't use `jq -r '.totp_enabled // empty'`:
  # jq's `//` operator treats `false` as a missing alternative.
  totp_state=$(echo "$me_resp" | jq -r '
    if has("totp_enabled") then
      if .totp_enabled == false then "false"
      elif .totp_enabled == true then "true"
      else "non-bool"
      end
    else "missing"
    end
  ' 2>/dev/null) || totp_state=""
  if [ "$totp_state" = "true" ]; then
    pass
  else
    fail "pre-condition: expected totp_enabled=true after enable, got '${totp_state}'" "$me_resp"
  fi
fi

# ---------------------------------------------------------------------------
# THE BUG: correct password + correct TOTP code returned 401 before #1389.
#
# Use 'wait' mode for totp_code so we don't reuse the code consumed by /enable
# — the backend rejects code reuse inside a 30s window as a replay defense.
# Without 'wait', this assertion can spuriously fail with HTTP 401 even on a
# fixed backend, exactly the false-positive class we want to avoid in a gate.
# ---------------------------------------------------------------------------

begin_test "Disable with correct password + correct code returns 2xx (#1370)"
if [ -z "${USER_TOKEN:-}" ] || [ -z "${TOTP_SECRET:-}" ]; then
  skip "TOTP not enabled"
else
  CODE=$(totp_code "$TOTP_SECRET" wait) || true
  # Capture body so the failure message is actionable. The pre-fix backend
  # returns AppError::Authentication("invalid session") which makes the
  # regression unambiguous in CI logs.
  tmp=$(mktemp)
  status=$(curl -s -o "$tmp" -w '%{http_code}' $CURL_TIMEOUT \
    -X POST \
    -H "Authorization: Bearer ${USER_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{\"password\":\"${TOTP_PASS}\",\"code\":\"${CODE}\"}" \
    "${BASE_URL}/api/v1/auth/totp/disable" 2>/dev/null) || status="000"
  body=$(cat "$tmp" 2>/dev/null || true)
  rm -f "$tmp"
  if [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then
    pass
  elif [ "$status" = "401" ]; then
    fail "pre-fix bug: disable returned 401 with correct password + correct code (#1370 regression)" "$body"
  else
    fail "expected 2xx from /totp/disable with correct creds, got HTTP ${status}" "$body"
  fi
fi

# ---------------------------------------------------------------------------
# After disable, the persisted user state must reflect totp_enabled = false.
# A bug that returns 2xx but doesn't actually flip the column would otherwise
# slip through the previous assertion.
# ---------------------------------------------------------------------------

begin_test "After disable, /auth/me reports totp_enabled = false"
if [ -z "${USER_TOKEN:-}" ]; then
  skip "no user token"
else
  me_resp=$(curl -sf $CURL_TIMEOUT \
    -H "Authorization: Bearer ${USER_TOKEN}" \
    "${BASE_URL}/api/v1/auth/me" 2>/dev/null) || true
  totp_state=$(echo "$me_resp" | jq -r '
    if has("totp_enabled") then
      if .totp_enabled == false then "false"
      elif .totp_enabled == true then "true"
      else "non-bool"
      end
    else "missing"
    end
  ' 2>/dev/null) || totp_state=""
  if [ "$totp_state" = "false" ]; then
    pass
  else
    fail "expected totp_enabled=false after disable, got '${totp_state}'" "$me_resp"
  fi
fi

# ---------------------------------------------------------------------------
# Session preservation: the bearer token used to call /totp/disable must
# remain valid afterwards. Some early drafts of the fix invalidated the
# session as a "safety" step; that broke the UI because the user got logged
# out at the moment they disabled 2FA. #1370's acceptance criteria require
# the session to survive.
# ---------------------------------------------------------------------------

begin_test "Bearer token still works after disable (session preserved)"
if [ -z "${USER_TOKEN:-}" ]; then
  skip "no user token"
else
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "Authorization: Bearer ${USER_TOKEN}" \
    "${BASE_URL}/api/v1/auth/me" 2>/dev/null) || status="000"
  if [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then
    pass
  else
    fail "session was invalidated by /totp/disable (HTTP ${status} on /auth/me) — #1370 expects session to survive"
  fi
fi

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

if [ -n "${USER_ID:-}" ] && [ "$USER_ID" != "null" ]; then
  api_delete "/api/v1/users/${USER_ID}" > /dev/null 2>&1 || true
fi

enable_expect_failure_trap

end_suite
