#!/usr/bin/env bash
# test-totp-backup-codes.sh - TOTP backup code consumption (Epic 11.10, #76)
#
# Verifies:
#   1. Enabling TOTP returns 10 backup codes
#   2. Logging in with username/password returns a totp_required + totp_token
#   3. POST /auth/totp/verify with a backup code (in lieu of the live TOTP)
#      succeeds the first time
#   4. The same backup code is rejected on the second use (single-use)
#   5. After all 10 backup codes are consumed, none of them work
#
# Backend reference:
#   - totp.rs:266-296 backup-code branch in verify_totp; matched code is
#     replaced with empty string in the stored array, and an empty hash is
#     skipped (`if !hash.is_empty()`), so each code is single-use
#
# Requires: curl, jq, python3 (for TOTP code generation via totp_code helper)
source "$(dirname "$0")/../lib/common.sh"

begin_suite "auth-totp-backup-codes"

auth_admin
setup_workdir

TOTP_USER="totp-bk-${RUN_ID}"
TOTP_PASS="TotpBkPass123!"
TOTP_EMAIL="totp-bk-${RUN_ID}@test.local"
USER_ID=""
USER_TOKEN=""
TOTP_SECRET=""
BACKUP_CODES_JSON=""

# -------------------------------------------------------------------------
# Setup user + login
# -------------------------------------------------------------------------

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

# -------------------------------------------------------------------------
# TOTP setup -> get the secret
# -------------------------------------------------------------------------

begin_test "TOTP setup returns base32 secret"
if [ -z "${USER_TOKEN:-}" ]; then
  skip "no user token"
else
  resp=$(curl -sf $CURL_TIMEOUT -X POST \
    -H "Authorization: Bearer ${USER_TOKEN}" \
    "${BASE_URL}/api/v1/auth/totp/setup" 2>/dev/null) || true
  TOTP_SECRET=$(echo "$resp" | jq -r '.secret // empty')
  if [ -n "$TOTP_SECRET" ] && [ "$TOTP_SECRET" != "null" ]; then
    pass
  else
    fail "no secret returned: ${resp:0:200}"
  fi
fi

# -------------------------------------------------------------------------
# Enable TOTP -> get backup codes
# -------------------------------------------------------------------------

begin_test "Enable TOTP returns 10 backup codes"
if [ -z "${TOTP_SECRET:-}" ]; then
  skip "no TOTP secret"
else
  CODE=$(totp_code "$TOTP_SECRET") || true
  if [ -z "$CODE" ]; then
    fail "totp_code helper failed to generate TOTP code"
  else
    resp=$(curl -sf $CURL_TIMEOUT -X POST \
      -H "Authorization: Bearer ${USER_TOKEN}" \
      -H "Content-Type: application/json" \
      -d "{\"code\":\"${CODE}\"}" \
      "${BASE_URL}/api/v1/auth/totp/enable" 2>/dev/null) || true
    BACKUP_CODES_JSON=$(echo "$resp" | jq -c '.backup_codes // empty')
    count=$(echo "$BACKUP_CODES_JSON" | jq 'length // 0' 2>/dev/null)
    if [ "$count" = "10" ]; then
      pass
    else
      fail "expected 10 backup codes, got '${count}': ${resp:0:200}"
    fi
  fi
fi

# -------------------------------------------------------------------------
# Helper: log in again to get a fresh totp_token, then verify with code.
# Always returns 0 and prints the HTTP status (or a sentinel string) on
# stdout. Callers inspect the printed value directly.
#
# NOTE: this MUST always return 0 because the test runs with `set -e` and the
# helper is called via plain command substitution (`status=$(...)`). If the
# helper returned non-zero on a 401 response, bash would abort the whole
# script before the test could assert that 401 was the expected outcome —
# which is exactly the bug release-gate run 25191428274 surfaced for the
# "Replay of the same backup code is rejected" case.
#
# Login is retried on transient failures (HTTP 429 / 5xx / curl error). Each
# call to this helper performs a username+password login, and the loginAuth
# rate limiter throttles bursts per-user. The "Each remaining backup code is
# single-use" test makes ~18 logins back-to-back, so retry-on-429 is required
# to avoid the no_totp_token sentinel surfacing as a flake (release-gate run
# 25214268566 / job 73931323974 hit this on backup code [4]).
# -------------------------------------------------------------------------

login_and_verify_with_code() {
  local backup_code="$1"
  local _max="${LOGIN_VERIFY_MAX_ATTEMPTS:-8}"
  local _delay="${LOGIN_VERIFY_RETRY_DELAY:-3}"
  local _attempt _http_status _body _tmp totp_token=""
  for _attempt in $(seq 1 "$_max"); do
    _tmp=$(mktemp)
    _http_status=$(curl -s --max-time 10 -o "$_tmp" -w '%{http_code}' \
      -X POST "${BASE_URL}/api/v1/auth/login" \
      -H "Content-Type: application/json" \
      -d "{\"username\":\"${TOTP_USER}\",\"password\":\"${TOTP_PASS}\"}" 2>/dev/null) || _http_status="000"
    _body=$(cat "$_tmp" 2>/dev/null || true)
    rm -f "$_tmp"

    if [ "$_http_status" = "200" ]; then
      totp_token=$(echo "$_body" | jq -r '.totp_token // empty' 2>/dev/null)
      [ -n "$totp_token" ] && [ "$totp_token" != "null" ] && break
      totp_token=""
    fi

    # Only retry on transient failures. A non-200 with a parseable body that
    # isn't 429/5xx/000 means the backend rejected the credentials for some
    # other reason and retrying won't help.
    case "$_http_status" in
      429|500|502|503|504|000) ;;
      *)
        # Non-transient: bail out so the caller sees the sentinel rather than
        # spinning for ~24s on a permanent error.
        break
        ;;
    esac

    if [ "$_attempt" -lt "$_max" ]; then
      echo "  login_and_verify retry ${_attempt}/${_max} (HTTP ${_http_status}), sleeping ${_delay}s..." 1>&2
      if [ "$_http_status" = "429" ]; then
        sleep "$(( _delay * 2 ))"
      else
        sleep "$_delay"
      fi
    fi
  done

  if [ -z "$totp_token" ]; then
    echo "no_totp_token"
    return 0
  fi

  local status
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X POST \
    -H "Content-Type: application/json" \
    -d "{\"totp_token\":\"${totp_token}\",\"code\":\"${backup_code}\"}" \
    "${BASE_URL}/api/v1/auth/totp/verify" 2>/dev/null) || true
  status="${status:-000}"
  echo "$status"
  return 0
}

# -------------------------------------------------------------------------
# First use of backup code 0 succeeds
# -------------------------------------------------------------------------

begin_test "First use of backup code succeeds"
if [ -z "${BACKUP_CODES_JSON:-}" ]; then
  skip "no backup codes"
else
  FIRST_CODE=$(echo "$BACKUP_CODES_JSON" | jq -r '.[0]')
  status=$(login_and_verify_with_code "$FIRST_CODE")
  if [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then
    pass
  else
    fail "first backup-code verify returned HTTP ${status} (expected 2xx)"
  fi
fi

# -------------------------------------------------------------------------
# Second use of the same backup code is rejected
# -------------------------------------------------------------------------

begin_test "Replay of the same backup code is rejected"
if [ -z "${BACKUP_CODES_JSON:-}" ]; then
  skip "no backup codes"
else
  status=$(login_and_verify_with_code "$FIRST_CODE")
  # backup-code mismatch -> AppError::Authentication -> 401
  if [ "$status" = "401" ]; then
    pass
  else
    fail "expected 401 on backup-code replay, got HTTP ${status}"
  fi
fi

# -------------------------------------------------------------------------
# Consume the remaining 9 codes; each should work exactly once.
# -------------------------------------------------------------------------

begin_test "Each remaining backup code is single-use"
if [ -z "${BACKUP_CODES_JSON:-}" ]; then
  skip "no backup codes"
else
  used_ok=true
  for i in 1 2 3 4 5 6 7 8 9; do
    code=$(echo "$BACKUP_CODES_JSON" | jq -r ".[$i]")
    if [ -z "$code" ] || [ "$code" = "null" ]; then
      used_ok=false
      echo "  missing backup code at index ${i}"
      break
    fi
    s=$(login_and_verify_with_code "$code")
    if ! { [ "$s" -ge 200 ] 2>/dev/null && [ "$s" -lt 300 ] 2>/dev/null; }; then
      used_ok=false
      echo "  backup code [${i}] (${code}) failed first use: HTTP ${s}"
      break
    fi
    # Replay should be rejected with 401
    s2=$(login_and_verify_with_code "$code")
    if [ "$s2" != "401" ]; then
      used_ok=false
      echo "  backup code [${i}] replay returned HTTP ${s2} (expected 401)"
      break
    fi
  done
  if [ "$used_ok" = "true" ]; then
    pass
  else
    fail "remaining backup codes did not behave as single-use"
  fi
fi

# -------------------------------------------------------------------------
# After all 10 are consumed, no original code works
# -------------------------------------------------------------------------

begin_test "Exhausted backup codes are all rejected"
if [ -z "${BACKUP_CODES_JSON:-}" ]; then
  skip "no backup codes"
else
  any_accepted=false
  for i in 0 1 2 3 4 5 6 7 8 9; do
    code=$(echo "$BACKUP_CODES_JSON" | jq -r ".[$i]")
    s=$(login_and_verify_with_code "$code")
    if [ "$s" -ge 200 ] 2>/dev/null && [ "$s" -lt 300 ] 2>/dev/null; then
      any_accepted=true
      echo "  backup code [${i}] still accepted after exhaustion (HTTP ${s})"
      break
    fi
  done
  if [ "$any_accepted" = "false" ]; then
    pass
  else
    fail "at least one backup code was accepted after the pool was exhausted"
  fi
fi

# -------------------------------------------------------------------------
# Cleanup
# -------------------------------------------------------------------------

if [ -n "${USER_ID:-}" ] && [ "$USER_ID" != "null" ]; then
  api_delete "/api/v1/users/${USER_ID}" > /dev/null 2>&1 || true
fi

# EXPECT_FAILURE=1 inverts the suite's exit code so this script can be used
# as a fixture to validate the gate (a "broken" gate is a passing self-test).
enable_expect_failure_trap

end_suite
