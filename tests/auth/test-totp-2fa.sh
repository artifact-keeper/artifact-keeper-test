#!/usr/bin/env bash
# test-totp-2fa.sh - TOTP 2FA setup and verification E2E test
#
# Tests TOTP setup, rejection of an invalid code, and enrollment with a real
# oathtool-generated code.
#
# Requires: curl, jq, oathtool (installed by the auth-tests job in
# release-gate.yml; a missing oathtool is reported as an infra failure on the
# enrollment testcase rather than silently skipped).
source "$(dirname "$0")/../lib/common.sh"

begin_suite "totp-2fa"
auth_admin
setup_workdir

# -------------------------------------------------------------------------
# Create a dedicated user for TOTP testing
# -------------------------------------------------------------------------

TOTP_USER="totp-test-${RUN_ID}"
TOTP_PASS="TotpPass123!"
TOTP_SECRET=""
USER_ID=""
USER_TOKEN=""

begin_test "Create user for TOTP test"
# POST /api/v1/users answers with an ENVELOPE:
#   {"user":{"id":...,"username":...},"generated_password":null}
#
# This test used to read `.id` (top level), which is always absent from that
# envelope, so USER_ID came back empty even on a fully successful HTTP 200 and
# the suite reported skip "could not create test user for TOTP". Every
# downstream testcase then skipped on the missing user, so totp-2fa certified
# NOTHING while auth-tests reported green (artifact-keeper-test#339/#343).
#
# The shared helper common.sh::create_test_user has always read
# `.user.id // .id`; only this suite hand-rolled the parse. Read the envelope
# first, then fall back to a bare `.id` for older backends.
resp=$(api_post "/api/v1/users" "{\"username\":\"${TOTP_USER}\",\"password\":\"${TOTP_PASS}\",\"email\":\"totp-${RUN_ID}@test.com\"}" 2>/dev/null) || true
USER_ID=$(echo "$resp" | jq -r '.user.id // .id // empty' 2>/dev/null) || true
if [ -n "$USER_ID" ] && [ "$USER_ID" != "null" ]; then
  pass
else
  # A precondition that fails is an INFRA/SETUP failure, not a skip: the
  # harness cannot tell "TOTP is unavailable" from "the harness is broken",
  # and a skip here would leave the suite certifying nothing while exiting 0.
  infra_fail "could not create test user for TOTP" "${resp:0:400}"
  end_suite
fi

# -------------------------------------------------------------------------
# Login as the test user
# -------------------------------------------------------------------------

begin_test "Login as test user"
login_resp=$(curl -sf $CURL_TIMEOUT -X POST -H "Content-Type: application/json" \
  -d "{\"username\":\"${TOTP_USER}\",\"password\":\"${TOTP_PASS}\"}" \
  "${BASE_URL}/api/v1/auth/login" 2>&1) || true
USER_TOKEN=$(echo "$login_resp" | jq -r '.access_token // .token // empty')
if [ -n "$USER_TOKEN" ] && [ "$USER_TOKEN" != "null" ]; then
  pass
else
  # Without a user token nothing downstream can run, so this is a precondition
  # failure rather than a product verdict.
  infra_fail "could not log in as the freshly-created test user" "${login_resp:0:400}"
  end_suite
fi

# -------------------------------------------------------------------------
# TOTP setup returns secret
# -------------------------------------------------------------------------

begin_test "TOTP setup returns secret"
resp=$(curl -sf $CURL_TIMEOUT -X POST \
  -H "Authorization: Bearer ${USER_TOKEN}" \
  "${BASE_URL}/api/v1/auth/totp/setup" 2>/dev/null) || true
TOTP_SECRET=$(echo "$resp" | jq -r '.secret // empty' 2>/dev/null) || true
if [ -n "$TOTP_SECRET" ] && [ "$TOTP_SECRET" != "null" ]; then
  pass
else
  # The previous version passed on "endpoint responded successfully" even with
  # no secret in the body, which made this testcase unable to fail. /totp/setup
  # returns {"secret":...,"qr_code_url":...}; a missing secret is a real defect
  # and every downstream step depends on it.
  fail "TOTP setup did not return a secret: ${resp:0:200}"
fi

# -------------------------------------------------------------------------
# Invalid TOTP code rejected
#
# Runs BEFORE enable, while the enrollment is still pending, so it exercises
# code validation on a user who has a pending secret.
#
# This assertion used to POST {"code":"000000"} to /api/v1/auth/totp/verify and
# expect 400/401. That endpoint is the LOGIN step: it takes
# {"totp_token","code"} and exchanges a partial-login token for full tokens
# (backend TotpVerifyRequest). Posting only `code` fails JSON deserialization
# with HTTP 422 before any TOTP logic runs, so the assertion never tested code
# validation at all -- it was simply never reached, because the whole suite
# skipped on the user-creation bug above (artifact-keeper-test#343).
#
# The endpoint that validates a code for an already-authenticated user is
# /auth/totp/enable (TotpCodeRequest {"code"}), which answers 401
# "Invalid TOTP code" for a wrong code.
# -------------------------------------------------------------------------

begin_test "Invalid TOTP code rejected"
status=$(curl -s -o /dev/null -w "%{http_code}" $CURL_TIMEOUT \
  -X POST -H "Authorization: Bearer ${USER_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"code":"000000"}' \
  "${BASE_URL}/api/v1/auth/totp/enable" 2>&1) || true
if [ "$status" = "400" ] || [ "$status" = "401" ]; then
  pass
else
  fail "invalid TOTP code accepted (got HTTP ${status}, expected 400 or 401)"
fi

# -------------------------------------------------------------------------
# Enable TOTP with a real code.
#
# oathtool is installed by the auth-tests job in release-gate.yml. require_cmd
# is deliberately NOT used here: it would abort the whole suite, and the
# assertions above are still worth running without it. Instead a missing
# oathtool is an explicit infra_fail on this one testcase, so a broken install
# step is visible as RED rather than silently reducing coverage.
# -------------------------------------------------------------------------

begin_test "Enable TOTP"
if ! command -v oathtool > /dev/null 2>&1; then
  infra_fail "oathtool not on PATH; the auth-tests job is expected to install it (artifact-keeper-test#343)"
else
  CODE=$(oathtool --totp -b "$TOTP_SECRET" 2>/dev/null) || true
  if [ -z "$CODE" ]; then
    infra_fail "oathtool failed to generate a TOTP code from the setup secret"
  else
    enable_body=$(mktemp)
    enable_status=$(curl -s -o "$enable_body" -w '%{http_code}' $CURL_TIMEOUT \
      -X POST \
      -H "Authorization: Bearer ${USER_TOKEN}" \
      -H "Content-Type: application/json" \
      -d "{\"code\":\"${CODE}\"}" \
      "${BASE_URL}/api/v1/auth/totp/enable" 2>/dev/null) || true
    enable_out=$(cat "$enable_body" 2>/dev/null || true); rm -f "$enable_body"
    if [ "$enable_status" -ge 200 ] 2>/dev/null && [ "$enable_status" -lt 300 ] 2>/dev/null; then
      # /totp/enable answers {"backup_codes":[...]} on success.
      if [ "$(echo "$enable_out" | jq -r '.backup_codes | length' 2>/dev/null || echo 0)" -gt 0 ]; then
        pass
      else
        fail "TOTP enable returned HTTP ${enable_status} but no backup codes: ${enable_out:0:200}"
      fi
    else
      fail "TOTP enable rejected a valid oathtool-generated code (HTTP ${enable_status}): ${enable_out:0:200}"
    fi
  fi
fi

# -------------------------------------------------------------------------
# Cleanup
# -------------------------------------------------------------------------

api_delete "/api/v1/users/${USER_ID}" > /dev/null 2>&1 || true

end_suite
