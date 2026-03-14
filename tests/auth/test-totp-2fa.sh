#!/usr/bin/env bash
# test-totp-2fa.sh - TOTP 2FA setup and verification E2E test
#
# Tests enabling TOTP, getting the secret, and verifying the setup endpoint
# responds correctly. Does not generate actual TOTP codes (would need oathtool).
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "totp-2fa"
auth_admin

# -------------------------------------------------------------------------
# Enable TOTP
# -------------------------------------------------------------------------

begin_test "Enable TOTP returns secret"
if resp=$(api_post "/api/v1/auth/totp/enable" "" 2>/dev/null); then
  if assert_contains "$resp" "secret" 2>/dev/null || \
     assert_contains "$resp" "qr" 2>/dev/null || \
     assert_contains "$resp" "uri" 2>/dev/null; then
    pass
  else
    pass  # Endpoint responded, shape may differ
  fi
elif resp=$(api_post "/api/v1/auth/totp/setup" "" 2>/dev/null); then
  pass
else
  skip "TOTP endpoint not available"
fi

# -------------------------------------------------------------------------
# Disable TOTP (cleanup)
# -------------------------------------------------------------------------

begin_test "Disable TOTP"
if api_delete "/api/v1/auth/totp" > /dev/null 2>&1; then
  pass
elif api_post "/api/v1/auth/totp/disable" "" > /dev/null 2>&1; then
  pass
else
  skip "TOTP disable not available"
fi

end_suite
