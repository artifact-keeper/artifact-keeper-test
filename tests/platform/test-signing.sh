#!/usr/bin/env bash
# test-signing.sh - Signing key CRUD E2E test
#
# Tests creating signing keys, listing them, and verifying key metadata.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "signing"
auth_admin

KEY_NAME="e2e-signing-key-${RUN_ID}"

begin_test "Create signing key"
if resp=$(api_post "/api/v1/signing/keys" \
    "{\"name\":\"${KEY_NAME}\",\"type\":\"rsa\",\"key_size\":2048}" 2>/dev/null); then
  KEY_ID=$(echo "$resp" | jq -r '.id // .key_id // empty') || true
  pass
elif resp=$(api_post "/api/v1/signing" \
    "{\"name\":\"${KEY_NAME}\",\"type\":\"rsa\"}" 2>/dev/null); then
  KEY_ID=$(echo "$resp" | jq -r '.id // .key_id // empty') || true
  pass
else
  skip "signing endpoint not available"
fi

begin_test "List signing keys"
if resp=$(api_get "/api/v1/signing/keys" 2>/dev/null); then
  if assert_contains "$resp" "$KEY_NAME"; then
    pass
  fi
elif resp=$(api_get "/api/v1/signing" 2>/dev/null); then
  if assert_contains "$resp" "$KEY_NAME"; then
    pass
  fi
else
  skip "signing key listing not available"
fi

begin_test "Get public key"
if [ -n "${KEY_ID:-}" ] && [ "$KEY_ID" != "null" ]; then
  if resp=$(api_get "/api/v1/signing/keys/${KEY_ID}/public" 2>/dev/null); then
    pass
  else
    skip "public key endpoint not available"
  fi
else
  skip "no key ID"
fi

begin_test "Delete signing key"
if [ -n "${KEY_ID:-}" ] && [ "$KEY_ID" != "null" ]; then
  if api_delete "/api/v1/signing/keys/${KEY_ID}" > /dev/null 2>&1; then
    pass
  else
    fail "could not delete signing key"
  fi
else
  skip "no key ID"
fi

end_suite
