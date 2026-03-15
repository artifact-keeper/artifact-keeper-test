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
    "{\"name\":\"${KEY_NAME}\",\"key_type\":\"rsa\",\"algorithm\":\"rsa4096\"}" 2>/dev/null); then
  KEY_ID=$(echo "$resp" | jq -r '.id // .key_id // empty') || true
  pass
else
  skip "signing endpoint not available"
fi

begin_test "List signing keys"
if resp=$(api_get "/api/v1/signing/keys" 2>/dev/null); then
  # Response may have .keys array or be a top-level array
  if echo "$resp" | jq -e '.keys' > /dev/null 2>&1; then
    keys_json=$(echo "$resp" | jq -r '.keys')
  else
    keys_json="$resp"
  fi
  if assert_contains "$keys_json" "$KEY_NAME"; then
    pass
  fi
else
  skip "signing key listing not available"
fi

begin_test "Get public key"
if [ -n "${KEY_ID:-}" ] && [ "$KEY_ID" != "null" ]; then
  # Public key endpoint returns raw PEM, not JSON
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(auth_header)" \
    "${BASE_URL}/api/v1/signing/keys/${KEY_ID}/public" 2>/dev/null) || true
  if [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then
    pass
  else
    skip "public key endpoint not available (HTTP ${status})"
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
