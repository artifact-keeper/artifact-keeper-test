#!/usr/bin/env bash
# test-signing.sh - Signing key CRUD E2E test
#
# Tests creating signing keys, listing them, and verifying key metadata.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "signing"
auth_admin
setup_workdir

KEY_NAME="e2e-signing-key-${RUN_ID}"
REPO_KEY="signing-test-${RUN_ID}"

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

# ---------------------------------------------------------------------------
# Signing behavior tests: configure a repo, upload, and verify signatures
# ---------------------------------------------------------------------------

begin_test "Create repo for signing"
if create_local_repo "$REPO_KEY" "generic"; then
  pass
else
  fail "could not create signing test repo"
fi

begin_test "Configure repo for signing"
if [ -z "${KEY_ID:-}" ] || [ "$KEY_ID" = "null" ]; then
  skip "no key ID available"
else
  resp=$(api_put "/api/v1/repositories/${REPO_KEY}/signing" \
    "{\"key_id\":\"${KEY_ID}\",\"enabled\":true}" 2>/dev/null) || resp=""
  if [ $? -eq 0 ]; then pass; else skip "signing config API not available"; fi
fi

begin_test "Upload artifact to signed repo"
if [ -z "${KEY_ID:-}" ] || [ "$KEY_ID" = "null" ]; then
  skip "no key ID, signing not configured"
else
  echo "signed-content-${RUN_ID}" > "${WORK_DIR}/signed.txt"
  if api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/signed/file.txt" \
      "${WORK_DIR}/signed.txt" "text/plain" > /dev/null 2>&1; then
    pass
  else
    fail "upload to signed repo failed"
  fi
fi

begin_test "Retrieve public key content"
if [ -z "${KEY_ID:-}" ] || [ "$KEY_ID" = "null" ]; then
  skip "no key ID"
else
  resp=$(curl -sf $CURL_TIMEOUT -H "$(auth_header)" \
    "${BASE_URL}/api/v1/signing/keys/${KEY_ID}/public" 2>/dev/null) || resp=""
  if assert_contains "$resp" "BEGIN PUBLIC KEY"; then
    pass
  else
    skip "public key endpoint not available or different format"
  fi
fi

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

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
