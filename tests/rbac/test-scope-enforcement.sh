#!/usr/bin/env bash
# test-scope-enforcement.sh - API token scope enforcement E2E test
#
# Verifies that API tokens with limited scopes are actually restricted.
# A read-only token should be able to list repositories but not create
# them or upload artifacts.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "scope-enforcement"
auth_admin
setup_workdir

TEST_REPO_A="e2e-scope-a-${RUN_ID}"
TEST_REPO_B="e2e-scope-b-${RUN_ID}"
READ_TOKEN_NAME="e2e-readonly-${RUN_ID}"
WRITE_TOKEN_NAME="e2e-readwrite-${RUN_ID}"

# -------------------------------------------------------------------------
# Setup: create test repositories
# -------------------------------------------------------------------------

begin_test "Create test repo A"
if create_local_repo "$TEST_REPO_A" "generic"; then
  pass
else
  fail "could not create test repo A"
fi

begin_test "Create test repo B"
if create_local_repo "$TEST_REPO_B" "generic"; then
  pass
else
  fail "could not create test repo B"
fi

# Upload a test artifact to repo A (as admin) for later read tests
echo "scope-test-${RUN_ID}" > "${WORK_DIR}/scope-artifact.bin"
api_upload "/api/v1/repositories/${TEST_REPO_A}/artifacts/scope-artifact.bin" \
  "${WORK_DIR}/scope-artifact.bin" > /dev/null 2>&1 || true

# -------------------------------------------------------------------------
# Create a read-only API token
# -------------------------------------------------------------------------

begin_test "Create read-only API token"
READ_TOKEN=""
READ_TOKEN_ID=""
if resp=$(api_post "/api/v1/auth/tokens" \
    "{\"name\":\"${READ_TOKEN_NAME}\",\"scopes\":[\"read\"]}" 2>/dev/null); then
  READ_TOKEN=$(echo "$resp" | jq -r '.token // .api_key // .key // empty') || true
  READ_TOKEN_ID=$(echo "$resp" | jq -r '.id // .token_id // empty') || true
  if [ -n "$READ_TOKEN" ] && [ "$READ_TOKEN" != "null" ]; then
    pass
  else
    fail "token created but value not returned"
  fi
else
  skip "API tokens endpoint not available"
fi

# -------------------------------------------------------------------------
# Read-only token CAN read repositories
# -------------------------------------------------------------------------

begin_test "Read-only token can list repositories"
if [ -n "${READ_TOKEN:-}" ] && [ "$READ_TOKEN" != "null" ]; then
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "Authorization: Bearer ${READ_TOKEN}" \
    "${BASE_URL}/api/v1/repositories" 2>/dev/null) || true
  if [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then
    pass
  else
    fail "expected 2xx for read with read-only token, got ${status}"
  fi
else
  skip "no read-only token"
fi

begin_test "Read-only token can get repo details"
if [ -n "${READ_TOKEN:-}" ] && [ "$READ_TOKEN" != "null" ]; then
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "Authorization: Bearer ${READ_TOKEN}" \
    "${BASE_URL}/api/v1/repositories/${TEST_REPO_A}" 2>/dev/null) || true
  if [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then
    pass
  else
    fail "expected 2xx for repo detail read, got ${status}"
  fi
else
  skip "no read-only token"
fi

# -------------------------------------------------------------------------
# Read-only token CANNOT create repositories
# -------------------------------------------------------------------------

begin_test "Read-only token cannot create repository"
if [ -n "${READ_TOKEN:-}" ] && [ "$READ_TOKEN" != "null" ]; then
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X POST \
    -H "Authorization: Bearer ${READ_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{\"key\":\"e2e-scope-blocked-${RUN_ID}\",\"name\":\"e2e-scope-blocked-${RUN_ID}\",\"format\":\"generic\",\"repo_type\":\"local\",\"is_public\":true}" \
    "${BASE_URL}/api/v1/repositories" 2>/dev/null) || true
  if [ "$status" = "403" ]; then
    pass
  else
    fail "expected 403 for repo creation with read-only token, got ${status}"
    # Clean up if the repo was somehow created
    auth_admin
    api_delete "/api/v1/repositories/e2e-scope-blocked-${RUN_ID}" > /dev/null 2>&1 || true
  fi
else
  skip "no read-only token"
fi

# -------------------------------------------------------------------------
# Read-only token CANNOT upload artifacts
# -------------------------------------------------------------------------

begin_test "Read-only token cannot upload artifact"
if [ -n "${READ_TOKEN:-}" ] && [ "$READ_TOKEN" != "null" ]; then
  echo "blocked-upload-${RUN_ID}" > "${WORK_DIR}/blocked.bin"
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X PUT \
    -H "Authorization: Bearer ${READ_TOKEN}" \
    -H "Content-Type: application/octet-stream" \
    --data-binary "@${WORK_DIR}/blocked.bin" \
    "${BASE_URL}/api/v1/repositories/${TEST_REPO_A}/artifacts/blocked.bin" 2>/dev/null) || true
  if [ "$status" = "403" ]; then
    pass
  else
    fail "expected 403 for upload with read-only token, got ${status}"
  fi
else
  skip "no read-only token"
fi

# -------------------------------------------------------------------------
# Read-only token CANNOT delete artifacts
# -------------------------------------------------------------------------

begin_test "Read-only token cannot delete artifact"
if [ -n "${READ_TOKEN:-}" ] && [ "$READ_TOKEN" != "null" ]; then
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X DELETE \
    -H "Authorization: Bearer ${READ_TOKEN}" \
    "${BASE_URL}/api/v1/repositories/${TEST_REPO_A}/artifacts/scope-artifact.bin" 2>/dev/null) || true
  if [ "$status" = "403" ]; then
    pass
  else
    fail "expected 403 for delete with read-only token, got ${status}"
  fi
else
  skip "no read-only token"
fi

# -------------------------------------------------------------------------
# Read-write token CAN perform write operations (positive control)
# -------------------------------------------------------------------------

begin_test "Create read-write API token"
WRITE_TOKEN=""
WRITE_TOKEN_ID=""
if resp=$(api_post "/api/v1/auth/tokens" \
    "{\"name\":\"${WRITE_TOKEN_NAME}\",\"scopes\":[\"read\",\"write\"]}" 2>/dev/null); then
  WRITE_TOKEN=$(echo "$resp" | jq -r '.token // .api_key // .key // empty') || true
  WRITE_TOKEN_ID=$(echo "$resp" | jq -r '.id // .token_id // empty') || true
  if [ -n "$WRITE_TOKEN" ] && [ "$WRITE_TOKEN" != "null" ]; then
    pass
  else
    fail "token created but value not returned"
  fi
else
  skip "API tokens endpoint not available"
fi

begin_test "Read-write token can upload artifact"
if [ -n "${WRITE_TOKEN:-}" ] && [ "$WRITE_TOKEN" != "null" ]; then
  echo "rw-upload-${RUN_ID}" > "${WORK_DIR}/rw-artifact.bin"
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X PUT \
    -H "Authorization: Bearer ${WRITE_TOKEN}" \
    -H "Content-Type: application/octet-stream" \
    --data-binary "@${WORK_DIR}/rw-artifact.bin" \
    "${BASE_URL}/api/v1/repositories/${TEST_REPO_A}/artifacts/rw-artifact.bin" 2>/dev/null) || true
  if [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then
    pass
  else
    fail "expected 2xx for upload with read-write token, got ${status}"
  fi
else
  skip "no read-write token"
fi

# -------------------------------------------------------------------------
# Repo-scoped token enforcement (if supported)
#
# Creates a token scoped to repo A, then verifies it cannot access repo B.
# If the API does not support repository_scopes, these tests are skipped.
# -------------------------------------------------------------------------

begin_test "Create repo-scoped API token (repo A only)"
SCOPED_TOKEN=""
SCOPED_TOKEN_ID=""
# The create-token API does not support repository_scopes in the request body.
# Repo scoping is configured via the api_token_repositories join table, which
# has no public REST endpoint yet. Skip until the API supports inline scoping.
skip "API does not support repository_scopes field on token creation"

begin_test "Repo-scoped token can access repo A"
if [ -n "${SCOPED_TOKEN:-}" ] && [ "$SCOPED_TOKEN" != "null" ]; then
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "Authorization: Bearer ${SCOPED_TOKEN}" \
    "${BASE_URL}/api/v1/repositories/${TEST_REPO_A}" 2>/dev/null) || true
  if [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then
    pass
  else
    fail "expected 2xx for scoped token accessing repo A, got ${status}"
  fi
else
  skip "no repo-scoped token"
fi

begin_test "Repo-scoped token cannot access repo B"
if [ -n "${SCOPED_TOKEN:-}" ] && [ "$SCOPED_TOKEN" != "null" ]; then
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "Authorization: Bearer ${SCOPED_TOKEN}" \
    "${BASE_URL}/api/v1/repositories/${TEST_REPO_B}" 2>/dev/null) || true
  if [ "$status" = "403" ]; then
    pass
  else
    fail "expected 403 for scoped token accessing repo B, got ${status}"
  fi
else
  skip "no repo-scoped token"
fi

begin_test "Repo-scoped token cannot upload to repo B"
if [ -n "${SCOPED_TOKEN:-}" ] && [ "$SCOPED_TOKEN" != "null" ]; then
  echo "scoped-blocked-${RUN_ID}" > "${WORK_DIR}/scoped-blocked.bin"
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X PUT \
    -H "Authorization: Bearer ${SCOPED_TOKEN}" \
    -H "Content-Type: application/octet-stream" \
    --data-binary "@${WORK_DIR}/scoped-blocked.bin" \
    "${BASE_URL}/api/v1/repositories/${TEST_REPO_B}/artifacts/scoped-blocked.bin" 2>/dev/null) || true
  if [ "$status" = "403" ]; then
    pass
  else
    fail "expected 403 for scoped token uploading to repo B, got ${status}"
  fi
else
  skip "no repo-scoped token"
fi

# -------------------------------------------------------------------------
# Cleanup
# -------------------------------------------------------------------------

auth_admin

# Revoke tokens
if [ -n "${READ_TOKEN_ID:-}" ] && [ "$READ_TOKEN_ID" != "null" ]; then
  api_delete "/api/v1/auth/tokens/${READ_TOKEN_ID}" > /dev/null 2>&1 || true
fi
if [ -n "${WRITE_TOKEN_ID:-}" ] && [ "$WRITE_TOKEN_ID" != "null" ]; then
  api_delete "/api/v1/auth/tokens/${WRITE_TOKEN_ID}" > /dev/null 2>&1 || true
fi
if [ -n "${SCOPED_TOKEN_ID:-}" ] && [ "$SCOPED_TOKEN_ID" != "null" ]; then
  api_delete "/api/v1/auth/tokens/${SCOPED_TOKEN_ID}" > /dev/null 2>&1 || true
fi

# Delete repos
api_delete "/api/v1/repositories/${TEST_REPO_A}" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${TEST_REPO_B}" > /dev/null 2>&1 || true

end_suite
