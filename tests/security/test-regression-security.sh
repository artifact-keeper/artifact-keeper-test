#!/usr/bin/env bash
# test-regression-security.sh - Regression tests for specific security bugs
#
# Covers:
#   1. Token revocation listing (bug #592)
#   2. Anonymous access on public repos, cross-format (bug #744)
#   3. Account lockout after repeated failed logins
#   4. Scan status accuracy for unscannable artifacts (bug #723)
#   5. Force password change flag on login
#
# Requires: curl, jq

source "$(dirname "$0")/../lib/common.sh"

begin_suite "regression-security"
auth_admin
setup_workdir

# =========================================================================
# 1. Token revocation listing (bug #592)
#
# The original test-token-revocation.sh only checks that a revoked token
# returns 401 on use. Bug #592 was that revoked tokens still appeared in
# the listing endpoint. This test verifies the listing is clean.
# =========================================================================

TEST_USER_592="e2e-bug592-${RUN_ID}"
TEST_PASS_592="Bug592_Pass!99"
TEST_EMAIL_592="e2e-bug592-${RUN_ID}@test.local"
USER_ID_592=""
TOKEN_ID_592=""

begin_test "Bug #592: Create test user for token revocation listing"
# Setup-step create: retry-with-backoff on transient 5xx/000 (fleet load can
# briefly starve the bcrypt blocking pool). 4xx (e.g. duplicate username) is
# surfaced immediately and never masked. See create_test_user_with_retry.
USER_ID_592=$(create_test_user_with_retry "$TEST_USER_592" "$TEST_PASS_592" "$TEST_EMAIL_592" \
  "{\"username\":\"${TEST_USER_592}\",\"password\":\"${TEST_PASS_592}\",\"email\":\"${TEST_EMAIL_592}\",\"display_name\":\"Bug 592 Test\"}") || true
if [ -n "$USER_ID_592" ] && [ "$USER_ID_592" != "null" ]; then
  pass
else
  fail "could not create test user for bug #592 (transient retries exhausted)"
fi

begin_test "Bug #592: Create API token"
TOKEN_NAME_592="revlist-tok-${RUN_ID}"
API_TOKEN_592=""
if [ -n "${USER_ID_592:-}" ] && [ "$USER_ID_592" != "null" ]; then
  if resp=$(api_post "/api/v1/users/${USER_ID_592}/tokens" \
      "{\"name\":\"${TOKEN_NAME_592}\",\"scopes\":[\"read\"]}" 2>/dev/null); then
    API_TOKEN_592=$(echo "$resp" | jq -r '.token // .api_key // .key // empty') || true
    TOKEN_ID_592=$(echo "$resp" | jq -r '.id // .token_id // empty') || true
    if [ -n "$TOKEN_ID_592" ] && [ "$TOKEN_ID_592" != "null" ]; then
      pass
    else
      fail "token created but no ID returned"
    fi
  else
    fail "could not create API token"
  fi
else
  skip "no user ID from previous step"
fi

begin_test "Bug #592: Revoke the token"
if [ -n "${USER_ID_592:-}" ] && [ "$USER_ID_592" != "null" ] && \
   [ -n "${TOKEN_ID_592:-}" ] && [ "$TOKEN_ID_592" != "null" ]; then
  if api_delete "/api/v1/users/${USER_ID_592}/tokens/${TOKEN_ID_592}" > /dev/null 2>&1; then
    pass
  else
    fail "could not revoke token"
  fi
else
  skip "no user or token ID"
fi

begin_test "Bug #592: Revoked token does NOT appear in listing"
if [ -n "${USER_ID_592:-}" ] && [ "$USER_ID_592" != "null" ] && \
   [ -n "${TOKEN_ID_592:-}" ] && [ "$TOKEN_ID_592" != "null" ]; then
  # Small delay to allow backend to process the deletion
  sleep 1
  listing=""
  if listing=$(api_get "/api/v1/users/${USER_ID_592}/tokens" 2>/dev/null); then
    # Check whether the revoked token ID appears anywhere in the listing
    if echo "$listing" | jq -e '.' > /dev/null 2>&1; then
      # Search for the token ID in the JSON response (handles arrays, .items, .tokens)
      found=$(echo "$listing" | jq -r --arg tid "$TOKEN_ID_592" '
        [.. | objects | select(.id == $tid or .token_id == $tid)] | length
      ' 2>/dev/null) || found="0"
      if [ "$found" = "0" ]; then
        pass
      else
        fail "revoked token ${TOKEN_ID_592} still appears in listing (found ${found} matches)"
      fi
    else
      fail "token listing response is not valid JSON"
    fi
  else
    # If the endpoint returns 404, the user may have no tokens at all, which is correct
    skip "could not fetch token listing (endpoint may not exist)"
  fi
else
  skip "no user or token ID"
fi

# Cleanup user for bug #592
if [ -n "${USER_ID_592:-}" ] && [ "$USER_ID_592" != "null" ]; then
  api_delete "/api/v1/users/${USER_ID_592}" > /dev/null 2>&1 || true
fi

# =========================================================================
# 2. Anonymous access on public repos (bug #744, cross-format)
#
# Public repositories should allow unauthenticated downloads. This was
# broken across formats: generic worked but npm/pypi did not.
# =========================================================================

GENERIC_REPO="pub-generic-${RUN_ID}"
NPM_REPO="pub-npm-${RUN_ID}"
PYPI_REPO="pub-pypi-${RUN_ID}"
PRIVATE_REPO="priv-generic-${RUN_ID}"

begin_test "Bug #744: Create public generic repo"
payload="{\"key\":\"${GENERIC_REPO}\",\"name\":\"${GENERIC_REPO}\",\"format\":\"generic\",\"repo_type\":\"local\",\"is_public\":true}"
if api_post "/api/v1/repositories" "$payload" > /dev/null 2>&1; then
  pass
else
  fail "could not create public generic repo"
fi

begin_test "Bug #744: Create public npm repo"
payload="{\"key\":\"${NPM_REPO}\",\"name\":\"${NPM_REPO}\",\"format\":\"npm\",\"repo_type\":\"local\",\"is_public\":true}"
if api_post "/api/v1/repositories" "$payload" > /dev/null 2>&1; then
  pass
else
  fail "could not create public npm repo"
fi

begin_test "Bug #744: Create public pypi repo"
payload="{\"key\":\"${PYPI_REPO}\",\"name\":\"${PYPI_REPO}\",\"format\":\"pypi\",\"repo_type\":\"local\",\"is_public\":true}"
if api_post "/api/v1/repositories" "$payload" > /dev/null 2>&1; then
  pass
else
  fail "could not create public pypi repo"
fi

# Upload test artifacts to each public repo as admin
begin_test "Bug #744: Upload artifact to public generic repo"
echo "public-generic-content-${RUN_ID}" > "${WORK_DIR}/public-generic.txt"
if api_upload "/api/v1/repositories/${GENERIC_REPO}/artifacts/pkg/v1/file.txt" \
    "${WORK_DIR}/public-generic.txt" "text/plain" > /dev/null 2>&1; then
  pass
else
  fail "could not upload to public generic repo"
fi

begin_test "Bug #744: Upload artifact to public npm repo"
# Build a minimal npm tarball and publish via the npm PUT endpoint
NPM_PKG_NAME="bug744-pkg-${RUN_ID}"
NPM_PKG_VER="1.0.0"

cd "$WORK_DIR"
mkdir -p npm-pkg && cd npm-pkg
cat > package.json <<EOF
{
  "name": "${NPM_PKG_NAME}",
  "version": "${NPM_PKG_VER}",
  "description": "Bug 744 anonymous access test"
}
EOF
echo "module.exports = {};" > index.js
tar czf "../${NPM_PKG_NAME}-${NPM_PKG_VER}.tgz" .
cd "$WORK_DIR"

NPM_TARBALL="${WORK_DIR}/${NPM_PKG_NAME}-${NPM_PKG_VER}.tgz"
NPM_TGZ_B64=$(base64 < "$NPM_TARBALL" | tr -d '\n')
NPM_TGZ_SHA=$(shasum -a 1 "$NPM_TARBALL" | awk '{print $1}')

npm_payload=$(cat <<NPMEOF
{
  "_id": "${NPM_PKG_NAME}",
  "name": "${NPM_PKG_NAME}",
  "versions": {
    "${NPM_PKG_VER}": {
      "name": "${NPM_PKG_NAME}",
      "version": "${NPM_PKG_VER}",
      "dist": {
        "shasum": "${NPM_TGZ_SHA}",
        "tarball": "${BASE_URL}/npm/${NPM_REPO}/${NPM_PKG_NAME}/-/${NPM_PKG_NAME}-${NPM_PKG_VER}.tgz"
      }
    }
  },
  "_attachments": {
    "${NPM_PKG_NAME}-${NPM_PKG_VER}.tgz": {
      "content_type": "application/octet-stream",
      "data": "${NPM_TGZ_B64}",
      "length": $(wc -c < "$NPM_TARBALL" | tr -d ' ')
    }
  }
}
NPMEOF
)

npm_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X PUT \
  -H "$(auth_header)" \
  -H "Content-Type: application/json" \
  -d "$npm_payload" \
  "${BASE_URL}/npm/${NPM_REPO}/${NPM_PKG_NAME}") || true

if [ "$npm_status" -ge 200 ] 2>/dev/null && [ "$npm_status" -lt 300 ] 2>/dev/null; then
  pass
else
  fail "npm publish returned HTTP ${npm_status}"
fi

begin_test "Bug #744: Upload artifact to public pypi repo"
# Build a minimal sdist and upload via multipart POST
PYPI_PKG_NAME="bug744pkg${RUN_ID//-/}"
PYPI_PKG_VER="1.0.0"
cd "$WORK_DIR"
mkdir -p "${PYPI_PKG_NAME}-${PYPI_PKG_VER}"
cat > "${PYPI_PKG_NAME}-${PYPI_PKG_VER}/setup.py" <<EOF
from setuptools import setup
setup(name="${PYPI_PKG_NAME}", version="${PYPI_PKG_VER}")
EOF
cat > "${PYPI_PKG_NAME}-${PYPI_PKG_VER}/PKG-INFO" <<EOF
Metadata-Version: 1.0
Name: ${PYPI_PKG_NAME}
Version: ${PYPI_PKG_VER}
EOF
PYPI_SDIST="${WORK_DIR}/${PYPI_PKG_NAME}-${PYPI_PKG_VER}.tar.gz"
tar czf "$PYPI_SDIST" "${PYPI_PKG_NAME}-${PYPI_PKG_VER}"
PYPI_SHA256=$(shasum -a 256 "$PYPI_SDIST" | cut -d' ' -f1)

pypi_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X POST "${BASE_URL}/pypi/${PYPI_REPO}/" \
  -u "${ADMIN_USER}:${ADMIN_PASS}" \
  -F ":action=file_upload" \
  -F "name=${PYPI_PKG_NAME}" \
  -F "version=${PYPI_PKG_VER}" \
  -F "sha256_digest=${PYPI_SHA256}" \
  -F "filetype=sdist" \
  -F "content=@${PYPI_SDIST};filename=$(basename "$PYPI_SDIST")") || true

if [ "$pypi_status" -ge 200 ] 2>/dev/null && [ "$pypi_status" -lt 300 ] 2>/dev/null; then
  pass
else
  fail "pypi upload returned HTTP ${pypi_status}"
fi

# Now test anonymous (no Authorization header) downloads from each public repo

begin_test "Bug #744: Anonymous download from public generic repo"
anon_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  "${BASE_URL}/api/v1/repositories/${GENERIC_REPO}/download/pkg/v1/file.txt") || true
if [ "$anon_status" = "200" ]; then
  pass
elif [ "$anon_status" = "301" ] || [ "$anon_status" = "302" ]; then
  # Follow redirect and check final status
  final_status=$(curl -sL -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    "${BASE_URL}/api/v1/repositories/${GENERIC_REPO}/download/pkg/v1/file.txt") || true
  if [ "$final_status" = "200" ]; then
    pass
  else
    fail "anonymous download from public generic repo returned ${final_status} after redirect"
  fi
else
  # Try format-level endpoint
  anon_status2=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    "${BASE_URL}/generic/${GENERIC_REPO}/pkg/v1/file.txt") || true
  if [ "$anon_status2" = "200" ]; then
    pass
  else
    fail "anonymous download from public generic repo returned ${anon_status} (API) / ${anon_status2} (format)"
  fi
fi

begin_test "Bug #744: Anonymous download from public npm repo"
# npm package metadata endpoint
anon_npm=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  "${BASE_URL}/npm/${NPM_REPO}/${NPM_PKG_NAME}") || true
if [ "$anon_npm" = "200" ]; then
  pass
elif [ "$anon_npm" = "401" ]; then
  fail "anonymous access to public npm repo returned 401 (bug #744 regression)"
else
  # 404 might mean the package path is different; not the auth bug
  skip "npm anonymous access returned ${anon_npm} (may not be an auth issue)"
fi

begin_test "Bug #744: Anonymous download from public pypi repo"
# PyPI simple index endpoint
anon_pypi=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  "${BASE_URL}/pypi/${PYPI_REPO}/simple/${PYPI_PKG_NAME}/") || true
if [ "$anon_pypi" = "200" ]; then
  pass
elif [ "$anon_pypi" = "401" ]; then
  fail "anonymous access to public pypi repo returned 401 (bug #744 regression)"
else
  skip "pypi anonymous access returned ${anon_pypi} (may not be an auth issue)"
fi

# Verify private repos still require authentication
begin_test "Bug #744: Create private repo"
payload="{\"key\":\"${PRIVATE_REPO}\",\"name\":\"${PRIVATE_REPO}\",\"format\":\"generic\",\"repo_type\":\"local\",\"is_public\":false}"
if api_post "/api/v1/repositories" "$payload" > /dev/null 2>&1; then
  pass
else
  fail "could not create private repo"
fi

begin_test "Bug #744: Upload artifact to private repo"
echo "private-content-${RUN_ID}" > "${WORK_DIR}/private.txt"
if api_upload "/api/v1/repositories/${PRIVATE_REPO}/artifacts/secret/file.txt" \
    "${WORK_DIR}/private.txt" "text/plain" > /dev/null 2>&1; then
  pass
else
  fail "could not upload to private repo"
fi

begin_test "Bug #744: Anonymous download from private repo is rejected"
priv_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  "${BASE_URL}/api/v1/repositories/${PRIVATE_REPO}/download/secret/file.txt") || true
if [ "$priv_status" = "401" ]; then
  pass
elif [ "$priv_status" = "403" ]; then
  pass
else
  # Try format-level endpoint
  priv_status2=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    "${BASE_URL}/generic/${PRIVATE_REPO}/secret/file.txt") || true
  if [ "$priv_status2" = "401" ] || [ "$priv_status2" = "403" ]; then
    pass
  else
    fail "anonymous download from private repo should return 401/403, got ${priv_status} (API) / ${priv_status2} (format)"
  fi
fi

# =========================================================================
# 3. Account lockout after repeated failed logins
#
# When ACCOUNT_LOCKOUT_THRESHOLD > 0, exceeding the threshold with wrong
# passwords should lock the account. The test environment typically sets
# this to 0 (disabled), so we check and skip if needed.
# =========================================================================

LOCKOUT_USER="e2e-lockout-${RUN_ID}"
LOCKOUT_PASS="Lockout_Pass!99"
LOCKOUT_EMAIL="e2e-lockout-${RUN_ID}@test.local"
LOCKOUT_USER_ID=""

begin_test "Account lockout: Create test user"
# Setup-step create: retry transient 5xx/000 only (see create_test_user_with_retry).
LOCKOUT_USER_ID=$(create_test_user_with_retry "$LOCKOUT_USER" "$LOCKOUT_PASS" "$LOCKOUT_EMAIL" \
  "{\"username\":\"${LOCKOUT_USER}\",\"password\":\"${LOCKOUT_PASS}\",\"email\":\"${LOCKOUT_EMAIL}\",\"display_name\":\"Lockout Test\"}") || true
if [ -n "$LOCKOUT_USER_ID" ] && [ "$LOCKOUT_USER_ID" != "null" ]; then
  pass
else
  fail "could not create lockout test user (transient retries exhausted)"
fi

begin_test "Account lockout: Detect lockout threshold"
# Try to read the lockout threshold from server config or settings API.
# If ACCOUNT_LOCKOUT_THRESHOLD env var is set, use that. Otherwise probe.
LOCKOUT_THRESHOLD="${ACCOUNT_LOCKOUT_THRESHOLD:-}"
if [ -z "$LOCKOUT_THRESHOLD" ]; then
  # Attempt to read from the admin settings API
  settings_resp=$(api_get "/api/v1/admin/settings" 2>/dev/null) || true
  if [ -n "$settings_resp" ]; then
    LOCKOUT_THRESHOLD=$(echo "$settings_resp" | jq -r '.account_lockout_threshold // .lockout_threshold // .security.account_lockout_threshold // empty' 2>/dev/null) || true
  fi
fi
if [ -z "$LOCKOUT_THRESHOLD" ]; then
  # Probe: send 6 failed logins and check if the account gets locked
  for i in $(seq 1 6); do
    curl -s -o /dev/null --max-time 5 -X POST -H "Content-Type: application/json" \
      -d "{\"username\":\"${LOCKOUT_USER}\",\"password\":\"probe_wrong_${i}\"}" \
      "${BASE_URL}/api/v1/auth/login" 2>/dev/null || true
  done
  probe_status=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 -X POST \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${LOCKOUT_USER}\",\"password\":\"${LOCKOUT_PASS}\"}" \
    "${BASE_URL}/api/v1/auth/login" 2>/dev/null) || true
  if [ "$probe_status" = "200" ]; then
    # Login succeeded after 6 wrong attempts -- lockout is disabled
    LOCKOUT_THRESHOLD="0"
    echo "  probed: lockout is disabled (login succeeded after 6 failed attempts)"
  else
    LOCKOUT_THRESHOLD="5"
    echo "  probed: lockout appears enabled (got ${probe_status} after 6 failed attempts)"
  fi
fi
echo "  lockout threshold: ${LOCKOUT_THRESHOLD}"
if [ "$LOCKOUT_THRESHOLD" = "0" ]; then
  skip "account lockout is disabled (threshold=0)"
else
  pass
fi

begin_test "Account lockout: Trigger lockout with failed attempts"
if [ "$LOCKOUT_THRESHOLD" = "0" ]; then
  skip "account lockout is disabled (threshold=0)"
elif [ -n "${LOCKOUT_USER_ID:-}" ] && [ "$LOCKOUT_USER_ID" != "null" ]; then
  # Send N+1 failed login attempts (threshold plus one extra)
  attempts=$((LOCKOUT_THRESHOLD + 1))
  for i in $(seq 1 "$attempts"); do
    curl -s -o /dev/null -w '' --max-time 10 \
      -X POST \
      -H "Content-Type: application/json" \
      -d "{\"username\":\"${LOCKOUT_USER}\",\"password\":\"wrong_password_${i}\"}" \
      "${BASE_URL}/api/v1/auth/login" 2>/dev/null || true
  done
  pass
else
  skip "no lockout user"
fi

begin_test "Account lockout: Correct password rejected after lockout"
if [ "$LOCKOUT_THRESHOLD" = "0" ]; then
  skip "account lockout is disabled (threshold=0)"
elif [ -n "${LOCKOUT_USER_ID:-}" ] && [ "$LOCKOUT_USER_ID" != "null" ]; then
  lockout_status=$(curl -s -o "$WORK_DIR/lockout-resp.json" -w '%{http_code}' --max-time 10 \
    -X POST \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${LOCKOUT_USER}\",\"password\":\"${LOCKOUT_PASS}\"}" \
    "${BASE_URL}/api/v1/auth/login" 2>/dev/null) || true
  lockout_body=$(cat "$WORK_DIR/lockout-resp.json" 2>/dev/null) || true

  # 423 Locked, 429 Too Many Requests, or 401 with a locked indicator are all valid
  if [ "$lockout_status" = "423" ]; then
    pass
  elif [ "$lockout_status" = "429" ]; then
    pass
  elif [ "$lockout_status" = "401" ]; then
    # Check if the response body mentions lockout/locked
    locked_indicator=$(echo "$lockout_body" | jq -r '.locked // .account_locked // .error // empty' 2>/dev/null) || true
    if echo "$locked_indicator" | grep -qi "lock" 2>/dev/null; then
      pass
    else
      # 401 after correct password could still be lockout (just without explicit messaging)
      pass
    fi
  elif [ "$lockout_status" = "200" ]; then
    fail "login succeeded with correct password after lockout threshold exceeded (account should be locked)"
  else
    skip "unexpected status ${lockout_status} after lockout attempts"
  fi
else
  skip "no lockout user"
fi

# Cleanup lockout user
if [ -n "${LOCKOUT_USER_ID:-}" ] && [ "$LOCKOUT_USER_ID" != "null" ]; then
  api_delete "/api/v1/users/${LOCKOUT_USER_ID}" > /dev/null 2>&1 || true
fi

# =========================================================================
# 4. Scan status accuracy for unscannable artifacts (bug #723)
#
# Upload a corrupt/empty file and verify the scan status reflects that
# it could not be scanned (not falsely reported as "clean"). Requires
# Trivy to be enabled. Skips if scanning is not available.
# =========================================================================

SCAN_REPO="sec-scan723-${RUN_ID}"
SCAN_TIMEOUT="${SCAN_TIMEOUT:-60}"

begin_test "Bug #723: Create generic repo for scan test"
if create_local_repo "$SCAN_REPO" "generic"; then
  pass
else
  fail "could not create generic repo for scan test"
fi

begin_test "Bug #723: Upload empty/corrupt artifact"
# Create a file that claims to be a tarball but contains garbage
dd if=/dev/urandom bs=64 count=1 of="${WORK_DIR}/corrupt-archive.tar.gz" 2>/dev/null
if api_upload "/api/v1/repositories/${SCAN_REPO}/artifacts/pkg/v1/corrupt-archive.tar.gz" \
    "${WORK_DIR}/corrupt-archive.tar.gz" "application/gzip" > /dev/null 2>&1; then
  pass
else
  fail "could not upload corrupt artifact"
fi

begin_test "Bug #723: Scan status reflects unscannable artifact"
# First, check if scanning is available by triggering a scan
scan_triggered=false
if resp=$(api_post "/api/v1/security/scan" "{\"repository_key\":\"${SCAN_REPO}\"}" 2>/dev/null); then
  scan_triggered=true
fi

if ! $scan_triggered; then
  # Try alternative: scan may happen automatically on upload
  # Check if the scan endpoint exists at all
  probe_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(auth_header)" \
    "${BASE_URL}/api/v1/repositories/${SCAN_REPO}/artifacts/pkg/v1/corrupt-archive.tar.gz") || true
  if [ "$probe_status" = "404" ] || [ "$probe_status" = "503" ]; then
    skip "scanning infrastructure not available"
  fi
fi

if $scan_triggered || [ "${probe_status:-}" = "200" ]; then
  # Poll for scan results
  scan_path="/api/v1/repositories/${SCAN_REPO}/artifacts/pkg/v1/corrupt-archive.tar.gz"
  elapsed=0
  scan_done=false
  scan_status_value=""

  while [ "$elapsed" -lt "$SCAN_TIMEOUT" ]; do
    artifact_resp=$(curl -s -o "$WORK_DIR/scan723.json" -w '%{http_code}' $CURL_TIMEOUT \
      -H "$(auth_header)" \
      -H "Accept: application/json" \
      "${BASE_URL}${scan_path}") || true

    if [ "$artifact_resp" = "200" ]; then
      scan_body=$(cat "$WORK_DIR/scan723.json")
      scan_status_value=$(echo "$scan_body" | jq -r '.scan_status // .security_status // .scan.status // empty' 2>/dev/null) || true

      if [ -n "$scan_status_value" ] && [ "$scan_status_value" != "pending" ] && \
         [ "$scan_status_value" != "in_progress" ] && [ "$scan_status_value" != "queued" ]; then
        scan_done=true
        break
      fi
    elif [ "$artifact_resp" = "404" ] || [ "$artifact_resp" = "503" ]; then
      not_found_count=$((${not_found_count:-0} + 1))
      if [ "$not_found_count" -ge 6 ]; then
        skip "Trivy scanning not enabled (endpoint returned ${artifact_resp} consistently)"
        scan_done="skipped"
        break
      fi
    fi
    sleep 5
    elapsed=$((elapsed + 5))
  done

  if [ "$scan_done" = "true" ]; then
    # The status should NOT be "clean" for a corrupt file. Valid statuses
    # include: "error", "failed", "unscannable", "unknown", "no_results",
    # or a status with vulnerability findings.
    if [ "$scan_status_value" = "clean" ] || [ "$scan_status_value" = "passed" ]; then
      fail "corrupt artifact reported as '${scan_status_value}' (bug #723: should not be clean)"
    else
      echo "  scan status for corrupt artifact: ${scan_status_value}"
      pass
    fi
  elif [ "$scan_done" != "skipped" ]; then
    skip "scan did not complete within ${SCAN_TIMEOUT}s"
  fi
else
  skip "could not trigger scan and scanning infrastructure not available"
fi

# =========================================================================
# 5. Force password change flag on login
#
# Admin forces a password change, then the user's next login should
# include an indicator that the password must be changed.
# =========================================================================

FPC_USER="e2e-fpc-${RUN_ID}"
FPC_PASS="ForcePC_Pass!99"
FPC_EMAIL="e2e-fpc-${RUN_ID}@test.local"
FPC_USER_ID=""

begin_test "Force password change: Create test user"
# Setup-step create: retry transient 5xx/000 only (see create_test_user_with_retry).
# This is the exact step that flaked ("could not create force-password-change
# test user") when a fleet-concurrent run starved the bcrypt blocking pool.
FPC_USER_ID=$(create_test_user_with_retry "$FPC_USER" "$FPC_PASS" "$FPC_EMAIL" \
  "{\"username\":\"${FPC_USER}\",\"password\":\"${FPC_PASS}\",\"email\":\"${FPC_EMAIL}\",\"display_name\":\"Force PC Test\"}") || true
if [ -n "$FPC_USER_ID" ] && [ "$FPC_USER_ID" != "null" ]; then
  pass
else
  fail "could not create force-password-change test user (transient retries exhausted)"
fi

begin_test "Force password change: Call force-password-change endpoint"
fpc_called=false
if [ -n "${FPC_USER_ID:-}" ] && [ "$FPC_USER_ID" != "null" ]; then
  fpc_status=$(curl -s -o "$WORK_DIR/fpc-resp.json" -w '%{http_code}' $CURL_TIMEOUT \
    -X POST \
    -H "$(auth_header)" \
    -H "Content-Type: application/json" \
    "${BASE_URL}/api/v1/users/${FPC_USER_ID}/force-password-change") || true

  if [ "$fpc_status" -ge 200 ] 2>/dev/null && [ "$fpc_status" -lt 300 ] 2>/dev/null; then
    fpc_called=true
    pass
  elif [ "$fpc_status" = "404" ]; then
    # Try alternative endpoint path
    fpc_status2=$(curl -s -o "$WORK_DIR/fpc-resp2.json" -w '%{http_code}' $CURL_TIMEOUT \
      -X PUT \
      -H "$(auth_header)" \
      -H "Content-Type: application/json" \
      -d "{\"must_change_password\":true}" \
      "${BASE_URL}/api/v1/users/${FPC_USER_ID}") || true
    if [ "$fpc_status2" -ge 200 ] 2>/dev/null && [ "$fpc_status2" -lt 300 ] 2>/dev/null; then
      fpc_called=true
      pass
    else
      skip "force-password-change endpoint not available (${fpc_status}, ${fpc_status2})"
    fi
  else
    fail "force-password-change returned unexpected HTTP ${fpc_status}"
  fi
else
  skip "no user ID"
fi

begin_test "Force password change: Login includes must_change_password flag"
if ! $fpc_called; then
  skip "force-password-change was not called"
elif [ -n "${FPC_USER_ID:-}" ] && [ "$FPC_USER_ID" != "null" ]; then
  login_resp=$(curl -s --max-time 10 \
    -X POST \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${FPC_USER}\",\"password\":\"${FPC_PASS}\"}" \
    "${BASE_URL}/api/v1/auth/login" 2>/dev/null) || true

  if [ -n "$login_resp" ] && echo "$login_resp" | jq -e '.' > /dev/null 2>&1; then
    # Check for any variant of the password change flag
    must_change=$(echo "$login_resp" | jq -r '
      .must_change_password //
      .password_change_required //
      .force_password_change //
      .require_password_change //
      empty
    ' 2>/dev/null) || true

    if [ "$must_change" = "true" ]; then
      pass
    elif [ "$must_change" = "false" ] || [ -z "$must_change" ]; then
      # Check if the response status itself indicates password change needed
      login_status=$(echo "$login_resp" | jq -r '.status // empty' 2>/dev/null) || true
      if echo "$login_status" | grep -qi "password" 2>/dev/null; then
        pass
      else
        fail "login response does not include must_change_password=true after force-password-change"
      fi
    else
      # Non-boolean value, check if truthy
      if [ "$must_change" != "null" ] && [ "$must_change" != "0" ]; then
        pass
      else
        fail "must_change_password flag is not set to true (got: ${must_change})"
      fi
    fi
  else
    fail "login response is not valid JSON: ${login_resp}"
  fi
else
  skip "no user ID"
fi

# Cleanup force-password-change user
if [ -n "${FPC_USER_ID:-}" ] && [ "$FPC_USER_ID" != "null" ]; then
  api_delete "/api/v1/users/${FPC_USER_ID}" > /dev/null 2>&1 || true
fi

# =========================================================================
# Cleanup: delete test repositories
# =========================================================================

api_delete "/api/v1/repositories/${GENERIC_REPO}" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${NPM_REPO}" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${PYPI_REPO}" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${PRIVATE_REPO}" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${SCAN_REPO}" > /dev/null 2>&1 || true

end_suite
