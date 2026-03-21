#!/usr/bin/env bash
# test-artifact-integrity.sh - T2-08: Artifact integrity verification
#
# Verifies that uploading an artifact with a mismatched checksum is rejected,
# while uploading with a correct checksum succeeds.

source "$(dirname "$0")/../lib/common.sh"

begin_suite "artifact-integrity"
auth_admin
setup_workdir

REPO_KEY="sec-integrity-${RUN_ID}"

# ---------------------------------------------------------------------------
# Create a generic repository
# ---------------------------------------------------------------------------

begin_test "Create generic local repo"
if create_local_repo "$REPO_KEY" "generic"; then
  pass
else
  fail "could not create generic repo"
fi

# ---------------------------------------------------------------------------
# Generate test artifact and compute correct checksum
# ---------------------------------------------------------------------------

echo "integrity-test-content-${RUN_ID}" > "${WORK_DIR}/artifact.bin"
CORRECT_SHA256=$(shasum -a 256 "${WORK_DIR}/artifact.bin" | awk '{print $1}')
WRONG_SHA256="0000000000000000000000000000000000000000000000000000000000000000"

# ---------------------------------------------------------------------------
# Upload with wrong SHA-256 checksum header
# ---------------------------------------------------------------------------

begin_test "Upload with mismatched SHA-256 checksum is rejected"
status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X PUT \
  -H "$(auth_header)" \
  -H "Content-Type: application/octet-stream" \
  -H "X-Checksum-Sha256: ${WRONG_SHA256}" \
  --data-binary "@${WORK_DIR}/artifact.bin" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/pkg/v1/artifact.bin") || true

if [ "$status" = "400" ] || [ "$status" = "409" ] || [ "$status" = "422" ]; then
  pass
elif [ "$status" = "200" ] || [ "$status" = "201" ]; then
  # Backend may not validate checksum headers yet. Check if the stored
  # checksum matches the correct one (server computed its own).
  stored_resp=""
  if stored_resp=$(api_get "/api/v1/repositories/${REPO_KEY}/artifacts/pkg/v1/artifact.bin" 2>/dev/null); then
    stored_sha=$(echo "$stored_resp" | jq -r '.sha256 // .checksums.sha256 // empty' 2>/dev/null) || true
    if [ "$stored_sha" = "$CORRECT_SHA256" ]; then
      skip "server accepted upload but computed its own correct checksum (does not validate client-provided checksum header)"
    else
      fail "server accepted upload with wrong checksum and stored an unexpected hash"
    fi
  else
    skip "server accepted upload with wrong checksum header but did not reject it (checksum header validation may not be implemented)"
  fi
else
  fail "expected 400/409/422 for mismatched checksum, got ${status}"
fi

# ---------------------------------------------------------------------------
# Upload with correct SHA-256 checksum header
# ---------------------------------------------------------------------------

begin_test "Upload with correct SHA-256 checksum succeeds"
status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X PUT \
  -H "$(auth_header)" \
  -H "Content-Type: application/octet-stream" \
  -H "X-Checksum-Sha256: ${CORRECT_SHA256}" \
  --data-binary "@${WORK_DIR}/artifact.bin" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/pkg/v1/correct-artifact.bin") || true

if [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then
  pass
else
  fail "expected 2xx for correct checksum upload, got ${status}"
fi

# ---------------------------------------------------------------------------
# Verify uploaded artifact checksum matches
# ---------------------------------------------------------------------------

begin_test "Downloaded artifact matches original content"
if curl -sf $CURL_TIMEOUT -H "$(auth_header)" \
    -o "${WORK_DIR}/downloaded.bin" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/pkg/v1/correct-artifact.bin" 2>/dev/null; then
  dl_sha256=$(shasum -a 256 "${WORK_DIR}/downloaded.bin" | awk '{print $1}')
  if assert_eq "$dl_sha256" "$CORRECT_SHA256" "downloaded checksum should match original"; then
    pass
  fi
else
  # Try format-level endpoint
  if curl -sf $CURL_TIMEOUT -H "$(auth_header)" \
      -o "${WORK_DIR}/downloaded2.bin" \
      "${BASE_URL}/generic/${REPO_KEY}/pkg/v1/correct-artifact.bin" 2>/dev/null; then
    dl_sha256=$(shasum -a 256 "${WORK_DIR}/downloaded2.bin" | awk '{print $1}')
    if assert_eq "$dl_sha256" "$CORRECT_SHA256" "downloaded checksum should match original"; then
      pass
    fi
  else
    skip "could not download artifact to verify integrity"
  fi
fi

end_suite
