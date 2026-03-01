#!/usr/bin/env bash
# test-concurrent-writes.sh - Verify no corruption from concurrent writes to the same path
#
# Launches two parallel uploads of the same artifact path with different
# content. Verifies exactly one version is stored (no corruption or partial
# writes) and that the stored content matches one of the two uploaded files.
#
# Requires: kubectl, NAMESPACE

source "$(dirname "$0")/../../lib/common.sh"

begin_suite "data-concurrent-writes"
require_cmd kubectl
auth_admin
setup_workdir

NAMESPACE="${NAMESPACE:-ak-test-${RUN_ID}}"
REPO_KEY="data-conc-${RUN_ID}"
ARTIFACT_PATH="files/v1/contested.bin"

# ---------------------------------------------------------------------------
# Create repository
# ---------------------------------------------------------------------------

begin_test "Create generic repository"
if create_local_repo "$REPO_KEY" "generic"; then
  pass
else
  fail "could not create generic repo"
fi

# ---------------------------------------------------------------------------
# Prepare two different files
# ---------------------------------------------------------------------------

begin_test "Prepare two distinct files for same path"
dd if=/dev/urandom bs=1024 count=16 of="${WORK_DIR}/version-a.bin" 2>/dev/null
dd if=/dev/urandom bs=1024 count=16 of="${WORK_DIR}/version-b.bin" 2>/dev/null
SHA_A=$(shasum -a 256 "${WORK_DIR}/version-a.bin" | awk '{print $1}')
SHA_B=$(shasum -a 256 "${WORK_DIR}/version-b.bin" | awk '{print $1}')
echo "  Version A SHA256: ${SHA_A}"
echo "  Version B SHA256: ${SHA_B}"
if [ "$SHA_A" != "$SHA_B" ]; then
  pass
else
  fail "generated files are identical (extremely unlikely, try again)"
fi

# ---------------------------------------------------------------------------
# Launch parallel uploads
# ---------------------------------------------------------------------------

begin_test "Upload two versions in parallel to the same path"
STATUS_A_FILE="${WORK_DIR}/status-a"
STATUS_B_FILE="${WORK_DIR}/status-b"

# Upload version A in background
(
  code=$(curl -s -o /dev/null -w '%{http_code}' -X PUT \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/octet-stream" \
    --data-binary "@${WORK_DIR}/version-a.bin" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/${ARTIFACT_PATH}" 2>/dev/null || echo "000")
  echo "$code" > "$STATUS_A_FILE"
) &
PID_A=$!

# Upload version B in background
(
  code=$(curl -s -o /dev/null -w '%{http_code}' -X PUT \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/octet-stream" \
    --data-binary "@${WORK_DIR}/version-b.bin" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/${ARTIFACT_PATH}" 2>/dev/null || echo "000")
  echo "$code" > "$STATUS_B_FILE"
) &
PID_B=$!

# Wait for both
wait "$PID_A" 2>/dev/null || true
wait "$PID_B" 2>/dev/null || true

CODE_A=$(cat "$STATUS_A_FILE" 2>/dev/null || echo "unknown")
CODE_B=$(cat "$STATUS_B_FILE" 2>/dev/null || echo "unknown")
echo "  Upload A status: ${CODE_A}"
echo "  Upload B status: ${CODE_B}"
pass

# ---------------------------------------------------------------------------
# Verify exactly one version is stored
# ---------------------------------------------------------------------------

begin_test "Download and verify stored content is not corrupted"
if curl -sf -H "$(auth_header)" \
    -o "${WORK_DIR}/downloaded.bin" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}/download/${ARTIFACT_PATH}"; then
  DL_SHA=$(shasum -a 256 "${WORK_DIR}/downloaded.bin" | awk '{print $1}')
  echo "  Downloaded SHA256: ${DL_SHA}"

  if [ "$DL_SHA" = "$SHA_A" ]; then
    echo "  Stored version matches version A"
    pass
  elif [ "$DL_SHA" = "$SHA_B" ]; then
    echo "  Stored version matches version B"
    pass
  else
    fail "stored content does not match either upload (corruption detected): got ${DL_SHA}"
  fi
else
  fail "could not download artifact after concurrent writes"
fi

# ---------------------------------------------------------------------------
# Verify file size is correct
# ---------------------------------------------------------------------------

begin_test "Verify file size matches one of the uploads"
if [ -f "${WORK_DIR}/downloaded.bin" ]; then
  DL_SIZE=$(wc -c < "${WORK_DIR}/downloaded.bin" | tr -d ' ')
  EXPECTED_SIZE=$(wc -c < "${WORK_DIR}/version-a.bin" | tr -d ' ')
  if assert_eq "$DL_SIZE" "$EXPECTED_SIZE" "file size mismatch (expected ${EXPECTED_SIZE}, got ${DL_SIZE})"; then
    pass
  fi
else
  fail "downloaded file does not exist"
fi

end_suite
