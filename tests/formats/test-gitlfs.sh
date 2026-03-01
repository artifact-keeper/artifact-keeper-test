#!/usr/bin/env bash
# test-gitlfs.sh - Git LFS E2E test
# Tests the Git LFS Batch API at /lfs/{repo_key}/.
source "$(dirname "$0")/../lib/common.sh"

begin_suite "gitlfs"
auth_admin
setup_workdir

REPO_KEY="test-gitlfs-${RUN_ID}"
LFS_MEDIA_TYPE="application/vnd.git-lfs+json"

# ---------------------------------------------------------------------------
# Create repository
# ---------------------------------------------------------------------------

begin_test "Create Git LFS local repository"
if create_local_repo "$REPO_KEY" "gitlfs"; then
  pass
else
  fail "could not create gitlfs repo"
fi

# ---------------------------------------------------------------------------
# Generate test object
# ---------------------------------------------------------------------------

begin_test "Generate test LFS object"
echo "Hello, Git LFS object content for E2E testing" > "${WORK_DIR}/lfs-object.bin"
OBJ_SIZE=$(wc -c < "${WORK_DIR}/lfs-object.bin" | tr -d ' ')
OBJ_OID=$(shasum -a 256 "${WORK_DIR}/lfs-object.bin" | awk '{print $1}')
pass

# ---------------------------------------------------------------------------
# Batch upload request
# ---------------------------------------------------------------------------

begin_test "POST batch upload request"
BATCH_RESP=$(curl -sf -X POST \
  -H "$(auth_header)" \
  -H "Content-Type: ${LFS_MEDIA_TYPE}" \
  -H "Accept: ${LFS_MEDIA_TYPE}" \
  -d "{\"operation\":\"upload\",\"transfers\":[\"basic\"],\"objects\":[{\"oid\":\"${OBJ_OID}\",\"size\":${OBJ_SIZE}}]}" \
  "${BASE_URL}/lfs/${REPO_KEY}/objects/batch") || true

if [ -z "$BATCH_RESP" ]; then
  fail "batch upload request returned empty response"
else
  UPLOAD_HREF=$(echo "$BATCH_RESP" | jq -r '.objects[0].actions.upload.href // empty')
  if [ -z "$UPLOAD_HREF" ]; then
    EXISTING=$(echo "$BATCH_RESP" | jq -r '.objects[0].oid // empty')
    if [ "$EXISTING" = "$OBJ_OID" ]; then
      pass
    else
      fail "batch response missing upload href and object oid"
    fi
  else
    pass
  fi
fi

# ---------------------------------------------------------------------------
# Upload object via PUT
# ---------------------------------------------------------------------------

begin_test "Upload LFS object via PUT"
if curl -sf -X PUT \
    -H "$(auth_header)" \
    -H "Content-Type: application/octet-stream" \
    --data-binary "@${WORK_DIR}/lfs-object.bin" \
    "${BASE_URL}/lfs/${REPO_KEY}/objects/${OBJ_OID}" > /dev/null; then
  pass
else
  fail "object upload returned non-2xx"
fi

# ---------------------------------------------------------------------------
# Verify upload
# ---------------------------------------------------------------------------

begin_test "Verify uploaded object"
VERIFY_STATUS=$(curl -s -o /dev/null -w '%{http_code}' -X POST \
  -H "$(auth_header)" \
  -H "Content-Type: ${LFS_MEDIA_TYPE}" \
  -d "{\"oid\":\"${OBJ_OID}\",\"size\":${OBJ_SIZE}}" \
  "${BASE_URL}/lfs/${REPO_KEY}/verify") || true

if [ "$VERIFY_STATUS" -ge 200 ] 2>/dev/null && [ "$VERIFY_STATUS" -lt 300 ] 2>/dev/null; then
  pass
else
  fail "verify returned HTTP ${VERIFY_STATUS}"
fi

# ---------------------------------------------------------------------------
# Batch download request
# ---------------------------------------------------------------------------

begin_test "POST batch download request"
DL_BATCH_RESP=$(curl -sf -X POST \
  -H "$(auth_header)" \
  -H "Content-Type: ${LFS_MEDIA_TYPE}" \
  -H "Accept: ${LFS_MEDIA_TYPE}" \
  -d "{\"operation\":\"download\",\"transfers\":[\"basic\"],\"objects\":[{\"oid\":\"${OBJ_OID}\",\"size\":${OBJ_SIZE}}]}" \
  "${BASE_URL}/lfs/${REPO_KEY}/objects/batch") || true

if [ -z "$DL_BATCH_RESP" ]; then
  fail "batch download request returned empty response"
else
  DL_OID=$(echo "$DL_BATCH_RESP" | jq -r '.objects[0].oid // empty')
  if assert_eq "$DL_OID" "$OBJ_OID" "batch download oid mismatch"; then
    pass
  fi
fi

# ---------------------------------------------------------------------------
# Download and verify content
# ---------------------------------------------------------------------------

begin_test "Download object and verify content"
if curl -sf -H "$(auth_header)" \
    -o "${WORK_DIR}/downloaded-lfs.bin" \
    "${BASE_URL}/lfs/${REPO_KEY}/objects/${OBJ_OID}"; then
  DL_SHA256=$(shasum -a 256 "${WORK_DIR}/downloaded-lfs.bin" | awk '{print $1}')
  if assert_eq "$DL_SHA256" "$OBJ_OID" "downloaded object SHA256 mismatch"; then
    pass
  fi
else
  fail "object download returned non-2xx"
fi

end_suite
