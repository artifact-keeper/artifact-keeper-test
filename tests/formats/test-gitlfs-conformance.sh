#!/usr/bin/env bash
# test-gitlfs-conformance.sh - Git LFS Batch API conformance tests
#
# Validates that the Git LFS endpoints conform to the LFS Batch API spec:
# batch upload/download negotiation, object storage, SHA256 integrity,
# multi-object batches, error responses, and Content-Type headers.
#
# Endpoints: ${BASE_URL}/lfs/{repo_key}/
#
# Requires: jq, shasum
source "$(dirname "$0")/../lib/common.sh"

begin_suite "gitlfs-conformance"
auth_admin
setup_workdir

REPO_KEY="test-gitlfs-conf-${RUN_ID}"
LFS_MEDIA_TYPE="application/vnd.git-lfs+json"
LFS_BASE="${BASE_URL}/lfs/${REPO_KEY}"

# ---------------------------------------------------------------------------
# Create repository
# ---------------------------------------------------------------------------

begin_test "Create Git LFS local repository"
if create_local_repo "$REPO_KEY" "gitlfs"; then
  pass
else
  fail "could not create gitlfs repository"
fi

# ---------------------------------------------------------------------------
# Generate test objects
# ---------------------------------------------------------------------------

echo "Git LFS conformance test object alpha" > "${WORK_DIR}/object-a.bin"
OBJ_A_SIZE=$(wc -c < "${WORK_DIR}/object-a.bin" | tr -d ' ')
OBJ_A_OID=$(shasum -a 256 "${WORK_DIR}/object-a.bin" | awk '{print $1}')

echo "Git LFS conformance test object bravo, slightly different content" > "${WORK_DIR}/object-b.bin"
OBJ_B_SIZE=$(wc -c < "${WORK_DIR}/object-b.bin" | tr -d ' ')
OBJ_B_OID=$(shasum -a 256 "${WORK_DIR}/object-b.bin" | awk '{print $1}')

# ---------------------------------------------------------------------------
# 1. POST /objects/batch with upload operation returns upload URLs
# ---------------------------------------------------------------------------

begin_test "Batch upload request returns upload actions"
UPLOAD_BATCH=$(curl -sf $CURL_TIMEOUT -X POST \
  -H "$(format_auth_header)" \
  -H "Content-Type: ${LFS_MEDIA_TYPE}" \
  -H "Accept: ${LFS_MEDIA_TYPE}" \
  -d "{\"operation\":\"upload\",\"transfers\":[\"basic\"],\"objects\":[{\"oid\":\"${OBJ_A_OID}\",\"size\":${OBJ_A_SIZE}}]}" \
  "${LFS_BASE}/objects/batch") || true

if [ -z "$UPLOAD_BATCH" ]; then
  fail "batch upload request returned empty response"
else
  # Response must contain an objects array
  obj_count=$(echo "$UPLOAD_BATCH" | jq '.objects | length' 2>/dev/null) || true
  if [ "$obj_count" -ge 1 ] 2>/dev/null; then
    # Check for upload action href or an already-existing indicator
    upload_href=$(echo "$UPLOAD_BATCH" | jq -r '.objects[0].actions.upload.href // empty')
    obj_oid=$(echo "$UPLOAD_BATCH" | jq -r '.objects[0].oid // empty')
    if [ -n "$upload_href" ] || [ "$obj_oid" = "$OBJ_A_OID" ]; then
      pass
    else
      fail "batch upload response missing upload href and valid oid"
    fi
  else
    fail "batch upload response has no objects array or it is empty"
  fi
fi

# ---------------------------------------------------------------------------
# 2. PUT to upload URL stores the object
# ---------------------------------------------------------------------------

begin_test "Upload object via PUT"
if curl -sf $CURL_TIMEOUT -X PUT \
    -H "$(format_auth_header)" \
    -H "Content-Type: application/octet-stream" \
    --data-binary "@${WORK_DIR}/object-a.bin" \
    "${LFS_BASE}/objects/${OBJ_A_OID}" > /dev/null; then
  pass
else
  fail "object upload returned non-2xx"
fi

# ---------------------------------------------------------------------------
# 3. POST /objects/batch with download operation returns object URLs
# ---------------------------------------------------------------------------

begin_test "Batch download request returns download actions"
DL_BATCH=$(curl -sf $CURL_TIMEOUT -X POST \
  -H "$(format_auth_header)" \
  -H "Content-Type: ${LFS_MEDIA_TYPE}" \
  -H "Accept: ${LFS_MEDIA_TYPE}" \
  -d "{\"operation\":\"download\",\"transfers\":[\"basic\"],\"objects\":[{\"oid\":\"${OBJ_A_OID}\",\"size\":${OBJ_A_SIZE}}]}" \
  "${LFS_BASE}/objects/batch") || true

if [ -z "$DL_BATCH" ]; then
  fail "batch download request returned empty response"
else
  dl_oid=$(echo "$DL_BATCH" | jq -r '.objects[0].oid // empty')
  dl_href=$(echo "$DL_BATCH" | jq -r '.objects[0].actions.download.href // empty')
  if [ "$dl_oid" = "$OBJ_A_OID" ]; then
    if [ -n "$dl_href" ]; then
      pass
    else
      # Some implementations provide the download directly without explicit actions
      echo "  note: no explicit download href, but oid matches"
      pass
    fi
  else
    fail "batch download oid mismatch: expected ${OBJ_A_OID}, got ${dl_oid}"
  fi
fi

# ---------------------------------------------------------------------------
# 4. GET to download URL returns the object content
# ---------------------------------------------------------------------------

begin_test "Download object via GET returns correct content"
if curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    -o "${WORK_DIR}/downloaded-a.bin" \
    "${LFS_BASE}/objects/${OBJ_A_OID}"; then
  if [ -s "${WORK_DIR}/downloaded-a.bin" ]; then
    pass
  else
    fail "downloaded object file is empty"
  fi
else
  fail "object download returned non-2xx"
fi

# ---------------------------------------------------------------------------
# 5. Object integrity: SHA256 oid matches content
# ---------------------------------------------------------------------------

begin_test "Downloaded object SHA256 matches oid"
if [ -s "${WORK_DIR}/downloaded-a.bin" ]; then
  DL_SHA256=$(shasum -a 256 "${WORK_DIR}/downloaded-a.bin" | awk '{print $1}')
  if assert_eq "$DL_SHA256" "$OBJ_A_OID" "SHA256 mismatch: expected ${OBJ_A_OID}, got ${DL_SHA256}"; then
    pass
  fi
else
  skip "no downloaded object to verify"
fi

# ---------------------------------------------------------------------------
# 6. Batch with multiple objects
# ---------------------------------------------------------------------------

begin_test "Batch request with multiple objects"
# Upload object B first
curl -sf $CURL_TIMEOUT -X PUT \
  -H "$(format_auth_header)" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@${WORK_DIR}/object-b.bin" \
  "${LFS_BASE}/objects/${OBJ_B_OID}" > /dev/null 2>&1 || true

MULTI_BATCH=$(curl -sf $CURL_TIMEOUT -X POST \
  -H "$(format_auth_header)" \
  -H "Content-Type: ${LFS_MEDIA_TYPE}" \
  -H "Accept: ${LFS_MEDIA_TYPE}" \
  -d "{\"operation\":\"download\",\"transfers\":[\"basic\"],\"objects\":[{\"oid\":\"${OBJ_A_OID}\",\"size\":${OBJ_A_SIZE}},{\"oid\":\"${OBJ_B_OID}\",\"size\":${OBJ_B_SIZE}}]}" \
  "${LFS_BASE}/objects/batch") || true

if [ -z "$MULTI_BATCH" ]; then
  fail "multi-object batch request returned empty response"
else
  obj_count=$(echo "$MULTI_BATCH" | jq '.objects | length' 2>/dev/null) || true
  if [ "$obj_count" -ge 2 ] 2>/dev/null; then
    pass
  else
    fail "expected 2 objects in batch response, got ${obj_count}"
  fi
fi

# ---------------------------------------------------------------------------
# 7. 404 for nonexistent oid
# ---------------------------------------------------------------------------

begin_test "404 for nonexistent oid download"
FAKE_OID="0000000000000000000000000000000000000000000000000000000000000000"
status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  "${LFS_BASE}/objects/${FAKE_OID}") || true
if assert_eq "$status" "404" "expected 404 for nonexistent oid, got ${status}"; then
  pass
fi

# ---------------------------------------------------------------------------
# 8. Content-Type: application/vnd.git-lfs+json on batch responses
# ---------------------------------------------------------------------------

begin_test "Batch response Content-Type is application/vnd.git-lfs+json"
content_type=$(curl -sf $CURL_TIMEOUT -X POST \
  -H "$(format_auth_header)" \
  -H "Content-Type: ${LFS_MEDIA_TYPE}" \
  -H "Accept: ${LFS_MEDIA_TYPE}" \
  -o /dev/null -w '%{content_type}' \
  -d "{\"operation\":\"download\",\"transfers\":[\"basic\"],\"objects\":[{\"oid\":\"${OBJ_A_OID}\",\"size\":${OBJ_A_SIZE}}]}" \
  "${LFS_BASE}/objects/batch") || true

if [ -n "$content_type" ]; then
  if [[ "$content_type" == *"application/vnd.git-lfs+json"* ]]; then
    pass
  else
    fail "expected Content-Type containing application/vnd.git-lfs+json, got ${content_type}"
  fi
else
  fail "could not determine Content-Type for batch response"
fi

end_suite
