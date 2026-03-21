#!/usr/bin/env bash
# test-ansible.sh - Ansible Galaxy collection E2E test
# Tests the Galaxy-compatible API at /ansible/{repo_key}/.
source "$(dirname "$0")/../lib/common.sh"

begin_suite "ansible"
auth_admin
setup_workdir

REPO_KEY="test-ansible-${RUN_ID}"

# -----------------------------------------------------------------------
begin_test "Create Ansible local repository"
# -----------------------------------------------------------------------
if create_local_repo "$REPO_KEY" "ansible"; then
  pass
else
  fail "could not create ansible repo"
fi

# -----------------------------------------------------------------------
begin_test "Upload Ansible collection"
# -----------------------------------------------------------------------
# Build a minimal collection tarball with galaxy.yml and MANIFEST.json
COLL_DIR="${WORK_DIR}/collection"
mkdir -p "${COLL_DIR}/testns/testcoll/plugins/modules"
mkdir -p "${COLL_DIR}/testns/testcoll/meta"

cat > "${COLL_DIR}/testns/testcoll/galaxy.yml" <<'GALAXYEOF'
namespace: testns
name: testcoll
version: "1.0.0"
readme: README.md
description: Test collection for E2E
authors:
  - Tester
license:
  - MIT
GALAXYEOF

cat > "${COLL_DIR}/testns/testcoll/MANIFEST.json" <<'MANIFESTEOF'
{
  "collection_info": {
    "namespace": "testns",
    "name": "testcoll",
    "version": "1.0.0",
    "description": "Test collection for E2E",
    "license": ["MIT"],
    "authors": ["Tester"],
    "dependencies": {}
  }
}
MANIFESTEOF

echo "# Test Collection" > "${COLL_DIR}/testns/testcoll/README.md"

cat > "${COLL_DIR}/testns/testcoll/plugins/modules/hello.py" <<'PYEOF'
#!/usr/bin/python
DOCUMENTATION = """
module: hello
short_description: Test module
"""
PYEOF

tar czf "${WORK_DIR}/testns-testcoll-1.0.0.tar.gz" -C "${COLL_DIR}" testns/testcoll

# Upload as multipart (Galaxy API expects multipart with 'file' field)
UPLOAD_STATUS=$(curl -s -o "${WORK_DIR}/upload-resp.json" -w '%{http_code}' \
  -X POST \
  -H "$(format_auth_header)" \
  -F "file=@${WORK_DIR}/testns-testcoll-1.0.0.tar.gz" \
  -F 'collection={"namespace":"testns","name":"testcoll","version":"1.0.0"};type=application/json' \
  "${BASE_URL}/ansible/${REPO_KEY}/api/v3/artifacts/collections/") || true

if [ "$UPLOAD_STATUS" -ge 200 ] 2>/dev/null && [ "$UPLOAD_STATUS" -lt 300 ] 2>/dev/null; then
  pass
else
  fail "upload returned HTTP ${UPLOAD_STATUS}"
fi

# -----------------------------------------------------------------------
begin_test "Query Galaxy-compatible API endpoint"
# -----------------------------------------------------------------------
LIST_RESP=$(curl -sf \
  -H "$(format_auth_header)" \
  "${BASE_URL}/ansible/${REPO_KEY}/api/v3/collections/") || true

if [ -n "$LIST_RESP" ]; then
  if assert_contains "$LIST_RESP" "testcoll" "collection list missing testcoll"; then
    pass
  fi
else
  fail "list collections returned empty response"
fi

# -----------------------------------------------------------------------
begin_test "List artifacts via management API"
# -----------------------------------------------------------------------
if resp=$(api_get "/api/v1/repositories/${REPO_KEY}/artifacts"); then
  if assert_contains "$resp" "testcoll" "artifact list should contain collection"; then
    pass
  fi
else
  fail "GET /api/v1/repositories/${REPO_KEY}/artifacts returned error"
fi

# -----------------------------------------------------------------------
begin_test "Download and verify collection"
# -----------------------------------------------------------------------
# Download via the management API artifact endpoint
if curl -sf -H "$(auth_header)" \
    -o "${WORK_DIR}/downloaded-collection.tar.gz" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/testns/testcoll/1.0.0/testns-testcoll-1.0.0.tar.gz"; then
  if [ -f "${WORK_DIR}/downloaded-collection.tar.gz" ] && [ -s "${WORK_DIR}/downloaded-collection.tar.gz" ]; then
    pass
  else
    fail "downloaded file is empty"
  fi
else
  # Try the Galaxy download endpoint
  dl_status=$(curl -s -o "${WORK_DIR}/downloaded-collection.tar.gz" -w '%{http_code}' \
    -H "$(format_auth_header)" \
    "${BASE_URL}/ansible/${REPO_KEY}/api/v3/collections/testns/testcoll/versions/1.0.0/download/" 2>/dev/null) || true
  if [ "$dl_status" = "200" ] && [ -s "${WORK_DIR}/downloaded-collection.tar.gz" ]; then
    pass
  else
    fail "download failed (status: ${dl_status})"
  fi
fi

# -----------------------------------------------------------------------
begin_test "Upload second version"
# -----------------------------------------------------------------------
# Update version in galaxy.yml and MANIFEST.json for v2
cat > "${COLL_DIR}/testns/testcoll/galaxy.yml" <<'GALAXYEOF2'
namespace: testns
name: testcoll
version: "2.0.0"
readme: README.md
description: Test collection for E2E v2
authors:
  - Tester
license:
  - MIT
GALAXYEOF2

cat > "${COLL_DIR}/testns/testcoll/MANIFEST.json" <<'MANIFESTEOF2'
{
  "collection_info": {
    "namespace": "testns",
    "name": "testcoll",
    "version": "2.0.0",
    "description": "Test collection for E2E v2",
    "license": ["MIT"],
    "authors": ["Tester"],
    "dependencies": {}
  }
}
MANIFESTEOF2

tar czf "${WORK_DIR}/testns-testcoll-2.0.0.tar.gz" -C "${COLL_DIR}" testns/testcoll

V2_STATUS=$(curl -s -o /dev/null -w '%{http_code}' \
  -X POST \
  -H "$(format_auth_header)" \
  -F "file=@${WORK_DIR}/testns-testcoll-2.0.0.tar.gz" \
  -F 'collection={"namespace":"testns","name":"testcoll","version":"2.0.0"};type=application/json' \
  "${BASE_URL}/ansible/${REPO_KEY}/api/v3/artifacts/collections/") || true

if [ "$V2_STATUS" -ge 200 ] 2>/dev/null && [ "$V2_STATUS" -lt 300 ] 2>/dev/null; then
  pass
else
  fail "v2 upload returned HTTP ${V2_STATUS}"
fi

# -----------------------------------------------------------------------
begin_test "Delete collection and verify removal"
# -----------------------------------------------------------------------
# Delete v1 via management API
status=$(curl -s -o /dev/null -w "%{http_code}" \
  -X DELETE -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/testns/testcoll/1.0.0/testns-testcoll-1.0.0.tar.gz" 2>&1) || true
if [ "$status" = "200" ] || [ "$status" = "204" ]; then
  verify_status=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "$(auth_header)" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/testns/testcoll/1.0.0/testns-testcoll-1.0.0.tar.gz" 2>&1) || true
  if [ "$verify_status" = "404" ]; then
    pass
  else
    fail "artifact still accessible after delete (status: ${verify_status})"
  fi
else
  fail "delete returned ${status}"
fi

end_suite
