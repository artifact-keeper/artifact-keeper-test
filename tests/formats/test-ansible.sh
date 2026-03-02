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

end_suite
