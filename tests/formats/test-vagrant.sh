#!/usr/bin/env bash
# Vagrant box format E2E test
# Tests box file upload and Vagrant Cloud API listing via /ext/vagrant/{repo_key}/.
source "$(dirname "$0")/../lib/common.sh"

begin_suite "vagrant"
auth_admin
setup_workdir

REPO_KEY="test-vagrant-${RUN_ID}"
BOX_NAME="test-box"
BOX_VERSION="1.0.$(date +%s)"
BOX_PROVIDER="virtualbox"
EXT_URL="${BASE_URL}/ext/vagrant/${REPO_KEY}"

# ---------------------------------------------------------------------------
# Create repository
# ---------------------------------------------------------------------------

begin_test "Create vagrant local repository"
if create_local_repo "$REPO_KEY" "vagrant"; then
  pass
else
  fail "could not create vagrant repo"
fi

# ---------------------------------------------------------------------------
# Create test box file
# ---------------------------------------------------------------------------

begin_test "Create test box file"
cd "$WORK_DIR"

# A Vagrant box is a tar.gz containing metadata.json and a disk image.
# Create a minimal box for testing.
mkdir -p box-content
cat > box-content/metadata.json <<EOF
{
  "provider": "${BOX_PROVIDER}"
}
EOF

cat > box-content/Vagrantfile <<'EOF'
Vagrant.configure("2") do |config|
  config.vm.base_mac = "0800272A2501"
end
EOF

# Create a small placeholder disk image
dd if=/dev/urandom bs=1024 count=2 of=box-content/box-disk.vmdk 2>/dev/null

tar czf "${WORK_DIR}/test.box" -C box-content .

pass

# ---------------------------------------------------------------------------
# Upload box file via PUT
# ---------------------------------------------------------------------------

begin_test "Upload box file"
if resp=$(curl -sf -X PUT \
  -H "$(format_auth_header)" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@${WORK_DIR}/test.box" \
  "${EXT_URL}/${BOX_NAME}/${BOX_VERSION}/${BOX_PROVIDER}/test.box" 2>&1); then
  pass
else
  fail "upload box file failed: ${resp}"
fi

# ---------------------------------------------------------------------------
# Query Vagrant Cloud API listing
# ---------------------------------------------------------------------------

begin_test "Query box listing"
sleep 1
if resp=$(curl -sf "${EXT_URL}/${BOX_NAME}" -H "$(format_auth_header)"); then
  if assert_contains "$resp" "$BOX_NAME" "box listing should contain box name"; then
    pass
  fi
else
  # Try querying the root listing
  if resp=$(curl -sf "${EXT_URL}/" -H "$(format_auth_header)"); then
    if assert_contains "$resp" "$BOX_NAME" "root listing should contain box name"; then
      pass
    fi
  else
    fail "could not retrieve box listing"
  fi
fi

# ---------------------------------------------------------------------------
# Download box file and verify size
# ---------------------------------------------------------------------------

begin_test "Download box file"
DL_FILE="${WORK_DIR}/downloaded.box"
if curl -sf -H "$(format_auth_header)" -o "$DL_FILE" \
  "${EXT_URL}/${BOX_NAME}/${BOX_VERSION}/${BOX_PROVIDER}/test.box"; then
  DL_SIZE=$(wc -c < "$DL_FILE" | tr -d ' ')
  ORIG_SIZE=$(wc -c < "${WORK_DIR}/test.box" | tr -d ' ')
  if assert_eq "$DL_SIZE" "$ORIG_SIZE" "downloaded box size should match original"; then
    pass
  fi
else
  fail "download box file failed"
fi

# ---------------------------------------------------------------------------
# Verify artifacts via management API
# ---------------------------------------------------------------------------

begin_test "List artifacts via management API"
if resp=$(api_get "/api/v1/repositories/${REPO_KEY}/artifacts"); then
  if assert_contains "$resp" "$BOX_NAME" "artifact list should contain box name"; then
    pass
  fi
else
  fail "GET /api/v1/repositories/${REPO_KEY}/artifacts returned error"
fi

end_suite
