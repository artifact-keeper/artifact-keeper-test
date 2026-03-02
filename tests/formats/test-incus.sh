#!/usr/bin/env bash
# test-incus.sh - Incus/LXC container image E2E test (curl-based)
#
# Tests the SimpleStreams API endpoints and image lifecycle:
#   1. Create an Incus repository
#   2. Upload a unified tarball image
#   3. Validate SimpleStreams index.json
#   4. Validate SimpleStreams images.json (products:1.0 catalog)
#   5. Download and verify an image file
#   6. Delete an image and verify catalog update

source "$(dirname "$0")/../lib/common.sh"

begin_suite "incus"
auth_admin
setup_workdir

REPO_KEY="test-incus-${RUN_ID}"

# -----------------------------------------------------------------------
# Create repository
# -----------------------------------------------------------------------
begin_test "Create Incus repository"
if create_local_repo "$REPO_KEY" "incus"; then
  pass
else
  fail "could not create incus repository"
fi

# -----------------------------------------------------------------------
# Generate and upload a unified tarball
# -----------------------------------------------------------------------
begin_test "Upload unified tarball"
UNIFIED_DIR="$WORK_DIR/unified"
mkdir -p "$UNIFIED_DIR/rootfs/etc"

cat > "$UNIFIED_DIR/metadata.yaml" <<'EOF'
architecture: x86_64
creation_date: 1708000000
properties:
  os: Ubuntu
  release: noble
  variant: default
  description: Ubuntu noble amd64 (test)
  serial: "20240215"
EOF
echo "Ubuntu 24.04 LTS" > "$UNIFIED_DIR/rootfs/etc/os-release"

UNIFIED_TARBALL="$WORK_DIR/incus.tar.gz"
tar czf "$UNIFIED_TARBALL" -C "$UNIFIED_DIR" metadata.yaml rootfs

upload_resp=$(curl -s -w "\n%{http_code}" -X PUT \
  -H "$(format_auth_header)" \
  -H "Content-Type: application/gzip" \
  --data-binary "@${UNIFIED_TARBALL}" \
  "${BASE_URL}/incus/${REPO_KEY}/images/ubuntu-noble/20240215/incus.tar.gz") || true

http_code=$(echo "$upload_resp" | tail -1)
upload_body=$(echo "$upload_resp" | sed '$d')

if [ "$http_code" = "201" ] || [ "$http_code" = "200" ]; then
  UNIFIED_SHA256=$(echo "$upload_body" | jq -r '.sha256 // empty' 2>/dev/null) || true
  pass
else
  fail "unified tarball upload returned ${http_code}, expected 201"
fi

# -----------------------------------------------------------------------
# Validate SimpleStreams index.json
# -----------------------------------------------------------------------
begin_test "Validate index.json"
index_resp=$(curl -sf "${BASE_URL}/incus/${REPO_KEY}/streams/v1/index.json" 2>/dev/null) || true

if [ -z "$index_resp" ]; then
  fail "could not fetch index.json"
else
  index_format=$(echo "$index_resp" | jq -r '.format // empty') || true
  if assert_eq "$index_format" "index:1.0" "index.json format should be index:1.0, got ${index_format}"; then
    pass
  fi
fi

# -----------------------------------------------------------------------
# Validate SimpleStreams images.json
# -----------------------------------------------------------------------
begin_test "Validate images.json"
images_resp=$(curl -sf "${BASE_URL}/incus/${REPO_KEY}/streams/v1/images.json" 2>/dev/null) || true

if [ -z "$images_resp" ]; then
  fail "could not fetch images.json"
else
  images_format=$(echo "$images_resp" | jq -r '.format // empty') || true
  if [ "$images_format" != "products:1.0" ]; then
    fail "images.json format should be products:1.0, got ${images_format}"
  else
    ubuntu_product=$(echo "$images_resp" | jq '.products["ubuntu-noble"] // null') || true
    if [ "$ubuntu_product" = "null" ] || [ -z "$ubuntu_product" ]; then
      fail "ubuntu-noble product not found in catalog"
    else
      pass
    fi
  fi
fi

# -----------------------------------------------------------------------
# Download and verify image file
# -----------------------------------------------------------------------
begin_test "Download image file"
dl_file="$WORK_DIR/downloaded.tar.gz"
dl_status=$(curl -s -o "$dl_file" -w '%{http_code}' \
  "${BASE_URL}/incus/${REPO_KEY}/images/ubuntu-noble/20240215/incus.tar.gz") || true

if [ "$dl_status" = "200" ]; then
  orig_size=$(wc -c < "$UNIFIED_TARBALL" | tr -d ' ')
  dl_size=$(wc -c < "$dl_file" | tr -d ' ')
  if [ "$orig_size" = "$dl_size" ]; then
    pass
  else
    fail "size mismatch: original=${orig_size}, downloaded=${dl_size}"
  fi
else
  fail "download returned ${dl_status}, expected 200"
fi

# -----------------------------------------------------------------------
# Delete image and verify catalog update
# -----------------------------------------------------------------------
begin_test "Delete image"
del_status=$(curl -s -o /dev/null -w '%{http_code}' -X DELETE \
  -H "$(format_auth_header)" \
  "${BASE_URL}/incus/${REPO_KEY}/images/ubuntu-noble/20240215/incus.tar.gz") || true

if [ "$del_status" = "204" ] || [ "$del_status" = "200" ]; then
  pass
else
  fail "delete returned ${del_status}, expected 204"
fi

begin_test "Verify deletion in catalog"
images_after=$(curl -sf "${BASE_URL}/incus/${REPO_KEY}/streams/v1/images.json" 2>/dev/null) || true

if [ -z "$images_after" ]; then
  # If the catalog is empty or gone after the only image was deleted, that counts as success
  pass
else
  ubuntu_after=$(echo "$images_after" | jq -r '.products["ubuntu-noble"].versions["20240215"].items // null' 2>/dev/null) || true
  if [ "$ubuntu_after" = "null" ] || [ -z "$ubuntu_after" ] || [ "$ubuntu_after" = "{}" ]; then
    pass
  else
    # The item might still be there briefly; treat as a warning, not a hard failure
    fail "deleted image still present in catalog"
  fi
fi

end_suite
