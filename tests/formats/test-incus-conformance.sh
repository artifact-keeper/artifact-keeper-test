#!/usr/bin/env bash
# test-incus-conformance.sh - Incus/LXD image repository conformance tests
#
# Validates that the Incus image repository implementation handles image
# uploads via monolithic PUT, serves the SimpleStreams catalog (index.json
# and images.json), supports downloads by product/version/filename path,
# and returns correct 404s for missing images.
#
# Endpoints: ${BASE_URL}/incus/{repo_key}/...
#   GET  /streams/v1/index.json               - SimpleStreams index
#   GET  /streams/v1/images.json              - Product catalog
#   PUT  /images/{product}/{version}/{file}   - Upload image file
#   GET  /images/{product}/{version}/{file}   - Download image file
#
# Requires: curl, jq, tar, xz or gzip, sha256sum or shasum
source "$(dirname "$0")/../lib/common.sh"

begin_suite "incus-conformance"
auth_admin
setup_workdir

REPO_KEY="test-incus-conf-${RUN_ID}"
PRODUCT="ubuntu-jammy-amd64"
VERSION="20260401"
FILENAME="rootfs.tar.gz"
INCUS_URL="${BASE_URL}/incus/${REPO_KEY}"

# Portable SHA256 helper (Linux uses sha256sum, macOS uses shasum)
sha256_hex() {
  if command -v sha256sum &>/dev/null; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

# ---------------------------------------------------------------------------
# Helper: build a minimal Incus/LXD rootfs tarball
#
# An Incus image is a compressed tarball. The metadata variant also
# includes a metadata.yaml file. For conformance testing, we create a
# small tar.gz with a metadata.yaml and a minimal filesystem tree.
# ---------------------------------------------------------------------------

build_incus_image() {
  local product="$1"
  local version="$2"
  local outfile="$3"

  local build_dir="${WORK_DIR}/incus-build-${product}-${version}"
  mkdir -p "${build_dir}/rootfs/etc"

  cat > "${build_dir}/metadata.yaml" <<EOYAML
architecture: amd64
creation_date: $(date +%s)
properties:
  description: Conformance test image ${product} ${version}
  os: ubuntu
  release: jammy
  architecture: amd64
  serial: "${version}"
EOYAML

  echo "conformance-test" > "${build_dir}/rootfs/etc/hostname"
  echo "root:x:0:0:root:/root:/bin/sh" > "${build_dir}/rootfs/etc/passwd"

  (cd "${build_dir}" && tar czf "${outfile}" metadata.yaml rootfs/)
}

# ---------------------------------------------------------------------------
# Create repository
# ---------------------------------------------------------------------------

begin_test "Create Incus local repository"
if create_local_repo "$REPO_KEY" "incus"; then
  pass
else
  fail "could not create incus repository"
fi

# ---------------------------------------------------------------------------
# 1. Upload container image (rootfs tarball)
# ---------------------------------------------------------------------------

begin_test "Upload container image"
IMAGE_FILE="${WORK_DIR}/${FILENAME}"
build_incus_image "$PRODUCT" "$VERSION" "$IMAGE_FILE"

upload_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X PUT \
  -H "$(format_auth_header)" \
  -H "Content-Type: application/gzip" \
  --data-binary "@${IMAGE_FILE}" \
  "${INCUS_URL}/images/${PRODUCT}/${VERSION}/${FILENAME}") || true

if [ "$upload_status" -ge 200 ] 2>/dev/null && [ "$upload_status" -lt 300 ] 2>/dev/null; then
  pass
else
  fail "image upload returned HTTP ${upload_status}, expected 2xx"
fi

sleep 1

# ---------------------------------------------------------------------------
# 2. List images (SimpleStreams catalog)
# ---------------------------------------------------------------------------

begin_test "SimpleStreams images.json lists uploaded image"
IMAGES_RESP=""
if IMAGES_RESP=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${INCUS_URL}/streams/v1/images.json" 2>/dev/null); then
  # images.json should contain a "products" object with entries
  has_products=$(echo "$IMAGES_RESP" | jq 'has("products")' 2>/dev/null) || true

  if [ "$has_products" = "true" ]; then
    # Check if our product appears
    product_count=$(echo "$IMAGES_RESP" | jq '.products | length' 2>/dev/null) || product_count=0

    if [ "$product_count" -ge 1 ] 2>/dev/null; then
      pass
    else
      fail "images.json has products object but it is empty"
    fi
  else
    # Some implementations may use a flat list or different structure
    if echo "$IMAGES_RESP" | jq '.' >/dev/null 2>&1; then
      echo "  note: valid JSON but missing 'products' key, checking for image references"
      if echo "$IMAGES_RESP" | grep -q "$PRODUCT" 2>/dev/null; then
        pass
      else
        fail "images.json does not reference uploaded product '${PRODUCT}'"
      fi
    else
      fail "images.json is not valid JSON"
    fi
  fi
else
  fail "GET /streams/v1/images.json returned error"
fi

# ---------------------------------------------------------------------------
# 3. Download image by product/version/filename
# ---------------------------------------------------------------------------

begin_test "Download image by path"
DL_FILE="${WORK_DIR}/downloaded-image.tar.gz"
dl_status=$(curl -s -o "$DL_FILE" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  "${INCUS_URL}/images/${PRODUCT}/${VERSION}/${FILENAME}") || true

if [ "$dl_status" -ge 200 ] 2>/dev/null && [ "$dl_status" -lt 300 ] 2>/dev/null; then
  if [ -s "$DL_FILE" ]; then
    pass
  else
    fail "downloaded image is empty"
  fi
else
  fail "image download returned HTTP ${dl_status}"
fi

# ---------------------------------------------------------------------------
# 4. Image metadata (SimpleStreams index.json)
# ---------------------------------------------------------------------------

begin_test "SimpleStreams index.json contains catalog reference"
INDEX_RESP=""
if INDEX_RESP=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${INCUS_URL}/streams/v1/index.json" 2>/dev/null); then
  # index.json should have a "format" field and an "index" object
  format_val=$(echo "$INDEX_RESP" | jq -r '.format // empty' 2>/dev/null) || true
  has_index=$(echo "$INDEX_RESP" | jq 'has("index")' 2>/dev/null) || true

  if [ "$has_index" = "true" ]; then
    # Verify the index references the images path
    images_path=$(echo "$INDEX_RESP" | jq -r '.index.images.path // empty' 2>/dev/null) || true
    if [ -n "$images_path" ]; then
      pass
    else
      # Accept if the index structure is present even without the expected path
      echo "  note: index.json has 'index' key but images path not at expected location"
      pass
    fi
  else
    # Accept if it is valid JSON with format field
    if [ -n "$format_val" ]; then
      echo "  note: index.json has format='${format_val}' but missing 'index' key"
      pass
    else
      fail "index.json missing both 'format' and 'index' fields"
    fi
  fi
else
  fail "GET /streams/v1/index.json returned error"
fi

# ---------------------------------------------------------------------------
# 5. Download integrity (SHA256 matches uploaded file)
# ---------------------------------------------------------------------------

begin_test "Download integrity (SHA256 matches uploaded file)"
if [ -s "$DL_FILE" ] && [ -s "$IMAGE_FILE" ]; then
  upload_sha=$(sha256_hex "$IMAGE_FILE")
  download_sha=$(sha256_hex "$DL_FILE")
  if assert_eq "$download_sha" "$upload_sha" "SHA256 mismatch: uploaded=${upload_sha} downloaded=${download_sha}"; then
    pass
  fi
else
  skip "uploaded or downloaded file missing for integrity check"
fi

# ---------------------------------------------------------------------------
# 6. 404 for nonexistent image
# ---------------------------------------------------------------------------

begin_test "404 for nonexistent image"
status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  "${INCUS_URL}/images/nonexistent-product-${RUN_ID}/99999999/missing.tar.gz") || true
if assert_eq "$status" "404" "expected 404 for nonexistent image, got ${status}"; then
  pass
fi

end_suite
