#!/usr/bin/env bash
# test-conan-packages.sh - Conan v2 package binary E2E tests
#
# Tests the Conan v2 package binary REST API: uploading package files
# (conaninfo.txt, conan_package.tgz, conanmanifest.txt) under recipe
# revisions, querying latest package revisions, downloading package
# files, and managing multiple package IDs and package revisions.
#
# Requires a running Artifact Keeper with Conan v2 support.

source "$(dirname "$0")/../lib/common.sh"

begin_suite "conan-packages"
auth_admin
setup_workdir

REPO_KEY="test-conan-pkg-${RUN_ID}"

# Fixed hashes for deterministic testing.
RECIPE_REV="af04a3b5c6d7e8f9a0b1c2d3e4f5a6b7"
PKG_ID_1="da39a3ee5e6b4b0d3255bfef95601890afd80709"
PKG_REV_1="0001000100010001000100010001beef"
PKG_ID_2="e3b0c44298fc1c149afbf4c8996fb92427ae41e4"
PKG_REV_2="0002000200020002000200020002cafe"
PKG_REV_1B="0003000300030003000300030003dead"

# Conan v2 API base for our test recipe: binpkg/1.0.0 with user/channel = _/_
RECIPE_BASE="/conan/${REPO_KEY}/v2/conans/binpkg/1.0.0/_/_"

# -----------------------------------------------------------------------
# 1. Create Conan local repository
# -----------------------------------------------------------------------
begin_test "Create Conan local repository"
if create_local_repo "$REPO_KEY" "conan"; then
  pass
else
  fail "could not create conan repo"
fi

# -----------------------------------------------------------------------
# 2. Upload recipe (conanfile.py) under a fixed revision
# -----------------------------------------------------------------------
begin_test "Upload recipe conanfile.py"

cat > "${WORK_DIR}/conanfile.py" <<'PYEOF'
from conan import ConanFile

class BinPkgConan(ConanFile):
    name = "binpkg"
    version = "1.0.0"
    license = "MIT"
    description = "Binary package E2E test library"
    settings = "os", "compiler", "build_type", "arch"

    def package_info(self):
        self.cpp_info.libs = ["binpkg"]
PYEOF

status=$(curl -s -o /dev/null -w '%{http_code}' -X PUT \
  -H "$(format_auth_header)" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@${WORK_DIR}/conanfile.py" \
  "${BASE_URL}${RECIPE_BASE}/revisions/${RECIPE_REV}/files/conanfile.py") || true

if [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then
  pass
else
  fail "recipe upload returned HTTP ${status}"
fi

# -----------------------------------------------------------------------
# 3. Upload conaninfo.txt for first package binary
# -----------------------------------------------------------------------
begin_test "Upload conaninfo.txt for package binary"

cat > "${WORK_DIR}/conaninfo.txt" <<'EOF'
[settings]
    arch=x86_64
    build_type=Release
    compiler=gcc
    compiler.version=12
    os=Linux
[requires]
    zlib/1.2.13
[options]
    shared=False
EOF

PKG_FILE_BASE="${RECIPE_BASE}/revisions/${RECIPE_REV}/packages/${PKG_ID_1}/revisions/${PKG_REV_1}/files"

status=$(curl -s -o /dev/null -w '%{http_code}' -X PUT \
  -H "$(format_auth_header)" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@${WORK_DIR}/conaninfo.txt" \
  "${BASE_URL}${PKG_FILE_BASE}/conaninfo.txt") || true

if [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then
  pass
else
  fail "conaninfo.txt upload returned HTTP ${status}"
fi

# -----------------------------------------------------------------------
# 4. Upload conan_package.tgz (tarball containing a fake library)
# -----------------------------------------------------------------------
begin_test "Upload conan_package.tgz with fake library"

mkdir -p "${WORK_DIR}/pkg-staging/lib"
# Create a small fake static library (just some bytes, not a real .a)
dd if=/dev/urandom of="${WORK_DIR}/pkg-staging/lib/libbinpkg.a" bs=1024 count=4 2>/dev/null
tar czf "${WORK_DIR}/conan_package.tgz" -C "${WORK_DIR}/pkg-staging" lib

status=$(curl -s -o /dev/null -w '%{http_code}' -X PUT \
  -H "$(format_auth_header)" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@${WORK_DIR}/conan_package.tgz" \
  "${BASE_URL}${PKG_FILE_BASE}/conan_package.tgz") || true

if [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then
  pass
else
  fail "conan_package.tgz upload returned HTTP ${status}"
fi

# -----------------------------------------------------------------------
# 5. Upload conanmanifest.txt for the package
# -----------------------------------------------------------------------
begin_test "Upload conanmanifest.txt for package"

# Build a manifest listing the two package files with dummy md5 hashes.
cat > "${WORK_DIR}/conanmanifest.txt" <<EOF
1708000000
conaninfo.txt: d41d8cd98f00b204e9800998ecf8427e
conan_package.tgz: $(md5sum "${WORK_DIR}/conan_package.tgz" 2>/dev/null | awk '{print $1}' || md5 -q "${WORK_DIR}/conan_package.tgz" 2>/dev/null || echo "0" )
EOF

status=$(curl -s -o /dev/null -w '%{http_code}' -X PUT \
  -H "$(format_auth_header)" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@${WORK_DIR}/conanmanifest.txt" \
  "${BASE_URL}${PKG_FILE_BASE}/conanmanifest.txt") || true

if [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then
  pass
else
  fail "conanmanifest.txt upload returned HTTP ${status}"
fi

# -----------------------------------------------------------------------
# 6. Get latest package revision and verify correct revision hash
# -----------------------------------------------------------------------
begin_test "Get latest package revision"

resp=$(curl -sf \
  -H "$(format_auth_header)" \
  "${BASE_URL}${RECIPE_BASE}/revisions/${RECIPE_REV}/packages/${PKG_ID_1}/latest" 2>/dev/null) || true

if [ -z "$resp" ]; then
  fail "latest package revision returned empty response"
else
  rev=$(echo "$resp" | jq -r '.revision // empty')
  if [ -n "$rev" ]; then
    if assert_eq "$rev" "$PKG_REV_1" "expected package revision ${PKG_REV_1}, got ${rev}"; then
      pass
    fi
  else
    fail "response missing 'revision' field: ${resp}"
  fi
fi

# -----------------------------------------------------------------------
# 7. Download conaninfo.txt and verify content roundtrip
# -----------------------------------------------------------------------
begin_test "Download conaninfo.txt and verify content"

dl_file="${WORK_DIR}/downloaded-conaninfo.txt"
dl_status=$(curl -sf -o "$dl_file" -w '%{http_code}' \
  -H "$(format_auth_header)" \
  "${BASE_URL}${PKG_FILE_BASE}/conaninfo.txt" 2>/dev/null) || true

if [ "$dl_status" = "200" ] && [ -s "$dl_file" ]; then
  dl_content=$(cat "$dl_file")
  ok=true
  if ! assert_contains "$dl_content" "arch=x86_64" "downloaded conaninfo.txt missing arch=x86_64"; then
    ok=false
  fi
  if ! assert_contains "$dl_content" "compiler=gcc" "downloaded conaninfo.txt missing compiler=gcc"; then
    ok=false
  fi
  if ! assert_contains "$dl_content" "zlib/1.2.13" "downloaded conaninfo.txt missing zlib/1.2.13 require"; then
    ok=false
  fi
  if $ok; then
    pass
  fi
else
  fail "download conaninfo.txt failed (HTTP ${dl_status})"
fi

# -----------------------------------------------------------------------
# 8. Download conan_package.tgz and verify it is valid gzip
# -----------------------------------------------------------------------
begin_test "Download conan_package.tgz and verify gzip"

dl_pkg="${WORK_DIR}/downloaded-conan_package.tgz"
dl_status=$(curl -sf -o "$dl_pkg" -w '%{http_code}' \
  -H "$(format_auth_header)" \
  "${BASE_URL}${PKG_FILE_BASE}/conan_package.tgz" 2>/dev/null) || true

if [ "$dl_status" = "200" ] && [ -s "$dl_pkg" ]; then
  if gzip -t "$dl_pkg" 2>/dev/null; then
    # Also verify the tarball contains our library file
    if tar tzf "$dl_pkg" 2>/dev/null | grep -q "libbinpkg.a"; then
      pass
    else
      fail "downloaded tarball does not contain lib/libbinpkg.a"
    fi
  else
    fail "downloaded conan_package.tgz is not valid gzip"
  fi
else
  fail "download conan_package.tgz failed (HTTP ${dl_status})"
fi

# -----------------------------------------------------------------------
# 9. Upload a second package_id (different arch/settings) under same recipe
# -----------------------------------------------------------------------
begin_test "Upload second package binary (aarch64)"

cat > "${WORK_DIR}/conaninfo-arm.txt" <<'EOF'
[settings]
    arch=armv8
    build_type=Release
    compiler=gcc
    compiler.version=12
    os=Linux
[requires]
    zlib/1.2.13
[options]
    shared=False
EOF

PKG2_FILE_BASE="${RECIPE_BASE}/revisions/${RECIPE_REV}/packages/${PKG_ID_2}/revisions/${PKG_REV_2}/files"

# Use retry helper: 1.1.x backend bcrypt-verifies Basic creds on every
# format-native call, and the spawn_blocking pool can transiently drop a
# verify task under back-to-back PUTs, surfacing as 401. See common.sh for
# the rationale (RATE_LIMIT_EXEMPT_USERNAMES wasn't backported to 1.1.x).
status=$(format_put_with_retry \
  "${BASE_URL}${PKG2_FILE_BASE}/conaninfo.txt" \
  "${WORK_DIR}/conaninfo-arm.txt") || true

if [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then
  pass
else
  fail "second package conaninfo.txt upload returned HTTP ${status}"
fi

# -----------------------------------------------------------------------
# 10. Verify both package binaries exist via latest endpoints
# -----------------------------------------------------------------------
begin_test "Verify both package binaries exist"

# Retry both reads; same transient-401 risk as the PUTs above.
resp1_file=$(mktemp)
resp2_file=$(mktemp)
status1=$(format_get_with_retry \
  "${BASE_URL}${RECIPE_BASE}/revisions/${RECIPE_REV}/packages/${PKG_ID_1}/latest" \
  "$resp1_file") || true
status2=$(format_get_with_retry \
  "${BASE_URL}${RECIPE_BASE}/revisions/${RECIPE_REV}/packages/${PKG_ID_2}/latest" \
  "$resp2_file") || true
resp1=$(cat "$resp1_file" 2>/dev/null || echo "")
resp2=$(cat "$resp2_file" 2>/dev/null || echo "")
rm -f "$resp1_file" "$resp2_file"

ok=true
rev1=$(echo "$resp1" | jq -r '.revision // empty' 2>/dev/null)
rev2=$(echo "$resp2" | jq -r '.revision // empty' 2>/dev/null)

if [ -z "$rev1" ]; then
  fail "package ${PKG_ID_1} latest revision not found"
  ok=false
fi
if [ -z "$rev2" ]; then
  fail "package ${PKG_ID_2} latest revision not found"
  ok=false
fi
if $ok; then
  if assert_eq "$rev1" "$PKG_REV_1" "pkg1 revision mismatch" && \
     assert_eq "$rev2" "$PKG_REV_2" "pkg2 revision mismatch"; then
    pass
  fi
fi

# -----------------------------------------------------------------------
# 11. Upload a second package revision for the first package_id
# -----------------------------------------------------------------------
begin_test "Upload second package revision for first package_id"

cat > "${WORK_DIR}/conaninfo-v2.txt" <<'EOF'
[settings]
    arch=x86_64
    build_type=Debug
    compiler=gcc
    compiler.version=12
    os=Linux
[requires]
    zlib/1.2.13
[options]
    shared=True
EOF

PKG1B_FILE_BASE="${RECIPE_BASE}/revisions/${RECIPE_REV}/packages/${PKG_ID_1}/revisions/${PKG_REV_1B}/files"

status=$(curl -s -o /dev/null -w '%{http_code}' -X PUT \
  -H "$(format_auth_header)" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@${WORK_DIR}/conaninfo-v2.txt" \
  "${BASE_URL}${PKG1B_FILE_BASE}/conaninfo.txt") || true

if [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then
  pass
else
  fail "second package revision upload returned HTTP ${status}"
fi

# -----------------------------------------------------------------------
# 12. List package revisions and verify count is 2
# -----------------------------------------------------------------------
begin_test "List package revisions and verify count"

resp=$(curl -sf \
  -H "$(format_auth_header)" \
  "${BASE_URL}${RECIPE_BASE}/revisions/${RECIPE_REV}/packages/${PKG_ID_1}/revisions" 2>/dev/null) || true

if [ -z "$resp" ]; then
  fail "list package revisions returned empty response"
else
  # The Conan v2 API returns {"revisions": [...]} with revision objects.
  count=$(echo "$resp" | jq '
    if .revisions then (.revisions | length)
    elif type == "array" then length
    else 0
    end
  ' 2>/dev/null)

  if [ -z "$count" ] || [ "$count" = "null" ]; then
    fail "could not parse revision count from response: ${resp}"
  elif assert_eq "$count" "2" "expected 2 package revisions, got ${count}"; then
    pass
  fi
fi

# -----------------------------------------------------------------------
# Cleanup: delete the repository
# -----------------------------------------------------------------------
api_delete "/api/v1/repositories/${REPO_KEY}" > /dev/null 2>&1 || true

end_suite
