#!/usr/bin/env bash
# test-conan-recipes.sh - Conan v2 recipe revision management E2E tests
#
# Validates the Conan v2 REST API recipe lifecycle: multi-file uploads per
# revision, latest/revision-list endpoints, multiple revisions of the same
# recipe, user/channel addressing, and conanfile.txt round-trips.

source "$(dirname "$0")/../lib/common.sh"

begin_suite "conan-recipes"
auth_admin
setup_workdir

REPO_KEY="test-conan-recipes-${RUN_ID}"
PKG_NAME="mylib"
PKG_VER="1.0.0"
REV1="$(echo -n 'conanfile-rev1-content' | md5sum | cut -d' ' -f1)"
REV2="$(echo -n 'conanfile-rev2-content' | md5sum | cut -d' ' -f1)"
CONAN_BASE="${BASE_URL}/conan/${REPO_KEY}/v2/conans"

# Helper: upload a file to a specific recipe revision
conan_upload_file() {
  local name="$1" ver="$2" user="$3" channel="$4" rev="$5" filename="$6" filepath="$7"
  curl -s -o /dev/null -w '%{http_code}' -X PUT \
    -H "$(format_auth_header)" \
    -H "Content-Type: application/octet-stream" \
    --data-binary "@${filepath}" \
    $CURL_TIMEOUT \
    "${CONAN_BASE}/${name}/${ver}/${user}/${channel}/revisions/${rev}/files/${filename}"
}

# Helper: download a file from a specific recipe revision
conan_download_file() {
  local name="$1" ver="$2" user="$3" channel="$4" rev="$5" filename="$6" dest="$7"
  curl -sf -o "$dest" -w '%{http_code}' \
    -H "$(format_auth_header)" \
    $CURL_TIMEOUT \
    "${CONAN_BASE}/${name}/${ver}/${user}/${channel}/revisions/${rev}/files/${filename}" 2>/dev/null
}

# ---------------------------------------------------------------------------
# 1. Create local Conan repository
# ---------------------------------------------------------------------------
begin_test "Create local Conan repository"
if create_local_repo "$REPO_KEY" "conan"; then
  pass
else
  fail "could not create conan repository"
fi

# ---------------------------------------------------------------------------
# 2. Upload conanfile.py for mylib/1.0.0 (revision 1)
# ---------------------------------------------------------------------------
begin_test "Upload conanfile.py for mylib/1.0.0 revision 1"

cat > "${WORK_DIR}/conanfile_v1.py" <<'PYEOF'
from conan import ConanFile

class MyLibConan(ConanFile):
    name = "mylib"
    version = "1.0.0"
    license = "Apache-2.0"
    description = "High-performance serialization library"
    settings = "os", "compiler", "build_type", "arch"
    requires = "zlib/1.3.1", "openssl/3.2.1"
    options = {"shared": [True, False], "fPIC": [True, False]}
    default_options = {"shared": False, "fPIC": True}

    def configure(self):
        if self.options.shared:
            self.options.rm_safe("fPIC")
PYEOF

status=$(conan_upload_file "$PKG_NAME" "$PKG_VER" "_" "_" "$REV1" "conanfile.py" "${WORK_DIR}/conanfile_v1.py") || true
if [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then
  pass
else
  fail "conanfile.py upload returned HTTP ${status}"
fi

# ---------------------------------------------------------------------------
# 3. Upload conanmanifest.txt for the same revision
# ---------------------------------------------------------------------------
begin_test "Upload conanmanifest.txt for revision 1"

conanfile_md5=$(md5sum "${WORK_DIR}/conanfile_v1.py" | cut -d' ' -f1)
cat > "${WORK_DIR}/conanmanifest_v1.txt" <<EOF
1713000000
conanfile.py: ${conanfile_md5}
EOF

status=$(conan_upload_file "$PKG_NAME" "$PKG_VER" "_" "_" "$REV1" "conanmanifest.txt" "${WORK_DIR}/conanmanifest_v1.txt") || true
if [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then
  pass
else
  fail "conanmanifest.txt upload returned HTTP ${status}"
fi

# ---------------------------------------------------------------------------
# 4. Upload conan_export.tgz (minimal tarball)
# ---------------------------------------------------------------------------
begin_test "Upload conan_export.tgz for revision 1"

mkdir -p "${WORK_DIR}/export_staging"
cp "${WORK_DIR}/conanmanifest_v1.txt" "${WORK_DIR}/export_staging/conanmanifest.txt"
tar czf "${WORK_DIR}/conan_export_v1.tgz" -C "${WORK_DIR}/export_staging" conanmanifest.txt

status=$(conan_upload_file "$PKG_NAME" "$PKG_VER" "_" "_" "$REV1" "conan_export.tgz" "${WORK_DIR}/conan_export_v1.tgz") || true
if [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then
  pass
else
  fail "conan_export.tgz upload returned HTTP ${status}"
fi

# ---------------------------------------------------------------------------
# 5. Verify latest revision endpoint returns the correct revision hash
# ---------------------------------------------------------------------------
begin_test "Latest revision returns revision 1 hash"

latest_resp=$(curl -sf \
  -H "$(format_auth_header)" \
  $CURL_TIMEOUT \
  "${CONAN_BASE}/${PKG_NAME}/${PKG_VER}/_/_/latest") || true

if [ -z "$latest_resp" ]; then
  fail "latest revision returned empty response"
else
  latest_rev=$(echo "$latest_resp" | jq -r '.revision // empty')
  if assert_eq "$latest_rev" "$REV1" "expected latest revision to be ${REV1}, got ${latest_rev}"; then
    pass
  fi
fi

# ---------------------------------------------------------------------------
# 6. Download conanfile.py and verify content matches
# ---------------------------------------------------------------------------
begin_test "Download conanfile.py and verify content"

dl_status=$(conan_download_file "$PKG_NAME" "$PKG_VER" "_" "_" "$REV1" "conanfile.py" "${WORK_DIR}/dl_conanfile.py") || true

if [ "$dl_status" = "200" ] && [ -s "${WORK_DIR}/dl_conanfile.py" ]; then
  original=$(cat "${WORK_DIR}/conanfile_v1.py")
  downloaded=$(cat "${WORK_DIR}/dl_conanfile.py")
  if assert_eq "$downloaded" "$original" "downloaded conanfile.py does not match uploaded content"; then
    pass
  fi
else
  fail "conanfile.py download failed with HTTP ${dl_status}"
fi

# ---------------------------------------------------------------------------
# 7. Download conanmanifest.txt and verify content
# ---------------------------------------------------------------------------
begin_test "Download conanmanifest.txt and verify content"

dl_status=$(conan_download_file "$PKG_NAME" "$PKG_VER" "_" "_" "$REV1" "conanmanifest.txt" "${WORK_DIR}/dl_manifest.txt") || true

if [ "$dl_status" = "200" ] && [ -s "${WORK_DIR}/dl_manifest.txt" ]; then
  if assert_contains "$(cat "${WORK_DIR}/dl_manifest.txt")" "$conanfile_md5" "manifest missing conanfile.py hash"; then
    pass
  fi
else
  fail "conanmanifest.txt download failed with HTTP ${dl_status}"
fi

# ---------------------------------------------------------------------------
# 8. List recipe revisions and verify count
# ---------------------------------------------------------------------------
begin_test "List recipe revisions shows one revision"

revisions_resp=$(curl -sf \
  -H "$(format_auth_header)" \
  $CURL_TIMEOUT \
  "${CONAN_BASE}/${PKG_NAME}/${PKG_VER}/_/_/revisions") || true

if [ -z "$revisions_resp" ]; then
  fail "revisions endpoint returned empty response"
else
  rev_count=$(echo "$revisions_resp" | jq '.revisions | length')
  if assert_eq "$rev_count" "1" "expected 1 revision, got ${rev_count}"; then
    first_rev=$(echo "$revisions_resp" | jq -r '.revisions[0].revision')
    if assert_eq "$first_rev" "$REV1" "first revision hash mismatch"; then
      pass
    fi
  fi
fi

# ---------------------------------------------------------------------------
# 9. Upload a second revision of the same recipe (different content, different hash)
# ---------------------------------------------------------------------------
begin_test "Upload second revision of mylib/1.0.0"

cat > "${WORK_DIR}/conanfile_v1r2.py" <<'PYEOF'
from conan import ConanFile

class MyLibConan(ConanFile):
    name = "mylib"
    version = "1.0.0"
    license = "Apache-2.0"
    description = "High-performance serialization library with SIMD support"
    settings = "os", "compiler", "build_type", "arch"
    requires = "zlib/1.3.1", "openssl/3.2.1", "boost/1.84.0"
    options = {"shared": [True, False], "fPIC": [True, False], "with_simd": [True, False]}
    default_options = {"shared": False, "fPIC": True, "with_simd": True}

    def configure(self):
        if self.options.shared:
            self.options.rm_safe("fPIC")

    def build_requirements(self):
        self.tool_requires("cmake/3.28.1")
PYEOF

status=$(conan_upload_file "$PKG_NAME" "$PKG_VER" "_" "_" "$REV2" "conanfile.py" "${WORK_DIR}/conanfile_v1r2.py") || true
if [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then
  # Also upload manifest for revision 2
  r2_md5=$(md5sum "${WORK_DIR}/conanfile_v1r2.py" | cut -d' ' -f1)
  cat > "${WORK_DIR}/conanmanifest_v1r2.txt" <<EOF
1713100000
conanfile.py: ${r2_md5}
EOF
  m_status=$(conan_upload_file "$PKG_NAME" "$PKG_VER" "_" "_" "$REV2" "conanmanifest.txt" "${WORK_DIR}/conanmanifest_v1r2.txt") || true
  if [ "$m_status" -ge 200 ] 2>/dev/null && [ "$m_status" -lt 300 ] 2>/dev/null; then
    pass
  else
    fail "revision 2 manifest upload returned HTTP ${m_status}"
  fi
else
  fail "revision 2 conanfile.py upload returned HTTP ${status}"
fi

# ---------------------------------------------------------------------------
# 10. Verify latest now returns the second revision
# ---------------------------------------------------------------------------
begin_test "Latest revision returns revision 2 after second upload"

latest_resp=$(curl -sf \
  -H "$(format_auth_header)" \
  $CURL_TIMEOUT \
  "${CONAN_BASE}/${PKG_NAME}/${PKG_VER}/_/_/latest") || true

if [ -z "$latest_resp" ]; then
  fail "latest revision returned empty response"
else
  latest_rev=$(echo "$latest_resp" | jq -r '.revision // empty')
  if assert_eq "$latest_rev" "$REV2" "expected latest revision to be ${REV2}, got ${latest_rev}"; then
    pass
  fi
fi

# ---------------------------------------------------------------------------
# 11. Verify revisions list shows both revisions
# ---------------------------------------------------------------------------
begin_test "Revisions list shows both revisions"

revisions_resp=$(curl -sf \
  -H "$(format_auth_header)" \
  $CURL_TIMEOUT \
  "${CONAN_BASE}/${PKG_NAME}/${PKG_VER}/_/_/revisions") || true

if [ -z "$revisions_resp" ]; then
  fail "revisions endpoint returned empty response"
else
  rev_count=$(echo "$revisions_resp" | jq '.revisions | length')
  if assert_eq "$rev_count" "2" "expected 2 revisions, got ${rev_count}"; then
    # Verify both revision hashes are present
    has_rev1=$(echo "$revisions_resp" | jq --arg r "$REV1" '[.revisions[].revision] | index($r) != null')
    has_rev2=$(echo "$revisions_resp" | jq --arg r "$REV2" '[.revisions[].revision] | index($r) != null')
    if [ "$has_rev1" = "true" ] && [ "$has_rev2" = "true" ]; then
      pass
    else
      fail "revisions list missing one or both hashes (has_rev1=${has_rev1}, has_rev2=${has_rev2})"
    fi
  fi
fi

# ---------------------------------------------------------------------------
# 12. Upload recipe with user/channel (mylib/1.0.0@myuser/stable)
# ---------------------------------------------------------------------------
begin_test "Upload recipe with user/channel (myuser/stable)"

cat > "${WORK_DIR}/conanfile_uc.py" <<'PYEOF'
from conan import ConanFile

class MyLibConan(ConanFile):
    name = "mylib"
    version = "1.0.0"
    license = "Apache-2.0"
    description = "Serialization library - user channel build"
    settings = "os", "compiler", "build_type", "arch"
    requires = "zlib/1.3.1"
PYEOF

UC_REV="$(echo -n 'user-channel-rev-content' | md5sum | cut -d' ' -f1)"

status=$(conan_upload_file "$PKG_NAME" "$PKG_VER" "myuser" "stable" "$UC_REV" "conanfile.py" "${WORK_DIR}/conanfile_uc.py") || true
if [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then
  pass
else
  fail "user/channel recipe upload returned HTTP ${status}"
fi

# ---------------------------------------------------------------------------
# 13. Verify user/channel recipe can be fetched independently
# ---------------------------------------------------------------------------
begin_test "Fetch user/channel recipe independently from default"

# Fetch latest for user/channel recipe
uc_latest=$(curl -sf \
  -H "$(format_auth_header)" \
  $CURL_TIMEOUT \
  "${CONAN_BASE}/${PKG_NAME}/${PKG_VER}/myuser/stable/latest") || true

if [ -z "$uc_latest" ]; then
  fail "user/channel latest revision returned empty response"
else
  uc_rev=$(echo "$uc_latest" | jq -r '.revision // empty')
  if assert_eq "$uc_rev" "$UC_REV" "user/channel latest revision mismatch"; then
    # Also verify the default (_/_) latest was not affected
    default_latest=$(curl -sf \
      -H "$(format_auth_header)" \
      $CURL_TIMEOUT \
      "${CONAN_BASE}/${PKG_NAME}/${PKG_VER}/_/_/latest") || true
    default_rev=$(echo "$default_latest" | jq -r '.revision // empty')
    if assert_eq "$default_rev" "$REV2" "default latest should still be REV2, got ${default_rev}"; then
      pass
    fi
  fi
fi

# ---------------------------------------------------------------------------
# 14. Upload recipe with conanfile.txt (not .py) and verify round-trip
# ---------------------------------------------------------------------------
begin_test "Upload and download conanfile.txt recipe"

cat > "${WORK_DIR}/conanfile.txt" <<'TXTEOF'
[requires]
zlib/1.3.1
openssl/3.2.1
boost/1.84.0

[generators]
CMakeDeps
CMakeToolchain

[options]
zlib/*:shared=False
TXTEOF

TXT_REV="$(echo -n 'conanfile-txt-rev-content' | md5sum | cut -d' ' -f1)"
TXT_PKG="txtconsumer"

# Upload conanfile.txt
status=$(conan_upload_file "$TXT_PKG" "1.0.0" "_" "_" "$TXT_REV" "conanfile.txt" "${WORK_DIR}/conanfile.txt") || true
if [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then
  # Download and verify round-trip
  dl_status=$(conan_download_file "$TXT_PKG" "1.0.0" "_" "_" "$TXT_REV" "conanfile.txt" "${WORK_DIR}/dl_conanfile.txt") || true
  if [ "$dl_status" = "200" ] && [ -s "${WORK_DIR}/dl_conanfile.txt" ]; then
    original=$(cat "${WORK_DIR}/conanfile.txt")
    downloaded=$(cat "${WORK_DIR}/dl_conanfile.txt")
    if assert_eq "$downloaded" "$original" "downloaded conanfile.txt does not match uploaded content"; then
      pass
    fi
  else
    fail "conanfile.txt download failed with HTTP ${dl_status}"
  fi
else
  fail "conanfile.txt upload returned HTTP ${status}"
fi

# ---------------------------------------------------------------------------
# Cleanup: delete the test repository
# ---------------------------------------------------------------------------
if api_delete "/api/v1/repositories/${REPO_KEY}" > /dev/null 2>&1; then
  echo "  Cleaned up repository ${REPO_KEY}"
else
  echo "  Warning: could not delete repository ${REPO_KEY}"
fi

end_suite
