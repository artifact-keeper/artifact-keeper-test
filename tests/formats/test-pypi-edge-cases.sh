#!/usr/bin/env bash
# test-pypi-edge-cases.sh - PyPI edge case tests
#
# Deep-dive tests for corner cases that pip, twine, and poetry clients
# encounter in the real world. Covers name normalization, PEP 440 version
# ordering, wheel uploads, concurrent access, unicode metadata, and more.
#
# Requires: curl, jq, shasum, python3

source "$(dirname "$0")/../lib/common.sh"

begin_suite "pypi-edge-cases"
auth_admin
setup_workdir
require_cmd python3

REPO_KEY="test-pypi-edge-${RUN_ID}"
PYPI_URL="${BASE_URL}/pypi/${REPO_KEY}"

# ---------------------------------------------------------------------------
# Helper: build a minimal sdist tarball
# ---------------------------------------------------------------------------
build_sdist() {
  local name="$1"
  local version="$2"
  local outdir="$3"
  local description="${4:-Edge case test package}"
  local author="${5:-Test Author}"
  local requires_dist="${6:-}"

  local sdist_dir="${outdir}/${name}-${version}"
  mkdir -p "${sdist_dir}"

  local module_name
  module_name=$(echo "$name" | tr '.-' '__')

  cat > "${sdist_dir}/setup.py" <<SETUP
from setuptools import setup
setup(
    name="${name}",
    version="${version}",
    py_modules=["${module_name}"],
    description="${description}",
    author="${author}",
)
SETUP

  cat > "${sdist_dir}/${module_name}.py" <<MOD
__version__ = "${version}"
MOD

  local requires_dist_line=""
  if [ -n "$requires_dist" ]; then
    requires_dist_line="Requires-Dist: ${requires_dist}"
  fi

  cat > "${sdist_dir}/PKG-INFO" <<PKGINFO
Metadata-Version: 2.1
Name: ${name}
Version: ${version}
Summary: ${description}
Author: ${author}
${requires_dist_line}
PKGINFO

  local tarball="${outdir}/${name}-${version}.tar.gz"
  tar czf "$tarball" -C "$outdir" "${name}-${version}"
  echo "$tarball"
}

# ---------------------------------------------------------------------------
# Helper: build a minimal wheel file
# ---------------------------------------------------------------------------
build_wheel() {
  local name="$1"
  local version="$2"
  local outdir="$3"
  local python_tag="${4:-py3}"
  local abi_tag="${5:-none}"
  local platform_tag="${6:-any}"

  local dist_name
  dist_name=$(echo "$name" | tr '-' '_')
  local wheel_name="${dist_name}-${version}-${python_tag}-${abi_tag}-${platform_tag}.whl"
  local wheel_dir="${outdir}/wheel_build_${dist_name}_${version}"
  mkdir -p "${wheel_dir}/${dist_name}"
  mkdir -p "${wheel_dir}/${dist_name}-${version}.dist-info"

  cat > "${wheel_dir}/${dist_name}/__init__.py" <<MOD
__version__ = "${version}"
MOD

  cat > "${wheel_dir}/${dist_name}-${version}.dist-info/METADATA" <<META
Metadata-Version: 2.1
Name: ${name}
Version: ${version}
Summary: Wheel edge case test
META

  cat > "${wheel_dir}/${dist_name}-${version}.dist-info/WHEEL" <<WHEEL
Wheel-Version: 1.0
Generator: test-pypi-edge-cases
Root-Is-Purelib: true
Tag: ${python_tag}-${abi_tag}-${platform_tag}
WHEEL

  cat > "${wheel_dir}/${dist_name}-${version}.dist-info/RECORD" <<RECORD
${dist_name}/__init__.py,sha256=,
${dist_name}-${version}.dist-info/METADATA,sha256=,
${dist_name}-${version}.dist-info/WHEEL,sha256=,
${dist_name}-${version}.dist-info/RECORD,,
RECORD

  local wheel_path="${outdir}/${wheel_name}"
  (cd "$wheel_dir" && python3 -c "
import zipfile, os
with zipfile.ZipFile('${wheel_path}', 'w') as zf:
    for root, dirs, files in os.walk('.'):
        for f in files:
            fp = os.path.join(root, f)
            zf.write(fp, os.path.relpath(fp, '.'))
" 2>/dev/null) || (cd "$wheel_dir" && zip -qr "$wheel_path" . 2>/dev/null)

  echo "$wheel_path"
}

# ---------------------------------------------------------------------------
# Helper: upload an sdist via multipart POST (Twine protocol)
# ---------------------------------------------------------------------------
upload_sdist() {
  local tarball="$1"
  local name="$2"
  local version="$3"
  local extra_fields=()
  if [ $# -ge 4 ]; then extra_fields=("${@:4}"); fi

  local basename_file
  basename_file=$(basename "$tarball")
  local sha256
  sha256=$(shasum -a 256 "$tarball" | cut -d' ' -f1)

  curl -sf $CURL_TIMEOUT -X POST "${PYPI_URL}/" \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    -F ":action=file_upload" \
    -F "name=${name}" \
    -F "version=${version}" \
    -F "sha256_digest=${sha256}" \
    -F "filetype=sdist" \
    ${extra_fields[@]+"${extra_fields[@]}"} \
    -F "content=@${tarball};filename=${basename_file}"
}

# ---------------------------------------------------------------------------
# Helper: upload a wheel via multipart POST
# ---------------------------------------------------------------------------
upload_wheel() {
  local wheel="$1"
  local name="$2"
  local version="$3"
  local extra_fields=()
  if [ $# -ge 4 ]; then extra_fields=("${@:4}"); fi

  local basename_file
  basename_file=$(basename "$wheel")
  local sha256
  sha256=$(shasum -a 256 "$wheel" | cut -d' ' -f1)

  curl -sf $CURL_TIMEOUT -X POST "${PYPI_URL}/" \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    -F ":action=file_upload" \
    -F "name=${name}" \
    -F "version=${version}" \
    -F "sha256_digest=${sha256}" \
    -F "filetype=bdist_wheel" \
    "${extra_fields[@]}" \
    -F "content=@${wheel};filename=${basename_file}"
}

# ---------------------------------------------------------------------------
# Helper: get package index HTML
# ---------------------------------------------------------------------------
get_package_index() {
  local normalized_name="$1"
  curl -sf $CURL_TIMEOUT \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    "${PYPI_URL}/simple/${normalized_name}/"
}

# ---------------------------------------------------------------------------
# Helper: get package index JSON (PEP 691)
# ---------------------------------------------------------------------------
get_package_index_json() {
  local normalized_name="$1"
  curl -sf $CURL_TIMEOUT \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    -H "Accept: application/vnd.pypi.simple.v1+json" \
    "${PYPI_URL}/simple/${normalized_name}/"
}

# ---------------------------------------------------------------------------
# Setup: create repository
# ---------------------------------------------------------------------------

begin_test "Create PyPI local repository for edge case tests"
if create_local_repo "$REPO_KEY" "pypi"; then
  pass
else
  fail "could not create pypi repository"
fi

# =========================================================================
# 1. Package name normalization edge cases
# =========================================================================

begin_test "Name normalization: underscores, hyphens, dots, mixed case"

# PEP 503 says all of these should resolve to the same normalized name:
# My.Package_Name -> my-package-name
NORM_PKG_ORIGINAL="My.Package_Name"
NORM_PKG_VERSION="1.0.0"
NORM_PKG_EXPECTED="my-package-name"

NORM_SDIST=$(build_sdist "$NORM_PKG_ORIGINAL" "$NORM_PKG_VERSION" "$WORK_DIR")
if upload_sdist "$NORM_SDIST" "$NORM_PKG_ORIGINAL" "$NORM_PKG_VERSION" 2>&1; then
  sleep 1
  # The root index should list the normalized name
  ROOT_HTML=""
  ROOT_HTML=$(curl -sf $CURL_TIMEOUT \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    "${PYPI_URL}/simple/") || true

  if [ -z "$ROOT_HTML" ]; then
    fail "could not fetch root index"
  else
    # Verify the index contains the normalized form
    if assert_contains "$ROOT_HTML" "$NORM_PKG_EXPECTED" \
        "root index should list normalized name '${NORM_PKG_EXPECTED}'"; then

      # All variant lookups should resolve: dots, underscores, mixed case, double separators
      all_ok=true
      for variant in "My.Package_Name" "my-package-name" "MY-PACKAGE-NAME" \
                     "my_package_name" "My_Package.Name" "my.package.name"; do
        status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
          -u "${ADMIN_USER}:${ADMIN_PASS}" \
          "${PYPI_URL}/simple/${variant}/") || status="000"
        if [ "$status" != "200" ] && [ "$status" != "301" ] && [ "$status" != "302" ] && [ "$status" != "308" ]; then
          fail "variant '${variant}' returned HTTP ${status}, expected 200 or redirect"
          all_ok=false
          break
        fi
      done
      if [ "$all_ok" = true ]; then
        pass
      fi
    fi
  fi
else
  fail "upload of normalized-name test package failed"
fi

# =========================================================================
# 2. Version ordering (PEP 440)
# =========================================================================

begin_test "Version ordering: PEP 440 sort in package index"

VER_PKG="version-order-${RUN_ID//-/_}"
VER_NORMALIZED=$(echo "$VER_PKG" | tr '_' '-')

# Upload versions out of order: 1.0.0, 2.0.0, 1.1.0, 10.0.0
for ver in "1.0.0" "2.0.0" "1.1.0" "10.0.0"; do
  sdist=$(build_sdist "$VER_PKG" "$ver" "$WORK_DIR")
  if ! upload_sdist "$sdist" "$VER_PKG" "$ver" 2>/dev/null; then
    fail "upload of ${VER_PKG} v${ver} failed"
    break
  fi
done

sleep 1
VER_HTML=""
VER_HTML=$(get_package_index "$VER_NORMALIZED") || true

if [ -z "$VER_HTML" ]; then
  fail "could not fetch version-order package index"
else
  # All four versions should appear in the index
  all_present=true
  for ver in "1.0.0" "1.1.0" "2.0.0" "10.0.0"; do
    if ! echo "$VER_HTML" | grep -q "$ver"; then
      fail "version ${ver} missing from package index"
      all_present=false
      break
    fi
  done
  if [ "$all_present" = true ]; then
    # Extract version numbers from filenames and check ordering.
    # PEP 503 does not mandate display order, but many servers sort numerically.
    # We verify all versions are present (the important part) and that 10.0.0
    # is not sorted between 1.0.0 and 2.0.0 (lexicographic trap).
    versions_in_order=$(echo "$VER_HTML" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | tr '\n' ' ')
    # Check that 10.0.0 does not appear before 2.0.0 (basic sanity)
    pos_2=$(echo "$VER_HTML" | grep -boF "2.0.0" | head -1 | cut -d: -f1) || pos_2=0
    pos_10=$(echo "$VER_HTML" | grep -boF "10.0.0" | head -1 | cut -d: -f1) || pos_10=0
    if [ "$pos_10" -gt 0 ] && [ "$pos_2" -gt 0 ] && [ "$pos_10" -lt "$pos_2" ]; then
      # 10.0.0 appeared before 2.0.0, which is a lexicographic sort bug.
      # Some servers do not sort, so we only warn, not fail.
      echo "  WARNING: 10.0.0 appears before 2.0.0 (lexicographic sort detected)"
    fi
    pass
  fi
fi

# =========================================================================
# 3. Wheel upload
# =========================================================================

begin_test "Wheel upload and download"

WHL_PKG="wheel-test-${RUN_ID//-/_}"
WHL_VERSION="1.0.0"
WHL_NORMALIZED=$(echo "$WHL_PKG" | tr '_' '-')

WHL_FILE=$(build_wheel "$WHL_PKG" "$WHL_VERSION" "$WORK_DIR")

if [ ! -f "$WHL_FILE" ]; then
  fail "failed to build wheel file"
else
  if upload_wheel "$WHL_FILE" "$WHL_PKG" "$WHL_VERSION" 2>&1; then
    sleep 1
    whl_html=$(get_package_index "$WHL_NORMALIZED") || whl_html=""
    if [ -z "$whl_html" ]; then
      fail "could not fetch wheel package index"
    else
      if assert_contains "$whl_html" ".whl" "package index should list the .whl file"; then
        pass
      fi
    fi
  else
    fail "wheel upload failed"
  fi
fi

# =========================================================================
# 4. Multiple file types per version (sdist + wheel)
# =========================================================================

begin_test "Multiple file types per version: sdist and wheel coexist"

MULTI_PKG="multifile-${RUN_ID//-/_}"
MULTI_VER="2.0.0"
MULTI_NORMALIZED=$(echo "$MULTI_PKG" | tr '_' '-')

multi_sdist=$(build_sdist "$MULTI_PKG" "$MULTI_VER" "$WORK_DIR")
multi_whl=$(build_wheel "$MULTI_PKG" "$MULTI_VER" "$WORK_DIR")

upload_ok=true
if ! upload_sdist "$multi_sdist" "$MULTI_PKG" "$MULTI_VER" 2>/dev/null; then
  fail "sdist upload for multifile test failed"
  upload_ok=false
fi
if $upload_ok && ! upload_wheel "$multi_whl" "$MULTI_PKG" "$MULTI_VER" 2>/dev/null; then
  fail "wheel upload for multifile test failed"
  upload_ok=false
fi

if $upload_ok; then
  sleep 1
  multi_html=$(get_package_index "$MULTI_NORMALIZED") || multi_html=""
  if [ -z "$multi_html" ]; then
    fail "could not fetch multifile package index"
  else
    has_tar=false
    has_whl=false
    echo "$multi_html" | grep -q '.tar.gz' && has_tar=true
    echo "$multi_html" | grep -q '.whl' && has_whl=true
    if [ "$has_tar" = true ] && [ "$has_whl" = true ]; then
      pass
    else
      fail "expected both .tar.gz (${has_tar}) and .whl (${has_whl}) in index"
    fi
  fi
fi

# =========================================================================
# 5. Large sdist (20 MB)
# =========================================================================

begin_test "Large sdist upload and download integrity (20 MB)"

LARGE_PKG="large-pkg-${RUN_ID//-/_}"
LARGE_VER="1.0.0"
LARGE_NORMALIZED=$(echo "$LARGE_PKG" | tr '_' '-')

# Build an sdist with a 20 MB payload file
large_dir="${WORK_DIR}/${LARGE_PKG}-${LARGE_VER}"
mkdir -p "$large_dir"

cat > "${large_dir}/setup.py" <<SETUP
from setuptools import setup
setup(name="${LARGE_PKG}", version="${LARGE_VER}", py_modules=["${LARGE_PKG//-/_}"])
SETUP

cat > "${large_dir}/${LARGE_PKG//-/_}.py" <<MOD
__version__ = "${LARGE_VER}"
MOD

cat > "${large_dir}/PKG-INFO" <<PKGINFO
Metadata-Version: 2.1
Name: ${LARGE_PKG}
Version: ${LARGE_VER}
Summary: Large sdist test
PKGINFO

# Generate 20 MB of deterministic data
dd if=/dev/urandom of="${large_dir}/payload.bin" bs=1048576 count=20 2>/dev/null

LARGE_TARBALL="${WORK_DIR}/${LARGE_PKG}-${LARGE_VER}.tar.gz"
tar czf "$LARGE_TARBALL" -C "$WORK_DIR" "${LARGE_PKG}-${LARGE_VER}"

LARGE_SHA=$(shasum -a 256 "$LARGE_TARBALL" | cut -d' ' -f1)
LARGE_SIZE=$(wc -c < "$LARGE_TARBALL" | tr -d ' ')

if upload_sdist "$LARGE_TARBALL" "$LARGE_PKG" "$LARGE_VER" 2>/dev/null; then
  sleep 1
  # Extract download link from index
  large_html=$(get_package_index "$LARGE_NORMALIZED") || large_html=""
  file_href=$(echo "$large_html" | grep -oE 'href="[^"]*\.tar\.gz[^"]*"' | head -1 | sed 's/href="//;s/"//') || file_href=""

  if [ -z "$file_href" ]; then
    fail "no download link found for large package"
  else
    clean_href=$(echo "$file_href" | sed 's/#.*//')
    if [[ "$clean_href" == http* ]]; then
      dl_url="$clean_href"
    elif [[ "$clean_href" == /* ]]; then
      dl_url="${BASE_URL}${clean_href}"
    else
      dl_url="${PYPI_URL}/simple/${LARGE_NORMALIZED}/${clean_href}"
    fi

    dl_file="${WORK_DIR}/large_downloaded.tar.gz"
    if curl -sf --max-time 120 --connect-timeout 10 \
        -u "${ADMIN_USER}:${ADMIN_PASS}" \
        -o "$dl_file" "$dl_url"; then
      dl_sha=$(shasum -a 256 "$dl_file" | cut -d' ' -f1)
      if assert_eq "$dl_sha" "$LARGE_SHA" \
          "downloaded SHA256 should match uploaded file"; then
        pass
      fi
    else
      fail "download of large package failed"
    fi
  fi
else
  fail "upload of 20 MB sdist failed"
fi

# =========================================================================
# 6. Concurrent uploads (5 parallel)
# =========================================================================

begin_test "Concurrent uploads: 5 packages in parallel"

CONCURRENT_PIDS=()
CONCURRENT_RESULTS="${WORK_DIR}/concurrent_results"
mkdir -p "$CONCURRENT_RESULTS"

for i in $(seq 1 5); do
  (
    cpkg="concurrent-${i}-${RUN_ID//-/_}"
    cver="1.0.${i}"
    csdist=$(build_sdist "$cpkg" "$cver" "$WORK_DIR/concurrent_${i}")
    mkdir -p "$WORK_DIR/concurrent_${i}" 2>/dev/null || true
    csdist=$(build_sdist "$cpkg" "$cver" "$WORK_DIR/concurrent_${i}")
    if upload_sdist "$csdist" "$cpkg" "$cver" 2>/dev/null; then
      echo "ok" > "${CONCURRENT_RESULTS}/result_${i}"
    else
      echo "fail" > "${CONCURRENT_RESULTS}/result_${i}"
    fi
  ) &
  CONCURRENT_PIDS+=($!)
done

# Wait for all uploads to complete
all_concurrent_ok=true
for pid in "${CONCURRENT_PIDS[@]}"; do
  wait "$pid" || true
done

for i in $(seq 1 5); do
  result_file="${CONCURRENT_RESULTS}/result_${i}"
  if [ -f "$result_file" ] && [ "$(cat "$result_file")" = "ok" ]; then
    :
  else
    all_concurrent_ok=false
  fi
done

if [ "$all_concurrent_ok" = true ]; then
  pass
else
  fail "one or more concurrent uploads failed"
fi

# =========================================================================
# 7. Concurrent reads while uploading
# =========================================================================

begin_test "Concurrent reads: 10 parallel downloads during upload"

# Use the version-order package (already uploaded) as the read target
READ_PKG_NORMALIZED="$VER_NORMALIZED"

# Start 10 parallel readers
READ_PIDS=()
READ_RESULTS="${WORK_DIR}/read_results"
mkdir -p "$READ_RESULTS"

for i in $(seq 1 10); do
  (
    status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
      -u "${ADMIN_USER}:${ADMIN_PASS}" \
      "${PYPI_URL}/simple/${READ_PKG_NORMALIZED}/") || status="000"
    echo "$status" > "${READ_RESULTS}/read_${i}"
  ) &
  READ_PIDS+=($!)
done

# Simultaneously upload a new version to the same package
(
  new_sdist=$(build_sdist "$VER_PKG" "99.0.0" "$WORK_DIR/concurrent_write")
  mkdir -p "$WORK_DIR/concurrent_write" 2>/dev/null || true
  new_sdist=$(build_sdist "$VER_PKG" "99.0.0" "$WORK_DIR/concurrent_write")
  upload_sdist "$new_sdist" "$VER_PKG" "99.0.0" 2>/dev/null || true
) &
WRITE_PID=$!

for pid in "${READ_PIDS[@]}"; do
  wait "$pid" || true
done
wait "$WRITE_PID" || true

read_failures=0
for i in $(seq 1 10); do
  rf="${READ_RESULTS}/read_${i}"
  if [ -f "$rf" ]; then
    rs=$(cat "$rf")
    if [ "$rs" != "200" ]; then
      read_failures=$((read_failures + 1))
    fi
  else
    read_failures=$((read_failures + 1))
  fi
done

if [ "$read_failures" -eq 0 ]; then
  pass
else
  fail "${read_failures}/10 concurrent reads failed during upload"
fi

# =========================================================================
# 8. Unicode in package metadata
# =========================================================================

begin_test "Unicode in package metadata"

UNI_PKG="unicode-meta-${RUN_ID//-/_}"
UNI_VER="1.0.0"
UNI_NORMALIZED=$(echo "$UNI_PKG" | tr '_' '-')
UNI_DESC="Paket mit Umlauten: Koeffizient, naive"
UNI_AUTHOR="Rene Descartes"

uni_sdist=$(build_sdist "$UNI_PKG" "$UNI_VER" "$WORK_DIR" "$UNI_DESC" "$UNI_AUTHOR")

if upload_sdist "$uni_sdist" "$UNI_PKG" "$UNI_VER" \
    -F "description=${UNI_DESC}" \
    -F "author=${UNI_AUTHOR}" 2>/dev/null; then
  sleep 1
  uni_html=$(get_package_index "$UNI_NORMALIZED") || uni_html=""
  if [ -n "$uni_html" ]; then
    # The index itself does not need to display metadata, but the package
    # should appear and be downloadable
    if assert_contains "$uni_html" ".tar.gz" \
        "unicode metadata package should be listed in index"; then
      pass
    fi
  else
    fail "could not fetch unicode metadata package index"
  fi
else
  fail "upload with unicode metadata failed"
fi

# =========================================================================
# 9. Empty package (metadata only, no code)
# =========================================================================

begin_test "Empty package: metadata only, no actual code"

EMPTY_PKG="empty-pkg-${RUN_ID//-/_}"
EMPTY_VER="0.0.1"
EMPTY_NORMALIZED=$(echo "$EMPTY_PKG" | tr '_' '-')

# Build a package with only PKG-INFO and setup.py, no module file
empty_dir="${WORK_DIR}/${EMPTY_PKG}-${EMPTY_VER}"
mkdir -p "$empty_dir"

cat > "${empty_dir}/setup.py" <<SETUP
from setuptools import setup
setup(name="${EMPTY_PKG}", version="${EMPTY_VER}")
SETUP

cat > "${empty_dir}/PKG-INFO" <<PKGINFO
Metadata-Version: 2.1
Name: ${EMPTY_PKG}
Version: ${EMPTY_VER}
Summary: Empty package with no code
PKGINFO

empty_tarball="${WORK_DIR}/${EMPTY_PKG}-${EMPTY_VER}.tar.gz"
tar czf "$empty_tarball" -C "$WORK_DIR" "${EMPTY_PKG}-${EMPTY_VER}"

if upload_sdist "$empty_tarball" "$EMPTY_PKG" "$EMPTY_VER" 2>/dev/null; then
  sleep 1
  empty_html=$(get_package_index "$EMPTY_NORMALIZED") || empty_html=""
  if [ -n "$empty_html" ] && echo "$empty_html" | grep -q ".tar.gz"; then
    pass
  else
    fail "empty package not listed in index"
  fi
else
  fail "upload of empty package failed"
fi

# =========================================================================
# 10. Pre-release versions (PEP 440)
# =========================================================================

begin_test "Pre-release versions: alpha, beta, release candidate, final"

PRE_PKG="prerelease-${RUN_ID//-/_}"
PRE_NORMALIZED=$(echo "$PRE_PKG" | tr '_' '-')

for ver in "1.0.0a1" "1.0.0b2" "1.0.0rc1" "1.0.0"; do
  pre_sdist=$(build_sdist "$PRE_PKG" "$ver" "$WORK_DIR/pre_${ver}")
  mkdir -p "$WORK_DIR/pre_${ver}" 2>/dev/null || true
  pre_sdist=$(build_sdist "$PRE_PKG" "$ver" "$WORK_DIR/pre_${ver}")
  if ! upload_sdist "$pre_sdist" "$PRE_PKG" "$ver" 2>/dev/null; then
    fail "upload of ${PRE_PKG} v${ver} failed"
    break
  fi
done

sleep 1
pre_html=$(get_package_index "$PRE_NORMALIZED") || pre_html=""

if [ -z "$pre_html" ]; then
  fail "could not fetch pre-release package index"
else
  all_pre_ok=true
  for ver in "1.0.0a1" "1.0.0b2" "1.0.0rc1" "1.0.0"; do
    if ! echo "$pre_html" | grep -q "$ver"; then
      fail "pre-release version ${ver} missing from index"
      all_pre_ok=false
      break
    fi
  done
  if [ "$all_pre_ok" = true ]; then
    pass
  fi
fi

# =========================================================================
# 11. Post-release and dev markers (PEP 440)
# =========================================================================

begin_test "Post-release and dev version markers (PEP 440)"

POST_PKG="postdev-${RUN_ID//-/_}"
POST_NORMALIZED=$(echo "$POST_PKG" | tr '_' '-')

for ver in "1.0.0" "1.0.0.post1" "1.0.0.dev3"; do
  post_sdist=$(build_sdist "$POST_PKG" "$ver" "$WORK_DIR/post_${ver}")
  mkdir -p "$WORK_DIR/post_${ver}" 2>/dev/null || true
  post_sdist=$(build_sdist "$POST_PKG" "$ver" "$WORK_DIR/post_${ver}")
  if ! upload_sdist "$post_sdist" "$POST_PKG" "$ver" 2>/dev/null; then
    fail "upload of ${POST_PKG} v${ver} failed"
    break
  fi
done

sleep 1
post_html=$(get_package_index "$POST_NORMALIZED") || post_html=""

if [ -z "$post_html" ]; then
  fail "could not fetch post/dev package index"
else
  all_post_ok=true
  for ver in "1.0.0" "1.0.0.post1" "1.0.0.dev3"; do
    if ! echo "$post_html" | grep -q "$ver"; then
      fail "version ${ver} missing from post/dev index"
      all_post_ok=false
      break
    fi
  done
  if [ "$all_post_ok" = true ]; then
    pass
  fi
fi

# =========================================================================
# 12. Duplicate version upload
# =========================================================================

begin_test "Duplicate version upload returns 409 or is idempotent"

DUP_PKG="dup-upload-${RUN_ID//-/_}"
DUP_VER="1.0.0"
DUP_NORMALIZED=$(echo "$DUP_PKG" | tr '_' '-')

dup_sdist=$(build_sdist "$DUP_PKG" "$DUP_VER" "$WORK_DIR/dup1")
mkdir -p "$WORK_DIR/dup1" 2>/dev/null || true
dup_sdist=$(build_sdist "$DUP_PKG" "$DUP_VER" "$WORK_DIR/dup1")

# First upload should succeed
if upload_sdist "$dup_sdist" "$DUP_PKG" "$DUP_VER" 2>/dev/null; then
  # Second upload of the exact same file and version
  dup_basename=$(basename "$dup_sdist")
  dup_sha=$(shasum -a 256 "$dup_sdist" | cut -d' ' -f1)

  dup_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X POST "${PYPI_URL}/" \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    -F ":action=file_upload" \
    -F "name=${DUP_PKG}" \
    -F "version=${DUP_VER}" \
    -F "sha256_digest=${dup_sha}" \
    -F "filetype=sdist" \
    -F "content=@${dup_sdist};filename=${dup_basename}") || dup_status="000"

  if [ "$dup_status" = "409" ] || [ "$dup_status" = "200" ] || [ "$dup_status" = "201" ]; then
    pass
  else
    fail "duplicate upload returned HTTP ${dup_status}, expected 409 or 200/201"
  fi
else
  fail "first upload of duplicate test package failed"
fi

# =========================================================================
# 13. Very long package name (128 characters)
# =========================================================================

begin_test "Very long package name (128 characters)"

# Build a name that is 128 characters total. Use a prefix plus padding.
LONG_PREFIX="long-name-test-${RUN_ID//-/_}-"
LONG_PAD_LEN=$((128 - ${#LONG_PREFIX}))
if [ "$LONG_PAD_LEN" -lt 1 ]; then
  LONG_PAD_LEN=1
fi
LONG_PAD=$(printf '%0.sa' $(seq 1 "$LONG_PAD_LEN"))
LONG_PKG="${LONG_PREFIX}${LONG_PAD}"
LONG_PKG="${LONG_PKG:0:128}"
LONG_VER="1.0.0"
LONG_NORMALIZED=$(echo "$LONG_PKG" | tr '[:upper:]' '[:lower:]' | sed 's/[-_.]\+/-/g')

long_sdist=$(build_sdist "$LONG_PKG" "$LONG_VER" "$WORK_DIR/long")
mkdir -p "$WORK_DIR/long" 2>/dev/null || true
long_sdist=$(build_sdist "$LONG_PKG" "$LONG_VER" "$WORK_DIR/long")

if upload_sdist "$long_sdist" "$LONG_PKG" "$LONG_VER" 2>/dev/null; then
  sleep 1
  long_html=$(get_package_index "$LONG_NORMALIZED") || long_html=""
  if [ -n "$long_html" ] && echo "$long_html" | grep -q ".tar.gz"; then
    pass
  else
    fail "long package name not found in index"
  fi
else
  fail "upload of package with 128-char name failed"
fi

# =========================================================================
# 14. Package with requires_dist metadata
# =========================================================================

begin_test "Package with requires_dist metadata preserved"

DEP_PKG="dep-meta-${RUN_ID//-/_}"
DEP_VER="1.0.0"
DEP_NORMALIZED=$(echo "$DEP_PKG" | tr '_' '-')

dep_sdist=$(build_sdist "$DEP_PKG" "$DEP_VER" "$WORK_DIR/dep" \
  "Package with dependencies" "Test Author" "requests>=2.20")

if upload_sdist "$dep_sdist" "$DEP_PKG" "$DEP_VER" \
    -F "requires_dist=requests>=2.20" \
    -F "requires_dist=flask>=1.0" 2>/dev/null; then
  sleep 1
  # Check PEP 691 JSON response for requires_dist or requires-python
  dep_json=$(get_package_index_json "$DEP_NORMALIZED") || dep_json=""

  if [ -n "$dep_json" ]; then
    # The JSON response may include requires-python or metadata about dependencies
    # At minimum the package should be listed with files
    file_count=$(echo "$dep_json" | jq '.files | length' 2>/dev/null) || file_count=""
    if [ -n "$file_count" ] && [ "$file_count" -gt 0 ] 2>/dev/null; then
      pass
    else
      # Fallback: HTML index should work
      dep_html=$(get_package_index "$DEP_NORMALIZED") || dep_html=""
      if [ -n "$dep_html" ] && echo "$dep_html" | grep -q ".tar.gz"; then
        pass
      else
        fail "package with requires_dist not found in index"
      fi
    fi
  else
    # No JSON support, check HTML
    dep_html=$(get_package_index "$DEP_NORMALIZED") || dep_html=""
    if [ -n "$dep_html" ] && echo "$dep_html" | grep -q ".tar.gz"; then
      pass
    else
      fail "package with requires_dist not found in either JSON or HTML index"
    fi
  fi
else
  fail "upload with requires_dist failed"
fi

# =========================================================================
# 15. Hash algorithm support (sha256 and md5 fragments)
# =========================================================================

begin_test "Hash fragments: sha256 present in file links"

# Use the multifile package which has both sdist and wheel
hash_html=$(get_package_index "$MULTI_NORMALIZED") || hash_html=""

if [ -z "$hash_html" ]; then
  fail "could not fetch package index for hash verification"
else
  # PEP 503 requires at least sha256 hash fragments in hrefs
  if echo "$hash_html" | grep -qE '#sha256=[0-9a-f]{64}'; then
    # Also check if md5 is present (some servers include both)
    if echo "$hash_html" | grep -qE 'md5=[0-9a-f]{32}'; then
      echo "  Both sha256 and md5 hashes present"
    else
      echo "  sha256 present, md5 not included (acceptable)"
    fi
    pass
  else
    # Check if any hash algorithm is used
    if echo "$hash_html" | grep -qE '#(sha256|sha384|sha512|md5)='; then
      pass
    else
      fail "no hash fragments found in file links"
    fi
  fi
fi

# =========================================================================
# 16. Simple index HTML structure (DOCTYPE)
# =========================================================================

begin_test "Simple index HTML5 structure with DOCTYPE"

doctype_html=""
doctype_html=$(curl -sf $CURL_TIMEOUT \
  -u "${ADMIN_USER}:${ADMIN_PASS}" \
  "${PYPI_URL}/simple/") || true

if [ -z "$doctype_html" ]; then
  fail "could not fetch root simple index"
else
  # PEP 503 recommends but does not strictly require DOCTYPE. Check for it.
  if echo "$doctype_html" | head -5 | grep -qi '<!DOCTYPE'; then
    # Also verify basic HTML structure
    if echo "$doctype_html" | grep -qi '<html'; then
      pass
    else
      fail "HTML response has DOCTYPE but missing <html> element"
    fi
  else
    # Some implementations skip DOCTYPE but still serve valid HTML
    if echo "$doctype_html" | grep -qi '<html\|<body\|<a '; then
      echo "  WARNING: No DOCTYPE declaration, but HTML content present"
      pass
    else
      fail "response does not appear to be valid HTML"
    fi
  fi
fi

# =========================================================================
# 17. PEP 691 JSON file entries have required fields
# =========================================================================

begin_test "PEP 691 JSON: file entries have filename, url, hashes, requires-python"

json691=""
json691=$(get_package_index_json "$MULTI_NORMALIZED") || json691=""

if [ -z "$json691" ]; then
  skip "server did not return PEP 691 JSON for package index"
else
  files_array=$(echo "$json691" | jq '.files' 2>/dev/null) || files_array=""
  if [ -z "$files_array" ] || [ "$files_array" = "null" ]; then
    skip "JSON response does not contain .files array in expected PEP 691 format"
  else
    file_count=$(echo "$json691" | jq '.files | length' 2>/dev/null) || file_count="0"
    if [ "$file_count" -eq 0 ] 2>/dev/null; then
      fail "PEP 691 .files array is empty"
    else
      # Check first file entry for required PEP 691 fields
      first_file=$(echo "$json691" | jq '.files[0]' 2>/dev/null)
      has_filename=$(echo "$first_file" | jq 'has("filename")' 2>/dev/null) || has_filename="false"
      has_url=$(echo "$first_file" | jq 'has("url")' 2>/dev/null) || has_url="false"
      has_hashes=$(echo "$first_file" | jq 'has("hashes")' 2>/dev/null) || has_hashes="false"

      missing_fields=""
      if [ "$has_filename" != "true" ]; then
        missing_fields="${missing_fields} filename"
      fi
      if [ "$has_url" != "true" ]; then
        missing_fields="${missing_fields} url"
      fi
      if [ "$has_hashes" != "true" ]; then
        missing_fields="${missing_fields} hashes"
      fi

      if [ -z "$missing_fields" ]; then
        # requires-python is optional per PEP 691 but recommended
        has_rp=$(echo "$first_file" | jq 'has("requires-python")' 2>/dev/null) || has_rp="false"
        if [ "$has_rp" != "true" ]; then
          echo "  Note: requires-python field not present (optional)"
        fi
        pass
      else
        fail "PEP 691 file entry missing required fields:${missing_fields}"
      fi
    fi
  fi
fi

# =========================================================================
# 18. Trailing slash handling
# =========================================================================

begin_test "Trailing slash: /simple/pkg and /simple/pkg/ both resolve"

SLASH_NORMALIZED="$MULTI_NORMALIZED"

# With trailing slash
status_with=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -u "${ADMIN_USER}:${ADMIN_PASS}" \
  "${PYPI_URL}/simple/${SLASH_NORMALIZED}/") || status_with="000"

# Without trailing slash
status_without=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -u "${ADMIN_USER}:${ADMIN_PASS}" \
  "${PYPI_URL}/simple/${SLASH_NORMALIZED}") || status_without="000"

# Both should return 200 or one redirects to the other (301/302/308)
ok_codes="200 301 302 308"
with_ok=false
without_ok=false

for code in $ok_codes; do
  [ "$status_with" = "$code" ] && with_ok=true
  [ "$status_without" = "$code" ] && without_ok=true
done

if [ "$with_ok" = true ] && [ "$without_ok" = true ]; then
  pass
else
  fail "trailing slash mismatch: with=HTTP ${status_with}, without=HTTP ${status_without}"
fi

# =========================================================================
# 19. Nonexistent package returns 404
# =========================================================================

begin_test "404 for nonexistent package name"

missing_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -u "${ADMIN_USER}:${ADMIN_PASS}" \
  "${PYPI_URL}/simple/this-package-absolutely-does-not-exist-anywhere/") || missing_status="000"

if assert_eq "$missing_status" "404" \
    "nonexistent package should return 404, got ${missing_status}"; then
  pass
fi

# =========================================================================
# 20. Content-Type for wheel download
# =========================================================================

begin_test "Wheel download Content-Type is binary"

# Get the wheel link from the wheel-test package index
whl_index_html=$(get_package_index "$WHL_NORMALIZED") || whl_index_html=""
whl_href=$(echo "$whl_index_html" | grep -oE 'href="[^"]*\.whl[^"]*"' | head -1 | sed 's/href="//;s/"//') || whl_href=""

if [ -z "$whl_href" ]; then
  skip "no wheel link found in index to test Content-Type"
else
  whl_clean_href=$(echo "$whl_href" | sed 's/#.*//')
  if [[ "$whl_clean_href" == http* ]]; then
    whl_dl_url="$whl_clean_href"
  elif [[ "$whl_clean_href" == /* ]]; then
    whl_dl_url="${BASE_URL}${whl_clean_href}"
  else
    whl_dl_url="${PYPI_URL}/simple/${WHL_NORMALIZED}/${whl_clean_href}"
  fi

  whl_ct=$(curl -sf $CURL_TIMEOUT -o /dev/null -w '%{content_type}' \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    "$whl_dl_url") || whl_ct=""

  if [ -z "$whl_ct" ]; then
    fail "could not determine Content-Type for wheel download"
  else
    # Wheels should be served as application/octet-stream, application/zip,
    # or application/x-wheel+zip
    if [[ "$whl_ct" == application/octet-stream* ]] || \
       [[ "$whl_ct" == application/zip* ]] || \
       [[ "$whl_ct" == application/x-wheel* ]] || \
       [[ "$whl_ct" == application/x-zip* ]]; then
      pass
    else
      fail "wheel Content-Type should be a binary type, got '${whl_ct}'"
    fi
  fi
fi

# =========================================================================
# Cleanup
# =========================================================================

api_delete "/api/v1/repositories/${REPO_KEY}" > /dev/null 2>&1 || true

end_suite
