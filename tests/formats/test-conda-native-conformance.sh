#!/usr/bin/env bash
# test-conda-native-conformance.sh - Conda native (.conda) format conformance tests
#
# Validates the Conda repository with the newer .conda (ZIP-based v2) package
# format, as opposed to the legacy .tar.bz2 format tested in test-conda-conformance.sh.
# The .conda format uses a ZIP container with metadata/ and pkg/ inner archives.
#
# Endpoints: ${BASE_URL}/conda/{repo_key}/
#
# Requires: curl, jq, zip
source "$(dirname "$0")/../lib/common.sh"

begin_suite "conda-native-conformance"
auth_admin
setup_workdir
require_cmd zip

REPO_KEY="test-conda-native-${RUN_ID}"
SUBDIR="linux-64"
PKG_NAME="nativetest"
PKG_VERSION="1.0.0"
PKG_BUILD="py312h0_0"
PKG_NAME_2="nativeutil"
PKG_VERSION_2="2.3.1"
PKG_BUILD_2="h1234abc_1"
CONDA_URL="${BASE_URL}/conda/${REPO_KEY}"

# Portable SHA256 helper
sha256_hex() {
  if command -v sha256sum &>/dev/null; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

# ---------------------------------------------------------------------------
# Helper: build a minimal .conda package (ZIP-based v2 format)
#
# The .conda format is a ZIP archive containing:
#   - metadata.json (top-level package metadata)
#   - info-<name>-<version>-<build>.tar.zst (or .tar.bz2): package info
#   - pkg-<name>-<version>-<build>.tar.zst (or .tar.bz2): package content
#
# For a minimal test package we create a valid ZIP with the metadata.json
# and small info/pkg inner archives using plain tar (the server validates
# the .conda extension but not necessarily the inner compression).
# ---------------------------------------------------------------------------

build_conda_native_pkg() {
  local name="$1"
  local version="$2"
  local build="$3"
  local subdir="$4"
  local outfile="$5"

  local build_dir="${WORK_DIR}/conda-native-${name}-${version}"
  mkdir -p "${build_dir}"

  # Create metadata.json (top-level in the .conda ZIP)
  cat > "${build_dir}/metadata.json" <<EOJSON
{
  "conda_pkg_format": 2,
  "name": "${name}",
  "version": "${version}",
  "build": "${build}",
  "subdir": "${subdir}"
}
EOJSON

  # Create a minimal info directory and tar it
  local info_dir="${build_dir}/info-content/info"
  mkdir -p "${info_dir}"

  cat > "${info_dir}/index.json" <<EOJSON
{
  "name": "${name}",
  "version": "${version}",
  "build": "${build}",
  "build_number": 0,
  "depends": [],
  "subdir": "${subdir}",
  "arch": "x86_64",
  "platform": "linux"
}
EOJSON

  cat > "${info_dir}/paths.json" <<EOJSON
{
  "paths": []
}
EOJSON

  # Tar the info directory (use plain tar for portability)
  (cd "${build_dir}/info-content" && tar cf "${build_dir}/info-${name}-${version}-${build}.tar" info/)

  # Create a minimal pkg directory and tar it
  local pkg_dir="${build_dir}/pkg-content/lib"
  mkdir -p "${pkg_dir}"
  echo "placeholder" > "${pkg_dir}/${name}.txt"
  (cd "${build_dir}/pkg-content" && tar cf "${build_dir}/pkg-${name}-${version}-${build}.tar" lib/)

  # Package everything into a .conda ZIP
  (cd "${build_dir}" && zip -q "${outfile}" \
    metadata.json \
    "info-${name}-${version}-${build}.tar" \
    "pkg-${name}-${version}-${build}.tar")
}

# ---------------------------------------------------------------------------
# Create repository
# ---------------------------------------------------------------------------

begin_test "Create conda local repository"
if create_local_repo "$REPO_KEY" "conda"; then
  pass
else
  fail "could not create conda repository"
fi

# ---------------------------------------------------------------------------
# 1. Upload a .conda package (ZIP-based v2 format)
# ---------------------------------------------------------------------------

begin_test "Upload .conda package via PUT"
CONDA_FILENAME="${PKG_NAME}-${PKG_VERSION}-${PKG_BUILD}.conda"
CONDA_FILE="${WORK_DIR}/${CONDA_FILENAME}"
build_conda_native_pkg "$PKG_NAME" "$PKG_VERSION" "$PKG_BUILD" "$SUBDIR" "$CONDA_FILE"

upload_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X PUT \
  -H "$(format_auth_header)" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@${CONDA_FILE}" \
  "${CONDA_URL}/${SUBDIR}/${CONDA_FILENAME}") || true

if [ "$upload_status" -ge 200 ] 2>/dev/null && [ "$upload_status" -lt 300 ] 2>/dev/null; then
  pass
else
  # Fallback: try POST /upload with headers
  upload_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X POST \
    -H "$(format_auth_header)" \
    -H "Content-Type: application/octet-stream" \
    -H "X-Conda-Subdir: ${SUBDIR}" \
    -H "X-Package-Filename: ${CONDA_FILENAME}" \
    --data-binary "@${CONDA_FILE}" \
    "${CONDA_URL}/upload") || true
  if [ "$upload_status" -ge 200 ] 2>/dev/null && [ "$upload_status" -lt 300 ] 2>/dev/null; then
    pass
  else
    fail ".conda package upload failed (HTTP ${upload_status})"
  fi
fi

sleep 1

# ---------------------------------------------------------------------------
# 2. GET repodata.json contains the .conda package
# ---------------------------------------------------------------------------

begin_test "repodata.json contains uploaded .conda package"
if resp=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${CONDA_URL}/${SUBDIR}/repodata.json" 2>/dev/null); then
  # The .conda package may appear in "packages.conda" or "packages" depending
  # on the server implementation
  found_in_conda=$(echo "$resp" | jq --arg f "$CONDA_FILENAME" \
    '.["packages.conda"][$f] != null' 2>/dev/null) || true
  found_in_packages=$(echo "$resp" | jq --arg f "$CONDA_FILENAME" \
    '.packages[$f] != null' 2>/dev/null) || true
  found_by_name=$(echo "$resp" | jq --arg n "$PKG_NAME" \
    '[(.packages // {}), (.["packages.conda"] // {}) | to_entries[] | select(.value.name == $n)] | length > 0' \
    2>/dev/null) || true

  if [ "$found_in_conda" = "true" ] || [ "$found_in_packages" = "true" ] || [ "$found_by_name" = "true" ]; then
    pass
  else
    # Accept if repodata has any packages (may be keyed differently)
    pkg_count=$(echo "$resp" | jq \
      '(.packages // {} | length) + (.["packages.conda"] // {} | length)' \
      2>/dev/null) || pkg_count=0
    if [ "$pkg_count" -ge 1 ] 2>/dev/null; then
      echo "  note: package found in repodata but keyed differently than expected"
      pass
    else
      fail "repodata.json has no packages after upload"
    fi
  fi
else
  fail "GET ${SUBDIR}/repodata.json returned error"
fi

# ---------------------------------------------------------------------------
# 3. Download the .conda file
# ---------------------------------------------------------------------------

begin_test "Download .conda package by subdir path"
DL_FILE="${WORK_DIR}/downloaded.conda"
dl_status=$(curl -s -o "$DL_FILE" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  "${CONDA_URL}/${SUBDIR}/${CONDA_FILENAME}") || true

if [ "$dl_status" -ge 200 ] 2>/dev/null && [ "$dl_status" -lt 300 ] 2>/dev/null; then
  if [ -s "$DL_FILE" ]; then
    pass
  else
    fail "downloaded .conda package is empty"
  fi
else
  fail ".conda package download returned HTTP ${dl_status}"
fi

# ---------------------------------------------------------------------------
# 4. Download integrity (SHA256 of uploaded matches downloaded)
# ---------------------------------------------------------------------------

begin_test "Download integrity (SHA256 matches uploaded file)"
if [ -s "$DL_FILE" ] && [ -s "$CONDA_FILE" ]; then
  upload_sha=$(sha256_hex "$CONDA_FILE")
  download_sha=$(sha256_hex "$DL_FILE")
  if assert_eq "$download_sha" "$upload_sha" \
    "SHA256 mismatch: uploaded=${upload_sha} downloaded=${download_sha}"; then
    pass
  fi
else
  skip "uploaded or downloaded file missing for integrity check"
fi

# ---------------------------------------------------------------------------
# 5. Multiple .conda packages in repodata
# ---------------------------------------------------------------------------

begin_test "Multiple .conda packages listed in repodata.json"
CONDA_FILENAME_2="${PKG_NAME_2}-${PKG_VERSION_2}-${PKG_BUILD_2}.conda"
CONDA_FILE_2="${WORK_DIR}/${CONDA_FILENAME_2}"
build_conda_native_pkg "$PKG_NAME_2" "$PKG_VERSION_2" "$PKG_BUILD_2" "$SUBDIR" "$CONDA_FILE_2"

upload2_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X PUT \
  -H "$(format_auth_header)" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@${CONDA_FILE_2}" \
  "${CONDA_URL}/${SUBDIR}/${CONDA_FILENAME_2}") || true

if [ "$upload2_status" -ge 200 ] 2>/dev/null && [ "$upload2_status" -lt 300 ] 2>/dev/null; then
  sleep 1
  if resp=$(curl -sf $CURL_TIMEOUT \
      -H "$(format_auth_header)" \
      "${CONDA_URL}/${SUBDIR}/repodata.json" 2>/dev/null); then
    total=$(echo "$resp" | jq \
      '(.packages // {} | length) + (.["packages.conda"] // {} | length)' \
      2>/dev/null) || total=0
    if [ "$total" -ge 2 ] 2>/dev/null; then
      pass
    else
      fail "repodata.json lists ${total} package(s) after two uploads, expected >= 2"
    fi
  else
    fail "could not fetch repodata.json after second upload"
  fi
else
  # Fallback: try POST /upload
  upload2_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X POST \
    -H "$(format_auth_header)" \
    -H "Content-Type: application/octet-stream" \
    -H "X-Conda-Subdir: ${SUBDIR}" \
    -H "X-Package-Filename: ${CONDA_FILENAME_2}" \
    --data-binary "@${CONDA_FILE_2}" \
    "${CONDA_URL}/upload") || true
  if [ "$upload2_status" -ge 200 ] 2>/dev/null && [ "$upload2_status" -lt 300 ] 2>/dev/null; then
    sleep 1
    if resp=$(curl -sf $CURL_TIMEOUT \
        -H "$(format_auth_header)" \
        "${CONDA_URL}/${SUBDIR}/repodata.json" 2>/dev/null); then
      total=$(echo "$resp" | jq \
        '(.packages // {} | length) + (.["packages.conda"] // {} | length)' \
        2>/dev/null) || total=0
      if [ "$total" -ge 2 ] 2>/dev/null; then
        pass
      else
        fail "repodata.json lists ${total} package(s) after two uploads, expected >= 2"
      fi
    else
      fail "could not fetch repodata.json after second upload"
    fi
  else
    fail "second .conda upload returned HTTP ${upload2_status}"
  fi
fi

# ---------------------------------------------------------------------------
# 6. 404 for nonexistent .conda package
# ---------------------------------------------------------------------------

begin_test "404 for nonexistent .conda package"
status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  "${CONDA_URL}/${SUBDIR}/nonexistent-${RUN_ID}-0.0.0-0.conda") || true
if assert_eq "$status" "404" "expected 404 for nonexistent .conda package, got ${status}"; then
  pass
fi

end_suite
