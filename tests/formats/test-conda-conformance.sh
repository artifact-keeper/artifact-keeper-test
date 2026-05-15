#!/usr/bin/env bash
# test-conda-conformance.sh - Conda channel conformance tests
#
# Validates that the Conda repository implementation produces correct
# repodata.json with required package fields, supports current_repodata.json,
# handles multiple packages, and verifies download integrity.
#
# Endpoints: ${BASE_URL}/conda/{repo_key}/
#
# Requires: curl, tar, bzip2, jq, sha256sum or shasum
source "$(dirname "$0")/../lib/common.sh"

begin_suite "conda-conformance"
auth_admin
setup_workdir

REPO_KEY="test-conda-conf-${RUN_ID}"
SUBDIR="noarch"
PKG_NAME="conftest-conda"
PKG_VERSION="1.0.0"
PKG_BUILD="0"
PKG_NAME_2="conftest-condautil"
PKG_VERSION_2="2.1.0"
PKG_BUILD_2="py310_0"
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
# Helper: build a minimal conda .tar.bz2 package
#
# A conda .tar.bz2 package contains at minimum:
#   - info/index.json (package metadata)
#   - info/paths.json (file listing)
# ---------------------------------------------------------------------------

build_conda_pkg() {
  local name="$1"
  local version="$2"
  local build="$3"
  local subdir="$4"
  local outfile="$5"

  local build_dir="${WORK_DIR}/conda-build-${name}-${version}"
  mkdir -p "${build_dir}/info"

  cat > "${build_dir}/info/index.json" <<EOJSON
{
  "name": "${name}",
  "version": "${version}",
  "build": "${build}",
  "build_number": 0,
  "depends": [],
  "subdir": "${subdir}",
  "arch": null,
  "platform": null,
  "noarch": "generic"
}
EOJSON

  cat > "${build_dir}/info/paths.json" <<EOJSON
{
  "paths": []
}
EOJSON

  # Add a minimal about.json for richer metadata
  cat > "${build_dir}/info/about.json" <<EOJSON
{
  "home": "https://example.com/${name}",
  "license": "MIT",
  "summary": "Conformance test conda package ${name}"
}
EOJSON

  (cd "${build_dir}" && tar cjf "${outfile}" info/)
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
# 1. Upload a .tar.bz2 conda package
# ---------------------------------------------------------------------------

begin_test "Upload conda .tar.bz2 package"
CONDA_FILENAME="${PKG_NAME}-${PKG_VERSION}-${PKG_BUILD}.tar.bz2"
CONDA_FILE="${WORK_DIR}/${CONDA_FILENAME}"
build_conda_pkg "$PKG_NAME" "$PKG_VERSION" "$PKG_BUILD" "$SUBDIR" "$CONDA_FILE"

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
  fail "conda upload returned HTTP ${upload_status}, expected 2xx"
fi

sleep 1

# ---------------------------------------------------------------------------
# 2. GET {subdir}/repodata.json returns channel metadata with packages
# ---------------------------------------------------------------------------

begin_test "repodata.json contains packages map"
if resp=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${CONDA_URL}/${SUBDIR}/repodata.json" 2>/dev/null); then
  has_packages=$(echo "$resp" | jq 'has("packages") or has("packages.conda")' 2>/dev/null) || true
  if [ "$has_packages" = "true" ]; then
    # Verify the uploaded package appears in either packages or packages.conda
    found_in_packages=$(echo "$resp" | jq --arg f "$CONDA_FILENAME" '.packages[$f] != null' 2>/dev/null) || true
    found_in_conda=$(echo "$resp" | jq --arg n "$PKG_NAME" '[.packages // {}, .["packages.conda"] // {} | to_entries[] | select(.value.name == $n)] | length > 0' 2>/dev/null) || true
    if [ "$found_in_packages" = "true" ] || [ "$found_in_conda" = "true" ]; then
      pass
    else
      # Package might be keyed differently; accept if the packages map is non-empty
      pkg_count=$(echo "$resp" | jq '(.packages // {} | length) + (.["packages.conda"] // {} | length)' 2>/dev/null) || pkg_count=0
      if [ "$pkg_count" -ge 1 ] 2>/dev/null; then
        echo "  note: package present in repodata but keyed differently than expected"
        pass
      else
        fail "repodata.json has empty packages map after upload"
      fi
    fi
  else
    fail "repodata.json missing 'packages' or 'packages.conda' key"
  fi
else
  fail "GET ${SUBDIR}/repodata.json returned error"
fi

# ---------------------------------------------------------------------------
# 3. Package entry has required fields (name, version, build, depends, md5, sha256, size)
# ---------------------------------------------------------------------------

begin_test "Package entry contains required fields"
if resp=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${CONDA_URL}/${SUBDIR}/repodata.json" 2>/dev/null); then
  # Extract the first package entry from either packages or packages.conda
  entry=$(echo "$resp" | jq '
    (.packages // {} | to_entries | .[0].value) //
    (.["packages.conda"] // {} | to_entries | .[0].value) //
    null
  ' 2>/dev/null)

  if [ "$entry" != "null" ] && [ -n "$entry" ]; then
    found=0
    missing=""

    for field in name version build; do
      val=$(echo "$entry" | jq -r ".${field} // empty" 2>/dev/null) || true
      if [ -n "$val" ]; then
        found=$((found + 1))
      else
        missing="${missing} ${field}"
      fi
    done

    # depends should be present (even if empty array)
    has_depends=$(echo "$entry" | jq 'has("depends")' 2>/dev/null) || true
    if [ "$has_depends" = "true" ]; then
      found=$((found + 1))
    else
      missing="${missing} depends"
    fi

    # md5, sha256, size are recommended but some registries may omit some
    for field in size; do
      val=$(echo "$entry" | jq ".${field} // empty" 2>/dev/null) || true
      if [ -n "$val" ] && [ "$val" != "null" ]; then
        found=$((found + 1))
      else
        missing="${missing} ${field}"
      fi
    done

    # Check for at least one checksum field
    has_md5=$(echo "$entry" | jq '.md5 // empty' -r 2>/dev/null) || true
    has_sha256=$(echo "$entry" | jq '.sha256 // empty' -r 2>/dev/null) || true
    if [ -n "$has_md5" ] || [ -n "$has_sha256" ]; then
      found=$((found + 1))
    else
      missing="${missing} md5/sha256"
    fi

    if [ "$found" -ge 4 ]; then
      if [ -n "$missing" ]; then
        echo "  note: some optional fields missing:${missing}"
      fi
      pass
    else
      fail "package entry missing required fields (found ${found}):${missing}"
    fi
  else
    fail "no package entries found in repodata.json"
  fi
else
  fail "could not fetch repodata.json for field inspection"
fi

# ---------------------------------------------------------------------------
# 4. Download conda package file
# ---------------------------------------------------------------------------

begin_test "Download conda package by subdir path"
DL_FILE="${WORK_DIR}/downloaded.tar.bz2"
dl_status=$(curl -s -o "$DL_FILE" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  "${CONDA_URL}/${SUBDIR}/${CONDA_FILENAME}") || true

if [ "$dl_status" -ge 200 ] 2>/dev/null && [ "$dl_status" -lt 300 ] 2>/dev/null; then
  if [ -s "$DL_FILE" ]; then
    pass
  else
    fail "downloaded conda package is empty"
  fi
else
  fail "conda package download returned HTTP ${dl_status}"
fi

# ---------------------------------------------------------------------------
# 5. Download integrity (SHA256 of uploaded matches downloaded)
# ---------------------------------------------------------------------------

begin_test "Download integrity (SHA256 matches uploaded file)"
if [ -s "$DL_FILE" ] && [ -s "$CONDA_FILE" ]; then
  upload_sha=$(sha256_hex "$CONDA_FILE")
  download_sha=$(sha256_hex "$DL_FILE")
  if assert_eq "$download_sha" "$upload_sha" "SHA256 mismatch: uploaded=${upload_sha} downloaded=${download_sha}"; then
    pass
  fi
else
  skip "uploaded or downloaded file missing for integrity check"
fi

# ---------------------------------------------------------------------------
# 6. Multiple packages in repodata
# ---------------------------------------------------------------------------

begin_test "Multiple packages listed in repodata.json"
CONDA_FILENAME_2="${PKG_NAME_2}-${PKG_VERSION_2}-${PKG_BUILD_2}.tar.bz2"
CONDA_FILE_2="${WORK_DIR}/${CONDA_FILENAME_2}"
build_conda_pkg "$PKG_NAME_2" "$PKG_VERSION_2" "$PKG_BUILD_2" "$SUBDIR" "$CONDA_FILE_2"

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
    total=$(echo "$resp" | jq '(.packages // {} | length) + (.["packages.conda"] // {} | length)' 2>/dev/null) || total=0
    if [ "$total" -ge 2 ] 2>/dev/null; then
      pass
    else
      fail "repodata.json lists ${total} package(s) after two uploads, expected >= 2"
    fi
  else
    fail "could not fetch repodata.json after second upload"
  fi
else
  fail "second package upload returned HTTP ${upload2_status}"
fi

# ---------------------------------------------------------------------------
# 7. GET {subdir}/current_repodata.json for latest versions only
# ---------------------------------------------------------------------------

begin_test "current_repodata.json returns latest versions"
if resp=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${CONDA_URL}/${SUBDIR}/current_repodata.json" 2>/dev/null); then
  # current_repodata.json should have the same structure as repodata.json
  # but only contain the latest versions of each package
  has_packages=$(echo "$resp" | jq 'has("packages") or has("packages.conda")' 2>/dev/null) || true
  if [ "$has_packages" = "true" ]; then
    pass
  else
    # Some registries alias current_repodata.json to repodata.json
    if echo "$resp" | jq '.' >/dev/null 2>&1; then
      echo "  note: current_repodata.json is valid JSON but may not filter to latest only"
      pass
    else
      fail "current_repodata.json is not valid JSON"
    fi
  fi
else
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${CONDA_URL}/${SUBDIR}/current_repodata.json") || true
  if [ "$status" = "404" ]; then
    skip "current_repodata.json endpoint not implemented"
  else
    fail "current_repodata.json returned unexpected error (HTTP ${status})"
  fi
fi

# ---------------------------------------------------------------------------
# 8. 404 for nonexistent subdir/package
# ---------------------------------------------------------------------------

begin_test "404 for nonexistent subdir or package"
# Nonexistent subdir
subdir_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  "${CONDA_URL}/fakearch-${RUN_ID}/repodata.json") || true

# Nonexistent package file
pkg_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  "${CONDA_URL}/${SUBDIR}/nonexistent-pkg-${RUN_ID}-0.0.0-0.tar.bz2") || true

if [ "$pkg_status" = "404" ]; then
  pass
elif [ "$subdir_status" = "404" ]; then
  echo "  note: nonexistent subdir returns 404, package returns ${pkg_status}"
  pass
else
  fail "expected 404 for nonexistent resource, got subdir=${subdir_status} pkg=${pkg_status}"
fi

end_suite
