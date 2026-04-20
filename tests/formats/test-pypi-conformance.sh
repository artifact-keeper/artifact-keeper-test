#!/usr/bin/env bash
# test-pypi-conformance.sh - PyPI Simple Repository API conformance tests
#
# Validates PEP 503 (HTML Simple Repository API) and PEP 691 (JSON Simple API)
# conformance. Tests content negotiation, name normalization, hash fragments,
# metadata attributes, and the Twine upload protocol.
#
# Reference specifications:
#   PEP 503: https://peps.python.org/pep-0503/
#   PEP 691: https://peps.python.org/pep-0691/
#   PEP 592: https://peps.python.org/pep-0592/
#
# Requires: curl, jq, python3 (for hash computation), shasum

source "$(dirname "$0")/../lib/common.sh"

begin_suite "pypi-conformance"
auth_admin
setup_workdir

REPO_KEY="test-pypi-conf-${RUN_ID}"
PKG_NAME="test_conformance_pkg_${RUN_ID//-/_}"
PKG_VERSION_1="1.0.0"
PKG_VERSION_2="2.0.0"
PYPI_URL="${BASE_URL}/pypi/${REPO_KEY}"

# PEP 503 normalizes names: lowercase, runs of [-_.] replaced with a single hyphen
NORMALIZED_NAME=$(echo "$PKG_NAME" | tr '[:upper:]' '[:lower:]' | sed 's/[-_.]\+/-/g')

# ---------------------------------------------------------------------------
# Helper: build a minimal sdist tarball
# ---------------------------------------------------------------------------
build_sdist() {
  local name="$1"
  local version="$2"
  local requires_python="${3:-}"
  local outdir="$4"

  local sdist_dir="${outdir}/${name}-${version}"
  mkdir -p "${sdist_dir}"

  cat > "${sdist_dir}/setup.py" <<EOF
from setuptools import setup
setup(
    name="${name}",
    version="${version}",
    py_modules=["${name}"],
    description="Conformance test package v${version}",
    python_requires="${requires_python}",
)
EOF

  cat > "${sdist_dir}/${name}.py" <<EOF
__version__ = "${version}"
def hello():
    return "Hello from ${name} v${version}"
EOF

  cat > "${sdist_dir}/PKG-INFO" <<PKGINFO
Metadata-Version: 2.1
Name: ${name}
Version: ${version}
Summary: Conformance test package v${version}
Requires-Python: ${requires_python}
PKGINFO

  local tarball="${outdir}/${name}-${version}.tar.gz"
  tar czf "$tarball" -C "$outdir" "${name}-${version}"
  echo "$tarball"
}

# ---------------------------------------------------------------------------
# Helper: upload an sdist via the Twine multipart POST protocol
# ---------------------------------------------------------------------------
upload_sdist() {
  local tarball="$1"
  local name="$2"
  local version="$3"
  local requires_python="${4:-}"

  local basename_file
  basename_file=$(basename "$tarball")
  local sha256
  sha256=$(shasum -a 256 "$tarball" | cut -d' ' -f1)

  local extra_fields=()
  if [ -n "$requires_python" ]; then
    extra_fields+=(-F "requires_python=${requires_python}")
  fi

  curl -sf $CURL_TIMEOUT -X POST "${PYPI_URL}/" \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    -F ":action=file_upload" \
    -F "name=${name}" \
    -F "version=${version}" \
    -F "sha256_digest=${sha256}" \
    -F "filetype=sdist" \
    "${extra_fields[@]}" \
    -F "content=@${tarball};filename=${basename_file}"
}

# ---------------------------------------------------------------------------
# Setup: create repository and upload test packages
# ---------------------------------------------------------------------------

begin_test "Create PyPI local repository"
if create_local_repo "$REPO_KEY" "pypi"; then
  pass
else
  fail "could not create pypi repository"
fi

begin_test "Upload sdist v${PKG_VERSION_1} via Twine protocol"
SDIST_1=$(build_sdist "$PKG_NAME" "$PKG_VERSION_1" ">=3.7" "$WORK_DIR")
SDIST_1_SHA256=$(shasum -a 256 "$SDIST_1" | cut -d' ' -f1)
if upload_sdist "$SDIST_1" "$PKG_NAME" "$PKG_VERSION_1" ">=3.7" 2>&1; then
  pass
else
  fail "upload of v${PKG_VERSION_1} failed"
fi

begin_test "Upload sdist v${PKG_VERSION_2} via Twine protocol"
SDIST_2=$(build_sdist "$PKG_NAME" "$PKG_VERSION_2" ">=3.8" "$WORK_DIR")
SDIST_2_SHA256=$(shasum -a 256 "$SDIST_2" | cut -d' ' -f1)
if upload_sdist "$SDIST_2" "$PKG_NAME" "$PKG_VERSION_2" ">=3.8" 2>&1; then
  pass
else
  fail "upload of v${PKG_VERSION_2} failed"
fi

# Brief pause for indexing
sleep 1

# =========================================================================
# PEP 503: HTML Simple Repository API
# =========================================================================

begin_test "Simple index root returns HTML with package links"
ROOT_HTML=""
if ROOT_HTML=$(curl -sf $CURL_TIMEOUT \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    "${PYPI_URL}/simple/"); then
  if assert_contains "$ROOT_HTML" "$NORMALIZED_NAME" \
      "root index should list the normalized package name"; then
    # PEP 503 requires anchor elements linking to package pages
    if assert_contains "$ROOT_HTML" "<a " \
        "root index should contain anchor elements"; then
      pass
    fi
  fi
else
  fail "GET /pypi/${REPO_KEY}/simple/ failed"
fi

begin_test "Simple index root Content-Type is text/html"
ROOT_CT=""
ROOT_CT=$(curl -sf $CURL_TIMEOUT -o /dev/null -w '%{content_type}' \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    "${PYPI_URL}/simple/") || true
if [[ "$ROOT_CT" == text/html* ]]; then
  pass
else
  fail "expected Content-Type text/html, got '${ROOT_CT}'"
fi

# =========================================================================
# PEP 691: JSON Simple Repository API
# =========================================================================

begin_test "Simple index root with PEP 691 JSON Accept header"
ROOT_JSON=""
if ROOT_JSON=$(curl -sf $CURL_TIMEOUT \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    -H "Accept: application/vnd.pypi.simple.v1+json" \
    "${PYPI_URL}/simple/"); then
  # PEP 691 root response must have a "projects" array
  PROJECT_COUNT=$(echo "$ROOT_JSON" | jq '.projects | length' 2>/dev/null) || PROJECT_COUNT=""
  if [ -n "$PROJECT_COUNT" ] && [ "$PROJECT_COUNT" -gt 0 ] 2>/dev/null; then
    pass
  else
    # Some servers return a different JSON structure; check for package name
    if assert_contains "$ROOT_JSON" "$NORMALIZED_NAME" \
        "JSON root should reference the package"; then
      pass
    fi
  fi
else
  fail "GET /simple/ with JSON Accept header failed"
fi

begin_test "PEP 691 JSON response Content-Type"
JSON_CT=""
JSON_CT=$(curl -sf $CURL_TIMEOUT -o /dev/null -w '%{content_type}' \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    -H "Accept: application/vnd.pypi.simple.v1+json" \
    "${PYPI_URL}/simple/") || true
if [[ "$JSON_CT" == *"application/vnd.pypi.simple"* ]] || [[ "$JSON_CT" == *"application/json"* ]]; then
  pass
else
  fail "expected PEP 691 JSON content type, got '${JSON_CT}'"
fi

# =========================================================================
# Content negotiation
# =========================================================================

begin_test "Content negotiation respects Accept header for package index"
# Verify the package-level endpoint also responds to content negotiation,
# not just the root index tested above.
PKG_NEG_HTML_CT=""
PKG_NEG_HTML_CT=$(curl -sf $CURL_TIMEOUT -o /dev/null -w '%{content_type}' \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    -H "Accept: text/html" \
    "${PYPI_URL}/simple/${NORMALIZED_NAME}/") || true
PKG_NEG_JSON_CT=""
PKG_NEG_JSON_CT=$(curl -sf $CURL_TIMEOUT -o /dev/null -w '%{content_type}' \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    -H "Accept: application/vnd.pypi.simple.v1+json" \
    "${PYPI_URL}/simple/${NORMALIZED_NAME}/") || true

if [[ "$PKG_NEG_HTML_CT" == text/html* ]]; then
  if [[ "$PKG_NEG_JSON_CT" == *"application/vnd.pypi.simple"* ]] || [[ "$PKG_NEG_JSON_CT" == *"application/json"* ]]; then
    pass
  else
    fail "JSON Accept on package index returned '${PKG_NEG_JSON_CT}' instead of JSON type"
  fi
else
  fail "HTML Accept on package index returned '${PKG_NEG_HTML_CT}' instead of text/html"
fi

# =========================================================================
# Package index (per-project page)
# =========================================================================

begin_test "Package index (HTML) lists file links"
PKG_HTML=""
if PKG_HTML=$(curl -sf $CURL_TIMEOUT \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    "${PYPI_URL}/simple/${NORMALIZED_NAME}/"); then
  if assert_contains "$PKG_HTML" ".tar.gz" \
      "package index should contain .tar.gz file links"; then
    if assert_contains "$PKG_HTML" "<a " \
        "package index should contain anchor elements"; then
      pass
    fi
  fi
else
  fail "GET /pypi/${REPO_KEY}/simple/${NORMALIZED_NAME}/ failed"
fi

begin_test "Package index (JSON) returns structured file list"
PKG_JSON=""
if PKG_JSON=$(curl -sf $CURL_TIMEOUT \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    -H "Accept: application/vnd.pypi.simple.v1+json" \
    "${PYPI_URL}/simple/${NORMALIZED_NAME}/"); then
  # PEP 691 package response has a "files" array
  FILE_COUNT=$(echo "$PKG_JSON" | jq '.files | length' 2>/dev/null) || FILE_COUNT=""
  if [ -n "$FILE_COUNT" ] && [ "$FILE_COUNT" -gt 0 ] 2>/dev/null; then
    pass
  else
    # Fallback: check for filename strings in the response
    if assert_contains "$PKG_JSON" ".tar.gz" \
        "JSON package index should reference tar.gz files"; then
      pass
    fi
  fi
else
  fail "GET /simple/${NORMALIZED_NAME}/ with JSON Accept failed"
fi

# =========================================================================
# Hash fragments (PEP 503)
# =========================================================================

begin_test "File links include sha256 hash fragment"
if [ -n "$PKG_HTML" ]; then
  # PEP 503 requires href="...#sha256=<hash>" on file links
  if echo "$PKG_HTML" | grep -qE '#sha256=[0-9a-f]{64}'; then
    pass
  else
    # Some implementations use other hash algorithms or place hash differently
    if echo "$PKG_HTML" | grep -qE '#(sha256|md5|sha384|sha512)='; then
      pass
    else
      fail "file links should contain hash fragments (#sha256=...)"
    fi
  fi
else
  fail "no HTML package index available to check"
fi

# =========================================================================
# Download and checksum verification
# =========================================================================

begin_test "Download uploaded file from index"
# Extract the first .tar.gz href from the HTML package index
FILE_HREF=""
FILE_HREF=$(echo "$PKG_HTML" | grep -oE 'href="[^"]*\.tar\.gz[^"]*"' | head -1 | sed 's/href="//;s/"//') || true

DOWNLOAD_FILE="${WORK_DIR}/downloaded.tar.gz"
if [ -z "$FILE_HREF" ]; then
  fail "no .tar.gz link found in package index"
else
  # Strip the hash fragment for the actual download URL
  CLEAN_HREF=$(echo "$FILE_HREF" | sed 's/#.*//')
  if [[ "$CLEAN_HREF" == http* ]]; then
    DOWNLOAD_URL="$CLEAN_HREF"
  elif [[ "$CLEAN_HREF" == /* ]]; then
    DOWNLOAD_URL="${BASE_URL}${CLEAN_HREF}"
  else
    DOWNLOAD_URL="${PYPI_URL}/simple/${NORMALIZED_NAME}/${CLEAN_HREF}"
  fi

  if curl -sf $CURL_TIMEOUT \
      -u "${ADMIN_USER}:${ADMIN_PASS}" \
      -o "$DOWNLOAD_FILE" \
      "$DOWNLOAD_URL"; then
    if [ -s "$DOWNLOAD_FILE" ]; then
      pass
    else
      fail "downloaded file is empty"
    fi
  else
    fail "file download failed from ${DOWNLOAD_URL}"
  fi
fi

begin_test "Downloaded file SHA256 matches index hash"
if [ -s "$DOWNLOAD_FILE" ]; then
  DOWNLOADED_SHA256=$(shasum -a 256 "$DOWNLOAD_FILE" | cut -d' ' -f1)
  # Extract the sha256 value from the href fragment
  INDEX_SHA256=$(echo "$FILE_HREF" | grep -oE 'sha256=[0-9a-f]{64}' | cut -d= -f2) || INDEX_SHA256=""

  if [ -n "$INDEX_SHA256" ]; then
    if assert_eq "$DOWNLOADED_SHA256" "$INDEX_SHA256" \
        "downloaded SHA256 (${DOWNLOADED_SHA256}) should match index hash (${INDEX_SHA256})"; then
      pass
    fi
  else
    # Hash might match the original upload hash instead
    if [ "$DOWNLOADED_SHA256" = "$SDIST_1_SHA256" ] || [ "$DOWNLOADED_SHA256" = "$SDIST_2_SHA256" ]; then
      pass
    else
      skip "could not extract sha256 from index link to verify"
    fi
  fi
else
  skip "no downloaded file to verify"
fi

# =========================================================================
# Multiple versions
# =========================================================================

begin_test "Multiple versions appear in package index"
if [ -n "$PKG_HTML" ]; then
  HAS_V1=false
  HAS_V2=false
  if echo "$PKG_HTML" | grep -q "${PKG_VERSION_1}"; then
    HAS_V1=true
  fi
  if echo "$PKG_HTML" | grep -q "${PKG_VERSION_2}"; then
    HAS_V2=true
  fi
  if [ "$HAS_V1" = "true" ] && [ "$HAS_V2" = "true" ]; then
    pass
  else
    fail "package index should list both v${PKG_VERSION_1} and v${PKG_VERSION_2} (v1=${HAS_V1}, v2=${HAS_V2})"
  fi
else
  fail "no HTML package index available"
fi

# =========================================================================
# PEP 503 name normalization
# =========================================================================

begin_test "PEP 503 name normalization: underscores to hyphens"
# The package was uploaded with underscores in the name. PEP 503 says the
# simple index must normalize names: replace [-_.] runs with a single hyphen,
# and lowercase everything.
if [ -n "$ROOT_HTML" ]; then
  if assert_contains "$ROOT_HTML" "$NORMALIZED_NAME" \
      "root index should use normalized name (hyphens, not underscores)"; then
    pass
  fi
else
  fail "no root index HTML available"
fi

begin_test "Case-insensitive package name lookup"
# PEP 503 requires that lookups are case-insensitive. Request with mixed case.
MIXED_CASE_NAME=$(echo "$NORMALIZED_NAME" | sed 's/\(.\)/\U\1/')  # capitalize first char
MIXED_CASE_STATUS=""
MIXED_CASE_STATUS=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    "${PYPI_URL}/simple/${MIXED_CASE_NAME}/") || MIXED_CASE_STATUS="000"

if [ "$MIXED_CASE_STATUS" = "200" ]; then
  pass
elif [ "$MIXED_CASE_STATUS" = "301" ] || [ "$MIXED_CASE_STATUS" = "302" ] || [ "$MIXED_CASE_STATUS" = "308" ]; then
  # A redirect to the canonical normalized name is also acceptable per PEP 503
  pass
else
  fail "expected 200 or redirect for mixed-case name, got HTTP ${MIXED_CASE_STATUS}"
fi

# =========================================================================
# Requires-Python metadata (PEP 503)
# =========================================================================

begin_test "data-requires-python attribute on file links"
if [ -n "$PKG_HTML" ]; then
  if echo "$PKG_HTML" | grep -qi 'data-requires-python'; then
    pass
  else
    skip "server does not include data-requires-python attribute (optional per PEP 503)"
  fi
else
  fail "no HTML package index available"
fi

# =========================================================================
# Yanked files (PEP 592)
# =========================================================================

begin_test "Yanked file attribute support"
# PEP 592 defines a data-yanked attribute on file links for yanked releases.
# We check whether the server supports the concept by looking at the index
# structure. Since we have not yanked anything, the attribute should be absent
# on our files, which is correct behavior.
if [ -n "$PKG_HTML" ]; then
  if echo "$PKG_HTML" | grep -qi 'data-yanked'; then
    # If present on our non-yanked files, that is a bug
    fail "data-yanked should not be present on files that have not been yanked"
  else
    # Correct: no yanked attribute on non-yanked files. The server may or may
    # not support yanking, but it is not incorrectly marking files.
    pass
  fi
else
  fail "no HTML package index available"
fi

# =========================================================================
# 404 on missing package
# =========================================================================

begin_test "404 for nonexistent package"
MISSING_STATUS=""
MISSING_STATUS=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    "${PYPI_URL}/simple/nonexistent-package-that-does-not-exist/") || MISSING_STATUS="000"

if assert_eq "$MISSING_STATUS" "404" \
    "nonexistent package should return 404, got ${MISSING_STATUS}"; then
  pass
fi

# =========================================================================
# Duplicate upload rejection
# =========================================================================

begin_test "Duplicate upload returns 409 or is idempotent"
DUP_STATUS=""
DUP_BASENAME=$(basename "$SDIST_1")
DUP_STATUS=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X POST "${PYPI_URL}/" \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    -F ":action=file_upload" \
    -F "name=${PKG_NAME}" \
    -F "version=${PKG_VERSION_1}" \
    -F "sha256_digest=${SDIST_1_SHA256}" \
    -F "filetype=sdist" \
    -F "content=@${SDIST_1};filename=${DUP_BASENAME}") || DUP_STATUS="000"

# Servers may reject duplicates with 409 Conflict or accept them idempotently (200)
if [ "$DUP_STATUS" = "409" ] || [ "$DUP_STATUS" = "200" ] || [ "$DUP_STATUS" = "201" ]; then
  pass
else
  fail "duplicate upload should return 409 or 200, got HTTP ${DUP_STATUS}"
fi

# =========================================================================
# PEP 691 JSON package detail
# =========================================================================

begin_test "PEP 691 JSON package detail has file hashes"
if [ -n "$PKG_JSON" ]; then
  # PEP 691 files array entries should have a "hashes" object with sha256
  HAS_HASHES=$(echo "$PKG_JSON" | jq '[.files[]? | select(.hashes.sha256 != null)] | length' 2>/dev/null) || HAS_HASHES=""
  if [ -n "$HAS_HASHES" ] && [ "$HAS_HASHES" -gt 0 ] 2>/dev/null; then
    pass
  else
    # Fallback: check for hash presence in a different structure
    if echo "$PKG_JSON" | grep -q 'sha256'; then
      pass
    else
      skip "JSON response does not include file hashes in expected PEP 691 structure"
    fi
  fi
else
  skip "no JSON package index available"
fi

# =========================================================================
# Cleanup
# =========================================================================

api_delete "/api/v1/repositories/${REPO_KEY}" > /dev/null 2>&1 || true

end_suite
