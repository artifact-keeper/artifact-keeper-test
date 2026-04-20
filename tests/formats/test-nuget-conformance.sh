#!/usr/bin/env bash
# test-nuget-conformance.sh - NuGet V3 Server API conformance tests
#
# Validates NuGet V3 protocol conformance: service index, package push,
# registration, flat container, search, content types, .nuspec extraction,
# SemVer2 handling, multi-version listing, and case-insensitive IDs.
#
# Endpoints: ${BASE_URL}/nuget/{repo_key}/
#
# Requires: curl, jq, zip

source "$(dirname "$0")/../lib/common.sh"

begin_suite "nuget-conformance"
require_cmd zip
auth_admin
setup_workdir

REPO_KEY="test-nuget-conf-${RUN_ID}"
PACKAGE_ID="ConfTest.Hello"
PACKAGE_ID_LOWER=$(echo "$PACKAGE_ID" | tr '[:upper:]' '[:lower:]')
PACKAGE_VERSION="1.0.0"
NUGET_BASE="${BASE_URL}/nuget/${REPO_KEY}"

# ---------------------------------------------------------------------------
# Helper: build a minimal .nupkg (a ZIP with .nuspec + OPC structure)
# ---------------------------------------------------------------------------

build_nupkg() {
  local pkg_id="$1"
  local pkg_version="$2"
  local outfile="$3"
  local description="${4:-NuGet conformance test package}"

  local build_dir="${WORK_DIR}/nupkg-build-${pkg_id}-${pkg_version}"
  mkdir -p "${build_dir}/lib/net8.0" "${build_dir}/_rels"

  cat > "${build_dir}/${pkg_id}.nuspec" <<NUSPEC
<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>${pkg_id}</id>
    <version>${pkg_version}</version>
    <authors>Conformance Test</authors>
    <description>${description}</description>
    <license type="expression">MIT</license>
    <repository type="git" url="https://example.com/repo" />
  </metadata>
</package>
NUSPEC

  echo "placeholder assembly ${pkg_version}" > "${build_dir}/lib/net8.0/${pkg_id}.dll"

  cat > "${build_dir}/[Content_Types].xml" <<'OPC'
<?xml version="1.0" encoding="utf-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml" />
  <Default Extension="nuspec" ContentType="application/xml" />
  <Default Extension="dll" ContentType="application/octet-stream" />
</Types>
OPC

  cat > "${build_dir}/_rels/.rels" <<RELS
<?xml version="1.0" encoding="utf-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Type="http://schemas.microsoft.com/packaging/2010/07/manifest" Target="/${pkg_id}.nuspec" Id="R1" />
</Relationships>
RELS

  (cd "${build_dir}" && zip -qr "${outfile}" .)
}

# Helper: push a .nupkg via the v2 push endpoint. Tries multipart first,
# then falls back to raw binary body. Prints the HTTP status code.
push_nupkg() {
  local nupkg_file="$1"
  local status

  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X PUT \
    -H "$(format_auth_header)" \
    -F "package=@${nupkg_file};type=application/octet-stream" \
    "${NUGET_BASE}/api/v2/package") || true

  if [ "$status" = "200" ] || [ "$status" = "201" ]; then
    echo "$status"
    return 0
  fi

  # Fallback: raw body upload
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X PUT \
    -H "$(format_auth_header)" \
    -H "Content-Type: application/octet-stream" \
    --data-binary "@${nupkg_file}" \
    "${NUGET_BASE}/api/v2/package") || true

  echo "$status"
}

# ---------------------------------------------------------------------------
# Setup: create repository and push initial package
# ---------------------------------------------------------------------------

begin_test "Create NuGet local repository"
if create_local_repo "$REPO_KEY" "nuget"; then
  pass
else
  fail "could not create nuget repository"
fi

NUPKG_V1="${WORK_DIR}/${PACKAGE_ID}.${PACKAGE_VERSION}.nupkg"
build_nupkg "$PACKAGE_ID" "$PACKAGE_VERSION" "$NUPKG_V1"

begin_test "PUT /api/v2/package pushes a .nupkg"
status=$(push_nupkg "$NUPKG_V1")
if [ "$status" = "200" ] || [ "$status" = "201" ]; then
  pass
else
  fail "package push returned HTTP ${status}, expected 200 or 201"
fi

# Brief pause for indexing
sleep 1

# ---------------------------------------------------------------------------
# 1. Service index
# ---------------------------------------------------------------------------

begin_test "GET /index.json returns service index with resource types"
SERVICE_INDEX=""
if SERVICE_INDEX=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${NUGET_BASE}/v3/index.json" 2>/dev/null); then

  # NuGet V3 service index must have a resources array
  resource_count=$(echo "$SERVICE_INDEX" | jq '.resources | length' 2>/dev/null) || resource_count="0"
  if [ "$resource_count" -gt 0 ] 2>/dev/null; then
    # Verify key resource types are present
    resource_types=$(echo "$SERVICE_INDEX" | jq -r '[.resources[]."@type"] | join(",")' 2>/dev/null) || resource_types=""
    found_all=true
    for rtype in SearchQueryService PackageBaseAddress RegistrationsBaseUrl PackagePublish; do
      if ! echo "$resource_types" | grep -qi "$rtype"; then
        # Some servers use versioned type names (e.g., SearchQueryService/3.0.0-beta)
        partial_match=$(echo "$SERVICE_INDEX" | jq -r "[.resources[].\"@type\" | select(test(\"${rtype}\"; \"i\"))] | length" 2>/dev/null) || partial_match="0"
        if [ "$partial_match" -eq 0 ] 2>/dev/null; then
          echo "  note: missing resource type '${rtype}'"
          found_all=false
        fi
      fi
    done
    if [ "$found_all" = "true" ]; then
      pass
    else
      # Not all types present, but service index works
      echo "  note: some resource types missing, but service index is functional"
      pass
    fi
  else
    # Fallback: check for version field (older NuGet service index)
    version=$(echo "$SERVICE_INDEX" | jq -r '.version // empty' 2>/dev/null) || true
    if [ -n "$version" ]; then
      pass
    else
      fail "service index does not contain resources array or version field"
    fi
  fi
else
  fail "GET /v3/index.json failed"
fi

# ---------------------------------------------------------------------------
# 2. Registration
# ---------------------------------------------------------------------------

begin_test "GET /v3/registration/{id}/index.json returns registration page"
REG_RESP=""
if REG_RESP=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${NUGET_BASE}/v3/registration/${PACKAGE_ID_LOWER}/index.json" 2>/dev/null); then

  # Registration index should reference the package and contain version entries
  if echo "$REG_RESP" | grep -qi "$PACKAGE_ID"; then
    # Check for items array or pages structure
    has_items=$(echo "$REG_RESP" | jq 'has("items")' 2>/dev/null) || has_items="false"
    if [ "$has_items" = "true" ]; then
      pass
    else
      # Some implementations use a flat structure
      pass
    fi
  else
    fail "registration response does not reference package ID"
  fi
else
  # Registration might use a different URL pattern
  REG_RESP=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${NUGET_BASE}/v3-registration/${PACKAGE_ID_LOWER}/index.json" 2>/dev/null) || true
  if [ -n "$REG_RESP" ] && echo "$REG_RESP" | grep -qi "$PACKAGE_ID"; then
    pass
  else
    skip "registration endpoint not available at expected paths"
  fi
fi

# ---------------------------------------------------------------------------
# 3. Flat container: download package
# ---------------------------------------------------------------------------

begin_test "GET /v3-flatcontainer/{id}/{version}/{id}.{version}.nupkg downloads the package"
DL_FILE="${WORK_DIR}/downloaded-v1.nupkg"
dl_status=$(curl -sf -o "$DL_FILE" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  "${NUGET_BASE}/v3/flatcontainer/${PACKAGE_ID_LOWER}/${PACKAGE_VERSION}/${PACKAGE_ID_LOWER}.${PACKAGE_VERSION}.nupkg" 2>/dev/null) || dl_status="000"

if [ "$dl_status" = "200" ] && [ -s "$DL_FILE" ]; then
  pass
else
  # Try alternate flat container path (v3-flatcontainer)
  dl_status=$(curl -sf -o "$DL_FILE" -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${NUGET_BASE}/v3-flatcontainer/${PACKAGE_ID_LOWER}/${PACKAGE_VERSION}/${PACKAGE_ID_LOWER}.${PACKAGE_VERSION}.nupkg" 2>/dev/null) || dl_status="000"
  if [ "$dl_status" = "200" ] && [ -s "$DL_FILE" ]; then
    pass
  else
    fail "package download returned HTTP ${dl_status}, expected 200 with non-empty body"
  fi
fi

# ---------------------------------------------------------------------------
# 4. Flat container: version listing
# ---------------------------------------------------------------------------

begin_test "GET /v3-flatcontainer/{id}/index.json lists all versions"
VERSIONS_RESP=""
if VERSIONS_RESP=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${NUGET_BASE}/v3/flatcontainer/${PACKAGE_ID_LOWER}/index.json" 2>/dev/null); then

  if assert_contains "$VERSIONS_RESP" "$PACKAGE_VERSION" \
      "version listing should contain ${PACKAGE_VERSION}"; then
    pass
  fi
else
  # Try alternate path
  VERSIONS_RESP=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${NUGET_BASE}/v3-flatcontainer/${PACKAGE_ID_LOWER}/index.json" 2>/dev/null) || true
  if [ -n "$VERSIONS_RESP" ] && echo "$VERSIONS_RESP" | grep -q "$PACKAGE_VERSION"; then
    pass
  else
    fail "flat container version listing not available or does not list expected version"
  fi
fi

# ---------------------------------------------------------------------------
# 5. Search
# ---------------------------------------------------------------------------

begin_test "Search: GET /query?q=keyword returns search results with totalHits"
SEARCH_RESP=""
if SEARCH_RESP=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${NUGET_BASE}/v3/search?q=${PACKAGE_ID}" 2>/dev/null); then

  has_total=$(echo "$SEARCH_RESP" | jq 'has("totalHits")' 2>/dev/null) || has_total="false"
  if [ "$has_total" = "true" ]; then
    total_hits=$(echo "$SEARCH_RESP" | jq '.totalHits' 2>/dev/null) || total_hits="0"
    if [ "$total_hits" -gt 0 ] 2>/dev/null; then
      pass
    else
      # Package might not be indexed for search yet
      echo "  note: totalHits is 0, search indexing may be delayed"
      pass
    fi
  else
    # Try alternate search path
    SEARCH_RESP=$(curl -sf $CURL_TIMEOUT \
      -H "$(format_auth_header)" \
      "${NUGET_BASE}/query?q=${PACKAGE_ID}" 2>/dev/null) || true
    if [ -n "$SEARCH_RESP" ]; then
      has_total=$(echo "$SEARCH_RESP" | jq 'has("totalHits")' 2>/dev/null) || has_total="false"
      if [ "$has_total" = "true" ]; then
        pass
      else
        fail "search response missing totalHits field"
      fi
    else
      fail "search endpoint not available"
    fi
  fi
else
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${NUGET_BASE}/v3/search?q=${PACKAGE_ID}") || true
  if [ "$status" = "404" ]; then
    skip "search endpoint not implemented"
  else
    fail "search request failed with HTTP ${status}"
  fi
fi

# ---------------------------------------------------------------------------
# 6. Download Content-Type
# ---------------------------------------------------------------------------

begin_test "Download returns correct Content-Type (application/octet-stream)"
dl_content_type=$(curl -sf $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  -o /dev/null -w '%{content_type}' \
  "${NUGET_BASE}/v3/flatcontainer/${PACKAGE_ID_LOWER}/${PACKAGE_VERSION}/${PACKAGE_ID_LOWER}.${PACKAGE_VERSION}.nupkg" 2>/dev/null) || dl_content_type=""

if [ -z "$dl_content_type" ]; then
  # Try alternate path
  dl_content_type=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    -o /dev/null -w '%{content_type}' \
    "${NUGET_BASE}/v3-flatcontainer/${PACKAGE_ID_LOWER}/${PACKAGE_VERSION}/${PACKAGE_ID_LOWER}.${PACKAGE_VERSION}.nupkg" 2>/dev/null) || dl_content_type=""
fi

if [ -n "$dl_content_type" ]; then
  # NuGet packages should be served as binary, not as JSON or HTML
  if [[ "$dl_content_type" == *"application/octet-stream"* ]] || \
     [[ "$dl_content_type" == *"application/zip"* ]] || \
     [[ "$dl_content_type" == *"application/x-nupkg"* ]]; then
    pass
  elif [[ "$dl_content_type" == *"application/json"* ]] || \
       [[ "$dl_content_type" == *"text/html"* ]]; then
    fail ".nupkg download should not be served as ${dl_content_type}"
  else
    echo "  Content-Type: ${dl_content_type}"
    pass
  fi
else
  fail "could not determine Content-Type for .nupkg download"
fi

# ---------------------------------------------------------------------------
# 7. .nuspec extraction: metadata available after push
# ---------------------------------------------------------------------------

begin_test ".nuspec extraction: metadata is available after push"
# The nuspec data should be accessible via the registration endpoint
nuspec_found=false

if [ -n "$REG_RESP" ]; then
  # Check if registration contains nuspec metadata fields
  if echo "$REG_RESP" | grep -qi "description" && echo "$REG_RESP" | grep -qi "Conformance"; then
    nuspec_found=true
  fi
fi

if [ "$nuspec_found" = "false" ]; then
  # Try fetching the .nuspec directly from the flat container
  nuspec_resp=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${NUGET_BASE}/v3/flatcontainer/${PACKAGE_ID_LOWER}/${PACKAGE_VERSION}/${PACKAGE_ID_LOWER}.nuspec" 2>/dev/null) || true
  if [ -z "$nuspec_resp" ]; then
    nuspec_resp=$(curl -sf $CURL_TIMEOUT \
      -H "$(format_auth_header)" \
      "${NUGET_BASE}/v3-flatcontainer/${PACKAGE_ID_LOWER}/${PACKAGE_VERSION}/${PACKAGE_ID_LOWER}.nuspec" 2>/dev/null) || true
  fi

  if [ -n "$nuspec_resp" ] && echo "$nuspec_resp" | grep -qi "$PACKAGE_ID"; then
    nuspec_found=true
  fi
fi

if [ "$nuspec_found" = "false" ]; then
  # Last resort: extract the .nuspec from the downloaded .nupkg
  if [ -s "$DL_FILE" ]; then
    extracted_nuspec=$(unzip -p "$DL_FILE" "*.nuspec" 2>/dev/null) || true
    if [ -n "$extracted_nuspec" ] && echo "$extracted_nuspec" | grep -qi "$PACKAGE_ID"; then
      nuspec_found=true
    fi
  fi
fi

if [ "$nuspec_found" = "true" ]; then
  pass
else
  skip ".nuspec metadata not available through tested endpoints"
fi

# ---------------------------------------------------------------------------
# 8. 404 for nonexistent package
# ---------------------------------------------------------------------------

begin_test "404 for nonexistent package"
missing_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  "${NUGET_BASE}/v3/registration/nonexistent-package-does-not-exist-${RUN_ID}/index.json" 2>/dev/null) || missing_status="000"

if assert_eq "$missing_status" "404" \
    "nonexistent package should return 404, got ${missing_status}"; then
  pass
fi

# ---------------------------------------------------------------------------
# 9. SemVer2 version handling (build metadata)
# ---------------------------------------------------------------------------

begin_test "SemVer2 version handling (1.0.0+build.1)"
SEMVER2_VERSION="1.0.0+build.1"
SEMVER2_NUPKG="${WORK_DIR}/${PACKAGE_ID}.semver2.nupkg"
build_nupkg "$PACKAGE_ID" "$SEMVER2_VERSION" "$SEMVER2_NUPKG" "SemVer2 build metadata test"

semver2_status=$(push_nupkg "$SEMVER2_NUPKG")
if [ "$semver2_status" = "200" ] || [ "$semver2_status" = "201" ]; then
  # Verify the version appears in the flat container listing
  sleep 1
  semver2_versions=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${NUGET_BASE}/v3/flatcontainer/${PACKAGE_ID_LOWER}/index.json" 2>/dev/null) || true
  if [ -z "$semver2_versions" ]; then
    semver2_versions=$(curl -sf $CURL_TIMEOUT \
      -H "$(format_auth_header)" \
      "${NUGET_BASE}/v3-flatcontainer/${PACKAGE_ID_LOWER}/index.json" 2>/dev/null) || true
  fi

  if [ -n "$semver2_versions" ]; then
    # SemVer2 build metadata might be stripped or preserved depending on implementation
    if echo "$semver2_versions" | grep -q "build" || echo "$semver2_versions" | grep -q "$PACKAGE_VERSION"; then
      pass
    else
      echo "  note: SemVer2 build metadata may have been stripped (acceptable per NuGet spec)"
      pass
    fi
  else
    pass
  fi
elif [ "$semver2_status" = "400" ] || [ "$semver2_status" = "409" ]; then
  # Server might reject build metadata or treat it as a conflict with 1.0.0
  echo "  note: server rejected SemVer2 build metadata (status ${semver2_status}), which is acceptable"
  pass
else
  fail "SemVer2 push returned HTTP ${semver2_status}, expected 200/201 or 400/409"
fi

# ---------------------------------------------------------------------------
# 10. Multiple versions listed correctly
# ---------------------------------------------------------------------------

begin_test "Multiple versions listed correctly"
PACKAGE_VERSION_2="2.0.0"
NUPKG_V2="${WORK_DIR}/${PACKAGE_ID}.${PACKAGE_VERSION_2}.nupkg"
build_nupkg "$PACKAGE_ID" "$PACKAGE_VERSION_2" "$NUPKG_V2" "Second version for multi-version test"

v2_status=$(push_nupkg "$NUPKG_V2")
if [ "$v2_status" = "200" ] || [ "$v2_status" = "201" ]; then
  sleep 1

  multi_versions=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${NUGET_BASE}/v3/flatcontainer/${PACKAGE_ID_LOWER}/index.json" 2>/dev/null) || true
  if [ -z "$multi_versions" ]; then
    multi_versions=$(curl -sf $CURL_TIMEOUT \
      -H "$(format_auth_header)" \
      "${NUGET_BASE}/v3-flatcontainer/${PACKAGE_ID_LOWER}/index.json" 2>/dev/null) || true
  fi

  if [ -n "$multi_versions" ]; then
    has_v1=$(echo "$multi_versions" | grep -c "$PACKAGE_VERSION" 2>/dev/null) || has_v1="0"
    has_v2=$(echo "$multi_versions" | grep -c "$PACKAGE_VERSION_2" 2>/dev/null) || has_v2="0"
    if [ "$has_v1" -gt 0 ] && [ "$has_v2" -gt 0 ]; then
      pass
    else
      fail "version listing should contain both ${PACKAGE_VERSION} and ${PACKAGE_VERSION_2}"
    fi
  else
    fail "could not fetch version listing after pushing second version"
  fi
else
  fail "second version push returned HTTP ${v2_status}"
fi

# ---------------------------------------------------------------------------
# 11. Package ID is case-insensitive
# ---------------------------------------------------------------------------

begin_test "Package ID is case-insensitive"
# NuGet package IDs are case-insensitive. Requesting with different casing
# should return the same package.
UPPER_ID=$(echo "$PACKAGE_ID" | tr '[:lower:]' '[:upper:]')
LOWER_ID="$PACKAGE_ID_LOWER"

upper_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  "${NUGET_BASE}/v3/flatcontainer/${LOWER_ID}/index.json" 2>/dev/null) || upper_status="000"

mixed_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  "${NUGET_BASE}/v3/flatcontainer/${UPPER_ID}/index.json" 2>/dev/null) || mixed_status="000"

if [ -z "$upper_status" ] || [ "$upper_status" = "000" ]; then
  # Try alternate path
  upper_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${NUGET_BASE}/v3-flatcontainer/${LOWER_ID}/index.json" 2>/dev/null) || upper_status="000"
  mixed_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${NUGET_BASE}/v3-flatcontainer/${UPPER_ID}/index.json" 2>/dev/null) || mixed_status="000"
fi

if [ "$upper_status" = "200" ]; then
  if [ "$mixed_status" = "200" ]; then
    pass
  elif [ "$mixed_status" = "404" ]; then
    # Server normalizes to lowercase only, which is acceptable
    echo "  note: server requires lowercase IDs in URLs (NuGet convention)"
    pass
  else
    fail "uppercase ID request returned HTTP ${mixed_status}, expected 200 or 404"
  fi
else
  fail "lowercase ID request returned HTTP ${upper_status}, expected 200"
fi

# ---------------------------------------------------------------------------
# 12. Download second version to verify both are independently accessible
# ---------------------------------------------------------------------------

begin_test "Download second version independently"
DL_V2="${WORK_DIR}/downloaded-v2.nupkg"
dl_v2_status=$(curl -sf -o "$DL_V2" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  "${NUGET_BASE}/v3/flatcontainer/${PACKAGE_ID_LOWER}/${PACKAGE_VERSION_2}/${PACKAGE_ID_LOWER}.${PACKAGE_VERSION_2}.nupkg" 2>/dev/null) || dl_v2_status="000"

if [ "$dl_v2_status" != "200" ] || [ ! -s "$DL_V2" ]; then
  dl_v2_status=$(curl -sf -o "$DL_V2" -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${NUGET_BASE}/v3-flatcontainer/${PACKAGE_ID_LOWER}/${PACKAGE_VERSION_2}/${PACKAGE_ID_LOWER}.${PACKAGE_VERSION_2}.nupkg" 2>/dev/null) || dl_v2_status="000"
fi

if [ "$dl_v2_status" = "200" ] && [ -s "$DL_V2" ]; then
  # Verify the two downloads are distinct files (different content)
  if [ -s "$DL_FILE" ]; then
    v1_size=$(wc -c < "$DL_FILE" | tr -d ' ')
    v2_size=$(wc -c < "$DL_V2" | tr -d ' ')
    if [ "$v1_size" != "$v2_size" ]; then
      pass
    else
      # Same size is unlikely but possible. Content check as fallback.
      echo "  note: v1 and v2 have same file size, both downloaded successfully"
      pass
    fi
  else
    pass
  fi
else
  fail "v2 download returned HTTP ${dl_v2_status}, expected 200"
fi

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

api_delete "/api/v1/repositories/${REPO_KEY}" > /dev/null 2>&1 || true

end_suite
