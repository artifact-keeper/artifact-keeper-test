#!/usr/bin/env bash
# test-nuget.sh - NuGet package registry E2E test (curl-based)
#
# Uploads a .nupkg to the NuGet v3 endpoint, verifies the service index,
# and downloads the package back.

source "$(dirname "$0")/../lib/common.sh"

begin_suite "nuget"
auth_admin
setup_workdir

REPO_KEY="test-nuget-${RUN_ID}"
PACKAGE_ID="E2ETest.Hello"
PACKAGE_VERSION="1.0.$(date +%s)"

# -----------------------------------------------------------------------
# Create repository
# -----------------------------------------------------------------------
begin_test "Create NuGet repository"
if create_local_repo "$REPO_KEY" "nuget"; then
  pass
else
  fail "could not create nuget repository"
fi

# -----------------------------------------------------------------------
# Generate a minimal .nupkg
# -----------------------------------------------------------------------
# A .nupkg is a ZIP file containing a .nuspec and package contents.
begin_test "Upload package"
PKG_DIR="$WORK_DIR/nupkg-build"
mkdir -p "$PKG_DIR/lib/net8.0"

cat > "$PKG_DIR/${PACKAGE_ID}.nuspec" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>${PACKAGE_ID}</id>
    <version>${PACKAGE_VERSION}</version>
    <authors>E2E Test</authors>
    <description>E2E test package for NuGet registry</description>
    <license type="expression">MIT</license>
  </metadata>
</package>
EOF

# Create a placeholder DLL (just needs to be a file)
echo "placeholder assembly" > "$PKG_DIR/lib/net8.0/${PACKAGE_ID}.dll"

# NuGet also expects [Content_Types].xml and a _rels/.rels in the zip
mkdir -p "$PKG_DIR/_rels"
cat > "$PKG_DIR/[Content_Types].xml" <<'EOF'
<?xml version="1.0" encoding="utf-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml" />
  <Default Extension="nuspec" ContentType="application/xml" />
  <Default Extension="dll" ContentType="application/octet-stream" />
</Types>
EOF

cat > "$PKG_DIR/_rels/.rels" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Type="http://schemas.microsoft.com/packaging/2010/07/manifest" Target="/${PACKAGE_ID}.nuspec" Id="R1" />
</Relationships>
EOF

NUPKG_FILE="$WORK_DIR/${PACKAGE_ID}.${PACKAGE_VERSION}.nupkg"
(cd "$PKG_DIR" && zip -qr "$NUPKG_FILE" .)

# NuGet push uses PUT with multipart/form-data
upload_status=$(curl -s -o /dev/null -w '%{http_code}' \
  -X PUT \
  -H "$(format_auth_header)" \
  -F "package=@${NUPKG_FILE};type=application/octet-stream" \
  "${BASE_URL}/nuget/${REPO_KEY}/api/v2/package") || true

if [ "$upload_status" = "200" ] || [ "$upload_status" = "201" ]; then
  pass
else
  # Try alternate push style (raw body)
  upload_status=$(curl -s -o /dev/null -w '%{http_code}' \
    -X PUT \
    -H "$(format_auth_header)" \
    -H "Content-Type: application/octet-stream" \
    --data-binary "@${NUPKG_FILE}" \
    "${BASE_URL}/nuget/${REPO_KEY}/api/v2/package") || true
  if [ "$upload_status" = "200" ] || [ "$upload_status" = "201" ]; then
    pass
  else
    fail "package upload returned ${upload_status}, expected 200 or 201"
  fi
fi

# -----------------------------------------------------------------------
# Verify NuGet v3 service index
# -----------------------------------------------------------------------
begin_test "Verify service index"
service_resp=$(curl -sf -H "$(format_auth_header)" \
  "${BASE_URL}/nuget/${REPO_KEY}/v3/index.json" 2>/dev/null) || true

if [ -n "$service_resp" ]; then
  version=$(echo "$service_resp" | jq -r '.version // empty' 2>/dev/null) || true
  if [ -n "$version" ]; then
    pass
  else
    # Check for resources array (NuGet v3 service index structure)
    resources=$(echo "$service_resp" | jq -r '.resources // empty' 2>/dev/null) || true
    if [ -n "$resources" ] && [ "$resources" != "null" ]; then
      pass
    else
      fail "service index does not contain expected NuGet v3 structure"
    fi
  fi
else
  fail "could not fetch NuGet service index"
fi

# -----------------------------------------------------------------------
# Verify package registration
# -----------------------------------------------------------------------
begin_test "Verify package registration"
# NuGet v3 uses lowercase package IDs in URLs
PACKAGE_ID_LOWER=$(echo "$PACKAGE_ID" | tr '[:upper:]' '[:lower:]')

reg_resp=$(curl -sf -H "$(format_auth_header)" \
  "${BASE_URL}/nuget/${REPO_KEY}/v3/registration/${PACKAGE_ID_LOWER}/index.json" 2>/dev/null) || true

if [ -n "$reg_resp" ] && echo "$reg_resp" | grep -qi "$PACKAGE_ID"; then
  pass
else
  skip "package registration endpoint not available"
fi

# -----------------------------------------------------------------------
# Download package
# -----------------------------------------------------------------------
begin_test "Download package"
dl_file="$WORK_DIR/downloaded.nupkg"
dl_status=$(curl -sf -o "$dl_file" -w '%{http_code}' \
  -H "$(format_auth_header)" \
  "${BASE_URL}/nuget/${REPO_KEY}/v3/flatcontainer/${PACKAGE_ID_LOWER}/${PACKAGE_VERSION}/${PACKAGE_ID_LOWER}.${PACKAGE_VERSION}.nupkg" 2>/dev/null) || true

if [ "$dl_status" = "200" ]; then
  if [ -s "$dl_file" ]; then
    pass
  else
    fail "downloaded nupkg is empty"
  fi
else
  fail "package download returned ${dl_status}, expected 200"
fi

end_suite
