#!/usr/bin/env bash
# test-vscode.sh - VS Code extension (VSIX) marketplace E2E test
#
# Tests publish and query of VSIX extensions via the
# /vscode/{repo_key}/ endpoints. Uses curl only (no native client needed).
#
# Requires: curl, zip

source "$(dirname "$0")/../lib/common.sh"

begin_suite "vscode"
auth_admin
setup_workdir
require_cmd zip

REPO_KEY="test-vscode-${RUN_ID}"
PUBLISHER="testpublisher"
EXT_NAME="testextension"
EXT_VERSION="0.1.$(date +%s)"
EXT_ID="${PUBLISHER}.${EXT_NAME}"

# ---------------------------------------------------------------------------
# Create repository
# ---------------------------------------------------------------------------

begin_test "Create vscode local repository"
if create_local_repo "$REPO_KEY" "vscode"; then
  pass
else
  fail "could not create vscode repository"
fi

# ---------------------------------------------------------------------------
# Build a minimal VSIX file
# ---------------------------------------------------------------------------
# A VSIX is a ZIP file containing at minimum:
#   - extension.vsixmanifest (XML metadata)
#   - extension/package.json

begin_test "Build minimal VSIX file"

cd "$WORK_DIR"
mkdir -p vsix-content/extension

cat > vsix-content/extension.vsixmanifest <<EOF
<?xml version="1.0" encoding="utf-8"?>
<PackageManifest Version="2.0.0" xmlns="http://schemas.microsoft.com/developer/vsx-schema/2011">
  <Metadata>
    <Identity Id="${EXT_ID}" Version="${EXT_VERSION}" Publisher="${PUBLISHER}" />
    <DisplayName>Test Extension</DisplayName>
    <Description>E2E test extension for artifact-keeper</Description>
  </Metadata>
  <Installation>
    <InstallationTarget Id="Microsoft.VisualStudio.Code" />
  </Installation>
  <Dependencies />
</PackageManifest>
EOF

cat > vsix-content/extension/package.json <<EOF
{
  "name": "${EXT_NAME}",
  "displayName": "Test Extension",
  "version": "${EXT_VERSION}",
  "publisher": "${PUBLISHER}",
  "engines": { "vscode": "^1.60.0" },
  "description": "E2E test extension"
}
EOF

cat > vsix-content/\[Content_Types\].xml <<EOF
<?xml version="1.0" encoding="utf-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension=".json" ContentType="application/json" />
  <Default Extension=".vsixmanifest" ContentType="text/xml" />
</Types>
EOF

cd vsix-content
VSIX_FILE="${WORK_DIR}/${EXT_ID}-${EXT_VERSION}.vsix"
if zip -r "$VSIX_FILE" . > /dev/null 2>&1; then
  pass
else
  fail "failed to create VSIX zip file"
fi

# ---------------------------------------------------------------------------
# Publish VSIX via API
# ---------------------------------------------------------------------------

begin_test "Publish VSIX extension"

PUBLISH_URL="${BASE_URL}/vscode/${REPO_KEY}/api/extensions"
if resp=$(curl -sf -X POST "$PUBLISH_URL" \
  -H "$(auth_header)" \
  -H "Content-Type: application/octet-stream" \
  -H "x-publisher: ${PUBLISHER}" \
  -H "x-extension-name: ${EXT_NAME}" \
  -H "x-extension-version: ${EXT_VERSION}" \
  --data-binary "@${VSIX_FILE}" 2>&1); then
  pass
else
  fail "VSIX publish failed: ${resp}"
fi

# ---------------------------------------------------------------------------
# Query extension via marketplace API
# ---------------------------------------------------------------------------

begin_test "Query extension via extensionquery"
sleep 1
QUERY_URL="/vscode/${REPO_KEY}/api/extensionquery"
if resp=$(api_get "$QUERY_URL"); then
  if assert_contains "$resp" "$EXT_NAME" "query response should contain extension name"; then
    pass
  fi
else
  fail "GET ${QUERY_URL} returned error"
fi

# ---------------------------------------------------------------------------
# Get latest version info
# ---------------------------------------------------------------------------

begin_test "Get latest version info"
LATEST_URL="/vscode/${REPO_KEY}/api/extensions/${PUBLISHER}/${EXT_NAME}/latest"
if resp=$(api_get "$LATEST_URL"); then
  if assert_contains "$resp" "$EXT_VERSION" "latest info should contain version"; then
    pass
  fi
else
  fail "GET ${LATEST_URL} returned error"
fi

# ---------------------------------------------------------------------------
# Download VSIX file
# ---------------------------------------------------------------------------

begin_test "Download VSIX file"
DL_URL="/vscode/${REPO_KEY}/extensions/${PUBLISHER}/${EXT_NAME}/${EXT_VERSION}/download"
DL_FILE="${WORK_DIR}/downloaded.vsix"
if curl -sf -H "$(auth_header)" -o "$DL_FILE" "${BASE_URL}${DL_URL}"; then
  # Verify it is a valid ZIP
  if file "$DL_FILE" | grep -q "Zip\|zip"; then
    pass
  else
    fail "downloaded file is not a valid ZIP/VSIX"
  fi
else
  fail "VSIX download failed"
fi

# ---------------------------------------------------------------------------
# Verify repository artifacts via management API
# ---------------------------------------------------------------------------

begin_test "List artifacts via management API"
if resp=$(api_get "/api/v1/repositories/${REPO_KEY}/artifacts"); then
  if assert_contains "$resp" "$EXT_NAME" "artifact list should contain extension"; then
    pass
  fi
else
  fail "GET /api/v1/repositories/${REPO_KEY}/artifacts returned error"
fi

end_suite
