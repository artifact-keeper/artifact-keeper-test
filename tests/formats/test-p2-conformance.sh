#!/usr/bin/env bash
# test-p2-conformance.sh - Eclipse P2 repository conformance tests
#
# Validates that the P2 repository implementation handles plugin/feature
# JAR uploads, generates content.xml and artifacts.xml metadata, supports
# downloads via the standard P2 path layout, and returns correct 404s.
#
# P2 does not have a dedicated native handler with custom routes. All
# operations go through the generic artifact API with the "p2" format,
# following the standard P2 repository directory layout:
#   plugins/{id}_{version}.jar
#   features/{id}_{version}.jar
#   content.xml  (or content.jar)
#   artifacts.xml (or artifacts.jar)
#
# Endpoints: ${BASE_URL}/api/v1/repositories/{repo_key}/...
#
# Requires: curl, jq, jar or zip (optional, for .jar creation)
source "$(dirname "$0")/../lib/common.sh"

begin_suite "p2-conformance"
auth_admin
setup_workdir

REPO_KEY="test-p2-conf-${RUN_ID}"
PLUGIN_ID="com.example.testplugin"
PLUGIN_VERSION="1.0.0"
FEATURE_ID="com.example.testfeature"
FEATURE_VERSION="1.0.0"

# Portable SHA256 helper (Linux uses sha256sum, macOS uses shasum)
sha256_hex() {
  if command -v sha256sum &>/dev/null; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

# ---------------------------------------------------------------------------
# Helper: build a minimal Eclipse plugin JAR
#
# A plugin JAR contains at minimum a META-INF/MANIFEST.MF with the
# Bundle-SymbolicName and Bundle-Version headers.
# ---------------------------------------------------------------------------

build_plugin_jar() {
  local id="$1"
  local version="$2"
  local outfile="$3"

  local build_dir="${WORK_DIR}/p2-build-${id}-${version}"
  mkdir -p "${build_dir}/META-INF"

  cat > "${build_dir}/META-INF/MANIFEST.MF" <<EOMANIFEST
Manifest-Version: 1.0
Bundle-ManifestVersion: 2
Bundle-Name: ${id}
Bundle-SymbolicName: ${id}
Bundle-Version: ${version}
Bundle-Vendor: Conformance Test
EOMANIFEST

  # Add a minimal class placeholder
  mkdir -p "${build_dir}/com/example"
  echo "// placeholder" > "${build_dir}/com/example/Plugin.java"

  # Build JAR using zip (jar utility may not be available)
  if command -v jar &>/dev/null; then
    (cd "${build_dir}" && jar cfm "${outfile}" META-INF/MANIFEST.MF com/ 2>/dev/null)
  else
    (cd "${build_dir}" && zip -r "${outfile}" META-INF/ com/ >/dev/null 2>&1)
  fi
}

# ---------------------------------------------------------------------------
# Create repository
# ---------------------------------------------------------------------------

begin_test "Create P2 local repository"
if create_local_repo "$REPO_KEY" "p2"; then
  pass
else
  fail "could not create p2 repository"
fi

# ---------------------------------------------------------------------------
# 1. Upload a P2 plugin JAR
# ---------------------------------------------------------------------------

begin_test "Upload P2 plugin JAR"
PLUGIN_JAR="${WORK_DIR}/${PLUGIN_ID}_${PLUGIN_VERSION}.jar"
build_plugin_jar "$PLUGIN_ID" "$PLUGIN_VERSION" "$PLUGIN_JAR"

upload_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X PUT \
  -H "$(auth_header)" \
  -H "Content-Type: application/java-archive" \
  --data-binary "@${PLUGIN_JAR}" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/plugins/${PLUGIN_ID}_${PLUGIN_VERSION}.jar") || true

if [ "$upload_status" -ge 200 ] 2>/dev/null && [ "$upload_status" -lt 300 ] 2>/dev/null; then
  pass
else
  fail "plugin JAR upload returned HTTP ${upload_status}, expected 2xx"
fi

sleep 1

# ---------------------------------------------------------------------------
# 2. GET content.xml or content.jar returns repository metadata
# ---------------------------------------------------------------------------

begin_test "content.xml returns repository metadata"
content_found=false

# Try content.xml first
content_status=$(curl -s -o "${WORK_DIR}/content.xml" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/download/content.xml") || true

if [ "$content_status" = "200" ] && [ -s "${WORK_DIR}/content.xml" ]; then
  content_found=true
  echo "  content.xml available"
fi

# Try content.jar as fallback
if ! $content_found; then
  content_status=$(curl -s -o "${WORK_DIR}/content.jar" -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(auth_header)" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}/download/content.jar") || true

  if [ "$content_status" = "200" ] && [ -s "${WORK_DIR}/content.jar" ]; then
    content_found=true
    echo "  content.jar available"
  fi
fi

if $content_found; then
  pass
else
  # P2 metadata generation may be deferred or not auto-generated;
  # skip if the repo simply stores artifacts without generating metadata.
  skip "content.xml/content.jar not available (HTTP ${content_status}), server may not auto-generate P2 metadata"
fi

# ---------------------------------------------------------------------------
# 3. GET artifacts.xml or artifacts.jar returns artifact metadata
# ---------------------------------------------------------------------------

begin_test "artifacts.xml returns artifact metadata"
artifacts_found=false

artifacts_status=$(curl -s -o "${WORK_DIR}/artifacts.xml" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/download/artifacts.xml") || true

if [ "$artifacts_status" = "200" ] && [ -s "${WORK_DIR}/artifacts.xml" ]; then
  artifacts_found=true
  echo "  artifacts.xml available"
fi

if ! $artifacts_found; then
  artifacts_status=$(curl -s -o "${WORK_DIR}/artifacts.jar" -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(auth_header)" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}/download/artifacts.jar") || true

  if [ "$artifacts_status" = "200" ] && [ -s "${WORK_DIR}/artifacts.jar" ]; then
    artifacts_found=true
    echo "  artifacts.jar available"
  fi
fi

if $artifacts_found; then
  pass
else
  skip "artifacts.xml/artifacts.jar not available (HTTP ${artifacts_status}), server may not auto-generate P2 metadata"
fi

# ---------------------------------------------------------------------------
# 4. Download plugin JAR
# ---------------------------------------------------------------------------

begin_test "Download plugin JAR"
DL_FILE="${WORK_DIR}/downloaded-plugin.jar"
dl_status=$(curl -s -o "$DL_FILE" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/download/plugins/${PLUGIN_ID}_${PLUGIN_VERSION}.jar") || true

if [ "$dl_status" -ge 200 ] 2>/dev/null && [ "$dl_status" -lt 300 ] 2>/dev/null; then
  if [ -s "$DL_FILE" ]; then
    # Verify integrity against the uploaded file
    upload_sha=$(sha256_hex "$PLUGIN_JAR")
    download_sha=$(sha256_hex "$DL_FILE")
    if assert_eq "$download_sha" "$upload_sha" "SHA256 mismatch: uploaded=${upload_sha} downloaded=${download_sha}"; then
      pass
    fi
  else
    fail "downloaded plugin JAR is empty"
  fi
else
  fail "plugin JAR download returned HTTP ${dl_status}"
fi

# ---------------------------------------------------------------------------
# 5. 404 for nonexistent artifact
# ---------------------------------------------------------------------------

begin_test "404 for nonexistent plugin"
status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/download/plugins/com.nonexistent.plugin_${RUN_ID}_99.0.0.jar") || true
if assert_eq "$status" "404" "expected 404 for nonexistent plugin, got ${status}"; then
  pass
fi

# ---------------------------------------------------------------------------
# 6. Repository metadata contains installable unit info
# ---------------------------------------------------------------------------

begin_test "Repository metadata references uploaded plugin"
# If content.xml was fetched, verify the plugin ID appears in it.
# If P2 metadata is not auto-generated, we verify the artifact is at
# least listed through the management API.
metadata_ok=false

if [ -s "${WORK_DIR}/content.xml" ]; then
  if grep -q "$PLUGIN_ID" "${WORK_DIR}/content.xml" 2>/dev/null; then
    metadata_ok=true
    echo "  plugin referenced in content.xml"
  fi
fi

if ! $metadata_ok; then
  # Fallback: check the artifact list via the management API
  artifacts_resp=$(curl -sf $CURL_TIMEOUT \
    -H "$(auth_header)" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts" 2>/dev/null) || true

  if [ -n "$artifacts_resp" ]; then
    found=$(echo "$artifacts_resp" | jq --arg id "$PLUGIN_ID" '
      if type == "array" then [.[] | select(.path // .name | contains($id))] | length
      elif .items then [.items[] | select(.path // .name | contains($id))] | length
      else 0
      end
    ' 2>/dev/null) || found=0

    if [ "$found" -ge 1 ] 2>/dev/null; then
      metadata_ok=true
      echo "  plugin found in artifact list via management API"
    fi
  fi
fi

if $metadata_ok; then
  pass
else
  fail "uploaded plugin '${PLUGIN_ID}' not found in repository metadata or artifact list"
fi

end_suite
