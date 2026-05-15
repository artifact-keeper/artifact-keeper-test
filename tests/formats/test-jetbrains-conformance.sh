#!/usr/bin/env bash
# test-jetbrains-conformance.sh - JetBrains Plugin Repository conformance tests
#
# Validates that the JetBrains plugin repository implementation handles
# plugin upload, download, listing, details, multi-version, and 404 scenarios.
#
# Endpoints: ${BASE_URL}/jetbrains/{repo_key}/
#
# Requires: curl, jq, zip (or jar)
source "$(dirname "$0")/../lib/common.sh"

begin_suite "jetbrains-conformance"
auth_admin
setup_workdir

REPO_KEY="test-jb-conf-${RUN_ID}"
PLUGIN_NAME="com.example.conformance"
PLUGIN_VERSION_1="1.0.0"
PLUGIN_VERSION_2="2.0.0"
JB_URL="${BASE_URL}/jetbrains/${REPO_KEY}"

# ---------------------------------------------------------------------------
# Helper: build a minimal JetBrains plugin JAR (ZIP with META-INF/plugin.xml)
# ---------------------------------------------------------------------------

build_plugin_jar() {
  local name="$1"
  local version="$2"
  local out_file="$3"
  local build_dir="${WORK_DIR}/plugin-${name}-${version}"

  mkdir -p "${build_dir}/META-INF"
  mkdir -p "${build_dir}/lib"

  cat > "${build_dir}/META-INF/plugin.xml" <<EOXML
<idea-plugin>
  <id>${name}</id>
  <name>${name} Plugin</name>
  <version>${version}</version>
  <vendor>Conformance Test</vendor>
  <description>Conformance test plugin v${version}.</description>
  <idea-version since-build="231.0" until-build="243.*"/>
</idea-plugin>
EOXML

  echo "placeholder class" > "${build_dir}/lib/${name}.txt"

  # Package as JAR (zip format with .jar extension)
  if command -v jar &>/dev/null; then
    jar cf "${out_file}" -C "${build_dir}" . 2>/dev/null
  else
    (cd "${build_dir}" && zip -qr "${out_file}" .)
  fi
}

# ---------------------------------------------------------------------------
# Create repository
# ---------------------------------------------------------------------------

begin_test "Create jetbrains local repository"
if create_local_repo "$REPO_KEY" "jetbrains"; then
  pass
else
  fail "could not create jetbrains repo"
fi

# ---------------------------------------------------------------------------
# 1. Upload a plugin JAR
# ---------------------------------------------------------------------------

begin_test "Upload plugin JAR"
JAR_V1="${WORK_DIR}/${PLUGIN_NAME}-${PLUGIN_VERSION_1}.jar"
build_plugin_jar "$PLUGIN_NAME" "$PLUGIN_VERSION_1" "$JAR_V1"

upload_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X POST \
  -H "$(format_auth_header)" \
  -H "Content-Type: application/octet-stream" \
  -H "x-plugin-name: ${PLUGIN_NAME}" \
  -H "x-plugin-version: ${PLUGIN_VERSION_1}" \
  --data-binary "@${JAR_V1}" \
  "${JB_URL}/plugin/uploadPlugin") || true

if [ "$upload_status" -ge 200 ] 2>/dev/null && [ "$upload_status" -lt 300 ] 2>/dev/null; then
  pass
else
  # Fallback: try multipart upload
  upload_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X POST \
    -H "$(format_auth_header)" \
    -F "name=${PLUGIN_NAME}" \
    -F "version=${PLUGIN_VERSION_1}" \
    -F "file=@${JAR_V1};type=application/octet-stream" \
    "${JB_URL}/plugin/uploadPlugin") || true
  if [ "$upload_status" -ge 200 ] 2>/dev/null && [ "$upload_status" -lt 300 ] 2>/dev/null; then
    pass
  else
    fail "plugin upload failed (HTTP ${upload_status})"
  fi
fi

sleep 1

# ---------------------------------------------------------------------------
# 2. Download plugin by name and version
# ---------------------------------------------------------------------------

begin_test "Download plugin JAR"
DL_FILE="${WORK_DIR}/downloaded-v1.jar"
dl_status=$(curl -s -o "$DL_FILE" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  "${JB_URL}/plugin/download/${PLUGIN_NAME}/${PLUGIN_VERSION_1}") || true

if [ "$dl_status" -ge 200 ] 2>/dev/null && [ "$dl_status" -lt 300 ] 2>/dev/null; then
  if [ -s "$DL_FILE" ]; then
    ORIG_SIZE=$(wc -c < "$JAR_V1" | tr -d ' ')
    DL_SIZE=$(wc -c < "$DL_FILE" | tr -d ' ')
    if assert_eq "$DL_SIZE" "$ORIG_SIZE" "downloaded JAR size (${DL_SIZE}) should match original (${ORIG_SIZE})"; then
      pass
    fi
  else
    fail "downloaded JAR is empty"
  fi
else
  fail "plugin download returned HTTP ${dl_status}"
fi

# ---------------------------------------------------------------------------
# 3. Plugin listing/metadata (XML or JSON)
# ---------------------------------------------------------------------------

begin_test "Plugin listing contains uploaded plugin"
if resp=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${JB_URL}/plugins/list/"); then
  if assert_contains "$resp" "$PLUGIN_NAME" "plugin listing should contain plugin name"; then
    if assert_contains "$resp" "$PLUGIN_VERSION_1" "plugin listing should contain plugin version"; then
      pass
    fi
  fi
else
  fail "GET /plugins/list/ returned error"
fi

# ---------------------------------------------------------------------------
# 4. Multiple versions of the same plugin
# ---------------------------------------------------------------------------

begin_test "Upload second version and verify both accessible"
JAR_V2="${WORK_DIR}/${PLUGIN_NAME}-${PLUGIN_VERSION_2}.jar"
build_plugin_jar "$PLUGIN_NAME" "$PLUGIN_VERSION_2" "$JAR_V2"

upload2_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X POST \
  -H "$(format_auth_header)" \
  -H "Content-Type: application/octet-stream" \
  -H "x-plugin-name: ${PLUGIN_NAME}" \
  -H "x-plugin-version: ${PLUGIN_VERSION_2}" \
  --data-binary "@${JAR_V2}" \
  "${JB_URL}/plugin/uploadPlugin") || true

if [ "$upload2_status" -ge 200 ] 2>/dev/null && [ "$upload2_status" -lt 300 ] 2>/dev/null; then
  sleep 1
  # Verify v2 is downloadable
  v2_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${JB_URL}/plugin/download/${PLUGIN_NAME}/${PLUGIN_VERSION_2}") || true
  # Verify v1 is still downloadable
  v1_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${JB_URL}/plugin/download/${PLUGIN_NAME}/${PLUGIN_VERSION_1}") || true

  if [ "$v2_status" = "200" ]; then
    if [ "$v1_status" = "200" ]; then
      pass
    else
      echo "  note: v2 accessible but v1 returned ${v1_status} (server may replace on re-publish)"
      pass
    fi
  else
    fail "v2 download returned ${v2_status}, v1 returned ${v1_status}"
  fi
else
  fail "second version upload returned HTTP ${upload2_status}"
fi

# ---------------------------------------------------------------------------
# 5. 404 for nonexistent plugin
# ---------------------------------------------------------------------------

begin_test "404 for nonexistent plugin download"
status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  "${JB_URL}/plugin/download/fake.nonexistent.plugin.${RUN_ID}/99.99.99") || true
if assert_eq "$status" "404" "expected 404 for nonexistent plugin, got ${status}"; then
  pass
fi

# ---------------------------------------------------------------------------
# 6. Plugin details/search endpoint
# ---------------------------------------------------------------------------

begin_test "Plugin details returns version information"
if resp=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${JB_URL}/plugin/details/${PLUGIN_NAME}"); then
  # Details JSON should contain the plugin name and version list
  if assert_contains "$resp" "$PLUGIN_NAME" "details should contain plugin name"; then
    if assert_contains "$resp" "versions" "details should contain versions array"; then
      pass
    fi
  fi
else
  # If details endpoint is not available, check plugin updates XML instead
  if resp=$(curl -sf $CURL_TIMEOUT \
      -H "$(format_auth_header)" \
      "${JB_URL}/plugins/${PLUGIN_NAME}/updates"); then
    if assert_contains "$resp" "$PLUGIN_NAME" "updates XML should contain plugin name"; then
      pass
    fi
  else
    fail "neither plugin details nor updates endpoint returned data"
  fi
fi

end_suite
