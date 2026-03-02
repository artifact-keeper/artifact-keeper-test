#!/usr/bin/env bash
# JetBrains plugin repository E2E test
# Tests plugin JAR upload and repository XML listing via /jetbrains/{repo_key}/.
source "$(dirname "$0")/../lib/common.sh"

begin_suite "jetbrains"
auth_admin
setup_workdir

REPO_KEY="test-jetbrains-${RUN_ID}"
PLUGIN_ID="com.example.testplugin"
PLUGIN_VERSION="1.0.$(date +%s)"
JB_URL="${BASE_URL}/jetbrains/${REPO_KEY}"
HANDLER_AVAILABLE=true

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
# Check JetBrains handler availability
# ---------------------------------------------------------------------------

begin_test "Check jetbrains handler availability"
PROBE_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
  -H "$(format_auth_header)" \
  "${JB_URL}/plugins/list/") || true
if [ "$PROBE_CODE" = "404" ]; then
  HANDLER_AVAILABLE=false
  skip "jetbrains handler not available (HTTP 404)"
else
  pass
fi

# ---------------------------------------------------------------------------
# Create test plugin JAR
# ---------------------------------------------------------------------------

begin_test "Create test plugin JAR"
cd "$WORK_DIR"

# JetBrains plugins contain META-INF/plugin.xml
mkdir -p plugin-content/META-INF
cat > plugin-content/META-INF/plugin.xml <<EOF
<idea-plugin>
  <id>${PLUGIN_ID}</id>
  <name>Test Plugin</name>
  <version>${PLUGIN_VERSION}</version>
  <vendor>E2E Test</vendor>
  <description>A test plugin for artifact-keeper E2E testing.</description>
  <idea-version since-build="231.0" until-build="243.*"/>
</idea-plugin>
EOF

mkdir -p plugin-content/lib
echo "placeholder" > plugin-content/lib/test-plugin.txt

# Package as JAR (zip with .jar extension)
jar cf "${WORK_DIR}/test-plugin-${PLUGIN_VERSION}.jar" -C plugin-content . 2>/dev/null || \
  (cd plugin-content && zip -qr "${WORK_DIR}/test-plugin-${PLUGIN_VERSION}.jar" .)

pass

# ---------------------------------------------------------------------------
# Upload plugin JAR
# ---------------------------------------------------------------------------

begin_test "Upload plugin JAR"
if [ "$HANDLER_AVAILABLE" = false ]; then
  skip "jetbrains handler not available"
else
  # Try raw upload with headers (avoids multipart parsing quirks)
  UPLOAD_CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST \
    -H "$(format_auth_header)" \
    -H "Content-Type: application/octet-stream" \
    -H "x-plugin-name: ${PLUGIN_ID}" \
    -H "x-plugin-version: ${PLUGIN_VERSION}" \
    --data-binary "@${WORK_DIR}/test-plugin-${PLUGIN_VERSION}.jar" \
    "${JB_URL}/plugin/uploadPlugin") || true

  if [ "$UPLOAD_CODE" -ge 200 ] 2>/dev/null && [ "$UPLOAD_CODE" -lt 300 ] 2>/dev/null; then
    pass
  else
    # Fallback: try multipart upload
    UPLOAD_CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST \
      -H "$(format_auth_header)" \
      -F "name=${PLUGIN_ID}" \
      -F "version=${PLUGIN_VERSION}" \
      -F "file=@${WORK_DIR}/test-plugin-${PLUGIN_VERSION}.jar;type=application/octet-stream" \
      "${JB_URL}/plugin/uploadPlugin") || true
    if [ "$UPLOAD_CODE" -ge 200 ] 2>/dev/null && [ "$UPLOAD_CODE" -lt 300 ] 2>/dev/null; then
      pass
    else
      fail "upload plugin JAR failed (HTTP ${UPLOAD_CODE})"
    fi
  fi
fi

# ---------------------------------------------------------------------------
# Query plugin repository XML
# ---------------------------------------------------------------------------

begin_test "Query plugin repository XML"
if [ "$HANDLER_AVAILABLE" = false ]; then
  skip "jetbrains handler not available"
else
  sleep 1
  if resp=$(curl -sf "${JB_URL}/plugins/list/" -H "$(format_auth_header)"); then
    if assert_contains "$resp" "$PLUGIN_ID" "plugin list XML should contain plugin ID"; then
      pass
    fi
  else
    fail "could not retrieve plugin listing XML from /plugins/list/"
  fi
fi

# ---------------------------------------------------------------------------
# Download plugin JAR back
# ---------------------------------------------------------------------------

begin_test "Download plugin JAR"
if [ "$HANDLER_AVAILABLE" = false ]; then
  skip "jetbrains handler not available"
else
  DL_FILE="${WORK_DIR}/downloaded-plugin.jar"
  if curl -sf -H "$(format_auth_header)" -o "$DL_FILE" \
    "${JB_URL}/plugin/download/${PLUGIN_ID}/${PLUGIN_VERSION}"; then
    DL_SIZE=$(wc -c < "$DL_FILE" | tr -d ' ')
    ORIG_SIZE=$(wc -c < "${WORK_DIR}/test-plugin-${PLUGIN_VERSION}.jar" | tr -d ' ')
    if assert_eq "$DL_SIZE" "$ORIG_SIZE" "downloaded JAR size should match original"; then
      pass
    fi
  else
    fail "download plugin JAR failed"
  fi
fi

# ---------------------------------------------------------------------------
# Verify artifacts via management API
# ---------------------------------------------------------------------------

begin_test "List artifacts via management API"
if [ "$HANDLER_AVAILABLE" = false ]; then
  skip "jetbrains handler not available"
else
  if resp=$(api_get "/api/v1/repositories/${REPO_KEY}/artifacts"); then
    if assert_contains "$resp" "$PLUGIN_ID" "artifact list should contain plugin ID"; then
      pass
    fi
  else
    fail "GET /api/v1/repositories/${REPO_KEY}/artifacts returned error"
  fi
fi

end_suite
