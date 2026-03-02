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
if resp=$(curl -sf -X PUT \
  -H "$(format_auth_header)" \
  -H "Content-Type: application/java-archive" \
  --data-binary "@${WORK_DIR}/test-plugin-${PLUGIN_VERSION}.jar" \
  "${JB_URL}/plugins/${PLUGIN_ID}/${PLUGIN_VERSION}/test-plugin-${PLUGIN_VERSION}.jar" 2>&1); then
  pass
else
  fail "upload plugin JAR failed: ${resp}"
fi

# ---------------------------------------------------------------------------
# Query plugin repository XML
# ---------------------------------------------------------------------------

begin_test "Query plugin repository XML"
sleep 1
if resp=$(curl -sf "${JB_URL}/plugins.xml" -H "$(format_auth_header)"); then
  if assert_contains "$resp" "$PLUGIN_ID" "plugins.xml should contain plugin ID"; then
    pass
  fi
else
  # Try updatePlugins.xml as an alternative endpoint
  if resp=$(curl -sf "${JB_URL}/updatePlugins.xml" -H "$(format_auth_header)"); then
    if assert_contains "$resp" "$PLUGIN_ID" "updatePlugins.xml should contain plugin ID"; then
      pass
    fi
  else
    fail "could not retrieve plugin listing XML"
  fi
fi

# ---------------------------------------------------------------------------
# Download plugin JAR back
# ---------------------------------------------------------------------------

begin_test "Download plugin JAR"
DL_FILE="${WORK_DIR}/downloaded-plugin.jar"
if curl -sf -H "$(format_auth_header)" -o "$DL_FILE" \
  "${JB_URL}/plugins/${PLUGIN_ID}/${PLUGIN_VERSION}/test-plugin-${PLUGIN_VERSION}.jar"; then
  DL_SIZE=$(wc -c < "$DL_FILE" | tr -d ' ')
  ORIG_SIZE=$(wc -c < "${WORK_DIR}/test-plugin-${PLUGIN_VERSION}.jar" | tr -d ' ')
  if assert_eq "$DL_SIZE" "$ORIG_SIZE" "downloaded JAR size should match original"; then
    pass
  fi
else
  fail "download plugin JAR failed"
fi

# ---------------------------------------------------------------------------
# Verify artifacts via management API
# ---------------------------------------------------------------------------

begin_test "List artifacts via management API"
if resp=$(api_get "/api/v1/repositories/${REPO_KEY}/artifacts"); then
  if assert_contains "$resp" "$PLUGIN_ID" "artifact list should contain plugin ID"; then
    pass
  fi
else
  fail "GET /api/v1/repositories/${REPO_KEY}/artifacts returned error"
fi

end_suite
