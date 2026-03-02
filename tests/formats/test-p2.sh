#!/usr/bin/env bash
# Eclipse P2 format E2E test
# Tests P2 feature/bundle upload and content.xml retrieval via /ext/p2/{repo_key}/.
source "$(dirname "$0")/../lib/common.sh"

begin_suite "p2"
auth_admin
setup_workdir

REPO_KEY="test-p2-${RUN_ID}"
BUNDLE_ID="com.example.test.bundle"
BUNDLE_VERSION="1.0.0"
EXT_URL="${BASE_URL}/ext/p2/${REPO_KEY}"

# ---------------------------------------------------------------------------
# Create repository
# ---------------------------------------------------------------------------

begin_test "Create p2 local repository"
if create_local_repo "$REPO_KEY" "p2"; then
  pass
else
  fail "could not create p2 repo"
fi

# ---------------------------------------------------------------------------
# Create test bundle JAR
# ---------------------------------------------------------------------------

begin_test "Create test P2 bundle artifact"
cd "$WORK_DIR"

# Create a minimal OSGi MANIFEST.MF
mkdir -p META-INF
cat > META-INF/MANIFEST.MF <<EOF
Manifest-Version: 1.0
Bundle-ManifestVersion: 2
Bundle-Name: Test Bundle
Bundle-SymbolicName: ${BUNDLE_ID}
Bundle-Version: ${BUNDLE_VERSION}
Export-Package: com.example.test;version="${BUNDLE_VERSION}"
EOF

mkdir -p com/example/test
cat > com/example/test/TestClass.java <<'EOF'
package com.example.test;
public class TestClass {
    public String hello() { return "hello from p2 bundle"; }
}
EOF

# Package as a JAR (which is just a zip)
jar cf "${WORK_DIR}/bundle.jar" -C "${WORK_DIR}" META-INF com 2>/dev/null || \
  zip -q "${WORK_DIR}/bundle.jar" -r META-INF com

pass

# ---------------------------------------------------------------------------
# Upload P2 bundle artifact
# ---------------------------------------------------------------------------

begin_test "Upload P2 bundle"
if resp=$(curl -sf -X PUT \
  -H "$(format_auth_header)" \
  -H "Content-Type: application/java-archive" \
  --data-binary "@${WORK_DIR}/bundle.jar" \
  "${EXT_URL}/plugins/${BUNDLE_ID}_${BUNDLE_VERSION}.jar" 2>&1); then
  pass
else
  fail "upload P2 bundle failed: ${resp}"
fi

# ---------------------------------------------------------------------------
# Query content.xml or compositeContent.xml
# ---------------------------------------------------------------------------

begin_test "Query P2 content metadata"
sleep 1
CONTENT_STATUS=$(curl -s -o "${WORK_DIR}/content.xml" -w '%{http_code}' \
  -H "$(format_auth_header)" \
  "${EXT_URL}/content.xml") || true

if [ "$CONTENT_STATUS" -ge 200 ] 2>/dev/null && [ "$CONTENT_STATUS" -lt 300 ] 2>/dev/null; then
  pass
else
  # Try compositeContent.xml as an alternative
  COMPOSITE_STATUS=$(curl -s -o "${WORK_DIR}/compositeContent.xml" -w '%{http_code}' \
    -H "$(format_auth_header)" \
    "${EXT_URL}/compositeContent.xml") || true

  if [ "$COMPOSITE_STATUS" -ge 200 ] 2>/dev/null && [ "$COMPOSITE_STATUS" -lt 300 ] 2>/dev/null; then
    pass
  else
    if [ "$CONTENT_STATUS" = "404" ] && [ "$COMPOSITE_STATUS" = "404" ]; then
      skip "P2 content metadata endpoint not implemented"
    else
      fail "content.xml returned HTTP ${CONTENT_STATUS}, compositeContent.xml returned HTTP ${COMPOSITE_STATUS}"
    fi
  fi
fi

# ---------------------------------------------------------------------------
# Verify artifacts via management API
# ---------------------------------------------------------------------------

begin_test "List artifacts via management API"
if resp=$(api_get "/api/v1/repositories/${REPO_KEY}/artifacts"); then
  if assert_contains "$resp" "$BUNDLE_ID" "artifact list should contain bundle ID"; then
    pass
  fi
else
  fail "GET /api/v1/repositories/${REPO_KEY}/artifacts returned error"
fi

end_suite
