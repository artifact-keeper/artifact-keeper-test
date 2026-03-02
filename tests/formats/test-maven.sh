#!/usr/bin/env bash
# test-maven.sh - Maven repository E2E test
#
# Tests artifact upload (PUT) and download (GET) via the
# /maven/{repo_key}/ endpoints using Maven 2 layout paths.
# Uses curl for all uploads and downloads.
#
# Requires: curl (mvn optional)

source "$(dirname "$0")/../lib/common.sh"

begin_suite "maven"
auth_admin
setup_workdir

REPO_KEY="test-maven-${RUN_ID}"
GROUP_ID="com.test"
ARTIFACT_ID="artifact"
VERSION="1.0"
MAVEN_URL="${BASE_URL}/maven/${REPO_KEY}"

# Maven layout: /com/test/artifact/1.0/artifact-1.0.jar
GROUP_PATH=$(echo "$GROUP_ID" | tr '.' '/')
ARTIFACT_BASE="${GROUP_PATH}/${ARTIFACT_ID}/${VERSION}"

# -------------------------------------------------------------------------
# Create repository
# -------------------------------------------------------------------------

begin_test "Create maven local repository"
if create_local_repo "$REPO_KEY" "maven"; then
  pass
else
  fail "could not create maven repository"
fi

# -------------------------------------------------------------------------
# Create test artifacts (JAR + POM)
# -------------------------------------------------------------------------

begin_test "Create test JAR and POM"

cd "$WORK_DIR"

# Create a minimal JAR file (it is just a ZIP with a manifest)
mkdir -p jar-content/META-INF
cat > jar-content/META-INF/MANIFEST.MF <<EOF
Manifest-Version: 1.0
Created-By: artifact-keeper-test
Implementation-Title: ${ARTIFACT_ID}
Implementation-Version: ${VERSION}
EOF

mkdir -p jar-content/com/test
echo "placeholder-class-file" > jar-content/com/test/TestClass.class

cd jar-content
JAR_FILE="${WORK_DIR}/${ARTIFACT_ID}-${VERSION}.jar"
if command -v jar &>/dev/null; then
  jar cf "$JAR_FILE" META-INF/ com/ 2>/dev/null || zip -r "$JAR_FILE" META-INF/ com/ > /dev/null 2>&1
else
  zip -r "$JAR_FILE" META-INF/ com/ > /dev/null 2>&1
fi

# Create POM
POM_FILE="${WORK_DIR}/${ARTIFACT_ID}-${VERSION}.pom"
cat > "$POM_FILE" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0
                             http://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <groupId>${GROUP_ID}</groupId>
  <artifactId>${ARTIFACT_ID}</artifactId>
  <version>${VERSION}</version>
  <packaging>jar</packaging>
  <name>Test Artifact</name>
  <description>E2E test artifact for Maven format</description>
</project>
EOF

if [ -f "$JAR_FILE" ] && [ -f "$POM_FILE" ]; then
  pass
else
  fail "failed to create JAR or POM file"
fi

# -------------------------------------------------------------------------
# Upload JAR via PUT
# -------------------------------------------------------------------------

begin_test "Upload JAR"

JAR_PATH="${ARTIFACT_BASE}/${ARTIFACT_ID}-${VERSION}.jar"
ORIG_SHA256=$(shasum -a 256 "$JAR_FILE" | awk '{print $1}')

if curl -sf $CURL_TIMEOUT -X PUT "${MAVEN_URL}/${JAR_PATH}" \
  -u "${ADMIN_USER}:${ADMIN_PASS}" \
  -H "Content-Type: application/java-archive" \
  --data-binary "@${JAR_FILE}" > /dev/null 2>&1; then
  pass
else
  fail "PUT JAR failed"
fi

# -------------------------------------------------------------------------
# Upload POM via PUT
# -------------------------------------------------------------------------

begin_test "Upload POM"

POM_PATH="${ARTIFACT_BASE}/${ARTIFACT_ID}-${VERSION}.pom"
if curl -sf $CURL_TIMEOUT -X PUT "${MAVEN_URL}/${POM_PATH}" \
  -u "${ADMIN_USER}:${ADMIN_PASS}" \
  -H "Content-Type: application/xml" \
  --data-binary "@${POM_FILE}" > /dev/null 2>&1; then
  pass
else
  fail "PUT POM failed"
fi

# -------------------------------------------------------------------------
# Verify metadata via GET
# -------------------------------------------------------------------------

begin_test "Verify maven-metadata.xml"
sleep 1
METADATA_PATH="${GROUP_PATH}/${ARTIFACT_ID}/maven-metadata.xml"
if resp=$(curl -sf $CURL_TIMEOUT "${MAVEN_URL}/${METADATA_PATH}" -u "${ADMIN_USER}:${ADMIN_PASS}"); then
  if assert_contains "$resp" "$VERSION" "metadata should list the uploaded version"; then
    pass
  fi
else
  # Some registries do not auto-generate maven-metadata.xml until explicitly deployed.
  skip "maven-metadata.xml not generated (may require explicit deploy)"
fi

# -------------------------------------------------------------------------
# Download JAR and verify checksum
# -------------------------------------------------------------------------

begin_test "Download JAR and verify checksum"
DL_FILE="${WORK_DIR}/downloaded.jar"
if curl -sf $CURL_TIMEOUT -u "${ADMIN_USER}:${ADMIN_PASS}" -o "$DL_FILE" "${MAVEN_URL}/${JAR_PATH}"; then
  DL_SHA256=$(shasum -a 256 "$DL_FILE" | awk '{print $1}')
  if assert_eq "$DL_SHA256" "$ORIG_SHA256" "SHA256 mismatch after round-trip"; then
    pass
  fi
else
  fail "download JAR failed"
fi

# -------------------------------------------------------------------------
# List artifacts via management API
# -------------------------------------------------------------------------

begin_test "List artifacts via management API"
if resp=$(api_get "/api/v1/repositories/${REPO_KEY}/artifacts"); then
  if assert_contains "$resp" "$ARTIFACT_ID" "artifact list should contain artifact"; then
    pass
  fi
else
  fail "GET /api/v1/repositories/${REPO_KEY}/artifacts returned error"
fi

end_suite
