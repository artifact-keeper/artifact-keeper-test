#!/usr/bin/env bash
# test-maven-conformance.sh - Maven repository layout and metadata conformance tests
#
# Validates that the Maven repository implementation conforms to the Maven 2
# repository layout specification. Tests cover artifact deployment, checksum
# generation, metadata XML structure, snapshot versioning, classifier support,
# content types, directory listing, and GPG signature hosting.
#
# Requires: curl, shasum (or sha256sum), zip or jar

source "$(dirname "$0")/../lib/common.sh"

begin_suite "maven-conformance"
auth_admin
setup_workdir

REPO_KEY="test-mvn-conf-${RUN_ID}"
SNAP_REPO_KEY="test-mvn-conf-snap-${RUN_ID}"
GROUP_ID="com.example.conformance"
ARTIFACT_ID="conf-artifact"
VERSION="1.0.0"
MAVEN_URL="${BASE_URL}/maven/${REPO_KEY}"
GROUP_PATH=$(echo "$GROUP_ID" | tr '.' '/')
ARTIFACT_BASE="${GROUP_PATH}/${ARTIFACT_ID}/${VERSION}"

# -------------------------------------------------------------------------
# Setup: create repositories
# -------------------------------------------------------------------------

begin_test "Create local Maven release repository"
if create_local_repo "$REPO_KEY" "maven"; then
  pass
else
  fail "could not create Maven release repository"
fi

begin_test "Create local Maven snapshot repository"
if create_local_repo "$SNAP_REPO_KEY" "maven"; then
  pass
else
  fail "could not create Maven snapshot repository"
fi

# -------------------------------------------------------------------------
# Build test artifacts
# -------------------------------------------------------------------------

cd "$WORK_DIR"
mkdir -p jar-content/META-INF jar-content/com/example
cat > jar-content/META-INF/MANIFEST.MF <<EOF
Manifest-Version: 1.0
Created-By: artifact-keeper-test
Implementation-Title: ${ARTIFACT_ID}
Implementation-Version: ${VERSION}
EOF
echo "placeholder-class-file-${RUN_ID}" > jar-content/com/example/Main.class

cd jar-content
JAR_FILE="${WORK_DIR}/${ARTIFACT_ID}-${VERSION}.jar"
if command -v jar &>/dev/null; then
  jar cf "$JAR_FILE" META-INF/ com/ 2>/dev/null || zip -r "$JAR_FILE" META-INF/ com/ > /dev/null 2>&1
else
  zip -r "$JAR_FILE" META-INF/ com/ > /dev/null 2>&1
fi
cd "$WORK_DIR"

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
  <name>Conformance Test Artifact</name>
  <description>Maven repository layout conformance test artifact</description>
</project>
EOF

JAR_SHA256=$(shasum -a 256 "$JAR_FILE" | awk '{print $1}')
JAR_SHA1=$(shasum -a 1 "$JAR_FILE" | awk '{print $1}')
JAR_MD5=$(md5 -q "$JAR_FILE" 2>/dev/null || md5sum "$JAR_FILE" 2>/dev/null | awk '{print $1}')

POM_SHA256=$(shasum -a 256 "$POM_FILE" | awk '{print $1}')
POM_SHA1=$(shasum -a 1 "$POM_FILE" | awk '{print $1}')
POM_MD5=$(md5 -q "$POM_FILE" 2>/dev/null || md5sum "$POM_FILE" 2>/dev/null | awk '{print $1}')

# =========================================================================
# Test 1: Deploy JAR
# =========================================================================

begin_test "Deploy JAR via PUT"
JAR_PATH="${ARTIFACT_BASE}/${ARTIFACT_ID}-${VERSION}.jar"
if curl -sf $CURL_TIMEOUT -X PUT "${MAVEN_URL}/${JAR_PATH}" \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    -H "Content-Type: application/java-archive" \
    --data-binary "@${JAR_FILE}" > /dev/null 2>&1; then
  pass
else
  fail "PUT JAR to ${JAR_PATH} failed"
fi

# =========================================================================
# Test 2: Deploy POM
# =========================================================================

begin_test "Deploy POM alongside JAR"
POM_PATH="${ARTIFACT_BASE}/${ARTIFACT_ID}-${VERSION}.pom"
if curl -sf $CURL_TIMEOUT -X PUT "${MAVEN_URL}/${POM_PATH}" \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    -H "Content-Type: application/xml" \
    --data-binary "@${POM_FILE}" > /dev/null 2>&1; then
  pass
else
  fail "PUT POM to ${POM_PATH} failed"
fi

# =========================================================================
# Test 3: Checksum files (explicit upload)
# =========================================================================

begin_test "Upload and retrieve explicit checksum files"
# Upload SHA1 and MD5 for the JAR
UPLOAD_OK=true
if ! printf '%s' "$JAR_SHA1" | curl -sf $CURL_TIMEOUT -X PUT "${MAVEN_URL}/${JAR_PATH}.sha1" \
    -u "${ADMIN_USER}:${ADMIN_PASS}" --data-binary @- > /dev/null 2>&1; then
  UPLOAD_OK=false
fi
if ! printf '%s' "$JAR_MD5" | curl -sf $CURL_TIMEOUT -X PUT "${MAVEN_URL}/${JAR_PATH}.md5" \
    -u "${ADMIN_USER}:${ADMIN_PASS}" --data-binary @- > /dev/null 2>&1; then
  UPLOAD_OK=false
fi

# Now retrieve them and verify
if $UPLOAD_OK; then
  GOT_SHA1=$(curl -sf $CURL_TIMEOUT -u "${ADMIN_USER}:${ADMIN_PASS}" \
      "${MAVEN_URL}/${JAR_PATH}.sha1" 2>/dev/null | tr -d '[:space:]')
  GOT_MD5=$(curl -sf $CURL_TIMEOUT -u "${ADMIN_USER}:${ADMIN_PASS}" \
      "${MAVEN_URL}/${JAR_PATH}.md5" 2>/dev/null | tr -d '[:space:]')
  if assert_eq "$GOT_SHA1" "$JAR_SHA1" "SHA1 checksum mismatch for JAR" && \
     assert_eq "$GOT_MD5" "$JAR_MD5" "MD5 checksum mismatch for JAR"; then
    pass
  fi
else
  fail "failed to upload checksum files"
fi

# =========================================================================
# Test 4: Auto-generated checksums
# =========================================================================

begin_test "Auto-generated SHA256 checksum for uploaded artifact"
# The server should auto-generate .sha256 even if not explicitly uploaded
GOT_SHA256=$(curl -sf $CURL_TIMEOUT -u "${ADMIN_USER}:${ADMIN_PASS}" \
    "${MAVEN_URL}/${JAR_PATH}.sha256" 2>/dev/null | tr -d '[:space:]') || true

if [ -n "$GOT_SHA256" ]; then
  if assert_eq "$GOT_SHA256" "$JAR_SHA256" "auto-generated SHA256 does not match actual artifact checksum"; then
    pass
  fi
else
  skip "server does not auto-generate .sha256 checksum files"
fi

# =========================================================================
# Test 5: Download JAR with content verification
# =========================================================================

begin_test "Download JAR returns exact uploaded content"
DL_JAR="${WORK_DIR}/downloaded.jar"
if curl -sf $CURL_TIMEOUT -u "${ADMIN_USER}:${ADMIN_PASS}" \
    -o "$DL_JAR" "${MAVEN_URL}/${JAR_PATH}"; then
  DL_SHA256=$(shasum -a 256 "$DL_JAR" | awk '{print $1}')
  if assert_eq "$DL_SHA256" "$JAR_SHA256" "JAR content changed during round-trip"; then
    pass
  fi
else
  fail "GET JAR from ${JAR_PATH} failed"
fi

# =========================================================================
# Test 6: Download POM with content verification
# =========================================================================

begin_test "Download POM returns exact uploaded content"
DL_POM="${WORK_DIR}/downloaded.pom"
if curl -sf $CURL_TIMEOUT -u "${ADMIN_USER}:${ADMIN_PASS}" \
    -o "$DL_POM" "${MAVEN_URL}/${POM_PATH}"; then
  DL_POM_SHA256=$(shasum -a 256 "$DL_POM" | awk '{print $1}')
  if assert_eq "$DL_POM_SHA256" "$POM_SHA256" "POM content changed during round-trip"; then
    pass
  fi
else
  fail "GET POM from ${POM_PATH} failed"
fi

# =========================================================================
# Test 7: maven-metadata.xml at artifact level lists version
# =========================================================================

begin_test "maven-metadata.xml lists deployed version"
sleep 1
METADATA_PATH="${GROUP_PATH}/${ARTIFACT_ID}/maven-metadata.xml"
if metadata=$(curl -sf $CURL_TIMEOUT -u "${ADMIN_USER}:${ADMIN_PASS}" \
    "${MAVEN_URL}/${METADATA_PATH}" 2>/dev/null); then
  if assert_contains "$metadata" "<version>${VERSION}</version>" \
      "metadata should list version ${VERSION}"; then
    pass
  fi
else
  skip "maven-metadata.xml not auto-generated by server"
fi

# =========================================================================
# Test 8: Snapshot metadata includes timestamp and build number
# =========================================================================

SNAP_VERSION="2.0.0-SNAPSHOT"
SNAP_BASE_VERSION="2.0.0"
SNAP_TIMESTAMP=$(date -u '+%Y%m%d.%H%M%S')
SNAP_BUILD=1
SNAP_MAVEN_URL="${BASE_URL}/maven/${SNAP_REPO_KEY}"
SNAP_GROUP_PATH="${GROUP_PATH}"
SNAP_ARTIFACT_BASE="${SNAP_GROUP_PATH}/${ARTIFACT_ID}/${SNAP_VERSION}"
SNAP_JAR_NAME="${ARTIFACT_ID}-${SNAP_BASE_VERSION}-${SNAP_TIMESTAMP}-${SNAP_BUILD}.jar"

begin_test "Deploy SNAPSHOT JAR with timestamp"
if curl -sf $CURL_TIMEOUT -X PUT \
    "${SNAP_MAVEN_URL}/${SNAP_ARTIFACT_BASE}/${SNAP_JAR_NAME}" \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    --data-binary "@${JAR_FILE}" > /dev/null 2>&1; then
  pass
else
  fail "PUT SNAPSHOT timestamped JAR failed"
fi

begin_test "SNAPSHOT metadata includes timestamp and build number"
# Upload version-level maven-metadata.xml with snapshot info
SNAP_META="<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<metadata modelVersion=\"1.1.0\">
  <groupId>${GROUP_ID}</groupId>
  <artifactId>${ARTIFACT_ID}</artifactId>
  <version>${SNAP_VERSION}</version>
  <versioning>
    <snapshot>
      <timestamp>${SNAP_TIMESTAMP}</timestamp>
      <buildNumber>${SNAP_BUILD}</buildNumber>
    </snapshot>
    <lastUpdated>$(echo "$SNAP_TIMESTAMP" | tr -d '.')</lastUpdated>
    <snapshotVersions>
      <snapshotVersion>
        <extension>jar</extension>
        <value>${SNAP_BASE_VERSION}-${SNAP_TIMESTAMP}-${SNAP_BUILD}</value>
        <updated>$(echo "$SNAP_TIMESTAMP" | tr -d '.')</updated>
      </snapshotVersion>
    </snapshotVersions>
  </versioning>
</metadata>"

if printf '%s' "$SNAP_META" | curl -sf $CURL_TIMEOUT -X PUT \
    "${SNAP_MAVEN_URL}/${SNAP_ARTIFACT_BASE}/maven-metadata.xml" \
    -u "${ADMIN_USER}:${ADMIN_PASS}" --data-binary @- > /dev/null 2>&1; then
  # Read it back and verify structure
  if resp=$(curl -sf $CURL_TIMEOUT -u "${ADMIN_USER}:${ADMIN_PASS}" \
      "${SNAP_MAVEN_URL}/${SNAP_ARTIFACT_BASE}/maven-metadata.xml" 2>/dev/null); then
    if assert_contains "$resp" "<timestamp>" "metadata should contain <timestamp>" && \
       assert_contains "$resp" "<buildNumber>" "metadata should contain <buildNumber>"; then
      pass
    fi
  else
    fail "could not read back SNAPSHOT metadata"
  fi
else
  fail "PUT SNAPSHOT maven-metadata.xml failed"
fi

# =========================================================================
# Test 9: Metadata merging (upload two versions, metadata lists both)
# =========================================================================

VERSION_2="1.1.0"
ARTIFACT_BASE_V2="${GROUP_PATH}/${ARTIFACT_ID}/${VERSION_2}"

begin_test "Metadata merging across multiple versions"
# Create a slightly different JAR for version 2
echo "v2-content-${RUN_ID}" > "${WORK_DIR}/v2-payload.txt"
V2_JAR="${WORK_DIR}/${ARTIFACT_ID}-${VERSION_2}.jar"
cd "$WORK_DIR"
if command -v jar &>/dev/null; then
  jar cf "$V2_JAR" v2-payload.txt 2>/dev/null || zip -r "$V2_JAR" v2-payload.txt > /dev/null 2>&1
else
  zip -r "$V2_JAR" v2-payload.txt > /dev/null 2>&1
fi

# Deploy version 2 JAR
V2_JAR_PATH="${ARTIFACT_BASE_V2}/${ARTIFACT_ID}-${VERSION_2}.jar"
if curl -sf $CURL_TIMEOUT -X PUT "${MAVEN_URL}/${V2_JAR_PATH}" \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    --data-binary "@${V2_JAR}" > /dev/null 2>&1; then
  sleep 1
  # Check metadata includes both versions
  if metadata=$(curl -sf $CURL_TIMEOUT -u "${ADMIN_USER}:${ADMIN_PASS}" \
      "${MAVEN_URL}/${METADATA_PATH}" 2>/dev/null); then
    HAS_V1=$(echo "$metadata" | grep -c "<version>${VERSION}</version>") || true
    HAS_V2=$(echo "$metadata" | grep -c "<version>${VERSION_2}</version>") || true
    if [ "$HAS_V1" -ge 1 ] && [ "$HAS_V2" -ge 1 ]; then
      pass
    else
      fail "maven-metadata.xml does not list both versions (v1: ${HAS_V1}, v2: ${HAS_V2})"
    fi
  else
    skip "maven-metadata.xml not auto-generated after multiple deploys"
  fi
else
  fail "PUT version ${VERSION_2} JAR failed"
fi

# =========================================================================
# Test 10: Snapshot versioning resolves to latest snapshot
# =========================================================================

begin_test "Snapshot versioning resolves latest snapshot"
# Deploy a second snapshot build
sleep 1
SNAP_TIMESTAMP2=$(date -u '+%Y%m%d.%H%M%S')
SNAP_BUILD2=2
SNAP_JAR_NAME2="${ARTIFACT_ID}-${SNAP_BASE_VERSION}-${SNAP_TIMESTAMP2}-${SNAP_BUILD2}.jar"

# Create distinct content for build 2
echo "snapshot-build-2-${RUN_ID}" > "${WORK_DIR}/snap2-payload.txt"
SNAP2_JAR="${WORK_DIR}/snap-build2.jar"
if command -v jar &>/dev/null; then
  jar cf "$SNAP2_JAR" "${WORK_DIR}/snap2-payload.txt" 2>/dev/null || \
    zip -r "$SNAP2_JAR" "${WORK_DIR}/snap2-payload.txt" > /dev/null 2>&1
else
  zip -r "$SNAP2_JAR" "${WORK_DIR}/snap2-payload.txt" > /dev/null 2>&1
fi

if curl -sf $CURL_TIMEOUT -X PUT \
    "${SNAP_MAVEN_URL}/${SNAP_ARTIFACT_BASE}/${SNAP_JAR_NAME2}" \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    --data-binary "@${SNAP2_JAR}" > /dev/null 2>&1; then
  # Update metadata to reflect build 2 as latest
  SNAP_META2="<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<metadata modelVersion=\"1.1.0\">
  <groupId>${GROUP_ID}</groupId>
  <artifactId>${ARTIFACT_ID}</artifactId>
  <version>${SNAP_VERSION}</version>
  <versioning>
    <snapshot>
      <timestamp>${SNAP_TIMESTAMP2}</timestamp>
      <buildNumber>${SNAP_BUILD2}</buildNumber>
    </snapshot>
    <lastUpdated>$(echo "$SNAP_TIMESTAMP2" | tr -d '.')</lastUpdated>
    <snapshotVersions>
      <snapshotVersion>
        <extension>jar</extension>
        <value>${SNAP_BASE_VERSION}-${SNAP_TIMESTAMP2}-${SNAP_BUILD2}</value>
        <updated>$(echo "$SNAP_TIMESTAMP2" | tr -d '.')</updated>
      </snapshotVersion>
    </snapshotVersions>
  </versioning>
</metadata>"

  printf '%s' "$SNAP_META2" | curl -sf $CURL_TIMEOUT -X PUT \
      "${SNAP_MAVEN_URL}/${SNAP_ARTIFACT_BASE}/maven-metadata.xml" \
      -u "${ADMIN_USER}:${ADMIN_PASS}" --data-binary @- > /dev/null 2>&1

  # Verify build 2 artifact is accessible
  if curl -sf $CURL_TIMEOUT -u "${ADMIN_USER}:${ADMIN_PASS}" \
      "${SNAP_MAVEN_URL}/${SNAP_ARTIFACT_BASE}/${SNAP_JAR_NAME2}" > /dev/null 2>&1; then
    pass
  else
    fail "latest snapshot build (build 2) is not accessible"
  fi
else
  fail "PUT second SNAPSHOT build failed"
fi

# =========================================================================
# Test 11: GPG signature hosting (.asc files)
# =========================================================================

begin_test "GPG signature file upload and download"
# Create a fake GPG signature (real signatures are binary, but the server
# should accept and return any .asc content)
ASC_CONTENT="-----BEGIN PGP SIGNATURE-----
Version: GnuPG v1
iQEcBAABAgAGFAKESignatureContentForTestingPurposes
=fake
-----END PGP SIGNATURE-----"

ASC_PATH="${JAR_PATH}.asc"
UPLOAD_OK=false
if printf '%s' "$ASC_CONTENT" | curl -sf $CURL_TIMEOUT -X PUT "${MAVEN_URL}/${ASC_PATH}" \
    -u "${ADMIN_USER}:${ADMIN_PASS}" --data-binary @- > /dev/null 2>&1; then
  UPLOAD_OK=true
fi

if $UPLOAD_OK; then
  GOT_ASC=$(curl -sf $CURL_TIMEOUT -u "${ADMIN_USER}:${ADMIN_PASS}" \
      "${MAVEN_URL}/${ASC_PATH}" 2>/dev/null) || true
  if [ -n "$GOT_ASC" ] && echo "$GOT_ASC" | grep -q "PGP SIGNATURE"; then
    pass
  else
    fail "downloaded .asc file does not contain expected PGP signature content"
  fi
else
  fail "PUT .asc signature file failed"
fi

# =========================================================================
# Test 12: Directory listing
# =========================================================================

begin_test "Directory listing returns file index"
DIR_PATH="${GROUP_PATH}/${ARTIFACT_ID}/${VERSION}/"
DIR_RESP=$(curl -sf $CURL_TIMEOUT -u "${ADMIN_USER}:${ADMIN_PASS}" \
    "${MAVEN_URL}/${DIR_PATH}" 2>/dev/null) || true

if [ -n "$DIR_RESP" ]; then
  # Directory listing should reference the JAR file name in some form
  # (HTML listing, XML index, or JSON, depending on server implementation)
  if assert_contains "$DIR_RESP" "${ARTIFACT_ID}-${VERSION}.jar" \
      "directory listing should include the deployed JAR"; then
    pass
  fi
else
  skip "server does not support directory listing for Maven paths"
fi

# =========================================================================
# Test 13: Content-Type for JAR downloads
# =========================================================================

begin_test "Content-Type for JAR is application/java-archive or application/octet-stream"
CT_JAR=$(curl -sf $CURL_TIMEOUT -o /dev/null -w '%{content_type}' \
    -u "${ADMIN_USER}:${ADMIN_PASS}" "${MAVEN_URL}/${JAR_PATH}") || true

if [ -n "$CT_JAR" ]; then
  case "$CT_JAR" in
    application/java-archive*|application/octet-stream*)
      pass
      ;;
    *)
      fail "unexpected Content-Type for JAR: ${CT_JAR} (expected application/java-archive or application/octet-stream)"
      ;;
  esac
else
  fail "could not determine Content-Type for JAR download"
fi

# =========================================================================
# Test 14: Content-Type for POM downloads
# =========================================================================

begin_test "Content-Type for POM is application/xml or text/xml"
CT_POM=$(curl -sf $CURL_TIMEOUT -o /dev/null -w '%{content_type}' \
    -u "${ADMIN_USER}:${ADMIN_PASS}" "${MAVEN_URL}/${POM_PATH}") || true

if [ -n "$CT_POM" ]; then
  case "$CT_POM" in
    application/xml*|text/xml*)
      pass
      ;;
    *)
      fail "unexpected Content-Type for POM: ${CT_POM} (expected application/xml or text/xml)"
      ;;
  esac
else
  fail "could not determine Content-Type for POM download"
fi

# =========================================================================
# Test 15: 404 on missing artifact
# =========================================================================

begin_test "GET nonexistent artifact returns 404"
MISSING_PATH="${GROUP_PATH}/nonexistent-artifact/99.99/nonexistent-artifact-99.99.jar"
HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -u "${ADMIN_USER}:${ADMIN_PASS}" "${MAVEN_URL}/${MISSING_PATH}") || true

if assert_eq "$HTTP_CODE" "404" "expected 404 for missing artifact, got ${HTTP_CODE}"; then
  pass
fi

# =========================================================================
# Test 16: Group path encoding (dots to slashes)
# =========================================================================

begin_test "Group with dots maps to directory path"
# Deploy to a deeply nested group ID to verify dot-to-slash mapping
DEEP_GROUP="org.apache.commons.lang3"
DEEP_GROUP_PATH="org/apache/commons/lang3"
DEEP_ARTIFACT="deep-test"
DEEP_VERSION="1.0"
DEEP_JAR_PATH="${DEEP_GROUP_PATH}/${DEEP_ARTIFACT}/${DEEP_VERSION}/${DEEP_ARTIFACT}-${DEEP_VERSION}.jar"

echo "deep-group-test-${RUN_ID}" > "${WORK_DIR}/deep.txt"
DEEP_JAR="${WORK_DIR}/deep.jar"
cd "$WORK_DIR"
if command -v jar &>/dev/null; then
  jar cf "$DEEP_JAR" deep.txt 2>/dev/null || zip -r "$DEEP_JAR" deep.txt > /dev/null 2>&1
else
  zip -r "$DEEP_JAR" deep.txt > /dev/null 2>&1
fi

if curl -sf $CURL_TIMEOUT -X PUT "${MAVEN_URL}/${DEEP_JAR_PATH}" \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    --data-binary "@${DEEP_JAR}" > /dev/null 2>&1; then
  # Verify the artifact is retrievable at the full directory path
  if curl -sf $CURL_TIMEOUT -u "${ADMIN_USER}:${ADMIN_PASS}" \
      "${MAVEN_URL}/${DEEP_JAR_PATH}" > /dev/null 2>&1; then
    pass
  else
    fail "artifact not retrievable at deep group path ${DEEP_JAR_PATH}"
  fi
else
  fail "PUT to deep group path failed"
fi

# =========================================================================
# Test 17: Classifier support (sources and javadoc JARs)
# =========================================================================

begin_test "Deploy and retrieve classifier artifacts (sources, javadoc)"
# Create a sources JAR
echo "// fake source code for ${ARTIFACT_ID}" > "${WORK_DIR}/Main.java"
SOURCES_JAR="${WORK_DIR}/${ARTIFACT_ID}-${VERSION}-sources.jar"
cd "$WORK_DIR"
if command -v jar &>/dev/null; then
  jar cf "$SOURCES_JAR" Main.java 2>/dev/null || zip -r "$SOURCES_JAR" Main.java > /dev/null 2>&1
else
  zip -r "$SOURCES_JAR" Main.java > /dev/null 2>&1
fi
SOURCES_SHA256=$(shasum -a 256 "$SOURCES_JAR" | awk '{print $1}')

# Create a javadoc JAR
echo "<html><body>Javadoc placeholder</body></html>" > "${WORK_DIR}/index.html"
JAVADOC_JAR="${WORK_DIR}/${ARTIFACT_ID}-${VERSION}-javadoc.jar"
if command -v jar &>/dev/null; then
  jar cf "$JAVADOC_JAR" index.html 2>/dev/null || zip -r "$JAVADOC_JAR" index.html > /dev/null 2>&1
else
  zip -r "$JAVADOC_JAR" index.html > /dev/null 2>&1
fi
JAVADOC_SHA256=$(shasum -a 256 "$JAVADOC_JAR" | awk '{print $1}')

SOURCES_PATH="${ARTIFACT_BASE}/${ARTIFACT_ID}-${VERSION}-sources.jar"
JAVADOC_PATH="${ARTIFACT_BASE}/${ARTIFACT_ID}-${VERSION}-javadoc.jar"

ALL_OK=true

# Upload sources JAR
if ! curl -sf $CURL_TIMEOUT -X PUT "${MAVEN_URL}/${SOURCES_PATH}" \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    --data-binary "@${SOURCES_JAR}" > /dev/null 2>&1; then
  ALL_OK=false
  echo "  failed to upload sources JAR"
fi

# Upload javadoc JAR
if ! curl -sf $CURL_TIMEOUT -X PUT "${MAVEN_URL}/${JAVADOC_PATH}" \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    --data-binary "@${JAVADOC_JAR}" > /dev/null 2>&1; then
  ALL_OK=false
  echo "  failed to upload javadoc JAR"
fi

if $ALL_OK; then
  # Download sources JAR and verify content
  DL_SOURCES="${WORK_DIR}/dl-sources.jar"
  DL_JAVADOC="${WORK_DIR}/dl-javadoc.jar"
  if curl -sf $CURL_TIMEOUT -u "${ADMIN_USER}:${ADMIN_PASS}" \
      -o "$DL_SOURCES" "${MAVEN_URL}/${SOURCES_PATH}" && \
     curl -sf $CURL_TIMEOUT -u "${ADMIN_USER}:${ADMIN_PASS}" \
      -o "$DL_JAVADOC" "${MAVEN_URL}/${JAVADOC_PATH}"; then
    DL_SRC_SHA256=$(shasum -a 256 "$DL_SOURCES" | awk '{print $1}')
    DL_DOC_SHA256=$(shasum -a 256 "$DL_JAVADOC" | awk '{print $1}')
    if assert_eq "$DL_SRC_SHA256" "$SOURCES_SHA256" "sources JAR checksum mismatch" && \
       assert_eq "$DL_DOC_SHA256" "$JAVADOC_SHA256" "javadoc JAR checksum mismatch"; then
      pass
    fi
  else
    fail "failed to download classifier artifacts"
  fi
else
  fail "failed to upload one or more classifier JARs"
fi

# =========================================================================
# Test 18: Release repo rejects SNAPSHOT upload (if enforced)
# =========================================================================

begin_test "Release repository rejects SNAPSHOT version upload"
SNAP_IN_RELEASE_VERSION="3.0.0-SNAPSHOT"
SNAP_IN_RELEASE_PATH="${GROUP_PATH}/${ARTIFACT_ID}/${SNAP_IN_RELEASE_VERSION}/${ARTIFACT_ID}-${SNAP_IN_RELEASE_VERSION}.jar"

SNAP_REJECT_HTTP=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X PUT \
    "${MAVEN_URL}/${SNAP_IN_RELEASE_PATH}" \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    --data-binary "@${JAR_FILE}")

if [ "$SNAP_REJECT_HTTP" = "400" ] || [ "$SNAP_REJECT_HTTP" = "409" ] || [ "$SNAP_REJECT_HTTP" = "422" ]; then
  pass
elif [ "$SNAP_REJECT_HTTP" = "200" ] || [ "$SNAP_REJECT_HTTP" = "201" ]; then
  # Some servers allow SNAPSHOT in any repo; this is not a conformance failure,
  # but the policy may not be enforced
  skip "server accepted SNAPSHOT in release repo (policy not enforced)"
else
  fail "unexpected HTTP ${SNAP_REJECT_HTTP} when uploading SNAPSHOT to release repo"
fi

# =========================================================================
# Cleanup
# =========================================================================

api_delete "/api/v1/repositories/${SNAP_REPO_KEY}" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${REPO_KEY}" > /dev/null 2>&1 || true

end_suite
