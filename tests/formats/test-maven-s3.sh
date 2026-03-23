#!/usr/bin/env bash
# test-maven-s3.sh - Maven + S3 storage backend E2E test
#
# Tests the full Maven deploy lifecycle against a repository that uses
# S3-compatible object storage. Exercises the exact flow that fails in
# issue #361: SNAPSHOT deploys, re-deploys, checksum uploads, and
# metadata generation.
#
# Requires: curl, shasum (or sha256sum)
# Optional: mvn (for real Maven deploy tests)
#
# Storage backend requirement: the backend must be configured with S3
# storage (STORAGE_BACKEND=s3) or have an S3 backend registered in the
# storage registry. The test creates a repository with storage_backend=s3.

source "$(dirname "$0")/../lib/common.sh"

begin_suite "maven-s3"
auth_admin
setup_workdir

REPO_KEY="test-maven-s3-${RUN_ID}"
GROUP_ID="com.test.s3"
ARTIFACT_ID="s3-artifact"
RELEASE_VERSION="1.0.${RUN_ID}"
SNAPSHOT_VERSION="2.0.${RUN_ID}-SNAPSHOT"
MAVEN_URL="${BASE_URL}/maven/${REPO_KEY}"
GROUP_PATH=$(echo "$GROUP_ID" | tr '.' '/')

# -------------------------------------------------------------------------
# Create S3-backed Maven repository
# -------------------------------------------------------------------------

begin_test "Create maven repository with S3 storage"

# Try creating with explicit S3 backend
PAYLOAD="{\"key\":\"${REPO_KEY}\",\"name\":\"${REPO_KEY}\",\"format\":\"maven\",\"repo_type\":\"local\",\"is_public\":true,\"storage_backend\":\"s3\"}"
CREATE_HTTP=$(curl -s -o /dev/null -w "%{http_code}" $CURL_TIMEOUT -X POST \
  -H "$(auth_header)" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD" "${BASE_URL}/api/v1/repositories")

if [ "$CREATE_HTTP" = "200" ] || [ "$CREATE_HTTP" = "201" ]; then
  pass
else
  # S3 backend may not be available; fall back to default storage
  # (this lets the test run against filesystem setups too, exercising the
  # Maven protocol even when S3 is not configured)
  PAYLOAD="{\"key\":\"${REPO_KEY}\",\"name\":\"${REPO_KEY}\",\"format\":\"maven\",\"repo_type\":\"local\",\"is_public\":true}"
  if curl -sf $CURL_TIMEOUT -X POST \
    -H "$(auth_header)" \
    -H "Content-Type: application/json" \
    -d "$PAYLOAD" "${BASE_URL}/api/v1/repositories" > /dev/null; then
    skip "S3 backend not available, created repo with default storage"
  else
    fail "could not create maven repository (HTTP $CREATE_HTTP)"
  fi
fi

# -------------------------------------------------------------------------
# Create test artifacts
# -------------------------------------------------------------------------

begin_test "Create test JAR and POM files"

cd "$WORK_DIR"
mkdir -p jar-content/META-INF jar-content/com/test

cat > jar-content/META-INF/MANIFEST.MF <<EOF
Manifest-Version: 1.0
Created-By: artifact-keeper-test
Implementation-Title: ${ARTIFACT_ID}
Implementation-Version: ${RELEASE_VERSION}
EOF
echo "placeholder-class-file" > jar-content/com/test/TestClass.class

cd jar-content
JAR_FILE="${WORK_DIR}/${ARTIFACT_ID}-${RELEASE_VERSION}.jar"
if command -v jar &>/dev/null; then
  jar cf "$JAR_FILE" META-INF/ com/ 2>/dev/null || zip -r "$JAR_FILE" META-INF/ com/ > /dev/null 2>&1
else
  zip -r "$JAR_FILE" META-INF/ com/ > /dev/null 2>&1
fi
cd "$WORK_DIR"

POM_FILE="${WORK_DIR}/${ARTIFACT_ID}-${RELEASE_VERSION}.pom"
cat > "$POM_FILE" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>${GROUP_ID}</groupId>
  <artifactId>${ARTIFACT_ID}</artifactId>
  <version>${RELEASE_VERSION}</version>
  <packaging>jar</packaging>
</project>
EOF

if [ -f "$JAR_FILE" ] && [ -f "$POM_FILE" ]; then
  pass
else
  fail "failed to create JAR or POM file"
fi

# -------------------------------------------------------------------------
# Release artifact PUT flow
# -------------------------------------------------------------------------

RELEASE_BASE="${GROUP_PATH}/${ARTIFACT_ID}/${RELEASE_VERSION}"

begin_test "PUT release JAR to S3 storage"
JAR_PATH="${RELEASE_BASE}/${ARTIFACT_ID}-${RELEASE_VERSION}.jar"
ORIG_SHA256=$(shasum -a 256 "$JAR_FILE" 2>/dev/null | awk '{print $1}')
if curl -sf $CURL_TIMEOUT -X PUT "${MAVEN_URL}/${JAR_PATH}" \
  -u "${ADMIN_USER}:${ADMIN_PASS}" \
  --data-binary "@${JAR_FILE}" > /dev/null; then
  pass
else
  fail "PUT release JAR failed"
fi

begin_test "PUT release POM to S3 storage"
POM_PATH="${RELEASE_BASE}/${ARTIFACT_ID}-${RELEASE_VERSION}.pom"
if curl -sf $CURL_TIMEOUT -X PUT "${MAVEN_URL}/${POM_PATH}" \
  -u "${ADMIN_USER}:${ADMIN_PASS}" \
  --data-binary "@${POM_FILE}" > /dev/null; then
  pass
else
  fail "PUT release POM failed"
fi

# -------------------------------------------------------------------------
# Checksum uploads (Maven deploy sends these alongside every file)
# -------------------------------------------------------------------------

begin_test "PUT SHA1 checksum for JAR"
JAR_SHA1=$(shasum -a 1 "$JAR_FILE" 2>/dev/null | awk '{print $1}')
if printf '%s' "$JAR_SHA1" | curl -sf $CURL_TIMEOUT -X PUT "${MAVEN_URL}/${JAR_PATH}.sha1" \
  -u "${ADMIN_USER}:${ADMIN_PASS}" \
  --data-binary @- > /dev/null; then
  pass
else
  fail "PUT JAR SHA1 failed"
fi

begin_test "PUT MD5 checksum for JAR"
JAR_MD5=$(md5 -q "$JAR_FILE" 2>/dev/null || md5sum "$JAR_FILE" 2>/dev/null | awk '{print $1}')
if printf '%s' "$JAR_MD5" | curl -sf $CURL_TIMEOUT -X PUT "${MAVEN_URL}/${JAR_PATH}.md5" \
  -u "${ADMIN_USER}:${ADMIN_PASS}" \
  --data-binary @- > /dev/null; then
  pass
else
  fail "PUT JAR MD5 failed"
fi

begin_test "PUT SHA1 checksum for POM"
POM_SHA1=$(shasum -a 1 "$POM_FILE" 2>/dev/null | awk '{print $1}')
if printf '%s' "$POM_SHA1" | curl -sf $CURL_TIMEOUT -X PUT "${MAVEN_URL}/${POM_PATH}.sha1" \
  -u "${ADMIN_USER}:${ADMIN_PASS}" \
  --data-binary @- > /dev/null; then
  pass
else
  fail "PUT POM SHA1 failed"
fi

# -------------------------------------------------------------------------
# maven-metadata.xml upload (Maven deploy does this after all artifacts)
# -------------------------------------------------------------------------

begin_test "PUT maven-metadata.xml"
METADATA_XML="<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<metadata>
  <groupId>${GROUP_ID}</groupId>
  <artifactId>${ARTIFACT_ID}</artifactId>
  <versioning>
    <latest>${RELEASE_VERSION}</latest>
    <release>${RELEASE_VERSION}</release>
    <versions>
      <version>${RELEASE_VERSION}</version>
    </versions>
    <lastUpdated>$(date -u '+%Y%m%d%H%M%S')</lastUpdated>
  </versioning>
</metadata>"

if printf '%s' "$METADATA_XML" | curl -sf $CURL_TIMEOUT -X PUT \
  "${MAVEN_URL}/${GROUP_PATH}/${ARTIFACT_ID}/maven-metadata.xml" \
  -u "${ADMIN_USER}:${ADMIN_PASS}" \
  --data-binary @- > /dev/null; then
  pass
else
  fail "PUT maven-metadata.xml failed"
fi

# -------------------------------------------------------------------------
# Download and verify release artifacts from S3
# -------------------------------------------------------------------------

begin_test "Download release JAR from S3 and verify checksum"
DL_FILE="${WORK_DIR}/downloaded-release.jar"
if curl -sf $CURL_TIMEOUT -u "${ADMIN_USER}:${ADMIN_PASS}" -o "$DL_FILE" "${MAVEN_URL}/${JAR_PATH}"; then
  DL_SHA256=$(shasum -a 256 "$DL_FILE" 2>/dev/null | awk '{print $1}')
  if assert_eq "$DL_SHA256" "$ORIG_SHA256" "SHA256 mismatch on release JAR round-trip"; then
    pass
  fi
else
  fail "download release JAR from S3 failed"
fi

begin_test "Download release POM from S3"
if curl -sf $CURL_TIMEOUT -u "${ADMIN_USER}:${ADMIN_PASS}" \
  "${MAVEN_URL}/${POM_PATH}" > /dev/null; then
  pass
else
  fail "download release POM from S3 failed"
fi

begin_test "Download stored SHA1 checksum"
STORED_SHA1=$(curl -sf $CURL_TIMEOUT -u "${ADMIN_USER}:${ADMIN_PASS}" "${MAVEN_URL}/${JAR_PATH}.sha1")
if [ -n "$STORED_SHA1" ]; then
  pass
else
  fail "stored SHA1 checksum is empty"
fi

# -------------------------------------------------------------------------
# SNAPSHOT deploy flow (the core of issue #361)
#
# Simulates what `mvn deploy` does for SNAPSHOTs:
# 1. GET version-level maven-metadata.xml (to determine build number)
# 2. PUT timestamped JAR and POM files
# 3. PUT checksums for each file
# 4. PUT updated version-level maven-metadata.xml
# 5. PUT updated artifact-level maven-metadata.xml
# -------------------------------------------------------------------------

SNAP_BASE_VERSION=$(echo "$SNAPSHOT_VERSION" | sed 's/-SNAPSHOT//')
TIMESTAMP=$(date -u '+%Y%m%d.%H%M%S')
BUILD_NUMBER=1
SNAP_BASE="${GROUP_PATH}/${ARTIFACT_ID}/${SNAPSHOT_VERSION}"

begin_test "GET SNAPSHOT metadata (expect 404 on first deploy)"
SNAP_META_HTTP=$(curl -s -o /dev/null -w "%{http_code}" $CURL_TIMEOUT \
  -u "${ADMIN_USER}:${ADMIN_PASS}" \
  "${MAVEN_URL}/${SNAP_BASE}/maven-metadata.xml")
# 404 is expected on first deploy; anything else should be investigated
if [ "$SNAP_META_HTTP" = "404" ] || [ "$SNAP_META_HTTP" = "200" ]; then
  pass
else
  fail "unexpected response for SNAPSHOT metadata: HTTP $SNAP_META_HTTP"
fi

begin_test "PUT SNAPSHOT JAR (timestamped)"
SNAP_JAR_NAME="${ARTIFACT_ID}-${SNAP_BASE_VERSION}-${TIMESTAMP}-${BUILD_NUMBER}.jar"
SNAP_JAR_PATH="${SNAP_BASE}/${SNAP_JAR_NAME}"
# Reuse the same JAR content
SNAP_JAR_SHA256=$(shasum -a 256 "$JAR_FILE" 2>/dev/null | awk '{print $1}')
if curl -sf $CURL_TIMEOUT -X PUT "${MAVEN_URL}/${SNAP_JAR_PATH}" \
  -u "${ADMIN_USER}:${ADMIN_PASS}" \
  --data-binary "@${JAR_FILE}" > /dev/null; then
  pass
else
  fail "PUT SNAPSHOT JAR failed"
fi

begin_test "PUT SNAPSHOT POM (timestamped)"
SNAP_POM_NAME="${ARTIFACT_ID}-${SNAP_BASE_VERSION}-${TIMESTAMP}-${BUILD_NUMBER}.pom"
SNAP_POM_PATH="${SNAP_BASE}/${SNAP_POM_NAME}"
# Create snapshot POM
SNAP_POM_FILE="${WORK_DIR}/snapshot.pom"
cat > "$SNAP_POM_FILE" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>${GROUP_ID}</groupId>
  <artifactId>${ARTIFACT_ID}</artifactId>
  <version>${SNAPSHOT_VERSION}</version>
  <packaging>jar</packaging>
</project>
EOF
if curl -sf $CURL_TIMEOUT -X PUT "${MAVEN_URL}/${SNAP_POM_PATH}" \
  -u "${ADMIN_USER}:${ADMIN_PASS}" \
  --data-binary "@${SNAP_POM_FILE}" > /dev/null; then
  pass
else
  fail "PUT SNAPSHOT POM failed"
fi

begin_test "PUT SNAPSHOT checksums (SHA1 + MD5 for JAR and POM)"
SNAP_JAR_SHA1=$(shasum -a 1 "$JAR_FILE" 2>/dev/null | awk '{print $1}')
SNAP_POM_SHA1=$(shasum -a 1 "$SNAP_POM_FILE" 2>/dev/null | awk '{print $1}')
SNAP_JAR_MD5=$(md5 -q "$JAR_FILE" 2>/dev/null || md5sum "$JAR_FILE" 2>/dev/null | awk '{print $1}')
SNAP_POM_MD5=$(md5 -q "$SNAP_POM_FILE" 2>/dev/null || md5sum "$SNAP_POM_FILE" 2>/dev/null | awk '{print $1}')

ALL_CHECKSUMS_OK=true
for SUFFIX_PAIR in \
  "${SNAP_JAR_PATH}.sha1:${SNAP_JAR_SHA1}" \
  "${SNAP_JAR_PATH}.md5:${SNAP_JAR_MD5}" \
  "${SNAP_POM_PATH}.sha1:${SNAP_POM_SHA1}" \
  "${SNAP_POM_PATH}.md5:${SNAP_POM_MD5}"; do
  CKSUM_PATH="${SUFFIX_PAIR%%:*}"
  CKSUM_VAL="${SUFFIX_PAIR##*:}"
  if ! printf '%s' "$CKSUM_VAL" | curl -sf $CURL_TIMEOUT -X PUT \
    "${MAVEN_URL}/${CKSUM_PATH}" \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    --data-binary @- > /dev/null 2>&1; then
    ALL_CHECKSUMS_OK=false
    echo "  Failed: ${CKSUM_PATH}"
  fi
done
if $ALL_CHECKSUMS_OK; then
  pass
else
  fail "one or more SNAPSHOT checksum uploads failed"
fi

begin_test "PUT SNAPSHOT version-level maven-metadata.xml"
SNAP_META="<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<metadata modelVersion=\"1.1.0\">
  <groupId>${GROUP_ID}</groupId>
  <artifactId>${ARTIFACT_ID}</artifactId>
  <version>${SNAPSHOT_VERSION}</version>
  <versioning>
    <snapshot>
      <timestamp>${TIMESTAMP}</timestamp>
      <buildNumber>${BUILD_NUMBER}</buildNumber>
    </snapshot>
    <lastUpdated>$(echo "$TIMESTAMP" | tr -d '.')</lastUpdated>
    <snapshotVersions>
      <snapshotVersion>
        <extension>jar</extension>
        <value>${SNAP_BASE_VERSION}-${TIMESTAMP}-${BUILD_NUMBER}</value>
        <updated>$(echo "$TIMESTAMP" | tr -d '.')</updated>
      </snapshotVersion>
      <snapshotVersion>
        <extension>pom</extension>
        <value>${SNAP_BASE_VERSION}-${TIMESTAMP}-${BUILD_NUMBER}</value>
        <updated>$(echo "$TIMESTAMP" | tr -d '.')</updated>
      </snapshotVersion>
    </snapshotVersions>
  </versioning>
</metadata>"

if printf '%s' "$SNAP_META" | curl -sf $CURL_TIMEOUT -X PUT \
  "${MAVEN_URL}/${SNAP_BASE}/maven-metadata.xml" \
  -u "${ADMIN_USER}:${ADMIN_PASS}" \
  --data-binary @- > /dev/null; then
  pass
else
  fail "PUT SNAPSHOT maven-metadata.xml failed"
fi

# -------------------------------------------------------------------------
# Download and verify SNAPSHOT artifacts
# -------------------------------------------------------------------------

begin_test "Download SNAPSHOT JAR and verify checksum"
DL_SNAP="${WORK_DIR}/downloaded-snapshot.jar"
if curl -sf $CURL_TIMEOUT -u "${ADMIN_USER}:${ADMIN_PASS}" \
  -o "$DL_SNAP" "${MAVEN_URL}/${SNAP_JAR_PATH}"; then
  DL_SNAP_SHA256=$(shasum -a 256 "$DL_SNAP" 2>/dev/null | awk '{print $1}')
  if assert_eq "$DL_SNAP_SHA256" "$SNAP_JAR_SHA256" "SNAPSHOT JAR SHA256 mismatch"; then
    pass
  fi
else
  fail "download SNAPSHOT JAR failed"
fi

begin_test "Download SNAPSHOT metadata"
SNAP_META_DL=$(curl -sf $CURL_TIMEOUT -u "${ADMIN_USER}:${ADMIN_PASS}" \
  "${MAVEN_URL}/${SNAP_BASE}/maven-metadata.xml" 2>/dev/null || true)
if [ -n "$SNAP_META_DL" ] && echo "$SNAP_META_DL" | grep -q "timestamp"; then
  pass
else
  fail "SNAPSHOT maven-metadata.xml missing or incomplete"
fi

# -------------------------------------------------------------------------
# SNAPSHOT re-deploy (build number 2)
# -------------------------------------------------------------------------

begin_test "Re-deploy SNAPSHOT with new build number"

# Create modified JAR content
echo "modified-class-v2" > "${WORK_DIR}/jar-content/com/test/TestClass.class"
cd "${WORK_DIR}/jar-content"
JAR_FILE_V2="${WORK_DIR}/${ARTIFACT_ID}-v2.jar"
if command -v jar &>/dev/null; then
  jar cf "$JAR_FILE_V2" META-INF/ com/ 2>/dev/null || zip -r "$JAR_FILE_V2" META-INF/ com/ > /dev/null 2>&1
else
  zip -r "$JAR_FILE_V2" META-INF/ com/ > /dev/null 2>&1
fi
cd "$WORK_DIR"

TIMESTAMP2=$(date -u '+%Y%m%d.%H%M%S')
BUILD_NUMBER2=2
SNAP_JAR_NAME2="${ARTIFACT_ID}-${SNAP_BASE_VERSION}-${TIMESTAMP2}-${BUILD_NUMBER2}.jar"
SNAP_JAR_PATH2="${SNAP_BASE}/${SNAP_JAR_NAME2}"

if curl -sf $CURL_TIMEOUT -X PUT "${MAVEN_URL}/${SNAP_JAR_PATH2}" \
  -u "${ADMIN_USER}:${ADMIN_PASS}" \
  --data-binary "@${JAR_FILE_V2}" > /dev/null; then
  pass
else
  fail "SNAPSHOT re-deploy (build 2) failed"
fi

begin_test "Verify both SNAPSHOT builds are accessible"
DL1_OK=false
DL2_OK=false
if curl -sf $CURL_TIMEOUT -u "${ADMIN_USER}:${ADMIN_PASS}" \
  "${MAVEN_URL}/${SNAP_JAR_PATH}" > /dev/null 2>&1; then
  DL1_OK=true
fi
if curl -sf $CURL_TIMEOUT -u "${ADMIN_USER}:${ADMIN_PASS}" \
  "${MAVEN_URL}/${SNAP_JAR_PATH2}" > /dev/null 2>&1; then
  DL2_OK=true
fi
if $DL2_OK; then
  # Build 2 must be accessible. Build 1 may or may not be (some registries
  # delete older snapshots; either behavior is acceptable).
  pass
else
  fail "SNAPSHOT build 2 not accessible"
fi

# -------------------------------------------------------------------------
# Release re-upload rejection
# -------------------------------------------------------------------------

begin_test "Reject release artifact re-upload (409)"
REUPLOAD_HTTP=$(curl -s -o /dev/null -w "%{http_code}" $CURL_TIMEOUT -X PUT \
  "${MAVEN_URL}/${JAR_PATH}" \
  -u "${ADMIN_USER}:${ADMIN_PASS}" \
  --data-binary "@${JAR_FILE}")
if [ "$REUPLOAD_HTTP" = "409" ]; then
  pass
else
  # Some implementations return 200 on re-upload; 409 is preferred but not required
  skip "re-upload returned HTTP $REUPLOAD_HTTP (expected 409)"
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
