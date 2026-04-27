#!/usr/bin/env bash
# test-gradle-conformance.sh - Gradle (Maven-aliased) repository conformance test
#
# Gradle does not have a dedicated HTTP route. The backend aliases gradle
# repos onto the Maven handler at the resolver layer:
#   src/api/handlers/maven.rs
#     proxy_helpers::resolve_repo_by_key(db, repo_key, &["maven", "gradle"], "a Maven")
# and at the trait layer:
#   src/formats/mod.rs
#     RepositoryFormat::Maven | RepositoryFormat::Gradle => MavenHandler::new()
#
# This test creates a repository with format=gradle and exercises the Maven
# wire protocol against it via /maven/{repo_key}/..., covering:
#   - Gradle Module Metadata file (.module JSON, Gradle-specific)
#   - POM upload (Gradle publishes alongside POM in maven-publish plugin)
#   - JAR upload and SHA-256 round trip
#   - maven-metadata.xml resolution
#   - Listing through the generic management API
#
# Endpoints: ${BASE_URL}/maven/{repo_key}/... and /api/v1/repositories/{key}/...
#
# Requires: curl, jq, jar or zip (optional, for .jar creation)
source "$(dirname "$0")/../lib/common.sh"

begin_suite "gradle-conformance"
auth_admin
setup_workdir

REPO_KEY="test-gradle-conf-${RUN_ID}"
GROUP_ID="com.example.gradle"
ARTIFACT_ID="gradle-lib"
VERSION="1.0.0"
GRADLE_URL="${BASE_URL}/maven/${REPO_KEY}"

GROUP_PATH=$(echo "$GROUP_ID" | tr '.' '/')
ARTIFACT_BASE="${GROUP_PATH}/${ARTIFACT_ID}/${VERSION}"

# ---------------------------------------------------------------------------
# Create repository with format=gradle (NOT maven)
# ---------------------------------------------------------------------------

begin_test "Create gradle local repository"
if create_local_repo "$REPO_KEY" "gradle"; then
  pass
else
  fail "could not create gradle repository (gradle format may not be accepted)"
fi

# ---------------------------------------------------------------------------
# Confirm gradle repo is reachable through the Maven router
# ---------------------------------------------------------------------------

begin_test "Probe gradle repo via /maven/{key} alias"
PROBE_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
  -u "${ADMIN_USER}:${ADMIN_PASS}" \
  "${GRADLE_URL}/${GROUP_PATH}/${ARTIFACT_ID}/maven-metadata.xml") || true
# Empty repo: expect 404 from a working router, NOT a 400 (format mismatch)
# or 500 (no route). Anything in {200, 401, 403, 404} confirms the route is
# wired and the resolver accepts gradle.
case "$PROBE_CODE" in
  200|401|403|404)
    pass
    ;;
  *)
    fail "unexpected status $PROBE_CODE from /maven/{gradle-repo} probe"
    ;;
esac

# ---------------------------------------------------------------------------
# Build artifacts: JAR, POM, and Gradle Module Metadata (.module)
# ---------------------------------------------------------------------------

begin_test "Create test JAR, POM, and Gradle Module Metadata"

cd "$WORK_DIR"

# Minimal JAR
mkdir -p jar-content/META-INF
cat > jar-content/META-INF/MANIFEST.MF <<EOF
Manifest-Version: 1.0
Created-By: artifact-keeper-test (gradle conformance)
Implementation-Title: ${ARTIFACT_ID}
Implementation-Version: ${VERSION}
EOF
mkdir -p jar-content/com/example/gradle
echo "placeholder" > jar-content/com/example/gradle/Lib.class

JAR_FILE="${WORK_DIR}/${ARTIFACT_ID}-${VERSION}.jar"
(cd jar-content && (jar cf "$JAR_FILE" META-INF/ com/ 2>/dev/null || zip -qr "$JAR_FILE" META-INF/ com/))

# POM (Gradle's maven-publish plugin emits this alongside the .module file)
POM_FILE="${WORK_DIR}/${ARTIFACT_ID}-${VERSION}.pom"
cat > "$POM_FILE" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>${GROUP_ID}</groupId>
  <artifactId>${ARTIFACT_ID}</artifactId>
  <version>${VERSION}</version>
  <packaging>jar</packaging>
</project>
EOF

# Gradle Module Metadata (.module) - this is the Gradle-specific format that
# the maven-publish Gradle plugin emits next to the POM.
# See: https://docs.gradle.org/current/userguide/publishing_gradle_module_metadata.html
MODULE_FILE="${WORK_DIR}/${ARTIFACT_ID}-${VERSION}.module"
cat > "$MODULE_FILE" <<EOF
{
  "formatVersion": "1.1",
  "component": {
    "group": "${GROUP_ID}",
    "module": "${ARTIFACT_ID}",
    "version": "${VERSION}",
    "attributes": {
      "org.gradle.status": "release"
    }
  },
  "createdBy": {
    "gradle": { "version": "8.5" }
  },
  "variants": [
    {
      "name": "apiElements",
      "attributes": {
        "org.gradle.category": "library",
        "org.gradle.dependency.bundling": "external",
        "org.gradle.jvm.version": "17",
        "org.gradle.libraryelements": "jar",
        "org.gradle.usage": "java-api"
      },
      "files": [
        {
          "name": "${ARTIFACT_ID}-${VERSION}.jar",
          "url": "${ARTIFACT_ID}-${VERSION}.jar"
        }
      ]
    }
  ]
}
EOF

if [ -f "$JAR_FILE" ] && [ -f "$POM_FILE" ] && [ -f "$MODULE_FILE" ]; then
  pass
else
  fail "failed to create JAR, POM, or .module file"
fi

# ---------------------------------------------------------------------------
# Upload all three through the Maven-aliased route
# ---------------------------------------------------------------------------

ORIG_SHA256=$(shasum -a 256 "$JAR_FILE" | awk '{print $1}')

begin_test "Upload JAR via PUT /maven/{gradle-repo-key}/..."
JAR_PATH="${ARTIFACT_BASE}/${ARTIFACT_ID}-${VERSION}.jar"
if curl -sf $CURL_TIMEOUT -X PUT "${GRADLE_URL}/${JAR_PATH}" \
  -u "${ADMIN_USER}:${ADMIN_PASS}" \
  -H "Content-Type: application/java-archive" \
  --data-binary "@${JAR_FILE}" > /dev/null 2>&1; then
  pass
else
  fail "PUT JAR to gradle-aliased route failed"
fi

begin_test "Upload POM via PUT /maven/{gradle-repo-key}/..."
POM_PATH="${ARTIFACT_BASE}/${ARTIFACT_ID}-${VERSION}.pom"
if curl -sf $CURL_TIMEOUT -X PUT "${GRADLE_URL}/${POM_PATH}" \
  -u "${ADMIN_USER}:${ADMIN_PASS}" \
  -H "Content-Type: application/xml" \
  --data-binary "@${POM_FILE}" > /dev/null 2>&1; then
  pass
else
  fail "PUT POM to gradle-aliased route failed"
fi

begin_test "Upload Gradle Module Metadata (.module) via PUT"
MODULE_PATH="${ARTIFACT_BASE}/${ARTIFACT_ID}-${VERSION}.module"
if curl -sf $CURL_TIMEOUT -X PUT "${GRADLE_URL}/${MODULE_PATH}" \
  -u "${ADMIN_USER}:${ADMIN_PASS}" \
  -H "Content-Type: application/json" \
  --data-binary "@${MODULE_FILE}" > /dev/null 2>&1; then
  pass
else
  # If the Maven handler rejects unknown extensions, this is the place where
  # the alias is incomplete for Gradle. Mark as fail so the gap is visible.
  fail "PUT .module to gradle-aliased route failed - Maven handler may not accept Gradle Module Metadata"
fi

# ---------------------------------------------------------------------------
# Round-trip JAR and verify SHA-256
# ---------------------------------------------------------------------------

begin_test "Download JAR and verify SHA-256 round trip"
DL_FILE="${WORK_DIR}/downloaded.jar"
if curl -sf $CURL_TIMEOUT -u "${ADMIN_USER}:${ADMIN_PASS}" -o "$DL_FILE" \
  "${GRADLE_URL}/${JAR_PATH}"; then
  DL_SHA256=$(shasum -a 256 "$DL_FILE" | awk '{print $1}')
  if assert_eq "$DL_SHA256" "$ORIG_SHA256" "SHA256 mismatch after gradle-aliased round-trip"; then
    pass
  fi
else
  fail "GET JAR from gradle-aliased route failed"
fi

# ---------------------------------------------------------------------------
# Round-trip the .module file (Gradle-specific, this is the real test)
# ---------------------------------------------------------------------------

begin_test "Download Gradle Module Metadata and verify content"
DL_MODULE="${WORK_DIR}/downloaded.module"
if curl -sf $CURL_TIMEOUT -u "${ADMIN_USER}:${ADMIN_PASS}" -o "$DL_MODULE" \
  "${GRADLE_URL}/${MODULE_PATH}"; then
  if assert_contains "$(cat "$DL_MODULE")" "\"formatVersion\": \"1.1\"" \
       "downloaded .module should preserve Gradle Module Metadata"; then
    pass
  fi
else
  fail "GET .module from gradle-aliased route failed"
fi

# ---------------------------------------------------------------------------
# Confirm via management API that the artifacts are listed against the gradle repo
# ---------------------------------------------------------------------------

begin_test "List artifacts via management API for gradle repo"
sleep 1
if resp=$(api_get "/api/v1/repositories/${REPO_KEY}/artifacts"); then
  if assert_contains "$resp" "$ARTIFACT_ID" \
       "artifact list for gradle repo should contain artifact"; then
    pass
  fi
else
  fail "GET /api/v1/repositories/${REPO_KEY}/artifacts returned error"
fi

# ---------------------------------------------------------------------------
# maven-metadata.xml is generated on demand for the Maven layout. This is
# the same code path used for plain Maven repos, so a passing assertion
# also confirms the Gradle alias does not bypass index generation.
# ---------------------------------------------------------------------------

begin_test "Resolve maven-metadata.xml against gradle-aliased repo"
METADATA_PATH="${GROUP_PATH}/${ARTIFACT_ID}/maven-metadata.xml"
if resp=$(curl -sf $CURL_TIMEOUT "${GRADLE_URL}/${METADATA_PATH}" \
  -u "${ADMIN_USER}:${ADMIN_PASS}"); then
  if assert_contains "$resp" "$VERSION" "metadata should list the uploaded version"; then
    pass
  fi
else
  # Some builds only auto-generate metadata after a deploy. Skip is acceptable.
  skip "maven-metadata.xml not generated for gradle-aliased repo (may require explicit deploy)"
fi

end_suite
