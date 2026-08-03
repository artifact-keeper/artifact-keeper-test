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

# -------------------------------------------------------------------------
# Grouped component view on hosted repos (artifact-keeper#3064, fixed by
# artifact-keeper#3093, ships in v1.7.1)
#
# Regression: GET .../artifacts?group_by=maven_component on a HOSTED Maven
# repo returned pagination.total > 0 with components: [] when the artifacts
# were uploaded via the direct HTTP PUT path, because the catalog stored the
# component name from the GAV path parser but the version from the raw path
# segment. The bug's fingerprint is total > 0 with an empty components
# array, so both halves are asserted explicitly below.
# -------------------------------------------------------------------------

GROUPED_ARTIFACT_ID="app-${RUN_ID}"
GROUPED_VERSION="2.0.0"
GROUPED_BASE="com/example/demo/${GROUPED_ARTIFACT_ID}/${GROUPED_VERSION}"

begin_test "Upload ${GROUPED_ARTIFACT_ID} ${GROUPED_VERSION} JAR and POM via direct PUT"
if require_feature "maven_grouped_hosted_direct_put"; then
  GROUPED_POM="${WORK_DIR}/${GROUPED_ARTIFACT_ID}-${GROUPED_VERSION}.pom"
  cat > "$GROUPED_POM" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example.demo</groupId>
  <artifactId>${GROUPED_ARTIFACT_ID}</artifactId>
  <version>${GROUPED_VERSION}</version>
  <packaging>jar</packaging>
</project>
EOF
  jar_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X PUT \
    "${MAVEN_URL}/${GROUPED_BASE}/${GROUPED_ARTIFACT_ID}-${GROUPED_VERSION}.jar" \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    -H "Content-Type: application/java-archive" \
    --data-binary "@${JAR_FILE}" 2>/dev/null) || jar_status="000"
  pom_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X PUT \
    "${MAVEN_URL}/${GROUPED_BASE}/${GROUPED_ARTIFACT_ID}-${GROUPED_VERSION}.pom" \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    -H "Content-Type: application/xml" \
    --data-binary "@${GROUPED_POM}" 2>/dev/null) || pom_status="000"
  if assert_http_2xx "$jar_status" "PUT grouped-view JAR failed"; then
    if assert_http_2xx "$pom_status" "PUT grouped-view POM failed"; then
      pass
    fi
  fi
fi

begin_test "Grouped view returns non-empty components with path-derived version"
if require_feature "maven_grouped_hosted_direct_put"; then
  sleep 1
  GROUPED_PATH="/api/v1/repositories/${REPO_KEY}/artifacts?group_by=maven_component&count=exact&per_page=100"
  if resp=$(api_get_with_retry "$GROUPED_PATH"); then
    comp_count=$(echo "$resp" | jq '.components | length' 2>/dev/null) || comp_count=""
    total=$(echo "$resp" | jq '.pagination.total' 2>/dev/null) || total=""
    if ! [[ "$comp_count" =~ ^[0-9]+$ ]] || ! [[ "$total" =~ ^[0-9]+$ ]]; then
      fail "grouped response missing components/pagination.total (components='${comp_count}' total='${total}')" "$resp"
    elif [ "$total" -gt 0 ] && [ "$comp_count" -eq 0 ]; then
      fail "regression fingerprint (artifact-keeper#3064): pagination.total=${total} but components is empty" "$resp"
    elif [ "$comp_count" -eq 0 ]; then
      fail "grouped view returned no components (total=${total})" "$resp"
    else
      grouped_version=$(echo "$resp" | jq -r --arg a "$GROUPED_ARTIFACT_ID" \
        '.components[] | select(.artifact_id == $a) | .version' 2>/dev/null | head -n1) || grouped_version=""
      if assert_eq "$grouped_version" "$GROUPED_VERSION" \
          "component version should come from the path (expected ${GROUPED_VERSION}, got '${grouped_version}')"; then
        if assert_eq "$total" "$comp_count" \
            "pagination.total (${total}) should equal returned component count (${comp_count})"; then
          pass
        fi
      fi
    fi
  else
    fail "GET ${GROUPED_PATH} returned error"
  fi
fi

end_suite
