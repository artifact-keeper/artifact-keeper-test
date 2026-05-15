#!/usr/bin/env bash
# test-sbt-conformance.sh - SBT/Ivy repository conformance tests
#
# Validates that the SBT/Ivy repository at /ivy/{repo_key}/ conforms to the
# Ivy repository layout protocol. Tests cover JAR deployment, ivy.xml
# descriptor deployment and retrieval, download with integrity verification,
# checksum file generation (.sha1, .md5), multi-version support, 404 for
# missing artifacts, and Maven-style metadata support.
#
# Ivy layout: /{org}/{name}/{version}/jars/{name}-{version}.jar
#             /{org}/{name}/{version}/ivys/ivy.xml
#
# Endpoints: ${BASE_URL}/ivy/{repo_key}/
#
# Requires: curl, shasum (or sha256sum), md5 or md5sum, zip
source "$(dirname "$0")/../lib/common.sh"

begin_suite "sbt-conformance"
auth_admin
setup_workdir

REPO_KEY="test-sbt-conf-${RUN_ID}"
ORG="com.conftest"
MODULE_NAME="conf-module"
SCALA_VERSION="2.13"
VERSION="1.0.0"
VERSION_2="2.0.0"
IVY_URL="${BASE_URL}/ivy/${REPO_KEY}"

# Ivy path layout for Scala artifacts: {org}/{name}_{scalaVersion}/{version}/
IVY_BASE="${ORG}/${MODULE_NAME}_${SCALA_VERSION}/${VERSION}"
IVY_BASE_V2="${ORG}/${MODULE_NAME}_${SCALA_VERSION}/${VERSION_2}"

# -------------------------------------------------------------------------
# Setup: create repository and build test artifacts
# -------------------------------------------------------------------------

begin_test "Create ivy (sbt) local repository"
if create_local_repo "$REPO_KEY" "sbt"; then
  pass
else
  fail "could not create sbt/ivy repository"
fi

# Build JAR artifact
cd "$WORK_DIR"
mkdir -p jar-content/META-INF jar-content/com/conftest
cat > jar-content/META-INF/MANIFEST.MF <<EOF
Manifest-Version: 1.0
Implementation-Title: ${MODULE_NAME}
Implementation-Version: ${VERSION}
Specification-Vendor: ${ORG}
EOF
echo "placeholder-class-${RUN_ID}" > jar-content/com/conftest/ConfModule.class

cd jar-content
JAR_FILE="${WORK_DIR}/${MODULE_NAME}_${SCALA_VERSION}-${VERSION}.jar"
zip -r "$JAR_FILE" META-INF/ com/ > /dev/null 2>&1
cd "$WORK_DIR"

# Build ivy.xml descriptor
IVY_FILE="${WORK_DIR}/ivy.xml"
cat > "$IVY_FILE" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<ivy-module version="2.0" xmlns:e="http://ant.apache.org/ivy/extra">
  <info organisation="${ORG}"
        module="${MODULE_NAME}_${SCALA_VERSION}"
        revision="${VERSION}"
        status="release"
        publication="$(date +%Y%m%d%H%M%S)">
  </info>
  <configurations>
    <conf name="compile" visibility="public"/>
    <conf name="runtime" visibility="public" extends="compile"/>
    <conf name="test" visibility="private" extends="runtime"/>
  </configurations>
  <publications>
    <artifact name="${MODULE_NAME}_${SCALA_VERSION}" type="jar" ext="jar" conf="compile"/>
  </publications>
  <dependencies>
  </dependencies>
</ivy-module>
EOF

JAR_SHA256=$(shasum -a 256 "$JAR_FILE" | awk '{print $1}')
JAR_SHA1=$(shasum -a 1 "$JAR_FILE" | awk '{print $1}')
JAR_MD5=$(md5 -q "$JAR_FILE" 2>/dev/null || md5sum "$JAR_FILE" 2>/dev/null | awk '{print $1}')

IVY_SHA256=$(shasum -a 256 "$IVY_FILE" | awk '{print $1}')
IVY_SHA1=$(shasum -a 1 "$IVY_FILE" | awk '{print $1}')
IVY_MD5=$(md5 -q "$IVY_FILE" 2>/dev/null || md5sum "$IVY_FILE" 2>/dev/null | awk '{print $1}')

# =========================================================================
# Test 1: Deploy JAR via PUT (Ivy layout)
# =========================================================================

JAR_PATH="${IVY_BASE}/jars/${MODULE_NAME}_${SCALA_VERSION}-${VERSION}.jar"

begin_test "Deploy JAR via PUT"
if curl -sf $CURL_TIMEOUT -X PUT "${IVY_URL}/${JAR_PATH}" \
    -H "$(format_auth_header)" \
    -H "Content-Type: application/java-archive" \
    --data-binary "@${JAR_FILE}" > /dev/null 2>&1; then
  pass
else
  fail "PUT JAR to ${JAR_PATH} failed"
fi

# =========================================================================
# Test 2: Deploy ivy.xml descriptor
# =========================================================================

IVY_PATH="${IVY_BASE}/ivys/ivy.xml"

begin_test "Deploy ivy.xml descriptor"
if curl -sf $CURL_TIMEOUT -X PUT "${IVY_URL}/${IVY_PATH}" \
    -H "$(format_auth_header)" \
    -H "Content-Type: application/xml" \
    --data-binary "@${IVY_FILE}" > /dev/null 2>&1; then
  pass
else
  fail "PUT ivy.xml to ${IVY_PATH} failed"
fi

# =========================================================================
# Test 3: Download JAR with content verification
# =========================================================================

begin_test "Download JAR returns exact uploaded content"
DL_JAR="${WORK_DIR}/dl-conformance.jar"
if curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    -o "$DL_JAR" \
    "${IVY_URL}/${JAR_PATH}"; then
  DL_JAR_SHA256=$(shasum -a 256 "$DL_JAR" | awk '{print $1}')
  if assert_eq "$DL_JAR_SHA256" "$JAR_SHA256" "JAR SHA256 mismatch after round-trip"; then
    pass
  fi
else
  fail "GET JAR from ${JAR_PATH} failed"
fi

# =========================================================================
# Test 4: Download ivy.xml and verify content
# =========================================================================

begin_test "Download ivy.xml returns correct descriptor"
if resp=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${IVY_URL}/${IVY_PATH}" 2>/dev/null); then
  if assert_contains "$resp" "${ORG}" "ivy.xml should contain organisation" && \
     assert_contains "$resp" "${MODULE_NAME}" "ivy.xml should contain module name" && \
     assert_contains "$resp" "${VERSION}" "ivy.xml should contain revision"; then
    pass
  fi
else
  fail "GET ivy.xml from ${IVY_PATH} failed"
fi

# =========================================================================
# Test 5: Checksum files (.sha1, .md5)
# =========================================================================

begin_test "Checksum files for JAR (.sha1, .md5)"
# Upload explicit checksum files
SHA1_UPLOAD_OK=true
MD5_UPLOAD_OK=true

if ! printf '%s' "$JAR_SHA1" | curl -sf $CURL_TIMEOUT -X PUT "${IVY_URL}/${JAR_PATH}.sha1" \
    -H "$(format_auth_header)" --data-binary @- > /dev/null 2>&1; then
  SHA1_UPLOAD_OK=false
fi
if ! printf '%s' "$JAR_MD5" | curl -sf $CURL_TIMEOUT -X PUT "${IVY_URL}/${JAR_PATH}.md5" \
    -H "$(format_auth_header)" --data-binary @- > /dev/null 2>&1; then
  MD5_UPLOAD_OK=false
fi

if $SHA1_UPLOAD_OK && $MD5_UPLOAD_OK; then
  # Retrieve and verify
  GOT_SHA1=$(curl -sf $CURL_TIMEOUT -H "$(format_auth_header)" \
      "${IVY_URL}/${JAR_PATH}.sha1" 2>/dev/null | tr -d '[:space:]') || true
  GOT_MD5=$(curl -sf $CURL_TIMEOUT -H "$(format_auth_header)" \
      "${IVY_URL}/${JAR_PATH}.md5" 2>/dev/null | tr -d '[:space:]') || true

  if assert_eq "$GOT_SHA1" "$JAR_SHA1" "SHA1 checksum mismatch for JAR" && \
     assert_eq "$GOT_MD5" "$JAR_MD5" "MD5 checksum mismatch for JAR"; then
    pass
  fi
elif $SHA1_UPLOAD_OK || $MD5_UPLOAD_OK; then
  # At least one checksum type works; check for auto-generated checksums
  if GOT_SHA1=$(curl -sf $CURL_TIMEOUT -H "$(format_auth_header)" \
      "${IVY_URL}/${JAR_PATH}.sha1" 2>/dev/null | tr -d '[:space:]'); then
    if assert_eq "$GOT_SHA1" "$JAR_SHA1" "SHA1 checksum mismatch"; then
      echo "  note: only SHA1 checksums supported"
      pass
    fi
  else
    fail "checksum upload partially succeeded but retrieval failed"
  fi
else
  # Check if the server auto-generates checksum files
  GOT_SHA1=$(curl -sf $CURL_TIMEOUT -H "$(format_auth_header)" \
      "${IVY_URL}/${JAR_PATH}.sha1" 2>/dev/null | tr -d '[:space:]') || true
  if [ -n "$GOT_SHA1" ] && [ "$GOT_SHA1" = "$JAR_SHA1" ]; then
    echo "  note: server auto-generates SHA1 checksums"
    pass
  else
    skip "checksum file upload and auto-generation not supported"
  fi
fi

# =========================================================================
# Test 6: Multiple versions
# =========================================================================

begin_test "Deploy and retrieve second version"
# Build JAR for version 2
cd "$WORK_DIR"
echo "v2-class-${RUN_ID}" > jar-content/com/conftest/ConfModule.class
cd jar-content
JAR_FILE_V2="${WORK_DIR}/${MODULE_NAME}_${SCALA_VERSION}-${VERSION_2}.jar"
zip -r "$JAR_FILE_V2" META-INF/ com/ > /dev/null 2>&1
cd "$WORK_DIR"

JAR_V2_SHA256=$(shasum -a 256 "$JAR_FILE_V2" | awk '{print $1}')

# Build ivy.xml for version 2
IVY_FILE_V2="${WORK_DIR}/ivy-v2.xml"
cat > "$IVY_FILE_V2" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<ivy-module version="2.0">
  <info organisation="${ORG}"
        module="${MODULE_NAME}_${SCALA_VERSION}"
        revision="${VERSION_2}"
        status="release">
  </info>
  <configurations>
    <conf name="compile" visibility="public"/>
  </configurations>
  <publications>
    <artifact name="${MODULE_NAME}_${SCALA_VERSION}" type="jar" ext="jar" conf="compile"/>
  </publications>
  <dependencies/>
</ivy-module>
EOF

JAR_PATH_V2="${IVY_BASE_V2}/jars/${MODULE_NAME}_${SCALA_VERSION}-${VERSION_2}.jar"
IVY_PATH_V2="${IVY_BASE_V2}/ivys/ivy.xml"

V2_JAR_OK=false
V2_IVY_OK=false

if curl -sf $CURL_TIMEOUT -X PUT "${IVY_URL}/${JAR_PATH_V2}" \
    -H "$(format_auth_header)" \
    -H "Content-Type: application/java-archive" \
    --data-binary "@${JAR_FILE_V2}" > /dev/null 2>&1; then
  V2_JAR_OK=true
fi

if curl -sf $CURL_TIMEOUT -X PUT "${IVY_URL}/${IVY_PATH_V2}" \
    -H "$(format_auth_header)" \
    -H "Content-Type: application/xml" \
    --data-binary "@${IVY_FILE_V2}" > /dev/null 2>&1; then
  V2_IVY_OK=true
fi

if $V2_JAR_OK && $V2_IVY_OK; then
  # Verify both versions are independently retrievable
  V1_OK=false
  V2_OK=false
  if curl -sf $CURL_TIMEOUT -H "$(format_auth_header)" \
      "${IVY_URL}/${JAR_PATH}" > /dev/null 2>&1; then
    V1_OK=true
  fi
  if curl -sf $CURL_TIMEOUT -H "$(format_auth_header)" \
      "${IVY_URL}/${JAR_PATH_V2}" > /dev/null 2>&1; then
    V2_OK=true
  fi

  if $V1_OK && $V2_OK; then
    pass
  else
    fail "not all versions retrievable (v1=${V1_OK}, v2=${V2_OK})"
  fi
elif $V2_JAR_OK; then
  fail "JAR upload succeeded but ivy.xml upload failed for v2"
else
  fail "v2 JAR upload failed"
fi

# =========================================================================
# Test 7: 404 for nonexistent artifact
# =========================================================================

begin_test "GET nonexistent artifact returns 404"
HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  "${IVY_URL}/${ORG}/nonexistent_module/99.99.99/jars/nonexistent_module-99.99.99.jar") || true

if assert_eq "$HTTP_CODE" "404" "expected 404 for nonexistent artifact, got ${HTTP_CODE}"; then
  pass
fi

# =========================================================================
# Test 8: Maven-style metadata if supported
# =========================================================================

begin_test "Maven-style metadata.xml for module versions"
# Some Ivy repositories also serve Maven-compatible metadata at the module level.
# Check if the server generates maven-metadata.xml listing available versions.
METADATA_PATH="${ORG}/${MODULE_NAME}_${SCALA_VERSION}/maven-metadata.xml"
meta_status=$(curl -s -o "${WORK_DIR}/maven-metadata.xml" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  "${IVY_URL}/${METADATA_PATH}") || true

if [ "$meta_status" = "200" ] && [ -s "${WORK_DIR}/maven-metadata.xml" ]; then
  if metadata=$(cat "${WORK_DIR}/maven-metadata.xml"); then
    if assert_contains "$metadata" "${MODULE_NAME}" "metadata should reference module name"; then
      # Check if versions are listed
      if echo "$metadata" | grep -q "<version>"; then
        echo "  metadata lists versions"
      fi
      pass
    fi
  else
    fail "could not read maven-metadata.xml"
  fi
elif [ "$meta_status" = "404" ]; then
  # Maven-style metadata is optional for Ivy repos. Try a directory listing instead.
  dir_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${IVY_URL}/${ORG}/${MODULE_NAME}_${SCALA_VERSION}/") || true
  if [ "$dir_status" = "200" ]; then
    echo "  note: no maven-metadata.xml, but directory listing works"
    pass
  else
    skip "Maven-style metadata and directory listing not supported for Ivy layout"
  fi
else
  fail "maven-metadata.xml returned unexpected HTTP ${meta_status}"
fi

end_suite
