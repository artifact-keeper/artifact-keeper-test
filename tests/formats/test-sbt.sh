#!/usr/bin/env bash
# test-sbt.sh - SBT/Ivy repository E2E test
#
# Tests artifact upload and download via the /ivy/{repo_key}/ endpoints
# using Ivy-style path layout. Uses curl only (no native sbt needed).
#
# Ivy layout: /{org}/{name}/{version}/jars/{name}-{version}.jar
#             /{org}/{name}/{version}/ivys/ivy.xml
#
# Requires: curl (no native client needed)

source "$(dirname "$0")/../lib/common.sh"

begin_suite "sbt"
auth_admin
setup_workdir

REPO_KEY="test-sbt-${RUN_ID}"
ORG="com.test"
MODULE_NAME="test-module"
SCALA_VERSION="2.13"
VERSION="1.0.$(date +%s)"
IVY_URL="${BASE_URL}/ivy/${REPO_KEY}"

# Ivy path layout for Scala: {org}/{name}_{scalaVersion}/{version}/
IVY_BASE="${ORG}/${MODULE_NAME}_${SCALA_VERSION}/${VERSION}"

# ---------------------------------------------------------------------------
# Create repository
# ---------------------------------------------------------------------------

begin_test "Create ivy (sbt) local repository"
if create_local_repo "$REPO_KEY" "sbt"; then
  pass
else
  fail "could not create sbt/ivy repository"
fi

# ---------------------------------------------------------------------------
# Create test artifacts (JAR + ivy.xml)
# ---------------------------------------------------------------------------

begin_test "Create test JAR and ivy.xml"

cd "$WORK_DIR"

# Create ivy.xml descriptor
cat > ivy.xml <<EOF
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

# Create a minimal JAR file
mkdir -p jar-content/META-INF
cat > jar-content/META-INF/MANIFEST.MF <<EOF
Manifest-Version: 1.0
Implementation-Title: ${MODULE_NAME}
Implementation-Version: ${VERSION}
Specification-Vendor: com.test
EOF

mkdir -p jar-content/com/test
cat > jar-content/com/test/TestModule.class <<EOF
placeholder-scala-class
EOF

cd jar-content
JAR_FILE="${WORK_DIR}/${MODULE_NAME}_${SCALA_VERSION}-${VERSION}.jar"
zip -r "$JAR_FILE" META-INF/ com/ > /dev/null 2>&1

cd "$WORK_DIR"

if [ -f "$JAR_FILE" ] && [ -f "ivy.xml" ]; then
  pass
else
  fail "failed to create JAR or ivy.xml"
fi

# ---------------------------------------------------------------------------
# Upload ivy.xml via PUT
# ---------------------------------------------------------------------------

begin_test "Upload ivy.xml"

IVY_PATH="${IVY_BASE}/ivys/ivy.xml"
if curl -sf -X PUT "${IVY_URL}/${IVY_PATH}" \
  -H "$(auth_header)" \
  -H "Content-Type: application/xml" \
  --data-binary "@${WORK_DIR}/ivy.xml" > /dev/null 2>&1; then
  pass
else
  fail "PUT ivy.xml failed"
fi

# ---------------------------------------------------------------------------
# Upload JAR via PUT
# ---------------------------------------------------------------------------

begin_test "Upload JAR"

JAR_PATH="${IVY_BASE}/jars/${MODULE_NAME}_${SCALA_VERSION}-${VERSION}.jar"
if curl -sf -X PUT "${IVY_URL}/${JAR_PATH}" \
  -H "$(auth_header)" \
  -H "Content-Type: application/java-archive" \
  --data-binary "@${JAR_FILE}" > /dev/null 2>&1; then
  pass
else
  fail "PUT JAR failed"
fi

# ---------------------------------------------------------------------------
# Verify ivy.xml via HEAD (existence check)
# ---------------------------------------------------------------------------

begin_test "Verify ivy.xml exists (HEAD)"
sleep 1
STATUS=$(curl -s -o /dev/null -w '%{http_code}' -X HEAD \
  -H "$(auth_header)" "${IVY_URL}/${IVY_PATH}") || true
if [ "$STATUS" -ge 200 ] 2>/dev/null && [ "$STATUS" -lt 300 ] 2>/dev/null; then
  pass
else
  fail "HEAD ivy.xml returned ${STATUS}, expected 2xx"
fi

# ---------------------------------------------------------------------------
# Download ivy.xml
# ---------------------------------------------------------------------------

begin_test "Download ivy.xml"
if resp=$(curl -sf "${IVY_URL}/${IVY_PATH}" -H "$(auth_header)"); then
  if assert_contains "$resp" "$ORG" "ivy.xml should contain organisation"; then
    if assert_contains "$resp" "$MODULE_NAME" "ivy.xml should contain module name"; then
      if assert_contains "$resp" "$VERSION" "ivy.xml should contain revision"; then
        pass
      fi
    fi
  fi
else
  fail "download ivy.xml failed"
fi

# ---------------------------------------------------------------------------
# Download JAR and verify size
# ---------------------------------------------------------------------------

begin_test "Download JAR"
DL_FILE="${WORK_DIR}/downloaded.jar"
if curl -sf -H "$(auth_header)" -o "$DL_FILE" "${IVY_URL}/${JAR_PATH}"; then
  DL_SIZE=$(wc -c < "$DL_FILE" | tr -d ' ')
  ORIG_SIZE=$(wc -c < "$JAR_FILE" | tr -d ' ')
  if assert_eq "$DL_SIZE" "$ORIG_SIZE" "downloaded JAR size should match original"; then
    pass
  fi
else
  fail "download JAR failed"
fi

# ---------------------------------------------------------------------------
# Upload and download a sources JAR
# ---------------------------------------------------------------------------

begin_test "Upload and download sources JAR"

SOURCES_JAR="${WORK_DIR}/${MODULE_NAME}_${SCALA_VERSION}-${VERSION}-sources.jar"
# Create a trivial sources jar
mkdir -p "${WORK_DIR}/src-content/com/test"
cat > "${WORK_DIR}/src-content/com/test/TestModule.scala" <<EOF
package com.test
object TestModule {
  val version = "${VERSION}"
}
EOF
cd "${WORK_DIR}/src-content"
zip -r "$SOURCES_JAR" com/ > /dev/null 2>&1

SRCS_PATH="${IVY_BASE}/srcs/${MODULE_NAME}_${SCALA_VERSION}-${VERSION}-sources.jar"

UPLOAD_OK=true
if ! curl -sf -X PUT "${IVY_URL}/${SRCS_PATH}" \
  -H "$(auth_header)" \
  -H "Content-Type: application/java-archive" \
  --data-binary "@${SOURCES_JAR}" > /dev/null 2>&1; then
  UPLOAD_OK=false
fi

if [ "$UPLOAD_OK" = true ]; then
  DL_SRCS="${WORK_DIR}/downloaded-sources.jar"
  if curl -sf -H "$(auth_header)" -o "$DL_SRCS" "${IVY_URL}/${SRCS_PATH}"; then
    DL_SIZE=$(wc -c < "$DL_SRCS" | tr -d ' ')
    ORIG_SIZE=$(wc -c < "$SOURCES_JAR" | tr -d ' ')
    if assert_eq "$DL_SIZE" "$ORIG_SIZE" "sources JAR size should match"; then
      pass
    fi
  else
    fail "download sources JAR failed"
  fi
else
  fail "upload sources JAR failed"
fi

# ---------------------------------------------------------------------------
# Verify repository artifacts via management API
# ---------------------------------------------------------------------------

begin_test "List artifacts via management API"
if resp=$(api_get "/api/v1/repositories/${REPO_KEY}/artifacts"); then
  if assert_contains "$resp" "$MODULE_NAME" "artifact list should contain module name"; then
    pass
  fi
else
  fail "GET /api/v1/repositories/${REPO_KEY}/artifacts returned error"
fi

end_suite
