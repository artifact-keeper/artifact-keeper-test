#!/usr/bin/env bash
# test-maven-virtual-snapshot.sh
#
# Regression test for artifact-keeper/artifact-keeper#839:
# "Virtual maven repo doesn't provide SNAPSHOT artifacts".
#
# Before the fix, a virtual maven repo returned NOT_FOUND for both the
# version-level maven-metadata.xml of a SNAPSHOT and for the SNAPSHOT JAR
# when requested by its -SNAPSHOT alias. This suite uploads a SNAPSHOT
# (JAR, POM, and both levels of maven-metadata.xml) to a hosted maven
# repo, adds that repo as the sole member of a virtual maven repo, then
# confirms that the virtual repo serves all three resource shapes.

source "$(dirname "$0")/../lib/common.sh"

begin_suite "maven-virtual-snapshot"
auth_admin
setup_workdir

HOSTED_KEY="test-mvn-snap-host-${RUN_ID}"
VIRTUAL_KEY="test-mvn-snap-virt-${RUN_ID}"

GROUP_ID="com.example.snaptest"
GROUP_PATH=$(echo "$GROUP_ID" | tr '.' '/')
ARTIFACT_ID="snap"
VERSION="1.0.0-SNAPSHOT"
SNAP_TS="20261231.235959"
SNAP_BUILD="1"
SNAP_VERSION="1.0.0-${SNAP_TS}-${SNAP_BUILD}"
LAST_UPDATED="${SNAP_TS//./}"

ARTIFACT_BASE_PATH="${GROUP_PATH}/${ARTIFACT_ID}"
SNAP_PATH="${ARTIFACT_BASE_PATH}/${VERSION}"

JAR_FILE="${WORK_DIR}/${ARTIFACT_ID}-${SNAP_VERSION}.jar"
POM_FILE="${WORK_DIR}/${ARTIFACT_ID}-${SNAP_VERSION}.pom"
VERSION_META_FILE="${WORK_DIR}/version-maven-metadata.xml"
GROUP_META_FILE="${WORK_DIR}/group-maven-metadata.xml"

# -------------------------------------------------------------------------
# Fixture generation
# -------------------------------------------------------------------------

# Jar body. Content does not need to be a real zip for this test since we
# only check that the bytes round-trip byte-for-byte through the virtual
# repo. A real jar would work too.
printf 'test-snap-jar-%s' "$RUN_ID" > "$JAR_FILE"

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

# Version-level SNAPSHOT metadata: this is the file that before #839's fix
# the virtual branch could not serve (parse_metadata_path returned None).
cat > "$VERSION_META_FILE" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<metadata modelVersion="1.1.0">
  <groupId>${GROUP_ID}</groupId>
  <artifactId>${ARTIFACT_ID}</artifactId>
  <version>${VERSION}</version>
  <versioning>
    <snapshot>
      <timestamp>${SNAP_TS}</timestamp>
      <buildNumber>${SNAP_BUILD}</buildNumber>
    </snapshot>
    <lastUpdated>${LAST_UPDATED}</lastUpdated>
    <snapshotVersions>
      <snapshotVersion>
        <extension>jar</extension>
        <value>${SNAP_VERSION}</value>
        <updated>${LAST_UPDATED}</updated>
      </snapshotVersion>
      <snapshotVersion>
        <extension>pom</extension>
        <value>${SNAP_VERSION}</value>
        <updated>${LAST_UPDATED}</updated>
      </snapshotVersion>
    </snapshotVersions>
  </versioning>
</metadata>
EOF

# Group-level metadata (so a maven client can discover the SNAPSHOT version).
cat > "$GROUP_META_FILE" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<metadata>
  <groupId>${GROUP_ID}</groupId>
  <artifactId>${ARTIFACT_ID}</artifactId>
  <versioning>
    <latest>${VERSION}</latest>
    <versions>
      <version>${VERSION}</version>
    </versions>
    <lastUpdated>${LAST_UPDATED}</lastUpdated>
  </versioning>
</metadata>
EOF

# -------------------------------------------------------------------------
# Repositories
# -------------------------------------------------------------------------

begin_test "Create hosted maven repo"
if create_local_repo "$HOSTED_KEY" "maven"; then pass; else fail "could not create hosted repo"; fi

begin_test "Create virtual maven repo with hosted as member"
if create_virtual_repo "$VIRTUAL_KEY" "maven" "$HOSTED_KEY"; then pass; else fail "could not create virtual repo"; fi

# -------------------------------------------------------------------------
# Populate hosted repo with a SNAPSHOT.
#
# Uploads MUST go through the Maven format endpoint (PUT /maven/<key>/<path>),
# not the generic /api/v1/repositories/<key>/artifacts/<path> endpoint. The
# generic endpoint stores artifacts under a content-addressed storage key and
# does NOT write the artifact_metadata rows that maven-metadata.xml generation
# (group-level aggregation) and version-level metadata serving rely on. Real
# Maven clients (mvn deploy) always hit /maven/<key>/<path>.
# -------------------------------------------------------------------------

begin_test "Upload SNAPSHOT JAR under timestamped filename"
if curl -sf $CURL_TIMEOUT -X PUT \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    -H "Content-Type: application/java-archive" \
    --data-binary "@${JAR_FILE}" \
    "${BASE_URL}/maven/${HOSTED_KEY}/${SNAP_PATH}/${ARTIFACT_ID}-${SNAP_VERSION}.jar" > /dev/null; then
  pass
else
  fail "jar upload failed"
fi

begin_test "Upload SNAPSHOT POM under timestamped filename"
if curl -sf $CURL_TIMEOUT -X PUT \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    -H "Content-Type: application/xml" \
    --data-binary "@${POM_FILE}" \
    "${BASE_URL}/maven/${HOSTED_KEY}/${SNAP_PATH}/${ARTIFACT_ID}-${SNAP_VERSION}.pom" > /dev/null; then
  pass
else
  fail "pom upload failed"
fi

begin_test "Upload version-level maven-metadata.xml"
if curl -sf $CURL_TIMEOUT -X PUT \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    -H "Content-Type: application/xml" \
    --data-binary "@${VERSION_META_FILE}" \
    "${BASE_URL}/maven/${HOSTED_KEY}/${SNAP_PATH}/maven-metadata.xml" > /dev/null; then
  pass
else
  fail "version metadata upload failed"
fi

begin_test "Upload group-level maven-metadata.xml"
if curl -sf $CURL_TIMEOUT -X PUT \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    -H "Content-Type: application/xml" \
    --data-binary "@${GROUP_META_FILE}" \
    "${BASE_URL}/maven/${HOSTED_KEY}/${ARTIFACT_BASE_PATH}/maven-metadata.xml" > /dev/null; then
  pass
else
  fail "group metadata upload failed"
fi

# Give indexers a moment to catch up.
sleep 2

# -------------------------------------------------------------------------
# Baseline: hosted repo serves its own content directly. If these fail,
# the problem is outside #839 and the #839 checks below are meaningless.
# -------------------------------------------------------------------------

begin_test "Baseline: hosted repo serves version-level SNAPSHOT metadata"
if curl -sf $CURL_TIMEOUT -H "$(auth_header)" \
    "${BASE_URL}/maven/${HOSTED_KEY}/${SNAP_PATH}/maven-metadata.xml" \
    -o "${WORK_DIR}/hosted-version-meta.xml"; then
  if grep -q "<snapshotVersion>" "${WORK_DIR}/hosted-version-meta.xml"; then
    pass
  else
    fail "hosted metadata missing snapshotVersion entries"
  fi
else
  fail "hosted repo did not serve its own version-level metadata"
fi

begin_test "Baseline: hosted repo serves SNAPSHOT jar by timestamped filename"
if curl -sf $CURL_TIMEOUT -H "$(auth_header)" \
    "${BASE_URL}/maven/${HOSTED_KEY}/${SNAP_PATH}/${ARTIFACT_ID}-${SNAP_VERSION}.jar" \
    -o "${WORK_DIR}/hosted.jar"; then
  if diff -q "$JAR_FILE" "${WORK_DIR}/hosted.jar" > /dev/null 2>&1; then
    pass
  else
    fail "hosted jar content differs from uploaded bytes"
  fi
else
  fail "hosted repo did not serve its own jar"
fi

# -------------------------------------------------------------------------
# The actual #839 regression checks. Pre-fix, both of these return 404.
# -------------------------------------------------------------------------

begin_test "Virtual repo serves version-level SNAPSHOT metadata (#839)"
HTTP_CODE=$(curl -s -o "${WORK_DIR}/virt-version-meta.xml" -w '%{http_code}' \
  $CURL_TIMEOUT -H "$(auth_header)" \
  "${BASE_URL}/maven/${VIRTUAL_KEY}/${SNAP_PATH}/maven-metadata.xml" 2>/dev/null || echo "000")
if [ "$HTTP_CODE" = "200" ]; then
  if grep -q "<snapshotVersion>" "${WORK_DIR}/virt-version-meta.xml" && \
     grep -q "${SNAP_VERSION}" "${WORK_DIR}/virt-version-meta.xml"; then
    pass
  else
    fail "virtual version metadata missing expected snapshotVersion entries (got HTTP ${HTTP_CODE})"
  fi
else
  fail "virtual repo returned HTTP ${HTTP_CODE} for version-level SNAPSHOT metadata"
fi

begin_test "Virtual repo serves SNAPSHOT jar by SNAPSHOT alias name (#839)"
# Maven clients request the jar using the SNAPSHOT alias (foo-1.0.0-SNAPSHOT.jar),
# not the timestamped filename. local_fetch_by_path's strict WHERE path = $2 lookup
# missed this alias, so every member returned NOT_FOUND.
HTTP_CODE=$(curl -s -o "${WORK_DIR}/virt-alias.jar" -w '%{http_code}' \
  $CURL_TIMEOUT -H "$(auth_header)" \
  "${BASE_URL}/maven/${VIRTUAL_KEY}/${SNAP_PATH}/${ARTIFACT_ID}-${VERSION}.jar" 2>/dev/null || echo "000")
if [ "$HTTP_CODE" = "200" ]; then
  if diff -q "$JAR_FILE" "${WORK_DIR}/virt-alias.jar" > /dev/null 2>&1; then
    pass
  else
    fail "virtual jar content differs from uploaded bytes"
  fi
else
  fail "virtual repo returned HTTP ${HTTP_CODE} for SNAPSHOT alias jar"
fi

begin_test "Virtual repo serves SNAPSHOT jar by timestamped filename"
HTTP_CODE=$(curl -s -o "${WORK_DIR}/virt-ts.jar" -w '%{http_code}' \
  $CURL_TIMEOUT -H "$(auth_header)" \
  "${BASE_URL}/maven/${VIRTUAL_KEY}/${SNAP_PATH}/${ARTIFACT_ID}-${SNAP_VERSION}.jar" 2>/dev/null || echo "000")
if [ "$HTTP_CODE" = "200" ]; then
  if diff -q "$JAR_FILE" "${WORK_DIR}/virt-ts.jar" > /dev/null 2>&1; then
    pass
  else
    fail "virtual timestamped jar content differs from uploaded bytes"
  fi
else
  fail "virtual repo returned HTTP ${HTTP_CODE} for timestamped jar"
fi

begin_test "Virtual repo serves group-level maven-metadata.xml"
HTTP_CODE=$(curl -s -o "${WORK_DIR}/virt-group-meta.xml" -w '%{http_code}' \
  $CURL_TIMEOUT -H "$(auth_header)" \
  "${BASE_URL}/maven/${VIRTUAL_KEY}/${ARTIFACT_BASE_PATH}/maven-metadata.xml" 2>/dev/null || echo "000")
if [ "$HTTP_CODE" = "200" ]; then
  if grep -q "${VERSION}" "${WORK_DIR}/virt-group-meta.xml"; then
    pass
  else
    fail "virtual group metadata missing SNAPSHOT version entry"
  fi
else
  fail "virtual repo returned HTTP ${HTTP_CODE} for group-level metadata"
fi

end_suite
