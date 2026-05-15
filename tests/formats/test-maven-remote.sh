#!/usr/bin/env bash
# test-maven-remote.sh - Maven remote proxy, virtual checksum, and version ordering E2E tests
#
# Covers:
#   - Remote proxy: create remote Maven repo proxying repo1.maven.org, pull known artifact
#   - Virtual checksum (bug #663): upload to local, resolve .sha256 through virtual
#   - Version ordering (bug #568): upload multiple versions, verify maven-metadata.xml ordering
#
# Requires: curl, jq, shasum (or sha256sum), zip or jar

source "$(dirname "$0")/../lib/common.sh"

begin_suite "maven-remote"
auth_admin
setup_workdir

REMOTE_KEY="test-mvn-remote-${RUN_ID}"
LOCAL_KEY="test-mvn-local-${RUN_ID}"
VIRTUAL_KEY="test-mvn-virtual-${RUN_ID}"
UPSTREAM_URL="https://repo1.maven.org/maven2"

# -------------------------------------------------------------------------
# Remote proxy tests
# -------------------------------------------------------------------------

begin_test "Create remote Maven repository"
if create_remote_repo "$REMOTE_KEY" "maven" "$UPSTREAM_URL"; then
  pass
else
  fail "could not create remote Maven repo"
fi

begin_test "Verify upstream reachability"
if curl -sf --max-time 10 "${UPSTREAM_URL}/junit/junit/4.13.2/junit-4.13.2.pom" > /dev/null 2>&1; then
  UPSTREAM_REACHABLE=true
  pass
else
  UPSTREAM_REACHABLE=false
  skip "repo1.maven.org unreachable from test environment"
fi

begin_test "Pull POM through remote proxy"
if [ "$UPSTREAM_REACHABLE" != "true" ]; then
  skip "upstream unreachable"
else
  REMOTE_MAVEN_URL="${BASE_URL}/maven/${REMOTE_KEY}"
  POM_PATH="junit/junit/4.13.2/junit-4.13.2.pom"
  if resp=$(curl -sf $CURL_TIMEOUT -u "${ADMIN_USER}:${ADMIN_PASS}" \
      "${REMOTE_MAVEN_URL}/${POM_PATH}" 2>/dev/null); then
    if assert_contains "$resp" "<artifactId>junit</artifactId>" \
        "proxied POM should contain junit artifactId"; then
      pass
    fi
  else
    fail "GET POM through remote proxy failed"
  fi
fi

begin_test "Pull JAR through remote proxy"
if [ "$UPSTREAM_REACHABLE" != "true" ]; then
  skip "upstream unreachable"
else
  JAR_PATH="junit/junit/4.13.2/junit-4.13.2.jar"
  DL_JAR="${WORK_DIR}/junit-remote.jar"
  if curl -sf $CURL_TIMEOUT -u "${ADMIN_USER}:${ADMIN_PASS}" \
      -o "$DL_JAR" "${REMOTE_MAVEN_URL}/${JAR_PATH}" 2>/dev/null; then
    if [ -s "$DL_JAR" ]; then
      pass
    else
      fail "downloaded JAR is empty"
    fi
  else
    fail "GET JAR through remote proxy failed"
  fi
fi

begin_test "Pull maven-metadata.xml through remote proxy"
if [ "$UPSTREAM_REACHABLE" != "true" ]; then
  skip "upstream unreachable"
else
  META_PATH="junit/junit/maven-metadata.xml"
  if resp=$(curl -sf $CURL_TIMEOUT -u "${ADMIN_USER}:${ADMIN_PASS}" \
      "${REMOTE_MAVEN_URL}/${META_PATH}" 2>/dev/null); then
    if assert_contains "$resp" "4.13.2" \
        "remote maven-metadata.xml should list 4.13.2"; then
      pass
    fi
  else
    skip "maven-metadata.xml not available through remote proxy"
  fi
fi

# -------------------------------------------------------------------------
# Virtual checksum test (bug #663)
#
# Upload a JAR to a local repo, create a virtual repo with that local as a
# member, then request the .sha256 checksum file through the virtual repo.
# -------------------------------------------------------------------------

begin_test "Create local Maven repository"
if create_local_repo "$LOCAL_KEY" "maven"; then
  pass
else
  fail "could not create local Maven repo"
fi

begin_test "Create test JAR for checksum test"
cd "$WORK_DIR"
mkdir -p cksum-jar/META-INF
cat > cksum-jar/META-INF/MANIFEST.MF <<EOF
Manifest-Version: 1.0
Created-By: artifact-keeper-test
EOF
echo "checksum-test-content-${RUN_ID}" > cksum-jar/payload.txt
cd cksum-jar
CKSUM_JAR="${WORK_DIR}/cksum-artifact-1.0.jar"
if command -v jar &>/dev/null; then
  jar cf "$CKSUM_JAR" META-INF/ payload.txt 2>/dev/null || \
    zip -r "$CKSUM_JAR" META-INF/ payload.txt > /dev/null 2>&1
else
  zip -r "$CKSUM_JAR" META-INF/ payload.txt > /dev/null 2>&1
fi
cd "$WORK_DIR"

if [ -f "$CKSUM_JAR" ] && [ -s "$CKSUM_JAR" ]; then
  pass
else
  fail "failed to create test JAR"
fi

begin_test "Upload JAR to local repo"
LOCAL_MAVEN_URL="${BASE_URL}/maven/${LOCAL_KEY}"
CKSUM_GROUP="com/test/cksum"
CKSUM_ARTIFACT="cksum-artifact"
CKSUM_VERSION="1.0"
JAR_UPLOAD_PATH="${CKSUM_GROUP}/${CKSUM_ARTIFACT}/${CKSUM_VERSION}/${CKSUM_ARTIFACT}-${CKSUM_VERSION}.jar"
EXPECTED_SHA256=$(shasum -a 256 "$CKSUM_JAR" | awk '{print $1}')

if curl -sf $CURL_TIMEOUT -X PUT "${LOCAL_MAVEN_URL}/${JAR_UPLOAD_PATH}" \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    -H "Content-Type: application/java-archive" \
    --data-binary "@${CKSUM_JAR}" > /dev/null 2>&1; then
  pass
else
  fail "PUT JAR to local repo failed"
fi

begin_test "Create virtual Maven repository"
if create_virtual_repo "$VIRTUAL_KEY" "maven"; then
  pass
else
  fail "could not create virtual Maven repo"
fi

begin_test "Add local repo as virtual member"
if api_post "/api/v1/repositories/${VIRTUAL_KEY}/members" \
    "{\"member_key\":\"${LOCAL_KEY}\",\"priority\":1}" > /dev/null 2>&1; then
  pass
else
  fail "could not add local repo as virtual member"
fi

sleep 1

begin_test "GET .sha256 checksum through virtual repo (bug #663)"
VIRTUAL_MAVEN_URL="${BASE_URL}/maven/${VIRTUAL_KEY}"
SHA256_PATH="${JAR_UPLOAD_PATH}.sha256"
if sha256_resp=$(curl -sf $CURL_TIMEOUT -u "${ADMIN_USER}:${ADMIN_PASS}" \
    "${VIRTUAL_MAVEN_URL}/${SHA256_PATH}" 2>/dev/null); then
  # The checksum response should be a hex string matching the uploaded artifact
  sha256_clean=$(echo "$sha256_resp" | tr -d '[:space:]')
  if assert_eq "$sha256_clean" "$EXPECTED_SHA256" \
      "virtual .sha256 does not match uploaded artifact checksum"; then
    pass
  fi
else
  fail "GET .sha256 through virtual repo returned error (bug #663)"
fi

begin_test "GET JAR through virtual repo"
DL_VIRTUAL="${WORK_DIR}/virtual-downloaded.jar"
if curl -sf $CURL_TIMEOUT -u "${ADMIN_USER}:${ADMIN_PASS}" \
    -o "$DL_VIRTUAL" "${VIRTUAL_MAVEN_URL}/${JAR_UPLOAD_PATH}" 2>/dev/null; then
  DL_SHA256=$(shasum -a 256 "$DL_VIRTUAL" | awk '{print $1}')
  if assert_eq "$DL_SHA256" "$EXPECTED_SHA256" \
      "JAR content mismatch through virtual repo"; then
    pass
  fi
else
  fail "GET JAR through virtual repo failed"
fi

# -------------------------------------------------------------------------
# Version ordering test (bug #568)
#
# Upload three versions (1.0, 1.1, 2.0) of a GAV to the local repo, then
# verify maven-metadata.xml reports <release> as 2.0 and versions are listed
# in order.
# -------------------------------------------------------------------------

VO_GROUP="com/test/ordering"
VO_ARTIFACT="order-artifact"

begin_test "Upload version 1.0"
echo "v1.0-content" > "${WORK_DIR}/v1.0.jar"
if curl -sf $CURL_TIMEOUT -X PUT \
    "${LOCAL_MAVEN_URL}/${VO_GROUP}/${VO_ARTIFACT}/1.0/${VO_ARTIFACT}-1.0.jar" \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    --data-binary "@${WORK_DIR}/v1.0.jar" > /dev/null 2>&1; then
  pass
else
  fail "PUT version 1.0 failed"
fi

begin_test "Upload version 1.1"
echo "v1.1-content" > "${WORK_DIR}/v1.1.jar"
if curl -sf $CURL_TIMEOUT -X PUT \
    "${LOCAL_MAVEN_URL}/${VO_GROUP}/${VO_ARTIFACT}/1.1/${VO_ARTIFACT}-1.1.jar" \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    --data-binary "@${WORK_DIR}/v1.1.jar" > /dev/null 2>&1; then
  pass
else
  fail "PUT version 1.1 failed"
fi

begin_test "Upload version 2.0"
echo "v2.0-content" > "${WORK_DIR}/v2.0.jar"
if curl -sf $CURL_TIMEOUT -X PUT \
    "${LOCAL_MAVEN_URL}/${VO_GROUP}/${VO_ARTIFACT}/2.0/${VO_ARTIFACT}-2.0.jar" \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    --data-binary "@${WORK_DIR}/v2.0.jar" > /dev/null 2>&1; then
  pass
else
  fail "PUT version 2.0 failed"
fi

begin_test "Verify maven-metadata.xml version ordering (bug #568)"
sleep 2
META_URL="${LOCAL_MAVEN_URL}/${VO_GROUP}/${VO_ARTIFACT}/maven-metadata.xml"
if metadata=$(curl -sf $CURL_TIMEOUT -u "${ADMIN_USER}:${ADMIN_PASS}" \
    "${META_URL}" 2>/dev/null); then
  # Check <release> is 2.0
  if echo "$metadata" | grep -q "<release>2.0</release>"; then
    # Verify all three versions are present
    has_1_0=$(echo "$metadata" | grep -c "<version>1.0</version>") || true
    has_1_1=$(echo "$metadata" | grep -c "<version>1.1</version>") || true
    has_2_0=$(echo "$metadata" | grep -c "<version>2.0</version>") || true
    if [ "$has_1_0" -ge 1 ] && [ "$has_1_1" -ge 1 ] && [ "$has_2_0" -ge 1 ]; then
      pass
    else
      fail "maven-metadata.xml missing one or more versions"
    fi
  else
    # Check if release tag exists at all
    if echo "$metadata" | grep -q "<release>"; then
      release_val=$(echo "$metadata" | grep "<release>" | sed 's/.*<release>\(.*\)<\/release>.*/\1/')
      fail "expected <release>2.0</release> but got <release>${release_val}</release> (bug #568)"
    else
      fail "maven-metadata.xml has no <release> element (bug #568)"
    fi
  fi
else
  fail "GET maven-metadata.xml returned error"
fi

begin_test "Verify version order in metadata"
if [ -n "${metadata:-}" ]; then
  # Extract versions in order from the XML
  versions=$(echo "$metadata" | grep "<version>" | sed 's/.*<version>\(.*\)<\/version>.*/\1/' | tr '\n' ',')
  # Versions should appear in ascending order: 1.0, 1.1, 2.0
  # Check that 1.0 appears before 2.0
  pos_1_0=$(echo "$metadata" | grep -n "<version>1.0</version>" | head -1 | cut -d: -f1) || true
  pos_2_0=$(echo "$metadata" | grep -n "<version>2.0</version>" | head -1 | cut -d: -f1) || true
  if [ -n "$pos_1_0" ] && [ -n "$pos_2_0" ] && [ "$pos_1_0" -lt "$pos_2_0" ]; then
    pass
  else
    fail "versions not in ascending order: ${versions}"
  fi
else
  skip "no metadata to check"
fi

# -------------------------------------------------------------------------
# Cleanup
# -------------------------------------------------------------------------

api_delete "/api/v1/repositories/${VIRTUAL_KEY}" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${LOCAL_KEY}" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${REMOTE_KEY}" > /dev/null 2>&1 || true

end_suite
