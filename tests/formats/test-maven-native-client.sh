#!/usr/bin/env bash
# test-maven-native-client.sh - Maven native client smoke test
#
# Pushes a synthetic JAR via `mvn deploy:deploy-file` and pulls it back via
# `mvn dependency:get`. The point of this script (vs. test-maven.sh, which
# uses curl) is to catch regressions that are only visible to the real
# Maven client: auth dialect mismatches, content-type negotiation,
# maven-metadata.xml shape, and the way mvn parses HTTP redirects.
#
# Skipped automatically when `mvn` is not on PATH.
#
# Requires: mvn, zip (for jar assembly when `jar` is unavailable)

source "$(dirname "$0")/../lib/common.sh"

begin_suite "maven-native-client"
auth_admin
setup_workdir
require_cmd mvn

REPO_KEY="test-mvn-nc-${RUN_ID}"
GROUP_ID="com.example.native"
ARTIFACT_ID="native-smoke"
VERSION="1.0.0"
MAVEN_URL="${BASE_URL}/maven/${REPO_KEY}"

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
# Build a synthetic JAR
# -------------------------------------------------------------------------

begin_test "Assemble synthetic JAR"
cd "$WORK_DIR"

mkdir -p jar-content/META-INF jar-content/com/example/smoke
cat > jar-content/META-INF/MANIFEST.MF <<EOF
Manifest-Version: 1.0
Created-By: artifact-keeper-test
Implementation-Title: ${ARTIFACT_ID}
Implementation-Version: ${VERSION}
EOF
# Note: this is not a real .class file, just a marker. mvn deploy:deploy-file
# does not validate JAR contents, it just uploads the bytes verbatim.
echo 'placeholder' > jar-content/com/example/smoke/Marker.class

JAR_FILE="${WORK_DIR}/${ARTIFACT_ID}-${VERSION}.jar"
if command -v jar &>/dev/null; then
  (cd jar-content && jar cf "$JAR_FILE" META-INF/ com/) 2>/dev/null
elif command -v zip &>/dev/null; then
  (cd jar-content && zip -r "$JAR_FILE" META-INF/ com/ > /dev/null)
else
  fail "neither jar nor zip available, cannot build synthetic JAR"
  end_suite
fi

if [ -s "$JAR_FILE" ]; then
  pass
else
  fail "JAR was not produced"
fi

# -------------------------------------------------------------------------
# Build a matching POM
# -------------------------------------------------------------------------

begin_test "Write POM"
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
</project>
EOF
if [ -s "$POM_FILE" ]; then
  pass
else
  fail "POM was not produced"
fi

# -------------------------------------------------------------------------
# Configure a one-off Maven settings file
#
# We deliberately keep settings.xml inside WORK_DIR so the test is hermetic
# and never touches the runner's ~/.m2/. The server id "ak-test" is what
# ties together <distributionManagement> auth in the deploy command.
# -------------------------------------------------------------------------

begin_test "Write Maven settings.xml"
SETTINGS_FILE="${WORK_DIR}/settings.xml"
LOCAL_REPO="${WORK_DIR}/.m2-local"
mkdir -p "$LOCAL_REPO"

# Maven 3.8.1+ ships a default mirror called `maven-default-http-blocker`
# that refuses any plain-HTTP repository (mirrorOf = `external:http:*`).
# In release-gate runs the backend lives at the cluster-internal HTTP URL
# `http://artifact-keeper-backend.test-${RUN_ID}.svc.cluster.local:8080/maven/...`,
# which the blocker rejects with:
#   "Blocked mirror for repositories: [ak-test (...)] from the specified
#    remote repositories: [central, maven-default-http-blocker]".
#
# We override the blocker by declaring our own mirror that captures the
# `ak-test` repo id with `<blocked>false</blocked>`. Maven evaluates
# user-defined mirrors before the built-in blocker, so this lets the
# request through. The mirror url is the same as the upstream repo,
# making the redirect a no-op. The mirror id needs matching credentials
# in <servers> because Maven looks up auth by the resolved mirror id.
cat > "$SETTINGS_FILE" <<EOF
<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0">
  <localRepository>${LOCAL_REPO}</localRepository>
  <mirrors>
    <mirror>
      <id>ak-test-allow-http</id>
      <name>Allow plain-HTTP for ak-test cluster-internal repo</name>
      <url>${MAVEN_URL}</url>
      <mirrorOf>ak-test</mirrorOf>
      <blocked>false</blocked>
    </mirror>
  </mirrors>
  <servers>
    <server>
      <id>ak-test</id>
      <username>${ADMIN_USER}</username>
      <password>${ADMIN_PASS}</password>
    </server>
    <server>
      <id>ak-test-allow-http</id>
      <username>${ADMIN_USER}</username>
      <password>${ADMIN_PASS}</password>
    </server>
  </servers>
</settings>
EOF
if [ -s "$SETTINGS_FILE" ]; then
  pass
else
  fail "settings.xml was not written"
fi

# -------------------------------------------------------------------------
# mvn deploy:deploy-file
# -------------------------------------------------------------------------

begin_test "mvn deploy:deploy-file pushes JAR + POM"
# The maven-deploy-plugin (default v2.7) uses the legacy Wagon HTTP transport,
# which has no built-in retry. A transient 401/5xx from the backend during the
# initial PUT (POM upload) tanks the whole deploy. Run 25214268566 hit this on
# v1.1.6 with no test/backend changes vs the run that passed (25194405511);
# the deploy reported "401 Unauthorized" while curl-based maven, mvn
# dependency:get, and other format tests in the same namespace worked fine.
#
# Retry up to 3 times on any failure with a 2s backoff, mirroring the policy
# already used by auth_admin() in tests/lib/common.sh and the password-change
# retry added in PR #125.
deploy_log="${WORK_DIR}/mvn-deploy.log"
deploy_attempts=3
deploy_ok=false
for deploy_attempt in $(seq 1 "$deploy_attempts"); do
  if mvn -B -q --settings "$SETTINGS_FILE" \
      deploy:deploy-file \
      -Dfile="$JAR_FILE" \
      -DpomFile="$POM_FILE" \
      -DrepositoryId="ak-test" \
      -Durl="$MAVEN_URL" \
      > "$deploy_log" 2>&1; then
    deploy_ok=true
    break
  fi
  if [ "$deploy_attempt" -lt "$deploy_attempts" ]; then
    echo "  mvn deploy:deploy-file attempt ${deploy_attempt}/${deploy_attempts} failed, retrying in 2s..."
    sleep 2
  fi
done
if $deploy_ok; then
  pass
else
  fail "mvn deploy:deploy-file failed after ${deploy_attempts} attempts; tail of log: $(tail -n 20 "$deploy_log" | tr '\n' ' ')"
fi

# -------------------------------------------------------------------------
# mvn dependency:get
# -------------------------------------------------------------------------

begin_test "mvn dependency:get pulls JAR back"
# Use a separate local repo to force a real network fetch.
PULL_REPO="${WORK_DIR}/.m2-pull"
mkdir -p "$PULL_REPO"

PULL_SETTINGS="${WORK_DIR}/settings-pull.xml"
# Same http-blocker override as above, but for the pull-side settings.
cat > "$PULL_SETTINGS" <<EOF
<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0">
  <localRepository>${PULL_REPO}</localRepository>
  <mirrors>
    <mirror>
      <id>ak-test-allow-http</id>
      <name>Allow plain-HTTP for ak-test cluster-internal repo</name>
      <url>${MAVEN_URL}</url>
      <mirrorOf>ak-test</mirrorOf>
      <blocked>false</blocked>
    </mirror>
  </mirrors>
  <servers>
    <server>
      <id>ak-test</id>
      <username>${ADMIN_USER}</username>
      <password>${ADMIN_PASS}</password>
    </server>
    <server>
      <id>ak-test-allow-http</id>
      <username>${ADMIN_USER}</username>
      <password>${ADMIN_PASS}</password>
    </server>
  </servers>
</settings>
EOF

pull_log="${WORK_DIR}/mvn-pull.log"
if mvn -B -q --settings "$PULL_SETTINGS" \
    dependency:get \
    -DremoteRepositories="ak-test::default::${MAVEN_URL}" \
    -Dartifact="${GROUP_ID}:${ARTIFACT_ID}:${VERSION}" \
    -Dtransitive=false \
    > "$pull_log" 2>&1; then
  # Verify the JAR landed in the pull-side local repo.
  expected="${PULL_REPO}/$(echo "$GROUP_ID" | tr '.' '/')/${ARTIFACT_ID}/${VERSION}/${ARTIFACT_ID}-${VERSION}.jar"
  if [ -s "$expected" ]; then
    pass
  else
    fail "mvn reported success but JAR is missing at ${expected}"
  fi
else
  fail "mvn dependency:get failed; tail of log: $(tail -n 20 "$pull_log" | tr '\n' ' ')"
fi

end_suite
