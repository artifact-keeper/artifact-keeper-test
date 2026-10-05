#!/usr/bin/env bash
# test-maven-prefixes.sh - Maven .meta/prefixes.txt with nested groupIds
#
# Regression test for artifact-keeper/artifact-keeper#4367. A repository
# holding both com.example.prefixes and com.example.prefixes.sub must not list
# /com/example/prefixes and /com/example/prefixes/sub: Resolver 2.x (Maven 4)
# only accepts paths that reach a leaf of the prefix tree, so the nested line
# makes it deny every other com/example/prefixes/... artifact on the client.
#
# Maven 3.9 never downloads the file, so the client half runs Maven 4 from
# Central. The repository is declared as a plain <repository>: Resolver skips
# prefix files for mirrored repositories, which is how test-maven-native-client.sh
# reaches the backend.
#
# Requires: curl, tar, shasum, java 17+

source "$(dirname "$0")/../lib/common.sh"

begin_suite "maven-prefixes"
auth_admin
setup_workdir

begin_test "Backend drops nested entries from .meta/prefixes.txt (artifact-keeper#4367)"
require_feature "maven_prefixes_no_nesting" || { end_suite; exit 0; }
pass

REPO_KEY="test-mvn-prefixes-${RUN_ID}"
MAVEN_URL="${BASE_URL}/maven/${REPO_KEY}"
PARENT_GROUP="com.example.prefixes"
CHILD_GROUP="com.example.prefixes.sub"
MAVEN4_VERSION="4.0.0-rc-7"

begin_test "Create maven local repository"
if create_local_repo "$REPO_KEY" "maven"; then
  pass
else
  fail_fatal "could not create maven repository"
fi

# put_pom GROUP ARTIFACT [DEPENDENCY_ARTIFACT]
# Uploads a pom-packaged artifact, optionally depending on PARENT_GROUP:DEP.
put_pom() {
  local group="$1" artifact="$2" dep="${3:-}" deps=""
  if [ -n "$dep" ]; then
    deps="<dependencies><dependency><groupId>${PARENT_GROUP}</groupId><artifactId>${dep}</artifactId><version>1.0</version><type>pom</type></dependency></dependencies>"
  fi
  local pom="${WORK_DIR}/${artifact}-1.0.pom"
  cat > "$pom" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>${group}</groupId>
  <artifactId>${artifact}</artifactId>
  <version>1.0</version>
  <packaging>pom</packaging>
  ${deps}
</project>
EOF
  local path
  path="$(echo "$group" | tr '.' '/')/${artifact}/1.0/${artifact}-1.0.pom"
  curl -sf $CURL_TIMEOUT -X PUT "${MAVEN_URL}/${path}" \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    -H "Content-Type: application/xml" \
    --data-binary "@${pom}" > /dev/null 2>&1
}

begin_test "Upload artifacts under a parent groupId and a nested one"
if put_pom "$PARENT_GROUP" bolt && put_pom "$PARENT_GROUP" widget bolt && put_pom "$CHILD_GROUP" gadget; then
  pass
else
  fail_fatal "PUT of a POM failed"
fi

# -------------------------------------------------------------------------
# The file itself
# -------------------------------------------------------------------------

PREFIXES_FILE="${WORK_DIR}/prefixes.txt"

begin_test "GET .meta/prefixes.txt"
if curl -sf $CURL_TIMEOUT -o "$PREFIXES_FILE" "${MAVEN_URL}/.meta/prefixes.txt" \
    && [ "$(head -n 1 "$PREFIXES_FILE")" = "## repository-prefixes/2.0" ]; then
  pass
else
  fail_fatal "no prefixes file with a repository-prefixes/2.0 header; got: $(head -c 300 "$PREFIXES_FILE" 2>/dev/null || true)"
fi

begin_test "No entry has a listed ancestor"
nested=""
while IFS= read -r line; do
  case "$line" in /*) ;; *) continue ;; esac
  while IFS= read -r other; do
    case "$line" in "${other}"/*) nested="${nested} ${line} (under ${other})" ;; esac
  done < <(grep '^/' "$PREFIXES_FILE")
done < "$PREFIXES_FILE"
if [ -z "$nested" ]; then
  pass
else
  fail "nested entries:${nested}"
fi

begin_test "Every uploaded groupId is covered"
missing=""
for group in "$PARENT_GROUP" "$CHILD_GROUP"; do
  group_path="/$(echo "$group" | tr '.' '/')"
  covered=false
  while IFS= read -r line; do
    case "$group_path" in "$line" | "$line"/*) covered=true ;; esac
  done < <(grep '^/' "$PREFIXES_FILE")
  $covered || missing="${missing} ${group_path}"
done
if [ -z "$missing" ]; then
  pass
else
  fail "not covered:${missing}; file: $(tr '\n' ' ' < "$PREFIXES_FILE")"
fi

# -------------------------------------------------------------------------
# A real Resolver 2.x client
# -------------------------------------------------------------------------

begin_test "Maven ${MAVEN4_VERSION} available"
require_cmd java
require_cmd shasum
java_major=$(java -version 2>&1 | sed -n -E 's/.*version "([0-9]+).*/\1/p' | head -n 1)
if [ "${java_major:-0}" -lt 17 ]; then
  skip_suite "java 17+ required for Maven 4, found ${java_major:-none}"
fi
MAVEN4_TGZ="${WORK_DIR}/apache-maven-${MAVEN4_VERSION}-bin.tar.gz"
MAVEN4_DIST="https://repo1.maven.org/maven2/org/apache/maven/apache-maven/${MAVEN4_VERSION}/apache-maven-${MAVEN4_VERSION}-bin.tar.gz"
if curl -sf --max-time 300 -o "$MAVEN4_TGZ" "$MAVEN4_DIST" \
    && [ "$(curl -sf --max-time 30 "${MAVEN4_DIST}.sha512" | cut -c1-128)" = "$(shasum -a 512 "$MAVEN4_TGZ" | cut -c1-128)" ] \
    && tar -xzf "$MAVEN4_TGZ" -C "$WORK_DIR"; then
  MVN4="${WORK_DIR}/apache-maven-${MAVEN4_VERSION}/bin/mvn"
  pass
else
  infra_fail "could not download or verify ${MAVEN4_DIST}"
  end_suite
fi

MVN_REPO_ID="ak-prefixes"
SETTINGS_FILE="${WORK_DIR}/settings.xml"
# Override the built-in HTTP blocker with a mirror of nothing, so the
# plain-HTTP backend stays a non-mirrored repository.
cat > "$SETTINGS_FILE" <<EOF
<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0">
  <localRepository>${WORK_DIR}/.m2-prefixes</localRepository>
  <mirrors>
    <mirror>
      <id>maven-default-http-blocker</id>
      <mirrorOf>dummy</mirrorOf>
      <url>http://0.0.0.0/</url>
      <blocked>false</blocked>
    </mirror>
  </mirrors>
  <profiles>
    <profile>
      <id>ak</id>
      <repositories>
        <repository>
          <id>${MVN_REPO_ID}</id>
          <url>${MAVEN_URL}/</url>
        </repository>
      </repositories>
    </profile>
  </profiles>
  <activeProfiles>
    <activeProfile>ak</activeProfile>
  </activeProfiles>
</settings>
EOF

begin_test "Maven 4 resolves a parent-group artifact and its parent-group dependency"
mvn_log="${WORK_DIR}/mvn-prefixes.log"
mvn_rc=0
"$MVN4" -B --settings "$SETTINGS_FILE" \
  org.apache.maven.plugins:maven-dependency-plugin:3.8.1:get \
  -Dartifact="${PARENT_GROUP}:widget:1.0:pom" > "$mvn_log" 2>&1 || mvn_rc=$?
bolt="${WORK_DIR}/.m2-prefixes/$(echo "$PARENT_GROUP" | tr '.' '/')/bolt/1.0/bolt-1.0.pom"
if ! grep -q "auto-discovered prefixes for remote repository ${MVN_REPO_ID}" "$mvn_log"; then
  # Without this the run proves nothing: the filter never saw the file.
  fail "Maven did not load the repository's prefixes file; tail of log: $(tail -n 20 "$mvn_log" | tr '\n' ' ')"
elif [ "$mvn_rc" -eq 0 ] && [ -s "$bolt" ]; then
  pass
else
  unresolved=$(grep -m 1 -o 'could not be resolved: .*' "$mvn_log" | cut -c1-300 || true)
  fail "mvn exit ${mvn_rc}: ${unresolved:-$(tail -n 20 "$mvn_log" | tr '\n' ' ')}"
fi

end_suite
