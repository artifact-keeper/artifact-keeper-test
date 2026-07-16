#!/usr/bin/env bash
# test-sbom-declared-deps.sh -- E2E for artifact-keeper#870.
#
# Proves the declared-dependency SBOM source: a Maven artifact whose POM
# declares dependencies must produce a NON-EMPTY SBOM even though a scanner
# cannot enumerate the (placeholder) jar. Before the #870 fix the SBOM read
# path sourced components only from scanner output, so this artifact produced
# an authoritative-looking "components": [] -- the silent-empty bug.
#
# What this asserts that the existing sbom-correctness-gate.sh (npm + lockfile,
# scanner-derived) does NOT:
#   - declared deps from the POM appear with no scan inventory present
#   - a ${property}-versioned dependency is resolved (the backend reads the
#     POM back from object storage and interpolates against <properties>)
#   - a maven purl is synthesized (pkg:maven/<group>/<artifact>@<version>)
#   - test-scoped dependencies are excluded
#   - the document carries an honest completeness signal (declared/partial),
#     not "complete" with an empty inventory
#
# Environment: BASE_URL, ADMIN_USER, ADMIN_PASS, RUN_ID (see lib/common.sh).

# shellcheck source=../lib/common.sh disable=SC1091
source "$(dirname "$0")/../lib/common.sh"

begin_suite "sbom-declared-deps"
auth_admin
setup_workdir

REPO_KEY="sbom-decl-${RUN_ID}"
GROUP_ID="com.aktest"
MVN_ARTIFACT="sbom-declared"
VERSION="1.0.0"
MAVEN_URL="${BASE_URL}/maven/${REPO_KEY}"
GROUP_PATH=$(echo "$GROUP_ID" | tr '.' '/')
BASE_PATH="${GROUP_PATH}/${MVN_ARTIFACT}/${VERSION}"
JAR_REL="${BASE_PATH}/${MVN_ARTIFACT}-${VERSION}.jar"
POM_REL="${BASE_PATH}/${MVN_ARTIFACT}-${VERSION}.pom"

# Expected declared dependencies (resolved):
GUAVA_PURL="pkg:maven/com.google.guava/guava@32.1.3-jre"
COMMONS_PURL="pkg:maven/org.apache.commons/commons-lang3@3.14.0"

# Resolved at runtime.
ARTIFACT_ID=""

cleanup_decl() {
  # shellcheck disable=SC2086
  curl -s $CURL_TIMEOUT -X DELETE -H "$(auth_header)" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}" >/dev/null 2>&1 || true
  [ -n "${WORK_DIR:-}" ] && rm -rf "$WORK_DIR" 2>/dev/null || true
}
trap cleanup_decl EXIT

# ---------------------------------------------------------------------------
# Feature gate: this behaviour ships in v1.2.0 (artifact-keeper#870). On older
# backends the declared-only SBOM is structurally empty, so asserting > 0 would
# flap; require_feature skips loudly instead.
# ---------------------------------------------------------------------------
begin_test "Backend supports declared-dependency SBOM (#870)"
require_feature "sbom_declared_dependencies" || { end_suite; exit 0; }
pass

# ---------------------------------------------------------------------------
# Create repo.
# ---------------------------------------------------------------------------
begin_test "Create maven local repository"
if create_local_repo "$REPO_KEY" "maven"; then
  pass
else
  fail "could not create maven repository ${REPO_KEY}"
  end_suite
  exit 1
fi

# ---------------------------------------------------------------------------
# Build a placeholder JAR (a scanner finds no packages in it) and a POM that
# declares two compile dependencies (one property-versioned, one literal) and
# one test-scoped dependency that must be excluded.
# ---------------------------------------------------------------------------
begin_test "Build placeholder JAR and dependency-bearing POM"
mkdir -p "${WORK_DIR}/jar/META-INF"
cat > "${WORK_DIR}/jar/META-INF/MANIFEST.MF" <<EOF
Manifest-Version: 1.0
Created-By: artifact-keeper-test
Implementation-Title: ${MVN_ARTIFACT}
Implementation-Version: ${VERSION}
EOF
JAR_FILE="${WORK_DIR}/${MVN_ARTIFACT}-${VERSION}.jar"
( cd "${WORK_DIR}/jar" && zip -qr "$JAR_FILE" META-INF/ ) 2>/dev/null

POM_FILE="${WORK_DIR}/${MVN_ARTIFACT}-${VERSION}.pom"
cat > "$POM_FILE" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <groupId>${GROUP_ID}</groupId>
  <artifactId>${MVN_ARTIFACT}</artifactId>
  <version>${VERSION}</version>
  <packaging>jar</packaging>
  <properties>
    <guava.version>32.1.3-jre</guava.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>\${guava.version}</version>
    </dependency>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-lang3</artifactId>
      <version>3.14.0</version>
    </dependency>
    <dependency>
      <groupId>org.junit.jupiter</groupId>
      <artifactId>junit-jupiter</artifactId>
      <version>5.10.0</version>
      <scope>test</scope>
    </dependency>
  </dependencies>
</project>
EOF

if [ -f "$JAR_FILE" ] && [ -f "$POM_FILE" ]; then
  pass
else
  fail "failed to build JAR or POM"
  end_suite
  exit 1
fi

# ---------------------------------------------------------------------------
# Upload JAR then POM via the Maven endpoint.
# ---------------------------------------------------------------------------
begin_test "Upload JAR"
# shellcheck disable=SC2086
if curl -sf $CURL_TIMEOUT -X PUT "${MAVEN_URL}/${JAR_REL}" \
  -u "${ADMIN_USER}:${ADMIN_PASS}" \
  -H "Content-Type: application/java-archive" \
  --data-binary "@${JAR_FILE}" >/dev/null 2>&1; then
  pass
else
  fail "PUT JAR failed"
fi

begin_test "Upload POM"
# shellcheck disable=SC2086
if curl -sf $CURL_TIMEOUT -X PUT "${MAVEN_URL}/${POM_REL}" \
  -u "${ADMIN_USER}:${ADMIN_PASS}" \
  -H "Content-Type: application/xml" \
  --data-binary "@${POM_FILE}" >/dev/null 2>&1; then
  pass
else
  fail "PUT POM failed"
fi

# ---------------------------------------------------------------------------
# Resolve artifact_id of the JAR.
# ---------------------------------------------------------------------------
begin_test "Resolve artifact_id for the JAR"
jar_re="${MVN_ARTIFACT}-${VERSION}\\.jar$"
# shellcheck disable=SC2086
list_status=$(curl -s -o "${WORK_DIR}/list.json" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts") || list_status="000"
if [ "$list_status" = "200" ]; then
  ARTIFACT_ID=$(jq -er --arg re "$jar_re" \
    '.items | map(select(((.path // "") | test($re)) or ((.name // "") | test($re)))) | first | .id // empty' \
    < "${WORK_DIR}/list.json" 2>/dev/null || true)
  # Fallback: some builds key the grouped artifact by version, not jar path.
  if [ -z "$ARTIFACT_ID" ]; then
    ARTIFACT_ID=$(jq -er --arg v "$VERSION" \
      '.items | map(select(.version == $v)) | first | .id // empty' \
      < "${WORK_DIR}/list.json" 2>/dev/null || true)
  fi
fi
if [ -n "$ARTIFACT_ID" ]; then
  echo "  artifact_id=${ARTIFACT_ID}"
  pass
else
  fail "could not resolve artifact_id (list HTTP ${list_status})" \
    "$(head -c 400 "${WORK_DIR}/list.json" 2>/dev/null || true)"
  end_suite
  exit 1
fi

# ---------------------------------------------------------------------------
# Generate the SBOM and assert it is NOT empty (the #870 core assertion).
# ---------------------------------------------------------------------------
begin_test "POST /api/v1/sbom returns 200 with component_count >= 2"
sbom_payload=$(jq -n --arg id "$ARTIFACT_ID" \
  '{artifact_id: $id, format: "cyclonedx", force_regenerate: true}')
# shellcheck disable=SC2086
sbom_status=$(curl -s -o "${WORK_DIR}/sbom.json" -w '%{http_code}' $CURL_TIMEOUT \
  -X POST -H "$(auth_header)" -H "Content-Type: application/json" \
  -d "$sbom_payload" "${BASE_URL}/api/v1/sbom") || sbom_status="000"

if [ "$sbom_status" != "200" ]; then
  fail "POST /api/v1/sbom returned HTTP ${sbom_status}" \
    "$(head -c 400 "${WORK_DIR}/sbom.json" 2>/dev/null || true)"
  end_suite
  exit 1
fi
component_count=$(jq -r '.component_count // 0' < "${WORK_DIR}/sbom.json")
echo "  component_count=${component_count}"
if [ "${component_count:-0}" -ge 2 ]; then
  pass
else
  # This is the #870 silent-empty class: a POM that names two compile
  # dependencies produced fewer than two components.
  fail "declared-dependency SBOM has component_count=${component_count} (expected >= 2; #870 regression)" \
    "$(head -c 600 "${WORK_DIR}/sbom.json" 2>/dev/null || true)"
fi

# ---------------------------------------------------------------------------
# Fetch the full document and assert the declared components, the resolved
# property version, the maven purls, and test-scope exclusion.
# ---------------------------------------------------------------------------
begin_test "Fetch SBOM content for component assertions"
# shellcheck disable=SC2086
get_status=$(curl -s -o "${WORK_DIR}/content.json" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/sbom/by-artifact/${ARTIFACT_ID}?format=cyclonedx") || get_status="000"
if [ "$get_status" = "200" ] && jq -e '.content.components | type == "array"' \
     < "${WORK_DIR}/content.json" >/dev/null 2>&1; then
  pass
else
  fail "GET /api/v1/sbom/by-artifact returned HTTP ${get_status} or no components array" \
    "$(head -c 400 "${WORK_DIR}/content.json" 2>/dev/null || true)"
  end_suite
  exit 1
fi

begin_test "Property-versioned dependency (guava) present with resolved purl"
if jq -e --arg purl "$GUAVA_PURL" \
     '.content.components | any(.purl == $purl)' \
     < "${WORK_DIR}/content.json" >/dev/null 2>&1; then
  pass
else
  # Proves the storage POM fallback + ${property} interpolation: the stored
  # metadata keeps the literal ${guava.version}; resolution requires reading
  # the POM back and interpolating against <properties>.
  fail "guava not present as ${GUAVA_PURL} (property resolution / declared-dep extraction failed)" \
    "$(jq -c '[.content.components[]?.purl]' < "${WORK_DIR}/content.json" 2>/dev/null | head -c 600)"
fi

begin_test "Literal-versioned dependency (commons-lang3) present with purl"
if jq -e --arg purl "$COMMONS_PURL" \
     '.content.components | any(.purl == $purl)' \
     < "${WORK_DIR}/content.json" >/dev/null 2>&1; then
  pass
else
  fail "commons-lang3 not present as ${COMMONS_PURL}" \
    "$(jq -c '[.content.components[]?.purl]' < "${WORK_DIR}/content.json" 2>/dev/null | head -c 600)"
fi

begin_test "Test-scoped dependency (junit-jupiter) is excluded"
if jq -e '.content.components | any((.name // "") | test("junit-jupiter"))' \
     < "${WORK_DIR}/content.json" >/dev/null 2>&1; then
  fail "test-scoped junit-jupiter leaked into the SBOM (should be excluded)" \
    "$(jq -c '[.content.components[]?.name]' < "${WORK_DIR}/content.json" 2>/dev/null | head -c 600)"
else
  pass
fi

# ---------------------------------------------------------------------------
# Honest completeness signal: a declared-only SBOM (no scanner inventory) must
# be marked declared or partial, never an authoritative "complete".
# ---------------------------------------------------------------------------
begin_test "Completeness signal is declared or partial (not authoritative-empty)"
completeness=$(jq -r '
    (.content.metadata.properties // [])
    | map(select(.name == "artifact-keeper:scan-completeness"))
    | first | .value // ""' < "${WORK_DIR}/content.json" 2>/dev/null || true)
echo "  scan-completeness=${completeness:-<absent>}"
case "$completeness" in
  declared|partial)
    pass
    ;;
  complete|"")
    # "complete" or a missing signal on a declared-only artifact would mean the
    # SBOM claims an authoritative full inventory it does not have (#870 class).
    fail "completeness signal is '${completeness:-<absent>}' for a declared-only SBOM; expected 'declared' or 'partial'"
    ;;
  *)
    fail "unexpected completeness signal '${completeness}'"
    ;;
esac

end_suite
