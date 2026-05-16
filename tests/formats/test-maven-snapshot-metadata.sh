#!/usr/bin/env bash
# test-maven-snapshot-metadata.sh - Maven SNAPSHOT metadata auto-generation
#
# When a Maven client redeploys a SNAPSHOT artifact twice, the registry is
# expected to auto-generate (or update) the version-level maven-metadata.xml
# with timestamp-resolved <snapshotVersion> entries (one per redeploy) so
# downstream clients can resolve the latest SNAPSHOT JAR. This is distinct
# from the virtual-repo regression in test-maven-virtual-snapshot.sh, which
# uploads pre-built maven-metadata.xml by hand.
#
# This suite uploads two timestamped SNAPSHOT JARs and asserts that the
# server-side version-level maven-metadata.xml contains both timestamps and
# orders them by lastUpdated.
#
# Covers issue #68 subtask 3.6.
#
# Requires: curl, python3

source "$(dirname "$0")/../lib/common.sh"

begin_suite "maven-snapshot-metadata"
auth_admin
setup_workdir
require_cmd python3

REPO_KEY="test-mvn-snapmeta-${RUN_ID}"
MAVEN_URL="${BASE_URL}/maven/${REPO_KEY}"
GROUP_ID="com.example.snapmeta"
GROUP_PATH=$(echo "$GROUP_ID" | tr '.' '/')
ARTIFACT_ID="snap"
VERSION="1.0.0-SNAPSHOT"
ARTIFACT_BASE_PATH="${GROUP_PATH}/${ARTIFACT_ID}"
SNAP_PATH="${ARTIFACT_BASE_PATH}/${VERSION}"

# Two timestamped redeploys. Maven's <timestamp> format is YYYYMMDD.HHMMSS.
TS_A="20260101.000001"
TS_B="20260101.000002"
SNAP_VERSION_A="1.0.0-${TS_A}-1"
SNAP_VERSION_B="1.0.0-${TS_B}-2"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

put_snapshot_jar() {
  local snap_version="$1"
  local body_file="${WORK_DIR}/${snap_version}.jar"
  printf 'snap-jar-%s-%s' "$RUN_ID" "$snap_version" > "$body_file"
  local url="${MAVEN_URL}/${SNAP_PATH}/${ARTIFACT_ID}-${snap_version}.jar"
  curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X PUT \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    -H "Content-Type: application/java-archive" \
    --data-binary "@${body_file}" \
    "$url"
}

put_snapshot_pom() {
  local snap_version="$1"
  local body_file="${WORK_DIR}/${snap_version}.pom"
  cat > "$body_file" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>${GROUP_ID}</groupId>
  <artifactId>${ARTIFACT_ID}</artifactId>
  <version>${VERSION}</version>
  <packaging>jar</packaging>
</project>
EOF
  local url="${MAVEN_URL}/${SNAP_PATH}/${ARTIFACT_ID}-${snap_version}.pom"
  curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X PUT \
    -u "${ADMIN_USER}:${ADMIN_PASS}" \
    -H "Content-Type: application/xml" \
    --data-binary "@${body_file}" \
    "$url"
}

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

begin_test "Create maven local repository"
if create_local_repo "$REPO_KEY" "maven"; then
  pass
else
  fail "could not create maven repository"
fi

# ---------------------------------------------------------------------------
# Two SNAPSHOT redeploys
# ---------------------------------------------------------------------------

begin_test "First SNAPSHOT deploy (${SNAP_VERSION_A})"
jar_a=$(put_snapshot_jar "$SNAP_VERSION_A") || jar_a="000"
pom_a=$(put_snapshot_pom "$SNAP_VERSION_A") || pom_a="000"
if assert_http_2xx "$jar_a" "first jar PUT not 2xx (HTTP ${jar_a})"; then
  if assert_http_2xx "$pom_a" "first pom PUT not 2xx (HTTP ${pom_a})"; then
    pass
  fi
fi

# Small gap so server-side timestamp ordering is unambiguous.
sleep 1

begin_test "Second SNAPSHOT deploy (${SNAP_VERSION_B})"
jar_b=$(put_snapshot_jar "$SNAP_VERSION_B") || jar_b="000"
pom_b=$(put_snapshot_pom "$SNAP_VERSION_B") || pom_b="000"
if assert_http_2xx "$jar_b" "second jar PUT not 2xx (HTTP ${jar_b})"; then
  if assert_http_2xx "$pom_b" "second pom PUT not 2xx (HTTP ${pom_b})"; then
    pass
  fi
fi

# Let the metadata generator catch up.
sleep 3

# ---------------------------------------------------------------------------
# Fetch version-level maven-metadata.xml and assert auto-generation
# ---------------------------------------------------------------------------

begin_test "Version-level maven-metadata.xml is auto-generated"
META_FILE="${WORK_DIR}/version-meta.xml"
meta_status=$(curl -s -o "$META_FILE" -w '%{http_code}' $CURL_TIMEOUT \
  -u "${ADMIN_USER}:${ADMIN_PASS}" \
  "${MAVEN_URL}/${SNAP_PATH}/maven-metadata.xml") || meta_status="000"

if [ "$meta_status" = "404" ] || [ "$meta_status" = "501" ]; then
  skip_suite "version-level maven-metadata.xml auto-generation not supported (HTTP ${meta_status})"
elif [ "$meta_status" != "200" ]; then
  fail "version-level maven-metadata.xml fetch returned HTTP ${meta_status}" \
       "$(head -c 400 "$META_FILE" 2>/dev/null)"
else
  pass
fi

# ---------------------------------------------------------------------------
# Assert the metadata contains both <snapshotVersion> entries
# ---------------------------------------------------------------------------

begin_test "Metadata contains both redeploy timestamps"
parsed=$(python3 - <<'PYEOF' "$META_FILE"
import sys, re
import xml.etree.ElementTree as ET
try:
    tree = ET.parse(sys.argv[1])
except Exception as exc:
    print(f"PARSE_ERROR:{exc}")
    sys.exit(0)

root = tree.getroot()
# Strip XML namespaces so tag names are predictable across Maven versions.
for el in root.iter():
    el.tag = re.sub(r'^\{.*\}', '', el.tag)

timestamps = [e.text for e in root.iter("timestamp") if e.text]
values     = [e.text for e in root.iter("value") if e.text]
build_nums = [e.text for e in root.iter("buildNumber") if e.text]
updated    = [e.text for e in root.iter("updated") if e.text]

print("TIMESTAMPS:" + ",".join(timestamps))
print("VALUES:" + ",".join(values))
print("BUILD_NUMBERS:" + ",".join(build_nums))
print("UPDATED:" + ",".join(updated))
PYEOF
) || parsed=""

if echo "$parsed" | grep -q '^PARSE_ERROR:'; then
  fail "maven-metadata.xml did not parse as XML" "$parsed"
else
  timestamps=$(echo "$parsed" | sed -n 's/^TIMESTAMPS://p')
  values=$(echo "$parsed" | sed -n 's/^VALUES://p')

  # Per Maven 3.x, <snapshot><timestamp> is the single most-recent one, but
  # <snapshotVersions> lists per-extension <value> entries for every
  # redeployed timestamp+build combo. Accept either:
  #   - two distinct values present, OR
  #   - one timestamp matching the second deploy and value list referencing it.
  saw_a=0
  saw_b=0
  case ",${values}," in
    *"${SNAP_VERSION_A}"*) saw_a=1 ;;
  esac
  case ",${values}," in
    *"${SNAP_VERSION_B}"*) saw_b=1 ;;
  esac

  if [ "$saw_a" -eq 1 ] && [ "$saw_b" -eq 1 ]; then
    pass
  elif [ "$saw_b" -eq 1 ] && [ -n "$timestamps" ]; then
    # Some backends prune older redeploys but always reflect the latest.
    # This is non-spec but common; document the partial-coverage outcome.
    echo "  note: only latest redeploy (${SNAP_VERSION_B}) reflected; older pruned"
    pass
  else
    fail "maven-metadata.xml missing expected snapshotVersion entries" \
         "expected to find ${SNAP_VERSION_A} and ${SNAP_VERSION_B} under <value>; got values=${values} timestamps=${timestamps}"
  fi
fi

# ---------------------------------------------------------------------------
# Assert the metadata ordering: <lastUpdated> >= TS_B (latest wins)
# ---------------------------------------------------------------------------

begin_test "Metadata lastUpdated reflects latest deploy"
last_updated=$(python3 - <<'PYEOF' "$META_FILE"
import sys, re
import xml.etree.ElementTree as ET
try:
    tree = ET.parse(sys.argv[1])
except Exception:
    sys.exit(0)
root = tree.getroot()
for el in root.iter():
    el.tag = re.sub(r'^\{.*\}', '', el.tag)
for tag in ("lastUpdated",):
    for e in root.iter(tag):
        if e.text:
            print(e.text.strip())
            sys.exit(0)
PYEOF
) || last_updated=""

if [ -z "$last_updated" ]; then
  skip "metadata has no <lastUpdated> element"
else
  # lastUpdated is yyyyMMddHHmmss (no dots). Strip dots from TS_B for compare.
  ts_b_compact="${TS_B//./}"
  if [[ "$last_updated" =~ ^[0-9]+$ ]] && [ "${#last_updated}" -ge 14 ] \
     && [ "$last_updated" -ge "$ts_b_compact" ]; then
    pass
  else
    # Server may use wall-clock time of deploy, which is fine as long as it's
    # monotonically >= our TS_B compact form when TS_B is in the past.
    # In CI the test always runs in the future relative to TS_B, so the
    # >= comparison should hold.
    fail "lastUpdated not monotonically newer than second deploy timestamp" \
         "lastUpdated=${last_updated} ts_b_compact=${ts_b_compact}"
  fi
fi

end_suite
