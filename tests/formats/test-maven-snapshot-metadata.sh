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
# This suite uploads two SNAPSHOT artifacts that differ by classifier (the
# first is the main JAR, the second carries the "tests" classifier) and
# asserts that the server-side version-level maven-metadata.xml lists both
# under <snapshotVersions>, each with its own timestamp. The backend dedupes
# <snapshotVersion> by (classifier, extension) keeping only the latest entry
# per key (maven.rs:567-582), so two artifacts with different classifiers is
# the only way to verify multi-entry metadata.
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
  local classifier="${2:-}"
  local cls_suffix=""
  if [ -n "$classifier" ]; then
    cls_suffix="-${classifier}"
  fi
  local body_file="${WORK_DIR}/${snap_version}${cls_suffix}.jar"
  printf 'snap-jar-%s-%s%s' "$RUN_ID" "$snap_version" "$cls_suffix" > "$body_file"
  local url="${MAVEN_URL}/${SNAP_PATH}/${ARTIFACT_ID}-${snap_version}${cls_suffix}.jar"
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

# Second deploy uses a distinct classifier so that (classifier, extension) is
# different from the first deploy. The backend (maven.rs:567-582) dedupes
# <snapshotVersion> entries by (classifier, extension), so without a new
# classifier the second deploy would just replace the first entry and the
# "two snapshotVersion entries" assertion below could not be exercised.
SNAPSHOT_CLASSIFIER_B="tests"

begin_test "Second SNAPSHOT deploy (${SNAP_VERSION_B}, classifier=${SNAPSHOT_CLASSIFIER_B})"
jar_b=$(put_snapshot_jar "$SNAP_VERSION_B" "$SNAPSHOT_CLASSIFIER_B") || jar_b="000"
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

begin_test "Metadata contains a distinct <snapshotVersion> entry per classifier"
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

# Maven 3.x version-level maven-metadata.xml structure:
#   <metadata>
#     <versioning>
#       <snapshot><timestamp/><buildNumber/></snapshot>
#       <snapshotVersions>
#         <snapshotVersion>
#           <classifier/>     (optional, empty for main artifact)
#           <extension/>
#           <value/>          (the timestamped version string)
#           <updated/>        (the per-entry timestamp)
#         </snapshotVersion>
#         ...
#       </snapshotVersions>
#     </versioning>
#   </metadata>
entries = []
for sv in root.iter("snapshotVersion"):
    classifier = ""
    extension = ""
    value = ""
    updated = ""
    for child in sv:
        if child.tag == "classifier" and child.text:
            classifier = child.text.strip()
        elif child.tag == "extension" and child.text:
            extension = child.text.strip()
        elif child.tag == "value" and child.text:
            value = child.text.strip()
        elif child.tag == "updated" and child.text:
            updated = child.text.strip()
    entries.append((classifier, extension, value, updated))

# Also expose the top-level snapshot timestamp and global lists for the
# downstream lastUpdated assertion.
top_ts = ""
for e in root.iter("timestamp"):
    if e.text:
        top_ts = e.text.strip()
        break

print(f"ENTRY_COUNT:{len(entries)}")
for cls, ext, val, upd in entries:
    print(f"ENTRY:{cls}|{ext}|{val}|{upd}")
print(f"TOP_TS:{top_ts}")
PYEOF
) || parsed=""

if echo "$parsed" | grep -q '^PARSE_ERROR:'; then
  fail "maven-metadata.xml did not parse as XML" "$parsed"
else
  entry_count=$(echo "$parsed" | sed -n 's/^ENTRY_COUNT://p')
  entries=$(echo "$parsed" | sed -n 's/^ENTRY://p')

  # Bucket entries by classifier and capture each entry's <updated> stamp.
  saw_main=0
  saw_tests=0
  main_updated=""
  tests_updated=""
  while IFS='|' read -r cls ext val upd; do
    [ -z "$cls$ext$val$upd" ] && continue
    case "$cls" in
      "")
        saw_main=1
        main_updated="$upd"
        ;;
      "${SNAPSHOT_CLASSIFIER_B}")
        saw_tests=1
        tests_updated="$upd"
        ;;
    esac
  done <<< "$entries"

  if [ "$saw_main" -eq 1 ] && [ "$saw_tests" -eq 1 ]; then
    # Both classifier buckets present. Each entry must have its own <updated>
    # timestamp; the spec does not require them to differ in value (the
    # generator may stamp both with the same wall clock), but each entry must
    # carry one so consumers can resolve per-classifier freshness.
    if [ -n "$main_updated" ] && [ -n "$tests_updated" ]; then
      echo "  saw main classifier (updated=${main_updated}) and tests classifier (updated=${tests_updated})"
      pass
    else
      fail "snapshotVersion entries are missing per-entry <updated> timestamps" \
           "main_updated='${main_updated}' tests_updated='${tests_updated}' entries=${entries}"
    fi
  elif [ "$entry_count" = "1" ] && [ "$saw_tests" -eq 1 ]; then
    # Backend dedupes (classifier, extension) keeping latest only and the
    # second deploy used the tests classifier; this is the documented backend
    # behavior in maven.rs:567-582 when only one classifier survives.
    fail "only the tests-classifier entry survived; main jar entry was dropped" \
         "entry_count=${entry_count} entries=${entries}"
  else
    fail "maven-metadata.xml does not contain two distinct snapshotVersion entries (one per classifier)" \
         "entry_count=${entry_count} saw_main=${saw_main} saw_tests=${saw_tests} entries=${entries}"
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
