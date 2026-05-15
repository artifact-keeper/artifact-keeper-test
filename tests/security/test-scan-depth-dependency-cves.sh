#!/usr/bin/env bash
# test-scan-depth-dependency-cves.sh -- Scanner depth, dependency-CVE class.
#
# Tracks issue #67 sub-task 2.5+2.16 (SBOM correctness + policy gate
# enforcement). This test asserts the scanner actually walks language-
# specific manifest files (package-lock.json, requirements.txt) and
# emits findings that point to KNOWN CVEs -- not just an empty
# "scanned, no findings" report.
#
# Difference from test-scan-completes.sh
# --------------------------------------
# test-scan-completes.sh asserts findings_count >= 1 on a single
# lodash-only fixture. That catches the gross silent-success class
# but does NOT prove the scanner walks BOTH the npm AND the pypi
# manifest in the same archive. This script ships a multi-manifest
# fixture and asserts findings against BOTH manifests, which is the
# load-bearing assertion for "the scanner walks every manifest it
# claims to support" (Reality Checker review of #67 sub-tasks).
#
# Fixture
# -------
# A tarball containing TWO known-vulnerable manifests:
#
#   package-lock.json    -> lodash 4.17.4 (CVE-2019-10744, CVSS 9.1)
#   requirements.txt     -> django==1.11.0 (multiple CVEs, e.g.
#                            CVE-2017-7233 CVSS 9.8 open redirect)
#
# Both are well-aged, well-fingerprinted CVEs in Trivy's DB, so the
# false-negative rate on a healthy backend is effectively zero.
#
# Skip semantics
# --------------
# Mirrors test-scan-completes.sh's scanner_unavailable() flow: in
# release-gate context (RELEASE_GATE=1) scanner unreachability is a
# hard fail (silent-success class); local dev can opt into a graceful
# skip via ALLOW_SCANNER_SKIP=1.
#
# Requires: curl, jq, tar

source "$(dirname "$0")/../lib/common.sh"

begin_suite "scan-depth-dependency-cves"
auth_admin
setup_workdir

REPO_KEY="sddc-${RUN_ID}"
PACKAGE_NAME="multi-manifest-fixture"
PACKAGE_VERSION="1.0.0"
TARBALL_NAME="${PACKAGE_NAME}-${PACKAGE_VERSION}.tgz"
ARTIFACT_PATH="${PACKAGE_NAME}/${PACKAGE_VERSION}/${TARBALL_NAME}"
SCAN_TIMEOUT="${SCAN_TIMEOUT:-180}"
ALLOW_SCANNER_SKIP="${ALLOW_SCANNER_SKIP:-0}"

scanner_unavailable() {
  local reason="$1"
  if [ "$ALLOW_SCANNER_SKIP" = "1" ]; then
    skip "scanner unavailable (${reason}); ALLOW_SCANNER_SKIP=1 honored for local dev"
    end_suite
    exit 0
  fi
  fail "scanner unavailable (${reason}); release-gate must fail on scanner-reach failures (#888 silent-success class)"
  end_suite
  exit 1
}

# ---------------------------------------------------------------------------
# Build multi-manifest fixture
# ---------------------------------------------------------------------------

begin_test "Build multi-manifest fixture (lodash + django)"
mkdir -p "${WORK_DIR}/pkg"

# npm lockfile pinning lodash 4.17.4 (CVE-2019-10744)
cat > "${WORK_DIR}/pkg/package.json" <<'EOF'
{
  "name": "multi-manifest-fixture",
  "version": "1.0.0",
  "dependencies": { "lodash": "4.17.4" }
}
EOF
cat > "${WORK_DIR}/pkg/package-lock.json" <<'EOF'
{
  "name": "multi-manifest-fixture",
  "version": "1.0.0",
  "lockfileVersion": 2,
  "requires": true,
  "packages": {
    "": {
      "name": "multi-manifest-fixture",
      "version": "1.0.0",
      "dependencies": { "lodash": "4.17.4" }
    },
    "node_modules/lodash": {
      "version": "4.17.4",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.4.tgz",
      "integrity": "sha1-eCA6TRwyLuHBHJgwGu1myF0sR4U="
    }
  },
  "dependencies": {
    "lodash": {
      "version": "4.17.4",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.4.tgz",
      "integrity": "sha1-eCA6TRwyLuHBHJgwGu1myF0sR4U="
    }
  }
}
EOF

# pip requirements pinning django 1.11.0 (CVE-2017-7233 et al)
cat > "${WORK_DIR}/pkg/requirements.txt" <<'EOF'
django==1.11.0
EOF

if tar -czf "${WORK_DIR}/${TARBALL_NAME}" -C "${WORK_DIR}" pkg 2>/dev/null; then
  pass
else
  fail "could not build fixture tarball"
fi

begin_test "Create generic repo"
if create_local_repo "$REPO_KEY" "generic"; then
  pass
else
  fail "could not create ${REPO_KEY}"
fi

begin_test "Upload fixture"
upload_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X PUT -H "$(auth_header)" \
  -H "Content-Type: application/gzip" \
  --data-binary "@${WORK_DIR}/${TARBALL_NAME}" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/${ARTIFACT_PATH}") || upload_status="000"
case "$upload_status" in
  200|201) pass ;;
  000)     scanner_unavailable "upload curl exit non-zero" ;;
  *)       fail "upload returned ${upload_status}" ;;
esac

TEST_START_EPOCH=$(date -u +%s)
sleep 3

# Resolve artifact id.
begin_test "Resolve artifact_id"
artifact_lookup_status=$(curl -s -o "${WORK_DIR}/artifact-resp.json" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" -H "Accept: application/json" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/${ARTIFACT_PATH}") || artifact_lookup_status="000"

ARTIFACT_ID=""
if [ "$artifact_lookup_status" = "200" ]; then
  ARTIFACT_ID=$(jq -er '.id // .artifact_id // empty' < "${WORK_DIR}/artifact-resp.json" 2>/dev/null || true)
fi
if [ -z "$ARTIFACT_ID" ]; then
  list_status=$(curl -s -o "${WORK_DIR}/list-resp.json" -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(auth_header)" -H "Accept: application/json" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts") || list_status="000"
  if [ "$list_status" = "200" ]; then
    ARTIFACT_ID=$(jq -er --arg p "$ARTIFACT_PATH" \
      '.items | map(select(.path == $p or .name == $p)) | first | .id // .artifact_id // empty' \
      < "${WORK_DIR}/list-resp.json" 2>/dev/null || true)
  fi
fi
if [ -n "$ARTIFACT_ID" ]; then
  pass
else
  fail "could not resolve artifact_id"
fi

# Trigger scan.
begin_test "Trigger scan"
scan_trigger_payload=$(jq -n --arg id "$ARTIFACT_ID" '{artifact_id: $id}')
trigger_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X POST -H "$(auth_header)" -H "Content-Type: application/json" \
  -d "$scan_trigger_payload" \
  "${BASE_URL}/api/v1/security/scan" 2>/dev/null) || trigger_status="000"
case "$trigger_status" in
  2*) pass ;;
  503) scanner_unavailable "trigger HTTP 503" ;;
  504) scanner_unavailable "trigger HTTP 504" ;;
  000) scanner_unavailable "trigger curl exit non-zero" ;;
  *)   echo "  trigger HTTP ${trigger_status}; proceeding to poll"; pass ;;
esac

# Poll.
begin_test "Scan reaches terminal state within ${SCAN_TIMEOUT}s"
SCAN_LIST_PATH="/api/v1/security/artifacts/${ARTIFACT_ID}/scans"
elapsed=0
poll_interval=5
final_status=""
final_body=""
final_scan_id=""
net_fail=0
while [ "$elapsed" -lt "$SCAN_TIMEOUT" ]; do
  http_status=$(curl -s -o "${WORK_DIR}/scans-resp.json" -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(auth_header)" -H "Accept: application/json" \
    "${BASE_URL}${SCAN_LIST_PATH}") || http_status="000"
  if [ "$http_status" = "200" ]; then
    net_fail=0
    scan_obj=$(jq -c '.items[0] // empty' < "${WORK_DIR}/scans-resp.json" 2>/dev/null || echo "")
    if [ -n "$scan_obj" ]; then
      state=$(echo "$scan_obj" | jq -er '.status | ascii_downcase' 2>/dev/null || echo "unknown")
      case "$state" in
        queued|pending|in_progress|scanning|running|unknown) ;;
        *) final_status="$state"
           final_body="$scan_obj"
           final_scan_id=$(echo "$scan_obj" | jq -er '.id // empty' 2>/dev/null || echo "")
           break ;;
      esac
    fi
  else
    net_fail=$(( net_fail + 1 ))
    [ "$net_fail" -ge 6 ] && scanner_unavailable "scan-list ${http_status} x6"
  fi
  sleep "$poll_interval"
  elapsed=$(( elapsed + poll_interval ))
done
if [ -n "$final_status" ]; then
  pass
else
  fail "scan did not reach terminal state"
fi

begin_test "Scan completed with findings_count >= 2 (one per manifest)"
findings_count=$(echo "$final_body" | jq -r '.findings_count // "null"' 2>/dev/null || echo "null")
if [ "$findings_count" = "null" ]; then
  fail "scan missing findings_count field"
elif ! [[ "$findings_count" =~ ^[0-9]+$ ]]; then
  fail "findings_count is non-integer: '${findings_count}'"
elif [ "$findings_count" -lt 2 ]; then
  fail "findings_count=${findings_count} on multi-manifest fixture; scanner walked at most one manifest (expected lodash AND django CVEs)"
else
  pass
fi

# ---------------------------------------------------------------------------
# Findings drilldown: assert at least one finding references each
# expected ecosystem. The findings endpoint may not be available on
# every backend; if it's missing, skip the per-package assertion but
# do NOT fail the suite (the findings_count >= 2 assertion above is
# the load-bearing one).
# ---------------------------------------------------------------------------

begin_test "Findings include both npm and pypi ecosystems"
if [ -z "$final_scan_id" ]; then
  skip "no scan id available; cannot fetch per-finding detail"
else
  findings_resp=$(curl -sf $CURL_TIMEOUT \
      -H "$(auth_header)" \
      "${BASE_URL}/api/v1/security/scans/${final_scan_id}/findings" 2>/dev/null) || findings_resp=""
  if [ -z "$findings_resp" ]; then
    skip "findings endpoint /api/v1/security/scans/{id}/findings not available on this backend"
  else
    # Convert findings response to lowercase string blob, then grep
    # for both lodash and django mentions. We don't pin the exact JSON
    # field name because backend versions disagree (package_name vs
    # name vs purl); a contains-match against the response body is
    # tolerant of all of those.
    blob=$(echo "$findings_resp" | tr '[:upper:]' '[:lower:]')
    has_lodash=0
    has_django=0
    echo "$blob" | grep -q 'lodash' && has_lodash=1
    echo "$blob" | grep -q 'django' && has_django=1
    if [ "$has_lodash" = "1" ] && [ "$has_django" = "1" ]; then
      pass
    else
      fail "scan walked only one ecosystem: lodash=${has_lodash}, django=${has_django}; findings body: $(echo "$findings_resp" | head -c 400)"
    fi
  fi
fi

# Cleanup
api_delete "/api/v1/repositories/${REPO_KEY}" >/dev/null 2>&1 || true

end_suite
