#!/usr/bin/env bash
# test-pinned-cve.sh -- Pinned-CVE assertion against /scans/{id}/findings.
#
# Covers artifact-keeper-test#64.
#
# Why this exists, on top of the lite gate's findings_count >= 1 check:
#   - findings_count >= 1 catches "scanner emitted at least one finding".
#     That defeats the gross silent-success class (#888) but it does NOT
#     catch scanner *correctness* drift:
#       a) If a future scanner version mis-parses payload.txt and emits
#          100 spurious findings, findings_count >= 1 still passes.
#       b) If the CVE database is stale and Trivy can no longer detect
#          CVE-2019-10744 but emits other (unrelated) findings,
#          findings_count >= 1 still passes.
#   - The fix is to bind the gate to a specific CVE id. The lite fixture
#     pins lodash 4.17.4, which has CVE-2019-10744 (Prototype Pollution,
#     CVSS 9.1). We assert that EXACT CVE shows up in the findings list
#     for the scan.
#
# Fixture choice: per the task brief, log4j 2.14.0 / CVE-2021-44228 is
# also a candidate. lodash is what test-scan-completes.sh already builds,
# and #64 explicitly references CVE-2019-10744 as the pinned value, so
# we follow that path. log4j coverage belongs in the format-matrix (oci
# manifest path) once that scaffold is wired up (#62 + #64 extension).
#
# Backend contract (verified against
#   artifact-keeper/backend/src/api/handlers/security.rs:287-311):
#     GET /api/v1/security/scans/{id}/findings
#     -> { items: [FindingResponse], total: i64 }
#     FindingResponse.cve_id is Option<String> (may be null for
#     non-CVE findings). We match on cve_id == "CVE-2019-10744".
#
# Environment:
#   BASE_URL              backend URL (default http://localhost:8080)
#   ADMIN_PASS            admin password
#   RUN_ID                resource-name suffix
#   EXPECTED_VULN_CVE     CVE id to assert (default: CVE-2019-10744)
#   SCAN_TIMEOUT          poll-until-completed budget (default 180)

# shellcheck source=../lib/common.sh disable=SC1091
source "$(dirname "$0")/../lib/common.sh"

begin_suite "pinned-cve"
auth_admin
setup_workdir

REPO_KEY="pinned-cve-${RUN_ID}"
PACKAGE_NAME="lodash-vuln-fixture"
PACKAGE_VERSION="1.0.0"
TARBALL_NAME="${PACKAGE_NAME}-${PACKAGE_VERSION}.tgz"
ARTIFACT_PATH="${PACKAGE_NAME}/${PACKAGE_VERSION}/${TARBALL_NAME}"
SCAN_TIMEOUT="${SCAN_TIMEOUT:-180}"
EXPECTED_VULN_CVE="${EXPECTED_VULN_CVE:-CVE-2019-10744}"

cleanup_pin() {
  # shellcheck disable=SC2086
  curl -sf $CURL_TIMEOUT -X DELETE -H "$(auth_header)" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}" >/dev/null 2>&1 || true
  [ -n "${WORK_DIR:-}" ] && rm -rf "$WORK_DIR" 2>/dev/null || true
}
trap cleanup_pin EXIT

# ---------------------------------------------------------------------------
# Build the known-vulnerable lodash 4.17.4 fixture (same payload shape as
# test-scan-completes.sh; deliberately duplicated rather than sourced so
# this test stays self-contained for the release-gate workflow).
# ---------------------------------------------------------------------------

begin_test "Build lodash 4.17.4 fixture (CVE-2019-10744)"
mkdir -p "${WORK_DIR}/package"
cat > "${WORK_DIR}/package/package.json" <<EOF
{
  "name": "${PACKAGE_NAME}",
  "version": "${PACKAGE_VERSION}",
  "dependencies": { "lodash": "4.17.4" }
}
EOF
cat > "${WORK_DIR}/package/package-lock.json" <<EOF
{
  "name": "${PACKAGE_NAME}",
  "version": "${PACKAGE_VERSION}",
  "lockfileVersion": 2,
  "requires": true,
  "packages": {
    "": { "name": "${PACKAGE_NAME}", "version": "${PACKAGE_VERSION}",
          "dependencies": { "lodash": "4.17.4" } },
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
if tar -czf "${WORK_DIR}/${TARBALL_NAME}" -C "${WORK_DIR}" package 2>/dev/null; then
  pass
else
  fail "could not build fixture tarball"
fi

# ---------------------------------------------------------------------------
# Repo + upload.
# ---------------------------------------------------------------------------

begin_test "Create generic local repository"
if create_local_repo "$REPO_KEY" "generic"; then
  pass
else
  fail "could not create generic repository ${REPO_KEY}"
fi

begin_test "Upload fixture"
# shellcheck disable=SC2086
upload_status=$(curl -s -o "${WORK_DIR}/upload-resp.json" -w '%{http_code}' $CURL_TIMEOUT \
  -X PUT \
  -H "$(auth_header)" \
  -H "Content-Type: application/gzip" \
  --data-binary "@${WORK_DIR}/${TARBALL_NAME}" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/${ARTIFACT_PATH}") || upload_status="000"
if [ "$upload_status" = "200" ] || [ "$upload_status" = "201" ]; then
  pass
else
  fail "upload returned HTTP ${upload_status}"
fi

# ---------------------------------------------------------------------------
# Resolve artifact_id.
# ---------------------------------------------------------------------------

begin_test "Resolve artifact_id"
ARTIFACT_ID=""
# shellcheck disable=SC2086
list_status=$(curl -s -o "${WORK_DIR}/list-resp.json" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts") || list_status="000"
if [ "$list_status" = "200" ]; then
  ARTIFACT_ID=$(jq -er --arg p "$ARTIFACT_PATH" \
    '.items | map(select(.path == $p or .name == $p)) | first | .id // empty' \
    < "${WORK_DIR}/list-resp.json" 2>/dev/null || true)
fi
if [ -n "$ARTIFACT_ID" ]; then
  pass
else
  fail "could not resolve artifact_id (list HTTP ${list_status})"
  end_suite
  exit 1
fi

# ---------------------------------------------------------------------------
# Trigger scan and poll until terminal.
# ---------------------------------------------------------------------------

begin_test "Trigger scan"
trigger_body=$(jq -n --arg id "$ARTIFACT_ID" '{artifact_id: $id, force: true}')
# shellcheck disable=SC2086
trig_status=$(curl -s -o "${WORK_DIR}/trig-resp.json" -w '%{http_code}' $CURL_TIMEOUT \
  -X POST \
  -H "$(auth_header)" \
  -H "Content-Type: application/json" \
  -d "$trigger_body" \
  "${BASE_URL}/api/v1/security/scan") || trig_status="000"
case "$trig_status" in
  2*) pass ;;
  *) fail "scan trigger returned HTTP ${trig_status}" ;;
esac

begin_test "Scan reaches completed within ${SCAN_TIMEOUT}s"
elapsed=0
SCAN_ID=""
final_status=""
while [ "$elapsed" -lt "$SCAN_TIMEOUT" ]; do
  # shellcheck disable=SC2086
  poll_status=$(curl -s -o "${WORK_DIR}/scans-resp.json" -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(auth_header)" \
    "${BASE_URL}/api/v1/security/artifacts/${ARTIFACT_ID}/scans") || poll_status="000"
  if [ "$poll_status" = "200" ]; then
    scan_obj=$(jq -c '.items[0] // empty' < "${WORK_DIR}/scans-resp.json" 2>/dev/null || echo "")
    if [ -n "$scan_obj" ]; then
      state=$(echo "$scan_obj" | jq -r '.status | ascii_downcase' 2>/dev/null || echo "unknown")
      case "$state" in
        completed|failed|error|timeout)
          final_status="$state"
          SCAN_ID=$(echo "$scan_obj" | jq -r '.id // empty')
          break
          ;;
      esac
    fi
  fi
  sleep 5
  elapsed=$(( elapsed + 5 ))
done

if [ "$final_status" = "completed" ]; then
  echo "  scan_id=${SCAN_ID}"
  pass
elif [ -n "$final_status" ]; then
  fail "scan reached terminal state '${final_status}', expected 'completed'"
  end_suite
  exit 1
else
  fail "scan did not reach a terminal state within ${SCAN_TIMEOUT}s"
  end_suite
  exit 1
fi

# ---------------------------------------------------------------------------
# Load-bearing assertion: fetch findings for the scan and confirm the
# pinned CVE appears.
#
# Backend handler list_findings returns FindingListResponse {items, total}.
# Each FindingResponse has cve_id: Option<String>; we match on
# .cve_id == EXPECTED_VULN_CVE. If cve_id is null for all rows but the
# scan claims findings_count > 0, that is a backend contract regression
# (separate failure mode -- we surface it loudly with the actual CVE
# values observed).
# ---------------------------------------------------------------------------

begin_test "GET /scans/${SCAN_ID}/findings includes ${EXPECTED_VULN_CVE}"
# shellcheck disable=SC2086
findings_status=$(curl -s -o "${WORK_DIR}/findings-resp.json" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/security/scans/${SCAN_ID}/findings?per_page=200") \
  || findings_status="000"

case "$findings_status" in
  200)
    # Confirm response shape first so a "200 with HTML" misroute fails loud.
    if ! jq -e '(.items | type) == "array" and (.total | type) == "number"' \
         < "${WORK_DIR}/findings-resp.json" >/dev/null 2>&1; then
      body=$(head -c 400 "${WORK_DIR}/findings-resp.json" 2>/dev/null || true)
      fail "findings endpoint 200 but body shape mismatch (expected {items: [], total: N})" "$body"
      end_suite
      exit 1
    fi

    total_findings=$(jq -r '.total' < "${WORK_DIR}/findings-resp.json")
    matched=$(jq --arg cve "$EXPECTED_VULN_CVE" \
      '[.items[] | select(.cve_id == $cve)] | length' \
      < "${WORK_DIR}/findings-resp.json")

    if [ "${matched:-0}" -ge 1 ]; then
      echo "  matched ${matched} finding(s) for ${EXPECTED_VULN_CVE} (total findings: ${total_findings})"
      pass
    else
      # Surface what we DID see so the operator can decide whether the
      # CVE database has drifted or the scanner mis-parsed the fixture.
      observed_cves=$(jq -r '[.items[].cve_id // "<null>"] | unique | join(", ")' \
        < "${WORK_DIR}/findings-resp.json" 2>/dev/null || echo "<jq-error>")
      preview=$(jq -c '.items[0:3]' < "${WORK_DIR}/findings-resp.json" 2>/dev/null | cut -c 1-500)
      fail "scan ${SCAN_ID} on lodash 4.17.4 did not surface ${EXPECTED_VULN_CVE} in findings (total=${total_findings})" \
"observed cve_ids: ${observed_cves}
first 3 findings: ${preview}
endpoint: GET ${BASE_URL}/api/v1/security/scans/${SCAN_ID}/findings
diagnosis:
  - If observed_cves is empty/<null> and total > 0, FindingResponse.cve_id stopped being populated.
  - If observed_cves are present but none is ${EXPECTED_VULN_CVE}, scanner DB drift or fixture rot.
  - If total == 0, scanner did not inspect the fixture; see test-scan-completes.sh diagnosis."
    fi
    ;;
  404)
    fail "findings endpoint returned 404; scan_id=${SCAN_ID} may be wrong or endpoint missing"
    ;;
  *)
    body=$(head -c 400 "${WORK_DIR}/findings-resp.json" 2>/dev/null || true)
    fail "findings endpoint returned HTTP ${findings_status}" "$body"
    ;;
esac

end_suite
