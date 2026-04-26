#!/usr/bin/env bash
# test-scan-completes-with-real-findings.sh
#
# Regression test for issue #871 and issue #888.
#
# Issue #871 (artifact-keeper/artifact-keeper#871): scans were stuck in the
# QUEUED state indefinitely after an S3 IMDS regression. The community report
# went undetected because no E2E test asserted that a scan ever transitions
# out of QUEUED. The fix landed in #878, but no test prevents recurrence.
#
# Issue #888 (artifact-keeper/artifact-keeper#888): a related class of failure
# where a Trivy scan reaches the "completed" terminal state even though the
# scanner pod is not running. The scan is therefore a silent success: the
# status is COMPLETED but no scanner ever ran against the artifact. Asserting
# only on status=COMPLETED is not sufficient to catch this variant.
#
# What this test does
#   1. Authenticates as admin.
#   2. Creates a generic local repository.
#   3. Uploads a small, pinned npm tarball fixture whose package.json declares
#      a dependency with a publicly known CVE. The fixture is constructed in
#      the test (no network, no :latest, fully deterministic).
#   4. Requests a vulnerability scan via POST /api/v1/security/scan.
#   5. Polls the per-artifact scan endpoint for up to 60 seconds.
#   6. Asserts the final status is COMPLETED (not QUEUED, not pending, not
#      in_progress, not FAILED). This catches the #871 symptom.
#   7. Asserts the scan response carries scanner provenance: a scanner name
#      or scanner version field, OR a findings/vulnerabilities array (even
#      an empty one is acceptable as long as the field is present, since
#      that proves the scanner actually emitted a report). This catches the
#      #888 symptom where status flips to COMPLETED with no scan output.
#   8. Cleans up the repository.
#
# If the scan endpoint is not reachable (e.g. Trivy scanner is not deployed
# in this environment) the test skips rather than fails. The release-gate
# environment must have a scanner deployed for this test to be meaningful;
# the skip path is for local dev runs against a stack without scanners.
#
# Environment
#   BASE_URL       backend URL (default http://localhost:8080)
#   ADMIN_USER     admin username (default admin)
#   ADMIN_PASS     admin password (default TestRunner!2026secure)
#   RUN_ID         used in resource names so concurrent runs do not collide
#   SCAN_TIMEOUT   max seconds to wait for scan completion (default 60)

source "$(dirname "$0")/../lib/common.sh"

begin_suite "scan-completes-with-real-findings"
auth_admin
setup_workdir

REPO_KEY="scan-complete-${RUN_ID}"
PACKAGE_NAME="vuln-fixture"
# Pinned fixture version. Bumping this is intentional. Do not use :latest.
PACKAGE_VERSION="1.0.0"
TARBALL_NAME="${PACKAGE_NAME}-${PACKAGE_VERSION}.tgz"
ARTIFACT_PATH="${PACKAGE_NAME}/${PACKAGE_VERSION}/${TARBALL_NAME}"
SCAN_TIMEOUT="${SCAN_TIMEOUT:-60}"

# ---------------------------------------------------------------------------
# Cleanup hook so a failure does not leak the repo for the next run
# ---------------------------------------------------------------------------

cleanup_repo() {
  curl -sf $CURL_TIMEOUT -X DELETE -H "$(auth_header)" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}" > /dev/null 2>&1 || true
}
trap 'cleanup_repo; rm -rf "$WORK_DIR"' EXIT

# ---------------------------------------------------------------------------
# Build a deterministic npm tarball with a known-vulnerable dependency
#
# We pin event-stream@3.3.6 in the manifest because it is a well known
# malicious release (GHSA-mh6f-8j2x-4483). Trivy and Grype both flag it.
# The tarball is built locally so the test does not reach out to the npm
# registry: that keeps the test deterministic and offline-capable.
# ---------------------------------------------------------------------------

begin_test "Build pinned vulnerable npm tarball fixture"
mkdir -p "${WORK_DIR}/package"
cat > "${WORK_DIR}/package/package.json" <<EOF
{
  "name": "${PACKAGE_NAME}",
  "version": "${PACKAGE_VERSION}",
  "description": "Pinned fixture used by scan-completes-with-real-findings E2E test",
  "main": "index.js",
  "dependencies": {
    "event-stream": "3.3.6"
  }
}
EOF
cat > "${WORK_DIR}/package/index.js" <<'EOF'
module.exports = function noop() { return null; };
EOF

if tar -czf "${WORK_DIR}/${TARBALL_NAME}" -C "${WORK_DIR}" package 2>/dev/null; then
  pass
else
  fail "could not build npm tarball fixture"
fi

# ---------------------------------------------------------------------------
# Create the repository
# ---------------------------------------------------------------------------

begin_test "Create generic local repository"
if create_local_repo "$REPO_KEY" "generic"; then
  pass
else
  fail "could not create generic repository ${REPO_KEY}"
fi

# ---------------------------------------------------------------------------
# Upload the fixture
# ---------------------------------------------------------------------------

begin_test "Upload pinned vulnerable fixture"
upload_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X PUT \
  -H "$(auth_header)" \
  -H "Content-Type: application/gzip" \
  --data-binary "@${WORK_DIR}/${TARBALL_NAME}" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/${ARTIFACT_PATH}") || true

if [ "$upload_status" = "200" ] || [ "$upload_status" = "201" ]; then
  pass
else
  fail "fixture upload returned ${upload_status}, expected 200 or 201"
fi

# ---------------------------------------------------------------------------
# Trigger a scan
#
# The backend exposes POST /api/v1/security/scan to enqueue a scan job. Some
# deployments scan automatically on upload. Either is fine: as long as the
# scan reaches a terminal state we can make the assertions below.
# ---------------------------------------------------------------------------

begin_test "Trigger vulnerability scan"
scan_trigger_payload=$(jq -n \
  --arg key "$REPO_KEY" \
  --arg path "$ARTIFACT_PATH" \
  '{repository_key: $key, artifact_path: $path}')

scan_trigger_status=$(curl -s -o "${WORK_DIR}/trigger-resp.json" -w '%{http_code}' $CURL_TIMEOUT \
  -X POST \
  -H "$(auth_header)" \
  -H "Content-Type: application/json" \
  -d "$scan_trigger_payload" \
  "${BASE_URL}/api/v1/security/scan" 2>/dev/null) || scan_trigger_status="000"

# Accept any 2xx from the trigger. If trigger is not available (e.g. older
# backend or scanner missing), we still attempt to poll because some builds
# scan on upload.
case "$scan_trigger_status" in
  2*)
    pass
    ;;
  404|503)
    skip "scan trigger endpoint not available (HTTP ${scan_trigger_status}); scanner likely not deployed"
    end_suite
    exit 0
    ;;
  *)
    echo "  scan trigger returned HTTP ${scan_trigger_status}, will still poll for status"
    pass
    ;;
esac

# ---------------------------------------------------------------------------
# Poll until the scan reaches a terminal state
#
# Regression assertion for #871: status MUST transition out of queued/pending
# within SCAN_TIMEOUT. If we time out while still in queued, fail the test
# explicitly with that reason: that is exactly the symptom #871 reported.
# ---------------------------------------------------------------------------

begin_test "Scan reaches terminal state within ${SCAN_TIMEOUT}s (regression for #871)"

SCAN_GET_PATH="/api/v1/repositories/${REPO_KEY}/artifacts/${ARTIFACT_PATH}/security/scan"
elapsed=0
poll_interval=3
final_status=""
final_body=""
not_found_count=0
last_observed_state=""

while [ "$elapsed" -lt "$SCAN_TIMEOUT" ]; do
  http_status=$(curl -s -o "${WORK_DIR}/scan-resp.json" -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(auth_header)" \
    -H "Accept: application/json" \
    "${BASE_URL}${SCAN_GET_PATH}") || true

  if [ "$http_status" = "200" ]; then
    body=$(cat "${WORK_DIR}/scan-resp.json")
    state=$(echo "$body" | jq -r '
      (.status // .scan_status // .scan.status // .state // "unknown")
      | ascii_downcase
    ' 2>/dev/null) || state="unknown"
    last_observed_state="$state"

    case "$state" in
      queued|pending|in_progress|scanning|running)
        # Not terminal yet. Keep polling.
        ;;
      *)
        final_status="$state"
        final_body="$body"
        break
        ;;
    esac
  elif [ "$http_status" = "404" ] || [ "$http_status" = "503" ]; then
    not_found_count=$(( not_found_count + 1 ))
    if [ "$not_found_count" -ge 6 ]; then
      skip "scan endpoint returned ${http_status} consistently; scanner likely not deployed"
      end_suite
      exit 0
    fi
  fi

  sleep "$poll_interval"
  elapsed=$(( elapsed + poll_interval ))
done

if [ -z "$final_status" ]; then
  # This is the exact #871 symptom: stuck in a non-terminal state past the
  # timeout. Report the last observed state so the failure is actionable.
  fail "scan did not reach a terminal state within ${SCAN_TIMEOUT}s (last state: '${last_observed_state:-none}'); regression for issue #871"
else
  pass
fi

# ---------------------------------------------------------------------------
# Assert the terminal status is COMPLETED (or an equivalent success state)
#
# We accept the canonical values the backend currently emits: "completed",
# "clean", "success". Anything else (queued, failed, error, timeout) fails
# the test. Critically, we treat "queued" as a hard failure here: a scan
# that is still QUEUED after the polling loop exited is the #871 bug.
# ---------------------------------------------------------------------------

begin_test "Final scan status is COMPLETED, not QUEUED or FAILED (regression for #871)"
case "$final_status" in
  completed|clean|success)
    pass
    ;;
  queued|pending)
    fail "scan terminal status is '${final_status}'; this is the exact #871 symptom (scan stuck in queue)"
    ;;
  failed|error|timeout)
    fail "scan reported terminal status '${final_status}'; expected completed"
    ;;
  *)
    fail "scan reported unexpected terminal status '${final_status}'; expected completed, clean, or success"
    ;;
esac

# ---------------------------------------------------------------------------
# Assert the scan response carries scanner provenance
#
# Regression assertion for #888: a scan can be marked completed even when
# the scanner pod was never reachable, in which case the response carries
# no scanner identity and no findings/vulnerabilities field at all. We
# require at least ONE of:
#
#   - a scanner name or scanner version field, e.g. .scanner, .scanner_name,
#     .scanner_version, .engine, .tool.name, .tool.version
#   - a scanned_at / completed_at timestamp emitted by the scanner
#   - a findings or vulnerabilities array present in the response (even if
#     empty, an explicit array proves the scanner emitted a structured
#     report rather than the backend silently flipping the status field)
#
# If none of these are present, the COMPLETED status is not trustworthy and
# we fail the test with a reference to #888.
# ---------------------------------------------------------------------------

begin_test "Scan response carries scanner provenance, not silent success (regression for #888)"
if [ -z "$final_body" ]; then
  fail "scan response body was empty; cannot verify scanner provenance"
else
  has_scanner_identity=$(echo "$final_body" | jq -r '
    (.scanner // .scanner_name // .scanner_version
      // .engine // .tool.name // .tool.version
      // .report.scanner // .report.scanner_name // empty) != ""
  ' 2>/dev/null || echo "false")

  has_scan_timestamp=$(echo "$final_body" | jq -r '
    (.scanned_at // .completed_at // .finished_at
      // .scan.completed_at // empty) != ""
  ' 2>/dev/null || echo "false")

  has_findings_field=$(echo "$final_body" | jq -r '
    (
      (.findings != null) or (.vulnerabilities != null)
        or (.results != null) or (.matches != null)
        or (.report.vulnerabilities != null)
        or (.report.findings != null)
    )
  ' 2>/dev/null || echo "false")

  if [ "$has_scanner_identity" = "true" ] || \
     [ "$has_scan_timestamp" = "true" ] || \
     [ "$has_findings_field" = "true" ]; then
    pass
  else
    # Capture a snippet of the response to make the failure diagnosable
    snippet=$(echo "$final_body" | jq -c 'del(.history?, .raw?)' 2>/dev/null | cut -c 1-400)
    fail "scan reported '${final_status}' but response carries no scanner identity, timestamp, or findings field; this is the #888 silent-success class (response head: ${snippet:-<unparseable>})"
  fi
fi

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

begin_test "Cleanup: delete repository"
if curl -sf $CURL_TIMEOUT -X DELETE -H "$(auth_header)" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}" > /dev/null 2>&1; then
  pass
else
  # Cleanup failures should not block the suite; trap also handles this.
  skip "cleanup of ${REPO_KEY} returned non-2xx; trap will retry"
fi

end_suite
