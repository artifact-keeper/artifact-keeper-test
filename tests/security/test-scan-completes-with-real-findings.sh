#!/usr/bin/env bash
# test-scan-completes-with-real-findings.sh
#
# Regression test for issues #871 and #888.
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
#   2. Creates a generic local repository and uploads a deterministic fixture.
#   3. Resolves the artifact_id from the management API (NOT from a path
#      pattern; the per-artifact scan endpoint is keyed by UUID).
#   4. Triggers a vulnerability scan via POST /api/v1/security/scan with
#      {artifact_id: uuid}. (The previous version of this test used a
#      non-existent path-keyed endpoint and SKIPped on 404 — green forever.)
#   5. Polls GET /api/v1/security/artifacts/{artifact_id}/scans for up to
#      SCAN_TIMEOUT seconds.
#   6. Asserts the latest scan's status is "completed" AND scanner_version
#      is non-null AND completed_at is non-null AND error_message is empty.
#      All four together prove that a scanner actually ran and emitted a
#      report — catches the #888 silent-success class.
#   7. Cleans up.
#
# Skip semantics (load-bearing)
#   In the release-gate context, scanner unavailability MUST fail the gate.
#   A skipped gate is exactly the silent-success class this test is meant to
#   catch. We honor a single env var:
#
#       ALLOW_SCANNER_SKIP=1   skip on persistent scanner unreachability
#                              (intended for local dev runs against a stack
#                              without scanners)
#
#   The release-gate workflow MUST NOT set this. Default behavior fails on
#   scanner unavailability.
#
# Environment
#   BASE_URL              backend URL (default http://localhost:8080)
#   ADMIN_USER            admin username (default admin)
#   ADMIN_PASS            admin password (default TestRunner!2026secure)
#   RUN_ID                used in resource names so concurrent runs don't collide
#   SCAN_TIMEOUT          max seconds to wait for scan completion (default 180)
#   ALLOW_SCANNER_SKIP    set to 1 in local dev to permit graceful skip; never
#                         set in release-gate

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
SCAN_TIMEOUT="${SCAN_TIMEOUT:-180}"
ALLOW_SCANNER_SKIP="${ALLOW_SCANNER_SKIP:-0}"

# ---------------------------------------------------------------------------
# Cleanup hook so a failure does not leak the repo for the next run.
# Append to setup_workdir's EXIT trap rather than overwriting it.
# ---------------------------------------------------------------------------

cleanup_repo() {
  # shellcheck disable=SC2086  # CURL_TIMEOUT must word-split, per common.sh
  curl -sf $CURL_TIMEOUT -X DELETE -H "$(auth_header)" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}" > /dev/null 2>&1 || true
}

# common.sh's setup_workdir installs `trap "rm -rf $WORK_DIR" EXIT`. We
# combine both cleanups into a single trap; common.sh's $WORK_DIR is in
# scope so we can reference it directly.
trap 'cleanup_repo; [ -n "${WORK_DIR:-}" ] && rm -rf "$WORK_DIR" 2>/dev/null || true' EXIT

# ---------------------------------------------------------------------------
# Fail-or-skip helper.
#
# Scanner-unreachable scenarios are legitimate failures in the release-gate
# context (the gate exists to catch exactly the class where the backend
# claims a scan succeeded while the scanner was down). For local-dev runs
# without scanners deployed, the operator can opt into graceful skip via
# ALLOW_SCANNER_SKIP=1.
# ---------------------------------------------------------------------------

scanner_unavailable() {
  local reason="$1"
  if [ "$ALLOW_SCANNER_SKIP" = "1" ]; then
    skip "scanner unavailable (${reason}); ALLOW_SCANNER_SKIP=1 honored for local dev"
    end_suite
    exit 0
  fi
  fail "scanner unavailable (${reason}); release-gate must fail when scanner cannot run, this is the #888 silent-success class"
  end_suite
  exit 1
}

# ---------------------------------------------------------------------------
# Build a deterministic npm tarball with a known-vulnerable dependency.
#
# We pin event-stream@3.3.6 in the manifest because it is a well-known
# malicious release (GHSA-mh6f-8j2x-4483). The tarball is built locally so
# the test does not reach out to the npm registry: that keeps the test
# deterministic and offline-capable.
#
# Caveat (documented to prevent silent-fixture rot): Trivy's npm scanner
# reads installed `node_modules`, not just `package.json` declarations.
# Without a lock file or installed deps, Trivy may emit zero findings for
# this fixture. The #888 catch does NOT depend on findings being non-zero
# — it asserts the scanner produced a report (scanner_version + completed_at
# + clean error_message). A separate follow-up adds an OCI-image fixture
# with a known-vulnerable base layer for findings-coverage assertions.
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
# shellcheck disable=SC2086  # CURL_TIMEOUT must word-split, per common.sh
upload_status=$(curl -s -o "${WORK_DIR}/upload-resp.json" -w '%{http_code}' $CURL_TIMEOUT \
  -X PUT \
  -H "$(auth_header)" \
  -H "Content-Type: application/gzip" \
  --data-binary "@${WORK_DIR}/${TARBALL_NAME}" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/${ARTIFACT_PATH}") || upload_status="000"

if [ "$upload_status" = "200" ] || [ "$upload_status" = "201" ]; then
  pass
elif [ "$upload_status" = "000" ]; then
  scanner_unavailable "backend unreachable on upload (curl exit non-zero)"
else
  fail "fixture upload returned ${upload_status}, expected 200 or 201"
fi

# ---------------------------------------------------------------------------
# Resolve the artifact_id.
#
# The per-artifact scan endpoint is /api/v1/security/artifacts/{artifact_id}/scans
# and is keyed by UUID, NOT by repository path. The previous version of this
# test polled a path-keyed endpoint that does not exist on the backend; the
# response was always 404 and the test SKIPped on consecutive failures —
# silent-success on every release. Catch the bug class the test is meant to
# catch instead.
# ---------------------------------------------------------------------------

begin_test "Resolve artifact_id for the uploaded fixture"
# shellcheck disable=SC2086  # CURL_TIMEOUT must word-split, per common.sh
artifact_lookup_status=$(curl -s -o "${WORK_DIR}/artifact-resp.json" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" \
  -H "Accept: application/json" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/${ARTIFACT_PATH}/metadata") \
  || artifact_lookup_status="000"

ARTIFACT_ID=""
if [ "$artifact_lookup_status" = "200" ]; then
  ARTIFACT_ID=$(jq -er '.id // .artifact_id // empty' < "${WORK_DIR}/artifact-resp.json" 2>/dev/null || true)
fi

# Fallback: list artifacts in the repo and find ours by path.
if [ -z "$ARTIFACT_ID" ]; then
  # shellcheck disable=SC2086  # CURL_TIMEOUT must word-split, per common.sh
  list_status=$(curl -s -o "${WORK_DIR}/list-resp.json" -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(auth_header)" \
    -H "Accept: application/json" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts") \
    || list_status="000"
  if [ "$list_status" = "200" ]; then
    ARTIFACT_ID=$(jq -er --arg p "$ARTIFACT_PATH" \
      '(.items // .artifacts // .) | map(select(.path == $p or .name == $p)) | first | .id // .artifact_id // empty' \
      < "${WORK_DIR}/list-resp.json" 2>/dev/null || true)
  fi
fi

if [ -n "$ARTIFACT_ID" ]; then
  pass
else
  fail "could not resolve artifact_id for ${ARTIFACT_PATH} (lookup HTTP ${artifact_lookup_status}); test cannot proceed"
fi

# ---------------------------------------------------------------------------
# Trigger a scan via the real API.
#
# POST /api/v1/security/scan accepts {artifact_id, repository_id} and
# returns TriggerScanResponse {message, artifacts_queued}. Some deployments
# also auto-scan on upload, in which case the explicit trigger may queue a
# duplicate or be a no-op — both are fine.
# ---------------------------------------------------------------------------

begin_test "Trigger vulnerability scan via /api/v1/security/scan"
scan_trigger_payload=$(jq -n --arg id "$ARTIFACT_ID" '{artifact_id: $id}')

# shellcheck disable=SC2086  # CURL_TIMEOUT must word-split, per common.sh
scan_trigger_status=$(curl -s -o "${WORK_DIR}/trigger-resp.json" -w '%{http_code}' $CURL_TIMEOUT \
  -X POST \
  -H "$(auth_header)" \
  -H "Content-Type: application/json" \
  -d "$scan_trigger_payload" \
  "${BASE_URL}/api/v1/security/scan" 2>/dev/null) || scan_trigger_status="000"

case "$scan_trigger_status" in
  2*)
    pass
    ;;
  000)
    scanner_unavailable "trigger curl exit non-zero (network/DNS)"
    ;;
  503)
    scanner_unavailable "scan trigger HTTP 503 (scanner pod likely unreachable)"
    ;;
  404)
    fail "scan trigger HTTP 404 — endpoint /api/v1/security/scan missing or backend version too old"
    ;;
  *)
    # Auto-scan-on-upload may make trigger return non-2xx (e.g. 409 already
    # queued). Note it but proceed to poll.
    echo "  scan trigger returned HTTP ${scan_trigger_status}; proceeding to poll (may be auto-scan-on-upload)"
    pass
    ;;
esac

# ---------------------------------------------------------------------------
# Poll the per-artifact scan list until a terminal state is observed.
#
# Real endpoint: GET /api/v1/security/artifacts/{artifact_id}/scans
# Response shape: { items: [ScanResponse], total }
# ScanResponse fields used: id, status, scanner_version, completed_at,
# error_message, started_at, findings_count, *_count.
#
# Network errors (curl exit code != 0, http_status="000") count toward the
# scanner_unavailable threshold so a fully-unreachable backend is detected
# instead of silently polling for the entire timeout.
# ---------------------------------------------------------------------------

begin_test "Scan reaches terminal state within ${SCAN_TIMEOUT}s (regression for #871)"

SCAN_LIST_PATH="/api/v1/security/artifacts/${ARTIFACT_ID}/scans"
elapsed=0
poll_interval=5
final_status=""
final_body=""
final_scan_id=""
network_fail_count=0
last_observed_state=""
observed_transient=0

while [ "$elapsed" -lt "$SCAN_TIMEOUT" ]; do
  # shellcheck disable=SC2086  # CURL_TIMEOUT must word-split, per common.sh
  http_status=$(curl -s -o "${WORK_DIR}/scans-resp.json" -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(auth_header)" \
    -H "Accept: application/json" \
    "${BASE_URL}${SCAN_LIST_PATH}") || http_status="000"

  if [ "$http_status" = "200" ]; then
    # Pick the most recent scan (highest created_at, or first item — backend
    # is documented to return descending). The list response shape is
    # `{items: [...], total: N}`.
    scan_obj=$(jq -c '.items[0] // empty' < "${WORK_DIR}/scans-resp.json" 2>/dev/null || echo "")
    if [ -n "$scan_obj" ]; then
      state=$(echo "$scan_obj" | jq -er '.status | ascii_downcase' 2>/dev/null || echo "unknown")
      last_observed_state="$state"
      case "$state" in
        queued|pending|in_progress|scanning|running)
          observed_transient=1
          ;;
        unknown)
          # Unparseable state — distinguish from "stuck queued"
          ;;
        *)
          final_status="$state"
          final_body="$scan_obj"
          final_scan_id=$(echo "$scan_obj" | jq -er '.id // empty' 2>/dev/null || echo "")
          break
          ;;
      esac
    fi
  elif [ "$http_status" = "000" ] || [ "$http_status" = "503" ]; then
    network_fail_count=$(( network_fail_count + 1 ))
    if [ "$network_fail_count" -ge 6 ]; then
      scanner_unavailable "scan-list HTTP ${http_status} for 6 consecutive polls"
    fi
  fi

  sleep "$poll_interval"
  elapsed=$(( elapsed + poll_interval ))
done

if [ -z "$final_status" ]; then
  # The exact #871 symptom: stuck in a non-terminal state past the timeout.
  fail "scan did not reach a terminal state within ${SCAN_TIMEOUT}s (last state: '${last_observed_state:-none}', observed_transient=${observed_transient}); regression for issue #871"
elif [ "$last_observed_state" = "unknown" ] && [ -z "$final_status" ]; then
  fail "scan response was unparseable (status field missing/null); cannot diagnose #871 vs response-shape drift"
else
  pass
fi

# ---------------------------------------------------------------------------
# Assert terminal status is success.
# ---------------------------------------------------------------------------

begin_test "Final scan status is COMPLETED, not FAILED (regression for #871)"
case "$final_status" in
  completed)
    pass
    ;;
  queued|pending|in_progress|scanning|running)
    fail "scan terminal status is '${final_status}'; this is the exact #871 symptom (scan stuck)"
    ;;
  failed|error|timeout)
    err_msg=$(echo "$final_body" | jq -r '.error_message // "no error_message"' 2>/dev/null || echo "no error_message")
    fail "scan reported terminal status '${final_status}' (error_message: ${err_msg})"
    ;;
  *)
    fail "scan reported unexpected terminal status '${final_status}'; expected 'completed'"
    ;;
esac

# ---------------------------------------------------------------------------
# Assert the scan response carries scanner provenance — the load-bearing
# regression assertion for #888.
#
# A scan can be marked COMPLETED even when the scanner pod was never
# reachable. To catch that, we require ALL of:
#
#   - scanner_version is a non-empty string (proves a scanner identified
#     itself in the response)
#   - completed_at is a non-null timestamp (proves the scanner finished)
#   - error_message is null or empty (proves the COMPLETED status is not
#     hiding a swallowed error)
#
# Each assertion uses `jq -e` with a strict boolean predicate so a literal
# JSON `null` value cannot pass as a non-empty string. This is the round-2
# fix from the senior review on PR #50.
# ---------------------------------------------------------------------------

begin_test "Scan response carries scanner provenance, not silent success (regression for #888)"
if [ -z "$final_body" ]; then
  fail "scan response was empty; cannot verify scanner provenance"
else
  # jq -e exits non-zero when the filter result is false/null/empty, so we
  # check the exit code directly rather than parsing a "true"/"false" string.
  scanner_version_present=0
  completed_at_present=0
  error_message_clean=0

  if echo "$final_body" | jq -e '
        .scanner_version != null and (.scanner_version | type) == "string" and (.scanner_version | length) > 0
      ' >/dev/null 2>&1; then
    scanner_version_present=1
  fi

  if echo "$final_body" | jq -e '
        .completed_at != null and (.completed_at | type) == "string" and (.completed_at | length) > 0
      ' >/dev/null 2>&1; then
    completed_at_present=1
  fi

  if echo "$final_body" | jq -e '
        .error_message == null or (.error_message | type) == "null" or ((.error_message | type) == "string" and (.error_message | length) == 0)
      ' >/dev/null 2>&1; then
    error_message_clean=1
  fi

  if [ "$scanner_version_present" = "1" ] && \
     [ "$completed_at_present" = "1" ] && \
     [ "$error_message_clean" = "1" ]; then
    pass
  else
    snippet=$(echo "$final_body" | jq -c '{id, status, scanner_version, started_at, completed_at, error_message, findings_count}' 2>/dev/null | cut -c 1-500)
    fail "COMPLETED scan ${final_scan_id} fails provenance: scanner_version=${scanner_version_present}, completed_at=${completed_at_present}, error_message_clean=${error_message_clean}; this is the #888 silent-success class. Response: ${snippet:-<unparseable>}"
  fi
fi

# ---------------------------------------------------------------------------
# Diagnostics on suite-level failure.
#
# When something fails above, dump the most recent scan response to the
# JUnit output dir so the release-gate workflow's diagnostics step has
# something concrete to upload. Pod logs from the scanner are out of
# scope here — those are captured by the release-gate's failure-hook
# step in release-gate.yml (added in this PR).
# ---------------------------------------------------------------------------

if [ -d "${JUNIT_OUTPUT_DIR:-/tmp/junit}" ]; then
  cp "${WORK_DIR}/scans-resp.json" "${JUNIT_OUTPUT_DIR}/scan-completes-final-resp.json" 2>/dev/null || true
  if [ -n "$final_scan_id" ]; then
    echo "$final_scan_id" > "${JUNIT_OUTPUT_DIR}/scan-completes-final-id.txt" 2>/dev/null || true
  fi
fi

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

begin_test "Cleanup: delete repository"
  # shellcheck disable=SC2086  # CURL_TIMEOUT must word-split, per common.sh
if curl -sf $CURL_TIMEOUT -X DELETE -H "$(auth_header)" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}" > /dev/null 2>&1; then
  pass
else
  # Cleanup failures should not block the suite; trap also handles this.
  skip "cleanup of ${REPO_KEY} returned non-2xx; trap will retry"
fi

end_suite
