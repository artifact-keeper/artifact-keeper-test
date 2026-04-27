#!/usr/bin/env bash
# test-scan-completes.sh -- Lite scan-completion E2E gate (v1.1.9 subset)
#
# Regression test for issues #871 (scan stuck queued) and #888 (scan
# marked COMPLETED while scanner pod was unreachable -- silent success).
#
# This is the LITE subset of the full epic (artifact-keeper-test#56).
# The lite version catches the gross failure modes WITHOUT depending on
# backend changes that ship in v1.2.0:
#
#   - Cannot assert on `scanner_version` because backend never populates
#     it (artifact-keeper#902 will fix that for v1.2.0). Instead we rely
#     on `completed_at` + `error_message` clean + recency-against-
#     test-start-epoch as the proxy for "a scanner actually ran".
#
# What this lite test catches
#   - Stuck queued (#871): scan never transitions out of queued/pending/
#     running/in_progress within SCAN_TIMEOUT.
#   - Silent COMPLETED (#888 gross case): scan reports completed but has
#     no completed_at OR has a non-empty error_message OR has a
#     created_at older than the test start. Each of these proves the
#     report is suspect.
#
# What this lite test does NOT catch (deferred to v1.2.0 / epic #56)
#   - Backend stub emitting fake scanner_version
#   - scanner_version semver shape regression
#   - completed_at >= started_at race
#   - Trivy pod scaled to zero mid-scan must yield FAILED (separate
#     negative-control test)
#
# Skip semantics (load-bearing)
#   In release-gate context, scanner unavailability MUST fail the gate
#   (the gate exists to catch exactly the silent-success class). Local
#   dev runs can opt in to graceful skip via ALLOW_SCANNER_SKIP=1.
#
# Environment
#   BASE_URL              backend URL (default http://localhost:8080)
#   ADMIN_USER            admin username (default admin)
#   ADMIN_PASS            admin password (default TestRunner!2026secure)
#   RUN_ID                resource-name suffix
#   SCAN_TIMEOUT          max seconds to wait for scan completion (default 180)
#   ALLOW_SCANNER_SKIP    set to 1 in local dev for graceful skip; never
#                         set in release-gate
#   EXPECT_FAILURE        set to 1 by the meta-test workflow to invert
#                         exit codes (used for the paired pass/fail proof
#                         per #883 contract)

source "$(dirname "$0")/../lib/common.sh"

begin_suite "scan-completes"
auth_admin
setup_workdir

REPO_KEY="scan-complete-${RUN_ID}"
PACKAGE_NAME="lodash-vuln-fixture"
PACKAGE_VERSION="1.0.0"
TARBALL_NAME="${PACKAGE_NAME}-${PACKAGE_VERSION}.tgz"
ARTIFACT_PATH="${PACKAGE_NAME}/${PACKAGE_VERSION}/${TARBALL_NAME}"
SCAN_TIMEOUT="${SCAN_TIMEOUT:-180}"
ALLOW_SCANNER_SKIP="${ALLOW_SCANNER_SKIP:-0}"
EXPECT_FAILURE="${EXPECT_FAILURE:-0}"

# Known-vulnerable fixture target. lodash 4.17.4 ships CVE-2019-10744
# (Prototype Pollution, CVSS 9.1). Trivy's fs scanner detects this via
# the package-lock.json parser. The findings_count assertion below
# (regression for the silent-success class) requires this fixture to
# actually produce findings -- if findings_count == 0 on a healthy
# backend, the scanner never inspected the bytes (Reality Checker /
# Security Engineer reviews of PR #60).
EXPECTED_VULN_PACKAGE="lodash"
EXPECTED_VULN_VERSION="4.17.4"
EXPECTED_VULN_CVE_HINT="CVE-2019-10744"

# ---------------------------------------------------------------------------
# Combined cleanup trap. setup_workdir installs an EXIT trap that rm's
# WORK_DIR. We add repo deletion AND the WORK_DIR cleanup in one trap so
# we don't clobber the parent.
# ---------------------------------------------------------------------------

cleanup() {
  local exit_code=$?

  # Mutual exclusion: EXPECT_FAILURE=1 inverts exit codes for self-test;
  # ALLOW_SCANNER_SKIP=1 makes scanner_unavailable() return success. If
  # both are set, the self-test would falsely report "gate caught a bad
  # backend" when in fact it just gracefully skipped. This bug class
  # would silently turn the self-test into a no-op -- the exact failure
  # mode #883 is meant to prevent.
  if [ "$EXPECT_FAILURE" = "1" ] && [ "$ALLOW_SCANNER_SKIP" = "1" ]; then
    echo "" >&2
    echo "ERROR: EXPECT_FAILURE=1 and ALLOW_SCANNER_SKIP=1 are mutually exclusive." >&2
    echo "  EXPECT_FAILURE inverts exit codes; ALLOW_SCANNER_SKIP coerces failure to success." >&2
    echo "  Together they corrupt the self-test signal. Pick one." >&2
    exit 5
  fi

  # Self-test mode: invert the meaning of exit code so a *real* failure
  # is reported as success (the gate is correctly catching a bad
  # backend), and exit 0 is reported as exit 4 (the gate falsely passed
  # on a bad backend).
  if [ "$EXPECT_FAILURE" = "1" ]; then
    if [ "$exit_code" -eq 0 ]; then
      echo "" >&2
      echo "ERROR: EXPECT_FAILURE=1 was set but the gate passed. Gate is broken or fixture is wrong." >&2
      exit_code=4
    else
      echo ""
      echo "Self-test PASSED: gate exited with code ${exit_code} as expected."
      exit_code=0
    fi
  fi

  # shellcheck disable=SC2086  # CURL_TIMEOUT must word-split, per common.sh
  curl -sf $CURL_TIMEOUT -X DELETE -H "$(auth_header)" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}" >/dev/null 2>&1 || true
  [ -n "${WORK_DIR:-}" ] && rm -rf "$WORK_DIR" 2>/dev/null || true

  exit "$exit_code"
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Fail-or-skip helper. Scanner unreachability is a legitimate failure
# in release-gate; only honors ALLOW_SCANNER_SKIP=1 for local dev.
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
# Numeric guard for `-gt` comparisons. Surfaces jq parse errors loudly
# instead of via `2>/dev/null` masking.
# ---------------------------------------------------------------------------

is_nonneg_int() {
  [[ "${1:-}" =~ ^[0-9]+$ ]]
}

# ---------------------------------------------------------------------------
# Build a known-vulnerable fixture. The tarball contains a
# package-lock.json that pins lodash 4.17.4 (CVE-2019-10744, CVSS 9.1).
# Trivy's filesystem scanner walks the tarball and the package-lock
# parser flags the lodash entry. This is what powers the findings_count
# assertion below: if the scanner actually ran, we get >= 1 finding;
# if the scanner was bypassed (silent-success class), the gate fails.
#
# Per Reality Checker / Security Engineer reviews of PR #60: the
# previous payload.txt fixture was not applicable to any scanner, so
# `Ok(vec![])` was a valid "scan" result and the gate falsely passed.
#
# package.json is included for completeness (some Trivy versions
# require it to anchor the lockfile parse); it does not need to match
# the lockfile exactly.
# ---------------------------------------------------------------------------

begin_test "Build known-vulnerable fixture (lodash 4.17.4 / CVE-2019-10744)"
mkdir -p "${WORK_DIR}/package"

cat > "${WORK_DIR}/package/package.json" <<EOF
{
  "name": "scan-completes-fixture",
  "version": "1.0.0",
  "description": "Release-gate fixture pinned to a known-vulnerable lodash for CVE-2019-10744 detection",
  "dependencies": {
    "lodash": "4.17.4"
  }
}
EOF

cat > "${WORK_DIR}/package/package-lock.json" <<EOF
{
  "name": "scan-completes-fixture",
  "version": "1.0.0",
  "lockfileVersion": 2,
  "requires": true,
  "packages": {
    "": {
      "name": "scan-completes-fixture",
      "version": "1.0.0",
      "dependencies": {
        "lodash": "4.17.4"
      }
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

if tar -czf "${WORK_DIR}/${TARBALL_NAME}" -C "${WORK_DIR}" package 2>/dev/null; then
  pass
else
  fail "could not build vulnerable fixture tarball"
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

begin_test "Upload fixture"
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
# Capture TEST_START_EPOCH BEFORE triggering the scan. The recency
# assertion below requires `created_at >= TEST_START_EPOCH + 2s` to
# defeat the auto-scan-on-upload race. The 2s buffer accounts for
# `date +%s` 1-second granularity and any clock-skew between the runner
# and the backend pod (usually co-located on the same node, so skew is
# bounded).
# ---------------------------------------------------------------------------

TEST_START_EPOCH=$(date -u +%s)

# ---------------------------------------------------------------------------
# Resolve the artifact_id. The metadata endpoint is GET /:key/artifacts/*path
# (NO /metadata suffix). The previous PR #50 attempt got this wrong and
# silently fell through to the list-by-path fallback every run.
# ---------------------------------------------------------------------------

begin_test "Resolve artifact_id"
# shellcheck disable=SC2086  # CURL_TIMEOUT must word-split, per common.sh
artifact_lookup_status=$(curl -s -o "${WORK_DIR}/artifact-resp.json" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" \
  -H "Accept: application/json" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/${ARTIFACT_PATH}") \
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
      '.items | map(select(.path == $p or .name == $p)) | first | .id // .artifact_id // empty' \
      < "${WORK_DIR}/list-resp.json" 2>/dev/null || true)
  fi
fi

if [ -n "$ARTIFACT_ID" ]; then
  pass
else
  fail "could not resolve artifact_id for ${ARTIFACT_PATH} (primary lookup HTTP ${artifact_lookup_status})"
fi

# ---------------------------------------------------------------------------
# Trigger a scan. Real endpoint: POST /api/v1/security/scan with
# {artifact_id}. Returns TriggerScanResponse {message, artifacts_queued}.
# Assert artifacts_queued >= 1 to catch eligibility-filter regressions
# that would otherwise silently send the test into a polling time-out.
# ---------------------------------------------------------------------------

begin_test "Trigger scan and assert artifacts_queued >= 1"
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
    queued=$(jq -er '.artifacts_queued // 0' < "${WORK_DIR}/trigger-resp.json" 2>/dev/null || echo 0)
    if is_nonneg_int "$queued" && [ "$queued" -ge 1 ]; then
      pass
    else
      fail "POST /api/v1/security/scan returned 2xx but artifacts_queued=${queued} (expected >= 1; eligibility filter excluded the artifact?)"
    fi
    ;;
  000)
    scanner_unavailable "trigger curl exit non-zero (network/DNS)"
    ;;
  502)
    fail "scan trigger HTTP 502 (BadGateway). Backend's BadGateway is emitted only by SSRF/proxy paths, not scan endpoints; this likely means ingress or backend pod is down -- different class than scanner-unreachable."
    ;;
  503)
    scanner_unavailable "scan trigger HTTP 503 (scanner pod unreachable)"
    ;;
  504)
    scanner_unavailable "scan trigger HTTP 504 (gateway timeout)"
    ;;
  404)
    fail "scan trigger HTTP 404 -- endpoint /api/v1/security/scan missing or backend version too old"
    ;;
  *)
    # Auto-scan-on-upload may make trigger return non-2xx (e.g. 409 already
    # queued). Note it and proceed to poll.
    echo "  scan trigger returned HTTP ${scan_trigger_status}; proceeding to poll (may be auto-scan-on-upload)"
    pass
    ;;
esac

# ---------------------------------------------------------------------------
# Poll the per-artifact scan list until terminal.
#
# Real endpoint: GET /api/v1/security/artifacts/{artifact_id}/scans
# Response shape: { items: [ScanResponse], total }
# Network errors (000) and gateway timeouts (502/504) AND 503 count
# toward the unavailable threshold so a fully-broken environment
# triggers scanner_unavailable instead of silently polling for the
# entire timeout. 502 separately is a hard fail (see above) -- but
# transient 502 during the polling window is treated as "unavailable"
# class along with the others.
# ---------------------------------------------------------------------------

begin_test "Scan reaches terminal state within ${SCAN_TIMEOUT}s"

SCAN_LIST_PATH="/api/v1/security/artifacts/${ARTIFACT_ID}/scans"
elapsed=0
poll_interval=5
final_status=""
final_body=""
final_scan_id=""
network_fail_count=0
unknown_state_count=0
last_observed_state=""

while [ "$elapsed" -lt "$SCAN_TIMEOUT" ]; do
  # shellcheck disable=SC2086  # CURL_TIMEOUT must word-split, per common.sh
  http_status=$(curl -s -o "${WORK_DIR}/scans-resp.json" -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(auth_header)" \
    -H "Accept: application/json" \
    "${BASE_URL}${SCAN_LIST_PATH}") || http_status="000"

  if [ "$http_status" = "200" ]; then
    # Reset the network fail counter on every successful poll. Without
    # this, a flap pattern (5 transient + intermittent 200) eventually
    # trips scanner_unavailable on the 6th transient even though the
    # scan is actually progressing.
    network_fail_count=0

    # Hard-fail on malformed JSON. A 200 with a non-JSON body (e.g.,
    # an HTML 200 from a misrouted ingress) would otherwise let the
    # gate spin silently for the full SCAN_TIMEOUT and then report a
    # generic timeout. That is the exact #872 silent-no-op pattern.
    if ! scan_obj=$(jq -c '.items[0] // empty' < "${WORK_DIR}/scans-resp.json" 2>&1); then
      snippet=$(head -c 500 "${WORK_DIR}/scans-resp.json" 2>/dev/null || echo "<empty>")
      fail "scan-list returned 200 but body was not JSON; release-gate must not silently spin on malformed responses" \
"jq error: ${scan_obj}
response (first 500 bytes):
${snippet}
endpoint: GET ${BASE_URL}${SCAN_LIST_PATH}"
      end_suite
      exit 1
    fi

    if [ -n "$scan_obj" ]; then
      state=$(echo "$scan_obj" | jq -er '.status | ascii_downcase' 2>/dev/null || echo "unknown")
      last_observed_state="$state"
      case "$state" in
        queued|pending|in_progress|scanning|running)
          unknown_state_count=0
          ;;
        unknown)
          # Cap consecutive unparseable responses. If .status is
          # missing or null for 3 polls in a row, that is a backend
          # contract regression -- fail loud rather than spin to
          # SCAN_TIMEOUT and report a generic message.
          unknown_state_count=$(( unknown_state_count + 1 ))
          if [ "$unknown_state_count" -ge 3 ]; then
            snippet=$(echo "$scan_obj" | jq -c '.' 2>/dev/null | cut -c 1-500)
            fail "scan response has malformed/missing .status for 3 consecutive polls; suspect backend ScanResponse contract regression" \
"observed scan body: ${snippet}
endpoint: GET ${BASE_URL}${SCAN_LIST_PATH}"
            end_suite
            exit 1
          fi
          ;;
        *)
          final_status="$state"
          final_body="$scan_obj"
          final_scan_id=$(echo "$scan_obj" | jq -er '.id // empty' 2>/dev/null || echo "")
          break
          ;;
      esac
    fi
  elif [ "$http_status" = "000" ] || [ "$http_status" = "502" ] || \
       [ "$http_status" = "503" ] || [ "$http_status" = "504" ]; then
    network_fail_count=$(( network_fail_count + 1 ))
    if [ "$network_fail_count" -ge 6 ]; then
      scanner_unavailable "scan-list HTTP ${http_status} for 6 consecutive polls"
    fi
  fi

  sleep "$poll_interval"
  elapsed=$(( elapsed + poll_interval ))
done

if [ -z "$final_status" ]; then
  fail "scan did not reach a terminal state within ${SCAN_TIMEOUT}s (last state: '${last_observed_state:-none}'); regression for issue #871"
fi

# ---------------------------------------------------------------------------
# Assert terminal status is "completed".
# ---------------------------------------------------------------------------

begin_test "Final scan status is completed"
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
# Assert the report passes the LITE provenance checks.
#
# Each predicate uses `jq -e` with strict null/empty handling so a
# literal JSON null cannot pass as a non-empty string. This is the
# round-3 lesson from PR #50.
#
#   - completed_at is a non-empty string (proves the scanner reported
#     completion at all)
#   - error_message is null or empty (proves the COMPLETED status is
#     not hiding a swallowed error)
#   - created_at >= TEST_START_EPOCH + 2s (defeats auto-scan-on-upload
#     race; we strip nanosecond fractional seconds before
#     `fromdateiso8601` since chrono::DateTime serializes with nanos
#     and jq's fromdateiso8601 only accepts %Y-%m-%dT%H:%M:%SZ)
#
# We do NOT assert on scanner_version because the backend never
# populates it (artifact-keeper#902 will fix that for v1.2.0; the full
# epic #56 will add the assertion then).
# ---------------------------------------------------------------------------

begin_test "Scan report passes lite provenance checks (regression for #888)"
if [ -z "$final_body" ]; then
  fail "scan response was empty; cannot verify provenance"
else
  completed_at_present=0
  error_message_clean=0
  scan_is_recent=0

  if echo "$final_body" | jq -e '
        .completed_at != null
        and (.completed_at | type) == "string"
        and (.completed_at | length) > 0
      ' >/dev/null 2>&1; then
    completed_at_present=1
  fi

  if echo "$final_body" | jq -e '
        .error_message == null
        or (.error_message | type) == "null"
        or ((.error_message | type) == "string" and (.error_message | length) == 0)
      ' >/dev/null 2>&1; then
    error_message_clean=1
  fi

  # Strip nanosecond fractional seconds before fromdateiso8601. chrono's
  # default RFC3339 serializer emits e.g. "2026-04-27T12:00:00.123456789Z"
  # but jq's fromdateiso8601 only accepts %Y-%m-%dT%H:%M:%SZ.
  recency_threshold=$(( TEST_START_EPOCH + 2 ))
  if echo "$final_body" | jq --arg threshold "$recency_threshold" -e '
        .created_at != null
        and (.created_at | type) == "string"
        and ((.created_at | sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601) >= ($threshold | tonumber))
      ' >/dev/null 2>&1; then
    scan_is_recent=1
  fi

  if [ "$completed_at_present" = "1" ] && \
     [ "$error_message_clean" = "1" ] && \
     [ "$scan_is_recent" = "1" ]; then
    pass
  else
    snippet=$(echo "$final_body" | jq -c '{id, status, started_at, completed_at, created_at, error_message, findings_count}' 2>/dev/null | cut -c 1-500)
    fail "scan ${final_scan_id} fails lite provenance: completed_at=${completed_at_present}, error_message_clean=${error_message_clean}, scan_is_recent=${scan_is_recent} (TEST_START_EPOCH=${TEST_START_EPOCH})" \
"scan response (projected): ${snippet:-<unparseable>}
endpoint: GET ${BASE_URL}${SCAN_LIST_PATH}
scan_id: ${final_scan_id}
artifact_id: ${ARTIFACT_ID}
diagnose: kubectl -n test-\${RUN_ID} logs deploy/artifact-keeper-trivy --since=10m"
  fi
fi

# ---------------------------------------------------------------------------
# Findings-count regression check.
#
# This is the load-bearing assertion against the silent-success class.
# The fixture pins lodash 4.17.4 in package-lock.json; that is
# CVE-2019-10744 (CVSS 9.1). Trivy's filesystem scanner detects it via
# the npm lockfile parser. If the scanner actually inspected the
# bytes, findings_count >= 1.
#
# Without this check, a backend that calls complete_scan with
# findings_count=0 (the Ok(vec![]) "not applicable" path in
# scanner_service.rs) satisfies every other gate predicate and ships
# a green "scanned, no findings" badge on a vulnerable artifact. That
# is the exact failure mode the customer flagged in
# https://github.com/orgs/artifact-keeper/discussions/872.
#
# A pinned-CVE assertion would tighten this further (assert the
# specific CVE id appears in the findings list), but ScanResponse does
# not expose findings inline; that would require GET
# /api/v1/security/scans/{id}/findings, which is deferred to the full
# epic (#56) so this LITE gate stays minimal.
# ---------------------------------------------------------------------------

begin_test "Scan emitted findings on known-vulnerable fixture (regression for #888 silent-success class)"
findings_count=$(echo "$final_body" | jq -r '.findings_count // "null"' 2>/dev/null || echo "null")
if [ "$findings_count" = "null" ]; then
  fail "scan ${final_scan_id} has no findings_count field" \
"This is a backend contract regression -- ScanResponse must include findings_count.
scan body: $(echo "$final_body" | jq -c '.' 2>/dev/null | cut -c 1-500)"
elif ! is_nonneg_int "$findings_count"; then
  fail "scan ${final_scan_id} reports non-integer findings_count='${findings_count}'" \
"scan body: $(echo "$final_body" | jq -c '.' 2>/dev/null | cut -c 1-500)"
elif [ "$findings_count" -lt 1 ]; then
  fail "scan ${final_scan_id} on known-vulnerable fixture (lodash ${EXPECTED_VULN_VERSION} / ${EXPECTED_VULN_CVE_HINT}) reports findings_count=0; scanner did not inspect the bytes" \
"This is the #888 silent-success failure mode reproducing.

Possible causes:
  1. Trivy is not enabled in the test deploy (chart values: trivy.enabled).
  2. Trivy fs scanner's is_applicable check rejected the fixture format.
  3. Backend's scanner_service Ok(vec![]) path treated empty as success.
  4. find_reusable_scan returned a stale empty scan from a prior run.

Diagnostic commands:
  kubectl -n test-\${RUN_ID} logs deploy/artifact-keeper-trivy --since=10m
  kubectl -n test-\${RUN_ID} logs deploy/artifact-keeper-backend --since=10m | grep -i scan
  curl -H \"Authorization: Bearer \$TOKEN\" \"${BASE_URL}/api/v1/security/scans/${final_scan_id}/findings\"

scan body: $(echo "$final_body" | jq -c '.' 2>/dev/null | cut -c 1-500)"
else
  pass
fi

# ---------------------------------------------------------------------------
# Diagnostics dump on failure. The release-gate workflow's failure-hook
# step uploads $JUNIT_OUTPUT_DIR; this leaves a breadcrumb the operator
# can use without re-running with --keep-namespace.
# ---------------------------------------------------------------------------

if [ -d "${JUNIT_OUTPUT_DIR:-/tmp/junit}" ]; then
  cp "${WORK_DIR}/scans-resp.json" "${JUNIT_OUTPUT_DIR}/scan-completes-final-resp.json" 2>/dev/null || true
  if [ -n "$final_scan_id" ]; then
    echo "$final_scan_id" > "${JUNIT_OUTPUT_DIR}/scan-completes-final-id.txt" 2>/dev/null || true
  fi
fi

end_suite
