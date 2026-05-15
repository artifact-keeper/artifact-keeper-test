#!/usr/bin/env bash
# test-stuck-scan-janitor.sh -- The stuck-scan janitor must NOT reap
# legitimate in-flight scans (regression for backend PR #1212).
#
# Tracks issue #69 sub-task 1.4 (cache TTL behavior; the janitor lives
# adjacent to the proxy/cache path because both rely on accurate
# state-transition timing).
#
# Background
# ----------
# Backend PR #1212 adds a janitor task that periodically scans the
# `security_scans` table for rows stuck in `queued` / `in_progress`
# past their max-runtime budget and force-transitions them to
# `failed` with an explanatory error_message. This unblocks the next
# scan-completion observer and matches the customer-pain pattern from
# discussions/872.
#
# Risk
# ----
# A too-aggressive janitor (max-runtime budget set too low, or wall-
# clock drift between the backend pod and the scanner pod) would reap
# scans that ARE making progress. The visible symptom would be
# silent-success false-failures (the scan was actually fine; the
# janitor preempted it) -- the EXACT opposite of the #871/#888 class
# the janitor was added to fix.
#
# What this script asserts
# ------------------------
# 1. Submit a normal scan against a vulnerable fixture and let it run
#    to completion. Total wall-clock for a typical scan on the
#    runner-pod-co-located trivy is ~10-40s. The janitor's max-runtime
#    budget must be > that, otherwise this test reproduces the
#    over-aggression bug directly.
#
# 2. Assert the scan completes with `status=completed` and a
#    `findings_count >= 1` (so we know the scanner actually inspected
#    the bytes, not that the janitor force-failed it).
#
# 3. Assert error_message is empty / null. If the janitor reaped the
#    scan, error_message contains the janitor's marker string. The
#    backend writes a distinctive substring like "janitor" or
#    "max_runtime_exceeded" -- we grep case-insensitively for either.
#
# 4. (Bonus) Hit /api/v1/security/scans?limit=50 and assert NO scan
#    in the last 5 minutes has the janitor marker in error_message.
#    This catches the case where the janitor IS firing on someone
#    else's scans even if ours got lucky. Run as an advisory check
#    (warn, do not fail) because other suites' scan-failures could
#    legitimately bear other error messages.
#
# What this script does NOT cover
# -------------------------------
# - The positive case: actually proving the janitor reaps a TRULY
#   stuck scan. That needs a deliberately-stalling fixture (e.g. a
#   scanner pod scaled to zero mid-scan), which belongs in a
#   negative-control test on the security suite (deferred to the
#   epic #56 follow-up).
#
# - Janitor scheduling cadence assertions. The cadence is configured
#   per deployment; we'd need a probe endpoint or a metric to assert
#   "janitor ran at least once in the last 60s". That's deferred to
#   the metrics-coverage epic.
#
# Requires: curl, jq, tar

source "$(dirname "$0")/../lib/common.sh"

begin_suite "stuck-scan-janitor"
auth_admin
setup_workdir

REPO_KEY="ssj-${RUN_ID}"
PACKAGE_NAME="lodash-vuln-fixture"
PACKAGE_VERSION="1.0.0"
TARBALL_NAME="${PACKAGE_NAME}-${PACKAGE_VERSION}.tgz"
ARTIFACT_PATH="${PACKAGE_NAME}/${PACKAGE_VERSION}/${TARBALL_NAME}"
SCAN_TIMEOUT="${SCAN_TIMEOUT:-180}"

# Janitor marker substrings the backend uses in error_message when it
# force-fails a stuck scan. If you rename either of these in the
# backend, update this list -- the assertion below greps for any one
# of them and a typo in the marker would silently de-fang the test.
JANITOR_MARKERS=(
  "janitor"
  "max_runtime_exceeded"
  "stuck_scan_reaper"
)

# Build the same lodash 4.17.4 fixture used by test-scan-completes.sh
# so we know it produces findings (CVE-2019-10744). Trivy detects this
# in package-lock.json.
begin_test "Build known-vulnerable fixture (lodash 4.17.4)"
mkdir -p "${WORK_DIR}/package"
cat > "${WORK_DIR}/package/package.json" <<EOF
{
  "name": "stuck-scan-janitor-fixture",
  "version": "1.0.0",
  "dependencies": { "lodash": "4.17.4" }
}
EOF
cat > "${WORK_DIR}/package/package-lock.json" <<EOF
{
  "name": "stuck-scan-janitor-fixture",
  "version": "1.0.0",
  "lockfileVersion": 2,
  "requires": true,
  "packages": {
    "": {
      "name": "stuck-scan-janitor-fixture",
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
if tar -czf "${WORK_DIR}/${TARBALL_NAME}" -C "${WORK_DIR}" package 2>/dev/null; then
  pass
else
  fail "could not build fixture tarball"
fi

begin_test "Create local generic repo"
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
  *)       fail "upload returned ${upload_status}" ;;
esac

# Resolve artifact id (mirrors test-scan-completes.sh).
begin_test "Resolve artifact_id"
artifact_lookup_status=$(curl -s -o "${WORK_DIR}/artifact-resp.json" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" \
  -H "Accept: application/json" \
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
  fail "could not resolve artifact_id for ${ARTIFACT_PATH}"
fi

# Trigger the scan.
begin_test "Trigger scan"
scan_trigger_payload=$(jq -n --arg id "$ARTIFACT_ID" '{artifact_id: $id}')
trigger_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X POST -H "$(auth_header)" -H "Content-Type: application/json" \
  -d "$scan_trigger_payload" \
  "${BASE_URL}/api/v1/security/scan" 2>/dev/null) || trigger_status="000"
case "$trigger_status" in
  2*) pass ;;
  *) echo "  scan trigger returned HTTP ${trigger_status}; proceeding (may be auto-scan-on-upload)"; pass ;;
esac

# Poll for completion.
begin_test "Scan reaches terminal state within ${SCAN_TIMEOUT}s"
SCAN_LIST_PATH="/api/v1/security/artifacts/${ARTIFACT_ID}/scans"
elapsed=0
poll_interval=5
final_status=""
final_body=""
while [ "$elapsed" -lt "$SCAN_TIMEOUT" ]; do
  http_status=$(curl -s -o "${WORK_DIR}/scans-resp.json" -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(auth_header)" -H "Accept: application/json" \
    "${BASE_URL}${SCAN_LIST_PATH}") || http_status="000"
  if [ "$http_status" = "200" ]; then
    scan_obj=$(jq -c '.items[0] // empty' < "${WORK_DIR}/scans-resp.json" 2>/dev/null || echo "")
    if [ -n "$scan_obj" ]; then
      state=$(echo "$scan_obj" | jq -er '.status | ascii_downcase' 2>/dev/null || echo "unknown")
      case "$state" in
        queued|pending|in_progress|scanning|running|unknown)
          ;;
        *)
          final_status="$state"
          final_body="$scan_obj"
          break
          ;;
      esac
    fi
  fi
  sleep "$poll_interval"
  elapsed=$(( elapsed + poll_interval ))
done
if [ -n "$final_status" ]; then
  pass
else
  fail "scan did not reach terminal state within ${SCAN_TIMEOUT}s"
fi

# ---------------------------------------------------------------------------
# Janitor non-interference assertions
# ---------------------------------------------------------------------------

begin_test "Final scan status is 'completed' (janitor did NOT reap mid-flight)"
if [ "$final_status" = "completed" ]; then
  pass
else
  err_msg=$(echo "$final_body" | jq -r '.error_message // ""' 2>/dev/null || echo "")
  fail "scan terminal status is '${final_status}' (error_message: '${err_msg}'); if error_message contains a janitor marker, PR #1212 over-aggression regressed"
fi

begin_test "Scan emitted findings (proves the scanner ran, was not preempted)"
findings_count=$(echo "$final_body" | jq -r '.findings_count // "null"' 2>/dev/null || echo "null")
if [ "$findings_count" = "null" ]; then
  fail "scan has no findings_count field"
elif ! [[ "$findings_count" =~ ^[0-9]+$ ]]; then
  fail "findings_count is non-integer: '${findings_count}'"
elif [ "$findings_count" -lt 1 ]; then
  fail "findings_count=0 on lodash 4.17.4 fixture; scanner did not inspect bytes (could be janitor preemption OR scanner-unavailable)"
else
  pass
fi

begin_test "error_message contains no janitor marker (regression for #1212 over-aggression)"
err_msg=$(echo "$final_body" | jq -r '.error_message // ""' 2>/dev/null || echo "")
marker_hit=""
for marker in "${JANITOR_MARKERS[@]}"; do
  # Case-insensitive substring match
  if echo "$err_msg" | grep -iqF "$marker"; then
    marker_hit="$marker"
    break
  fi
done
if [ -z "$marker_hit" ]; then
  pass
else
  fail "error_message contains janitor marker '${marker_hit}': '${err_msg}' -- janitor reaped a legitimate in-flight scan"
fi

# ---------------------------------------------------------------------------
# Cross-suite advisory: check recent scans for janitor markers. This
# is informational only: a hit here doesn't fail the suite because it
# could legitimately reflect another test exercising the negative
# path. But it's logged so an operator triaging a release-gate
# failure can spot a pattern.
# ---------------------------------------------------------------------------

begin_test "Advisory: no recent scans bear janitor markers (cross-suite check)"
advisory_resp=$(curl -sf $CURL_TIMEOUT \
    -H "$(auth_header)" \
    "${BASE_URL}/api/v1/security/scans?limit=50" 2>/dev/null) || advisory_resp=""
if [ -z "$advisory_resp" ]; then
  skip "could not fetch /api/v1/security/scans for advisory check"
else
  hit_count=0
  for marker in "${JANITOR_MARKERS[@]}"; do
    n=$(echo "$advisory_resp" | jq --arg m "$marker" \
        '[.items[]? | select((.error_message // "") | ascii_downcase | contains($m | ascii_downcase))] | length' \
        2>/dev/null || echo 0)
    if [[ "$n" =~ ^[0-9]+$ ]]; then
      hit_count=$(( hit_count + n ))
    fi
  done
  if [ "$hit_count" -eq 0 ]; then
    pass
  else
    # Note: we PASS even on hit because this is advisory, but echo
    # the count so the run log preserves the signal.
    echo "  advisory: ${hit_count} recent scans bear janitor markers (informational, not failing)"
    pass
  fi
fi

# Cleanup
api_delete "/api/v1/repositories/${REPO_KEY}" >/dev/null 2>&1 || true

end_suite
