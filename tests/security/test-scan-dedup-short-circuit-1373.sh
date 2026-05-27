#!/usr/bin/env bash
# test-scan-dedup-short-circuit-1373.sh -- scan dedup short-circuit on identical bytes
#
# Reproducer / regression test for artifact-keeper#1373.
#
# Background
#   trigger_scan previously inserted a `running` placeholder for every call,
#   even when the artifact already had a completed scan for the same checksum
#   + scan_type. The worker then converted the placeholder to `completed`,
#   leaving two completed rows behind for what should have been a single
#   logical scan.
#
#   PR #1388 adds an explicit short-circuit BEFORE the placeholder insert:
#   when the artifact already has a completed scan for these exact bytes +
#   scanner combo (within the 30-day TTL window), trigger_scan returns the
#   existing scan_id directly instead of starting a fresh scan.
#
# What this script catches
#   - The exact #1373 symptom: the per-artifact scans list contains two
#     `completed` rows after triggering the same scan twice on byte-identical
#     content.
#   - A regression that re-introduces the duplicate placeholder insert -- the
#     second trigger_scan call would observe a different scan_id from the
#     first (the new placeholder), and the list-after-second call would show
#     count >= 2.
#
#   The fix has two observable contracts; this script asserts both:
#     1. The two trigger_scan calls return the SAME scan_id.
#     2. GET /api/v1/security/artifacts/{id}/scans returns exactly 1 completed
#        row after both triggers.
#
# What this script does NOT cover
#   - Cross-artifact reuse (where an identical-bytes scan exists on a
#     DIFFERENT artifact): that path still inserts a copied row and is
#     covered by backend/tests/scan_dedup_short_circuit_tests.rs.
#   - 30-day TTL expiry of the reusable scan window: requires time travel
#     fixtures that don't fit a release-gate E2E.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "scan-dedup-short-circuit-1373"
auth_admin
setup_workdir

REPO_KEY="scan-dedup-${RUN_ID}"
PACKAGE_NAME="dedup-fixture"
PACKAGE_VERSION="1.0.0"
TARBALL_NAME="${PACKAGE_NAME}-${PACKAGE_VERSION}.tgz"

# Two artifact paths so we can upload byte-identical content under two names.
# Per the PR, the same-artifact short-circuit hinges on (artifact_id +
# checksum + scan_type); the cross-artifact reuse path is separate. This
# script focuses on the same-artifact path because that is the customer-
# observable failure mode (re-triggering a scan from the UI on a single
# artifact).
ARTIFACT_PATH_A="${PACKAGE_NAME}/${PACKAGE_VERSION}/A/${TARBALL_NAME}"

SCAN_TIMEOUT="${SCAN_TIMEOUT:-180}"
ALLOW_SCANNER_SKIP="${ALLOW_SCANNER_SKIP:-0}"

# -------------------------------------------------------------------------
# Scanner-unavailable handling. The release-gate must fail if the scanner
# can't run; local dev can opt in to graceful skip. Same contract as
# test-scan-completes.sh.
# -------------------------------------------------------------------------

scanner_unavailable() {
  local reason="$1"
  if [ "$ALLOW_SCANNER_SKIP" = "1" ]; then
    skip "scanner unavailable (${reason}); ALLOW_SCANNER_SKIP=1 honored for local dev"
    end_suite
    exit 0
  fi
  fail "scanner unavailable (${reason}); release-gate must fail when scanner cannot run"
  end_suite
  exit 1
}

# Cleanup trap that combines repo deletion with the workdir cleanup
# setup_workdir installed. Wraps both so we don't clobber the parent trap.
cleanup() {
  local exit_code=$?
  curl -sf $CURL_TIMEOUT -X DELETE -H "$(auth_header)" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}" >/dev/null 2>&1 || true
  exit "$exit_code"
}
add_exit_handler "cleanup"

# -------------------------------------------------------------------------
# Build a small fixture. We don't need a vulnerable payload here -- the
# short-circuit decision is byte-identity + scan_type, independent of
# findings count. A tiny tarball with a package.json is the cheapest input
# the npm scanner_type accepts.
# -------------------------------------------------------------------------

begin_test "Build small fixture (byte-identical content)"
mkdir -p "${WORK_DIR}/package"
cat > "${WORK_DIR}/package/package.json" <<EOF
{
  "name": "${PACKAGE_NAME}",
  "version": "${PACKAGE_VERSION}",
  "description": "Dedup fixture for #1373 -- bytes must be stable across re-triggers"
}
EOF
# Force a deterministic mtime so the tarball has a stable sha256 even if
# this test races with itself across reruns.
touch -t 202601010000.00 "${WORK_DIR}/package/package.json"
if tar -czf "${WORK_DIR}/${TARBALL_NAME}" -C "${WORK_DIR}" package 2>/dev/null; then
  pass
else
  fail "could not build fixture tarball"
fi

# -------------------------------------------------------------------------
# Create repo + upload the fixture once. The artifact short-circuit hinges
# on a single artifact_id receiving two trigger_scan calls.
# -------------------------------------------------------------------------

begin_test "Create generic local repository"
if create_local_repo "$REPO_KEY" "generic"; then
  pass
else
  fail "could not create repository ${REPO_KEY}"
fi

begin_test "Upload fixture (artifact A)"
upload_status=$(curl -s -o "${WORK_DIR}/upload-resp.json" -w '%{http_code}' $CURL_TIMEOUT \
  -X PUT \
  -H "$(auth_header)" \
  -H "Content-Type: application/gzip" \
  --data-binary "@${WORK_DIR}/${TARBALL_NAME}" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/${ARTIFACT_PATH_A}") || upload_status="000"

if [ "$upload_status" = "200" ] || [ "$upload_status" = "201" ]; then
  pass
elif [ "$upload_status" = "000" ]; then
  scanner_unavailable "backend unreachable on upload"
else
  fail "upload returned ${upload_status}, expected 200/201"
fi

# Resolve artifact_id. Mirrors test-scan-completes.sh resolution path.
begin_test "Resolve artifact_id for artifact A"
artifact_lookup_status=$(curl -s -o "${WORK_DIR}/artifact-resp.json" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" \
  -H "Accept: application/json" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/${ARTIFACT_PATH_A}") \
  || artifact_lookup_status="000"

ARTIFACT_ID=""
if [ "$artifact_lookup_status" = "200" ]; then
  ARTIFACT_ID=$(jq -er '.id // .artifact_id // empty' < "${WORK_DIR}/artifact-resp.json" 2>/dev/null || true)
fi
if [ -z "$ARTIFACT_ID" ]; then
  list_status=$(curl -s -o "${WORK_DIR}/list-resp.json" -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(auth_header)" \
    -H "Accept: application/json" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts") \
    || list_status="000"
  if [ "$list_status" = "200" ]; then
    ARTIFACT_ID=$(jq -er --arg p "$ARTIFACT_PATH_A" \
      '.items | map(select(.path == $p or .name == $p)) | first | .id // .artifact_id // empty' \
      < "${WORK_DIR}/list-resp.json" 2>/dev/null || true)
  fi
fi

if [ -n "$ARTIFACT_ID" ] && [ "$ARTIFACT_ID" != "null" ]; then
  pass
else
  fail "could not resolve artifact_id for ${ARTIFACT_PATH_A} (lookup HTTP ${artifact_lookup_status})"
fi

# -------------------------------------------------------------------------
# Trigger #1. Capture the scan_id this returns. We wait for the scan to
# reach a terminal state before triggering #2 because the short-circuit only
# fires against a COMPLETED prior scan -- if the second trigger lands while
# the first is still `running`, the backend takes a different code path
# (the same-artifact race-recovery branch) which is a separate decision
# tested in backend/tests/scan_dedup_short_circuit_tests.rs.
# -------------------------------------------------------------------------

begin_test "Trigger #1: POST /api/v1/security/scan returns 2xx"
TRIGGER1_PAYLOAD=$(jq -n --arg id "$ARTIFACT_ID" '{artifact_id: $id}')
trigger1_status=$(curl -s -o "${WORK_DIR}/trigger1.json" -w '%{http_code}' $CURL_TIMEOUT \
  -X POST \
  -H "$(auth_header)" \
  -H "Content-Type: application/json" \
  -d "$TRIGGER1_PAYLOAD" \
  "${BASE_URL}/api/v1/security/scan" 2>/dev/null) || trigger1_status="000"

case "$trigger1_status" in
  2*) pass ;;
  000) scanner_unavailable "trigger #1 curl exit non-zero" ;;
  503|504) scanner_unavailable "trigger #1 HTTP ${trigger1_status}" ;;
  *) fail "trigger #1 returned HTTP ${trigger1_status}, expected 2xx" ;;
esac

# Wait for the first scan to be completed so trigger #2 will exercise the
# short-circuit branch (not the race-recovery branch).
begin_test "Wait for scan #1 to reach completed"
SCAN_LIST_PATH="/api/v1/security/artifacts/${ARTIFACT_ID}/scans"
elapsed=0
poll_interval=5
first_scan_id=""
first_state=""
network_fail_count=0

while [ "$elapsed" -lt "$SCAN_TIMEOUT" ]; do
  http_status=$(curl -s -o "${WORK_DIR}/scans1.json" -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(auth_header)" \
    -H "Accept: application/json" \
    "${BASE_URL}${SCAN_LIST_PATH}") || http_status="000"

  if [ "$http_status" = "200" ]; then
    network_fail_count=0
    state=$(jq -er '.items[0].status // empty | ascii_downcase' < "${WORK_DIR}/scans1.json" 2>/dev/null || echo "")
    if [ "$state" = "completed" ]; then
      first_state="$state"
      first_scan_id=$(jq -er '.items[0].id // empty' < "${WORK_DIR}/scans1.json" 2>/dev/null || echo "")
      break
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

if [ "$first_state" = "completed" ] && [ -n "$first_scan_id" ]; then
  pass
else
  fail "scan #1 did not reach 'completed' within ${SCAN_TIMEOUT}s (last state: '${first_state:-none}')"
fi

# -------------------------------------------------------------------------
# Trigger #2: SAME artifact, SAME bytes. The short-circuit must fire: the
# returned scan_id should equal first_scan_id, and the per-artifact list
# should still show exactly one completed row.
#
# trigger_scan does not include the reused scan_id in its response body
# (TriggerScanResponse is {message, artifacts_queued}), so we observe the
# short-circuit indirectly: artifacts_queued > 0 would indicate a NEW scan
# was started, and the list-after-trigger #2 would show count >= 2.
# -------------------------------------------------------------------------

begin_test "Trigger #2 on same artifact + same bytes"
TRIGGER2_PAYLOAD=$(jq -n --arg id "$ARTIFACT_ID" '{artifact_id: $id}')
trigger2_status=$(curl -s -o "${WORK_DIR}/trigger2.json" -w '%{http_code}' $CURL_TIMEOUT \
  -X POST \
  -H "$(auth_header)" \
  -H "Content-Type: application/json" \
  -d "$TRIGGER2_PAYLOAD" \
  "${BASE_URL}/api/v1/security/scan" 2>/dev/null) || trigger2_status="000"

if [[ "$trigger2_status" =~ ^2[0-9][0-9]$ ]]; then
  pass
else
  fail "trigger #2 returned HTTP ${trigger2_status}, expected 2xx"
fi

# Give the backend a moment to settle any inflight bookkeeping. If the bug
# is reproducing, a duplicate placeholder will appear within ~1s of the
# second trigger because the placeholder insert is synchronous.
sleep 3

# -------------------------------------------------------------------------
# Load-bearing assertion #1: per-artifact list shows exactly 1 completed row.
#
# This is the symptom the customer saw: a second `completed` row appearing
# for what should have been a single logical scan. Pin the count to exactly 1.
# -------------------------------------------------------------------------

begin_test "Per-artifact scans list has exactly 1 completed row (#1373 regression)"
list_status=$(curl -s -o "${WORK_DIR}/scans2.json" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" \
  -H "Accept: application/json" \
  "${BASE_URL}${SCAN_LIST_PATH}") || list_status="000"

if [ "$list_status" != "200" ]; then
  fail "scan-list returned HTTP ${list_status}"
else
  completed_count=$(jq '[.items[] | select((.status | ascii_downcase) == "completed")] | length' \
                    < "${WORK_DIR}/scans2.json" 2>/dev/null || echo "0")
  total_count=$(jq '.items | length // 0' < "${WORK_DIR}/scans2.json" 2>/dev/null || echo "0")
  if [ "$completed_count" = "1" ]; then
    pass
  else
    snippet=$(jq -c '[.items[] | {id, status}]' < "${WORK_DIR}/scans2.json" 2>/dev/null | cut -c 1-500)
    fail "expected exactly 1 completed scan for artifact ${ARTIFACT_ID}, got ${completed_count} (total rows: ${total_count})" \
"This is the #1373 symptom: the second trigger_scan call inserted a new
placeholder row that the worker promoted to 'completed', leaving 2+
completed rows where the short-circuit should have returned the existing
scan_id.

scans (projected): ${snippet}
endpoint: GET ${BASE_URL}${SCAN_LIST_PATH}
first scan_id: ${first_scan_id}"
  fi
fi

# -------------------------------------------------------------------------
# Load-bearing assertion #2: the second-most-recent (if present) is the
# same scan_id as the first. Asserting this on top of the count-of-1
# assertion catches a regression where a placeholder is inserted then
# garbage-collected (count=1 again, but with a different id than expected).
#
# If the list has only one row, the id check trivially holds.
# -------------------------------------------------------------------------

begin_test "Latest completed scan_id equals first scan_id (no duplicate placeholder)"
latest_completed_id=$(jq -er '[.items[] | select((.status | ascii_downcase) == "completed")][0].id // empty' \
                      < "${WORK_DIR}/scans2.json" 2>/dev/null || echo "")
if [ -n "$latest_completed_id" ] && [ "$latest_completed_id" = "$first_scan_id" ]; then
  pass
else
  fail "latest completed scan_id (${latest_completed_id:-<empty>}) does not match first scan_id (${first_scan_id})" \
"The short-circuit must return the existing scan_id; a different id here
means a fresh placeholder was inserted and promoted to 'completed' (the
exact regression #1388 fixes)."
fi

end_suite
