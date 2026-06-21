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
#
# IMPORTANT (scan_type scoping): the backend registers MORE THAN ONE scanner
# (e.g. `dependency` + `grype`), and each one writes its OWN scan_results row
# per artifact. The #1373 dedup contract is therefore per-scan_type: every
# configured scanner that ran must end with EXACTLY ONE completed row for the
# artifact, and re-triggering must not add a second row for any scan_type.
# The original test asserted "exactly 1 completed row TOTAL", which only ever
# held when a single scanner happened to run -- with two applicable scanners
# a correctly-deduped artifact has two completed rows (one each), so the old
# assertion failed even on the sequential happy path. We scope the wait and
# both assertions per scan_type so the real dedup invariant is checked
# without weakening it.
#
# We also wait for ALL scan_types to reach a terminal state (no row left in
# `running`/`pending`) before triggering #2, so trigger #2 always exercises
# the completed-scan short-circuit rather than the race-recovery branch.
begin_test "Wait for scan #1 to reach completed (all scan_types terminal)"
SCAN_LIST_PATH="/api/v1/security/artifacts/${ARTIFACT_ID}/scans"
elapsed=0
poll_interval=5
all_terminal="no"
network_fail_count=0

# Terminal statuses for a scan row. `completed` is the dedup-eligible one;
# `not_applicable`/`failed` are terminal too (a scanner that didn't apply or
# errored should not block the wait forever).
is_all_terminal_jq='
  (.items | length) > 0
  and ([.items[] | (.status | ascii_downcase)
        | select(. != "completed" and . != "not_applicable" and . != "failed")]
       | length) == 0
'

while [ "$elapsed" -lt "$SCAN_TIMEOUT" ]; do
  http_status=$(curl -s -o "${WORK_DIR}/scans1.json" -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(auth_header)" \
    -H "Accept: application/json" \
    "${BASE_URL}${SCAN_LIST_PATH}") || http_status="000"

  if [ "$http_status" = "200" ]; then
    network_fail_count=0
    if jq -e "$is_all_terminal_jq" < "${WORK_DIR}/scans1.json" >/dev/null 2>&1; then
      all_terminal="yes"
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

# Snapshot the per-scan_type completed-row map after trigger #1. Shape:
#   { "dependency": "<uuid>", "grype": "<uuid>", ... }
# Only `completed` rows are recorded (the dedup-eligible state). At least one
# scan_type must have completed for the short-circuit to be testable.
first_completed_by_type='{}'
first_completed_count=0
if [ "$all_terminal" = "yes" ]; then
  first_completed_by_type=$(jq -c '
    [.items[] | select((.status|ascii_downcase) == "completed")]
    | group_by(.scan_type)
    | map({(.[0].scan_type): (.[0].id)})
    | add // {}
  ' < "${WORK_DIR}/scans1.json" 2>/dev/null || echo '{}')
  first_completed_count=$(jq -r '[.items[] | select((.status|ascii_downcase)=="completed")] | length' \
                          < "${WORK_DIR}/scans1.json" 2>/dev/null || echo 0)
fi

if [ "$all_terminal" = "yes" ] && [ "${first_completed_count:-0}" -ge 1 ] 2>/dev/null; then
  pass
else
  last_states=$(jq -c '[.items[] | {scan_type, status}]' < "${WORK_DIR}/scans1.json" 2>/dev/null | cut -c1-300)
  fail "scan #1 did not reach a terminal state with >=1 completed row within ${SCAN_TIMEOUT}s" \
"all_terminal=${all_terminal} completed_rows=${first_completed_count}
states: ${last_states}"
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

# Snapshot scan state after trigger #2 settles, then run the two assertions.
list_status=$(curl -s -o "${WORK_DIR}/scans2.json" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" \
  -H "Accept: application/json" \
  "${BASE_URL}${SCAN_LIST_PATH}") || list_status="000"

# -------------------------------------------------------------------------
# Load-bearing assertion #1: EXACTLY ONE completed row PER scan_type.
#
# This is the precise #1373 dedup contract. The backend runs >=1 scanner and
# each writes its own row, so "one completed row total" is wrong; the real
# invariant is that no single scan_type accumulates a second completed row.
# We assert the max completed-count across scan_types is exactly 1 (and that
# at least one scan_type completed). A duplicate placeholder promoted to
# 'completed' for ANY scan_type makes that scan_type's count >= 2 and fails
# here -- which is exactly the symptom we must keep catching. We do NOT
# loosen this to "<= N"; per-scan_type the bound stays hard at 1.
# -------------------------------------------------------------------------
begin_test "Each scan_type has exactly 1 completed row (#1373 regression)"
if [ "$list_status" != "200" ]; then
  fail "scan-list returned HTTP ${list_status}"
else
  # Per-scan_type completed counts, e.g. [{"scan_type":"grype","completed":1},...]
  per_type=$(jq -c '
    [.items[] | select((.status|ascii_downcase) == "completed")]
    | group_by(.scan_type)
    | map({scan_type: .[0].scan_type, completed: length})
  ' < "${WORK_DIR}/scans2.json" 2>/dev/null || echo '[]')
  num_types=$(echo "$per_type" | jq 'length' 2>/dev/null || echo 0)
  max_per_type=$(echo "$per_type" | jq '[.[].completed] | max // 0' 2>/dev/null || echo 0)

  if [ "${num_types:-0}" -ge 1 ] 2>/dev/null && [ "${max_per_type:-0}" = "1" ]; then
    pass
  else
    snippet=$(jq -c '[.items[] | {id, scan_type, status, is_reused}]' < "${WORK_DIR}/scans2.json" 2>/dev/null | cut -c 1-700)
    fail "dedup contract broken: a scan_type has >1 completed row for artifact ${ARTIFACT_ID} (scan_types=${num_types}, max completed/type=${max_per_type})" \
"This is the #1373 symptom: a trigger_scan call inserted a new placeholder
row that the worker promoted to 'completed', leaving 2+ completed rows for
one scan_type where the short-circuit should have returned the existing
scan_id.

per-scan_type completed counts: ${per_type}
scans (projected): ${snippet}
endpoint: GET ${BASE_URL}${SCAN_LIST_PATH}
completed-by-type after trigger #1: ${first_completed_by_type}

NOTE: if this fails ONLY under concurrent load (and passes sequentially),
the cause is the known check-then-act race in
ScannerService::prepare_artifact_scan: find_existing_scan_for_artifact
(SELECT) and create_scan_result_with_checksum (INSERT) are not atomic and
there is no unique constraint on (artifact_id, scan_type, checksum_sha256),
so concurrent triggers each insert a fresh placeholder. That is a REAL
backend defect, not a test bug -- do NOT mask it by loosening this bound."
  fi
fi

# -------------------------------------------------------------------------
# Load-bearing assertion #2: the completed scan_id for each scan_type is
# UNCHANGED from the post-trigger-#1 snapshot. The short-circuit must return
# the EXISTING id; a different id for any scan_type means a fresh placeholder
# was inserted and promoted to 'completed' (the regression #1388 fixes), even
# if some janitor later collapsed the count back to 1.
# -------------------------------------------------------------------------
begin_test "Completed scan_id per scan_type unchanged after re-trigger (no dup placeholder)"
if [ "$list_status" != "200" ]; then
  fail "scan-list returned HTTP ${list_status}"
else
  second_completed_by_type=$(jq -c '
    [.items[] | select((.status|ascii_downcase) == "completed")]
    | group_by(.scan_type)
    | map({(.[0].scan_type): (.[0].id)})
    | add // {}
  ' < "${WORK_DIR}/scans2.json" 2>/dev/null || echo '{}')

  # Every scan_type present in the trigger-#1 snapshot must map to the SAME
  # completed id after trigger #2. New scan_types appearing is also a dup
  # signal, so require the two maps to be equal.
  if [ "$first_completed_by_type" = "$second_completed_by_type" ] && [ "$first_completed_by_type" != "{}" ]; then
    pass
  elif echo "$first_completed_by_type" | jq -e \
        --argjson after "$second_completed_by_type" \
        'to_entries | all(.value == ($after[.key])) and (length > 0) and (($after | length) == length)' \
        >/dev/null 2>&1; then
    # Robust equality independent of key ordering.
    pass
  else
    fail "completed scan_id changed for some scan_type after re-trigger" \
"The short-circuit must return the existing scan_id per scan_type; a changed
or added id means a fresh placeholder was inserted and promoted to
'completed' (the exact regression #1388 fixes).

after trigger #1: ${first_completed_by_type}
after trigger #2: ${second_completed_by_type}"
  fi
fi

end_suite
