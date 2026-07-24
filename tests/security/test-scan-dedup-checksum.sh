#!/usr/bin/env bash
# test-scan-dedup-checksum.sh -- Scan reuse via checksum dedup
#
# Covers Epic 2 sub-task 2.4 (artifact-keeper-test#67). The load-bearing
# cross-artifact dedup contract:
#
#   Two byte-identical artifacts get DISTINCT scan ids by design. When the
#   second artifact is scanned, the checksum-dedup path copies the prior
#   scan's results into a NEW scan row flagged is_reused=true with
#   source_scan_id pointing at the first artifact's scan. We therefore assert
#   the reuse linkage (is_reused=true, source_scan_id == scan A's id) rather
#   than id equality across the two artifacts. The is_reused boolean shipped
#   in v1.2.0 (artifact-keeper#907), so it is now asserted directly.
#
# What this test does NOT assert (deferred)
#   - scanner_version on either row (artifact-keeper#902)
#   - scan_result_id pinning (artifact-keeper#906)
#
# Skip semantics
# --------------
# If the scanner is not configured (502/503/504 or 500 with body matching
# /scanner.*not.*configured/), the suite SKIPs the dedup assertions because
# there is no scan row to dedup against. The repo create + upload steps
# still PASS so the gate distinguishes "scanner off" from "API regressed".
#
# Requires: curl, jq, tar, shasum
set -euo pipefail
source "$(dirname "$0")/../lib/common.sh"

begin_suite "scan-dedup-checksum"
auth_admin
setup_workdir

REPO_KEY="dedup-${RUN_ID}"
PACKAGE_NAME="dedup-fixture"
PACKAGE_VERSION="1.0.0"
TARBALL_NAME="${PACKAGE_NAME}-${PACKAGE_VERSION}.tgz"
ARTIFACT_PATH_A="${PACKAGE_NAME}/${PACKAGE_VERSION}/a-${TARBALL_NAME}"
ARTIFACT_PATH_B="${PACKAGE_NAME}/${PACKAGE_VERSION}/b-${TARBALL_NAME}"
SCAN_TIMEOUT="${SCAN_TIMEOUT:-180}"
SCANNER_AVAILABLE=true

cleanup() {
  api_delete "/api/v1/repositories/${REPO_KEY}" >/dev/null 2>&1 || true
}
add_exit_handler 'cleanup'

# Helper: trigger and wait for a terminal scan state on the given artifact id.
# Echoes the scan id on stdout, empty on failure. Sets SCANNER_AVAILABLE=false
# globally on scanner-not-configured responses.
trigger_and_wait() {
  local art_id="$1"
  local trig_status
  trig_status=$(curl -s -o "${WORK_DIR}/trig.json" -w '%{http_code}' $CURL_TIMEOUT \
    -X POST -H "$(auth_header)" -H "Content-Type: application/json" \
    -d "$(jq -n --arg id "$art_id" '{artifact_id:$id}')" \
    "${BASE_URL}/api/v1/security/scan") || trig_status="000"
  case "$trig_status" in
    501|503|504) SCANNER_AVAILABLE=false; echo ""; return 0 ;;
    500)
      if grep -qi "scanner.*not.*configured" "${WORK_DIR}/trig.json" 2>/dev/null; then
        SCANNER_AVAILABLE=false; echo ""; return 0
      fi
      ;;
  esac
  # Wait for a COMPLETED scan and return ITS id, not `.items[0].id`.
  #
  # A trigger fans out to every applicable scanner. Some scanners can reach a
  # `failed` terminal state independently of the dedup-bearing scanner (e.g.
  # grype failing on a deploy where its binary/DB is unavailable, while the
  # always-present `dependency` scanner completes and IS deduped). A
  # `failed` row is not deduped, so picking `.items[0]` blindly can return a
  # non-deduped failed row whose id differs between two byte-identical
  # artifacts -- a false "dedup bypassed" failure that depends only on which
  # scanner happens to sort first. We instead key on a completed/clean row,
  # which is the row the dedup short-circuit actually targets. If only
  # non-completed terminal states exist after the timeout, fall back to the
  # first terminal row so the caller still gets a deterministic signal.
  local elapsed=0 final="" any_terminal=""
  while [ "$elapsed" -lt "$SCAN_TIMEOUT" ]; do
    local resp completed_id
    resp=$(api_get "/api/v1/security/artifacts/${art_id}/scans" 2>/dev/null || true)
    # Prefer a completed/clean row (the deduped one). jq: lowercase status.
    completed_id=$(echo "$resp" | jq -r '
      [ .items[]? | select((.status // "" | ascii_downcase) as $s
        | $s == "completed" or $s == "clean") ] | .[0].id // empty' \
      2>/dev/null || echo "")
    if [ -n "$completed_id" ]; then
      final="$completed_id"
      break
    fi
    # Track whether every scanner has reached SOME terminal state, so we can
    # stop waiting (and fall back) instead of spinning the full timeout when
    # no completed row will ever appear (e.g. all scanners failed).
    any_terminal=$(echo "$resp" | jq -r '
      [ .items[]? | select((.status // "" | ascii_downcase) as $s
        | $s == "failed" or $s == "error" or $s == "cancelled" or $s == "timeout") ]
      | (.[0].id // empty)' 2>/dev/null || echo "")
    local pending
    pending=$(echo "$resp" | jq -r '
      [ .items[]? | select((.status // "" | ascii_downcase) as $s
        | ($s == "pending" or $s == "running" or $s == "queued")) ] | length' \
      2>/dev/null || echo "0")
    if [ -n "$any_terminal" ] && [ "${pending:-0}" = "0" ]; then
      # No completed row and nothing still pending: fall back to a terminal
      # (failed/error/...) row id so the caller isn't left empty-handed.
      final="$any_terminal"
      break
    fi
    sleep 5
    elapsed=$(( elapsed + 5 ))
  done
  echo "$final"
}

begin_test "Build deterministic fixture"
mkdir -p "${WORK_DIR}/pkg"
cat > "${WORK_DIR}/pkg/package.json" <<'EOF'
{"name":"dedup-fixture","version":"1.0.0","dependencies":{"lodash":"4.17.4"}}
EOF
# Use --mtime + --owner/--group to make tarball bytes deterministic across
# runs. These flags are GNU-tar specific; BSD/macOS tar rejects them. The
# dedup contract only needs the SAME bytes uploaded to both paths (which is
# guaranteed because both uploads read the same ${TARBALL_NAME} file), so
# fall back to a plain `tar -czf` when the GNU flags are unavailable. This
# keeps the suite runnable on non-Linux dev machines while still producing
# byte-identical content for the two upload paths.
if tar --sort=name --mtime='2024-01-01 00:00:00 UTC' --owner=0 --group=0 \
    -czf "${WORK_DIR}/${TARBALL_NAME}" -C "${WORK_DIR}" pkg 2>/dev/null \
   || tar -czf "${WORK_DIR}/${TARBALL_NAME}" -C "${WORK_DIR}" pkg 2>/dev/null; then
  pass
else
  fail "could not build deterministic fixture tarball"
fi

begin_test "Create repository"
if create_local_repo "$REPO_KEY" "generic"; then
  pass
else
  fail "could not create repo ${REPO_KEY}"
fi

begin_test "Upload artifact A"
up_a=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X PUT -H "$(auth_header)" -H "Content-Type: application/gzip" \
  --data-binary "@${WORK_DIR}/${TARBALL_NAME}" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/${ARTIFACT_PATH_A}") || up_a="000"
case "$up_a" in
  200|201) pass ;;
  *)       fail "upload A returned HTTP ${up_a}" ;;
esac

begin_test "Resolve artifact_id A"
art_a=$(curl -sf $CURL_TIMEOUT -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/${ARTIFACT_PATH_A}" 2>/dev/null || true)
ARTIFACT_A_ID=$(echo "$art_a" | jq -r '.id // .artifact_id // empty' 2>/dev/null || echo "")
ARTIFACT_A_SHA=$(echo "$art_a" | jq -r '.checksum_sha256 // .sha256 // .checksum // empty' 2>/dev/null || echo "")
if [ -n "$ARTIFACT_A_ID" ]; then
  pass
else
  fail "could not resolve artifact_id A"
fi

begin_test "Scan artifact A to completion"
SCAN_A_ID=""
if [ -z "$ARTIFACT_A_ID" ]; then
  skip "no artifact_id A"
else
  SCAN_A_ID=$(trigger_and_wait "$ARTIFACT_A_ID")
  if ! $SCANNER_AVAILABLE; then
    skip "scanner service not configured; dedup contract cannot be exercised"
  elif [ -n "$SCAN_A_ID" ]; then
    pass
  else
    fail "scan A did not reach terminal state within ${SCAN_TIMEOUT}s"
  fi
fi

begin_test "Upload artifact B (byte-identical bytes, different path)"
up_b=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X PUT -H "$(auth_header)" -H "Content-Type: application/gzip" \
  --data-binary "@${WORK_DIR}/${TARBALL_NAME}" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/${ARTIFACT_PATH_B}") || up_b="000"
case "$up_b" in
  200|201) pass ;;
  *)       fail "upload B returned HTTP ${up_b}" ;;
esac

begin_test "Resolve artifact_id B and assert identical checksum to A"
art_b=$(curl -sf $CURL_TIMEOUT -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/${ARTIFACT_PATH_B}" 2>/dev/null || true)
ARTIFACT_B_ID=$(echo "$art_b" | jq -r '.id // .artifact_id // empty' 2>/dev/null || echo "")
ARTIFACT_B_SHA=$(echo "$art_b" | jq -r '.checksum_sha256 // .sha256 // .checksum // empty' 2>/dev/null || echo "")
if [ -z "$ARTIFACT_B_ID" ]; then
  fail "could not resolve artifact_id B"
elif [ -z "$ARTIFACT_A_SHA" ] || [ -z "$ARTIFACT_B_SHA" ]; then
  # Checksum field name varies across backend versions; if it isn't exposed
  # we cannot validate the precondition, but the dedup test below is still
  # meaningful because the fixture tarball IS byte-identical by construction.
  skip "checksum field not exposed on artifact response; cannot pre-validate identical hash (dedup test below still runs on byte-identical bytes)"
elif [ "$ARTIFACT_A_SHA" = "$ARTIFACT_B_SHA" ]; then
  pass
else
  fail "checksums differ: A=${ARTIFACT_A_SHA} B=${ARTIFACT_B_SHA} (fixture was not deterministic)"
fi

# Load-bearing dedup assertion: byte-identical artifacts get DISTINCT scan ids
# by design. The checksum-dedup path copies A's results into a new row for
# artifact B flagged is_reused=true with source_scan_id pointing at the matching
# A scan. We assert that reuse linkage on B's completed scan row rather than id
# equality.
begin_test "Second scan on identical bytes is flagged reused from one of scan A's scans"
if ! $SCANNER_AVAILABLE; then
  skip "scanner unavailable"
elif [ -z "$ARTIFACT_B_ID" ] || [ -z "$SCAN_A_ID" ]; then
  skip "missing artifact B id or scan A id; cannot assert dedup"
else
  SCAN_B_ID=$(trigger_and_wait "$ARTIFACT_B_ID")
  if [ -z "$SCAN_B_ID" ]; then
    fail "scan B did not reach terminal state within ${SCAN_TIMEOUT}s on identical bytes"
  else
    # Capture the full SET of A's completed/clean scan ids, not just SCAN_A_ID.
    # With several scanners live (dependency, grype, trivy-fs, ...) artifact A
    # has one completed row per scan_type and their completion order is
    # nondeterministic, so SCAN_A_ID (trigger_and_wait's arbitrary .items[0])
    # is only ONE of them. Cross-artifact dedup links PER scan_type -- B's
    # reused dependency scan points at A's dependency scan specifically, which
    # may not be the row SCAN_A_ID happened to capture -- so B's source_scan_id
    # must be checked for membership in A's whole completed-id set, not equality
    # with a single id. See artifact-keeper-test#291.
    a_scans=$(api_get "/api/v1/security/artifacts/${ARTIFACT_A_ID}/scans" 2>/dev/null || true)
    a_completed_ids=$(echo "$a_scans" | jq -c '
      [ .items[]? | select((.status // "" | ascii_downcase) as $s
        | $s == "completed" or $s == "clean") | .id ]' 2>/dev/null || echo "[]")
    # B must have a completed/clean row flagged is_reused=true whose
    # source_scan_id is one of A's completed scan ids.
    b_scans=$(api_get "/api/v1/security/artifacts/${ARTIFACT_B_ID}/scans" 2>/dev/null || true)
    reuse_match=$(echo "$b_scans" | jq -r --argjson aset "$a_completed_ids" '
      [ .items[]?
        | select((.status // "" | ascii_downcase) as $s
                 | $s == "completed" or $s == "clean")
        | select(.is_reused == true)
        | select(.source_scan_id as $ssid | ($aset | index($ssid)) != null) ]
      | length' 2>/dev/null || echo "0")
    if [ "${reuse_match:-0}" -ge 1 ] 2>/dev/null; then
      echo "  scan B id=${SCAN_B_ID} reused from one of A's completed scans (is_reused=true, source_scan_id in ${a_completed_ids})"
      pass
    else
      fail "expected artifact B to have a completed scan flagged is_reused=true whose source_scan_id is one of A's completed scan ids ${a_completed_ids} (dedup did not link back to scan A)" \
        "$(echo "$b_scans" | jq -c '(.items // []) | map({id,scan_type,status,is_reused,source_scan_id})')"
    fi
  fi
fi

# Secondary assertion: the per-artifact scan list for B must contain no
# DUPLICATE completed row for any single scan_type. Guards against a backend
# that returns the right id from the trigger but still writes a second
# scan_results row for the same (artifact, scan_type) pair.
#
# IMPORTANT (#1373 / B13): the dedup contract is "one completed row per
# (artifact, scan_type)", NOT "one completed row total". The orchestrator
# fans a trigger out to every APPLICABLE scanner (dependency, grype, and
# trivy-fs on a generic tarball when Trivy is wired), so a correctly-deduped
# artifact legitimately has one completed row per scanner type -- e.g. 3
# completed rows when 3 scanners apply. Counting all completed rows and
# expecting 1 (the previous assertion) mis-counts a healthy multi-scanner
# deploy as a dedup duplicate. We instead group by scan_type and fail only
# if any scan_type has more than one completed row.
begin_test "Per-artifact scan list for B has no duplicate completed row per scan_type"
if ! $SCANNER_AVAILABLE; then
  skip "scanner unavailable"
elif [ -z "$ARTIFACT_B_ID" ]; then
  skip "no artifact_id B"
else
  resp=$(api_get "/api/v1/security/artifacts/${ARTIFACT_B_ID}/scans" 2>/dev/null || true)
  # Total completed rows (across all scan_types) -- must be >= 1.
  completed_count=$(echo "$resp" | jq -r '
    (.items // []) | map(select(
      .status == "completed" or .status == "clean"
    )) | length' 2>/dev/null || echo "0")
  # Max number of completed rows for any single scan_type -- must be <= 1.
  max_per_type=$(echo "$resp" | jq -r '
    (.items // [])
    | map(select(.status == "completed" or .status == "clean"))
    | group_by(.scan_type)
    | map(length)
    | (max // 0)' 2>/dev/null || echo "0")
  # List any scan_type that has a duplicate, for triage.
  dup_types=$(echo "$resp" | jq -r '
    (.items // [])
    | map(select(.status == "completed" or .status == "clean"))
    | group_by(.scan_type)
    | map(select(length > 1) | .[0].scan_type)
    | join(",")' 2>/dev/null || echo "")
  if [ "$completed_count" = "0" ]; then
    fail "artifact B has no completed scan row (dedup link broken)"
  elif [ "${max_per_type:-0}" -gt 1 ] 2>/dev/null; then
    fail "artifact B has a duplicate completed row for scan_type(s) [${dup_types}]; expected at most 1 per scan_type (dedup wrote a duplicate)" \
      "$(echo "$resp" | jq -c '(.items // []) | map({id,scan_type,status,is_reused,source_scan_id})')"
  else
    pass
  fi
fi

end_suite
