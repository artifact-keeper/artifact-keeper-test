#!/usr/bin/env bash
# test-scan-dedup-checksum.sh -- Scan reuse via checksum dedup
#
# Covers Epic 2 sub-task 2.4 (artifact-keeper-test#67), the parts the gate
# CAN observe today. The `is_reused` boolean is deferred to v1.2.0
# (artifact-keeper#907); without it, the test focuses on the load-bearing
# storage contract:
#
#   Two uploads of byte-identical artifacts MUST share a single scan_results
#   row. A second upload + scan-trigger MUST NOT add a duplicate
#   completed scan for the same content hash. The find_reusable_scan
#   short-circuit returns the prior scan id, and the per-artifact scan
#   list reflects the SAME id across both artifacts.
#
# What this test does NOT assert (deferred)
#   - is_reused == true on the second scan response (artifact-keeper#907)
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
  local elapsed=0 final="" state=""
  while [ "$elapsed" -lt "$SCAN_TIMEOUT" ]; do
    local resp
    resp=$(api_get "/api/v1/security/artifacts/${art_id}/scans" 2>/dev/null || true)
    state=$(echo "$resp" | jq -r '.items[0].status // "" | ascii_downcase' 2>/dev/null || echo "")
    case "$state" in
      completed|clean|failed|error|cancelled|timeout)
        final=$(echo "$resp" | jq -r '.items[0].id // empty' 2>/dev/null || echo "")
        break
        ;;
    esac
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
# Use --mtime + --owner/--group to make tarball bytes deterministic across runs
# so the content hash is identical between the two upload paths.
if tar --sort=name --mtime='2024-01-01 00:00:00 UTC' --owner=0 --group=0 \
    -czf "${WORK_DIR}/${TARBALL_NAME}" -C "${WORK_DIR}" pkg 2>/dev/null; then
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

# Load-bearing dedup assertion: second scan trigger MUST resolve to the SAME
# scan_id as the first. The find_reusable_scan path short-circuits to the
# prior row instead of creating a new scan_results entry.
begin_test "Second scan on identical bytes returns same scan_id (no duplicate row)"
if ! $SCANNER_AVAILABLE; then
  skip "scanner unavailable"
elif [ -z "$ARTIFACT_B_ID" ] || [ -z "$SCAN_A_ID" ]; then
  skip "missing artifact B id or scan A id; cannot assert dedup"
else
  SCAN_B_ID=$(trigger_and_wait "$ARTIFACT_B_ID")
  if [ -z "$SCAN_B_ID" ]; then
    fail "scan B did not reach terminal state within ${SCAN_TIMEOUT}s on identical bytes"
  elif [ "$SCAN_A_ID" = "$SCAN_B_ID" ]; then
    echo "  reused scan id=${SCAN_A_ID} across artifacts ${ARTIFACT_A_ID} and ${ARTIFACT_B_ID}"
    pass
  else
    fail "dedup bypassed: scan A id=${SCAN_A_ID} but scan B id=${SCAN_B_ID} for byte-identical artifacts (find_reusable_scan did not short-circuit)"
  fi
fi

# Secondary assertion: the per-artifact scan list for B must contain only one
# completed row, not a duplicate. Guards against a backend that returns the
# right id from the trigger but still writes a second scan_results row.
begin_test "Per-artifact scan list for B contains exactly one completed scan"
if ! $SCANNER_AVAILABLE; then
  skip "scanner unavailable"
elif [ -z "$ARTIFACT_B_ID" ]; then
  skip "no artifact_id B"
else
  resp=$(api_get "/api/v1/security/artifacts/${ARTIFACT_B_ID}/scans" 2>/dev/null || true)
  completed_count=$(echo "$resp" | jq -r '
    (.items // []) | map(select(
      .status == "completed" or .status == "clean"
    )) | length' 2>/dev/null || echo "0")
  if [ "$completed_count" = "1" ]; then
    pass
  elif [ "$completed_count" = "0" ]; then
    fail "artifact B has no completed scan row (dedup link broken)"
  else
    fail "artifact B has ${completed_count} completed scan rows; expected 1 (dedup wrote a duplicate)"
  fi
fi

end_suite
