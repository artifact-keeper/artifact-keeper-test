#!/usr/bin/env bash
# test-grype-scanner.sh - Grype vulnerability scanner E2E test
#
# Covers Epic 2 sub-task 2.15 (artifact-keeper-test#67). Grype is bundled
# INTO the backend image (docker/Dockerfile.backend: /usr/local/bin/grype +
# pre-seeded DB at /home/artifact/.cache/grype) so it has no sidecar and
# should always be available. Absence of a scan_type=grype row after a
# trigger is therefore a real failure, not a skip.
#
# Backend integration notes (read while writing this test):
#   - grype_scanner.rs: name()="grype", scan_type()="grype". convert_findings
#     produces RawFinding{cve_id: Some(m.vulnerability.id), source:"grype",
#     affected_component: m.artifact.name, ...}.
#   - is_applicable accepts npm tarballs, pypi wheels, and OCI manifests
#     (when a registry image ref can be reconstructed). We use the generic
#     tarball path -- simplest route to a deterministic CVE.
#   - There is NO GET /api/v1/security/scanners endpoint. "Grype is
#     registered" = a scan_type=grype row appears in GET /security/scans
#     after a trigger.
#   - POST /security/scan has no per-scanner selector; trigger fans out
#     to all applicable scanners. Filter the scans list by scan_type=grype.
#
# Vulnerable fixture: reuses the proven lodash 4.17.4 (CVE-2019-10744)
# pattern from test-scan-completes.sh. Grype's package-lock.json matcher
# detects this deterministically against the seeded DB.

set -euo pipefail
source "$(dirname "$0")/../lib/common.sh"
require_cmd jq

begin_suite "grype-scanner"
auth_admin
setup_workdir

REPO_KEY="test-grype-${RUN_ID}"
ARTIFACT_PATH="grype-fixture-${RUN_ID}.tgz"
EXPECTED_CVE="CVE-2019-10744"
EXPECTED_VULN_VERSION="4.17.4"
SCAN_TIMEOUT="${SCAN_TIMEOUT:-90}"
ARTIFACT_ID=""
SCAN_ID=""

cleanup_repo() {
  # shellcheck disable=SC2086  # CURL_TIMEOUT must word-split per common.sh
  curl -sf $CURL_TIMEOUT -X DELETE -H "$(auth_header)" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}" > /dev/null 2>&1 || true
}
add_exit_handler 'cleanup_repo'

# Vulnerable fixture: tarball with package.json + package-lock.json
# pinning lodash 4.17.4. Grype's lockfile parser matches against seeded DB.

begin_test "Build vulnerable fixture (lodash ${EXPECTED_VULN_VERSION} / ${EXPECTED_CVE})"
mkdir -p "${WORK_DIR}/package"
cat > "${WORK_DIR}/package/package.json" <<EOF
{
  "name": "grype-fixture",
  "version": "1.0.0",
  "dependencies": { "lodash": "${EXPECTED_VULN_VERSION}" }
}
EOF
cat > "${WORK_DIR}/package/package-lock.json" <<EOF
{
  "name": "grype-fixture",
  "version": "1.0.0",
  "lockfileVersion": 2,
  "requires": true,
  "packages": {
    "": { "name": "grype-fixture", "version": "1.0.0",
          "dependencies": { "lodash": "${EXPECTED_VULN_VERSION}" } },
    "node_modules/lodash": {
      "version": "${EXPECTED_VULN_VERSION}",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-${EXPECTED_VULN_VERSION}.tgz",
      "integrity": "sha1-eCA6TRwyLuHBHJgwGu1myF0sR4U="
    }
  },
  "dependencies": {
    "lodash": {
      "version": "${EXPECTED_VULN_VERSION}",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-${EXPECTED_VULN_VERSION}.tgz",
      "integrity": "sha1-eCA6TRwyLuHBHJgwGu1myF0sR4U="
    }
  }
}
EOF
if tar -czf "${WORK_DIR}/fixture.tgz" -C "${WORK_DIR}" package 2>/dev/null; then
  pass
else
  fail "could not build vulnerable fixture tarball"
fi

# Generic-format repo + raw tarball upload, matching the lockfile-walker
# pattern established in test-scan-completes.sh.

begin_test "Create generic local repository"
if create_repo "$REPO_KEY" "generic" "local"; then pass; else fail "could not create generic repository ${REPO_KEY}"; fi

begin_test "Upload vulnerable fixture"
# shellcheck disable=SC2086  # CURL_TIMEOUT must word-split per common.sh
upload_status=$(curl -s -o "${WORK_DIR}/upload.json" -w '%{http_code}' $CURL_TIMEOUT \
  -X PUT -H "$(auth_header)" -H "Content-Type: application/gzip" \
  --data-binary "@${WORK_DIR}/fixture.tgz" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/${ARTIFACT_PATH}") || upload_status=000
if [ "$upload_status" = "200" ] || [ "$upload_status" = "201" ]; then
  pass
else
  fail "fixture upload returned ${upload_status}" "$(head -c 200 "${WORK_DIR}/upload.json")"
fi

# Resolve artifact_id via GET /:key/artifacts/*path (no /metadata suffix);
# fall back to listing the repo if that 404s.

begin_test "Resolve artifact_id"
# shellcheck disable=SC2086  # CURL_TIMEOUT must word-split per common.sh
lookup_status=$(curl -s -o "${WORK_DIR}/art.json" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" -H "Accept: application/json" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/${ARTIFACT_PATH}") || lookup_status=000
if [ "$lookup_status" = "200" ]; then
  ARTIFACT_ID=$(jq -er '.id // .artifact_id // empty' < "${WORK_DIR}/art.json" 2>/dev/null || true)
fi
if [ -z "$ARTIFACT_ID" ]; then
  list_resp=$(api_get "/api/v1/repositories/${REPO_KEY}/artifacts" 2>/dev/null) || true
  ARTIFACT_ID=$(echo "$list_resp" | jq -r --arg p "$ARTIFACT_PATH" '
    (if type == "array" then . elif .items then .items else [] end)
    | map(select(.path == $p or .name == $p)) | .[0].id // empty')
fi
if [ -n "$ARTIFACT_ID" ]; then pass; else fail "could not resolve artifact_id for ${ARTIFACT_PATH}"; fi

# Trigger + poll for the grype-typed scan_result. No scan_type=grype row
# after the timeout is a real failure (grype is bundled in the backend image).

begin_test "Grype scan_result row materializes after trigger (proves grype is registered)"
if [ -z "$ARTIFACT_ID" ]; then
  fail "no artifact_id, cannot trigger scan"
else
  rc=0
  SCAN_ID=$(trigger_and_wait_scan "$ARTIFACT_ID" "$SCAN_TIMEOUT" "grype") || rc=$?
  case "$rc" in
    0)
      final_status=$(api_get "/api/v1/security/scans/${SCAN_ID}" 2>/dev/null | jq -r '.status // empty' 2>/dev/null || echo "")
      if [ "$final_status" = "completed" ]; then
        pass
      else
        fail "grype scan reached terminal state but status=${final_status:-unknown}" "scan_id=${SCAN_ID}"
      fi
      ;;
    2) fail "no scan_type=grype row materialized within ${SCAN_TIMEOUT}s; grype is bundled in the backend image (Dockerfile.backend) so this means the orchestrator did not register GrypeScanner" ;;
    3) fail "grype scan accepted but stuck non-terminal after ${SCAN_TIMEOUT}s (silent-success class)" ;;
    *) fail "scan trigger failed (rc=$rc)" ;;
  esac
fi

# Load-bearing CVE assertion. 0 findings on this fixture = scanner ran
# but did not inspect bytes (#888 silent-success class). Real failure.

begin_test "Grype findings include expected CVE for vulnerable fixture"
if [ -z "$SCAN_ID" ]; then
  skip "no grype scan_id available"
else
  findings_resp=$(api_get "/api/v1/security/scans/${SCAN_ID}/findings?per_page=200" 2>/dev/null) || true
  if [ -z "$findings_resp" ]; then
    fail "GET /scans/${SCAN_ID}/findings returned empty body"
  else
    total=$(echo "$findings_resp" | jq '.total // 0')
    if [ "$total" = "0" ]; then
      fail "grype completed scan but findings_count=0 on known-vulnerable fixture (lodash ${EXPECTED_VULN_VERSION} / ${EXPECTED_CVE}); scanner did not inspect the bytes" \
        "scan_id=${SCAN_ID}"
    else
      has_cve=$(echo "$findings_resp" | jq -r --arg c "$EXPECTED_CVE" '[.items[] | select((.cve_id // "") == $c)] | length' 2>/dev/null || echo "0")
      if [ "${has_cve:-0}" -ge 1 ]; then
        pass
      else
        # Capture what we DID find for triage. Don't accept "any CVE" --
        # the fixture is deterministic and any drift means the seeded DB
        # is stale or the matcher regressed.
        seen=$(echo "$findings_resp" | jq -r '[.items[].cve_id] | unique | join(",")')
        fail "grype findings present but ${EXPECTED_CVE} not among them; saw cve_ids=[${seen}]"
      fi
    fi
  fi
fi

# Source/cve_id shape per grype_scanner.rs:208 (cve_id=Some(id),
# source="grype"). Empty source = convert_findings attribution regression
# (would merge grype results into trivy's UI bucket).

begin_test "Grype findings carry source=\"grype\" and cve_id"
if [ -z "$SCAN_ID" ]; then
  skip "no grype scan_id available"
else
  findings_resp=$(api_get "/api/v1/security/scans/${SCAN_ID}/findings?per_page=200" 2>/dev/null) || true
  count=$(echo "$findings_resp" | jq '.items | length // 0')
  if [ "$count" = "0" ]; then
    skip "no findings to shape-check (covered by CVE assertion above)"
  else
    bad_source=$(echo "$findings_resp" | jq -r '[.items[] | select(.source != "grype")] | length')
    no_cve=$(echo "$findings_resp" | jq -r '[.items[] | select((.cve_id // "") == "")] | length')
    if [ "$bad_source" != "0" ]; then
      fail "${bad_source} finding(s) have source != \"grype\" on a scan_type=grype row (convert_findings source-attribution broken)"
    elif [ "$no_cve" != "0" ]; then
      fail "${no_cve} finding(s) on a grype scan have empty cve_id (grype_scanner.rs:208 always sets Some(m.vulnerability.id); empty means the convert path was bypassed)"
    else
      pass
    fi
  fi
fi

# scanner_version should be "grype-X.Y.Z" from format_grype_version in
# scanner_service.rs (cached CLI probe).

begin_test "Grype scan row reports scanner_version"
if [ -z "$SCAN_ID" ]; then
  skip "no grype scan_id available"
else
  scan_resp=$(api_get "/api/v1/security/scans/${SCAN_ID}" 2>/dev/null) || true
  ver=$(echo "$scan_resp" | jq -r '.scanner_version // empty')
  if [ -z "$ver" ]; then
    skip "scan completed but scanner_version is null (CLI version probe returned None; not a finding-correctness issue)"
  elif [[ "$ver" == *grype* ]]; then
    pass
  else
    fail "scanner_version='${ver}' does not contain 'grype'; format_grype_version regression?"
  fi
fi

end_suite
