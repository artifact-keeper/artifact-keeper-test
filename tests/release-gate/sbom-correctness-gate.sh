#!/usr/bin/env bash
# sbom-correctness-gate.sh -- Release-gate primitive for the SBOM correctness
# silent-success class (#870: SBOM endpoint returned 200 with empty/fake data).
#
# Covers artifact-keeper-test issues:
#   - #47 E2E SBOM correctness
#   - #57 Epic: SBOM correctness silent-success gate
#
# Status: SCAFFOLD.
#
# Per artifact-keeper-test#57, PR #51's review surfaced architectural
# blockers that this gate cannot resolve without a backend change:
#
#   1. Trivy is invoked WITHOUT --list-all-pkgs (artifact-keeper#903).
#      Without that flag, scan_findings only stores CVE-bearing rows,
#      so SBOMs derived from scan_findings are "CVEs in deps" rather
#      than "deps". The empty-SBOM symptom is structural, not a bug
#      we can assert around.
#   2. Component names are persisted as "name (target)" (e.g.
#      "body-parser (package-lock.json)"), so substring-matching on
#      known component names needs care.
#   3. The cve/history endpoint previously used as a "scan complete"
#      probe returns [] for any unknown artifact and was a silent
#      no-op (#57 round-2 finding).
#
# The full gate per #57 requires:
#   - Backend: artifact-keeper#903 (--list-all-pkgs + name normalization)
#   - Test: enable scan_on_upload BEFORE the upload
#   - Test: poll via GET /api/v1/scans?artifact_id=... not cve/history
#   - Test: force_regenerate=true on every poll iteration
#   - Test: negative-control fixture (garbage tarball -> component_count == 0)
#   - Test: Trivy DB version pinning
#   - Workflow: scanner pod log capture on failure
#   - Meta-test: paired pass/fail evidence
#
# Until #903 ships, this scaffold runs the *contract pin* portion: it
# asserts the endpoints exist and respond with the right shape, but
# it does NOT yet assert on component count. That keeps the gate
# present in CI (so a 404 on /api/v1/sbom would fail the gate loud)
# without falsely passing on the actual silent-empty bug.
#
# Environment:
#   BASE_URL    backend URL
#   ADMIN_PASS  admin password
#   RUN_ID      resource-name suffix

# shellcheck source=../lib/common.sh disable=SC1091
source "$(dirname "$0")/../lib/common.sh"

begin_suite "sbom-correctness-gate"
auth_admin
setup_workdir

REPO_KEY="sbom-gate-${RUN_ID}"
PACKAGE_NAME="sbom-fixture"
PACKAGE_VERSION="1.0.0"
TARBALL_NAME="${PACKAGE_NAME}-${PACKAGE_VERSION}.tgz"
ARTIFACT_PATH="${PACKAGE_NAME}/${PACKAGE_VERSION}/${TARBALL_NAME}"

cleanup_sbom() {
  # shellcheck disable=SC2086  # CURL_TIMEOUT must word-split
  curl -sf $CURL_TIMEOUT -X DELETE -H "$(auth_header)" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}" >/dev/null 2>&1 || true
  [ -n "${WORK_DIR:-}" ] && rm -rf "$WORK_DIR" 2>/dev/null || true
}
trap cleanup_sbom EXIT

# ---------------------------------------------------------------------------
# Build a minimal npm-shaped fixture so the artifact has an SBOM-extractable
# manifest. Same lockfile shape as test-scan-completes.sh because the SBOM
# pipeline currently derives components from scan_findings (until #903).
# ---------------------------------------------------------------------------

begin_test "Build SBOM fixture"
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
    "node_modules/lodash": { "version": "4.17.4" }
  }
}
EOF
if tar -czf "${WORK_DIR}/${TARBALL_NAME}" -C "${WORK_DIR}" package 2>/dev/null; then
  pass
else
  fail "could not build SBOM fixture tarball"
fi

# ---------------------------------------------------------------------------
# Create repo + upload fixture.
# ---------------------------------------------------------------------------

begin_test "Create generic local repository"
if create_local_repo "$REPO_KEY" "generic"; then
  pass
else
  fail "could not create generic repository ${REPO_KEY}"
fi

begin_test "Upload SBOM fixture"
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
# shellcheck disable=SC2086
list_status=$(curl -s -o "${WORK_DIR}/list-resp.json" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts") || list_status="000"
ARTIFACT_ID=""
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
# Contract pin: POST /api/v1/sbom must return 200 with a SbomResponse
# shape. This is the minimum pin until #903 lands. It catches the gross
# regression where the SBOM endpoint disappears or starts returning 5xx,
# but it does NOT yet catch the silent-empty bug (#870) -- that requires
# #903 + the scaffold-completion sub-tasks in #57.
# ---------------------------------------------------------------------------

begin_test "POST /api/v1/sbom returns 200 with SBOM response shape"
sbom_payload=$(jq -n --arg id "$ARTIFACT_ID" \
  '{artifact_id: $id, format: "cyclonedx", force_regenerate: true}')
# shellcheck disable=SC2086
sbom_status=$(curl -s -o "${WORK_DIR}/sbom-resp.json" -w '%{http_code}' $CURL_TIMEOUT \
  -X POST \
  -H "$(auth_header)" \
  -H "Content-Type: application/json" \
  -d "$sbom_payload" \
  "${BASE_URL}/api/v1/sbom") || sbom_status="000"

case "$sbom_status" in
  200)
    # Confirm response shape. SbomResponse fields per
    # backend/src/api/handlers/sbom.rs:91-107
    if jq -e '
          (.id | type) == "string"
          and (.artifact_id | type) == "string"
          and (.format | type) == "string"
          and (.component_count | type) == "number"
          and (.dependency_count | type) == "number"
        ' < "${WORK_DIR}/sbom-resp.json" >/dev/null 2>&1; then
      sbom_component_count=$(jq -r '.component_count' < "${WORK_DIR}/sbom-resp.json")
      echo "  component_count=${sbom_component_count} (NOT asserted >0 until artifact-keeper#903)"
      pass
    else
      body=$(head -c 400 "${WORK_DIR}/sbom-resp.json" 2>/dev/null || true)
      fail "SBOM response shape mismatch" "$body"
    fi
    ;;
  404)
    fail "POST /api/v1/sbom returned 404 (endpoint missing in this backend version)"
    ;;
  503|504)
    # Scanner-pod unavailability classifies the SAME as scan-completion-gate.sh:
    # release-gate context must fail loud. The silent-success class this gate
    # exists to catch is exactly "report success when scanner could not run".
    fail "POST /api/v1/sbom returned ${sbom_status}; scanner pod unavailable, release-gate must fail loud (#870 class)"
    ;;
  *)
    body=$(head -c 400 "${WORK_DIR}/sbom-resp.json" 2>/dev/null || true)
    fail "POST /api/v1/sbom returned HTTP ${sbom_status}" "$body"
    ;;
esac

# ---------------------------------------------------------------------------
# Component-count assertion (scaffold).
# Per #57, this must NOT be wired up until artifact-keeper#903 ships
# (--list-all-pkgs + name normalization). Without #903, the SBOM is
# legitimately empty for non-CVE deps and an assertion here would
# flap or, worse, drive contributors to add `|| true` workarounds
# that mask the real bug.
# ---------------------------------------------------------------------------

begin_test "SBOM component_count > 0 (deferred to artifact-keeper#903)"
# TODO(artifact-keeper-test#57, artifact-keeper#903): once --list-all-pkgs
# is enabled and names are normalized, replace the skip with:
#   component_count=$(jq -r '.component_count' < "${WORK_DIR}/sbom-resp.json")
#   if [ "$component_count" -gt 0 ]; then pass; else fail "..."; fi
skip "deferred to artifact-keeper#903 (--list-all-pkgs + name normalization)"

end_suite
