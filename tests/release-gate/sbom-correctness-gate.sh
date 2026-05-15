#!/usr/bin/env bash
# sbom-correctness-gate.sh -- Release-gate primitive for the SBOM correctness
# silent-success class (#870: SBOM endpoint returned 200 with empty/fake data).
#
# Covers artifact-keeper-test issues:
#   - #47 E2E SBOM correctness
#   - #57 Epic: SBOM correctness silent-success gate
#
# Status: ACTIVE.
#
# artifact-keeper#903 (--list-all-pkgs + name normalization, scan_packages
# inventory) merged via PR #1150 on 2026-05-11. With #903 live, this gate
# asserts the full silent-empty bug: lockfile-bearing fixture must produce
# component_count >= 1. The assertion is gated on backend feature detection
# (probe /api/v1/openapi.json for the get_sbom_components path that #903
# introduced) so the gate stays portable across release tags that may lag
# #903 -- pre-#903 deploy targets skip the load-bearing check rather than
# flap, and the skip is surfaced loudly.
#
# Earlier scaffold rationale (now resolved):
#   - Trivy invoked WITHOUT --list-all-pkgs: resolved by #903 (both
#     trivy_fs_scanner.rs and image_scanner.rs now pass the flag).
#   - Component names persisted as "name (target)": resolved by #903's
#     name normalization in convert_trivy_packages.
#   - cve/history probe returning [] silently: replaced upstream by the
#     /api/v1/scans?artifact_id polling shape; we read .component_count
#     directly from the SBOM response, not the probe.
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
# shape. Catches the gross regression where the SBOM endpoint disappears
# or starts returning 5xx. The component_count > 0 assertion below
# catches the actual silent-empty bug (#870) on backends carrying #903.
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
      echo "  component_count=${sbom_component_count} (asserted >= 1 below if #903 detected)"
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
# Component-count assertion.
#
# artifact-keeper#903 (--list-all-pkgs + name normalization, scan_packages
# inventory) merged via PR #1150 on 2026-05-11. Once a backend carrying
# migration 085 (scan_packages table) is deployed, the SBOM endpoint must
# return component_count >= 1 for our lockfile-bearing npm fixture. The
# assertion is gated on backend feature detection (probe the OpenAPI spec
# for the scan_packages-derived response shape) so the gate stays portable
# across release tags that lag #903.
# ---------------------------------------------------------------------------

begin_test "Detect backend support for #903 (scan_packages inventory)"
# Probe approach: inspect the OpenAPI spec for the get_sbom_components
# operation, which #903 introduced alongside the inventory pipeline. The
# spec is served at /api/v1/openapi.json (utoipa). A backend predating
# #903 either lacks the path entirely or exposes only the legacy
# components-from-findings shape. We treat the path presence as the
# feature signal.
HAS_LIST_ALL_PKGS=0
# shellcheck disable=SC2086
spec_status=$(curl -s -o "${WORK_DIR}/openapi.json" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/openapi.json") || spec_status="000"
if [ "$spec_status" = "200" ]; then
  if jq -e '.paths | keys[] | select(test("/sbom/.*/components$"))' \
       < "${WORK_DIR}/openapi.json" >/dev/null 2>&1; then
    HAS_LIST_ALL_PKGS=1
  fi
fi
echo "  HAS_LIST_ALL_PKGS=${HAS_LIST_ALL_PKGS} (openapi status=${spec_status})"
pass

begin_test "SBOM component_count > 0 for lockfile-bearing fixture"
if [ "$HAS_LIST_ALL_PKGS" = "1" ]; then
  component_count=$(jq -r '.component_count // 0' < "${WORK_DIR}/sbom-resp.json")
  if [ "${component_count:-0}" -ge 1 ]; then
    echo "  component_count=${component_count} (>= 1 confirms #903 inventory pipeline live)"
    pass
  else
    # This is exactly the #870 silent-success class: backend advertises
    # the #903 inventory shape but returns 0 components for a lockfile
    # that names lodash. That means either the scan didn't run, the
    # scan_packages table didn't receive rows, or the SBOM service is
    # still reading from scan_findings only.
    body=$(head -c 400 "${WORK_DIR}/sbom-resp.json" 2>/dev/null || true)
    fail "SBOM component_count=${component_count} on lockfile-bearing fixture (#870 silent-empty class)" "$body"
  fi
else
  # Pre-#903 backend (e.g. v1.1.x release-image rebuild against a tag
  # that predates PR #1150). The empty-SBOM symptom is structural on
  # those builds; asserting > 0 would flap. Surface the gap loudly via
  # skip so the gate's scope on this deploy target is honest.
  skip "backend predates artifact-keeper#903 (no get_sbom_components path in OpenAPI spec)"
fi

end_suite
