#!/usr/bin/env bash
# test-sbom-components-populated.sh -- SBOM components must be populated
# for artifacts uploaded via native package-manager protocols.
#
# Tracks artifact-keeper#870 (deferred to v1.2.1):
#   spawn_scan_on_upload is currently only wired to the incus handler, so
#   uploads coming in through the native protocol endpoints (npm publish,
#   maven jar PUT, pypi /simple, cargo crate, etc.) never trigger a scan.
#   With no scan_packages rows for the artifact,
#   extract_dependencies_for_artifact (handlers/sbom.rs:1247) returns an
#   empty list, so the SBOM document the customer fetches has
#   `content.components = []` even when the upload contained a real
#   lockfile / manifest.
#
# Documented workaround until v1.2.1: enable `scan_on_upload` on the repo
# (or POST /api/v1/security/scan per artifact). This test does NEITHER of
# those things by design: the customer-observable behaviour is that they
# uploaded with no extra config and then asked for the SBOM. If the
# SBOM the platform hands back is empty, that is the silent-success
# regression we want to catch.
#
# Load-bearing observable
# -----------------------
# After a native NPM publish (PUT /npm/{repo}/{pkg} with the _attachments
# JSON the npm client sends) of a tarball containing a known
# package-lock.json (lodash 4.17.21), the SBOM for the resulting artifact
# must list at least one component. The CycloneDX document is fetched via
# either of:
#   GET  /api/v1/sbom/by-artifact/{artifact_id}    (preferred; populated
#                                                   only after the
#                                                   bug is fixed)
#   POST /api/v1/sbom {artifact_id, format}        (forces a generate
#                                                   pass; still reads
#                                                   from scan_packages,
#                                                   so empty until #870
#                                                   ships)
# and `content.components | length` must be >= 1.
#
# Expected gate state (until v1.2.1 lands)
# ----------------------------------------
# The assertion FAILS today: components is `[]`. Because this is a known
# deferred capability (auto-scan-on-native-upload not shipped), the test
# calls `skip_suite` with a reason that matches the documented capability
# exemption in tests/lib/common.sh::_CAPABILITY_EXEMPTIONS. Under
# RELEASE_GATE=1 that produces an EXEMPT row in the gate log instead of
# a hard FAIL. When v1.2.1 ships the spawn_scan_on_upload fix, the
# components array becomes non-empty, the assertion PASSES, and the
# exemption is no longer exercised -- at which point the row in the
# allowlist can be removed.
#
# Self-test mode (EXPECT_FAILURE=1):
#   Inverts the final exit code (end_suite handles this centrally).
#
# Requires: curl, jq, tar, base64

set -euo pipefail
source "$(dirname "$0")/../lib/common.sh"

begin_suite "sbom-components-populated-870"
auth_admin
setup_workdir

REPO_KEY="sbom-native-${RUN_ID}"
PKG_NAME="sbom-native-fixture"
PKG_VERSION="1.0.0"
TARBALL_FILE="${WORK_DIR}/${PKG_NAME}-${PKG_VERSION}.tgz"
ARTIFACT_PATH="${PKG_NAME}/-/${PKG_NAME}-${PKG_VERSION}.tgz"
# How long we let the platform sit between upload and SBOM fetch. The
# test ASSUMES the auto-scan listener is broken (per #870), so this is
# just enough headroom for any scan that DOES exist to land. When the
# fix ships, the scan completes well inside this window on a healthy
# stack.
AUTO_SCAN_WAIT="${AUTO_SCAN_WAIT:-45}"

ARTIFACT_ID=""

cleanup_repo() {
  # shellcheck disable=SC2086
  curl -sf $CURL_TIMEOUT -X DELETE -H "$(auth_header)" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}" > /dev/null 2>&1 || true
}
add_exit_handler 'cleanup_repo'

# ---------------------------------------------------------------------------
# Build fixture: a minimal npm-style tarball containing a package-lock.json
# that names a known dependency (lodash). A scanner that walks the lockfile
# (Trivy fs, Grype source) MUST emit at least one scan_packages row, which
# is what populates components on the SBOM read path.
# ---------------------------------------------------------------------------

begin_test "Build npm-style fixture tarball"
mkdir -p "${WORK_DIR}/publish-pkg"
cat > "${WORK_DIR}/publish-pkg/package.json" <<EOF
{
  "name": "${PKG_NAME}",
  "version": "${PKG_VERSION}",
  "license": "MIT",
  "description": "Fixture for #870 SBOM-components-populated gate test",
  "dependencies": { "lodash": "4.17.21" }
}
EOF
cat > "${WORK_DIR}/publish-pkg/package-lock.json" <<EOF
{
  "name": "${PKG_NAME}",
  "version": "${PKG_VERSION}",
  "lockfileVersion": 2,
  "requires": true,
  "packages": {
    "": {
      "name": "${PKG_NAME}",
      "version": "${PKG_VERSION}",
      "dependencies": { "lodash": "4.17.21" }
    },
    "node_modules/lodash": {
      "version": "4.17.21",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
      "integrity": "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg==",
      "license": "MIT"
    }
  }
}
EOF
if tar -czf "${TARBALL_FILE}" -C "${WORK_DIR}/publish-pkg" . 2>/dev/null; then
  pass
else
  fail "could not build fixture tarball"
  end_suite
  exit 1
fi

# ---------------------------------------------------------------------------
# Create a hosted npm repo. NPM is the native protocol we hit; per #870
# the same bug exists for maven jar, pypi wheel, cargo crate, etc., but a
# single representative format is enough to pin the regression.
# ---------------------------------------------------------------------------

begin_test "Create hosted npm repository"
if create_local_repo "$REPO_KEY" "npm"; then
  pass
else
  fail "could not create npm repo ${REPO_KEY}"
  end_suite
  exit 1
fi

# ---------------------------------------------------------------------------
# Native npm publish via the JSON _attachments payload (what `npm publish`
# sends to the registry). This goes through the npm format handler, which
# is exactly where spawn_scan_on_upload is NOT wired today.
# ---------------------------------------------------------------------------

begin_test "Native npm publish (PUT /npm/{repo}/{pkg})"
TARBALL_B64=$(base64 < "${TARBALL_FILE}" | tr -d '\n')
TARBALL_SIZE=$(wc -c < "${TARBALL_FILE}" | tr -d ' ')
NPM_REGISTRY="${BASE_URL}/npm/${REPO_KEY}/"

PUBLISH_PAYLOAD=$(cat <<EOJSON
{
  "name": "${PKG_NAME}",
  "description": "Fixture for #870 SBOM-components-populated gate test",
  "versions": {
    "${PKG_VERSION}": {
      "name": "${PKG_NAME}",
      "version": "${PKG_VERSION}",
      "description": "Fixture for #870 SBOM-components-populated gate test",
      "license": "MIT",
      "dist": {
        "tarball": "${NPM_REGISTRY}${PKG_NAME}/-/${PKG_NAME}-${PKG_VERSION}.tgz"
      }
    }
  },
  "_attachments": {
    "${PKG_NAME}-${PKG_VERSION}.tgz": {
      "content_type": "application/octet-stream",
      "data": "${TARBALL_B64}",
      "length": ${TARBALL_SIZE}
    }
  }
}
EOJSON
)

publish_status=$(curl -s -o "${WORK_DIR}/publish.json" -w '%{http_code}' $CURL_TIMEOUT \
  -X PUT \
  -H "$(format_auth_header)" \
  -H "Content-Type: application/json" \
  -d "$PUBLISH_PAYLOAD" \
  "${NPM_REGISTRY}${PKG_NAME}") || publish_status="000"

case "$publish_status" in
  200|201) pass ;;
  *)
    fail "npm publish returned HTTP ${publish_status}" \
         "$(head -c 400 "${WORK_DIR}/publish.json" 2>/dev/null || true)"
    end_suite
    exit 1
    ;;
esac

# ---------------------------------------------------------------------------
# Resolve artifact_id from the management API. The native publish creates
# the artifact row but does not echo the UUID, so we list and match by
# package path.
# ---------------------------------------------------------------------------

begin_test "Resolve artifact_id for uploaded tarball"
# Give the artifact row a beat to land before we query.
sleep 2
list_resp=$(api_get "/api/v1/repositories/${REPO_KEY}/artifacts" 2>/dev/null || true)
if [ -n "$list_resp" ]; then
  # Native NPM stores artifacts at paths like `{pkg}/-/{pkg}-{ver}.tgz`;
  # match by either path suffix or by name containing the package name
  # so we tolerate small layout differences across backend revisions.
  ARTIFACT_ID=$(echo "$list_resp" | jq -r --arg p "$ARTIFACT_PATH" --arg n "$PKG_NAME" '
    (if type == "array" then . elif .items then .items else [] end)
    | map(select(
        ((.path // "") | tostring | endswith($p)) or
        ((.name // "") | tostring | contains($n))
      ))
    | .[0].id // empty')
fi
if [ -n "$ARTIFACT_ID" ]; then
  pass
else
  fail "could not resolve artifact_id for ${ARTIFACT_PATH}" \
       "list_resp head: $(echo "$list_resp" | head -c 400)"
  end_suite
  exit 1
fi

# ---------------------------------------------------------------------------
# Give the platform a window for any auto-scan that does fire to land.
# Per #870 we expect none, but we explicitly wait so the assertion below
# is not racing a scan that simply hadn't started yet on a healthy stack.
# ---------------------------------------------------------------------------

begin_test "Wait ${AUTO_SCAN_WAIT}s for any post-upload auto-scan"
elapsed=0
scan_count=0
while [ "$elapsed" -lt "$AUTO_SCAN_WAIT" ]; do
  scan_resp=$(api_get "/api/v1/security/artifacts/${ARTIFACT_ID}/scans" 2>/dev/null || true)
  if [ -n "$scan_resp" ]; then
    scan_count=$(echo "$scan_resp" | jq -r '
      (if type == "array" then . elif .items then .items else [] end) | length' \
      2>/dev/null || echo 0)
    if [ "$scan_count" -gt 0 ]; then
      break
    fi
  fi
  sleep 5
  elapsed=$(( elapsed + 5 ))
done
echo "  observed ${scan_count} scan row(s) for artifact ${ARTIFACT_ID} after ${elapsed}s"
pass

# ---------------------------------------------------------------------------
# Load-bearing assertion: the SBOM for this artifact lists at least one
# component. Try GET /sbom/by-artifact first (the customer-facing read
# path). If the backend reports no SBOM yet, force-generate one via
# POST /sbom; either way the document the customer ends up with must
# have content.components non-empty for the native-protocol upload to
# be considered correct.
# ---------------------------------------------------------------------------

begin_test "SBOM components are populated for native-protocol upload"
sbom_status=$(curl -s -o "${WORK_DIR}/sbom.json" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/sbom/by-artifact/${ARTIFACT_ID}") || sbom_status="000"

if [ "$sbom_status" = "404" ]; then
  # No SBOM materialised on its own (#870: scan never ran -> no
  # downstream SBOM either). Force-generate one so we can still assert
  # the read-path shape. The generate path also reads from
  # scan_packages, so this stays empty until the fix ships.
  gen_payload=$(jq -n --arg id "$ARTIFACT_ID" '{artifact_id: $id, format: "cyclonedx"}')
  gen_status=$(curl -s -o "${WORK_DIR}/sbom.json" -w '%{http_code}' $CURL_TIMEOUT \
    -X POST -H "$(auth_header)" -H "Content-Type: application/json" \
    -d "$gen_payload" \
    "${BASE_URL}/api/v1/sbom") || gen_status="000"
  sbom_status="$gen_status"
fi

case "$sbom_status" in
  200)
    # CycloneDX shape: top-level "components" lives under content.
    # Tolerate both flattened ("components") and nested ("content.components")
    # response shapes since the convert/generate path serialises
    # SbomContentResponse with serde flatten on metadata + a raw content blob.
    components_len=$(jq -r '
      ((.content.components // .components // []) | length)
    ' "${WORK_DIR}/sbom.json" 2>/dev/null || echo 0)

    if [ -z "$components_len" ] || ! [[ "$components_len" =~ ^[0-9]+$ ]]; then
      fail "could not parse components array from SBOM response" \
           "$(head -c 400 "${WORK_DIR}/sbom.json")"
    elif [ "$components_len" -ge 1 ]; then
      echo "  components_len=${components_len} (>= 1, assertion green)"
      pass
    else
      # The #870 silent-success case: SBOM returned 200 with components: [].
      # Hand off to skip_suite with the documented exemption reason so
      # the release-gate logs an EXEMPT row instead of a hard fail.
      # When #870 lands in v1.2.1 this branch stops firing and the
      # exemption row in common.sh can be deleted.
      skip_suite "native-protocol upload did not trigger scan; SBOM components empty (deferred to v1.2.1 per #870; spawn_scan_on_upload only wired to incus handler)"
    fi
    ;;
  404)
    fail "no SBOM available for artifact ${ARTIFACT_ID} after generate attempt" \
         "$(head -c 400 "${WORK_DIR}/sbom.json")"
    ;;
  501|503)
    # SBOM subsystem genuinely not shipped on this backend -> not a
    # #870 signal; fall through to skip_suite (which under RELEASE_GATE=1
    # still hard-fails because this reason does NOT match the #870
    # exemption substring).
    skip_suite "SBOM endpoints not available on this backend (HTTP ${sbom_status})"
    ;;
  *)
    fail "GET /sbom/by-artifact/${ARTIFACT_ID} returned HTTP ${sbom_status}" \
         "$(head -c 400 "${WORK_DIR}/sbom.json")"
    ;;
esac

end_suite
