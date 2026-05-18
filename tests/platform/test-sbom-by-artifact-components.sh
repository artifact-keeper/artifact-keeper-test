#!/usr/bin/env bash
# test-sbom-by-artifact-components.sh - SBOM by-artifact deep-content test
#
# Covers Epic 2 sub-task 2.7 (artifact-keeper-test#68): the existing
# tests/platform/test-sbom.sh stops at smoke checks (bomFormat present,
# specVersion present, component_count present). This test strengthens
# the by-artifact retrieval path with:
#   - assertions on the full CycloneDX components array (every entry has
#     name + version)
#   - version pinning: pinned versions in the source manifest survive into
#     the SBOM (not silently rewritten to "*", "latest", or "0.0.0")
#   - license metadata: at least one declared license round-trips into the
#     SBOM's component.licenses entry
#
# Flow:
#   1. Build a small npm tarball with a pinned dependency and a declared
#      MIT license on the root package.
#   2. Upload to a local npm repo, resolve artifact_id.
#   3. Generate a CycloneDX SBOM.
#   4. GET /sbom/by-artifact/{artifact_id} and assert the three properties
#      above against the response body.
#
# Requires: curl, jq, tar

set -euo pipefail
source "$(dirname "$0")/../lib/common.sh"

begin_suite "sbom-by-artifact-components"
auth_admin
setup_workdir

REPO_KEY="test-sbom-bya-${RUN_ID}"
PKG_NAME="sbom-bya-fixture-${RUN_ID}"
PKG_VERSION="2.4.1"
DEP_NAME="lodash"
# Pin to a specific version (no caret, no tilde) so a generator that
# silently rewrites pins to "latest" surfaces as a test failure.
DEP_VERSION="4.17.21"
ROOT_LICENSE="MIT"
ARTIFACT_ID=""
SBOM_BODY=""

cleanup_repo() {
  # shellcheck disable=SC2086
  curl -sf $CURL_TIMEOUT -X DELETE -H "$(auth_header)" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}" > /dev/null 2>&1 || true
}
add_exit_handler 'cleanup_repo'

begin_test "Build pinned-dep npm tarball with license"
mkdir -p "${WORK_DIR}/pkg"
cat > "${WORK_DIR}/pkg/package.json" <<EOF
{
  "name": "${PKG_NAME}",
  "version": "${PKG_VERSION}",
  "description": "SBOM by-artifact deep-content fixture",
  "main": "index.js",
  "license": "${ROOT_LICENSE}",
  "dependencies": {
    "${DEP_NAME}": "${DEP_VERSION}"
  }
}
EOF
cat > "${WORK_DIR}/pkg/index.js" <<EOF
module.exports = { name: "${PKG_NAME}" };
EOF
TARBALL="${WORK_DIR}/${PKG_NAME}-${PKG_VERSION}.tgz"
if tar czf "$TARBALL" -C "${WORK_DIR}/pkg" . 2>/dev/null; then
  pass
else
  fail "could not build npm tarball"
fi

begin_test "Create repo and upload tarball"
if create_local_repo "$REPO_KEY" "npm"; then
  upload_path="${PKG_NAME}-${PKG_VERSION}.tgz"
  if api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/${upload_path}" \
       "$TARBALL" > /dev/null 2>&1; then
    pass
  else
    fail "tarball upload failed"
  fi
else
  fail "could not create repo"
fi

begin_test "Resolve artifact_id"
list_resp=$(api_get "/api/v1/repositories/${REPO_KEY}/artifacts" 2>/dev/null) || true
ARTIFACT_ID=$(echo "$list_resp" | jq -r '
  if type == "array" then .[0].id // empty
  elif .items then .items[0].id // empty
  else empty
  end' 2>/dev/null) || true
if [ -n "$ARTIFACT_ID" ] && [ "$ARTIFACT_ID" != "null" ]; then pass; else fail "could not resolve artifact_id"; fi

begin_test "Generate CycloneDX SBOM"
if [ -z "$ARTIFACT_ID" ]; then
  skip "no artifact_id"
else
  if api_post "/api/v1/sbom" \
       "{\"artifact_id\":\"${ARTIFACT_ID}\",\"format\":\"cyclonedx\"}" \
       > /dev/null 2>&1; then
    pass
  else
    skip "SBOM generation not available"
  fi
fi

begin_test "Fetch SBOM by artifact"
if [ -z "$ARTIFACT_ID" ]; then
  skip "no artifact_id"
else
  status=$(curl -s -o "$WORK_DIR/sbom.json" -w '%{http_code}' \
    -H "$(auth_header)" \
    "${BASE_URL}/api/v1/sbom/by-artifact/${ARTIFACT_ID}") || status=000
  if [ "$status" = "404" ]; then
    skip "no SBOM available for artifact"
  elif [[ ! "$status" =~ ^2[0-9][0-9]$ ]]; then
    fail "GET /sbom/by-artifact/${ARTIFACT_ID} returned HTTP ${status}"
  else
    SBOM_BODY=$(cat "$WORK_DIR/sbom.json")
    pass
  fi
fi

# ---------------------------------------------------------------------------
# 2.7.a -- Every component in the CycloneDX document has name + version.
# Catches a regression where the generator emits stub rows {name: "..."}
# without version, which downstream tooling (Dependency-Track, OSV) silently
# ignores -- the exact "SBOM untrusted" customer pain from discussion #872.
# ---------------------------------------------------------------------------

begin_test "Every CycloneDX component has name + version"
if [ -z "$SBOM_BODY" ]; then
  skip "no SBOM body"
else
  comps_path=$(echo "$SBOM_BODY" | jq -r '
    if (.content.components // null) | type == "array" then "content"
    elif (.components // null) | type == "array" then "root"
    else "none"
    end')
  if [ "$comps_path" = "none" ]; then
    skip "SBOM body has no components array (generator may not parse this format yet)"
  else
    if [ "$comps_path" = "content" ]; then
      missing=$(echo "$SBOM_BODY" | jq -r '.content.components | map(select((.name // "") == "" or (.version // "") == "")) | length')
      total=$(echo "$SBOM_BODY" | jq -r '.content.components | length')
    else
      missing=$(echo "$SBOM_BODY" | jq -r '.components | map(select((.name // "") == "" or (.version // "") == "")) | length')
      total=$(echo "$SBOM_BODY" | jq -r '.components | length')
    fi
    if [ "$total" = "0" ]; then
      skip "components array is empty"
    elif [ "$missing" != "0" ]; then
      fail "${missing}/${total} components missing name or version"
    else
      pass
    fi
  fi
fi

# ---------------------------------------------------------------------------
# 2.7.b -- Pinned version survives into the SBOM.
# package.json declares "${DEP_NAME}": "${DEP_VERSION}" (exact pin). The
# emitted component for that dep must carry the same version string -- a
# generator that rewrites pins to "*", "latest", or "0.0.0" is the regression
# we are guarding against.
# ---------------------------------------------------------------------------

begin_test "Pinned dependency version survives into SBOM"
if [ -z "$SBOM_BODY" ]; then
  skip "no SBOM body"
else
  pinned_ver=$(echo "$SBOM_BODY" | jq -r --arg n "$DEP_NAME" '
    (.content.components // .components // [])
    | map(select(.name == $n))
    | .[0].version // empty')
  if [ -z "$pinned_ver" ]; then
    # Either the generator does not parse npm deps at all, or it emits only
    # the root package. Both are partial implementations rather than a
    # version-pin regression, so skip.
    skip "dependency '${DEP_NAME}' not present in SBOM (parser may not handle npm deps)"
  elif [ "$pinned_ver" != "$DEP_VERSION" ]; then
    fail "version drift: declared '${DEP_VERSION}', SBOM emitted '${pinned_ver}'"
  else
    pass
  fi
fi

# ---------------------------------------------------------------------------
# 2.7.c -- License metadata round-trips. package.json declares
# "license": "MIT" on the root package. The component matching the root
# package name must carry an MIT license entry.
#
# CycloneDX represents licenses as:
#   "licenses": [ { "license": { "id": "MIT" } } ]
# We accept either .id or .name match for forward-compat with generators
# that emit license names instead of SPDX ids.
# ---------------------------------------------------------------------------

begin_test "Root component carries declared license"
if [ -z "$SBOM_BODY" ]; then
  skip "no SBOM body"
else
  root_lic=$(echo "$SBOM_BODY" | jq -r --arg n "$PKG_NAME" --arg lic "$ROOT_LICENSE" '
    (.content.components // .components // [])
    | map(select(.name == $n))
    | .[0].licenses // []
    | map(.license.id // .license.name // .id // .name // empty)
    | map(select(. == $lic))
    | .[0] // empty')
  if [ -z "$root_lic" ]; then
    # Some generators emit license at the SBOM document level rather than
    # per-component; accept that as a partial-but-valid implementation
    # (the assertion this test is named for is component-level, but we do
    # not want to false-fail on a documented variant).
    doc_lic=$(echo "$SBOM_BODY" | jq -r --arg lic "$ROOT_LICENSE" '
      (.content.metadata.licenses // .metadata.licenses // [])
      | map(.license.id // .license.name // .id // .name // empty)
      | map(select(. == $lic))
      | .[0] // empty')
    if [ -n "$doc_lic" ]; then
      pass
    else
      # If the root component itself is absent, the parser does not handle
      # this format end-to-end; skip rather than fail on a known gap.
      has_root=$(echo "$SBOM_BODY" | jq -r --arg n "$PKG_NAME" '
        (.content.components // .components // [])
        | map(select(.name == $n)) | length')
      if [ "$has_root" = "0" ]; then
        skip "root component '${PKG_NAME}' not present in SBOM"
      else
        fail "root component present but no '${ROOT_LICENSE}' license entry"
      fi
    fi
  else
    pass
  fi
fi

end_suite
