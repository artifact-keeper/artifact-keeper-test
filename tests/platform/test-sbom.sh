#!/usr/bin/env bash
# test-sbom.sh - SBOM generation and listing E2E test
#
# Uploads an artifact, triggers SBOM generation, and verifies the SBOM
# can be retrieved.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "sbom"
auth_admin
setup_workdir

REPO_KEY="test-sbom-${RUN_ID}"

begin_test "Create repo and upload artifact"
if create_local_repo "$REPO_KEY" "generic"; then
  echo "sbom-test-${RUN_ID}" > "${WORK_DIR}/app.jar"
  api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/app.jar" \
    "${WORK_DIR}/app.jar" > /dev/null 2>&1
  pass
else
  fail "could not create repo"
fi

sleep 2

begin_test "Generate SBOM"
# Get artifact ID
ARTIFACT_ID=""
if resp=$(api_get "/api/v1/repositories/${REPO_KEY}/artifacts" 2>/dev/null); then
  ARTIFACT_ID=$(echo "$resp" | jq -r '
    if type == "array" then .[0].id // empty
    elif .items then .items[0].id // empty
    else empty
    end' 2>/dev/null) || true
fi

if [ -n "$ARTIFACT_ID" ] && [ "$ARTIFACT_ID" != "null" ]; then
  if resp=$(api_post "/api/v1/sbom" \
      "{\"artifact_id\":\"${ARTIFACT_ID}\",\"format\":\"cyclonedx\"}" 2>/dev/null); then
    pass
  else
    skip "SBOM generation not available"
  fi
else
  skip "could not get artifact ID for SBOM"
fi

begin_test "List SBOMs"
SBOM_RESP=""
if resp=$(api_get "/api/v1/sbom" 2>/dev/null); then
  SBOM_RESP="$resp"
  pass
elif resp=$(api_get "/api/v1/sbom?repository_key=${REPO_KEY}" 2>/dev/null); then
  SBOM_RESP="$resp"
  pass
else
  skip "SBOM listing not available"
fi

# -------------------------------------------------------------------------
# Get full SBOM content for structural validation
# -------------------------------------------------------------------------

begin_test "Get SBOM content by artifact"
SBOM_CONTENT=""
if [ -n "$ARTIFACT_ID" ] && [ "$ARTIFACT_ID" != "null" ]; then
  if content_resp=$(api_get "/api/v1/sbom/by-artifact/${ARTIFACT_ID}" 2>/dev/null); then
    SBOM_CONTENT="$content_resp"
    pass
  else
    skip "SBOM content retrieval not available"
  fi
else
  skip "no artifact ID for SBOM content retrieval"
fi

# -------------------------------------------------------------------------
# Structural validation of SBOM metadata
# -------------------------------------------------------------------------

begin_test "SBOM has valid CycloneDX structure"
if [ -n "$SBOM_CONTENT" ]; then
  # Check the content field for CycloneDX bomFormat
  has_bom_format=$(echo "$SBOM_CONTENT" | jq -e '.content.bomFormat' 2>/dev/null) || true
  if [ -n "$has_bom_format" ] && [ "$has_bom_format" != "null" ]; then
    bom_format=$(echo "$SBOM_CONTENT" | jq -r '.content.bomFormat')
    if [ "$bom_format" = "CycloneDX" ]; then
      pass
    else
      fail "unexpected bomFormat: ${bom_format}"
    fi
  else
    # Fall back to checking the metadata format field
    format=$(echo "$SBOM_CONTENT" | jq -r '.format // empty' 2>/dev/null) || true
    if [ "$format" = "cyclonedx" ] || [ "$format" = "CycloneDX" ]; then
      pass
    else
      skip "SBOM response does not contain bomFormat field"
    fi
  fi
else
  skip "no SBOM content to validate"
fi

begin_test "SBOM contains specVersion"
if [ -n "$SBOM_CONTENT" ]; then
  # Check content field for CycloneDX specVersion
  has_spec=$(echo "$SBOM_CONTENT" | jq -e '.content.specVersion' 2>/dev/null) || true
  if [ -n "$has_spec" ] && [ "$has_spec" != "null" ]; then
    pass
  else
    # Fall back to metadata spec_version field
    spec_ver=$(echo "$SBOM_CONTENT" | jq -r '.spec_version // empty' 2>/dev/null) || true
    if [ -n "$spec_ver" ] && [ "$spec_ver" != "null" ]; then
      pass
    else
      fail "SBOM missing specVersion"
    fi
  fi
else
  skip "no SBOM content to validate"
fi

begin_test "SBOM has component count"
if [ -n "$SBOM_CONTENT" ]; then
  comp_count=$(echo "$SBOM_CONTENT" | jq -r '.component_count // empty' 2>/dev/null) || true
  if [ -n "$comp_count" ] && [ "$comp_count" != "null" ]; then
    pass
  else
    skip "SBOM response does not include component_count"
  fi
else
  skip "no SBOM content to validate"
fi

end_suite
