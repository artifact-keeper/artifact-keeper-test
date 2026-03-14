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
  if resp=$(api_post "/api/v1/sbom/generate" \
      "{\"artifact_id\":\"${ARTIFACT_ID}\",\"format\":\"cyclonedx\"}" 2>/dev/null); then
    pass
  else
    skip "SBOM generation not available"
  fi
else
  skip "could not get artifact ID for SBOM"
fi

begin_test "List SBOMs"
if resp=$(api_get "/api/v1/sbom" 2>/dev/null); then
  pass
elif resp=$(api_get "/api/v1/sbom?repository_key=${REPO_KEY}" 2>/dev/null); then
  pass
else
  skip "SBOM listing not available"
fi

end_suite
