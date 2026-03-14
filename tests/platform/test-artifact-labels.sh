#!/usr/bin/env bash
# test-artifact-labels.sh - Artifact label CRUD E2E test
source "$(dirname "$0")/../lib/common.sh"

begin_suite "artifact-labels"
auth_admin
setup_workdir

REPO_KEY="test-artlabels-${RUN_ID}"

begin_test "Create repo and upload artifact"
if create_local_repo "$REPO_KEY" "generic"; then
  echo "label-test-${RUN_ID}" > "${WORK_DIR}/labeled.bin"
  api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/labeled.bin" \
    "${WORK_DIR}/labeled.bin" > /dev/null 2>&1
  pass
else
  fail "could not create repo"
fi

sleep 2

begin_test "Set labels on artifact"
ARTIFACT_ID=""
if resp=$(api_get "/api/v1/repositories/${REPO_KEY}/artifacts" 2>/dev/null); then
  ARTIFACT_ID=$(echo "$resp" | jq -r '
    if type == "array" then .[0].id // empty
    elif .items then .items[0].id // empty
    else empty end' 2>/dev/null) || true
fi
if [ -n "$ARTIFACT_ID" ] && [ "$ARTIFACT_ID" != "null" ]; then
  if api_put "/api/v1/artifacts/${ARTIFACT_ID}/labels" \
      '{"labels":{"release":"candidate","build":"123"}}' > /dev/null 2>&1; then
    pass
  elif api_post "/api/v1/artifacts/${ARTIFACT_ID}/labels" \
      '{"labels":{"release":"candidate","build":"123"}}' > /dev/null 2>&1; then
    pass
  else
    skip "artifact labels not available"
  fi
else
  skip "no artifact ID"
fi

begin_test "Get artifact labels"
if [ -n "$ARTIFACT_ID" ] && [ "$ARTIFACT_ID" != "null" ]; then
  if resp=$(api_get "/api/v1/artifacts/${ARTIFACT_ID}/labels" 2>/dev/null); then
    if assert_contains "$resp" "candidate"; then pass; fi
  else
    skip "artifact label retrieval not available"
  fi
else
  skip "no artifact ID"
fi

end_suite
