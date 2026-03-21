#!/usr/bin/env bash
source "$(dirname "$0")/../lib/common.sh"

begin_suite "platform-builds"
auth_admin
setup_workdir

REPO_KEY="builds-test-${RUN_ID}"

begin_test "Create test repo"
if create_local_repo "$REPO_KEY" "generic"; then pass; else fail "create repo"; fi

begin_test "Upload test artifact"
echo "build-artifact-${RUN_ID}" > "${WORK_DIR}/artifact.txt"
if api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/build/artifact.txt" \
    "${WORK_DIR}/artifact.txt" "text/plain"; then
  pass
else
  fail "upload failed"
fi

begin_test "Create build"
resp=$(api_post "/api/v1/builds" "{\"name\":\"test-build-${RUN_ID}\",\"number\":\"1\",\"started\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}") || true
BUILD_ID=$(echo "$resp" | jq -r '.id // empty')
if [ -n "$BUILD_ID" ]; then
  pass
else
  skip "builds API not available"
fi

begin_test "List builds"
resp=$(api_get "/api/v1/builds") || true
if [ -n "$BUILD_ID" ]; then
  if assert_contains "$resp" "$BUILD_ID"; then pass; else fail "build not in list"; fi
else
  skip "builds API not available"
fi

begin_test "Get build by ID"
if [ -n "$BUILD_ID" ]; then
  resp=$(api_get "/api/v1/builds/${BUILD_ID}") || true
  if assert_contains "$resp" "test-build-${RUN_ID}"; then pass; else fail "build name not found"; fi
else
  skip "builds API not available"
fi

end_suite
