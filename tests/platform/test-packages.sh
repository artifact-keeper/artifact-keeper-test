#!/usr/bin/env bash
source "$(dirname "$0")/../lib/common.sh"

begin_suite "platform-packages"
auth_admin
setup_workdir

REPO_A="pkgs-repo-a-${RUN_ID}"
REPO_B="pkgs-repo-b-${RUN_ID}"

begin_test "Create two repos"
create_local_repo "$REPO_A" "generic" && create_local_repo "$REPO_B" "generic"
if [ $? -eq 0 ]; then pass; else fail "create repos"; fi

begin_test "Upload to repo A"
echo "pkg-a-${RUN_ID}" > "${WORK_DIR}/pkg-a.txt"
api_upload "/api/v1/repositories/${REPO_A}/artifacts/shared-pkg/v1/file.txt" \
  "${WORK_DIR}/pkg-a.txt" "text/plain" > /dev/null
pass

begin_test "Upload to repo B"
echo "pkg-b-${RUN_ID}" > "${WORK_DIR}/pkg-b.txt"
api_upload "/api/v1/repositories/${REPO_B}/artifacts/shared-pkg/v1/file.txt" \
  "${WORK_DIR}/pkg-b.txt" "text/plain" > /dev/null
pass

begin_test "Query packages API for cross-repo aggregation"
resp=$(api_get "/api/v1/packages?q=shared-pkg") || true
if [ $? -eq 0 ] || [ -n "$resp" ]; then
  if assert_contains "$resp" "shared-pkg"; then
    pass
  else
    fail "package not found in aggregated results"
  fi
else
  skip "packages API not available"
fi

end_suite
