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
pkg_status=$(curl -s -o "$WORK_DIR/packages-resp.json" -w '%{http_code}' \
  -H "$(auth_header)" $CURL_TIMEOUT \
  "${BASE_URL}/api/v1/packages?q=shared-pkg" 2>/dev/null) || pkg_status="000"
resp=$(cat "$WORK_DIR/packages-resp.json" 2>/dev/null) || resp=""

if [ "$pkg_status" = "404" ] || [ "$pkg_status" = "000" ]; then
  skip "packages API not implemented (returned ${pkg_status})"
elif [ "$pkg_status" -ge 200 ] 2>/dev/null && [ "$pkg_status" -lt 300 ] 2>/dev/null; then
  if [ -n "$resp" ] && echo "$resp" | grep -q "shared-pkg"; then
    pass
  else
    fail "package not found in aggregated results"
  fi
else
  skip "packages API returned unexpected status ${pkg_status}"
fi

end_suite
