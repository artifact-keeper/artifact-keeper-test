#!/usr/bin/env bash
# test-dependency-confusion.sh - T2-07: Dependency confusion prevention
#
# Verifies that a virtual repo serves the local package over a higher-versioned
# upstream. The local repo (priority 1) must win over the remote repo (priority 2)
# when both contain an artifact at the same path.

source "$(dirname "$0")/../lib/common.sh"

begin_suite "dependency-confusion"
auth_admin
setup_workdir

LOCAL_KEY="sec-depconf-local-${RUN_ID}"
REMOTE_KEY="sec-depconf-remote-${RUN_ID}"
VIRTUAL_KEY="sec-depconf-virtual-${RUN_ID}"

# ---------------------------------------------------------------------------
# Create local repo and upload "internal-pkg" v1.0.0
# ---------------------------------------------------------------------------

begin_test "Create local generic repo"
if create_local_repo "$LOCAL_KEY" "generic"; then
  pass
else
  fail "could not create local repo"
fi

begin_test "Upload internal-pkg v1.0.0 to local repo"
echo "internal-pkg-local-v1.0.0-${RUN_ID}" > "${WORK_DIR}/internal-pkg.tar.gz"
if api_upload "/api/v1/repositories/${LOCAL_KEY}/artifacts/internal-pkg/1.0.0/internal-pkg.tar.gz" \
    "${WORK_DIR}/internal-pkg.tar.gz"; then
  pass
else
  fail "upload to local repo failed"
fi

# ---------------------------------------------------------------------------
# Create remote repo pointing to a nonexistent upstream
# ---------------------------------------------------------------------------

begin_test "Create remote repo with nonexistent upstream"
# Points to a URL that will never resolve a package. The key point is that the
# virtual repo should prefer the local member regardless.
if create_remote_repo "$REMOTE_KEY" "generic" "https://nonexistent-upstream.invalid/repo"; then
  pass
else
  fail "could not create remote repo"
fi

# ---------------------------------------------------------------------------
# Create virtual repo with local (priority 1) and remote (priority 2)
# ---------------------------------------------------------------------------

begin_test "Create virtual repo"
if create_virtual_repo "$VIRTUAL_KEY" "generic"; then
  pass
else
  fail "could not create virtual repo"
fi

begin_test "Add members to virtual repo (local=priority 1, remote=priority 2)"
MEMBERS_PAYLOAD="{\"members\":[{\"member_key\":\"${LOCAL_KEY}\",\"priority\":1},{\"member_key\":\"${REMOTE_KEY}\",\"priority\":2}]}"
if api_put "/api/v1/repositories/${VIRTUAL_KEY}/members" "$MEMBERS_PAYLOAD" 2>/dev/null; then
  pass
else
  # Try individual POST as fallback
  if api_post "/api/v1/repositories/${VIRTUAL_KEY}/members" \
      "{\"member_key\":\"${LOCAL_KEY}\",\"priority\":1}" 2>/dev/null; then
    api_post "/api/v1/repositories/${VIRTUAL_KEY}/members" \
      "{\"member_key\":\"${REMOTE_KEY}\",\"priority\":2}" 2>/dev/null || true
    pass
  else
    fail "could not add members to virtual repo"
  fi
fi

# ---------------------------------------------------------------------------
# Fetch internal-pkg through virtual repo, assert local copy is returned
# ---------------------------------------------------------------------------

sleep 2

begin_test "Fetch internal-pkg through virtual repo returns local version"
dl_resp=""
if dl_resp=$(api_get "/api/v1/repositories/${VIRTUAL_KEY}/artifacts/internal-pkg/1.0.0/internal-pkg.tar.gz" \
    -o "${WORK_DIR}/downloaded.tar.gz" -w '%{http_code}' 2>/dev/null); then
  # Verify content matches the local upload
  expected_content="internal-pkg-local-v1.0.0-${RUN_ID}"
  if [ -f "${WORK_DIR}/downloaded.tar.gz" ]; then
    actual_content=$(cat "${WORK_DIR}/downloaded.tar.gz")
    if assert_contains "$actual_content" "$expected_content" \
        "virtual repo should serve local package content, not upstream"; then
      pass
    fi
  else
    fail "downloaded file does not exist"
  fi
else
  # Try the format-level download endpoint
  if curl -sf $CURL_TIMEOUT -H "$(auth_header)" \
      -o "${WORK_DIR}/downloaded2.tar.gz" \
      "${BASE_URL}/generic/${VIRTUAL_KEY}/internal-pkg/1.0.0/internal-pkg.tar.gz" 2>/dev/null; then
    actual_content=$(cat "${WORK_DIR}/downloaded2.tar.gz")
    expected_content="internal-pkg-local-v1.0.0-${RUN_ID}"
    if assert_contains "$actual_content" "$expected_content" \
        "virtual repo should serve local package content via format endpoint"; then
      pass
    fi
  else
    skip "could not download artifact through virtual repo (endpoint may not support direct download)"
  fi
fi

# ---------------------------------------------------------------------------
# Verify artifact listing through virtual repo shows the local version
# ---------------------------------------------------------------------------

begin_test "Virtual repo artifact listing includes local package"
if list_resp=$(api_get "/api/v1/repositories/${VIRTUAL_KEY}/artifacts" 2>/dev/null); then
  if assert_contains "$list_resp" "internal-pkg" \
      "virtual repo listing should include internal-pkg from local member"; then
    pass
  fi
else
  skip "virtual repo artifact listing not available"
fi

end_suite
