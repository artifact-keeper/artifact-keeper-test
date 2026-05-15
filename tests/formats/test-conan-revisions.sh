#!/usr/bin/env bash
# test-conan-revisions.sh - Conan v2 recipe and package revision E2E tests
# Validates the revision lifecycle: uploading multiple recipe revisions,
# listing them, verifying ordering and timestamps, downloading from specific
# revisions, and managing package revisions under a recipe revision.
source "$(dirname "$0")/../lib/common.sh"

begin_suite "conan-revisions"
auth_admin
setup_workdir

REPO_KEY="test-conan-rev-${RUN_ID}"
PKG_NAME="revlib"
PKG_VERSION="1.0.0"
PKG_USER="_"
PKG_CHANNEL="_"
CONAN_BASE="${BASE_URL}/conan/${REPO_KEY}/v2/conans/${PKG_NAME}/${PKG_VERSION}/${PKG_USER}/${PKG_CHANNEL}"

REV1="aa11bb22cc33dd44ee55ff6600112233"
REV2="bb22cc33dd44ee55ff6600112233aa11"
REV3="cc33dd44ee55ff6600112233aa11bb22"

PKG_ID="da39a3ee5e6b4b0d3255bfef95601890afd80709"
PREV1="dd44ee55ff6600112233aa11bb22cc33"
PREV2="ee55ff6600112233aa11bb22cc33dd44"

# -----------------------------------------------------------------------
begin_test "Create Conan local repository"
# -----------------------------------------------------------------------
if create_local_repo "$REPO_KEY" "conan"; then
  pass
else
  fail "could not create conan repo"
fi

# -----------------------------------------------------------------------
begin_test "Upload recipe revision 1 and verify latest"
# -----------------------------------------------------------------------
cat > "${WORK_DIR}/conanfile-v1.py" <<'PYEOF'
from conan import ConanFile

class RevLibConan(ConanFile):
    name = "revlib"
    version = "1.0.0"
    description = "Revision test, content v1"
PYEOF

status=$(curl -s -o /dev/null -w '%{http_code}' -X PUT \
  -H "$(format_auth_header)" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@${WORK_DIR}/conanfile-v1.py" \
  "${CONAN_BASE}/revisions/${REV1}/files/conanfile.py") || true

if [ "$status" -lt 200 ] 2>/dev/null || [ "$status" -ge 300 ] 2>/dev/null; then
  fail "rev1 upload returned HTTP ${status}"
else
  latest=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${CONAN_BASE}/latest") || true
  if [ -z "$latest" ]; then
    fail "latest endpoint returned empty response after rev1 upload"
  else
    latest_rev=$(echo "$latest" | jq -r '.revision // empty')
    if assert_eq "$latest_rev" "$REV1" "expected latest to be rev1 (${REV1}), got ${latest_rev}"; then
      pass
    fi
  fi
fi

# -----------------------------------------------------------------------
begin_test "Upload recipe revision 2 and verify latest updates"
# -----------------------------------------------------------------------
cat > "${WORK_DIR}/conanfile-v2.py" <<'PYEOF'
from conan import ConanFile

class RevLibConan(ConanFile):
    name = "revlib"
    version = "1.0.0"
    description = "Revision test, content v2 with changes"
    license = "MIT"
PYEOF

status=$(curl -s -o /dev/null -w '%{http_code}' -X PUT \
  -H "$(format_auth_header)" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@${WORK_DIR}/conanfile-v2.py" \
  "${CONAN_BASE}/revisions/${REV2}/files/conanfile.py") || true

if [ "$status" -lt 200 ] 2>/dev/null || [ "$status" -ge 300 ] 2>/dev/null; then
  fail "rev2 upload returned HTTP ${status}"
else
  latest=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${CONAN_BASE}/latest") || true
  latest_rev=$(echo "$latest" | jq -r '.revision // empty')
  if assert_eq "$latest_rev" "$REV2" "expected latest to be rev2 (${REV2}), got ${latest_rev}"; then
    pass
  fi
fi

# -----------------------------------------------------------------------
begin_test "Upload recipe revision 3 and verify latest updates"
# -----------------------------------------------------------------------
cat > "${WORK_DIR}/conanfile-v3.py" <<'PYEOF'
from conan import ConanFile

class RevLibConan(ConanFile):
    name = "revlib"
    version = "1.0.0"
    description = "Revision test, content v3 final iteration"
    license = "Apache-2.0"
    author = "test"
PYEOF

status=$(curl -s -o /dev/null -w '%{http_code}' -X PUT \
  -H "$(format_auth_header)" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@${WORK_DIR}/conanfile-v3.py" \
  "${CONAN_BASE}/revisions/${REV3}/files/conanfile.py") || true

if [ "$status" -lt 200 ] 2>/dev/null || [ "$status" -ge 300 ] 2>/dev/null; then
  fail "rev3 upload returned HTTP ${status}"
else
  latest=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${CONAN_BASE}/latest") || true
  latest_rev=$(echo "$latest" | jq -r '.revision // empty')
  if assert_eq "$latest_rev" "$REV3" "expected latest to be rev3 (${REV3}), got ${latest_rev}"; then
    pass
  fi
fi

# -----------------------------------------------------------------------
begin_test "List recipe revisions contains all three"
# -----------------------------------------------------------------------
revisions_resp=$(curl -sf $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  "${CONAN_BASE}/revisions") || true

if [ -z "$revisions_resp" ]; then
  fail "revisions list returned empty response"
else
  rev_count=$(echo "$revisions_resp" | jq '.revisions | length')
  found_rev1=$(echo "$revisions_resp" | jq --arg r "$REV1" '[.revisions[].revision] | map(select(. == $r)) | length')
  found_rev2=$(echo "$revisions_resp" | jq --arg r "$REV2" '[.revisions[].revision] | map(select(. == $r)) | length')
  found_rev3=$(echo "$revisions_resp" | jq --arg r "$REV3" '[.revisions[].revision] | map(select(. == $r)) | length')

  ok=true
  if [ "$rev_count" -lt 3 ] 2>/dev/null; then
    fail "expected at least 3 revisions, got ${rev_count}"
    ok=false
  fi
  if [ "$found_rev1" != "1" ] && $ok; then
    fail "rev1 (${REV1}) not found in revisions list"
    ok=false
  fi
  if [ "$found_rev2" != "1" ] && $ok; then
    fail "rev2 (${REV2}) not found in revisions list"
    ok=false
  fi
  if [ "$found_rev3" != "1" ] && $ok; then
    fail "rev3 (${REV3}) not found in revisions list"
    ok=false
  fi
  if $ok; then
    pass
  fi
fi

# -----------------------------------------------------------------------
begin_test "Revisions have valid time fields"
# -----------------------------------------------------------------------
# Each revision entry should have a "time" field with a parseable timestamp.
if [ -z "$revisions_resp" ]; then
  fail "no revisions response available"
else
  all_have_time=$(echo "$revisions_resp" | jq '
    [.revisions[] | select(.time != null and (.time | length) > 0)] | length
  ')
  total=$(echo "$revisions_resp" | jq '.revisions | length')
  if assert_eq "$all_have_time" "$total" "not all revisions have a non-empty time field (${all_have_time}/${total})"; then
    # Verify the time value looks like a timestamp (ISO 8601 or epoch)
    first_time=$(echo "$revisions_resp" | jq -r '.revisions[0].time')
    # Accept ISO 8601 (contains T or -) or numeric epoch
    if [[ "$first_time" =~ [0-9]{4}-[0-9]{2}-[0-9]{2} ]] || [[ "$first_time" =~ ^[0-9]+\.?[0-9]*$ ]]; then
      pass
    else
      fail "time field '${first_time}' does not look like a valid timestamp"
    fi
  fi
fi

# -----------------------------------------------------------------------
begin_test "Revisions are ordered by time (most recent first)"
# -----------------------------------------------------------------------
if [ -z "$revisions_resp" ]; then
  fail "no revisions response available"
else
  # The first entry in the list should be the most recently uploaded revision.
  # REV3 was uploaded last, so it should appear first if ordered descending.
  first_rev=$(echo "$revisions_resp" | jq -r '.revisions[0].revision')
  if assert_eq "$first_rev" "$REV3" "expected first revision to be most recent (${REV3}), got ${first_rev}"; then
    pass
  fi
fi

# -----------------------------------------------------------------------
begin_test "Download file from rev1 returns v1 content"
# -----------------------------------------------------------------------
dl_rev1="${WORK_DIR}/dl-rev1.py"
dl_status=$(curl -sf -o "$dl_rev1" -w '%{http_code}' \
  -H "$(format_auth_header)" \
  "${CONAN_BASE}/revisions/${REV1}/files/conanfile.py" 2>/dev/null) || true

if [ "$dl_status" != "200" ] || [ ! -s "$dl_rev1" ]; then
  fail "download from rev1 failed (HTTP ${dl_status})"
else
  if assert_contains "$(cat "$dl_rev1")" "content v1" "rev1 download should contain 'content v1'"; then
    pass
  fi
fi

# -----------------------------------------------------------------------
begin_test "Download file from rev2 returns different content"
# -----------------------------------------------------------------------
dl_rev2="${WORK_DIR}/dl-rev2.py"
dl_status=$(curl -sf -o "$dl_rev2" -w '%{http_code}' \
  -H "$(format_auth_header)" \
  "${CONAN_BASE}/revisions/${REV2}/files/conanfile.py" 2>/dev/null) || true

if [ "$dl_status" != "200" ] || [ ! -s "$dl_rev2" ]; then
  fail "download from rev2 failed (HTTP ${dl_status})"
else
  rev2_content=$(cat "$dl_rev2")
  if assert_contains "$rev2_content" "content v2" "rev2 download should contain 'content v2'"; then
    # Also verify it differs from rev1
    rev1_content=$(cat "$dl_rev1")
    if [ "$rev1_content" = "$rev2_content" ]; then
      fail "rev1 and rev2 downloads are identical, expected different content"
    else
      pass
    fi
  fi
fi

# -----------------------------------------------------------------------
begin_test "Upload package binary under rev1 (prev1)"
# -----------------------------------------------------------------------
mkdir -p "${WORK_DIR}/pkg"
echo "binary-payload-v1-compiled-output" > "${WORK_DIR}/pkg/conan_package.tgz"

pkg_status=$(curl -s -o /dev/null -w '%{http_code}' -X PUT \
  -H "$(format_auth_header)" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@${WORK_DIR}/pkg/conan_package.tgz" \
  "${CONAN_BASE}/revisions/${REV1}/packages/${PKG_ID}/revisions/${PREV1}/files/conan_package.tgz") || true

if [ "$pkg_status" -ge 200 ] 2>/dev/null && [ "$pkg_status" -lt 300 ] 2>/dev/null; then
  pass
else
  fail "package rev1 upload returned HTTP ${pkg_status}"
fi

# -----------------------------------------------------------------------
begin_test "Upload second package revision under rev1 (prev2)"
# -----------------------------------------------------------------------
echo "binary-payload-v2-recompiled-output" > "${WORK_DIR}/pkg/conan_package2.tgz"

pkg_status=$(curl -s -o /dev/null -w '%{http_code}' -X PUT \
  -H "$(format_auth_header)" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@${WORK_DIR}/pkg/conan_package2.tgz" \
  "${CONAN_BASE}/revisions/${REV1}/packages/${PKG_ID}/revisions/${PREV2}/files/conan_package.tgz") || true

if [ "$pkg_status" -ge 200 ] 2>/dev/null && [ "$pkg_status" -lt 300 ] 2>/dev/null; then
  pass
else
  fail "package rev2 upload returned HTTP ${pkg_status}"
fi

# -----------------------------------------------------------------------
begin_test "List package revisions under rev1 contains both"
# -----------------------------------------------------------------------
pkg_revisions=$(curl -sf $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  "${CONAN_BASE}/revisions/${REV1}/packages/${PKG_ID}/revisions") || true

if [ -z "$pkg_revisions" ]; then
  fail "package revisions list returned empty response"
else
  pkg_rev_count=$(echo "$pkg_revisions" | jq '.revisions | length')
  found_prev1=$(echo "$pkg_revisions" | jq --arg r "$PREV1" '[.revisions[].revision] | map(select(. == $r)) | length')
  found_prev2=$(echo "$pkg_revisions" | jq --arg r "$PREV2" '[.revisions[].revision] | map(select(. == $r)) | length')

  ok=true
  if [ "$pkg_rev_count" -lt 2 ] 2>/dev/null; then
    fail "expected at least 2 package revisions, got ${pkg_rev_count}"
    ok=false
  fi
  if [ "$found_prev1" != "1" ] && $ok; then
    fail "prev1 (${PREV1}) not found in package revisions list"
    ok=false
  fi
  if [ "$found_prev2" != "1" ] && $ok; then
    fail "prev2 (${PREV2}) not found in package revisions list"
    ok=false
  fi
  if $ok; then
    pass
  fi
fi

# -----------------------------------------------------------------------
begin_test "Latest package revision returns prev2"
# -----------------------------------------------------------------------
pkg_latest=$(curl -sf $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  "${CONAN_BASE}/revisions/${REV1}/packages/${PKG_ID}/latest") || true

if [ -z "$pkg_latest" ]; then
  fail "package latest endpoint returned empty response"
else
  pkg_latest_rev=$(echo "$pkg_latest" | jq -r '.revision // empty')
  if assert_eq "$pkg_latest_rev" "$PREV2" "expected latest package revision to be prev2 (${PREV2}), got ${pkg_latest_rev}"; then
    pass
  fi
fi

# -----------------------------------------------------------------------
# Cleanup
# -----------------------------------------------------------------------
api_delete "/api/v1/repositories/${REPO_KEY}" > /dev/null 2>&1 || true

end_suite
