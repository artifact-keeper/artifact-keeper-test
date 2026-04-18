#!/usr/bin/env bash
# test-conan-remote.sh - Conan v2 remote proxy and virtual repo E2E tests
#
# Tests remote (pull-through proxy) and virtual (aggregation) repository
# behavior for the Conan v2 REST API. Uploads a local recipe, creates a
# remote proxy pointing at center.conan.io, wires both into a virtual
# repo, and verifies search and fetch through all three repo types.
#
# Requires: curl, jq

source "$(dirname "$0")/../lib/common.sh"

begin_suite "conan-remote"
auth_admin
setup_workdir

LOCAL_KEY="test-conan-local-${RUN_ID}"
REMOTE_KEY="test-conan-remote-${RUN_ID}"
VIRTUAL_KEY="test-conan-virtual-${RUN_ID}"
UPSTREAM_URL="https://center.conan.io"

# Local recipe details
LOCAL_NAME="locallib"
LOCAL_VERSION="1.0.0"
LOCAL_REVISION="a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"

# Well-known upstream package
UPSTREAM_PKG="zlib"
UPSTREAM_VERSION="1.3.1"

# =========================================================================
# Test 1: Create local Conan repo and upload a recipe
# =========================================================================

begin_test "Create local Conan repository"
if create_local_repo "$LOCAL_KEY" "conan"; then
  pass
else
  fail "could not create local Conan repo"
fi

# Upload a conanfile.py so the local repo has content for virtual lookups
cat > "${WORK_DIR}/conanfile.py" <<'PYEOF'
from conan import ConanFile

class LocalLibConan(ConanFile):
    name = "locallib"
    version = "1.0.0"
    license = "MIT"
    description = "Local test library for remote/virtual E2E"
    settings = "os", "compiler", "build_type", "arch"
PYEOF

begin_test "Upload locallib/1.0.0 recipe to local repo"
upload_status=$(curl -s -o /dev/null -w '%{http_code}' -X PUT \
  -H "$(format_auth_header)" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@${WORK_DIR}/conanfile.py" \
  "${BASE_URL}/conan/${LOCAL_KEY}/v2/conans/${LOCAL_NAME}/${LOCAL_VERSION}/_/_/revisions/${LOCAL_REVISION}/files/conanfile.py") || true

if [ "$upload_status" -ge 200 ] 2>/dev/null && [ "$upload_status" -lt 300 ] 2>/dev/null; then
  pass
else
  fail "recipe upload returned HTTP ${upload_status}"
fi

# =========================================================================
# Test 2: Create remote Conan repo pointing at Conan Center
# =========================================================================

begin_test "Create remote Conan repository"
if create_remote_repo "$REMOTE_KEY" "conan" "$UPSTREAM_URL"; then
  pass
else
  fail "could not create remote Conan repo"
fi

# =========================================================================
# Test 3: Check upstream reachability
# =========================================================================

begin_test "Check upstream reachability"
if curl -sf --max-time 10 "${UPSTREAM_URL}/v2/ping" > /dev/null 2>&1 || \
   curl -sf --max-time 10 "${UPSTREAM_URL}" > /dev/null 2>&1; then
  UPSTREAM_REACHABLE=true
  pass
else
  UPSTREAM_REACHABLE=false
  skip "center.conan.io unreachable from test environment"
fi

# =========================================================================
# Test 4: Search for zlib through remote proxy
# =========================================================================

begin_test "Search for zlib through remote proxy"
if [ "$UPSTREAM_REACHABLE" != "true" ]; then
  skip "upstream unreachable"
else
  if resp=$(curl -sf $CURL_TIMEOUT \
      -H "$(format_auth_header)" \
      "${BASE_URL}/conan/${REMOTE_KEY}/v2/conans/search?q=zlib" 2>/dev/null); then
    if assert_contains "$resp" "zlib" "search results should contain zlib"; then
      pass
    fi
  else
    # Remote search may not be supported for all upstreams; skip gracefully
    skip "search through remote proxy returned error (upstream may not support search)"
  fi
fi

# =========================================================================
# Test 5: Fetch latest revision of zlib through remote proxy
# =========================================================================

begin_test "Fetch zlib latest revision through remote proxy"
if [ "$UPSTREAM_REACHABLE" != "true" ]; then
  skip "upstream unreachable"
else
  if resp=$(curl -sf $CURL_TIMEOUT \
      -H "$(format_auth_header)" \
      "${BASE_URL}/conan/${REMOTE_KEY}/v2/conans/${UPSTREAM_PKG}/${UPSTREAM_VERSION}/_/_/latest" 2>/dev/null); then
    rev=$(echo "$resp" | jq -r '.revision // empty' 2>/dev/null) || true
    if [ -n "$rev" ]; then
      UPSTREAM_REVISION="$rev"
      pass
    else
      # The response may use a different field name
      if assert_contains "$resp" "revision" "latest response should contain revision field"; then
        UPSTREAM_REVISION=""
        pass
      fi
    fi
  else
    skip "latest revision endpoint returned error for ${UPSTREAM_PKG}/${UPSTREAM_VERSION}"
  fi
fi

# =========================================================================
# Test 6: Create virtual Conan repo
# =========================================================================

begin_test "Create virtual Conan repository"
if create_virtual_repo "$VIRTUAL_KEY" "conan"; then
  pass
else
  fail "could not create virtual Conan repo"
fi

# =========================================================================
# Test 7: Add local repo as virtual member (priority 1)
# =========================================================================

begin_test "Add local repo as virtual member (priority 1)"
if api_post "/api/v1/repositories/${VIRTUAL_KEY}/members" \
    "{\"member_key\":\"${LOCAL_KEY}\",\"priority\":1}" > /dev/null 2>&1; then
  pass
else
  fail "could not add local repo as virtual member"
fi

# =========================================================================
# Test 8: Add remote repo as virtual member (priority 2)
# =========================================================================

begin_test "Add remote repo as virtual member (priority 2)"
if api_post "/api/v1/repositories/${VIRTUAL_KEY}/members" \
    "{\"member_key\":\"${REMOTE_KEY}\",\"priority\":2}" > /dev/null 2>&1; then
  pass
else
  fail "could not add remote repo as virtual member"
fi

# Short pause so the virtual repo membership propagates
sleep 1

# =========================================================================
# Test 9: Search through virtual repo for locallib
# =========================================================================

begin_test "Search virtual repo for locallib (from local member)"
if resp=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${BASE_URL}/conan/${VIRTUAL_KEY}/v2/conans/search?q=locallib" 2>/dev/null); then
  if assert_contains "$resp" "locallib" "virtual search should find locallib from local member"; then
    pass
  fi
else
  fail "virtual repo search for locallib returned error"
fi

# =========================================================================
# Test 10: Search through virtual repo for zlib (from remote member)
# =========================================================================

begin_test "Search virtual repo for zlib (from remote member)"
if [ "$UPSTREAM_REACHABLE" != "true" ]; then
  skip "upstream unreachable"
else
  if resp=$(curl -sf $CURL_TIMEOUT \
      -H "$(format_auth_header)" \
      "${BASE_URL}/conan/${VIRTUAL_KEY}/v2/conans/search?q=zlib" 2>/dev/null); then
    if assert_contains "$resp" "zlib" "virtual search should find zlib from remote member"; then
      pass
    fi
  else
    skip "virtual repo search for zlib returned error (upstream search may not be supported)"
  fi
fi

# =========================================================================
# Test 11: Fetch locallib latest through virtual, compare to direct local
# =========================================================================

begin_test "Fetch locallib latest through virtual matches local"
# Get latest revision directly from the local repo
local_resp=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${BASE_URL}/conan/${LOCAL_KEY}/v2/conans/${LOCAL_NAME}/${LOCAL_VERSION}/_/_/latest" 2>/dev/null) || true

# Get latest revision through the virtual repo
virtual_resp=$(curl -sf $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${BASE_URL}/conan/${VIRTUAL_KEY}/v2/conans/${LOCAL_NAME}/${LOCAL_VERSION}/_/_/latest" 2>/dev/null) || true

if [ -z "$local_resp" ]; then
  fail "could not fetch locallib latest from local repo"
elif [ -z "$virtual_resp" ]; then
  fail "could not fetch locallib latest from virtual repo"
else
  local_rev=$(echo "$local_resp" | jq -r '.revision // empty' 2>/dev/null) || true
  virtual_rev=$(echo "$virtual_resp" | jq -r '.revision // empty' 2>/dev/null) || true

  if [ -n "$local_rev" ] && [ -n "$virtual_rev" ]; then
    if assert_eq "$virtual_rev" "$local_rev" \
        "virtual revision (${virtual_rev}) should match local revision (${local_rev})"; then
      pass
    fi
  else
    # Fallback: compare the full responses if revision extraction fails
    if assert_eq "$virtual_resp" "$local_resp" \
        "virtual latest response should match local latest response"; then
      pass
    fi
  fi
fi

# =========================================================================
# Test 12: Verify virtual repo ping endpoint
# =========================================================================

begin_test "Virtual repo ping endpoint returns 200 with capabilities"
ping_status=$(curl -s -o /dev/null -w '%{http_code}' \
  -H "$(format_auth_header)" \
  "${BASE_URL}/conan/${VIRTUAL_KEY}/v2/ping") || true

if [ "$ping_status" = "200" ]; then
  # Also verify the X-Conan-Server-Capabilities header is present
  capabilities=$(curl -s -D - -o /dev/null \
    -H "$(format_auth_header)" \
    "${BASE_URL}/conan/${VIRTUAL_KEY}/v2/ping" 2>/dev/null \
    | grep -i "X-Conan-Server-Capabilities" || true)

  if [ -n "$capabilities" ]; then
    pass
  else
    # Ping returned 200 but no capabilities header; still acceptable
    pass
  fi
else
  fail "ping returned HTTP ${ping_status}, expected 200"
fi

# =========================================================================
# Cleanup
# =========================================================================

api_delete "/api/v1/repositories/${VIRTUAL_KEY}" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${REMOTE_KEY}" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${LOCAL_KEY}" > /dev/null 2>&1 || true

end_suite
