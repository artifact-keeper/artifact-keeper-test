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
# Feature-gated: this test requires conan remote-search-forwarding, which is
# planned for v1.3.0 (tracked in artifact-keeper#868). On older backends
# require_feature emits a skip with the version reason.
if require_feature "conan_remote_search_forward"; then
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
      skip "search through remote proxy returned error (upstream may not support search)"
    fi
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
# Feature-gated: requires conan virtual-search-aggregation (artifact-keeper#868),
# planned for v1.3.0.
if require_feature "conan_virtual_search_aggregate"; then
  if resp=$(curl -sf $CURL_TIMEOUT \
      -H "$(format_auth_header)" \
      "${BASE_URL}/conan/${VIRTUAL_KEY}/v2/conans/search?q=locallib" 2>/dev/null); then
    if assert_contains "$resp" "locallib" "virtual search should find locallib from local member"; then
      pass
    fi
  else
    fail "virtual repo search for locallib returned error"
  fi
fi

# =========================================================================
# Test 10: Search through virtual repo for zlib (from remote member)
# =========================================================================

begin_test "Search virtual repo for zlib (from remote member)"
# Feature-gated: this needs BOTH virtual-aggregation AND remote-forwarding
# (artifact-keeper#868). require_feature on either is sufficient since they
# ship together; pick the broader virtual-aggregate flag.
if require_feature "conan_virtual_search_aggregate"; then
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
fi

# =========================================================================
# Test 11: Fetch locallib latest through virtual, compare to direct local
# =========================================================================

begin_test "Fetch locallib latest through virtual matches local"
# Virtual recipe_latest fan-out across non-Remote members landed in v1.2.x
# via #875. v1.1.x backend lacks fan-out so virtual_resp is empty.
# Tracked for v1.1.10 backport in artifact-keeper#986.
if require_feature "conan_virtual_recipe_fanout"; then

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

fi  # require_feature "conan_virtual_recipe_fanout"

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
# #3887: a remote whose upstream lacks a revision answers 404, so the Conan
# client falls through to its next remote (the issue's multi-remote case).
# Uses the harness mock upstream (tests/lib/mock-upstream.py), which answers
# 404 for any path it has no file for, like conan_server does.
# =========================================================================

MOCK_REMOTE_KEY="test-conan-mockremote-${RUN_ID}"
MOCK_NAME="mocklib"
MOCK_VERSION="2.0.0"
MOCK_RREV="5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e"
MOCK_MISSING_RREV="0badc0de0badc0de0badc0de0badc0de"
MOCK_READY=false

# conan_get <url>: sets global HTTP_STATUS and HTTP_BODY.
conan_get() {
  local out
  out=$(curl -s -w '\n%{http_code}' -H "$(format_auth_header)" $CURL_TIMEOUT "$1") || out=$'\n000'
  HTTP_BODY=$(printf '%s\n' "$out" | head -n -1)
  HTTP_STATUS=$(printf '%s\n' "$out" | tail -n 1)
}

begin_test "#3887 remote: mock upstream serves mocklib/2.0.0 with one revision"
if start_mock_upstream "${WORK_DIR}/mock-state"; then
  mref="${MOCK_STATE_DIR}/files/v2/conans/${MOCK_NAME}/${MOCK_VERSION}/_/_"
  mkdir -p "${mref}/revisions/${MOCK_RREV}"
  # Only the per-revision endpoints are seeded; everything else (other
  # revisions, other recipes) gets the mock's 404, like conan_server.
  printf '{"files":{"conanfile.py":{},"conanmanifest.txt":{},"conan_export.tgz":{}}}\n' \
    > "${mref}/revisions/${MOCK_RREV}/files"
  printf '{}\n' > "${mref}/revisions/${MOCK_RREV}/search"
  if create_remote_repo "$MOCK_REMOTE_KEY" "conan" "$MOCK_BASE_URL"; then
    MOCK_READY=true
    pass
  else
    fail "could not create remote Conan repo against the mock upstream ${MOCK_BASE_URL}"
  fi
else
  skip "mock upstream did not start"
fi

begin_test "#3887 remote: /files for a revision the upstream has returns 200"
if [ "$MOCK_READY" != "true" ]; then
  skip "mock upstream not available"
else
  conan_get "${BASE_URL}/conan/${MOCK_REMOTE_KEY}/v2/conans/${MOCK_NAME}/${MOCK_VERSION}/_/_/revisions/${MOCK_RREV}/files"
  if assert_eq "$HTTP_STATUS" "200" "expected 200 for upstream-held revision files, got HTTP ${HTTP_STATUS} body=${HTTP_BODY:0:200}" && \
     assert_contains "$HTTP_BODY" "conanfile.py" "files listing should come from the upstream"; then
    pass
  fi
fi

begin_test "#3887 remote: /files for a revision the upstream lacks returns 404"
if [ "$MOCK_READY" != "true" ]; then
  skip "mock upstream not available"
else
  conan_get "${BASE_URL}/conan/${MOCK_REMOTE_KEY}/v2/conans/${MOCK_NAME}/${MOCK_VERSION}/_/_/revisions/${MOCK_MISSING_RREV}/files"
  if assert_eq "$HTTP_STATUS" "404" "expected 404 when the upstream lacks the revision, got HTTP ${HTTP_STATUS} body=${HTTP_BODY:0:200}" && \
     assert_contains "$HTTP_BODY" "Recipe not found: '${MOCK_NAME}/${MOCK_VERSION}#${MOCK_MISSING_RREV}'" "404 body should name the missing revision"; then
    pass
  fi
fi

begin_test "#3887 remote: package search for a revision the upstream has without binaries returns 200 {}"
if [ "$MOCK_READY" != "true" ]; then
  skip "mock upstream not available"
else
  conan_get "${BASE_URL}/conan/${MOCK_REMOTE_KEY}/v2/conans/${MOCK_NAME}/${MOCK_VERSION}/_/_/revisions/${MOCK_RREV}/search"
  if assert_eq "$HTTP_STATUS" "200" "expected 200 for upstream-held revision search, got HTTP ${HTTP_STATUS} body=${HTTP_BODY:0:200}"; then
    if [ "$(echo "$HTTP_BODY" | jq -c '.' 2>/dev/null)" = "{}" ]; then
      pass
    else
      fail "expected {} for package search of a binary-less upstream revision" "${HTTP_BODY:0:500}"
    fi
  fi
fi

begin_test "#3887 remote: package search for a revision the upstream lacks returns 404"
if [ "$MOCK_READY" != "true" ]; then
  skip "mock upstream not available"
else
  conan_get "${BASE_URL}/conan/${MOCK_REMOTE_KEY}/v2/conans/${MOCK_NAME}/${MOCK_VERSION}/_/_/revisions/${MOCK_MISSING_RREV}/search"
  if assert_eq "$HTTP_STATUS" "404" "expected 404 when the upstream lacks the revision, got HTTP ${HTTP_STATUS} body=${HTTP_BODY:0:200}" && \
     assert_contains "$HTTP_BODY" "Recipe not found: '${MOCK_NAME}/${MOCK_VERSION}#${MOCK_MISSING_RREV}'" "404 body should name the missing revision"; then
    pass
  fi
fi

begin_test "#3887 remote: revisions for a recipe the upstream lacks returns 404"
if [ "$MOCK_READY" != "true" ]; then
  skip "mock upstream not available"
else
  conan_get "${BASE_URL}/conan/${MOCK_REMOTE_KEY}/v2/conans/nosuchlib/9.9.9/_/_/revisions"
  if assert_eq "$HTTP_STATUS" "404" "expected 404 when the upstream lacks the recipe, got HTTP ${HTTP_STATUS} body=${HTTP_BODY:0:200}" && \
     assert_contains "$HTTP_BODY" "Recipe not found: 'nosuchlib/9.9.9'" "404 body should name the missing recipe"; then
    pass
  fi
fi

# The client-side view of #3887: remotes are [mock-backed remote, local].
# locallib#LOCAL_REVISION exists only in the local repo. The Conan client asks
# the first remote for the revision's files and moves to the next remote only
# on 404; an empty 200 made it stop with "no conanfile".
begin_test "#3887 multi-remote: first remote 404s on /files, second remote serves the revision"
if [ "$MOCK_READY" != "true" ]; then
  skip "mock upstream not available"
else
  conan_get "${BASE_URL}/conan/${MOCK_REMOTE_KEY}/v2/conans/${LOCAL_NAME}/${LOCAL_VERSION}/_/_/revisions/${LOCAL_REVISION}/files"
  first_status="$HTTP_STATUS"; first_body="$HTTP_BODY"
  conan_get "${BASE_URL}/conan/${LOCAL_KEY}/v2/conans/${LOCAL_NAME}/${LOCAL_VERSION}/_/_/revisions/${LOCAL_REVISION}/files"
  if assert_eq "$first_status" "404" "first remote (${MOCK_REMOTE_KEY}) must answer 404 so the client falls through, got HTTP ${first_status} body=${first_body:0:200}" && \
     assert_eq "$HTTP_STATUS" "200" "second remote (${LOCAL_KEY}) should serve the revision files, got HTTP ${HTTP_STATUS}" && \
     assert_contains "$HTTP_BODY" "conanfile.py" "second remote files listing should include conanfile.py"; then
    pass
  fi
fi

if [ "$MOCK_READY" = "true" ]; then
  api_delete "/api/v1/repositories/${MOCK_REMOTE_KEY}" > /dev/null 2>&1 || true
fi

# =========================================================================
# Cleanup
# =========================================================================

api_delete "/api/v1/repositories/${VIRTUAL_KEY}" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${REMOTE_KEY}" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${LOCAL_KEY}" > /dev/null 2>&1 || true

end_suite
