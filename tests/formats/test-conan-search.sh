#!/usr/bin/env bash
# test-conan-search.sh - Conan v2 search endpoint E2E tests
#
# Uploads multiple recipes to a Conan v2 repository, then exercises the
# search endpoint with exact names, wildcards, and edge cases.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "conan-search"
auth_admin
setup_workdir

REPO_KEY="test-conan-search-${RUN_ID}"

# Fixed revision hashes for deterministic uploads
REV_A1="a100000000000000000000000000000a"
REV_B1="b100000000000000000000000000000b"
REV_B2="b200000000000000000000000000000b"
REV_O1="c100000000000000000000000000000c"
REV_U1="d100000000000000000000000000000d"

# -----------------------------------------------------------------------
# Helper: upload a Conan recipe (just the conanfile.py)
# Usage: upload_recipe NAME VERSION USER CHANNEL REVISION
# -----------------------------------------------------------------------
upload_recipe() {
  local name="$1"
  local version="$2"
  local user="$3"
  local channel="$4"
  local revision="$5"

  cat > "${WORK_DIR}/conanfile-${name}-${version}.py" <<PYEOF
from conan import ConanFile

class ${name}Conan(ConanFile):
    name = "${name}"
    version = "${version}"
    license = "MIT"
    description = "Test recipe ${name}/${version}"
PYEOF

  local status
  status=$(curl -s -o /dev/null -w '%{http_code}' -X PUT \
    $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    -H "Content-Type: application/octet-stream" \
    --data-binary "@${WORK_DIR}/conanfile-${name}-${version}.py" \
    "${BASE_URL}/conan/${REPO_KEY}/v2/conans/${name}/${version}/${user}/${channel}/revisions/${revision}/files/conanfile.py") || true

  echo "$status"
}

# -----------------------------------------------------------------------
# Helper: run a search query and return the response body
# Usage: conan_search PATTERN
# -----------------------------------------------------------------------
conan_search() {
  local pattern="$1"
  curl -s $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${BASE_URL}/conan/${REPO_KEY}/v2/conans/search?q=${pattern}"
}

# -----------------------------------------------------------------------
# Helper: run a search query and return both status code and body
# Usage: conan_search_with_status PATTERN
# Outputs: HTTP_STATUS\nBODY
# -----------------------------------------------------------------------
conan_search_with_status() {
  local pattern="$1"
  local tmpfile="${WORK_DIR}/search-resp.json"
  local status
  status=$(curl -s -o "$tmpfile" -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(format_auth_header)" \
    "${BASE_URL}/conan/${REPO_KEY}/v2/conans/search?q=${pattern}") || true
  echo "$status"
  cat "$tmpfile" 2>/dev/null || true
}

# -----------------------------------------------------------------------
begin_test "Create Conan local repository"
# -----------------------------------------------------------------------
if create_local_repo "$REPO_KEY" "conan"; then
  pass
else
  fail "could not create conan repo"
fi

# -----------------------------------------------------------------------
begin_test "Upload four test recipes"
# -----------------------------------------------------------------------
upload_ok=true

s=$(upload_recipe "searchlib-a" "1.0.0" "_" "_" "$REV_A1")
if [ "$s" -lt 200 ] 2>/dev/null || [ "$s" -ge 300 ] 2>/dev/null; then
  fail "searchlib-a/1.0.0 upload returned HTTP ${s}"
  upload_ok=false
fi

s=$(upload_recipe "searchlib-b" "1.0.0" "_" "_" "$REV_B1")
if [ "$s" -lt 200 ] 2>/dev/null || [ "$s" -ge 300 ] 2>/dev/null; then
  fail "searchlib-b/1.0.0 upload returned HTTP ${s}"
  upload_ok=false
fi

s=$(upload_recipe "searchlib-b" "2.0.0" "_" "_" "$REV_B2")
if [ "$s" -lt 200 ] 2>/dev/null || [ "$s" -ge 300 ] 2>/dev/null; then
  fail "searchlib-b/2.0.0 upload returned HTTP ${s}"
  upload_ok=false
fi

s=$(upload_recipe "other-pkg" "1.0.0" "_" "_" "$REV_O1")
if [ "$s" -lt 200 ] 2>/dev/null || [ "$s" -ge 300 ] 2>/dev/null; then
  fail "other-pkg/1.0.0 upload returned HTTP ${s}"
  upload_ok=false
fi

if $upload_ok; then
  pass
fi

# Allow a moment for indexing
sleep 1

# -----------------------------------------------------------------------
begin_test "Search exact name returns only that package"
# -----------------------------------------------------------------------
resp=$(conan_search "searchlib-a") || true
if [ -z "$resp" ]; then
  fail "search returned empty response"
else
  if assert_contains "$resp" "searchlib-a" "expected searchlib-a in results"; then
    if assert_not_contains "$resp" "searchlib-b" "expected searchlib-b absent for exact search"; then
      if assert_not_contains "$resp" "other-pkg" "expected other-pkg absent for exact search"; then
        pass
      fi
    fi
  fi
fi

# -----------------------------------------------------------------------
begin_test "Wildcard search for searchlib* returns both searchlib packages"
# -----------------------------------------------------------------------
resp=$(conan_search "searchlib*") || true
if [ -z "$resp" ]; then
  fail "search returned empty response"
else
  if assert_contains "$resp" "searchlib-a" "expected searchlib-a in wildcard results" && \
     assert_contains "$resp" "searchlib-b" "expected searchlib-b in wildcard results"; then
    pass
  fi
fi

# -----------------------------------------------------------------------
begin_test "Wildcard search *lib* matches all lib packages"
# -----------------------------------------------------------------------
resp=$(conan_search "*lib*") || true
if [ -z "$resp" ]; then
  fail "search returned empty response"
else
  if assert_contains "$resp" "searchlib-a" "expected searchlib-a in *lib* results" && \
     assert_contains "$resp" "searchlib-b" "expected searchlib-b in *lib* results"; then
    pass
  fi
fi

# -----------------------------------------------------------------------
begin_test "Wildcard search * returns all packages"
# -----------------------------------------------------------------------
resp=$(conan_search "*") || true
if [ -z "$resp" ]; then
  fail "search returned empty response"
else
  if assert_contains "$resp" "searchlib-a" "expected searchlib-a in * results" && \
     assert_contains "$resp" "searchlib-b" "expected searchlib-b in * results" && \
     assert_contains "$resp" "other-pkg" "expected other-pkg in * results"; then
    pass
  fi
fi

# -----------------------------------------------------------------------
begin_test "Search for non-existent package returns empty results"
# -----------------------------------------------------------------------
resp=$(conan_search "doesnotexist") || true
if [ -z "$resp" ]; then
  fail "search returned empty response (expected valid JSON with empty results)"
else
  count=$(echo "$resp" | jq '.results | length' 2>/dev/null) || count=""
  if [ "$count" = "0" ]; then
    pass
  elif [ -z "$count" ]; then
    # The response might use a different shape, check for an empty array
    is_empty=$(echo "$resp" | jq 'if .results then (.results | length == 0) elif type == "array" then (length == 0) else false end' 2>/dev/null) || is_empty="false"
    if [ "$is_empty" = "true" ]; then
      pass
    else
      fail "expected empty results for non-existent package, got: ${resp}"
    fi
  else
    fail "expected 0 results for non-existent package, got ${count}"
  fi
fi

# -----------------------------------------------------------------------
begin_test "Upload recipe with user/channel and search for it"
# -----------------------------------------------------------------------
s=$(upload_recipe "userlib" "1.0.0" "testuser" "stable" "$REV_U1")
if [ "$s" -lt 200 ] 2>/dev/null || [ "$s" -ge 300 ] 2>/dev/null; then
  fail "userlib/1.0.0@testuser/stable upload returned HTTP ${s}"
else
  sleep 1
  resp=$(conan_search "userlib*") || true
  if [ -z "$resp" ]; then
    fail "search for userlib* returned empty response"
  else
    if assert_contains "$resp" "userlib" "expected userlib in search results"; then
      pass
    fi
  fi
fi

# -----------------------------------------------------------------------
begin_test "Search results contain version information"
# -----------------------------------------------------------------------
resp=$(conan_search "searchlib-b*") || true
if [ -z "$resp" ]; then
  fail "search returned empty response"
else
  # Results should be in name/version format (e.g. "searchlib-b/1.0.0")
  if assert_contains "$resp" "searchlib-b/1.0.0" "expected searchlib-b/1.0.0 in results" && \
     assert_contains "$resp" "searchlib-b/2.0.0" "expected searchlib-b/2.0.0 in results"; then
    pass
  fi
fi

# -----------------------------------------------------------------------
begin_test "Search results are valid JSON with results array"
# -----------------------------------------------------------------------
resp=$(conan_search "*") || true
if [ -z "$resp" ]; then
  fail "search returned empty response"
else
  valid=$(echo "$resp" | jq -e '.results | type == "array"' 2>/dev/null) || valid="false"
  if [ "$valid" = "true" ]; then
    pass
  else
    fail "response is not valid JSON with a results array: ${resp}"
  fi
fi

# -----------------------------------------------------------------------
begin_test "Search response Content-Type is application/json"
# -----------------------------------------------------------------------
content_type=$(curl -s -o /dev/null -w '%{content_type}' $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  "${BASE_URL}/conan/${REPO_KEY}/v2/conans/search?q=*") || true

if [[ "$content_type" == *"application/json"* ]]; then
  pass
else
  fail "expected Content-Type application/json, got: ${content_type}"
fi

# -----------------------------------------------------------------------
begin_test "Search with user/channel recipe returns correct reference format"
# -----------------------------------------------------------------------
resp=$(conan_search "userlib*") || true
if [ -z "$resp" ]; then
  fail "search returned empty response"
else
  # Recipes uploaded with user/channel should appear as name/version@user/channel
  if assert_contains "$resp" "testuser" "expected testuser in user/channel reference"; then
    pass
  fi
fi

# -----------------------------------------------------------------------
# Cleanup
# -----------------------------------------------------------------------
api_delete "/api/v1/repositories/${REPO_KEY}" > /dev/null 2>&1 || true

end_suite
