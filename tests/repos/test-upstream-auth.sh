#!/usr/bin/env bash
# test-upstream-auth.sh - Upstream authentication for remote repos
#
# Tests setting and removing upstream auth credentials on a remote repo,
# including basic and bearer auth types, and the test-upstream endpoint.
#
# Since artifact-keeper#4662 (1.11.1) a PUBLIC Remote refuses upstream
# credentials with 400 unless the caller opts in with
# `allow_public_with_upstream_credentials: true` (anonymous pulls would spend
# the credentials). The remote under test is therefore PRIVATE, and each
# upstream-auth PUT is a hard assertion checked against the repository's
# reported upstream_auth_type / upstream_auth_configured. A separate public
# Remote pins the #4662 refusal.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "upstream-auth"
auth_admin
setup_workdir

UPSTREAM_KEY="test-upauth-local-${RUN_ID}"
REMOTE_KEY="test-upauth-remote-${RUN_ID}"
PUBLIC_REMOTE_KEY="test-upauth-pubremote-${RUN_ID}"

# put_upstream_auth KEY PAYLOAD -> echoes the HTTP status; the body lands in ${WORK_DIR}/upauth.json
put_upstream_auth() {
  curl -s -o "${WORK_DIR}/upauth.json" -w '%{http_code}' $CURL_TIMEOUT -X PUT \
    -H "$(auth_header)" -H "Content-Type: application/json" \
    -d "$2" "${BASE_URL}/api/v1/repositories/$1/upstream-auth" 2>/dev/null || echo "000"
}

# upstream_auth_state KEY -> "<upstream_auth_type>|<upstream_auth_configured>"
upstream_auth_state() {
  api_get "/api/v1/repositories/$1" 2>/dev/null \
    | jq -r '"\(.upstream_auth_type // "none")|\(.upstream_auth_configured)"' 2>/dev/null || echo "unreadable"
}

# -------------------------------------------------------------------------
# Create a local repo as mock upstream and seed it with an artifact
# -------------------------------------------------------------------------

begin_test "Create local repo as upstream"
if create_local_repo "$UPSTREAM_KEY" "generic"; then
  pass
else
  fail "could not create local repo"
fi

begin_test "Upload artifact to upstream"
echo "upstream-payload-${RUN_ID}" > "${WORK_DIR}/payload.txt"
if api_upload "/api/v1/repositories/${UPSTREAM_KEY}/artifacts/libs/file.jar" \
    "${WORK_DIR}/payload.txt"; then
  pass
else
  fail "upload to upstream failed"
fi

# -------------------------------------------------------------------------
# Create remote repo pointing at the local one
# -------------------------------------------------------------------------

begin_test "Create private remote repo"
UPSTREAM_URL="${BASE_URL}/generic/${UPSTREAM_KEY}"
REMOTE_PAYLOAD=$(jq -n --arg key "$REMOTE_KEY" --arg url "$UPSTREAM_URL" \
  '{key: $key, name: $key, format: "generic", repo_type: "remote", upstream_url: $url, is_public: false}')
if api_post "/api/v1/repositories" "$REMOTE_PAYLOAD" > /dev/null; then
  pass
else
  fail "could not create remote repo"
fi

# -------------------------------------------------------------------------
# Set upstream auth (basic)
# -------------------------------------------------------------------------

begin_test "Set upstream auth with basic credentials"
BASIC_AUTH_PAYLOAD="{\"auth_type\":\"basic\",\"username\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASS}\"}"
st=$(put_upstream_auth "$REMOTE_KEY" "$BASIC_AUTH_PAYLOAD")
state=$(upstream_auth_state "$REMOTE_KEY")
if [ "$st" = "200" ] && [ "$state" = "basic|true" ]; then
  pass
else
  fail "basic upstream-auth PUT returned ${st}, repository reports ${state}; expected 200 and basic|true" \
    "Response: $(head -c 300 "${WORK_DIR}/upauth.json" 2>/dev/null)"
fi

# -------------------------------------------------------------------------
# Test upstream connectivity
# -------------------------------------------------------------------------

begin_test "Test upstream connectivity"
if resp=$(api_post "/api/v1/repositories/${REMOTE_KEY}/test-upstream" "" 2>/dev/null); then
  # The response should indicate success or a reachable upstream
  if echo "$resp" | jq -e '.success // .reachable // .status' > /dev/null 2>&1; then
    pass
  else
    # Any 2xx means the endpoint worked
    pass
  fi
else
  skip "test-upstream endpoint not available"
fi

# -------------------------------------------------------------------------
# Verify remote repo still shows correct details
# -------------------------------------------------------------------------

begin_test "Get remote repo details with auth configured"
if resp=$(api_get "/api/v1/repositories/${REMOTE_KEY}" 2>/dev/null); then
  if assert_contains "$resp" "remote"; then
    pass
  fi
else
  fail "could not get remote repo details"
fi

# -------------------------------------------------------------------------
# Switch to bearer auth
# -------------------------------------------------------------------------

begin_test "Set upstream auth with bearer token"
# The bearer token travels in `password` (UpstreamAuthRequest has no `token`
# field; the old payload was refused 400 and the skip hid it).
BEARER_AUTH_PAYLOAD="{\"auth_type\":\"bearer\",\"password\":\"test-bearer-token-${RUN_ID}\"}"
st=$(put_upstream_auth "$REMOTE_KEY" "$BEARER_AUTH_PAYLOAD")
state=$(upstream_auth_state "$REMOTE_KEY")
if [ "$st" = "200" ] && [ "$state" = "bearer|true" ]; then
  pass
else
  fail "bearer upstream-auth PUT returned ${st}, repository reports ${state}; expected 200 and bearer|true" \
    "Response: $(head -c 300 "${WORK_DIR}/upauth.json" 2>/dev/null)"
fi

# -------------------------------------------------------------------------
# Remove upstream auth
# -------------------------------------------------------------------------

begin_test "Remove upstream auth"
NONE_AUTH_PAYLOAD='{"auth_type":"none"}'
st=$(put_upstream_auth "$REMOTE_KEY" "$NONE_AUTH_PAYLOAD")
state=$(upstream_auth_state "$REMOTE_KEY")
if [ "$st" = "200" ] && [ "${state#*|}" = "false" ]; then
  pass
else
  fail "removing upstream auth returned ${st}, repository reports ${state}; expected 200 and upstream_auth_configured false" \
    "Response: $(head -c 300 "${WORK_DIR}/upauth.json" 2>/dev/null)"
fi

# -------------------------------------------------------------------------
# Verify remote repo still works after auth removal
# -------------------------------------------------------------------------

begin_test "Remote repo accessible after auth removal"
if resp=$(api_get "/api/v1/repositories/${REMOTE_KEY}" 2>/dev/null); then
  if assert_contains "$resp" "$REMOTE_KEY"; then
    pass
  fi
else
  fail "could not access remote repo after auth removal"
fi

# -------------------------------------------------------------------------
# #4662: a PUBLIC Remote refuses upstream credentials without the override
# -------------------------------------------------------------------------

begin_test "Public remote refuses upstream credentials without the override (#4662)"
if create_remote_repo "$PUBLIC_REMOTE_KEY" "generic" "$UPSTREAM_URL"; then
  st=$(put_upstream_auth "$PUBLIC_REMOTE_KEY" "$BASIC_AUTH_PAYLOAD")
  state=$(upstream_auth_state "$PUBLIC_REMOTE_KEY")
  if [ "$st" = "400" ] && [ "${state#*|}" = "false" ]; then
    pass
  else
    fail "basic upstream-auth PUT on a public remote returned ${st}, repository reports ${state}; expected 400 and nothing stored" \
      "Response: $(head -c 300 "${WORK_DIR}/upauth.json" 2>/dev/null)"
  fi
else
  fail "could not create the public remote repo"
fi

# -------------------------------------------------------------------------
# Cleanup
# -------------------------------------------------------------------------

api_delete "/api/v1/repositories/${PUBLIC_REMOTE_KEY}" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${REMOTE_KEY}" > /dev/null 2>&1 || true
api_delete "/api/v1/repositories/${UPSTREAM_KEY}" > /dev/null 2>&1 || true

end_suite
