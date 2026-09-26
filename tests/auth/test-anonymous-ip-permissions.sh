#!/usr/bin/env bash
# test-anonymous-ip-permissions.sh - request-IP conditions + anonymous grants (#1849)
#
# Permission rules gained an optional conditions object
# ({"allowed_cidrs": [...]}) and a new principal_type "anonymous" granting
# unauthenticated callers read on a repository or project — the CI-runner
# use case: keep a repository private to the world while runners inside the
# operator's CIDRs pull without credentials. Anonymous rules are read-only,
# and a caller outside the ranges gets the same existence-hiding denial as
# a rules-less repository.
#
# Requires guest access enabled (the anonymous surface is off by policy when
# AK_GUEST_ACCESS_ENABLED=false; that posture is certified by
# test-public-repo-guest-disabled.sh instead).
#
# On an UNFIXED backend every grant case fails: the permissions API knows
# neither "anonymous" nor "conditions", so the rule writes 400 and anonymous
# downloads stay denied.

source "$(dirname "$0")/../lib/common.sh"

begin_suite "anonymous-ip-permissions"

auth_admin

REPO_KEY="zz-1849-anon-${RUN_ID}"
ART_PATH="ci/artifact.bin"
NIL_UUID="00000000-0000-0000-0000-000000000000"

anon_download_status() {
  curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}/download/${ART_PATH}" 2>/dev/null || echo "000"
}

begin_test "Setup: private repository with one artifact"
# create_repo sends is_public:true, so create the repo explicitly as
# private — the whole premise under test.
setup_st=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
  -X POST \
  -H "$(auth_header)" \
  -H "Content-Type: application/json" \
  -d "{\"key\":\"${REPO_KEY}\",\"name\":\"${REPO_KEY}\",\"format\":\"generic\",\"repo_type\":\"local\",\"is_public\":false}" \
  "${BASE_URL}/api/v1/repositories" 2>/dev/null || echo "000")
if [ "$setup_st" != "201" ] && [ "$setup_st" != "200" ]; then
  fail "could not create private repository ${REPO_KEY} (status ${setup_st})"
fi
echo "ci-bytes-${RUN_ID}" > "/tmp/zz-1849-artifact.bin"
if api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/${ART_PATH}" "/tmp/zz-1849-artifact.bin" "application/octet-stream" >/dev/null 2>&1; then
  pass "seeded ${REPO_KEY}/${ART_PATH}"
else
  fail "could not upload seed artifact"
fi

begin_test "Anonymous download is denied before any rule"
st=$(anon_download_status)
if [ "$st" = "401" ] || [ "$st" = "404" ]; then
  pass "anonymous download denied (status ${st}) — existence-hiding baseline"
else
  fail "anonymous download of a private repo returned ${st}, expected 401/404"
fi

begin_test "Anonymous read rule with a matching CIDR grants the download"
# The API needs the repository's UUID; resolve it first.
repo_id=$(curl -sf --max-time 10 -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}" 2>/dev/null | jq -r '.id // empty')
if [ -z "$repo_id" ]; then
  fail "could not resolve repository id for ${REPO_KEY}"
fi
created=$(curl -s --max-time 10 -w '\n%{http_code}' \
  -X POST \
  -H "$(auth_header)" \
  -H "Content-Type: application/json" \
  -d "{\"principal_type\":\"anonymous\",\"principal_id\":\"${NIL_UUID}\",\"target_type\":\"repository\",\"target_id\":\"${repo_id}\",\"actions\":[\"read\"],\"conditions\":{\"allowed_cidrs\":[\"0.0.0.0/0\"]}}" \
  "${BASE_URL}/api/v1/permissions" 2>/dev/null)
st=$(echo "$created" | tail -n1)
body=$(echo "$created" | sed '$d')
if [ "$st" != "200" ] && [ "$st" != "201" ]; then
  fail "creating the anonymous read rule returned ${st}: ${body}"
fi
RULE_ID=$(echo "$body" | jq -r '.id // empty')
if [ -z "$RULE_ID" ]; then
  fail "anonymous rule create did not return an id: ${body}"
fi
st=$(anon_download_status)
if [ "$st" = "200" ]; then
  pass "anonymous download granted through the matching rule (status 200)"
else
  fail "anonymous download returned ${st} with a matching anonymous rule in place (#1849)"
fi

begin_test "Narrowing the rule's CIDRs to a non-matching range re-denies"
st=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
  -X PUT \
  -H "$(auth_header)" \
  -H "Content-Type: application/json" \
  -d "{\"principal_type\":\"anonymous\",\"principal_id\":\"${NIL_UUID}\",\"target_type\":\"repository\",\"target_id\":\"${repo_id}\",\"actions\":[\"read\"],\"conditions\":{\"allowed_cidrs\":[\"192.0.2.0/24\"]}}" \
  "${BASE_URL}/api/v1/permissions/${RULE_ID}" 2>/dev/null || echo "000")
if [ "$st" != "200" ]; then
  fail "updating the rule's conditions returned ${st}"
fi
# The listing cache is 30s; wait for invalidation to take effect before
# asserting the denial. The create/update path invalidates synchronously,
# so a short settle is enough.
sleep 2
st=$(anon_download_status)
if [ "$st" = "401" ] || [ "$st" = "404" ]; then
  pass "outside the narrowed CIDRs the download is denied again (status ${st})"
else
  fail "anonymous download returned ${st} after the rule was narrowed to a non-matching CIDR (#1849)"
fi

begin_test "Anonymous rules are read-only (write action rejected)"
st=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
  -X POST \
  -H "$(auth_header)" \
  -H "Content-Type: application/json" \
  -d "{\"principal_type\":\"anonymous\",\"principal_id\":\"${NIL_UUID}\",\"target_type\":\"repository\",\"target_id\":\"${repo_id}\",\"actions\":[\"read\",\"write\"]}" \
  "${BASE_URL}/api/v1/permissions" 2>/dev/null || echo "000")
if [ "$st" = "400" ]; then
  pass "anonymous rule with write action rejected 400"
else
  fail "anonymous rule carrying write returned ${st}, expected 400 (anonymous is a download grant only)"
fi

begin_test "Invalid conditions are rejected at write time"
st=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
  -X POST \
  -H "$(auth_header)" \
  -H "Content-Type: application/json" \
  -d "{\"principal_type\":\"anonymous\",\"principal_id\":\"${NIL_UUID}\",\"target_type\":\"repository\",\"target_id\":\"${repo_id}\",\"actions\":[\"read\"],\"conditions\":{\"allowed_cidrs\":[\"not-a-cidr\"]}}" \
  "${BASE_URL}/api/v1/permissions" 2>/dev/null || echo "000")
if [ "$st" = "400" ]; then
  pass "unparseable CIDR rejected 400"
else
  fail "rule with an unparseable CIDR returned ${st}, expected 400"
fi

api_delete "/api/v1/permissions/${RULE_ID}" >/dev/null 2>&1 || true
api_delete "/api/v1/repositories/${REPO_KEY}" >/dev/null 2>&1 || true
rm -f "/tmp/zz-1849-artifact.bin"

end_suite
