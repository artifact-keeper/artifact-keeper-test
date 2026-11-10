#!/usr/bin/env bash
# test-mcp-ssrf-no-probe.sh - Artifact Keeper never dereferences a URL in a
# server.json (artifact-keeper#5253 threat T6; docs/mcp-registry.md
# "Security notes": publish, list and read are database and object-storage
# operations only).
#
# Two runner-hosted mocks listen on MOCK_UPSTREAM_HOSTNAME (an address the
# backend can reach): the streamable-HTTP MCP mock
# (tests/lib/mock-mcp-http-server.py) and the generic byte mock
# (tests/lib/mock-upstream.py). A server is published whose remotes[].url,
# a remote URL variable default, websiteUrl, icons[].src and repository.url
# all point at them; an `open` repository additionally accepts an npm
# registryBaseUrl at the generic mock (the package resolves in the mapped npm
# repository and is served at its Artifact Keeper coordinates, so the mock URL
# is replaced, never fetched; artifact-keeper#5452), and an own-repos publish
# naming that registryBaseUrl is refused (422) without a lookup. Then every
# read and write route is exercised as admin and as anonymous. Both mocks must
# record zero requests.
#
# Metadata addresses: remotes[] also carries
# http://169.254.169.254/latest/meta-data/. The official schema allows any
# absolute http(s) URL, so the publish is accepted. This suite can only
# observe the runner-hosted mocks: it cannot see whether the backend dialled
# 169.254.169.254 (on a runner without a metadata service the dial would just
# fail). The mock counters are the evidence that no URL in the document is
# dialled; the metadata entry pins that such a document is stored and served
# as data.
#
# Discriminating control: the runner itself requests each mock once before
# the exercise, and the counters must move, so "zero" means "nothing called"
# rather than "the counter is broken".

# shellcheck source=../lib/common.sh disable=SC1091
source "$(dirname "$0")/../lib/common.sh"
# shellcheck source=../lib/mcp-helpers.sh disable=SC1091
source "$(dirname "$0")/../lib/mcp-helpers.sh"

begin_suite "mcp-ssrf-no-probe"
auth_admin
setup_workdir
require_cmd curl
require_cmd jq
require_cmd python3
mcp_require_registry
mcp_require_dialback

KEY="sec-mcpssrf-${RUN_ID}"
OPEN_KEY="sec-mcpssrf-open-${RUN_ID}"
NAME="io.github.ak-e2e/ssrf-${RUN_ID}"
NPM_PKG="@ak-e2e/ssrf-${RUN_ID}"
METADATA_URL="http://169.254.169.254/latest/meta-data/"

expect_problem() {
  local why
  if why=$(mcp_check_problem "$1" "$2"); then
    pass
  else
    fail "$3: ${why}"
  fi
}

# generic_count: total requests the generic mock logged.
generic_count() {
  if [ -f "${MOCK_STATE_DIR}/request-log.txt" ]; then
    wc -l < "${MOCK_STATE_DIR}/request-log.txt" | tr -d ' '
  else
    echo 0
  fi
}

begin_test "Start the MCP HTTP mock and the generic mock on the runner"
if start_mock_mcp_http "${WORK_DIR}/mcp-http" && start_mock_upstream "${WORK_DIR}/generic"; then
  GEN_URL="http://$(mcp_mock_host):${MOCK_PORT}"
  pass
else
  fail_fatal "a mock did not start"
fi

begin_test "Control: the runner's own requests are counted by both mocks"
curl -s -o /dev/null --max-time 5 "${MCP_HTTP_LOCAL_URL%/mcp}/control" || true
curl -s -o /dev/null --max-time 5 "${MOCK_LOCAL_URL}/control" || true
HTTP_BASE=$(mcp_http_count)
GEN_BASE=$(generic_count)
if [ "$HTTP_BASE" -ge 1 ] && [ "$GEN_BASE" -ge 1 ]; then
  pass
else
  fail_fatal "mock counters did not move on a direct request (mcp-http ${HTTP_BASE}, generic ${GEN_BASE})" \
    "Without working counters the zero-request assertion below would be vacuous."
fi

# `open` accepts foreign coordinates only for a package that resolves in a
# mapped backing repository (artifact-keeper#5452), so the open repository
# maps an npm Local holding the package its document names.
begin_test "Create the backing npm repository and publish the echo package to it"
if mcp_create_backing_repos "sec-mcpssrf-${RUN_ID}" \
  && mcp_publish_echo_package "$MCP_NPM_KEY" "$NPM_PKG" 1.0.0 "$NAME"; then
  pass
else
  fail_fatal "backing npm setup failed: HTTP ${MCP_STATUS:-}: $(mcp_snip)"
fi

begin_test "Create own-repos and open (npm mapped) MCP repositories"
if mcp_create_repo "$KEY" \
  && mcp_create_repo "$OPEN_KEY" "$(jq -cn --arg n "$MCP_NPM_KEY" '{mcp_package_policy:"open",mcp_package_repos:{npm:$n}}')"; then
  pass
else
  fail_fatal "MCP repository creation failed: ${MCP_CREATE_ERROR:-}"
fi

DOC="${WORK_DIR}/ssrf.json"
jq -n --arg s "$MCP_SCHEMA_URL" --arg n "$NAME" --arg mcp "$MCP_HTTP_URL" \
  --arg gen "$GEN_URL" --arg hostport "$(mcp_mock_host):${MCP_HTTP_PORT}" --arg md "$METADATA_URL" '{
  "$schema": $s, name: $n, version: "1.0.0",
  description: "SSRF no-probe fixture",
  websiteUrl: ($gen + "/website"),
  repository: {url: ($gen + "/repository"), source: "github"},
  icons: [{src: ($gen + "/icon.png"), mimeType: "image/png"}],
  remotes: [
    {type: "streamable-http", url: $mcp},
    {type: "streamable-http", url: "http://{endpoint}/mcp",
     variables: {endpoint: {description: "MCP endpoint host:port", default: $hostport}}},
    {type: "sse", url: ($gen + "/sse")},
    {type: "streamable-http", url: $md}
  ]}' > "$DOC"

begin_test "Publish a server whose every URL points at the mocks and the metadata address (200)"
mcp_publish "$KEY" "$DOC"
if [ "$MCP_STATUS" = "200" ] && [ "$(mcp_json '[.server.remotes[].url] | index("'"$METADATA_URL"'") != null')" = "true" ]; then
  pass
else
  fail "publish of the URL-laden server: HTTP ${MCP_STATUS}: $(mcp_snip)"
fi

begin_test "Publish a second version (1.0.1) and an open-repository copy with an npm registryBaseUrl at the mock"
jq '.version = "1.0.1"' "$DOC" > "${WORK_DIR}/ssrf-101.json"
mcp_publish "$KEY" "${WORK_DIR}/ssrf-101.json"
s1="$MCP_STATUS"
jq --arg gen "$GEN_URL" --arg pkg "$NPM_PKG" '.packages = [{registryType:"npm", registryBaseUrl: ($gen + "/npm"),
  identifier: $pkg, version: "1.0.0", transport: {type: "stdio"}}]' "$DOC" > "${WORK_DIR}/ssrf-open.json"
mcp_publish "$OPEN_KEY" "${WORK_DIR}/ssrf-open.json"
s2="$MCP_STATUS"
open_base=$(mcp_json '.server.packages[0].registryBaseUrl')
if [ "$s1" = "200" ] && [ "$s2" = "200" ] && [ "$(mcp_url_path "$open_base")" = "/npm/${MCP_NPM_KEY}" ]; then
  pass
else
  fail "second publishes: own-repos ${s1}, open ${s2} (registryBaseUrl '${open_base}', want /npm/${MCP_NPM_KEY}): $(mcp_snip)"
fi

begin_test "own-repos refuses the mock registryBaseUrl (422) by lookup, not by fetch"
jq '.version = "2.0.0"' "${WORK_DIR}/ssrf-open.json" > "${WORK_DIR}/ssrf-own-pkg.json"
mcp_publish "$KEY" "${WORK_DIR}/ssrf-own-pkg.json"
expect_problem 422 mcp_external_registry "own-repos publish naming the mock registry"

# ---------------------------------------------------------------------------
# Exercise every route, admin and anonymous
# ---------------------------------------------------------------------------

begin_test "Exercise list, search, detail, versions, latest, status PATCH and repository reads"
ENC=$(mcp_encode_name "$NAME")
bad=""
for repo in "$KEY" "$OPEN_KEY"; do
  for who in admin anon; do
    for api in v0.1 v0; do
      for tail in "servers" "servers?search=ssrf-${RUN_ID}" "servers?version=latest" \
                  "servers/${ENC}/versions" "servers/${ENC}/versions/1.0.0" \
                  "servers/${ENC}/versions/latest" "servers/${NAME}/versions/1.0.0" \
                  "servers?updated_since=2000-01-01T00:00:00Z"; do
        mcp_req GET "${BASE_URL}/mcp/${repo}/${api}/${tail}" "$who"
        [ "$MCP_STATUS" = "200" ] || bad="${bad} ${who}:${repo}:${api}/${tail}=${MCP_STATUS}"
      done
    done
  done
done
for who in admin anon; do
  mcp_patch_status "$KEY" "$NAME" 1.0.0 deprecated "probe check" "$who" || true
  [ "$who" = "admin" ] && [ "$MCP_STATUS" != "200" ] && bad="${bad} admin:patch-version=${MCP_STATUS}"
  [ "$who" = "anon" ] && [ "$MCP_STATUS" != "401" ] && bad="${bad} anon:patch-version=${MCP_STATUS}"
  mcp_patch_status "$KEY" "$NAME" "" active "" "$who" || true
  [ "$who" = "admin" ] && [ "$MCP_STATUS" != "200" ] && bad="${bad} admin:patch-all=${MCP_STATUS}"
  [ "$who" = "anon" ] && [ "$MCP_STATUS" != "401" ] && bad="${bad} anon:patch-all=${MCP_STATUS}"
  for path in "/api/v1/repositories/${KEY}" "/api/v1/repositories/${KEY}/artifacts?per_page=50" "/api/v1/repositories/${OPEN_KEY}"; do
    mcp_req GET "${BASE_URL}${path}" "$who"
    [ "$MCP_STATUS" = "200" ] || bad="${bad} ${who}:${path}=${MCP_STATUS}"
  done
done
if [ -z "$bad" ]; then
  pass
else
  fail "some exercise requests did not answer as expected:${bad}" \
    "The zero-request verdict below only means something if the routes actually served the document."
fi

begin_test "The served document still names the mock URLs (they were stored as data)"
mcp_get "$KEY" "servers/${ENC}/versions/1.0.0" anon
if [ "$(mcp_json '.server.websiteUrl')" = "${GEN_URL}/website" ] \
  && [ "$(mcp_json '.server.remotes[0].url')" = "$MCP_HTTP_URL" ] \
  && [ "$(mcp_json '.server.icons[0].src')" = "${GEN_URL}/icon.png" ]; then
  pass
else
  fail "served URLs differ from the published ones: $(mcp_snip)"
fi

# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------

# no_new_requests: the counters stay at the control baseline for 4 seconds
# (async work started by a publish or read would land within that window).
begin_test "Neither mock received a request from the backend"
moved=""
for _ in $(seq 1 16); do
  h=$(mcp_http_count)
  g=$(generic_count)
  if [ "$h" != "$HTTP_BASE" ] || [ "$g" != "$GEN_BASE" ]; then
    moved="mcp-http ${HTTP_BASE}->${h}, generic ${GEN_BASE}->${g}"
    break
  fi
  sleep 0.25
done
if [ -z "$moved" ]; then
  pass
else
  fail "the backend dereferenced a server.json URL (${moved})" \
    "mcp-http log: $(tail -5 "${MCP_HTTP_STATE_DIR}/request-log.txt" 2>/dev/null | tr '\n' ' ') generic log: $(tail -5 "${MOCK_STATE_DIR}/request-log.txt" 2>/dev/null | tr '\n' ' ')"
fi

end_suite
