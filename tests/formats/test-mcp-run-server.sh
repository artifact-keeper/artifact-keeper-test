#!/usr/bin/env bash
# test-mcp-run-server.sh - resolve an MCP server from an Artifact Keeper MCP
# registry and run it, the way an agent host does (artifact-keeper#5253).
#
# stdio leg:
#   1. publish the zero-dependency echo server (tests/fixtures/mcp/echo-server)
#      to an npm Local
#   2. publish a server.json naming it to an own-repos MCP repository
#   3. resolve like a client: GET .../versions/latest, take packages[0]
#      (identifier, version, the served registryBaseUrl)
#   4. `npm install --registry <served registryBaseUrl>` into a clean client
#      directory with its own .npmrc
#   5. launch the installed bin over stdio with tests/lib/mcp-stdio-client.py:
#      tools/list has `echo`, tools/call echo returns the text sent
#
# streamable-http leg: a remote-only server whose remotes[0].url is the
# runner-hosted mock MCP server (tests/lib/mock-mcp-http-server.py). The URL
# is resolved from the registry and called from the runner. The mock's
# foreign-count (requests not sent by the test client) must stay 0 after
# publish, list and detail: Artifact Keeper never dials remotes[].url.
#
# Inspector lane (optional, AK_TEST_MCP_INSPECTOR=1): the official MCP
# Inspector CLI, pinned, lists the tools of the installed server and of the
# remote. Needs the public npm registry; otherwise a per-test skip.
#
# Requires: node, npm, python3, jq, curl, tar

# shellcheck source=../lib/common.sh disable=SC1091
source "$(dirname "$0")/../lib/common.sh"
# shellcheck source=../lib/mcp-helpers.sh disable=SC1091
source "$(dirname "$0")/../lib/mcp-helpers.sh"

begin_suite "mcp-run-server"
auth_admin
setup_workdir
require_cmd node
require_cmd npm
require_cmd python3
require_cmd jq
require_cmd curl
require_cmd tar
mcp_require_registry

MCP_KEY="test-mcp-run-${RUN_ID}"
NS="io.github.ak-e2e-${RUN_ID}"
SERVER="${NS}/echo"
REMOTE_SERVER="${NS}/echo-remote"
ECHO_PKG="ak-e2e-echo-run-${RUN_ID}"
PING="ping-${RUN_ID}"
# Pinned MCP Inspector (published 2026-10-14 on registry.npmjs.org).
MCP_INSPECTOR_VERSION="${MCP_INSPECTOR_VERSION:-2.11.0}"
CLIENT_DIR="${WORK_DIR}/client"
mkdir -p "$CLIENT_DIR"

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

begin_test "Create npm backing repository and publish the echo package"
if ! mcp_create_backing_repos "test-mcp-run-${RUN_ID}"; then
  fail_fatal "could not create the npm backing repository"
fi
if mcp_publish_echo_package "$MCP_NPM_KEY" "$ECHO_PKG" "1.0.0" "$SERVER"; then
  pass
else
  fail_fatal "npm publish of ${ECHO_PKG}@1.0.0 returned HTTP ${MCP_STATUS}" "$(mcp_snip)"
fi

begin_test "Create MCP repository (own-repos, npm mapped)"
if mcp_create_repo "$MCP_KEY" "$(jq -cn --argjson m "$(mcp_package_repos_json)" '{mcp_package_repos:$m}')"; then
  pass
else
  fail_fatal "could not create MCP repository: ${MCP_CREATE_ERROR}"
fi

begin_test "Publish server.json naming the echo package"
mcp_server_json "$SERVER" "1.0.0" "$(mcp_npm_package_json "$ECHO_PKG" "1.0.0")" > "${WORK_DIR}/server.json"
mcp_publish "$MCP_KEY" "${WORK_DIR}/server.json"
if [ "$MCP_STATUS" = "200" ]; then
  pass
else
  fail_fatal "publish returned HTTP ${MCP_STATUS}, expected 200" "$(mcp_snip)"
fi

# ---------------------------------------------------------------------------
# stdio leg
# ---------------------------------------------------------------------------

begin_test "Resolve the server from the registry (versions/latest -> packages[0])"
mcp_get "$MCP_KEY" "servers/$(mcp_encode_name "$SERVER")/versions/latest" anon
R_TYPE=$(mcp_json '.server.packages[0].registryType // empty')
R_ID=$(mcp_json '.server.packages[0].identifier // empty')
R_VER=$(mcp_json '.server.packages[0].version // empty')
R_BASE=$(mcp_json '.server.packages[0].registryBaseUrl // empty')
R_TRANSPORT=$(mcp_json '.server.packages[0].transport.type // empty')
if [ "$MCP_STATUS" = "200" ] && [ "$R_TYPE" = "npm" ] && [ "$R_ID" = "$ECHO_PKG" ] && [ "$R_VER" = "1.0.0" ] \
   && [ "$R_TRANSPORT" = "stdio" ] && [ "$(mcp_url_path "${R_BASE%/}")" = "/npm/${MCP_NPM_KEY}" ]; then
  echo "  resolved: npm ${R_ID}@${R_VER} from ${R_BASE}"
  pass
else
  fail_fatal "resolve: HTTP ${MCP_STATUS} type='${R_TYPE}' identifier='${R_ID}' version='${R_VER}' registryBaseUrl='${R_BASE}' transport='${R_TRANSPORT}'" "$(mcp_snip)"
fi

begin_test "npm install from the served registryBaseUrl"
NPM_REGISTRY="${R_BASE%/}/"
AUTH_B64=$(printf '%s:%s' "$ADMIN_USER" "$ADMIN_PASS" | base64 | tr -d '\n')
REG_NOPROTO=$(printf '%s' "$NPM_REGISTRY" | sed -E 's|^https?:||')
cat > "${CLIENT_DIR}/.npmrc" <<EOF
registry=${NPM_REGISTRY}
${REG_NOPROTO}:_auth=${AUTH_B64}
${REG_NOPROTO%/}/:_auth=${AUTH_B64}
always-auth=true
EOF
printf '{"name":"ak-e2e-mcp-client","version":"0.0.0","private":true}\n' > "${CLIENT_DIR}/package.json"
NPM_LOG="${WORK_DIR}/npm-install.log"
if (cd "$CLIENT_DIR" && timeout 180 npm install --no-audit --no-fund --no-package-lock \
      --userconfig "${CLIENT_DIR}/.npmrc" --cache "${WORK_DIR}/npm-cache" \
      --registry "$NPM_REGISTRY" "${R_ID}@${R_VER}") > "$NPM_LOG" 2>&1; then
  SERVER_JS="${CLIENT_DIR}/node_modules/${R_ID}/bin/server.js"
  if [ -f "$SERVER_JS" ] && [ "$(jq -r .version "${CLIENT_DIR}/node_modules/${R_ID}/package.json")" = "$R_VER" ]; then
    pass
  else
    fail_fatal "npm install succeeded but ${SERVER_JS} is missing or the wrong version" "$(tail -20 "$NPM_LOG")"
  fi
else
  fail_fatal "npm install ${R_ID}@${R_VER} from ${NPM_REGISTRY} failed" "$(tail -30 "$NPM_LOG")"
fi

begin_test "Installed server answers tools/list and tools/call over stdio"
OUT="${WORK_DIR}/stdio-client.json"
if mcp_client --timeout 15 --call "echo={\"text\":\"${PING}\"}" -- node "$SERVER_JS" > "$OUT" 2> "${WORK_DIR}/stdio-client.err"; then
  names=$(jq -r '.toolNames | join(",")' "$OUT" 2>/dev/null)
  text=$(jq -r '.calls[0].text // empty' "$OUT" 2>/dev/null)
  sv=$(jq -r '.serverInfo.version // empty' "$OUT" 2>/dev/null)
  if [[ ",${names}," == *",echo,"* ]] && [ "$text" = "$PING" ] && [ "$sv" = "$R_VER" ]; then
    pass
  else
    fail "tools='${names}' echo text='${text}' serverInfo.version='${sv}'" "$(head -c 800 "$OUT")"
  fi
else
  fail "mcp client failed (rc=$?)" "$(head -c 400 "$OUT"; head -c 400 "${WORK_DIR}/stdio-client.err")"
fi

begin_test "Installed bin launches as the package declares"
if [ -x "${CLIENT_DIR}/node_modules/.bin/ak-e2e-echo-mcp" ] \
   && mcp_client --timeout 15 --call "echo={\"text\":\"bin-${PING}\"}" -- "${CLIENT_DIR}/node_modules/.bin/ak-e2e-echo-mcp" > "$OUT" 2>/dev/null \
   && [ "$(jq -r '.calls[0].text // empty' "$OUT")" = "bin-${PING}" ]; then
  pass
else
  fail "node_modules/.bin/ak-e2e-echo-mcp missing or did not answer" "$(head -c 400 "$OUT" 2>/dev/null)"
fi

# ---------------------------------------------------------------------------
# streamable-http leg
# ---------------------------------------------------------------------------

begin_test "Start the mock streamable-http MCP server"
if start_mock_mcp_http "${WORK_DIR}/mock-http"; then
  pass
else
  fail_fatal "mock MCP HTTP server did not start" "$(head -c 400 "${WORK_DIR}/mock-mcp-http.err" 2>/dev/null)"
fi

begin_test "Publish a remote-only server pointing at the mock"
mcp_server_json "$REMOTE_SERVER" "1.0.0" "" "$(mcp_remote_json "$MCP_HTTP_URL")" > "${WORK_DIR}/remote.json"
mcp_publish "$MCP_KEY" "${WORK_DIR}/remote.json"
if [ "$MCP_STATUS" = "200" ]; then
  pass
else
  fail_fatal "publish returned HTTP ${MCP_STATUS}" "$(mcp_snip)"
fi

begin_test "Resolve remotes[0].url from the registry (list and detail)"
mcp_get "$MCP_KEY" "servers" anon
l_url=$(jq -r --arg n "$REMOTE_SERVER" '[.servers[] | select(.server.name == $n)][0].server.remotes[0].url // empty' "$MCP_BODY" 2>/dev/null)
mcp_get "$MCP_KEY" "servers/$(mcp_encode_name "$REMOTE_SERVER")/versions/latest" anon
RESOLVED_URL=$(mcp_json '.server.remotes[0].url // empty')
r_type=$(mcp_json '.server.remotes[0].type // empty')
if [ "$MCP_STATUS" = "200" ] && [ "$RESOLVED_URL" = "$MCP_HTTP_URL" ] && [ "$l_url" = "$MCP_HTTP_URL" ] && [ "$r_type" = "streamable-http" ]; then
  pass
else
  fail "detail HTTP ${MCP_STATUS} url='${RESOLVED_URL}' type='${r_type}'; list url='${l_url}'; published '${MCP_HTTP_URL}'"
fi

begin_test "Artifact Keeper never dialed remotes[].url (foreign-count 0 after publish, list, detail)"
foreign=$(mcp_http_count foreign-count)
total=$(mcp_http_count request-count)
if [ "$foreign" = "0" ]; then
  pass
else
  fail "mock saw ${foreign} foreign request(s) (${total} total) before any client call"
fi

begin_test "Resolved remote answers tools/list and tools/call over streamable HTTP"
CALL_URL="$RESOLVED_URL"
# The served URL names the backend-facing address; when that is
# MOCK_UPSTREAM_HOSTNAME, call the same server through loopback.
if [ -n "${MOCK_UPSTREAM_HOSTNAME:-}" ] && [ "$RESOLVED_URL" = "$MCP_HTTP_URL" ]; then
  CALL_URL="$MCP_HTTP_LOCAL_URL"
fi
HOUT="${WORK_DIR}/http-client.json"
if mcp_client --transport http --url "$CALL_URL" --timeout 15 --call "echo={\"text\":\"${PING}\"}" > "$HOUT" 2> "${WORK_DIR}/http-client.err"; then
  names=$(jq -r '.toolNames | join(",")' "$HOUT" 2>/dev/null)
  text=$(jq -r '.calls[0].text // empty' "$HOUT" 2>/dev/null)
  if [[ ",${names}," == *",echo,"* ]] && [ "$text" = "$PING" ]; then
    pass
  else
    fail "tools='${names}' echo text='${text}'" "$(head -c 800 "$HOUT")"
  fi
else
  fail "http mcp client failed against ${CALL_URL}" "$(head -c 400 "$HOUT"; head -c 400 "${WORK_DIR}/http-client.err")"
fi

begin_test "foreign-count still 0 after the client calls"
foreign=$(mcp_http_count foreign-count)
if [ "$foreign" = "0" ] && [ "$(mcp_http_count request-count)" -gt 0 ]; then
  pass
else
  fail "foreign-count=${foreign} request-count=$(mcp_http_count request-count)"
fi

# ---------------------------------------------------------------------------
# Inspector lane (optional)
# ---------------------------------------------------------------------------

inspector() {
  timeout 180 npx --yes --registry https://registry.npmjs.org --userconfig "${WORK_DIR}/inspector.npmrc" \
    --cache "${WORK_DIR}/npm-cache-inspector" \
    "@modelcontextprotocol/inspector@${MCP_INSPECTOR_VERSION}" --cli "$@"
}
: > "${WORK_DIR}/inspector.npmrc"

begin_test "MCP Inspector ${MCP_INSPECTOR_VERSION} lists the installed server's tools (stdio)"
if [ "${AK_TEST_MCP_INSPECTOR:-0}" != "1" ]; then
  skip "inspector lane disabled (AK_TEST_MCP_INSPECTOR unset)"
else
  if inspector node "$SERVER_JS" --method tools/list > "${WORK_DIR}/insp-stdio.out" 2> "${WORK_DIR}/insp-stdio.err" \
     && jq -e '[.tools[].name] | index("echo") != null' "${WORK_DIR}/insp-stdio.out" >/dev/null 2>&1; then
    pass
  else
    fail "inspector stdio tools/list did not list echo" "$(head -c 600 "${WORK_DIR}/insp-stdio.out"; head -c 400 "${WORK_DIR}/insp-stdio.err")"
  fi
fi

begin_test "MCP Inspector ${MCP_INSPECTOR_VERSION} lists the remote's tools (streamable HTTP)"
if [ "${AK_TEST_MCP_INSPECTOR:-0}" != "1" ]; then
  skip "inspector lane disabled (AK_TEST_MCP_INSPECTOR unset)"
else
  if inspector "$CALL_URL" --transport http --method tools/list > "${WORK_DIR}/insp-http.out" 2> "${WORK_DIR}/insp-http.err" \
     && jq -e '[.tools[].name] | index("echo") != null' "${WORK_DIR}/insp-http.out" >/dev/null 2>&1; then
    pass
  else
    fail "inspector http tools/list did not list echo" "$(head -c 600 "${WORK_DIR}/insp-http.out"; head -c 400 "${WORK_DIR}/insp-http.err")"
  fi
fi

end_suite
