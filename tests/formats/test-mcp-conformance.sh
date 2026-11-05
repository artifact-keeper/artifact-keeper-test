#!/usr/bin/env bash
# test-mcp-conformance.sh - MCP Registry wire conformance (artifact-keeper#5253)
#
# Curl-only, audit lane. Drives the whole server.json corpus in
# tests/fixtures/mcp/server-json through the registry API:
#
#   valid/*.json         published into an `open` repository and read back:
#                        200, served document equal to the submitted one
#                        (packages verbatim), source packagePolicy open
#   invalid/cases.tsv    every vector answers its status and error code as
#                        application/problem+json with Cache-Control:
#                        no-store, never a 5xx
#   own-repos/cases.tsv  the same against an own-repos repository with an npm
#                        Local (echo package published at 1.0.0) and a docker
#                        Local mapped (__OCI_REF__ = <ak-host>/<oci repo>/<image>)
#
# Then: 120 versions of one server walked through /servers with limit=100
# and the rest, and through /versions; unknown query parameters ignored;
# Accept: text/html still answers JSON; trailing-slash behaviour pinned
# (the backend answers the unknown-name 404 for a trailing slash); HEAD on
# the list.
#
# Requires: curl, jq, python3, tar

# shellcheck source=../lib/common.sh disable=SC1091
source "$(dirname "$0")/../lib/common.sh"
# shellcheck source=../lib/mcp-helpers.sh disable=SC1091
source "$(dirname "$0")/../lib/mcp-helpers.sh"

begin_suite "mcp-conformance"
auth_admin
setup_workdir
require_cmd curl
require_cmd jq
require_cmd python3
require_cmd tar
mcp_require_registry

OPEN_KEY="test-mcp-open-${RUN_ID}"
OWN_KEY="test-mcp-own-${RUN_ID}"
WALK_KEY="test-mcp-walk-${RUN_ID}"
NS="io.github.ak-e2e-${RUN_ID}"
ECHO_PKG="ak-e2e-echo-conf-${RUN_ID}"
OCI_HOST=$(printf '%s' "${AK_EXTERNAL_URL:-$BASE_URL}" | sed -E 's#^[A-Za-z]+://##; s#/.*$##')
CORPUS="${MCP_FIXTURES_DIR}/server-json"

# slug FILE: a per-run unique server-name suffix for a corpus file.
slug() {
  local b
  b=$(basename "$1" .json)
  printf 'c-%s-%s' "$RUN_ID" "$b" | cut -c1-120
}

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

begin_test "Create open, own-repos and walk repositories with npm and docker backing"
if ! mcp_create_backing_repos "test-mcp-conf-${RUN_ID}" oci; then
  fail_fatal "could not create backing repositories"
fi
if ! mcp_publish_echo_package "$MCP_NPM_KEY" "$ECHO_PKG" "1.0.0" "${NS}/echo"; then
  fail_fatal "npm publish of ${ECHO_PKG}@1.0.0 returned HTTP ${MCP_STATUS}" "$(mcp_snip)"
fi
mcp_create_repo "$OPEN_KEY" '{"mcp_package_policy":"open"}' || fail_fatal "open repository: ${MCP_CREATE_ERROR}"
mcp_create_repo "$OWN_KEY" "$(jq -cn --argjson m "$(mcp_package_repos_json)" '{mcp_package_policy:"own-repos",mcp_package_repos:$m}')" \
  || fail_fatal "own-repos repository: ${MCP_CREATE_ERROR}"
mcp_create_repo "$WALK_KEY" || fail_fatal "walk repository: ${MCP_CREATE_ERROR}"
pass

# ---------------------------------------------------------------------------
# valid corpus into an open repository
# ---------------------------------------------------------------------------

for f in "${CORPUS}"/valid/*.json; do
  base=$(basename "$f")
  begin_test "valid/${base}: publish to open and read back verbatim"
  out="${WORK_DIR}/valid-${base}"
  s=$(slug "$f")
  mcp_render_fixture "$f" "$out" "SLUG=${s}"
  name=$(jq -r .name "$out")
  version=$(jq -r .version "$out")
  mcp_publish "$OPEN_KEY" "$out"
  if [ "$MCP_STATUS" != "200" ]; then
    fail "publish answered HTTP ${MCP_STATUS}" "$(mcp_snip)"
    continue
  fi
  pub_server=$(jq -S -c '.server' "$MCP_BODY")
  mcp_get "$OPEN_KEY" "$(mcp_version_path "$name" "$version")" anon
  why=""
  [ "$MCP_STATUS" = "200" ] || why="${why} read HTTP ${MCP_STATUS};"
  [ "$(jq -S -c '.server' "$MCP_BODY" 2>/dev/null)" = "$pub_server" ] || why="${why} read .server differs from the publish answer;"
  [ "$(jq -S -c '.' "$out")" = "$pub_server" ] || why="${why} served document differs from the submitted one;"
  [ "$(jq -S -c '.packages // null' "$out")" = "$(jq -S -c '.server.packages // null' "$MCP_BODY")" ] || why="${why} packages not verbatim;"
  [ "$(mcp_json '._meta["com.artifactkeeper.registry/source"].packagePolicy')" = "open" ] || why="${why} source.packagePolicy='$(mcp_json '._meta["com.artifactkeeper.registry/source"].packagePolicy')';"
  [ "$(mcp_header content-type)" = "application/json" ] || why="${why} content-type='$(mcp_header content-type)';"
  if [ -z "$why" ]; then
    pass
  else
    fail "${base}:${why}" "submitted: $(jq -S -c . "$out" | head -c 400)
served: $(jq -S -c .server "$MCP_BODY" 2>/dev/null | head -c 400)"
  fi
done

# ---------------------------------------------------------------------------
# Refusal corpora
# ---------------------------------------------------------------------------

# run_cases REPO CASES_TSV LABEL KEY=VALUE...: one test per vector.
run_cases() {
  local repo="$1" tsv="$2" label="$3"
  shift 3
  local file want code out r
  while IFS=$'\t' read -r file want code; do
    case "$file" in ''|'#'*) continue ;; esac
    begin_test "${label}/${file}: ${want} ${code}"
    out="${WORK_DIR}/${label}-${file}"
    mcp_render_fixture "$(dirname "$tsv")/${file}" "$out" "SLUG=$(slug "$file")" "$@"
    mcp_publish "$repo" "$out"
    if [ "${MCP_STATUS:0:1}" = "5" ] || [ "$MCP_STATUS" = "000" ]; then
      fail "server error or no answer: HTTP ${MCP_STATUS}" "$(mcp_snip)"
    elif r=$(mcp_check_problem "$want" "$code"); then
      pass
    else
      fail "$r"
    fi
  done < "$tsv"
}

run_cases "$OPEN_KEY" "${CORPUS}/invalid/cases.tsv" invalid
run_cases "$OWN_KEY" "${CORPUS}/own-repos/cases.tsv" own-repos \
  "NPM_PKG=${ECHO_PKG}" "AK_BASE=${BASE_URL}" "OCI_REF=${OCI_HOST}/${MCP_OCI_KEY}/echo-image"

begin_test "own-repos: a valid npm entry resolves (corpus sanity)"
mcp_server_json "${NS}/echo" "1.0.0" "$(mcp_npm_package_json "$ECHO_PKG" "1.0.0")" > "${WORK_DIR}/own-ok.json"
mcp_publish "$OWN_KEY" "${WORK_DIR}/own-ok.json"
if [ "$MCP_STATUS" = "200" ] && [ "$(mcp_url_path "$(mcp_json '.server.packages[0].registryBaseUrl // empty')")" = "/npm/${MCP_NPM_KEY}" ] \
   && [ "$(mcp_json '._meta["com.artifactkeeper.registry/source"].packagePolicy')" = "own-repos" ]; then
  pass
else
  fail "HTTP ${MCP_STATUS}" "$(mcp_snip)"
fi

begin_test "open: the same npm entry is served verbatim (no registryBaseUrl added)"
mcp_server_json "${NS}/echo-open" "1.0.0" "$(mcp_npm_package_json "$ECHO_PKG" "1.0.0")" > "${WORK_DIR}/open-npm.json"
mcp_publish "$OPEN_KEY" "${WORK_DIR}/open-npm.json"
if [ "$MCP_STATUS" = "200" ] && [ "$(jq -S -c .packages "${WORK_DIR}/open-npm.json")" = "$(jq -S -c .server.packages "$MCP_BODY")" ] \
   && [ -z "$(mcp_json '.server.packages[0].registryBaseUrl // empty')" ]; then
  pass
else
  fail "HTTP ${MCP_STATUS}" "$(mcp_snip)"
fi

# ---------------------------------------------------------------------------
# 120 versions
# ---------------------------------------------------------------------------

WALK="${NS}/walk"
begin_test "Publish 120 versions of one server"
why=""
for i in $(seq 1 120); do
  mcp_server_json "$WALK" "1.0.${i}" "" "$(mcp_remote_json "https://mcp.example.invalid/mcp")" > "${WORK_DIR}/walk.json"
  mcp_publish "$WALK_KEY" "${WORK_DIR}/walk.json"
  [ "$MCP_STATUS" = "200" ] || { why="1.0.${i}: HTTP ${MCP_STATUS} $(mcp_snip)"; break; }
done
if [ -z "$why" ]; then pass; else fail_fatal "$why"; fi

expected_order=$(for i in $(seq 1 120); do printf '1.0.%s\n' "$i"; done | LC_ALL=C sort | paste -sd, -)

begin_test "/servers walked with limit=100 then the rest"
mcp_get "$WALK_KEY" "servers?limit=100" anon
p1=$(mcp_json '.metadata.count')
c1=$(mcp_json '.metadata.nextCursor // empty')
v1=$(jq -r '[.servers[].server.version] | join(",")' "$MCP_BODY")
p2=""; c2=""; v2=""
if [ -n "$c1" ]; then
  mcp_get "$WALK_KEY" "servers?limit=100&cursor=$(jq -rn --arg v "$c1" '$v|@uri')" anon
  p2=$(mcp_json '.metadata.count')
  c2=$(mcp_json '.metadata.nextCursor // empty')
  v2=$(jq -r '[.servers[].server.version] | join(",")' "$MCP_BODY")
fi
if [ "$p1" = "100" ] && [ -n "$c1" ] && [ "$p2" = "20" ] && [ -z "$c2" ] && [ "${v1},${v2}" = "$expected_order" ]; then
  pass
else
  fail "page1 count=${p1} cursor='${c1:0:20}'; page2 count=${p2} cursor='${c2}'; order matches=$([ "${v1},${v2}" = "$expected_order" ] && echo yes || echo no)"
fi

begin_test "/versions answers all 120 in text order, no cursor, limit ignored"
# Pinned to the backend: /versions is not paged (at most the newest 1000
# versions) and ignores `limit`, as upstream's /versions does.
mcp_get "$WALK_KEY" "servers/$(mcp_encode_name "$WALK")/versions" anon
a_count=$(mcp_json '.metadata.count')
a_next=$(mcp_json '.metadata.nextCursor // empty')
a_order=$(jq -r '[.servers[].server.version] | join(",")' "$MCP_BODY")
a_latest=$(jq -r '[.servers[] | select(._meta["io.modelcontextprotocol.registry/official"].isLatest) | .server.version] | join(",")' "$MCP_BODY")
mcp_get "$WALK_KEY" "servers/$(mcp_encode_name "$WALK")/versions?limit=100" anon
b_count=$(mcp_json '.metadata.count')
if [ "$a_count" = "120" ] && [ -z "$a_next" ] && [ "$a_order" = "$expected_order" ] && [ "$a_latest" = "1.0.120" ] && [ "$b_count" = "120" ]; then
  pass
else
  fail "count=${a_count} nextCursor='${a_next}' isLatest='${a_latest}' limit=100 count=${b_count} order matches=$([ "$a_order" = "$expected_order" ] && echo yes || echo no)"
fi

# ---------------------------------------------------------------------------
# Request handling
# ---------------------------------------------------------------------------

begin_test "Unknown query parameters are ignored"
mcp_get "$WALK_KEY" "servers?limit=5" anon
want=$(cat "$MCP_BODY")
mcp_get "$WALK_KEY" "servers?limit=5&frobnicate=1&page=9&sort=desc" anon
if [ "$MCP_STATUS" = "200" ] && [ "$(cat "$MCP_BODY")" = "$want" ]; then
  pass
else
  fail "HTTP ${MCP_STATUS}; body differs=$([ "$(cat "$MCP_BODY")" = "$want" ] && echo no || echo yes)" "$(mcp_snip)"
fi

begin_test "Accept: text/html still answers JSON"
mcp_req GET "$(mcp_base "$WALK_KEY")/servers?limit=1" anon -H "Accept: text/html"
if [ "$MCP_STATUS" = "200" ] && [ "$(mcp_header content-type)" = "application/json" ] && jq -e '.servers | length == 1' "$MCP_BODY" >/dev/null 2>&1; then
  pass
else
  fail "HTTP ${MCP_STATUS} content-type '$(mcp_header content-type)'" "$(mcp_snip)"
fi

begin_test "Trailing slash answers the unknown-name 404 (pinned)"
why=""
for tail in "servers/" "servers/$(mcp_encode_name "$WALK")/versions/" "$(mcp_version_path "$WALK" "1.0.1")/" "ping/"; do
  mcp_get "$WALK_KEY" "$tail" anon
  r=$(mcp_check_plain_404) || why="${why} ${tail}: ${r};"
done
if [ -z "$why" ]; then pass; else fail "trailing slash:${why}"; fi

begin_test "HEAD on the list answers 200 with the GET headers"
_mcp_new_resp
st=$(curl -s -I -o "$MCP_HDRS" -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" "$(mcp_base "$WALK_KEY")/servers" 2>/dev/null) || st="000"
if [ "$st" = "200" ] && [ "$(mcp_header content-type)" = "application/json" ] && [ "$(mcp_header access-control-allow-origin)" = "*" ]; then
  pass
else
  fail "HEAD HTTP ${st} content-type '$(mcp_header content-type)'"
fi

end_suite
