#!/usr/bin/env bash
# test-mcp.sh - MCP Registry repository E2E test (artifact-keeper#5253)
#
# A Local `mcp` repository is a private MCP registry: it speaks the registry
# API v0.1 (and the /v0 alias) at
#
#   ${BASE_URL}/mcp/<repo>/v0.1/...
#
# and stores server.json documents (schema 2025-12-11). Under the default
# package policy (own-repos) every packages[] entry must name a package this
# instance already hosts, here an npm Local mapped through mcp_package_repos.
#
# Covered:
#   - curl publish: 200 with {server, _meta} as served, official status
#     active, isLatest, com.artifactkeeper.registry/source, npm
#     registryBaseUrl rewritten to the backing repository
#   - the real mcp-publisher (pinned, checksummed): publish and status
#     deprecate with an Artifact Keeper API token in token.json
#   - the recorded publisher wire (tests/fixtures/mcp/publisher-wire.txt)
#     replayed with curl, so a publisher bump that changes its requests fails
#     here; POST /v0/validate is Phase 2 and is a per-test skip until mounted
#   - /v0 alias bodies identical to /v0.1
#   - listing: version text order, versions/latest, version=latest, cursor
#     paging, limit default/clamp/400s, search length and case, updated_since
#     with include_deleted=false, garbage cursor
#   - encoded and literal-slash server names
#   - 409 on republish of identical bytes, stored document unchanged
#   - status: deprecated with statusMessage, deleted hidden from list and
#     latest, include_deleted=true, deleted exact read 404 plain, PATCH of all
#     versions
#   - own-repos 422s (external registryBaseUrl, unknown package)
#   - generic artifact upload refused with 400, artifact listing path
#   - ping/health/version, CORS on GET and preflight, nosniff
#   - private repository: anonymous read is 401 problem+json with the
#     WWW-Authenticate challenge
#
# Requires: curl, jq, python3, tar

# shellcheck source=../lib/common.sh disable=SC1091
source "$(dirname "$0")/../lib/common.sh"
# shellcheck source=../lib/mcp-helpers.sh disable=SC1091
source "$(dirname "$0")/../lib/mcp-helpers.sh"

begin_suite "mcp"
auth_admin
setup_workdir
require_cmd curl
require_cmd jq
require_cmd python3
require_cmd tar
mcp_require_registry

MCP_KEY="test-mcp-${RUN_ID}"
LIST_KEY="test-mcp-list-${RUN_ID}"
BIG_KEY="test-mcp-big-${RUN_ID}"
PRIV_KEY="test-mcp-priv-${RUN_ID}"
NS="io.github.ak-e2e-${RUN_ID}"
ECHO_PKG="ak-e2e-echo-${RUN_ID}"
REMOTE_URL="https://mcp.example.invalid/mcp"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# doc NAME VERSION [PACKAGES_JSON] [REMOTES_JSON]: write a server.json and
# echo its path. With neither PACKAGES nor REMOTES the server is remote-only.
# Called through $(...), so the file name comes from mktemp, not a counter.
doc() {
  local name="$1" version="$2" pkgs="${3:-}" remotes="${4:-}" out
  out=$(mktemp "${WORK_DIR}/doc-XXXXXX.json")
  if [ -z "$pkgs" ] && [ -z "$remotes" ]; then
    remotes=$(mcp_remote_json "$REMOTE_URL")
  fi
  mcp_server_json "$name" "$version" "$pkgs" "$remotes" > "$out"
  printf '%s' "$out"
}

# publish_ok REPO NAME VERSION [PACKAGES] [REMOTES]: 0 on HTTP 200.
publish_ok() {
  local f
  f=$(doc "$2" "$3" "${4:-}" "${5:-}")
  mcp_publish "$1" "$f"
  [ "$MCP_STATUS" = "200" ]
}

# list_versions FILTER_FILE: the server versions of the last list answer.
versions_csv() {
  jq -r '[.servers[].server.version] | join(",")' "$MCP_BODY" 2>/dev/null || true
}

ENC() { mcp_encode_name "$1"; }

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

begin_test "Create npm backing repository and publish the echo package"
if ! mcp_create_backing_repos "test-mcp-${RUN_ID}"; then
  fail_fatal "could not create the npm backing repository"
fi
if mcp_publish_echo_package "$MCP_NPM_KEY" "$ECHO_PKG" "1.0.0" "${NS}/echo"; then
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

ECHO_PKGS=$(mcp_npm_package_json "$ECHO_PKG" "1.0.0")

# ---------------------------------------------------------------------------
# Publish with curl
# ---------------------------------------------------------------------------

begin_test "curl publish answers 200 with the served document"
PUB_FILE=$(doc "${NS}/echo" "1.0.0" "$ECHO_PKGS")
mcp_publish "$MCP_KEY" "$PUB_FILE"
PUB_BODY="${WORK_DIR}/publish-1.json"
cp "$MCP_BODY" "$PUB_BODY"
if [ "$MCP_STATUS" != "200" ]; then
  fail_fatal "publish returned HTTP ${MCP_STATUS}, expected 200" "$(mcp_snip)"
fi
why=""
[ "$(mcp_json '.server.name')" = "${NS}/echo" ] || why="${why} server.name='$(mcp_json '.server.name')';"
[ "$(mcp_json '.server.version')" = "1.0.0" ] || why="${why} server.version;"
[ "$(mcp_json '._meta["io.modelcontextprotocol.registry/official"].status')" = "active" ] || why="${why} official.status not active;"
[ "$(mcp_json '._meta["io.modelcontextprotocol.registry/official"].isLatest')" = "true" ] || why="${why} isLatest not true;"
[ -n "$(mcp_json '._meta["io.modelcontextprotocol.registry/official"].publishedAt // empty')" ] || why="${why} no publishedAt;"
[ "$(mcp_json '._meta["com.artifactkeeper.registry/source"] | type')" = "object" ] || why="${why} no com.artifactkeeper.registry/source;"
[ "$(mcp_json '._meta["com.artifactkeeper.registry/source"].packagePolicy')" = "own-repos" ] || why="${why} source.packagePolicy='$(mcp_json '._meta["com.artifactkeeper.registry/source"].packagePolicy')';"
case "$(mcp_url_path "$(mcp_json '.server.packages[0].registryBaseUrl // empty')")" in
  "/npm/${MCP_NPM_KEY}"|"/npm/${MCP_NPM_KEY}/") ;;
  *) why="${why} registryBaseUrl='$(mcp_json '.server.packages[0].registryBaseUrl // empty')' not the backing repo;" ;;
esac
if [ -z "$why" ]; then pass; else fail "publish answer is wrong:${why}" "$(mcp_snip)"; fi

begin_test "Published version reads back as published"
mcp_get "$MCP_KEY" "$(mcp_version_path "${NS}/echo" "1.0.0")" anon
if [ "$MCP_STATUS" != "200" ]; then
  fail "anonymous read returned HTTP ${MCP_STATUS}" "$(mcp_snip)"
elif [ "$(jq -S -c '.server' "$MCP_BODY")" != "$(jq -S -c '.server' "$PUB_BODY")" ]; then
  fail "read .server differs from the publish answer" "$(mcp_snip)"
else
  pass
fi

# ---------------------------------------------------------------------------
# The real mcp-publisher
# ---------------------------------------------------------------------------

PUBLISHER_OK=false
begin_test "Install mcp-publisher ${MCP_PUBLISHER_VERSION}"
install_mcp_publisher
rc=$?
if [ "$rc" = "0" ]; then
  PUBLISHER_OK=true
  pass
else
  infra_fail "install_mcp_publisher rc=${rc}: ${MCP_PUBLISHER_ERROR}"
fi

PUB_HOME="${WORK_DIR}/home"
mkdir -p "$PUB_HOME"
API_TOKEN=$(mcp_mint_token "$ADMIN_TOKEN" "mcp-publisher-${RUN_ID}" '["write:artifacts"]')
if [ -n "$API_TOKEN" ]; then
  PUB_TOKEN="$API_TOKEN"
  PUB_TOKEN_KIND="API token (write:artifacts)"
else
  PUB_TOKEN="$ADMIN_TOKEN"
  PUB_TOKEN_KIND="admin session token (API token mint failed)"
fi
echo "  publisher credential: ${PUB_TOKEN_KIND}"
mcp_write_publisher_token "$PUB_HOME" "$(mcp_root "$MCP_KEY")" "$PUB_TOKEN"

begin_test "mcp-publisher publish"
if ! $PUBLISHER_OK; then
  skip "mcp-publisher not installed (infra failure recorded above)"
else
  PDIR="${WORK_DIR}/publisher-src"
  mkdir -p "$PDIR"
  mcp_server_json "${NS}/echo" "1.0.1" "$ECHO_PKGS" "" "Published by mcp-publisher" > "${PDIR}/server.json"
  if (cd "$PDIR" && mcp_publisher "$PUB_HOME" publish); then
    mcp_get "$MCP_KEY" "$(mcp_version_path "${NS}/echo" "1.0.1")" anon
    if [ "$MCP_STATUS" = "200" ] && [ "$(mcp_json '.server.description')" = "Published by mcp-publisher" ]; then
      pass
    else
      fail "version published by mcp-publisher does not read back (HTTP ${MCP_STATUS})" "$(mcp_snip)"
    fi
  else
    fail "mcp-publisher publish failed" "$(head -c 800 "$MCP_PUBLISHER_OUT")"
  fi
fi

begin_test "mcp-publisher status --status deprecated"
if ! $PUBLISHER_OK; then
  skip "mcp-publisher not installed (infra failure recorded above)"
elif mcp_publisher "$PUB_HOME" status --status deprecated --message "deprecated by mcp-publisher ${RUN_ID}" "${NS}/echo" "1.0.1"; then
  mcp_get "$MCP_KEY" "$(mcp_version_path "${NS}/echo" "1.0.1")" anon
  st=$(mcp_json '._meta["io.modelcontextprotocol.registry/official"].status')
  msg=$(mcp_json '._meta["io.modelcontextprotocol.registry/official"].statusMessage // empty')
  if [ "$MCP_STATUS" = "200" ] && [ "$st" = "deprecated" ] && [ "$msg" = "deprecated by mcp-publisher ${RUN_ID}" ]; then
    pass
  else
    fail "after status: HTTP ${MCP_STATUS} status='${st}' statusMessage='${msg}'" "$(mcp_snip)"
  fi
else
  fail "mcp-publisher status failed" "$(head -c 800 "$MCP_PUBLISHER_OUT")"
fi

# ---------------------------------------------------------------------------
# Publisher wire contract
# ---------------------------------------------------------------------------

WIRE_NAME="${NS}/wire"
WIRE_VERSION="1.0.0"
WIRE_ENC=$(ENC "$WIRE_NAME")
WIRE_ROOT=$(mcp_root "$MCP_KEY")
WIRE_DOC=$(doc "$WIRE_NAME" "$WIRE_VERSION")

while IFS=$'\t' read -r w_cmd w_method w_path w_auth; do
  case "$w_cmd" in ''|'#'*) continue ;; esac
  path="${w_path//\{enc\}/$WIRE_ENC}"
  path="${path//\{version\}/$WIRE_VERSION}"
  begin_test "Publisher wire contract unchanged: ${w_cmd} ${w_method} ${w_path}"
  auth=anon
  [ "$w_auth" = "yes" ] && auth="$PUB_TOKEN"
  if [ "$w_cmd" = "validate" ]; then
    if ! mcp_probe_route POST "${WIRE_ROOT}${path}" "$(cat "$WIRE_DOC")"; then
      skip "POST /v0/validate is Phase 2 (mcp_validate): the backend answered the router fallback (HTTP ${MCP_STATUS} unknown-name body) with an admin token"
      continue
    fi
  fi
  case "$w_method" in
    POST|PATCH)
      if [ "$w_method" = "PATCH" ]; then
        body='{"status":"deprecated","statusMessage":"wire replay"}'
      else
        body=$(cat "$WIRE_DOC")
      fi
      if [ "$auth" = "anon" ]; then
        mcp_req "$w_method" "${WIRE_ROOT}${path}" anon -H "Content-Type: application/json" -d "$body"
      else
        mcp_req "$w_method" "${WIRE_ROOT}${path}" "$auth" -H "Content-Type: application/json" -d "$body"
      fi
      ;;
    *)
      mcp_req "$w_method" "${WIRE_ROOT}${path}" "$auth"
      ;;
  esac
  if [ "${MCP_STATUS:0:1}" = "2" ]; then
    pass
  else
    fail "${w_method} ${path} answered HTTP ${MCP_STATUS}, expected 2xx" "$(mcp_snip)"
  fi
done < "${MCP_FIXTURES_DIR}/publisher-wire.txt"

# ---------------------------------------------------------------------------
# /v0 alias
# ---------------------------------------------------------------------------

begin_test "/v0 alias answers bodies identical to /v0.1"
why=""
for tail in "servers" "servers/$(ENC "${NS}/echo")/versions" "$(mcp_version_path "${NS}/echo" "1.0.0")" "servers/$(ENC "${NS}/echo")/versions/latest" "ping" "version"; do
  mcp_req GET "$(mcp_root "$MCP_KEY")/v0.1/${tail}" anon
  a_status="$MCP_STATUS"
  a_body=$(cat "$MCP_BODY")
  mcp_req GET "$(mcp_root "$MCP_KEY")/v0/${tail}" anon
  if [ "$a_status" != "200" ] || [ "$MCP_STATUS" != "200" ]; then
    why="${why} ${tail}: v0.1=${a_status} v0=${MCP_STATUS};"
  elif [ "$a_body" != "$(cat "$MCP_BODY")" ]; then
    why="${why} ${tail}: bodies differ;"
  fi
done
if [ -z "$why" ]; then pass; else fail "alias mismatch:${why}"; fi

# ---------------------------------------------------------------------------
# Listing semantics (dedicated repository, deterministic contents)
# ---------------------------------------------------------------------------

begin_test "Create listing repository and publish alpha 1.0.0, 1.10.0, 1.2.0 and bravo 1.0.0"
ALPHA="${NS}/alpha"
BRAVO="${NS}/bravo"
if ! mcp_create_repo "$LIST_KEY"; then
  fail_fatal "could not create listing repository: ${MCP_CREATE_ERROR}"
fi
why=""
for v in 1.0.0 1.10.0 1.2.0; do
  publish_ok "$LIST_KEY" "$ALPHA" "$v" || why="${why} alpha@${v}=${MCP_STATUS};"
done
publish_ok "$LIST_KEY" "$BRAVO" "1.0.0" || why="${why} bravo@1.0.0=${MCP_STATUS};"
if [ -z "$why" ]; then pass; else fail_fatal "listing fixtures did not publish:${why}" "$(mcp_snip)"; fi

begin_test "versions are ordered by version text (1.0.0, 1.10.0, 1.2.0)"
mcp_get "$LIST_KEY" "servers/$(ENC "$ALPHA")/versions" anon
got=$(versions_csv)
if [ "$MCP_STATUS" = "200" ] && [ "$got" = "1.0.0,1.10.0,1.2.0" ]; then
  pass
else
  fail "versions answered HTTP ${MCP_STATUS} order '${got}'" "$(mcp_snip)"
fi

begin_test "versions/latest is 1.10.0 (SemVer precedence) with isLatest"
mcp_get "$LIST_KEY" "servers/$(ENC "$ALPHA")/versions/latest" anon
if [ "$MCP_STATUS" = "200" ] && [ "$(mcp_json '.server.version')" = "1.10.0" ] \
   && [ "$(mcp_json '._meta["io.modelcontextprotocol.registry/official"].isLatest')" = "true" ]; then
  pass
else
  fail "latest answered HTTP ${MCP_STATUS} version '$(mcp_json '.server.version')'" "$(mcp_snip)"
fi

begin_test "isLatest is set only on alpha 1.10.0 in the full listing"
mcp_get "$LIST_KEY" "servers" anon
got=$(jq -r --arg n "$ALPHA" '[.servers[] | select(.server.name == $n and ._meta["io.modelcontextprotocol.registry/official"].isLatest == true) | .server.version] | join(",")' "$MCP_BODY" 2>/dev/null)
order=$(jq -r '[.servers[] | "\(.server.name | split("/")[1])@\(.server.version)"] | join(",")' "$MCP_BODY" 2>/dev/null)
if [ "$MCP_STATUS" = "200" ] && [ "$got" = "1.10.0" ] && [ "$order" = "alpha@1.0.0,alpha@1.10.0,alpha@1.2.0,bravo@1.0.0" ]; then
  pass
else
  fail "list HTTP ${MCP_STATUS} isLatest on '${got}', order '${order}'" "$(mcp_snip)"
fi

begin_test "?version=latest answers one entry per server"
mcp_get "$LIST_KEY" "servers?version=latest" anon
got=$(jq -r '[.servers[] | "\(.server.name | split("/")[1])@\(.server.version)"] | join(",")' "$MCP_BODY" 2>/dev/null)
if [ "$MCP_STATUS" = "200" ] && [ "$got" = "alpha@1.10.0,bravo@1.0.0" ] && [ "$(mcp_json '.metadata.count')" = "2" ]; then
  pass
else
  fail "version=latest HTTP ${MCP_STATUS}: '${got}'" "$(mcp_snip)"
fi

begin_test "?version=<exact> filters to that version"
mcp_get "$LIST_KEY" "servers?version=1.0.0" anon
got=$(jq -r '[.servers[] | "\(.server.name | split("/")[1])@\(.server.version)"] | join(",")' "$MCP_BODY" 2>/dev/null)
if [ "$MCP_STATUS" = "200" ] && [ "$got" = "alpha@1.0.0,bravo@1.0.0" ]; then
  pass
else
  fail "version=1.0.0 HTTP ${MCP_STATUS}: '${got}'" "$(mcp_snip)"
fi

begin_test "limit=1 pages through every entry; no nextCursor on the last page"
seen=""
cursor=""
pages=0
why=""
while [ "$pages" -lt 10 ]; do
  pages=$(( pages + 1 ))
  if [ -n "$cursor" ]; then
    mcp_get "$LIST_KEY" "servers?limit=1&cursor=$(jq -rn --arg v "$cursor" '$v|@uri')" anon
  else
    mcp_get "$LIST_KEY" "servers?limit=1" anon
  fi
  [ "$MCP_STATUS" = "200" ] || { why="page ${pages} HTTP ${MCP_STATUS}"; break; }
  [ "$(mcp_json '.metadata.count')" = "1" ] || { why="page ${pages} count $(mcp_json '.metadata.count')"; break; }
  seen="${seen}$(jq -r '.servers[0] | "\(.server.name | split("/")[1])@\(.server.version)"' "$MCP_BODY"),"
  cursor=$(mcp_json '.metadata.nextCursor // empty')
  [ -n "$cursor" ] || break
done
if [ -z "$why" ] && [ "$pages" = "4" ] && [ "$seen" = "alpha@1.0.0,alpha@1.10.0,alpha@1.2.0,bravo@1.0.0," ]; then
  pass
else
  fail "paging: ${why:-pages=${pages} seen=${seen}}" "$(mcp_snip)"
fi

begin_test "limit=0, -1 and abc are 400 problem+json"
why=""
for l in 0 -1 abc; do
  mcp_get "$LIST_KEY" "servers?limit=${l}" anon
  r=$(mcp_check_problem 400 "") || why="${why} limit=${l}: ${r};"
done
if [ -z "$why" ]; then pass; else fail "limit refusals:${why}"; fi

begin_test "search of 2 characters is 422; 3 characters is a case-insensitive substring"
mcp_get "$LIST_KEY" "servers?search=lp" anon
r=$(mcp_check_problem 422 "")
s1="$MCP_STATUS"
mcp_get "$LIST_KEY" "servers?search=LPH" anon
got=$(jq -r '[.servers[].server.name] | unique | join(",")' "$MCP_BODY" 2>/dev/null)
cnt=$(mcp_json '.metadata.count')
if [ -z "$r" ] && [ "$MCP_STATUS" = "200" ] && [ "$got" = "$ALPHA" ] && [ "$cnt" = "3" ]; then
  pass
else
  fail "search=lp HTTP ${s1} (${r}); search=LPH HTTP ${MCP_STATUS} names '${got}' count ${cnt}" "$(mcp_snip)"
fi

begin_test "updated_since with include_deleted=false is 400"
mcp_get "$LIST_KEY" "servers?updated_since=2020-01-01T00:00:00Z&include_deleted=false" anon
if r=$(mcp_check_problem 400 ""); then
  mcp_get "$LIST_KEY" "servers?updated_since=2020-01-01T00:00:00Z" anon
  if [ "$MCP_STATUS" = "200" ] && [ "$(mcp_json '.metadata.count')" = "4" ]; then
    pass
  else
    fail "updated_since alone answered HTTP ${MCP_STATUS} count $(mcp_json '.metadata.count')" "$(mcp_snip)"
  fi
else
  fail "$r"
fi

begin_test "garbage cursor is 400"
mcp_get "$LIST_KEY" "servers?cursor=not-a-cursor%21%21" anon
if r=$(mcp_check_problem 400 ""); then pass; else fail "$r"; fi

begin_test "limit defaults to 30 and clamps at 100 (101 versions)"
if ! mcp_create_repo "$BIG_KEY"; then
  fail "could not create repository: ${MCP_CREATE_ERROR}"
else
  why=""
  for i in $(seq 1 101); do
    publish_ok "$BIG_KEY" "${NS}/big" "1.0.${i}" || { why="publish 1.0.${i}: HTTP ${MCP_STATUS}"; break; }
  done
  if [ -z "$why" ]; then
    mcp_get "$BIG_KEY" "servers" anon
    d_count=$(mcp_json '.metadata.count')
    d_next=$(mcp_json '.metadata.nextCursor // empty')
    mcp_get "$BIG_KEY" "servers?limit=1000" anon
    c_count=$(mcp_json '.metadata.count')
    c_next=$(mcp_json '.metadata.nextCursor // empty')
    if [ "$d_count" != "30" ] || [ -z "$d_next" ]; then
      why="default page count=${d_count} nextCursor='${d_next}'"
    elif [ "$c_count" != "100" ] || [ -z "$c_next" ]; then
      why="limit=1000 count=${c_count} nextCursor='${c_next}'"
    else
      mcp_get "$BIG_KEY" "servers?limit=1000&cursor=$(jq -rn --arg v "$c_next" '$v|@uri')" anon
      [ "$(mcp_json '.metadata.count')" = "1" ] && [ -z "$(mcp_json '.metadata.nextCursor // empty')" ] \
        || why="second page count=$(mcp_json '.metadata.count') nextCursor='$(mcp_json '.metadata.nextCursor // empty')'"
    fi
  fi
  if [ -z "$why" ]; then pass; else fail "$why" "$(mcp_snip)"; fi
fi

# ---------------------------------------------------------------------------
# Names
# ---------------------------------------------------------------------------

begin_test "Encoded and literal-slash names answer the same document"
mcp_req GET "$(mcp_base "$MCP_KEY")/servers/$(ENC "${NS}/echo")/versions/1.0.0" anon
enc_status="$MCP_STATUS"
enc_body=$(cat "$MCP_BODY")
mcp_req GET "$(mcp_base "$MCP_KEY")/servers/${NS}/echo/versions/1.0.0" anon
lit_status="$MCP_STATUS"
lit_body=$(cat "$MCP_BODY")
mcp_req GET "$(mcp_base "$MCP_KEY")/servers/${NS}/echo/versions" anon
lv_status="$MCP_STATUS"
if [ "$enc_status" = "200" ] && [ "$lit_status" = "200" ] && [ "$lv_status" = "200" ] && [ "$enc_body" = "$lit_body" ]; then
  pass
else
  fail "encoded=${enc_status} literal=${lit_status} literal versions=${lv_status} same_body=$([ "$enc_body" = "$lit_body" ] && echo yes || echo no)"
fi

# ---------------------------------------------------------------------------
# Write-once
# ---------------------------------------------------------------------------

begin_test "Republishing identical bytes is 409 mcp_version_exists; document unchanged"
mcp_get "$MCP_KEY" "$(mcp_version_path "${NS}/echo" "1.0.0")" anon
before=$(jq -S -c '.server' "$MCP_BODY" 2>/dev/null)
mcp_publish "$MCP_KEY" "$PUB_FILE"
if r=$(mcp_check_problem 409 mcp_version_exists); then
  mcp_get "$MCP_KEY" "$(mcp_version_path "${NS}/echo" "1.0.0")" anon
  after=$(jq -S -c '.server' "$MCP_BODY" 2>/dev/null)
  if [ -n "$before" ] && [ "$before" = "$after" ]; then
    pass
  else
    fail "stored document changed after the refused republish"
  fi
else
  fail "$r"
fi

# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------

ST="${NS}/status"
begin_test "Publish status fixture versions 1.0.0 and 2.0.0"
why=""
publish_ok "$MCP_KEY" "$ST" "1.0.0" || why="${why} 1.0.0=${MCP_STATUS};"
publish_ok "$MCP_KEY" "$ST" "2.0.0" || why="${why} 2.0.0=${MCP_STATUS};"
if [ -z "$why" ]; then pass; else fail "publish failed:${why}" "$(mcp_snip)"; fi

begin_test "PATCH status deprecated carries statusMessage; version stays listed and latest"
mcp_patch_status "$MCP_KEY" "$ST" "2.0.0" deprecated "use 3.x ${RUN_ID}"
p_status="$MCP_STATUS"
mcp_get "$MCP_KEY" "$(mcp_version_path "$ST" "2.0.0")" anon
st=$(mcp_json '._meta["io.modelcontextprotocol.registry/official"].status')
msg=$(mcp_json '._meta["io.modelcontextprotocol.registry/official"].statusMessage // empty')
mcp_get "$MCP_KEY" "servers/$(ENC "$ST")/versions/latest" anon
lat=$(mcp_json '.server.version')
mcp_get "$MCP_KEY" "servers?search=$(jq -rn --arg v "${ST#*/}" '$v|@uri')" anon
listed=$(jq -r --arg n "$ST" '[.servers[] | select(.server.name == $n) | .server.version] | join(",")' "$MCP_BODY")
if [ "${p_status:0:1}" = "2" ] && [ "$st" = "deprecated" ] && [ "$msg" = "use 3.x ${RUN_ID}" ] && [ "$lat" = "2.0.0" ] && [ "$listed" = "1.0.0,2.0.0" ]; then
  pass
else
  fail "PATCH=${p_status} status='${st}' message='${msg}' latest='${lat}' listed='${listed}'"
fi

begin_test "PATCH status deleted hides the version from the list and moves latest"
mcp_patch_status "$MCP_KEY" "$ST" "2.0.0" deleted "gone ${RUN_ID}"
p_status="$MCP_STATUS"
mcp_get "$MCP_KEY" "servers?search=$(jq -rn --arg v "${ST#*/}" '$v|@uri')" anon
listed=$(jq -r --arg n "$ST" '[.servers[] | select(.server.name == $n) | .server.version] | join(",")' "$MCP_BODY")
mcp_get "$MCP_KEY" "servers/$(ENC "$ST")/versions/latest" anon
lat=$(mcp_json '.server.version')
lat_is=$(mcp_json '._meta["io.modelcontextprotocol.registry/official"].isLatest')
mcp_get "$MCP_KEY" "servers/$(ENC "$ST")/versions" anon
vers=$(versions_csv)
if [ "${p_status:0:1}" = "2" ] && [ "$listed" = "1.0.0" ] && [ "$lat" = "1.0.0" ] && [ "$lat_is" = "true" ] && [ "$vers" = "1.0.0" ]; then
  pass
else
  fail "PATCH=${p_status} listed='${listed}' latest='${lat}' isLatest='${lat_is}' versions='${vers}'"
fi

begin_test "include_deleted=true lists the deleted version"
mcp_get "$MCP_KEY" "servers?include_deleted=true&search=$(jq -rn --arg v "${ST#*/}" '$v|@uri')" anon
got=$(jq -r --arg n "$ST" '[.servers[] | select(.server.name == $n) | "\(.server.version):\(._meta["io.modelcontextprotocol.registry/official"].status)"] | join(",")' "$MCP_BODY")
mcp_get "$MCP_KEY" "servers/$(ENC "$ST")/versions?include_deleted=true" anon
vers=$(versions_csv)
if [ "$got" = "1.0.0:active,2.0.0:deleted" ] && [ "$vers" = "1.0.0,2.0.0" ]; then
  pass
else
  fail "include_deleted list '${got}', versions '${vers}'"
fi

begin_test "Deleted exact read is 404 plain; 200 with include_deleted=true"
mcp_get "$MCP_KEY" "$(mcp_version_path "$ST" "2.0.0")" anon
if r=$(mcp_check_plain_404); then
  mcp_get "$MCP_KEY" "$(mcp_version_path "$ST" "2.0.0")?include_deleted=true" anon
  if [ "$MCP_STATUS" = "200" ] && [ "$(mcp_json '._meta["io.modelcontextprotocol.registry/official"].status')" = "deleted" ]; then
    pass
  else
    fail "include_deleted=true read answered HTTP ${MCP_STATUS}" "$(mcp_snip)"
  fi
else
  fail "$r"
fi

begin_test "PATCH of every version answers {updatedCount, servers}"
# updatedCount counts the versions whose status changed: deprecate both
# (1.0.0 active, 2.0.0 deleted), then restore both.
mcp_patch_status "$MCP_KEY" "$ST" "" deprecated "all ${RUN_ID}"
d_status="$MCP_STATUS"
d_cnt=$(mcp_json '.updatedCount')
d_srv=$(jq -r '[.servers[]? | "\(.server.version):\(._meta["io.modelcontextprotocol.registry/official"].status)"] | sort | join(",")' "$MCP_BODY" 2>/dev/null)
mcp_patch_status "$MCP_KEY" "$ST" "" active
a_status="$MCP_STATUS"
a_cnt=$(mcp_json '.updatedCount')
mcp_get "$MCP_KEY" "servers/$(ENC "$ST")/versions/latest" anon
lat=$(mcp_json '.server.version')
if [ "$d_status" = "200" ] && [ "$d_cnt" = "2" ] && [ "$d_srv" = "1.0.0:deprecated,2.0.0:deprecated" ] \
   && [ "$a_status" = "200" ] && [ "$a_cnt" = "2" ] && [ "$lat" = "2.0.0" ]; then
  pass
else
  fail "deprecate all: HTTP ${d_status} updatedCount='${d_cnt}' servers='${d_srv}'; restore all: HTTP ${a_status} updatedCount='${a_cnt}'; latest after='${lat}'" "$(mcp_snip)"
fi

# ---------------------------------------------------------------------------
# own-repos refusals
# ---------------------------------------------------------------------------

for case_file in npm-external-registry.json:mcp_external_registry npm-not-found.json:mcp_package_not_found; do
  f="${case_file%%:*}"
  code="${case_file#*:}"
  begin_test "own-repos: ${f} is 422 ${code}"
  out="${WORK_DIR}/own-${f}"
  mcp_render_fixture "${MCP_FIXTURES_DIR}/server-json/own-repos/${f}" "$out" \
    "SLUG=own-${RUN_ID}-${f%.json}" "NPM_PKG=${ECHO_PKG}" "AK_BASE=${BASE_URL}"
  mcp_publish "$MCP_KEY" "$out"
  if r=$(mcp_check_problem 422 "$code"); then
    if [ -n "$(mcp_json '.detail // empty')" ]; then pass; else fail "422 without a detail line" "$(mcp_snip)"; fi
  else
    fail "$r"
  fi
done

# ---------------------------------------------------------------------------
# Artifact API
# ---------------------------------------------------------------------------

begin_test "Generic artifact upload into the MCP repository is 400"
printf '{"name":"x"}' > "${WORK_DIR}/generic.json"
st=$(curl -s -o "${WORK_DIR}/generic.out" -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" -X PUT \
  -H "$(auth_header)" -H "Content-Type: application/json" --data-binary "@${WORK_DIR}/generic.json" \
  "${BASE_URL}/api/v1/repositories/${MCP_KEY}/artifacts/servers/${NS}/sneak/1.0.0/server.json" 2>/dev/null) || st="000"
mcp_get "$MCP_KEY" "servers/$(ENC "${NS}/sneak")/versions" anon
if [ "$st" = "400" ] && [ "$MCP_STATUS" = "404" ]; then
  pass
else
  fail "generic PUT answered HTTP ${st} (expected 400); registry read of the path answered ${MCP_STATUS}" "$(head -c 300 "${WORK_DIR}/generic.out")"
fi

begin_test "Artifact listing shows servers/<name>/<version>/server.json"
arts=$(curl -s "${CURL_TIMEOUT_ARGS[@]}" -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${MCP_KEY}/artifacts?per_page=200" 2>/dev/null)
want="servers/${NS}/echo/1.0.0/server.json"
if printf '%s' "$arts" | jq -e --arg p "$want" '[(.items // .artifacts // .data // .)[]? | select(.path == $p)] | length == 1' >/dev/null 2>&1; then
  pass
else
  fail "no artifact at ${want}" "$(printf '%s' "$arts" | head -c 600)"
fi

# ---------------------------------------------------------------------------
# Utility routes, headers
# ---------------------------------------------------------------------------

begin_test "ping, health and version"
mcp_get "$MCP_KEY" "ping" anon
p_ok=$([ "$MCP_STATUS" = "200" ] && [ "$(mcp_json '.status')" = "ok" ] && echo y || echo "n(${MCP_STATUS} $(mcp_snip))")
mcp_get "$MCP_KEY" "health" anon
h_ok=$([ "$MCP_STATUS" = "200" ] && [ -n "$(mcp_json '.status // empty')" ] && echo y || echo "n(${MCP_STATUS} $(mcp_snip))")
mcp_get "$MCP_KEY" "version" anon
v_ok=$([ "$MCP_STATUS" = "200" ] && [ -n "$(mcp_json '.version // empty')" ] && echo y || echo "n(${MCP_STATUS} $(mcp_snip))")
if [ "$p_ok$h_ok$v_ok" = "yyy" ]; then pass; else fail "ping=${p_ok} health=${h_ok} version=${v_ok}"; fi

begin_test "CORS: GET carries Access-Control-Allow-Origin *; preflight allows GET with Authorization"
mcp_req GET "$(mcp_base "$MCP_KEY")/servers" anon -H "Origin: https://vscode.example.invalid"
g_acao=$(mcp_header access-control-allow-origin)
g_acac=$(mcp_header access-control-allow-credentials)
mcp_req OPTIONS "$(mcp_base "$MCP_KEY")/servers" anon -H "Origin: https://vscode.example.invalid" \
  -H "Access-Control-Request-Method: GET" -H "Access-Control-Request-Headers: authorization"
o_status="$MCP_STATUS"
o_acao=$(mcp_header access-control-allow-origin)
o_meth=$(mcp_header access-control-allow-methods | tr 'A-Z' 'a-z')
o_hdrs=$(mcp_header access-control-allow-headers | tr 'A-Z' 'a-z')
if [ "$g_acao" = "*" ] && [ -z "$g_acac" ] && [ "${o_status:0:1}" = "2" ] && [ "$o_acao" = "*" ] \
   && [[ "$o_meth" == *get* ]] && [[ "$o_hdrs" == *authorization* ]] && [[ "$o_hdrs" == *content-type* ]]; then
  pass
else
  fail "GET ACAO='${g_acao}' ACAC='${g_acac}'; OPTIONS HTTP ${o_status} ACAO='${o_acao}' methods='${o_meth}' headers='${o_hdrs}'"
fi

begin_test "Responses carry X-Content-Type-Options: nosniff"
mcp_get "$MCP_KEY" "servers" anon
a=$(mcp_header x-content-type-options)
mcp_get "$MCP_KEY" "servers/$(ENC "${NS}/absent")/versions/1.0.0" anon
b=$(mcp_header x-content-type-options)
if [ "$a" = "nosniff" ] && [ "$b" = "nosniff" ]; then pass; else fail "nosniff on 200='${a}' on 404='${b}'"; fi

begin_test "Private repository: anonymous read is 401 problem+json with a challenge"
if ! mcp_create_repo "$PRIV_KEY" "" false; then
  fail "could not create private repository: ${MCP_CREATE_ERROR}"
else
  mcp_get "$PRIV_KEY" "servers" anon
  r=$(mcp_check_problem 401 "")
  chal=$(mcp_header www-authenticate)
  mcp_get "$PRIV_KEY" "servers" admin
  a_status="$MCP_STATUS"
  if [ -z "$r" ] && [ -n "$chal" ] && [ "$a_status" = "200" ]; then
    pass
  else
    fail "anonymous: ${r:-ok} WWW-Authenticate='${chal}'; admin read HTTP ${a_status}"
  fi
fi

end_suite
