# =============================================================================
# plugins/mcp.sh - format-conformance plugin (MCP Registry, artifact-keeper#5253)
# FC_FORMAT: mcp
# FC_MOUNT: mcp
# FC_REPO_FORMAT: mcp
# FC_PROFILE: client.mcp
# FC_SERVICE: client-mcp
# FC_ENABLED: 1
# =============================================================================
# MCP routes (backend handlers/mcp.rs): nest /mcp; registry API under
# /:repo/v0.1 (and the /v0 alias the publisher uses): POST publish,
# GET servers/:name/versions/:version|latest. The advertised location a
# client FOLLOWS is the version document's packages[0].registryBaseUrl, which
# own-repos (the default package policy) rewrites to this instance's backing
# repository (/npm/<repo>).
#
# Publish with the REAL mcp-publisher (pinned version + sha256 from
# tests/lib/mcp-helpers.sh, downloaded on the runner and copied into the
# client) from inside client-mcp. Consume the way an agent host does: read
# versions/latest from $FC_INT_URL only, take packages[0], `npm install` it
# from the advertised registryBaseUrl, launch it over stdio with
# tests/lib/mcp-stdio-client.py. The package is the zero-dependency echo
# server (tests/fixtures/mcp/echo-server), so nothing comes from npmjs.org.
#
# Candidates without the format: when sourced, the plugin probes
# /api/v1/formats; if `mcp` is absent AND repository creation answers
# `400 Invalid format: mcp`, the suite records one NOT APPLICABLE skip and
# exits 0 before the driver creates the repository (artifact-keeper-test#396
# carve-out; the same two-signal probe as tiers/mcp-registry). Anything else
# proceeds and fails normally.
#
# Edge cases: a held version (backing tarball quarantined) reads exactly like
# an unknown name to a reader; own-repos refuses a package on another
# registry with 422 mcp_external_registry.
# =============================================================================
# shellcheck disable=SC2034  # read by harness/lib/native_client.sh
FC_CASES="held_plain_404 own_repos_external_registry"

# shellcheck source=/dev/null
source "$(dirname "${COMMON_SH:?}")/mcp-helpers.sh"

MCPFC_LIB="$(cd "$(dirname "$COMMON_SH")" && pwd)"
MCPFC_RESOLVER="${DTF_DIR:?}/harness/tiers/mcp-registry/resolve.js"
MCPFC_SUF="$(printf '%s' "$RUN_ID" | tr 'A-Z' 'a-z' | tr -c 'a-z0-9-' '-' | tail -c 20)"
MCPFC_SUF="${MCPFC_SUF#-}"
MCPFC_NPM="${FC_REPO}-npm"
MCPFC_NAME="io.github.ak-e2e/dtf-fc-${MCPFC_SUF}"
MCPFC_PKG="ak-e2e-fc-echo-${MCPFC_SUF}"
MCPFC_VER="1.0.0"
MCPFC_MARK="DTF-MCP-ECHO-${MCPFC_SUF}"
MCPFC_CW="/tmp/mcpfc"
MCPFC_AID=""

# --- applicability probe (runs at source time, before the repo is created) --
_mcpfc_not_applicable() {
  local f="${WORK_DIR}/mcpfc-formats.json" code n body
  code=$(curl -s -o "$f" -w '%{http_code}' --max-time 30 -H "$(auth_header)" \
    "${BASE_URL}/api/v1/formats" 2>/dev/null) || code="000"
  [ "$code" = "200" ] || return 1
  n=$(jq -r '[(if type == "array" then . else (.items // []) end)[] | select(.format_key == "mcp")] | length' "$f" 2>/dev/null) || return 1
  [ "$n" = "0" ] || return 1
  body=$(jq -cn --arg k "${FC_REPO}-probe" '{key:$k,name:$k,format:"mcp",repo_type:"local",is_public:true}')
  code=$(curl -s -o "${f}.create" -w '%{http_code}' --max-time 30 -X POST -H "$(auth_header)" \
    -H "Content-Type: application/json" -d "$body" "${BASE_URL}/api/v1/repositories" 2>/dev/null) || code="000"
  [ "$code" = "400" ] && grep -q 'Invalid format: mcp' "${f}.create" 2>/dev/null
}
if _mcpfc_not_applicable; then
  begin_test "preflight: the candidate serves the mcp repository format"
  skip_not_applicable "the MCP Registry format is not in this candidate: /api/v1/formats lists no 'mcp' and POST /api/v1/repositories answers 400 Invalid format: mcp"
  end_suite
  exit 0
fi

# Host-side anonymous read of an exact version (MCP_STATUS/MCP_BODY/MCP_HDRS).
_mcpfc_anon_version() {
  mcp_req GET "$(mcp_base "$FC_REPO")/$(mcp_version_path "$1" "$2")" anon
}

# ---------------------------------------------------------------------------
# fc_publish - echo server into an npm Local, map it as the repo's npm
# backing repository, then the REAL mcp-publisher publishes from the client.
# ---------------------------------------------------------------------------
fc_publish() {
  create_local_repo "$MCPFC_NPM" npm || { echo "npm backing repo create failed"; return 1; }
  mcp_publish_echo_package "$MCPFC_NPM" "$MCPFC_PKG" "$MCPFC_VER" "$MCPFC_NAME" \
    || { echo "echo package publish -> ${MCP_STATUS}: $(mcp_snip)"; return 1; }
  mcp_patch_repo "$FC_REPO" "$(jq -cn --arg n "$MCPFC_NPM" '{mcp_package_repos:{npm:$n}}')" \
    || { echo "PATCH mcp_package_repos -> ${MCP_STATUS}: $(mcp_snip)"; return 1; }
  install_mcp_publisher || { echo "install_mcp_publisher: ${MCP_PUBLISHER_ERROR:-failed}"; return 1; }
  local tok
  tok=$(mcp_mint_token "$ADMIN_TOKEN" "dtf-fc-mcp-${MCPFC_SUF}" '["read:artifacts","write:artifacts"]')
  [ -n "$tok" ] || { echo "API token mint returned no token"; return 1; }
  mcp_server_json "$MCPFC_NAME" "$MCPFC_VER" "$(mcp_npm_package_json "$MCPFC_PKG" "$MCPFC_VER")" \
    > "${WORK_DIR}/mcpfc-server.json"
  mcp_write_publisher_token "${WORK_DIR}/mcpfc-home" "$FC_INT_URL" "$tok"
  nc_exec "rm -rf '${MCPFC_CW}' && mkdir -p '${MCPFC_CW}/pub' '${MCPFC_CW}/home/.config/mcp-publisher'" || return 1
  nc_copy_to_ctr "$MCP_PUBLISHER" "${MCPFC_CW}/mcp-publisher" || { echo "copy publisher failed"; return 1; }
  nc_copy_to_ctr "${WORK_DIR}/mcpfc-server.json" "${MCPFC_CW}/pub/server.json" || return 1
  nc_copy_to_ctr "${WORK_DIR}/mcpfc-home/.config/mcp-publisher/token.json" \
    "${MCPFC_CW}/home/.config/mcp-publisher/token.json" || return 1
  nc_exec -t 90 "chmod +x '${MCPFC_CW}/mcp-publisher' && cd '${MCPFC_CW}/pub' && HOME='${MCPFC_CW}/home' '${MCPFC_CW}/mcp-publisher' publish" \
    || { echo "mcp-publisher publish failed"; return 1; }
  _mcpfc_anon_version "$MCPFC_NAME" "$MCPFC_VER"
  [ "$MCP_STATUS" = "200" ] || { echo "published version reads ${MCP_STATUS}: $(mcp_snip)"; return 1; }
  echo "  published ${MCPFC_NAME}@${MCPFC_VER} via mcp-publisher ${MCP_PUBLISHER_VERSION}"
}

# ---------------------------------------------------------------------------
# fc_client_setup - resolver + stdio client in the container; an .npmrc whose
# default registry is AK's npm backing repo (no npmjs.org fallback).
# ---------------------------------------------------------------------------
fc_client_setup() {
  nc_exec "rm -rf '${MCPFC_CW}/run' '${MCPFC_CW}/npmcache' && mkdir -p '${MCPFC_CW}/run'
printf 'registry=http://backend:8080/npm/${MCPFC_NPM}/\n' > '${MCPFC_CW}/.npmrc'" || return 1
  nc_copy_to_ctr "$MCPFC_RESOLVER" "${MCPFC_CW}/resolve.js" || { echo "copy resolver failed"; return 1; }
  nc_copy_to_ctr "${MCPFC_LIB}/mcp-stdio-client.py" "${MCPFC_CW}/mcp-stdio-client.py" \
    || { echo "copy stdio client failed"; return 1; }
  nc_exec "command -v node && command -v npm && command -v python3" || { echo "client lacks node/npm/python3"; return 1; }
}

# ---------------------------------------------------------------------------
# fc_consume - resolve latest from $FC_INT_URL, npm install packages[0] from
# its advertised registryBaseUrl, run it over stdio, keep the transcript.
# ---------------------------------------------------------------------------
fc_consume() {
  local res use id ver
  res=$(nc_exec -t 60 "cd '${MCPFC_CW}' && REG='${FC_INT_URL}' NAME='${MCPFC_NAME}' VER=latest node resolve.js") \
    || { echo "resolve failed: ${res}"; return 1; }
  res=$(printf '%s' "$res" | tail -n1)
  use=$(printf '%s' "$res" | jq -r '.use // empty')
  id=$(printf '%s' "$res" | jq -r '.identifier // empty')
  ver=$(printf '%s' "$res" | jq -r '.version // empty')
  [ "$(printf '%s' "$res" | jq -r '.status')" = "200" ] && [ -n "$use" ] && [ -n "$id" ] && [ -n "$ver" ] \
    || { echo "registry did not resolve a package: ${res}"; return 1; }
  echo "  resolved ${id}@${ver} from ${use}"
  nc_exec -t 300 "cd '${MCPFC_CW}' && npm install --prefix run --userconfig '${MCPFC_CW}/.npmrc' \
    --registry '${use}/' --cache '${MCPFC_CW}/npmcache' --no-audit --no-fund --no-package-lock '${id}@${ver}' 2>&1" \
    || { echo "npm install from the advertised registryBaseUrl failed"; return 1; }
  nc_exec -t 60 "cd '${MCPFC_CW}' && python3 mcp-stdio-client.py --timeout 20 \
    --call 'echo={\"text\":\"${MCPFC_MARK}\"}' -- run/node_modules/.bin/ak-e2e-echo-mcp > out.json" \
    || { echo "stdio session failed"; return 1; }
}

# ---------------------------------------------------------------------------
# fc_assert - client-side proof: the installed copy is the pinned version and
# answered tools/list=[echo] and echo(marker).
# ---------------------------------------------------------------------------
fc_assert() {
  local out names text iv
  out=$(docker exec "$FC_CLIENT_CTR" cat "${MCPFC_CW}/out.json" 2>/dev/null)
  iv=$(docker exec "$FC_CLIENT_CTR" node -p "require('${MCPFC_CW}/run/node_modules/${MCPFC_PKG}/package.json').version" 2>/dev/null)
  names=$(printf '%s' "$out" | jq -r '.toolNames // [] | join(",")' 2>/dev/null)
  text=$(printf '%s' "$out" | jq -r '.calls[0].text // empty' 2>/dev/null)
  echo "  installed=${iv} toolNames=${names} echo=${text}"
  [ "$iv" = "$MCPFC_VER" ] && [ "$names" = "echo" ] && [ "$text" = "$MCPFC_MARK" ] \
    || { echo "  transcript: $(printf '%s' "$out" | head -c 400)"; return 1; }
}

# ---------------------------------------------------------------------------
# fc_advertised_check - the #2580 discriminator. The advertised
# registryBaseUrl + identifier resolves (packument 200 listing the version,
# tarball 200 with the published bytes); a tarball for a version that was
# never published under the same base 404s.
# ---------------------------------------------------------------------------
fc_advertised_check() {
  local adv path tb dl
  adv=$(nc_advertised "$(mcp_base "$FC_REPO")/$(mcp_version_path "$MCPFC_NAME" "$MCPFC_VER")" \
    "jq -r '.server.packages[0].registryBaseUrl // empty'") || return 1
  path=$(mcp_url_path "$adv")
  echo "  advertised registryBaseUrl=${adv}"
  [ "$path" = "/npm/${MCPFC_NPM}" ] || { echo "  path ${path} is not /npm/${MCPFC_NPM}"; return 1; }
  tb=$(nc_advertised "${BASE_URL}${path}/${MCPFC_PKG}" \
    "jq -r '.versions[\"${MCPFC_VER}\"].dist.tarball // empty'") || return 1
  dl="${WORK_DIR}/mcpfc-served.tgz"
  nc_fetch "${BASE_URL}$(mcp_url_path "$tb")" "$dl" || return 1
  nc_assert_sha_eq "$(nc_sha256 "$MCP_ECHO_TARBALL")" "$(nc_sha256 "$dl")" "served tarball != published tarball" || return 1
  nc_expect_code 404 "${BASE_URL}${path}/${MCPFC_PKG}/-/${MCPFC_PKG}-9.9.9.tgz" || return 1
}

# ===========================================================================
# Edge cases
# ===========================================================================

# held_plain_404 - quarantine the pinned tarball: a reader's 404 for the exact
# version is byte-identical (body + stable headers) to an unknown name's, the
# client can no longer resolve latest, and releasing restores 200.
# Bug class: a hold that leaks its existence or does not apply.
fc_case_held_plain_404() {
  MCPFC_AID=$(mcp_artifact_id "$MCPFC_NPM" "${MCPFC_PKG}-${MCPFC_VER}\\.tgz$")
  [ -n "$MCPFC_AID" ] || { echo "no artifact id for the tarball"; return 1; }
  mcp_quarantine "$MCPFC_AID" "dtf fc mcp hold" || { echo "quarantine -> ${MCP_STATUS}"; return 1; }
  local why rc=0 st
  _mcpfc_anon_version "${MCPFC_NAME}-absent" "$MCPFC_VER"
  cp "$MCP_BODY" "${WORK_DIR}/mcpfc-unknown.body"; cp "$MCP_HDRS" "${WORK_DIR}/mcpfc-unknown.hdrs"
  _mcpfc_anon_version "$MCPFC_NAME" "$MCPFC_VER"
  why=$(mcp_check_plain_404) || { echo "  reader: ${why}"; rc=1; }
  cmp -s "$MCP_BODY" "${WORK_DIR}/mcpfc-unknown.body" || { echo "  body differs from the unknown-name body"; rc=1; }
  [ "$(mcp_stable_headers "$MCP_HDRS")" = "$(mcp_stable_headers "${WORK_DIR}/mcpfc-unknown.hdrs")" ] \
    || { echo "  headers differ from the unknown-name headers"; rc=1; }
  st=$(nc_exec -t 60 "cd '${MCPFC_CW}' && REG='${FC_INT_URL}' NAME='${MCPFC_NAME}' VER=latest node resolve.js" | tail -n1 | jq -r '.status // empty')
  [ "$st" = "404" ] || { echo "  client resolve of latest while held -> ${st} (want 404)"; rc=1; }
  mcp_release "$MCPFC_AID" || { echo "release -> ${MCP_STATUS}"; return 1; }
  MCPFC_AID=""
  _mcpfc_anon_version "$MCPFC_NAME" "$MCPFC_VER"
  [ "$MCP_STATUS" = "200" ] || { echo "  after release -> ${MCP_STATUS}"; rc=1; }
  [ "$rc" = 0 ] && echo "  held version reads as unknown; release restores 200"
  return "$rc"
}

# own_repos_external_registry - a server.json naming the same package on
# registry.npmjs.org is 422 mcp_external_registry under own-repos and stores
# nothing. Bug class: own-repos letting an external recipe through.
fc_case_own_repos_external_registry() {
  local src out why slug="dtf-fc-ext-${MCPFC_SUF}"
  src="$(dirname "$MCPFC_LIB")/fixtures/mcp/server-json/own-repos/npm-external-registry.json"
  out="${WORK_DIR}/mcpfc-ext.json"
  mcp_render_fixture "$src" "$out" "SLUG=${slug}" "NPM_PKG=${MCPFC_PKG}"
  mcp_publish "$FC_REPO" "$out"
  why=$(mcp_check_problem 422 mcp_external_registry) || { echo "  ${why}"; return 1; }
  _mcpfc_anon_version "io.github.ak-e2e/${slug}" "1.0.0"
  why=$(mcp_check_plain_404) || { echo "  refused publish is readable: ${why}"; return 1; }
  echo "  422 mcp_external_registry, nothing stored"
}

# ---------------------------------------------------------------------------
# fc_cleanup - release a hold left by a failed case, drop the npm repo and
# the client workspace (the driver deletes $FC_REPO).
# ---------------------------------------------------------------------------
fc_cleanup() {
  [ -n "$MCPFC_AID" ] && mcp_release "$MCPFC_AID"
  api_delete "/api/v1/repositories/${MCPFC_NPM}" >/dev/null 2>&1 || true
  docker exec "$FC_CLIENT_CTR" rm -rf "$MCPFC_CW" >/dev/null 2>&1 || true
}
