#!/usr/bin/env bash
# =============================================================================
# tiers/mcp-registry/oracle.sh - MCP Registry (artifact-keeper#5253): publish
# with the real mcp-publisher, resolve + install + run the server from a
# client on the deployment network, held version 404 byte-identical to an
# unknown name, own-repos 422. See the manifest for the gates.
#
# run.sh exported BASE_URL, ADMIN_USER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH, AK_TEST_ROOT, DTF_DIR.
#
# The client side runs inside client-mcp (profiles/client.mcp.yml) by
# default. Overrides, for running the oracle outside a compose slot:
#   MCP_CLIENT_CTR   container to exec into (default ak-dtf<slot>-client-mcp)
#   MCP_INT_URL      backend URL as that container reaches it
#                    (default http://backend:8080)
#   MCP_CLIENT_MODE  "host" runs the client steps on the runner instead of in
#                    a container (needs node, npm, python3; MCP_INT_URL then
#                    defaults to BASE_URL)
#   MCP_PUBLISHER_BIN  a local mcp-publisher binary instead of the download
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${RUN_ID:?}"; : "${DTF_SLOT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
TEST_LIB="$(cd "$(dirname "$COMMON_SH")" && pwd)"
# The pinned publisher (MCP_PUBLISHER_VERSION + per-arch sha256), the echo
# server fixture, the not-found body and the request helpers all come from
# the corpus library, so the tier and tests/ can never pin different bytes.
# shellcheck source=/dev/null
source "${TEST_LIB}/mcp-helpers.sh"

TIER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

begin_suite "dtf-mcp-registry"
auth_admin
setup_workdir
require_cmd jq
require_cmd python3
mcp_require_registry

MODE="${MCP_CLIENT_MODE:-ctr}"
CTR="${MCP_CLIENT_CTR:-ak-dtf${DTF_SLOT}-client-mcp}"
if [ "$MODE" = "host" ]; then
  INT="${MCP_INT_URL:-$BASE_URL}"
  CW="${WORK_DIR}/client"
  mkdir -p "$CW"
else
  INT="${MCP_INT_URL:-http://backend:8080}"
  CW="/tmp/dtf-mcp-${RUN_ID}"
fi

SUF="$(printf '%s' "${RUN_ID}" | tr 'A-Z' 'a-z' | tr -c 'a-z0-9-' '-' | tail -c 24)"
SUF="${SUF#-}"
MCP_KEY="dtf-mcp-${SUF}"
NPM_PREFIX="dtf-mcpb-${SUF}"
SLUG="dtf-echo-${SUF}"
NAME="io.github.ak-e2e/${SLUG}"
PKG="ak-e2e-echo-${SUF}"
VER="1.0.0"
MARK="dtf-mcp-marker-${SUF}"
REG_INT="${INT}/mcp/${MCP_KEY}"

# --- client-side execution ---------------------------------------------------
# cx [-t SECS] SCRIPT: run SCRIPT in the client (container or host) with the
# CX_ENV pairs in its environment; output goes to stdout.
CX_ENV=()
cx() {
  local secs=180
  if [ "${1:-}" = "-t" ]; then secs="$2"; shift 2; fi
  local e=() kv
  if [ "$MODE" = "host" ]; then
    timeout "$secs" env "${CX_ENV[@]}" HOME="${CW}/home" bash -c "cd '${CW}' 2>/dev/null || true; $1" 2>&1
  else
    for kv in "${CX_ENV[@]}"; do e+=(-e "$kv"); done
    timeout "$secs" docker exec "${e[@]}" -e "HOME=${CW}/home" "$CTR" bash -c "cd '${CW}' 2>/dev/null || true; $1" 2>&1
  fi
}
# cx_put LOCAL CLIENT_PATH
cx_put() {
  if [ "$MODE" = "host" ]; then
    cp "$1" "$2"
  else
    docker cp "$1" "${CTR}:$2" >/dev/null 2>&1
  fi
}

DETAIL=""
note() { echo "   $1"; DETAIL="${DETAIL}$1
"; }

# =============================================================================
# preflight: does this candidate have the format at all? Two signals must
# agree before the tier stands down as NOT APPLICABLE: the format catalog
# lacks `mcp` AND repository creation answers `400 Invalid format: mcp`.
# =============================================================================
begin_test "preflight: the candidate serves the mcp repository format"
FMT="${WORK_DIR}/formats.json"
fcode=$(curl -s -o "$FMT" -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" -H "$(auth_header)" \
  "${BASE_URL}/api/v1/formats" 2>/dev/null) || fcode="000"
if [ "$fcode" != "200" ] || ! jq -e . "$FMT" >/dev/null 2>&1; then
  infra_fail "GET /api/v1/formats answered ${fcode}; cannot tell whether the candidate ships the format" "$(head -c 300 "$FMT" 2>/dev/null)"
  end_suite
fi
has_fmt=$(jq -r '[(if type == "array" then . else (.items // []) end)[] | select(.format_key == "mcp")] | length' "$FMT" 2>/dev/null || echo 0)
if [ "${has_fmt:-0}" = "0" ]; then
  probe_body=$(jq -cn --arg k "${MCP_KEY}-probe" '{key:$k,name:$k,format:"mcp",repo_type:"local",is_public:true}')
  pcode=$(curl -s -o "${WORK_DIR}/probe.json" -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" -X POST \
    -H "$(auth_header)" -H "Content-Type: application/json" -d "$probe_body" \
    "${BASE_URL}/api/v1/repositories" 2>/dev/null) || pcode="000"
  if [ "$pcode" = "400" ] && grep -q 'Invalid format: mcp' "${WORK_DIR}/probe.json" 2>/dev/null; then
    skip_not_applicable "the MCP Registry format is not in this candidate: /api/v1/formats lists no 'mcp' and POST /api/v1/repositories answers 400 Invalid format: mcp"
    end_suite
    exit 0
  fi
  [ "${pcode:0:1}" = "2" ] && api_delete "/api/v1/repositories/${MCP_KEY}-probe" >/dev/null 2>&1
  fail "the format catalog lists no 'mcp' but repository creation answered ${pcode} (not the 400 Invalid format refusal)" \
    "$(head -c 300 "${WORK_DIR}/probe.json" 2>/dev/null)"
  end_suite
fi
pass

# =============================================================================
# setup: npm backing repository with the echo server, the own-repos MCP
# repository mapped to it, a scoped API token, the client workspace
# =============================================================================
begin_test "setup: echo server in an npm Local, own-repos mcp repo mapped to it, client workspace ready"
ok=1
DETAIL=""
mcp_create_backing_repos "$NPM_PREFIX" || { ok=0; note "npm backing repo create failed"; }
NPM_KEY="${MCP_NPM_KEY:-}"
if [ "$ok" = 1 ] && ! mcp_publish_echo_package "$NPM_KEY" "$PKG" "$VER" "$NAME"; then
  ok=0; note "echo package publish to /npm/${NPM_KEY} answered ${MCP_STATUS}: $(mcp_snip)"
fi
if [ "$ok" = 1 ] && ! mcp_create_repo "$MCP_KEY" "$(jq -cn --argjson r "$(mcp_package_repos_json)" '{mcp_package_policy:"own-repos",mcp_package_repos:$r}')"; then
  ok=0; note "mcp repo create failed: ${MCP_CREATE_ERROR:-}"
fi
TOKEN=$(mcp_mint_token "$ADMIN_TOKEN" "dtf-mcp-${SUF}" '["read:artifacts","write:artifacts"]')
[ -n "$TOKEN" ] || { ok=0; note "API token mint returned no token"; }
if [ "$MODE" != "host" ] && ! docker exec "$CTR" true >/dev/null 2>&1; then
  ok=0; note "client container ${CTR} is not running"
fi
if [ "$ok" = 1 ]; then
  cx "cd / && rm -rf '${CW}' && mkdir -p '${CW}/home' '${CW}/pub' '${CW}/run'" >/dev/null || true
  cx_put "${TEST_LIB}/mcp-stdio-client.py" "${CW}/mcp-stdio-client.py" || { ok=0; note "copy stdio client failed"; }
  cx_put "${TIER_DIR}/resolve.js" "${CW}/resolve.js" || { ok=0; note "copy resolver failed"; }
  tools=$(cx 'for c in node npm python3; do command -v "$c" >/dev/null || echo "missing:$c"; done')
  [ -z "$tools" ] || { ok=0; note "client lacks: ${tools}"; }
fi
if [ "$ok" = 1 ]; then
  pass
else
  infra_fail "fixture setup failed; the candidate is unjudged" "$DETAIL"
  end_suite
fi

# Read the published version anonymously from the runner (the registry is
# public); sets MCP_STATUS/MCP_BODY/MCP_HDRS.
anon_version() { mcp_req GET "$(mcp_base "$MCP_KEY")/$(mcp_version_path "$1" "$2")" anon; }

# =============================================================================
# FIX: the real mcp-publisher publishes from the client container
# =============================================================================
begin_test "publish: mcp-publisher ${MCP_PUBLISHER_VERSION} publishes from the client; the version reads back with registryBaseUrl rewritten to /npm/${NPM_KEY}"
DETAIL=""
install_mcp_publisher
prc=$?
if [ "$prc" -ne 0 ]; then
  infra_fail "install_mcp_publisher failed (rc ${prc}): ${MCP_PUBLISHER_ERROR:-}"
  end_suite
fi
mcp_server_json "$NAME" "$VER" "$(mcp_npm_package_json "$PKG" "$VER")" > "${WORK_DIR}/server.json"
mcp_write_publisher_token "${WORK_DIR}/pubhome" "$REG_INT" "$TOKEN"
cx_put "$MCP_PUBLISHER" "${CW}/mcp-publisher"
cx_put "${WORK_DIR}/server.json" "${CW}/pub/server.json"
cx "mkdir -p '${CW}/home/.config/mcp-publisher'" >/dev/null
cx_put "${WORK_DIR}/pubhome/.config/mcp-publisher/token.json" "${CW}/home/.config/mcp-publisher/token.json"
pub_out=$(cx -t 90 "chmod +x '${CW}/mcp-publisher' && cd '${CW}/pub' && '${CW}/mcp-publisher' publish; echo \"publisher-exit=\$?\"")
note "$(printf '%s' "$pub_out" | tail -n 6)"
anon_version "$NAME" "$VER"
adv=$(mcp_json '.server.packages[0].registryBaseUrl // empty')
if ! printf '%s' "$pub_out" | grep -q 'publisher-exit=0'; then
  fail "mcp-publisher publish did not exit 0" "$DETAIL"
elif [ "$MCP_STATUS" != "200" ]; then
  fail "anonymous read of ${NAME}@${VER} answered ${MCP_STATUS} after a successful publish: $(mcp_snip)" "$DETAIL"
elif [ "$(mcp_url_path "$adv")" != "/npm/${NPM_KEY}" ] \
  || [ "$(mcp_json '.server.packages[0].identifier')" != "$PKG" ] \
  || [ "$(mcp_json '.server.packages[0].version')" != "$VER" ]; then
  fail "served package is not pinned to the backing repository (registryBaseUrl='${adv}', want path /npm/${NPM_KEY})" "$(mcp_snip)"
else
  pass
fi
PUBLISHED=0
[ "$MCP_STATUS" = "200" ] && PUBLISHED=1

# =============================================================================
# CONTROL: the pinned package installs from the npm repository directly
# =============================================================================
begin_test "control: ${PKG}@${VER} installs from /npm/${NPM_KEY} directly (backing repository sound)"
CX_ENV=("NPMREG=${INT}/npm/${NPM_KEY}/" "SPEC=${PKG}@${VER}")
ctl=$(cx -t 240 'rm -rf ctl && mkdir -p ctl && npm install --prefix ctl --registry "$NPMREG" --cache "$PWD/npmcache-ctl" --no-audit --no-fund --no-package-lock "$SPEC" >ctl.log 2>&1; rc=$?; tail -n 5 ctl.log; test -f ctl/node_modules/'"${PKG}"'/bin/server.js && echo installed-ok; echo "rc=$rc"')
if printf '%s' "$ctl" | grep -q installed-ok; then
  pass
else
  infra_fail "npm cannot install the fixture from its own npm repository; the MCP layer cannot be judged" "$ctl"
fi

# =============================================================================
# FIX: resolve from the registry, install from the advertised location, run
# =============================================================================
begin_test "consume: the client resolves ${NAME} (latest) from the registry, npm-installs packages[0] from its registryBaseUrl and runs it over stdio"
DETAIL=""
CX_ENV=("REG=${REG_INT}" "NAME=${NAME}" "VER=latest")
res=$(cx -t 60 'node resolve.js')
note "resolve: ${res}"
r_status=$(printf '%s' "$res" | tail -n1 | jq -r '.status // empty' 2>/dev/null)
r_use=$(printf '%s' "$res" | tail -n1 | jq -r '.use // empty' 2>/dev/null)
r_id=$(printf '%s' "$res" | tail -n1 | jq -r '.identifier // empty' 2>/dev/null)
r_ver=$(printf '%s' "$res" | tail -n1 | jq -r '.version // empty' 2>/dev/null)
if [ "$PUBLISHED" != 1 ]; then
  fail "skipped: the publish above did not produce a readable version"
elif [ "$r_status" != "200" ] || [ -z "$r_use" ] || [ "$r_id" != "$PKG" ] || [ "$r_ver" != "$VER" ]; then
  fail "the client could not resolve the server's package from the registry" "$DETAIL"
else
  CX_ENV=("NPMREG=${r_use}/" "SPEC=${r_id}@${r_ver}" "ID=${r_id}" "CALL=echo={\"text\":\"${MARK}\"}")
  run=$(cx -t 300 'rm -rf run && mkdir -p run && npm install --prefix run --registry "$NPMREG" --cache "$PWD/npmcache-run" --no-audit --no-fund --no-package-lock "$SPEC" >run.log 2>&1 || { tail -n 20 run.log; echo npm-install-failed; exit 0; }
python3 mcp-stdio-client.py --timeout 20 --call "$CALL" -- "run/node_modules/.bin/ak-e2e-echo-mcp"')
  out=$(printf '%s' "$run" | tail -n1)
  note "run: $(printf '%s' "$run" | tail -n 3)"
  names=$(printf '%s' "$out" | jq -r '.toolNames // [] | join(",")' 2>/dev/null)
  text=$(printf '%s' "$out" | jq -r '.calls[0].text // empty' 2>/dev/null)
  if printf '%s' "$run" | grep -q npm-install-failed; then
    fail "npm install from the advertised registryBaseUrl (${r_use}) failed" "$DETAIL"
  elif [ "$names" != "echo" ] || [ "$text" != "$MARK" ]; then
    fail "the installed server did not answer tools/list=[echo] and echo(${MARK}) (toolNames='${names}' text='${text}')" "$DETAIL"
  else
    pass
  fi
fi

# =============================================================================
# FIX: own-repos refuses what this instance does not host, storing nothing
# =============================================================================
OWN="${AK_TEST_ROOT:-${TEST_LIB}/../..}/tests/fixtures/mcp/server-json/own-repos"
own_case() { # <fixture> <expected error> <slug>
  local out="${WORK_DIR}/own-$3.json"
  mcp_render_fixture "${OWN}/$1" "$out" "SLUG=$3" "NPM_PKG=${PKG}"
  mcp_publish "$MCP_KEY" "$out" "$TOKEN"
  local why
  if ! why=$(mcp_check_problem 422 "$2"); then
    note "$1: ${why}"
    return 1
  fi
  anon_version "io.github.ak-e2e/$3" "1.0.0"
  if ! why=$(mcp_check_plain_404); then
    note "$1: refused publish left a readable version: ${why}"
    return 1
  fi
  note "$1: 422 $2, nothing stored"
}
begin_test "own-repos: a package on registry.npmjs.org is 422 mcp_external_registry and an absent package is 422 mcp_package_not_found; nothing stored"
DETAIL=""
own_ok=1
own_case npm-external-registry.json mcp_external_registry "${SLUG}-ext" || own_ok=0
own_case npm-not-found.json mcp_package_not_found "${SLUG}-nf" || own_ok=0
if [ "$own_ok" = 1 ]; then pass; else fail "own-repos did not refuse as documented" "$DETAIL"; fi

# =============================================================================
# FIX: a held version is indistinguishable from an unknown name
# =============================================================================
begin_test "held: with the pinned tarball quarantined, a reader's 404 for ${NAME}@${VER} is byte-identical to an unknown name's; the holder sees mcp_backing_artifact_blocked; release restores 200"
DETAIL=""
held_ok=1
AID=$(mcp_artifact_id "$NPM_KEY" "${PKG}-${VER}\\.tgz$")
if [ "$PUBLISHED" != 1 ]; then
  fail "skipped: the publish above did not produce a readable version"
elif [ -z "$AID" ]; then
  infra_fail "no artifact id for ${PKG}-${VER}.tgz in ${NPM_KEY}; cannot place the hold"
elif ! mcp_quarantine "$AID" "dtf mcp-registry hold"; then
  infra_fail "quarantine of artifact ${AID} answered ${MCP_STATUS}: $(mcp_snip)"
else
  add_exit_handler "curl -s -o /dev/null --max-time 30 -X POST -H \"\$(auth_header)\" -H 'Content-Type: application/json' -d '{}' \"${BASE_URL}/api/v1/quarantine/${AID}/release\" || true"
  anon_version "io.github.ak-e2e/${SLUG}-absent" "$VER"
  cp "$MCP_BODY" "${WORK_DIR}/unknown.body"; cp "$MCP_HDRS" "${WORK_DIR}/unknown.hdrs"
  u_status="$MCP_STATUS"
  anon_version "$NAME" "$VER"
  if ! why=$(mcp_check_plain_404); then
    held_ok=0; note "reader: ${why}"
  fi
  if [ "$u_status" != "404" ] || ! cmp -s "$MCP_BODY" "${WORK_DIR}/unknown.body"; then
    held_ok=0; note "reader body differs from the unknown-name body (unknown ${u_status}: $(head -c 200 "${WORK_DIR}/unknown.body"))"
  fi
  if [ "$(mcp_stable_headers "$MCP_HDRS")" != "$(mcp_stable_headers "${WORK_DIR}/unknown.hdrs")" ]; then
    held_ok=0
    note "reader headers differ from the unknown-name headers: $(diff <(mcp_stable_headers "${WORK_DIR}/unknown.hdrs") <(mcp_stable_headers "$MCP_HDRS") | tr '\n' ' ')"
  fi
  CX_ENV=("REG=${REG_INT}" "NAME=${NAME}" "VER=latest")
  hs=$(cx -t 60 'node resolve.js' | tail -n1 | jq -r '.status // empty' 2>/dev/null)
  [ "$hs" = "404" ] || { held_ok=0; note "client resolve of latest while held answered '${hs}', want 404"; }
  mcp_req GET "$(mcp_base "$MCP_KEY")/$(mcp_version_path "$NAME" "$VER")" admin
  if ! why=$(mcp_check_problem 404 mcp_backing_artifact_blocked); then
    held_ok=0; note "holder: ${why}"
  elif grep -qF -e "$NPM_KEY" -e "$AID" "$MCP_BODY"; then
    held_ok=0; note "holder body names the backing repository or artifact id: $(mcp_snip)"
  fi
  if mcp_release "$AID"; then
    anon_version "$NAME" "$VER"
    [ "$MCP_STATUS" = "200" ] || { held_ok=0; note "after release the version answers ${MCP_STATUS}: $(mcp_snip)"; }
  else
    held_ok=0; note "release of ${AID} answered ${MCP_STATUS}"
  fi
  if [ "$held_ok" = 1 ]; then pass; else fail "the hold leaked or did not apply" "$DETAIL"; fi
fi

if [ "$MODE" != "host" ]; then
  docker exec "$CTR" rm -rf "$CW" >/dev/null 2>&1 || true
fi
end_suite
