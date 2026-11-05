#!/usr/bin/env bash
# test-mcp-backing-quarantine.sh - a held version disappears from an MCP
# registry, and only a repository holder learns why (artifact-keeper#5253).
#
# Two echo package versions (1.0.0, 1.1.0) are published to an npm Local and
# two server versions pin them in an own-repos MCP repository. Quarantining
# the 1.1.0 npm tarball holds server version 1.1.0:
#
#   - omitted from /servers, /versions and search; versions/latest answers
#     1.0.0 with isLatest true
#   - a reader (anonymous, or an authenticated user without a grant) gets the
#     unknown-name 404, byte for byte and header for header the answer for an
#     unknown version and an unknown name
#   - a repository holder (a user with read on the MCP repository through a
#     grant, and the administrator) gets 404 problem+json with error
#     mcp_backing_artifact_blocked, gate quarantine and the package as
#     submitted, and never the backing repository key or an artifact id
#   - every answer is Cache-Control: no-store; include_deleted=true reveals
#     nothing
#   - releasing the tarball restores the version in list and latest
#
# Then the server.json artifact of 1.1.0 itself is quarantined:
# mcp_pending_review for holders, plain 404 for readers, restored on release.
#
# Requires: curl, jq, python3, tar

# shellcheck source=../lib/common.sh disable=SC1091
source "$(dirname "$0")/../lib/common.sh"
# shellcheck source=../lib/mcp-helpers.sh disable=SC1091
source "$(dirname "$0")/../lib/mcp-helpers.sh"

begin_suite "mcp-backing-quarantine"
auth_admin
setup_workdir
require_cmd curl
require_cmd jq
require_cmd python3
require_cmd tar
mcp_require_registry

MCP_KEY="test-mcp-q-${RUN_ID}"
NS="io.github.ak-e2e-${RUN_ID}"
SERVER="${NS}/held"
ECHO_PKG="ak-e2e-echo-q-${RUN_ID}"
HOLDER_USER="mcpq-holder-${RUN_ID}"
READER_USER="mcpq-reader-${RUN_ID}"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# snapshot AUTH TAIL LABEL: GET and keep body/headers as WORK_DIR/LABEL.{body,hdrs}
snapshot() {
  mcp_get "$MCP_KEY" "$2" "$1"
  cp "$MCP_BODY" "${WORK_DIR}/$3.body"
  mcp_stable_headers "$MCP_HDRS" > "${WORK_DIR}/$3.hdrs"
  printf '%s' "$MCP_STATUS" > "${WORK_DIR}/$3.status"
}

# same_answer A B: 0 when two snapshots match in status, body and stable headers.
same_answer() {
  cmp -s "${WORK_DIR}/$1.status" "${WORK_DIR}/$2.status" \
    && cmp -s "${WORK_DIR}/$1.body" "${WORK_DIR}/$2.body" \
    && cmp -s "${WORK_DIR}/$1.hdrs" "${WORK_DIR}/$2.hdrs"
}

answer_diff() {
  echo "status $(cat "${WORK_DIR}/$1.status") vs $(cat "${WORK_DIR}/$2.status")"
  echo "body A: $(head -c 300 "${WORK_DIR}/$1.body")"
  echo "body B: $(head -c 300 "${WORK_DIR}/$2.body")"
  diff "${WORK_DIR}/$1.hdrs" "${WORK_DIR}/$2.hdrs" | head -20
}

listed_versions() {
  mcp_get "$MCP_KEY" "$1" "${2:-anon}"
  jq -r --arg n "$SERVER" '[.servers[]? | select(.server.name == $n) | .server.version] | join(",")' "$MCP_BODY" 2>/dev/null
}

V110="$(mcp_version_path "$SERVER" "1.1.0")"
V_LATEST="servers/$(mcp_encode_name "$SERVER")/versions/latest"
V_UNKNOWN="$(mcp_version_path "$SERVER" "9.9.9")"
N_UNKNOWN="$(mcp_version_path "${NS}/no-such-server" "1.1.0")"
SEARCH="servers?search=$(jq -rn --arg v "$SERVER" '$v|@uri')"

# check_reader_plain AUTH LABEL: the exact read of 1.1.0 matches the unknown
# version and the unknown name byte for byte. Records pass/fail.
check_reader_plain() {
  local auth="$1" label="$2"
  snapshot "$auth" "$V110" "${label}-held"
  local r
  r=$(mcp_check_plain_404) || { fail "${label}: ${r}"; return; }
  snapshot "$auth" "$V_UNKNOWN" "${label}-unknown-version"
  snapshot "$auth" "$N_UNKNOWN" "${label}-unknown-name"
  if ! same_answer "${label}-held" "${label}-unknown-version"; then
    fail "${label}: held answer differs from the unknown-version answer" "$(answer_diff "${label}-held" "${label}-unknown-version")"
  elif ! same_answer "${label}-held" "${label}-unknown-name"; then
    fail "${label}: held answer differs from the unknown-name answer" "$(answer_diff "${label}-held" "${label}-unknown-name")"
  else
    pass
  fi
}

# check_holder_reason AUTH ERROR [GATE|HOLD]: the exact read of 1.1.0 is a
# 404 reason body for a holder. Records pass/fail.
check_holder_reason() {
  local auth="$1" code="$2" kind="$3" r why=""
  mcp_get "$MCP_KEY" "$V110" "$auth"
  r=$(mcp_check_problem 404 "$code") || { fail "$r"; return; }
  [ "$(mcp_json '.name')" = "$SERVER" ] || why="${why} name='$(mcp_json '.name')';"
  [ "$(mcp_json '.version')" = "1.1.0" ] || why="${why} version='$(mcp_json '.version')';"
  case "$kind" in
    gate)
      [ "$(mcp_json '.gate')" = "quarantine" ] || why="${why} gate='$(mcp_json '.gate')';"
      [[ "$(mcp_json '.package // empty')" == *"${ECHO_PKG}"* ]] || why="${why} package='$(mcp_json '.package // empty')' does not name ${ECHO_PKG};"
      ;;
    hold)
      [ "$(mcp_json '.hold')" = "quarantine" ] || why="${why} hold='$(mcp_json '.hold')';"
      ;;
  esac
  local leak
  for leak in "$MCP_NPM_KEY" "$TARBALL_ID" "$TARBALL_ID_OLD" "$SJ_ID" "$SJ_ID_OLD"; do
    [ -n "$leak" ] || continue
    if grep -qF "$leak" "$MCP_BODY"; then
      why="${why} body names '${leak}';"
    fi
  done
  if [ -z "$why" ]; then pass; else fail "holder reason body:${why}" "$(mcp_snip)"; fi
}

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

begin_test "Publish echo 1.0.0 and 1.1.0 to the npm backing repository"
if ! mcp_create_backing_repos "test-mcp-q-${RUN_ID}"; then
  fail_fatal "could not create the npm backing repository"
fi
why=""
mcp_publish_echo_package "$MCP_NPM_KEY" "$ECHO_PKG" "1.0.0" "$SERVER" || why="${why} 1.0.0=${MCP_STATUS};"
mcp_publish_echo_package "$MCP_NPM_KEY" "$ECHO_PKG" "1.1.0" "$SERVER" || why="${why} 1.1.0=${MCP_STATUS};"
if [ -z "$why" ]; then pass; else fail_fatal "npm publish failed:${why}" "$(mcp_snip)"; fi

begin_test "Create MCP repository and publish server versions 1.0.0 and 1.1.0"
if ! mcp_create_repo "$MCP_KEY" "$(jq -cn --argjson m "$(mcp_package_repos_json)" '{mcp_package_repos:$m}')"; then
  fail_fatal "could not create MCP repository: ${MCP_CREATE_ERROR}"
fi
why=""
for v in 1.0.0 1.1.0; do
  mcp_server_json "$SERVER" "$v" "$(mcp_npm_package_json "$ECHO_PKG" "$v")" > "${WORK_DIR}/server-${v}.json"
  mcp_publish "$MCP_KEY" "${WORK_DIR}/server-${v}.json"
  [ "$MCP_STATUS" = "200" ] || why="${why} ${v}=${MCP_STATUS} $(mcp_snip);"
done
if [ -z "$why" ]; then pass; else fail_fatal "server publish failed:${why}"; fi

begin_test "Resolve artifact ids and create the holder and reader users"
TARBALL_ID=$(mcp_artifact_id "$MCP_NPM_KEY" "/-/${ECHO_PKG}-1\\.1\\.0\\.tgz$")
TARBALL_ID_OLD=$(mcp_artifact_id "$MCP_NPM_KEY" "/-/${ECHO_PKG}-1\\.0\\.0\\.tgz$")
SJ_ID=$(mcp_artifact_id "$MCP_KEY" "^servers/${SERVER//./\\.}/1\\.1\\.0/server\\.json$")
SJ_ID_OLD=$(mcp_artifact_id "$MCP_KEY" "^servers/${SERVER//./\\.}/1\\.0\\.0/server\\.json$")
why=""
[ -n "$TARBALL_ID" ] || why="${why} no 1.1.0 tarball artifact;"
[ -n "$SJ_ID" ] || why="${why} no 1.1.0 server.json artifact;"
mcp_make_user "$HOLDER_USER" > "${WORK_DIR}/holder.tok" || why="${why} holder user;"
HOLDER_TOKEN=$(cat "${WORK_DIR}/holder.tok")
HOLDER_ID="$MCP_USER_ID"
mcp_make_user "$READER_USER" > "${WORK_DIR}/reader.tok" || why="${why} reader user;"
READER_TOKEN=$(cat "${WORK_DIR}/reader.tok")
if [ -n "$HOLDER_ID" ] && ! mcp_grant "$HOLDER_ID" "$MCP_KEY" '["read"]'; then
  why="${why} read grant HTTP ${MCP_STATUS} $(mcp_snip);"
fi
[ -n "$HOLDER_TOKEN" ] && [ -n "$READER_TOKEN" ] || why="${why} missing user token;"
if [ -z "$why" ]; then pass; else fail_fatal "setup:${why}"; fi

begin_test "Before the hold: 1.1.0 is listed and latest"
l=$(listed_versions servers)
mcp_get "$MCP_KEY" "$V_LATEST" anon
if [ "$l" = "1.0.0,1.1.0" ] && [ "$(mcp_json '.server.version')" = "1.1.0" ]; then
  pass
else
  fail_fatal "listed '${l}', latest '$(mcp_json '.server.version')'"
fi

# ---------------------------------------------------------------------------
# Backing package quarantined
# ---------------------------------------------------------------------------

begin_test "Quarantine the 1.1.0 npm tarball"
if mcp_quarantine "$TARBALL_ID" "release-gate MCP backing hold ${RUN_ID}"; then
  pass
else
  fail_fatal "quarantine returned HTTP ${MCP_STATUS}" "$(mcp_snip)"
fi

begin_test "Held 1.1.0 is omitted from /servers, /versions and search"
l=$(listed_versions servers)
s=$(listed_versions "$SEARCH")
lt=$(listed_versions "servers?version=latest")
mcp_get "$MCP_KEY" "servers/$(mcp_encode_name "$SERVER")/versions" anon
v=$(jq -r '[.servers[]?.server.version] | join(",")' "$MCP_BODY" 2>/dev/null)
if [ "$l" = "1.0.0" ] && [ "$s" = "1.0.0" ] && [ "$v" = "1.0.0" ] && [ "$lt" = "1.0.0" ]; then
  pass
else
  fail "list='${l}' search='${s}' versions='${v}' version=latest='${lt}'"
fi

begin_test "versions/latest answers 1.0.0 with isLatest true"
mcp_get "$MCP_KEY" "$V_LATEST" anon
if [ "$MCP_STATUS" = "200" ] && [ "$(mcp_json '.server.version')" = "1.0.0" ] \
   && [ "$(mcp_json '._meta["io.modelcontextprotocol.registry/official"].isLatest')" = "true" ]; then
  pass
else
  fail "latest HTTP ${MCP_STATUS} version '$(mcp_json '.server.version')' isLatest '$(mcp_json '._meta["io.modelcontextprotocol.registry/official"].isLatest')'" "$(mcp_snip)"
fi

begin_test "Anonymous reader: held 1.1.0 is byte-identical to an unknown version and an unknown name"
check_reader_plain anon anon

begin_test "Authenticated user without a grant gets the plain 404"
check_reader_plain "$READER_TOKEN" reader

begin_test "Grant holder gets 404 mcp_backing_artifact_blocked, gate quarantine, no backing repo or artifact id"
check_holder_reason "$HOLDER_TOKEN" mcp_backing_artifact_blocked gate
cp "$MCP_BODY" "${WORK_DIR}/holder-reason.body"

begin_test "Administrator gets the same reason body"
check_holder_reason admin mcp_backing_artifact_blocked gate
if [ "$(jq -S -c 'del(.instance)' "$MCP_BODY" 2>/dev/null)" != "$(jq -S -c 'del(.instance)' "${WORK_DIR}/holder-reason.body" 2>/dev/null)" ]; then
  echo "  note: admin and holder bodies differ: admin=$(mcp_snip) holder=$(head -c 300 "${WORK_DIR}/holder-reason.body")"
fi

begin_test "Holder's view of the listings omits the held version too"
l=$(listed_versions servers "$HOLDER_TOKEN")
mcp_get "$MCP_KEY" "$V_LATEST" "$HOLDER_TOKEN"
if [ "$l" = "1.0.0" ] && [ "$(mcp_json '.server.version')" = "1.0.0" ]; then
  pass
else
  fail "holder list '${l}' latest '$(mcp_json '.server.version')'"
fi

begin_test "include_deleted=true does not reveal the held version"
l=$(listed_versions "servers?include_deleted=true")
mcp_get "$MCP_KEY" "servers/$(mcp_encode_name "$SERVER")/versions?include_deleted=true" anon
v=$(jq -r '[.servers[]?.server.version] | join(",")' "$MCP_BODY" 2>/dev/null)
mcp_get "$MCP_KEY" "${V110}?include_deleted=true" anon
r=$(mcp_check_plain_404)
if [ "$l" = "1.0.0" ] && [ "$v" = "1.0.0" ] && [ -z "$r" ]; then
  pass
else
  fail "include_deleted list='${l}' versions='${v}' exact: ${r:-ok}"
fi

begin_test "Release restores 1.1.0 in list and latest"
if ! mcp_release "$TARBALL_ID"; then
  fail "release returned HTTP ${MCP_STATUS}" "$(mcp_snip)"
else
  l=$(listed_versions servers)
  mcp_get "$MCP_KEY" "$V_LATEST" anon
  lat=$(mcp_json '.server.version')
  mcp_get "$MCP_KEY" "$V110" anon
  if [ "$l" = "1.0.0,1.1.0" ] && [ "$lat" = "1.1.0" ] && [ "$MCP_STATUS" = "200" ]; then
    pass
  else
    fail "after release: list='${l}' latest='${lat}' exact HTTP ${MCP_STATUS}"
  fi
fi

# ---------------------------------------------------------------------------
# server.json artifact quarantined
# ---------------------------------------------------------------------------

begin_test "Quarantine the 1.1.0 server.json artifact"
if mcp_quarantine "$SJ_ID" "release-gate MCP document hold ${RUN_ID}"; then
  pass
else
  fail_fatal "quarantine returned HTTP ${MCP_STATUS}" "$(mcp_snip)"
fi

begin_test "server.json hold: omitted from list, latest skips it"
l=$(listed_versions servers)
mcp_get "$MCP_KEY" "$V_LATEST" anon
if [ "$l" = "1.0.0" ] && [ "$(mcp_json '.server.version')" = "1.0.0" ]; then
  pass
else
  fail "list='${l}' latest='$(mcp_json '.server.version')'"
fi

begin_test "server.json hold: plain 404 for an anonymous reader"
check_reader_plain anon anon-sj

begin_test "server.json hold: plain 404 for a user without a grant"
check_reader_plain "$READER_TOKEN" reader-sj

begin_test "server.json hold: holder gets 404 mcp_pending_review, hold quarantine"
check_holder_reason "$HOLDER_TOKEN" mcp_pending_review hold

begin_test "server.json hold: administrator gets mcp_pending_review"
check_holder_reason admin mcp_pending_review hold

begin_test "Release of the server.json restores 1.1.0"
if ! mcp_release "$SJ_ID"; then
  fail "release returned HTTP ${MCP_STATUS}" "$(mcp_snip)"
else
  l=$(listed_versions servers)
  mcp_get "$MCP_KEY" "$V_LATEST" anon
  if [ "$l" = "1.0.0,1.1.0" ] && [ "$(mcp_json '.server.version')" = "1.1.0" ]; then
    pass
  else
    fail "after release: list='${l}' latest='$(mcp_json '.server.version')'"
  fi
fi

end_suite
