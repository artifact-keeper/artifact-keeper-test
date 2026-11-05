#!/usr/bin/env bash
# test-mcp-held-response-indistinguishable.sh - a reader cannot tell a held
# server version from one that does not exist (artifact-keeper#5253;
# docs/mcp-registry.md "What a client sees").
#
# Every hidden answer on the /mcp/ surface is 404 application/problem+json
# with Cache-Control: no-store, and for a reader (anonymous on a public
# repository, or an authenticated user with no grant) it is byte for byte
# the unknown-name answer (MCP_NOT_FOUND_BODY) with the same headers.
#
# Cases, each read as anonymous and as a no-grant user, on /v0.1 and /v0, with
# the name URL-encoded and with a literal slash, all with an Origin header so
# the CORS headers are part of the comparison:
#   unknown name; unknown version of a known name; pinned package held by
#   quarantine (backing hold); server.json itself quarantined; pinned package
#   deleted through the artifact API (unresolvable); status deleted (without
#   include_deleted).
# Plus, for servers whose every version is hidden: /versions and
# /versions/latest are the plain 404 (VS Code reads a 404 on latest as "not
# in the registry"; any other status keeps a previously verified server).
#
# Discriminating control: the administrator (a repository holder) gets a
# differing reason body for the holds, so the readers' identical answers are
# the gate's doing, not a missing version.

# shellcheck source=../lib/common.sh disable=SC1091
source "$(dirname "$0")/../lib/common.sh"
# shellcheck source=../lib/mcp-helpers.sh disable=SC1091
source "$(dirname "$0")/../lib/mcp-helpers.sh"

begin_suite "mcp-held-response-indistinguishable"
auth_admin
setup_workdir
require_cmd curl
require_cmd jq
require_cmd python3
require_cmd tar
mcp_require_registry

PREFIX="sec-mcpheld-${RUN_ID}"
KEY="${PREFIX}-mcp"
PKG="@ak-e2e/held-${RUN_ID}"
NS="io.github.ak-e2e"
KNOWN="${NS}/held-known-${RUN_ID}"
BACKING="${NS}/held-backing-${RUN_ID}"
SELF="${NS}/held-self-${RUN_ID}"
GONE="${NS}/held-gone-${RUN_ID}"
DELETED="${NS}/held-deleted-${RUN_ID}"
UNKNOWN="${NS}/held-never-${RUN_ID}"
ORIGIN="https://client.example.invalid"

# publish_server NAME VERSION PKG_VERSION: sets LAST_SERVER_AID.
publish_server() {
  mcp_server_json "$1" "$2" "$(mcp_npm_package_json "$PKG" "$3")" > "${WORK_DIR}/srv.json"
  mcp_publish "$KEY" "${WORK_DIR}/srv.json"
  LAST_SERVER_AID=$(mcp_json '._meta["com.artifactkeeper.registry/source"].artifactId // empty')
  [ "$MCP_STATUS" = "200" ]
}

begin_test "Fixtures: backing npm, MCP repository, echo package versions 1-4"
ok=true
mcp_create_backing_repos "$PREFIX" || ok=false
$ok && { mcp_create_repo "$KEY" "{\"mcp_package_repos\":$(mcp_package_repos_json)}" || ok=false; }
for v in 1.0.0 2.0.0 4.0.0; do
  $ok && { mcp_publish_echo_package "$MCP_NPM_KEY" "$PKG" "$v" "$KNOWN" || ok=false; }
done
if $ok; then pass; else fail_fatal "fixture setup failed: ${MCP_CREATE_ERROR:-HTTP ${MCP_STATUS:-?}}"; fi

begin_test "Fixtures: publish one server per hidden state"
ok=true
publish_server "$KNOWN" 1.0.0 4.0.0 || ok=false
publish_server "$BACKING" 1.0.0 1.0.0 || ok=false
publish_server "$SELF" 1.0.0 4.0.0 || ok=false
SELF_AID="$LAST_SERVER_AID"
publish_server "$GONE" 1.0.0 2.0.0 || ok=false
publish_server "$DELETED" 1.0.0 4.0.0 || ok=false
if $ok && [ -n "$SELF_AID" ]; then pass; else fail_fatal "server publish failed: HTTP ${MCP_STATUS}: $(mcp_snip)"; fi

begin_test "Fixtures: quarantine the backing package, the server.json, delete a package, delete a status"
ok=true
why=""
AID_PKG1=$(mcp_artifact_id "$MCP_NPM_KEY" '1\.0\.0\.tgz$')
PKG2_PATH=$(curl -s "${CURL_TIMEOUT_ARGS[@]}" -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${MCP_NPM_KEY}/artifacts?per_page=200" \
  | jq -r '[(.items // .artifacts // .data // .)[]? | select((.path // "") | test("2\\.0\\.0\\.tgz$"))][0].path // empty')
mcp_quarantine "$AID_PKG1" || { ok=false; why="${why} backing quarantine ${MCP_STATUS}"; }
mcp_quarantine "$SELF_AID" || { ok=false; why="${why} server.json quarantine ${MCP_STATUS}"; }
st=$(curl -s -o /dev/null -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" -X DELETE -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${MCP_NPM_KEY}/artifacts/${PKG2_PATH}" 2>/dev/null) || st="000"
[ -n "$PKG2_PATH" ] && [ "${st:0:1}" = "2" ] || { ok=false; why="${why} package delete ${st} (${PKG2_PATH})"; }
mcp_patch_status "$KEY" "$DELETED" 1.0.0 deleted "release-gate" || true
[ "$MCP_STATUS" = "200" ] || { ok=false; why="${why} status deleted ${MCP_STATUS}"; }
if $ok; then pass; else fail_fatal "hold setup failed:${why}"; fi

begin_test "Fixtures: an authenticated user with no grant on the repository"
if mcp_make_user "mcpheld-${RUN_ID}" > "${WORK_DIR}/tok"; then
  TOK_NONE=$(cat "${WORK_DIR}/tok")
  pass
else
  fail_fatal "user creation failed"
fi

# ---------------------------------------------------------------------------
# Collect
# ---------------------------------------------------------------------------

# Reference: anonymous, /v0.1, encoded, unknown name.
mcp_req GET "$(mcp_base "$KEY")/$(mcp_version_path "$UNKNOWN" 1.0.0)" anon -H "Origin: ${ORIGIN}"
REF_STATUS="$MCP_STATUS"
REF_BODY=$(cat "$MCP_BODY")
REF_HDRS=$(mcp_stable_headers "$MCP_HDRS")

begin_test "Reference: the unknown-name answer is MCP_NOT_FOUND_BODY with problem+json, no-store and CORS"
if ! why=$(mcp_check_plain_404); then
  fail "unknown name: ${why}"
elif [ "$(mcp_header access-control-allow-origin)" != "*" ]; then
  fail "unknown-name 404 lacks Access-Control-Allow-Origin: * (headers: ${REF_HDRS})"
else
  pass
fi

# compare_reader WHO LABEL URL: the answer must equal the reference.
compare_reader() {
  local who="$1" label="$2" url="$3" hdrs
  mcp_req GET "$url" "$who" -H "Origin: ${ORIGIN}"
  hdrs=$(mcp_stable_headers "$MCP_HDRS")
  if [ "$MCP_STATUS" != "$REF_STATUS" ]; then
    echo "${label}: HTTP ${MCP_STATUS} (reference ${REF_STATUS}): $(mcp_snip)"
    return 1
  fi
  if [ "$(cat "$MCP_BODY")" != "$REF_BODY" ]; then
    echo "${label}: body differs from the unknown-name body: $(mcp_snip)"
    return 1
  fi
  if [ "$hdrs" != "$REF_HDRS" ]; then
    echo "${label}: headers differ from the unknown-name answer: $(diff <(printf '%s\n' "$REF_HDRS") <(printf '%s\n' "$hdrs") | tr '\n' ' ')"
    return 1
  fi
  return 0
}

declare -A CASES=(
  ["unknown name"]="${UNKNOWN}|1.0.0"
  ["unknown version of a known name"]="${KNOWN}|9.9.9"
  ["pinned package quarantined"]="${BACKING}|1.0.0"
  ["server.json quarantined"]="${SELF}|1.0.0"
  ["pinned package deleted (unresolvable)"]="${GONE}|1.0.0"
  ["status deleted"]="${DELETED}|1.0.0"
)
CASE_ORDER=("unknown name" "unknown version of a known name" "pinned package quarantined" \
  "server.json quarantined" "pinned package deleted (unresolvable)" "status deleted")

for who in anon user; do
  auth="anon"
  [ "$who" = "user" ] && auth="$TOK_NONE"
  for label in "${CASE_ORDER[@]}"; do
    name="${CASES[$label]%%|*}"
    version="${CASES[$label]##*|}"
    begin_test "Reader (${who}): ${label} is indistinguishable from an unknown name"
    bad=""
    for api in v0.1 v0; do
      root="${BASE_URL}/mcp/${KEY}/${api}"
      out=$(compare_reader "$auth" "${api} encoded" "${root}/$(mcp_version_path "$name" "$version")") || bad="${bad} ${out};"
      out=$(compare_reader "$auth" "${api} literal" "${root}/servers/${name}/versions/${version}") || bad="${bad} ${out};"
    done
    if [ -z "$bad" ]; then pass; else fail "${label} (${who}):${bad}"; fi
  done
done

# Servers whose every version is hidden: /versions and /versions/latest.
for who in anon user; do
  auth="anon"
  [ "$who" = "user" ] && auth="$TOK_NONE"
  for name in "$BACKING" "$SELF" "$GONE" "$DELETED"; do
    begin_test "Reader (${who}): held-only ${name##*/} /versions and /versions/latest are the plain 404"
    bad=""
    for api in v0.1 v0; do
      root="${BASE_URL}/mcp/${KEY}/${api}"
      enc=$(mcp_encode_name "$name")
      out=$(compare_reader "$auth" "${api} versions" "${root}/servers/${enc}/versions") || bad="${bad} ${out};"
      out=$(compare_reader "$auth" "${api} latest" "${root}/servers/${enc}/versions/latest") || bad="${bad} ${out};"
      out=$(compare_reader "$auth" "${api} literal latest" "${root}/servers/${name}/versions/latest") || bad="${bad} ${out};"
    done
    if [ -z "$bad" ]; then pass; else fail "held-only ${name}:${bad}"; fi
  done
done

begin_test "Reader: the listing shows only the servable server"
mcp_get "$KEY" "servers?limit=100" anon
names=$(mcp_json '[.servers[].server.name] | join(",")')
if [ "$MCP_STATUS" = "200" ] && [ "$names" = "$KNOWN" ]; then
  pass
else
  fail "listing: HTTP ${MCP_STATUS}, names '${names}'"
fi

begin_test "Control: the known version itself is served (200) to both readers"
mcp_get "$KEY" "$(mcp_version_path "$KNOWN" 1.0.0)" anon
s_anon="$MCP_STATUS"
mcp_get "$KEY" "$(mcp_version_path "$KNOWN" 1.0.0)" "$TOK_NONE"
if [ "$s_anon" = "200" ] && [ "$MCP_STATUS" = "200" ]; then
  pass
else
  fail "known version: anonymous ${s_anon}, no-grant user ${MCP_STATUS}"
fi

# ---------------------------------------------------------------------------
# Discriminating control: the holder sees the reasons
# ---------------------------------------------------------------------------

# admin_reason NAME CODE
admin_reason() {
  mcp_get "$KEY" "$(mcp_version_path "$1" 1.0.0)"
  local why
  if ! why=$(mcp_check_problem 404 "$2"); then
    fail "admin read of ${1}: ${why}"
  elif [ "$(cat "$MCP_BODY")" = "$MCP_NOT_FOUND_BODY" ]; then
    fail "admin read of ${1} is the plain body"
  elif [ "$(mcp_json '.name')" != "$1" ] || [ "$(mcp_json '.version')" != "1.0.0" ]; then
    fail "admin hold body does not name the version: $(mcp_snip)"
  elif grep -qF "$MCP_NPM_KEY" "$MCP_BODY"; then
    fail "admin hold body names the backing repository: $(mcp_snip)"
  else
    pass
  fi
}

begin_test "Control (admin): pinned package quarantined -> mcp_backing_artifact_blocked"
admin_reason "$BACKING" mcp_backing_artifact_blocked

begin_test "Control (admin): server.json quarantined -> mcp_pending_review"
admin_reason "$SELF" mcp_pending_review

begin_test "Control (admin): pinned package deleted -> mcp_unresolvable"
admin_reason "$GONE" mcp_unresolvable

begin_test "Control (admin): a deleted status is the plain 404 for the holder too, 200 with include_deleted"
mcp_get "$KEY" "$(mcp_version_path "$DELETED" 1.0.0)"
if ! why=$(mcp_check_plain_404); then
  fail "admin read of a deleted version: ${why}"
else
  mcp_get "$KEY" "$(mcp_version_path "$DELETED" 1.0.0)?include_deleted=true"
  if [ "$MCP_STATUS" = "200" ]; then pass; else fail "include_deleted=true: HTTP ${MCP_STATUS}"; fi
fi

begin_test "include_deleted=true never reveals a hold to a reader"
mcp_req GET "$(mcp_base "$KEY")/$(mcp_version_path "$BACKING" 1.0.0)?include_deleted=true" anon -H "Origin: ${ORIGIN}"
if [ "$(cat "$MCP_BODY")" = "$REF_BODY" ] && [ "$MCP_STATUS" = "404" ]; then
  pass
else
  fail "held version with include_deleted=true: HTTP ${MCP_STATUS}: $(mcp_snip)"
fi

end_suite
