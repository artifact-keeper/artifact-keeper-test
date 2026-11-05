#!/usr/bin/env bash
# test-mcp-quarantined-package-blocked.sh - a server version whose pinned npm
# package is held is hidden on the registry surface, and comes back when the
# hold is released (artifact-keeper#5253; docs/mcp-registry.md "What a
# client sees"; docs/security/download-holds.md).
#
# The upload-time hold path: the backing npm repository has
# quarantine_enabled, so the echo package is held the moment it is published.
#
# Contract under test:
#   - the server.json publish succeeds (the package exists in the backing
#     repository; the hold is a serve-time gate, not a publish refusal).
#   - while held the version is omitted from /servers, /versions and search,
#     skipped by latest, and an exact read is the plain unknown-name 404 for a
#     reader; the administrator gets 404 mcp_backing_artifact_blocked with
#     gate "quarantine" and the package as submitted, never the backing
#     repository key or an artifact id.
#   - the npm tarball on the npm route is refused too: 409 for an upload-time
#     hold (download-holds.md).
#   - POST /api/v1/quarantine/{id}/release restores both on the next read.
#   - a rejected package (POST /api/v1/quarantine/{id}/reject) hides its
#     server version with gate "scan_policy" (the docs group "refused by scan
#     policy or rejected"), the tarball answers 403, and latest falls back to
#     the newest servable version.

# shellcheck source=../lib/common.sh disable=SC1091
source "$(dirname "$0")/../lib/common.sh"
# shellcheck source=../lib/mcp-helpers.sh disable=SC1091
source "$(dirname "$0")/../lib/mcp-helpers.sh"

begin_suite "mcp-quarantined-package-blocked"
auth_admin
setup_workdir
require_cmd curl
require_cmd jq
require_cmd python3
require_cmd tar
mcp_require_registry

PREFIX="sec-mcpq-${RUN_ID}"
KEY="${PREFIX}-mcp"
PKG="@ak-e2e/q-${RUN_ID}"
NAME="io.github.ak-e2e/q-${RUN_ID}"
ENC=$(mcp_encode_name "$NAME")

expect_problem() {
  local why
  if why=$(mcp_check_problem "$1" "$2"); then
    pass
  else
    fail "$3: ${why}"
  fi
}

# tarball_status VERSION: HTTP status of the npm tarball download (admin).
tarball_status() {
  curl -s -o "${WORK_DIR}/tarball-$1.out" -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" \
    -H "$(format_auth_header)" "${BASE_URL}/npm/${MCP_NPM_KEY}/${PKG}/-/${PKG##*/}-$1.tgz" 2>/dev/null || echo 000
}

# listed VERSION: 0 when the anonymous listing carries NAME@VERSION.
listed() {
  mcp_get "$KEY" "servers?limit=100" anon
  jq -e --arg n "$NAME" --arg v "$1" '[.servers[]? | select(.server.name == $n and .server.version == $v)] | length == 1' "$MCP_BODY" >/dev/null 2>&1
}

# admin_body_clean: the holder's body names no backing repository or id.
admin_body_clean() {
  ! grep -qF "$MCP_NPM_KEY" "$MCP_BODY" && ! grep -qF "$1" "$MCP_BODY"
}

begin_test "Create the npm backing repository with upload-time quarantine and the MCP repository"
if mcp_create_backing_repos "$PREFIX"; then
  st=$(curl -s -o "${WORK_DIR}/qpatch.json" -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" -X PATCH \
    -H "$(auth_header)" -H "Content-Type: application/json" \
    -d '{"quarantine_enabled":true,"quarantine_duration_minutes":60}' \
    "${BASE_URL}/api/v1/repositories/${MCP_NPM_KEY}" 2>/dev/null) || st="000"
  if [ "${st:0:1}" = "2" ] && mcp_create_repo "$KEY" "{\"mcp_package_repos\":$(mcp_package_repos_json)}"; then
    pass
  else
    fail_fatal "quarantine PATCH HTTP ${st} or MCP create failed: ${MCP_CREATE_ERROR:-$(head -c 300 "${WORK_DIR}/qpatch.json")}"
  fi
else
  fail_fatal "npm backing repository creation failed"
fi

begin_test "Publish the echo package 1.0.0: it is held on upload"
if mcp_publish_echo_package "$MCP_NPM_KEY" "$PKG" 1.0.0 "$NAME"; then
  AID1=$(mcp_artifact_id "$MCP_NPM_KEY" '1\.0\.0\.tgz$')
  qs=$(curl -s "${CURL_TIMEOUT_ARGS[@]}" -H "$(auth_header)" "${BASE_URL}/api/v1/quarantine/${AID1}" | jq -r '.quarantine_status // empty')
  if [ -n "$AID1" ] && [ "$qs" = "quarantined" ]; then
    pass
  else
    fail_fatal "the echo tarball is not held on upload (artifact '${AID1}', quarantine_status '${qs}')"
  fi
else
  fail_fatal "npm publish failed: HTTP ${MCP_STATUS}: $(mcp_snip)"
fi

begin_test "Publish the server.json pinning the held package: 200 (package exists)"
mcp_server_json "$NAME" 1.0.0 "$(mcp_npm_package_json "$PKG" 1.0.0)" > "${WORK_DIR}/s1.json"
mcp_publish "$KEY" "${WORK_DIR}/s1.json"
if [ "$MCP_STATUS" = "200" ]; then
  pass
else
  fail_fatal "server.json publish over a held package: HTTP ${MCP_STATUS}: $(mcp_snip)"
fi

begin_test "Held: the anonymous listing omits the version"
if listed 1.0.0; then
  fail "the held version is listed: $(mcp_snip)"
elif [ "$MCP_STATUS" != "200" ]; then
  fail "listing: HTTP ${MCP_STATUS}"
else
  pass
fi

begin_test "Held: search omits the version"
mcp_get "$KEY" "servers?search=q-${RUN_ID}" anon
if [ "$MCP_STATUS" = "200" ] && [ "$(mcp_json '.servers | length')" = "0" ]; then
  pass
else
  fail "search while held: HTTP ${MCP_STATUS}: $(mcp_snip)"
fi

for tail in "servers/${ENC}/versions/1.0.0" "servers/${ENC}/versions/latest" "servers/${ENC}/versions"; do
  begin_test "Held: anonymous GET ${tail} is the plain 404"
  mcp_get "$KEY" "$tail" anon
  if why=$(mcp_check_plain_404); then pass; else fail "${tail} while held: ${why}"; fi
done

begin_test "Held: the administrator gets 404 mcp_backing_artifact_blocked, gate quarantine"
mcp_get "$KEY" "servers/${ENC}/versions/1.0.0"
if ! why=$(mcp_check_problem 404 mcp_backing_artifact_blocked); then
  fail "admin read while held: ${why}"
elif [ "$(mcp_json '.gate')" != "quarantine" ] || [ "$(mcp_json '.package')" != "npm:${PKG}@1.0.0" ] \
  || [ "$(mcp_json '.name')" != "$NAME" ] || [ "$(mcp_json '.version')" != "1.0.0" ]; then
  fail "admin hold body fields: $(mcp_snip)"
elif ! admin_body_clean "$AID1"; then
  fail "the holder's body names the backing repository or the artifact id: $(mcp_snip)"
else
  pass
fi

begin_test "Held: the npm tarball download is refused with 409 (upload-time hold)"
st=$(tarball_status 1.0.0)
if [ "$st" = "409" ]; then
  pass
else
  fail "npm tarball of a held package: HTTP ${st} (expected 409): $(head -c 200 "${WORK_DIR}/tarball-1.0.0.out")"
fi

begin_test "Release the hold (POST /api/v1/quarantine/{id}/release)"
if mcp_release "$AID1"; then pass; else fail "release: HTTP ${MCP_STATUS}: $(mcp_snip)"; fi

begin_test "Released: the anonymous exact read is 200 with the AK coordinates"
mcp_get "$KEY" "servers/${ENC}/versions/1.0.0" anon
base=$(mcp_json '.server.packages[0].registryBaseUrl')
if [ "$MCP_STATUS" = "200" ] && [ "$(mcp_url_path "$base")" = "/npm/${MCP_NPM_KEY}" ]; then
  pass
else
  fail "after release: HTTP ${MCP_STATUS}, registryBaseUrl '${base}': $(mcp_snip)"
fi

begin_test "Released: listed and latest again"
if listed 1.0.0; then
  mcp_get "$KEY" "servers/${ENC}/versions/latest" anon
  if [ "$MCP_STATUS" = "200" ] && [ "$(mcp_json '.server.version')" = "1.0.0" ]; then
    pass
  else
    fail "latest after release: HTTP ${MCP_STATUS}: $(mcp_snip)"
  fi
else
  fail "the released version is not listed: $(mcp_snip)"
fi

begin_test "Released: the npm tarball downloads (200)"
st=$(tarball_status 1.0.0)
if [ "$st" = "200" ]; then pass; else fail "npm tarball after release: HTTP ${st}"; fi

# ---------------------------------------------------------------------------
# Rejected package version
# ---------------------------------------------------------------------------

begin_test "Publish the echo package 1.1.0 and a server version pinning it"
if mcp_publish_echo_package "$MCP_NPM_KEY" "$PKG" 1.1.0 "$NAME"; then
  AID2=$(mcp_artifact_id "$MCP_NPM_KEY" '1\.1\.0\.tgz$')
  mcp_server_json "$NAME" 1.1.0 "$(mcp_npm_package_json "$PKG" 1.1.0)" > "${WORK_DIR}/s2.json"
  mcp_publish "$KEY" "${WORK_DIR}/s2.json"
  if [ -n "$AID2" ] && [ "$MCP_STATUS" = "200" ]; then
    pass
  else
    fail_fatal "1.1.0 setup: artifact '${AID2}', server publish HTTP ${MCP_STATUS}: $(mcp_snip)"
  fi
else
  fail_fatal "npm publish of 1.1.0 failed: HTTP ${MCP_STATUS}"
fi

begin_test "Reject the 1.1.0 package (POST /api/v1/quarantine/{id}/reject)"
mcp_req POST "${BASE_URL}/api/v1/quarantine/${AID2}/reject" admin \
  -H "Content-Type: application/json" -d '{"reason":"release-gate MCP reject"}'
if [ "${MCP_STATUS:0:1}" = "2" ]; then pass; else fail "reject: HTTP ${MCP_STATUS}: $(mcp_snip)"; fi

begin_test "Rejected: the anonymous exact read of 1.1.0 is the plain 404"
mcp_get "$KEY" "servers/${ENC}/versions/1.1.0" anon
if why=$(mcp_check_plain_404); then pass; else fail "rejected version, reader: ${why}"; fi

begin_test "Rejected: the administrator gets mcp_backing_artifact_blocked, gate scan_policy"
mcp_get "$KEY" "servers/${ENC}/versions/1.1.0"
if ! why=$(mcp_check_problem 404 mcp_backing_artifact_blocked); then
  fail "admin read of the rejected version: ${why}"
elif [ "$(mcp_json '.gate')" != "scan_policy" ] || [ "$(mcp_json '.package')" != "npm:${PKG}@1.1.0" ]; then
  fail "rejected hold body: gate '$(mcp_json '.gate')' package '$(mcp_json '.package')': $(mcp_snip)"
elif ! admin_body_clean "$AID2"; then
  fail "the holder's body names the backing repository or the artifact id: $(mcp_snip)"
else
  pass
fi

begin_test "Rejected: latest falls back to 1.0.0, which is marked isLatest"
mcp_get "$KEY" "servers/${ENC}/versions/latest" anon
if [ "$MCP_STATUS" = "200" ] && [ "$(mcp_json '.server.version')" = "1.0.0" ] \
  && [ "$(mcp_json '._meta["io.modelcontextprotocol.registry/official"].isLatest')" = "true" ]; then
  pass
else
  fail "latest with 1.1.0 rejected: HTTP ${MCP_STATUS}: $(mcp_snip)"
fi

begin_test "Rejected: /versions lists only 1.0.0"
mcp_get "$KEY" "servers/${ENC}/versions" anon
if [ "$MCP_STATUS" = "200" ] && [ "$(mcp_json '[.servers[].server.version] | join(",")')" = "1.0.0" ]; then
  pass
else
  fail "versions with 1.1.0 rejected: HTTP ${MCP_STATUS}: $(mcp_snip)"
fi

begin_test "Rejected: the npm tarball answers 403"
st=$(tarball_status 1.1.0)
if [ "$st" = "403" ]; then
  pass
else
  fail "npm tarball of a rejected package: HTTP ${st} (expected 403): $(head -c 200 "${WORK_DIR}/tarball-1.1.0.out")"
fi

end_suite
