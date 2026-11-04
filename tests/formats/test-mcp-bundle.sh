#!/usr/bin/env bash
# test-mcp-bundle.sh - MCPB bundles hosted next to a server version
# (artifact-keeper#5253 Phase 3, issue 3.4 "MCPB bundles" and 4.3).
#
# Audit lane. An .mcpb (a zip with manifest.json at its root) uploaded under
# a published version becomes a second artifact of that version; the served
# version gains an automatic packages[] entry with registryType mcpb, a
# computed fileSha256 that matches the uploaded bytes and a ticketed download
# URL. The ticketed URL downloads the bytes; a bogus ticket does not.
# Quarantining the bundle hides the version (plain 404 for readers).
#
# Gate: mcp_require_registry mcp_bundles, then two probes that must BOTH say
# "absent" to stand down: (1) a publish whose packages[] names an mcpb entry
# answers 422 mcp_external_registry (the Phase 1 table: mcpb is unresolvable
# until Phase 3), and (2) the bundle upload route answers with the router
# fallback. Then mcp_skip_later_phase mcp_bundles.
#
# Not covered: an EXPIRED ticket (the ticket lifetime is not configurable
# from the API, and waiting it out would dominate the suite); a bogus ticket
# is asserted instead.
#
# Requires: curl, jq, python3, sha256sum.

# shellcheck source=../lib/common.sh disable=SC1091
source "$(dirname "$0")/../lib/common.sh"
# shellcheck source=../lib/mcp-helpers.sh disable=SC1091
source "$(dirname "$0")/../lib/mcp-helpers.sh"

begin_suite "mcp-bundle"
auth_admin
setup_workdir
require_cmd curl
require_cmd jq
require_cmd python3
require_cmd sha256sum
mcp_require_registry mcp_bundles

# --- Contract names not pinned by the docs yet (guesses) -------------------
# Upload route: phase23 streams B "e.g. PUT .../versions/{v}/bundles/{file}.mcpb".
BUNDLE_TAIL="bundles"
# Download URL query parameter carrying the ticket (existing download-ticket
# mechanism).
TICKET_PARAM="ticket"

REPO="mcp-bundle-${RUN_ID}"
NAME="io.github.ak-bundle/echo-${RUN_ID}"
VER="1.0.0"
BUNDLE_FILE="echo-${RUN_ID}.mcpb"
BUNDLE="${WORK_DIR}/${BUNDLE_FILE}"

bundle_url() {
  printf '%s/%s/%s/%s' "$(mcp_base "$REPO")" "$(mcp_version_path "$NAME" "$VER")" "$BUNDLE_TAIL" "$BUNDLE_FILE"
}

# ---------------------------------------------------------------------------
# Setup: a bundle and a published version
# ---------------------------------------------------------------------------

begin_test "Setup: build ${BUNDLE_FILE} and publish ${NAME}@${VER}"
python3 -I - "$BUNDLE" "$NAME" "$VER" <<'PY'
import json, sys, zipfile
out, name, version = sys.argv[1:4]
manifest = {
    "manifest_version": "0.2",
    "name": name.split("/")[-1],
    "display_name": "AK e2e echo",
    "version": version,
    "description": "Release-gate MCPB fixture",
    "author": {"name": "Artifact Keeper release gate"},
    "server": {"type": "node", "entry_point": "server/index.js",
               "mcp_config": {"command": "node", "args": ["${__dirname}/server/index.js"]}},
    "tools": [{"name": "echo", "description": "Return the text argument unchanged."}],
}
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("manifest.json", json.dumps(manifest, indent=2))
    z.writestr("server/index.js", "process.stdin.pipe(process.stdout);\n")
PY
BUNDLE_SHA=$(sha256sum "$BUNDLE" | cut -d' ' -f1)
if ! mcp_create_repo "$REPO"; then
  fail_fatal "create mcp repository" "$MCP_CREATE_ERROR"
fi
mcp_server_json "$NAME" "$VER" "" "$(mcp_remote_json "https://bundle.example.invalid/mcp")" > "${WORK_DIR}/v1.json"
mcp_publish "$REPO" "${WORK_DIR}/v1.json"
[ "$MCP_STATUS" = "200" ] || fail_fatal "publish ${NAME}@${VER} answered ${MCP_STATUS}" "$(mcp_snip)"
pass

# Probe 1: an mcpb entry naming an external URL, under own-repos.
jq -cn --arg s "$MCP_SCHEMA_URL" --arg n "${NAME}-probe" --arg sha "$BUNDLE_SHA" \
  '{"$schema":$s,name:$n,description:"mcpb probe",version:"1.0.0",
    packages:[{registryType:"mcpb",identifier:"https://example.invalid/x.mcpb",fileSha256:$sha,transport:{type:"stdio"}}]}' \
  > "${WORK_DIR}/probe.json"
mcp_publish "$REPO" "${WORK_DIR}/probe.json"
MCPB_PROBE="${MCP_STATUS}:$(mcp_json '.error // empty')"
# Probe 2: the upload route.
mcp_req PUT "$(bundle_url)" admin -H "Content-Type: application/octet-stream" --data-binary "@${BUNDLE}"
UPLOAD_STATUS="$MCP_STATUS"
UPLOAD_FALLBACK=0
case "$MCP_STATUS" in
  405) [ "$(mcp_json '.error // empty')" = "mcp_method_not_allowed" ] && UPLOAD_FALLBACK=1 ;;
  404) [ "$(cat "$MCP_BODY")" = "$MCP_NOT_FOUND_BODY" ] && UPLOAD_FALLBACK=1 ;;
esac
if [ "$MCPB_PROBE" = "422:mcp_external_registry" ] && [ "$UPLOAD_FALLBACK" = "1" ]; then
  mcp_skip_later_phase mcp_bundles "an mcpb packages[] entry answered 422 mcp_external_registry and PUT $(mcp_url_path "$(bundle_url)") answered ${UPLOAD_STATUS} with the router fallback"
fi

# ---------------------------------------------------------------------------
# Assertions
# ---------------------------------------------------------------------------

begin_test "Upload the bundle under the version"
if [ "${UPLOAD_STATUS:0:1}" = "2" ]; then
  pass
else
  fail_fatal "bundle upload answered ${UPLOAD_STATUS}" "$(mcp_snip)"
fi

begin_test "The served version gains an mcpb packages[] entry whose fileSha256 matches the bytes"
mcp_get "$REPO" "$(mcp_version_path "$NAME" "$VER")" anon
entry=$(mcp_json '[.server.packages[]? | select(.registryType == "mcpb")][0] // empty')
IDENT=$(printf '%s' "$entry" | jq -r '.identifier // empty' 2>/dev/null)
got_sha=$(printf '%s' "$entry" | jq -r '.fileSha256 // empty' 2>/dev/null)
if [ "$MCP_STATUS" != "200" ] || [ -z "$entry" ]; then
  fail "no mcpb entry on the served version (HTTP ${MCP_STATUS}): $(mcp_snip)"
elif [ "$got_sha" != "$BUNDLE_SHA" ]; then
  fail "fileSha256 ${got_sha} != sha256 of the uploaded bytes ${BUNDLE_SHA}"
elif [ -z "$IDENT" ]; then
  fail "mcpb entry has no identifier (download URL): ${entry}"
else
  pass
fi

begin_test "The ticketed download URL serves the uploaded bytes"
if [ -z "$IDENT" ]; then
  fail "no download URL from the previous test"
else
  code=$(curl -s -o "${WORK_DIR}/downloaded.mcpb" -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" "${BASE_URL}$(mcp_url_path "$IDENT")" 2>/dev/null) || code="000"
  if [ "$code" != "200" ]; then
    fail "GET ${IDENT} answered ${code}"
  elif [ "$(sha256sum "${WORK_DIR}/downloaded.mcpb" | cut -d' ' -f1)" != "$BUNDLE_SHA" ]; then
    fail "downloaded bytes differ from the uploaded bundle"
  elif ! printf '%s' "$IDENT" | grep -qE "[?&]${TICKET_PARAM}="; then
    fail "download URL carries no ${TICKET_PARAM} parameter: ${IDENT}"
  else
    pass
  fi
fi

begin_test "A bogus ticket does not download the bundle"
if [ -z "$IDENT" ]; then
  fail "no download URL"
else
  bogus=$(printf '%s' "$IDENT" | sed -E "s/([?&]${TICKET_PARAM}=)[^&]*/\\1bogus-${RUN_ID}/")
  code=$(curl -s -o "${WORK_DIR}/bogus.mcpb" -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" "${BASE_URL}$(mcp_url_path "$bogus")" 2>/dev/null) || code="000"
  if [ "${code:0:1}" = "2" ] || cmp -s "${WORK_DIR}/bogus.mcpb" "$BUNDLE"; then
    fail "a bogus ticket answered ${code} (want 401/403/404, never the bytes)"
  else
    pass
  fi
fi

begin_test "Quarantining the bundle hides the version"
BUNDLE_ID=$(mcp_artifact_id "$REPO" "\\.mcpb$")
if [ -z "$BUNDLE_ID" ]; then
  fail "no artifact row for the bundle in ${REPO}"
elif ! mcp_quarantine "$BUNDLE_ID" "release-gate MCPB hold"; then
  fail "quarantine of the bundle answered ${MCP_STATUS}: $(mcp_snip)"
else
  mcp_get "$REPO" "$(mcp_version_path "$NAME" "$VER")" anon
  if ! why=$(mcp_check_plain_404); then
    fail "anonymous read of a version whose bundle is quarantined: ${why}"
  else
    mcp_get "$REPO" "$(mcp_version_path "$NAME" "$VER")" admin
    err=$(mcp_json '.error // empty')
    if [ "$MCP_STATUS" = "404" ] && { [ "$err" = "mcp_backing_artifact_blocked" ] || [ "$err" = "mcp_pending_review" ]; }; then
      if mcp_release "$BUNDLE_ID"; then
        mcp_get "$REPO" "$(mcp_version_path "$NAME" "$VER")" anon
        if [ "$MCP_STATUS" = "200" ]; then
          pass
        else
          fail "release did not restore the version (HTTP ${MCP_STATUS})"
        fi
      else
        fail "release answered ${MCP_STATUS}"
      fi
    else
      fail "admin read answered ${MCP_STATUS} '${err}', want 404 mcp_backing_artifact_blocked or mcp_pending_review"
    fi
  fi
fi

end_suite
