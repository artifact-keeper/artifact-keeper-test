#!/usr/bin/env bash
# test-mcp-bundle.sh - MCPB bundles hosted next to a server version
# (artifact-keeper#5253 Phase 3, issue 3.4 "MCPB bundles" and 4.3;
# docs/mcp-registry.md "MCPB bundles").
#
# Audit lane. An .mcpb (a zip with manifest.json at its root) is uploaded
# with PUT .../servers/{name}/versions/{v}/bundles/{file}.mcpb BEFORE the
# version is published: 201 {file, fileSha256, size, signature, manifest,
# artifactId, downloadUrl, packageEntry} (200 for identical bytes again, 409
# mcp_bundle_exists for other bytes under the same file name). Publishing the
# version then adds one packages[] entry per uploaded bundle (registryType
# mcpb, the bundle's fileSha256, its Artifact Keeper URL as identifier). On
# an exact read by an authenticated caller the identifier carries a
# single-use download ticket, so a client handed the document can download
# the bundle of a private registry without its own credential; GET of the
# bundle answers application/zip with X-Checksum-Sha256 and
# Cache-Control: private, no-store. Once the version is published a bundle
# upload is 409 mcp_version_exists. mcp_require_bundle_signature refuses an
# unsigned bundle (422 mcp_bundle_unsigned). Quarantining the bundle holds
# the version like any backing package (a no-grant user gets the plain 404,
# the admin 404 mcp_backing_artifact_blocked); releasing it restores it.
#
# The repository is private so the ticket is what authorises the anonymous
# download (on a public one any anonymous caller could read the bundle).
#
# Gate: mcp_require_registry mcp_bundles, then two probes that must BOTH say
# "absent" to stand down: (1) a publish whose packages[] names an mcpb entry
# answers 422 mcp_external_registry (the Phase 1 table: mcpb is unresolvable
# until Phase 3; the final backend answers 422 mcp_package_not_found for a
# fileSha256 that matches no bundle), and (2) the bundle upload route answers
# with the router fallback. Then mcp_skip_later_phase mcp_bundles.
#
# Not covered: an EXPIRED ticket (five minutes, not configurable from the
# API); a bogus and a reused ticket are asserted instead. Signed bundles
# (PKCS#7, `mcpb sign`) are not built here.
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

# --- Contract (docs/mcp-registry.md "MCPB bundles") ------------------------
BUNDLE_TAIL="bundles"
# Query parameter of the single-use download ticket on an exact read.
TICKET_PARAM="ticket"

REPO="mcp-bundle-${RUN_ID}"
NAME="io.github.ak-bundle/echo-${RUN_ID}"
VER="1.0.0"
BUNDLE_FILE="echo-${RUN_ID}.mcpb"
BUNDLE="${WORK_DIR}/${BUNDLE_FILE}"
BUNDLE_OTHER="${WORK_DIR}/other-${BUNDLE_FILE}"
BUNDLE_V9="${WORK_DIR}/v9-${BUNDLE_FILE}"

# bundle_url [VERSION] [FILE] [NAME]
bundle_url() {
  printf '%s/%s/%s/%s' "$(mcp_base "$REPO")" "$(mcp_version_path "${3:-$NAME}" "${1:-$VER}")" "$BUNDLE_TAIL" "${2:-$BUNDLE_FILE}"
}

# upload FILE [VERSION] [NAME]: PUT a bundle; MCP_STATUS / MCP_BODY.
upload() {
  mcp_req PUT "$(bundle_url "${2:-$VER}" "$BUNDLE_FILE" "${3:-$NAME}")" admin \
    -H "Content-Type: application/octet-stream" --data-binary "@$1"
}

# build_bundle OUT VERSION TOOL_DESCRIPTION
build_bundle() {
  python3 -I - "$1" "$NAME" "$2" "$3" <<'PY'
import json, sys, zipfile
out, name, version, desc = sys.argv[1:5]
manifest = {
    "manifest_version": "0.2",
    "name": name.split("/")[-1],
    "display_name": "AK e2e echo",
    "version": version,
    "description": "Release-gate MCPB fixture",
    "author": {"name": "Artifact Keeper release gate"},
    "server": {"type": "node", "entry_point": "server/index.js",
               "mcp_config": {"command": "node", "args": ["${__dirname}/server/index.js"]}},
    "tools": [{"name": "echo", "description": desc}],
}
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("manifest.json", json.dumps(manifest, indent=2))
    z.writestr("server/index.js", "process.stdin.pipe(process.stdout);\n")
PY
}

# ---------------------------------------------------------------------------
# Setup and the probes
# ---------------------------------------------------------------------------

begin_test "Setup: build ${BUNDLE_FILE} and a private mcp repository"
build_bundle "$BUNDLE" "$VER" "Return the text argument unchanged."
build_bundle "$BUNDLE_OTHER" "$VER" "Return the text argument, other bytes."
build_bundle "$BUNDLE_V9" 9.0.0 "Return the text argument unchanged."
BUNDLE_SHA=$(sha256sum "$BUNDLE" | cut -d' ' -f1)
if ! mcp_create_repo "$REPO" "" false; then
  fail_fatal "create mcp repository" "$MCP_CREATE_ERROR"
fi
pass

# Probe 1: an mcpb entry naming an external URL, under own-repos, before any
# bundle is uploaded.
jq -cn --arg s "$MCP_SCHEMA_URL" --arg n "${NAME}-probe" --arg sha "$BUNDLE_SHA" \
  '{"$schema":$s,name:$n,description:"mcpb probe",version:"1.0.0",
    packages:[{registryType:"mcpb",identifier:"https://example.invalid/x.mcpb",fileSha256:$sha,transport:{type:"stdio"}}]}' \
  > "${WORK_DIR}/probe.json"
mcp_publish "$REPO" "${WORK_DIR}/probe.json"
MCPB_PROBE="${MCP_STATUS}:$(mcp_json '.error // empty')"
# Probe 2: the upload route, for a version that is not published yet.
upload "$BUNDLE"
UPLOAD_STATUS="$MCP_STATUS"
UPLOAD_BODY="${WORK_DIR}/upload.json"
cp "$MCP_BODY" "$UPLOAD_BODY"
UPLOAD_FALLBACK=0
case "$MCP_STATUS" in
  405) [ "$(mcp_json '.error // empty')" = "mcp_method_not_allowed" ] && UPLOAD_FALLBACK=1 ;;
  404) [ "$(cat "$MCP_BODY")" = "$MCP_NOT_FOUND_BODY" ] && UPLOAD_FALLBACK=1 ;;
esac
if [ "$MCPB_PROBE" = "422:mcp_external_registry" ] && [ "$UPLOAD_FALLBACK" = "1" ]; then
  mcp_skip_later_phase mcp_bundles "an mcpb packages[] entry answered 422 mcp_external_registry and PUT $(mcp_url_path "$(bundle_url)") answered ${UPLOAD_STATUS} with the router fallback"
fi

# ---------------------------------------------------------------------------
# Upload
# ---------------------------------------------------------------------------

begin_test "Upload before publishing: 201 with fileSha256, unsigned signature and the packageEntry"
up=$(jq -r '"\(.file)|\(.fileSha256)|\(.signature.state)|\(.packageEntry.registryType)|\(.packageEntry.fileSha256)|\(.manifest.version)"' "$UPLOAD_BODY" 2>/dev/null)
want="${BUNDLE_FILE}|${BUNDLE_SHA}|unsigned|mcpb|${BUNDLE_SHA}|${VER}"
BUNDLE_ID=$(jq -r '.artifactId // empty' "$UPLOAD_BODY" 2>/dev/null)
DOWNLOAD_URL=$(jq -r '.downloadUrl // empty' "$UPLOAD_BODY" 2>/dev/null)
if [ "$UPLOAD_STATUS" != "201" ]; then
  fail_fatal "bundle upload answered ${UPLOAD_STATUS}" "$(head -c 400 "$UPLOAD_BODY")"
elif [ "$up" != "$want" ]; then
  fail "upload answer file|fileSha256|signature.state|packageEntry.registryType|packageEntry.fileSha256|manifest.version is '${up}', expected '${want}'"
elif [ -z "$BUNDLE_ID" ] || [ "$(mcp_url_path "$DOWNLOAD_URL")" != "$(mcp_url_path "$(bundle_url)")" ]; then
  fail "upload answer artifactId '${BUNDLE_ID}' / downloadUrl '${DOWNLOAD_URL}' (want the bundle route)"
else
  pass
fi

begin_test "Re-upload: identical bytes 200, other bytes under the same file name 409 mcp_bundle_exists"
upload "$BUNDLE"
same="$MCP_STATUS"
upload "$BUNDLE_OTHER"
if [ "$same" != "200" ]; then
  fail "re-upload of identical bytes answered ${same}, want 200"
elif why=$(mcp_check_problem 409 mcp_bundle_exists); then
  pass
else
  fail "other bytes under the same file name: ${why}"
fi

begin_test "mcp_require_bundle_signature refuses an unsigned bundle (422 mcp_bundle_unsigned)"
if ! mcp_patch_repo "$REPO" '{"mcp_require_bundle_signature":true}'; then
  fail "PATCH mcp_require_bundle_signature=true answered ${MCP_STATUS}: $(mcp_snip)"
else
  upload "$BUNDLE_V9" 9.0.0
  why=$(mcp_check_problem 422 mcp_bundle_unsigned) || true
  mcp_patch_repo "$REPO" '{"mcp_require_bundle_signature":false}' || true
  if [ -z "$why" ]; then
    pass
  else
    fail "unsigned upload with the signature required: ${why}"
  fi
fi

# ---------------------------------------------------------------------------
# Publish and serve
# ---------------------------------------------------------------------------

begin_test "Publish ${NAME}@${VER}: the served version gains the bundle's mcpb packages[] entry"
mcp_server_json "$NAME" "$VER" "" "$(mcp_remote_json "https://bundle.example.invalid/mcp")" > "${WORK_DIR}/v1.json"
mcp_publish "$REPO" "${WORK_DIR}/v1.json"
pub_status="$MCP_STATUS"
mcp_get "$REPO" "$(mcp_version_path "$NAME" "$VER")" admin
entry=$(mcp_json '[.server.packages[]? | select(.registryType == "mcpb")][0] // empty')
IDENT=$(printf '%s' "$entry" | jq -r '.identifier // empty' 2>/dev/null)
got_sha=$(printf '%s' "$entry" | jq -r '.fileSha256 // empty' 2>/dev/null)
if [ "$pub_status" != "200" ]; then
  fail_fatal "publish ${NAME}@${VER} answered ${pub_status}"
elif [ "$MCP_STATUS" != "200" ] || [ -z "$entry" ]; then
  fail "no mcpb entry on the served version (HTTP ${MCP_STATUS}): $(mcp_snip)"
elif [ "$got_sha" != "$BUNDLE_SHA" ]; then
  fail "fileSha256 ${got_sha} != sha256 of the uploaded bytes ${BUNDLE_SHA}"
elif [ "$(mcp_url_path "${IDENT%%\?*}")" != "$(mcp_url_path "$(bundle_url)")" ]; then
  fail "mcpb identifier '${IDENT}' is not the bundle's Artifact Keeper URL"
else
  pass
fi

begin_test "An upload for the published version is 409 mcp_version_exists"
upload "$BUNDLE_OTHER"
if why=$(mcp_check_problem 409 mcp_version_exists); then
  pass
else
  fail "$why"
fi

begin_test "The ticketed URL downloads the bytes anonymously, once (application/zip, X-Checksum-Sha256, no-store)"
if ! printf '%s' "$IDENT" | grep -qE "[?&]${TICKET_PARAM}="; then
  fail "the admin's exact read serves no ${TICKET_PARAM} on the bundle URL: ${IDENT}"
else
  hdrs="${WORK_DIR}/dl.hdrs"
  code=$(curl -s -o "${WORK_DIR}/downloaded.mcpb" -D "$hdrs" -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" "${BASE_URL}$(mcp_url_path "$IDENT")" 2>/dev/null) || code="000"
  again=$(curl -s -o /dev/null -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" "${BASE_URL}$(mcp_url_path "$IDENT")" 2>/dev/null) || again="000"
  plain=$(curl -s -o /dev/null -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" "${BASE_URL}$(mcp_url_path "${IDENT%%\?*}")" 2>/dev/null) || plain="000"
  if [ "$code" != "200" ]; then
    fail "GET ${IDENT} answered ${code}"
  elif [ "$(sha256sum "${WORK_DIR}/downloaded.mcpb" | cut -d' ' -f1)" != "$BUNDLE_SHA" ]; then
    fail "downloaded bytes differ from the uploaded bundle"
  elif [ "$(mcp_header content-type "$hdrs")" != "application/zip" ] || [ "$(mcp_header x-checksum-sha256 "$hdrs")" != "$BUNDLE_SHA" ] \
    || [ "$(mcp_header cache-control "$hdrs")" != "private, no-store" ]; then
    fail "download headers content-type '$(mcp_header content-type "$hdrs")', x-checksum-sha256 '$(mcp_header x-checksum-sha256 "$hdrs")', cache-control '$(mcp_header cache-control "$hdrs")'"
  elif [ "${again:0:1}" = "2" ]; then
    fail "the single-use ticket downloaded a second time (HTTP ${again})"
  elif [ "${plain:0:1}" = "2" ]; then
    fail "the private bundle downloaded anonymously without a ticket (HTTP ${plain})"
  else
    pass
  fi
fi

begin_test "A bogus ticket does not download the bundle"
if [ -z "$IDENT" ]; then
  fail "no download URL"
else
  bogus="${IDENT%%\?*}?${TICKET_PARAM}=bogus-${RUN_ID}"
  code=$(curl -s -o "${WORK_DIR}/bogus.mcpb" -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" "${BASE_URL}$(mcp_url_path "$bogus")" 2>/dev/null) || code="000"
  if [ "${code:0:1}" = "2" ] || cmp -s "${WORK_DIR}/bogus.mcpb" "$BUNDLE"; then
    fail "a bogus ticket answered ${code} (want 401/403/404, never the bytes)"
  else
    pass
  fi
fi

# ---------------------------------------------------------------------------
# The bundle's gate holds the version
# ---------------------------------------------------------------------------

begin_test "Quarantining the bundle hides the version; releasing it restores it"
mcp_make_user "mcp-bundle-nogrant-${RUN_ID}" > "${WORK_DIR}/nogrant.tok" || true
NOGRANT_TOKEN=$(cat "${WORK_DIR}/nogrant.tok" 2>/dev/null)
if [ -z "$BUNDLE_ID" ]; then
  fail "no artifactId for the bundle from the upload"
elif [ -z "$NOGRANT_TOKEN" ]; then
  fail "could not create the no-grant user"
elif ! mcp_quarantine "$BUNDLE_ID" "release-gate MCPB hold"; then
  fail "quarantine of the bundle answered ${MCP_STATUS}: $(mcp_snip)"
else
  mcp_get "$REPO" "$(mcp_version_path "$NAME" "$VER")" "$NOGRANT_TOKEN"
  reader_why=$(mcp_check_plain_404) || true
  mcp_get "$REPO" "$(mcp_version_path "$NAME" "$VER")" admin
  admin_why=$(mcp_check_problem 404 mcp_backing_artifact_blocked) || true
  mcp_req GET "$(bundle_url)" admin
  dl_why=$(mcp_check_plain_404) || true
  mcp_release "$BUNDLE_ID" || true
  release_status="$MCP_STATUS"
  mcp_get "$REPO" "$(mcp_version_path "$NAME" "$VER")" admin
  restored="$MCP_STATUS"
  if [ -n "$reader_why" ]; then
    fail "no-grant read of a version whose bundle is quarantined: ${reader_why}"
  elif [ -n "$admin_why" ]; then
    fail "admin read of a version whose bundle is quarantined: ${admin_why}"
  elif [ -n "$dl_why" ]; then
    fail "download of a quarantined bundle: ${dl_why}"
  elif [ "${release_status:0:1}" != "2" ] || [ "$restored" != "200" ]; then
    fail "release answered ${release_status}, then the version answered ${restored} (want 200)"
  else
    pass
  fi
fi

end_suite
