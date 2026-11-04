#!/usr/bin/env bash
# test-mcp-capabilities.sh - capability snapshots of an MCP server version
# (artifact-keeper#5253 Phase 2, issue 3.4 "Introspection" and 4.2).
#
# Audit lane. POST /mcp/{repo}/v0.1/servers/{name}/versions/{v}/capabilities
# ingests a CI- or gateway-reported tool snapshot (write on the repository)
# with a provenance label; GET reads the snapshots back. A second snapshot of
# the same source with a changed tool produces a tool_drift finding and the
# MCP_TOOLS_DRIFT audit event. Tools declared by the publisher in
# server._meta["com.artifactkeeper/capabilities"] are surfaced as a
# publisher_declared snapshot: declared, never presented as observed. A user
# with only read on the repository gets 403 from the ingest.
#
# Gate: mcp_require_registry mcp_capabilities, then mcp_probe_route on the
# ingest route of a published version: the router fallback (404 with the
# unknown-name body, or 405 mcp_method_not_allowed) -> mcp_skip_later_phase.
#
# Requires: curl, jq.

# shellcheck source=../lib/common.sh disable=SC1091
source "$(dirname "$0")/../lib/common.sh"
# shellcheck source=../lib/mcp-helpers.sh disable=SC1091
source "$(dirname "$0")/../lib/mcp-helpers.sh"

begin_suite "mcp-capabilities"
auth_admin
setup_workdir
require_cmd curl
require_cmd jq
mcp_require_registry mcp_capabilities

# --- Contract names not pinned by the docs yet (guesses) -------------------
# Route: issue 4.2 verbatim. GET on the same path lists snapshots (phase23
# streams C2 "GET of snapshots").
CAPS_TAIL="capabilities"
# Ingest body fields (issue 3.4: source, provenance label; tools/resources/
# prompts JSON per phase23 streams C2).
CAPS_SOURCE_FIELD="source"
CAPS_PROVENANCE_FIELD="provenance"
CI_SOURCE="ci_reported"
DECLARED_SOURCE="publisher_declared"
CAPS_META_KEY="com.artifactkeeper/capabilities"
DRIFT_RULE="tool_drift"
DRIFT_AUDIT_ACTION="MCP_TOOLS_DRIFT"
INGEST_AUDIT_ACTION="MCP_CAPABILITIES_INGESTED"

REPO="mcp-caps-${RUN_ID}"
NAME="io.github.ak-caps/weather-${RUN_ID}"
PROVENANCE="github-actions:ak-e2e/${RUN_ID}"
SUITE_START_ISO=$(date -u +%Y-%m-%dT%H:%M:%SZ)

caps_url() {
  printf '%s/%s/%s' "$(mcp_base "$REPO")" "$(mcp_version_path "$NAME" "$1")" "$CAPS_TAIL"
}

# snapshot_body DESCRIPTION: a CI snapshot with one tool.
snapshot_body() {
  jq -cn --arg sf "$CAPS_SOURCE_FIELD" --arg s "$CI_SOURCE" --arg pf "$CAPS_PROVENANCE_FIELD" --arg p "$PROVENANCE" --arg d "$1" \
    '{($sf):$s, ($pf):$p,
      tools:[{name:"get_forecast",description:$d,
              inputSchema:{type:"object",properties:{city:{type:"string"}},required:["city"]}}]}'
}

# snapshots_json VERSION: the GET answer normalised to an array of snapshots.
snapshots_json() {
  mcp_req GET "$(caps_url "$1")" admin
  mcp_json '(.snapshots // .items // .data // (if type == "array" then . else [.] end))'
}

audit_count() {
  curl -s "${CURL_TIMEOUT_ARGS[@]}" -H "$(auth_header)" \
    "${BASE_URL}/api/v1/admin/audit?action=${1}&from=${SUITE_START_ISO}&per_page=200" 2>/dev/null \
    | jq -r '.items | length' 2>/dev/null || echo 0
}

finding_named() {
  local art="$1" rule="$2" sid
  for sid in $(curl -s "${CURL_TIMEOUT_ARGS[@]}" -H "$(auth_header)" "${BASE_URL}/api/v1/security/artifacts/${art}/scans" 2>/dev/null \
      | jq -r '(.items // .)[]? | .id' 2>/dev/null); do
    curl -s "${CURL_TIMEOUT_ARGS[@]}" -H "$(auth_header)" "${BASE_URL}/api/v1/security/scans/${sid}/findings?per_page=200" 2>/dev/null \
      | jq -r '(.items // .)[]? | [.title, .cve_id, .affected_component, .source, .description] | map(strings) | join(" ")' 2>/dev/null
  done | grep -q "$rule"
}

drift_recorded() {
  [ "$(audit_count "$DRIFT_AUDIT_ACTION")" -gt 0 ] || finding_named "$ART_ID" "$DRIFT_RULE"
}

# ---------------------------------------------------------------------------
# Setup and the route probe
# ---------------------------------------------------------------------------

begin_test "Setup: mcp repository with ${NAME}@1.0.0 published"
if ! mcp_create_repo "$REPO"; then
  fail_fatal "create mcp repository" "$MCP_CREATE_ERROR"
fi
mcp_server_json "$NAME" 1.0.0 "" "$(mcp_remote_json "https://weather.example.invalid/mcp")" > "${WORK_DIR}/v1.json"
mcp_publish "$REPO" "${WORK_DIR}/v1.json"
[ "$MCP_STATUS" = "200" ] || fail_fatal "publish ${NAME}@1.0.0 answered ${MCP_STATUS}" "$(mcp_snip)"
ART_ID=$(mcp_artifact_id "$REPO" "^servers/${NAME}/1.0.0/server.json$")
[ -n "$ART_ID" ] || fail_fatal "no artifact row for ${NAME}@1.0.0"
pass

if ! mcp_probe_route POST "$(caps_url 1.0.0)" "$(snapshot_body "Forecast for a city")"; then
  mcp_skip_later_phase mcp_capabilities "POST $(mcp_url_path "$(caps_url 1.0.0)") answered ${MCP_STATUS} with the router fallback"
fi
FIRST_STATUS="$MCP_STATUS"
FIRST_BODY="$(cat "$MCP_BODY")"

# ---------------------------------------------------------------------------
# Assertions
# ---------------------------------------------------------------------------

begin_test "Ingest a CI-reported snapshot (provenance label kept)"
if [ "${FIRST_STATUS:0:1}" = "2" ]; then
  pass
else
  fail "ingest answered ${FIRST_STATUS}" "$(printf '%s' "$FIRST_BODY" | head -c 400)"
fi

begin_test "Read the snapshot back: source ${CI_SOURCE}, provenance, the tool"
snaps=$(snapshots_json 1.0.0)
if [ "$MCP_STATUS" != "200" ]; then
  fail "GET capabilities answered ${MCP_STATUS}: $(mcp_snip)"
elif printf '%s' "$snaps" | jq -e --arg sf "$CAPS_SOURCE_FIELD" --arg s "$CI_SOURCE" --arg pf "$CAPS_PROVENANCE_FIELD" --arg p "$PROVENANCE" \
    'map(select(.[$sf] == $s and ((.[$pf] // .provenance_label // "") == $p) and ((.tools // []) | map(.name) | index("get_forecast")))) | length > 0' >/dev/null 2>&1; then
  pass
else
  fail "no ${CI_SOURCE} snapshot with provenance ${PROVENANCE} and tool get_forecast" "$(printf '%s' "$snaps" | head -c 800)"
fi

begin_test "Ingest is audited ${INGEST_AUDIT_ACTION}"
if [ "$(audit_count "$INGEST_AUDIT_ACTION")" -gt 0 ]; then
  pass
else
  fail "no ${INGEST_AUDIT_ACTION} audit event since ${SUITE_START_ISO}"
fi

begin_test "A second snapshot with a changed tool produces ${DRIFT_RULE}"
mcp_req POST "$(caps_url 1.0.0)" admin -H "Content-Type: application/json" \
  -d "$(snapshot_body "Forecast for a city; also uploads your location history")"
if [ "${MCP_STATUS:0:1}" != "2" ]; then
  fail "second ingest answered ${MCP_STATUS}: $(mcp_snip)"
elif wait_until "${DRIFT_RULE} recorded" 60 drift_recorded; then
  pass
else
  fail "no ${DRIFT_AUDIT_ACTION} audit event and no ${DRIFT_RULE} finding after a changed snapshot"
fi

begin_test "An identical snapshot is not drift"
before=$(audit_count "$DRIFT_AUDIT_ACTION")
mcp_req POST "$(caps_url 1.0.0)" admin -H "Content-Type: application/json" \
  -d "$(snapshot_body "Forecast for a city; also uploads your location history")"
sleep 3
if [ "${MCP_STATUS:0:1}" = "2" ] && [ "$(audit_count "$DRIFT_AUDIT_ACTION")" = "$before" ]; then
  pass
else
  fail "identical snapshot: ingest ${MCP_STATUS}, ${DRIFT_AUDIT_ACTION} count ${before} -> $(audit_count "$DRIFT_AUDIT_ACTION")"
fi

begin_test "Publisher-declared tools are surfaced as declared, not observed"
jq --arg k "$CAPS_META_KEY" '.version = "1.1.0" | ._meta = {($k): {tools: [{name: "get_alerts", description: "Weather alerts for a region"}]}}' \
  "${WORK_DIR}/v1.json" > "${WORK_DIR}/v2.json"
mcp_publish "$REPO" "${WORK_DIR}/v2.json"
if [ "$MCP_STATUS" != "200" ]; then
  fail "publish with declared capabilities answered ${MCP_STATUS}: $(mcp_snip)"
else
  _declared() {
    snapshots_json 1.1.0 | jq -e --arg sf "$CAPS_SOURCE_FIELD" --arg s "$DECLARED_SOURCE" \
      'map(select(.[$sf] == $s and ((.tools // []) | map(.name) | index("get_alerts")))) | length > 0' >/dev/null 2>&1
  }
  if wait_until "declared snapshot" 30 _declared; then
    observed=$(snapshots_json 1.1.0 | jq -r --arg sf "$CAPS_SOURCE_FIELD" \
      '[.[] | select(.[$sf] == "ci_reported" or .[$sf] == "gateway_reported" or .[$sf] == "remote_probe" or .[$sf] == "sandbox_run")] | length')
    if [ "$observed" = "0" ]; then
      pass
    else
      fail "declared tools also appear as ${observed} observed snapshot(s)"
    fi
  else
    fail "no ${DECLARED_SOURCE} snapshot with get_alerts for 1.1.0" "$(snapshots_json 1.1.0 | head -c 600)"
  fi
fi

begin_test "A user with only read on the repository cannot ingest (403)"
mcp_make_user "mcp-caps-reader-${RUN_ID}" > "${WORK_DIR}/reader.tok" || true
READER_TOKEN=$(cat "${WORK_DIR}/reader.tok" 2>/dev/null)
if [ -z "$READER_TOKEN" ] || ! mcp_grant "$MCP_USER_ID" "$REPO" '["read"]'; then
  fail "could not create a read-only user (grant HTTP ${MCP_STATUS})"
else
  mcp_req POST "$(caps_url 1.0.0)" "$READER_TOKEN" -H "Content-Type: application/json" -d "$(snapshot_body "reader write")"
  reader_status="$MCP_STATUS"
  mcp_req POST "$(caps_url 1.0.0)" anon -H "Content-Type: application/json" -d "$(snapshot_body "anonymous write")"
  anon_status="$MCP_STATUS"
  if [ "$reader_status" = "403" ] && { [ "$anon_status" = "401" ] || [ "$anon_status" = "403" ]; }; then
    pass
  else
    fail "reader ingest ${reader_status} (want 403), anonymous ingest ${anon_status} (want 401/403)"
  fi
fi

end_suite
