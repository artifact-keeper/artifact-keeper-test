#!/usr/bin/env bash
# test-mcp-capabilities.sh - capability snapshots of an MCP server version
# (artifact-keeper#5253 Phase 2, issue 3.4 "Introspection" and 4.2).
#
# Audit lane (docs/mcp-registry.md "Capabilities and introspection").
# POST /mcp/{repo}/v0.1/servers/{name}/versions/{v}/capabilities ingests a
# CI- or gateway-reported snapshot ({source, generatedBy, tools, ...}, write
# on the repository) and answers 201 {snapshot, previousSnapshotId, drift};
# the display label (`provenance`) is set by AK ("reported by CI (<user>,
# <generatedBy>)"), never by the caller. GET answers {current, snapshots,
# introspection, notice}; `current` carries the lists, `snapshots` are
# summaries. A second snapshot of the same source with a changed tool answers
# drift {scanId} (a tool_drift finding, audited MCP_TOOLS_DRIFT), and
# GET .../capabilities/diff shows the change. Tools declared by the publisher
# in _meta["com.artifactkeeper/capabilities"] are a publisher_declared
# snapshot with observed false. A user with only read on the repository gets
# 403 mcp_forbidden from the ingest, an anonymous caller 401.
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

# --- Contract (docs/mcp-registry.md "Capabilities and introspection") ------
CAPS_TAIL="capabilities"
CI_SOURCE="ci_reported"
DECLARED_SOURCE="publisher_declared"
CAPS_META_KEY="com.artifactkeeper/capabilities"
DRIFT_RULE="tool_drift"
DRIFT_AUDIT_ACTION="MCP_TOOLS_DRIFT"
INGEST_AUDIT_ACTION="MCP_CAPABILITIES_INGESTED"

REPO="mcp-caps-${RUN_ID}"
NAME="io.github.ak-caps/weather-${RUN_ID}"
GENERATED_BY="github-actions/ak-e2e/${RUN_ID}"
SUITE_START_ISO=$(date -u +%Y-%m-%dT%H:%M:%SZ)

caps_url() {
  printf '%s/%s/%s' "$(mcp_base "$REPO")" "$(mcp_version_path "$NAME" "$1")" "$CAPS_TAIL"
}

# snapshot_body DESCRIPTION: a CI snapshot with one tool.
snapshot_body() {
  jq -cn --arg s "$CI_SOURCE" --arg g "$GENERATED_BY" --arg d "$1" \
    '{source:$s, generatedBy:$g, authState:"none",
      tools:[{name:"get_forecast",description:$d,
              inputSchema:{type:"object",properties:{city:{type:"string"}},required:["city"]}}]}'
}

# caps_get VERSION: GET the version's capabilities as the admin.
caps_get() {
  mcp_req GET "$(caps_url "$1")" admin
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

begin_test "Ingest a CI-reported snapshot: 201 {snapshot, previousSnapshotId: null, drift: null}"
first=$(printf '%s' "$FIRST_BODY" | jq -r '"\(.snapshot.source)|\(.snapshot.id != null)|\(.previousSnapshotId)|\(.drift)"' 2>/dev/null)
if [ "$FIRST_STATUS" = "201" ] && [ "$first" = "${CI_SOURCE}|true|null|null" ]; then
  pass
else
  fail "ingest answered ${FIRST_STATUS} with snapshot.source|has-id|previousSnapshotId|drift '${first}', expected 201 '${CI_SOURCE}|true|null|null'" "$(printf '%s' "$FIRST_BODY" | head -c 400)"
fi

begin_test "Read the snapshot back: current is ${CI_SOURCE} with the AK-set label and the tool"
caps_get 1.0.0
cur=$(mcp_json '.current | "\(.source)|\(.observed)|\(.outcome)|\([.tools[]?.name] | join(","))"')
label=$(mcp_json '.current.provenance // empty')
if [ "$MCP_STATUS" != "200" ]; then
  fail "GET capabilities answered ${MCP_STATUS}: $(mcp_snip)"
elif [ "$cur" != "${CI_SOURCE}|false|ok|get_forecast" ]; then
  fail "current source|observed|outcome|tools is '${cur}', expected '${CI_SOURCE}|false|ok|get_forecast'" "$(mcp_snip)"
elif ! printf '%s' "$label" | grep -q '^reported by CI (' || ! printf '%s' "$label" | grep -qF "$GENERATED_BY"; then
  fail "current.provenance '${label}' is not the AK label 'reported by CI (<user>, ${GENERATED_BY})'"
elif [ -z "$(mcp_json '.notice // empty')" ]; then
  fail "the answer carries no notice (capability lists are untrusted)"
else
  pass
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
drift_scan=$(mcp_json '.drift.scanId // empty')
prev=$(mcp_json '.previousSnapshotId // empty')
if [ "$MCP_STATUS" != "201" ]; then
  fail "second ingest answered ${MCP_STATUS}: $(mcp_snip)"
elif [ -z "$drift_scan" ] || [ -z "$prev" ]; then
  fail "a changed snapshot answered drift '${drift_scan}' previousSnapshotId '${prev}' (want both set): $(mcp_snip)"
elif wait_until "${DRIFT_RULE} recorded" 60 drift_recorded; then
  pass
else
  fail "no ${DRIFT_AUDIT_ACTION} audit event and no ${DRIFT_RULE} finding after a changed snapshot"
fi

begin_test "capabilities/diff shows the changed tool"
mcp_req GET "$(caps_url 1.0.0)/diff?source=${CI_SOURCE}" admin
diffed=$(mcp_json '"\(.summary.tools.changed)|\(.summary.identical)|\([.tools.changed[]?.key] | join(","))|\([.tools.changed[]?.fields[]?] | index("description") != null)"')
if [ "$MCP_STATUS" = "200" ] && [ "$diffed" = "1|false|get_forecast|true" ]; then
  pass
else
  fail "diff answered ${MCP_STATUS} with changed|identical|keys|description-changed '${diffed}', expected '1|false|get_forecast|true'" "$(mcp_snip)"
fi

begin_test "An identical snapshot is not drift"
before=$(audit_count "$DRIFT_AUDIT_ACTION")
mcp_req POST "$(caps_url 1.0.0)" admin -H "Content-Type: application/json" \
  -d "$(snapshot_body "Forecast for a city; also uploads your location history")"
same_status="$MCP_STATUS"
same_drift=$(mcp_json '.drift')
sleep 3
if [ "$same_status" = "201" ] && [ "$same_drift" = "null" ] && [ "$(audit_count "$DRIFT_AUDIT_ACTION")" = "$before" ]; then
  pass
else
  fail "identical snapshot: ingest ${same_status} drift '${same_drift}', ${DRIFT_AUDIT_ACTION} count ${before} -> $(audit_count "$DRIFT_AUDIT_ACTION")"
fi

begin_test "Publisher-declared tools are surfaced as declared, not observed"
jq --arg k "$CAPS_META_KEY" '.version = "1.1.0" | ._meta = {($k): {tools: [{name: "get_alerts", description: "Weather alerts for a region"}]}}' \
  "${WORK_DIR}/v1.json" > "${WORK_DIR}/v2.json"
mcp_publish "$REPO" "${WORK_DIR}/v2.json"
if [ "$MCP_STATUS" != "200" ]; then
  fail "publish with declared capabilities answered ${MCP_STATUS}: $(mcp_snip)"
else
  _declared() {
    caps_get 1.1.0
    [ "$(mcp_json '.current | "\(.source)|\([.tools[]?.name] | join(","))"')" = "${DECLARED_SOURCE}|get_alerts" ]
  }
  if wait_until "declared snapshot" 30 _declared; then
    caps_get 1.1.0
    observed=$(mcp_json '[.current, .snapshots[]?] | map(select(.observed == true or .source != "publisher_declared")) | length')
    if [ "$observed" = "0" ]; then
      pass
    else
      fail "declared tools appear as ${observed} observed or non-declared snapshot(s)" "$(mcp_snip)"
    fi
  else
    fail "current is not a ${DECLARED_SOURCE} snapshot with get_alerts for 1.1.0" "$(mcp_snip)"
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
  mcp_req POST "$(caps_url 1.0.0)" "$READER_TOKEN" -H "Content-Type: application/json" -d "$(snapshot_body "reader write")"
  reader_why=$(mcp_check_problem 403 mcp_forbidden) || true
  if [ -z "$reader_why" ] && [ "$anon_status" = "401" ]; then
    pass
  else
    fail "reader ingest ${reader_status} (want 403 mcp_forbidden: ${reader_why:-ok}), anonymous ingest ${anon_status} (want 401)"
  fi
fi

end_suite
