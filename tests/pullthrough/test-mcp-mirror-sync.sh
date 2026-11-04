#!/usr/bin/env bash
# test-mcp-mirror-sync.sh - MCP Remote in mirror mode (artifact-keeper#5253
# Phase 3, issue 3.4 "Mirror mode" and 8 Phase 3).
#
# mcp_remote_mode=mirror ingests EVERY upstream name (not just approved ones)
# into the Remote's own artifacts with an updated_since sync, mirrors the
# upstream status, and keeps serving curated: an unapproved name stays off
# /v0.1. Ingested documents are write-once: when the upstream changes the
# content of an already ingested, approved name@version (same version,
# different description) the approval of that version is revoked (hold
# content_drift, a name@version catalog row in `review` with contentDrift)
# and audited MCP_SERVER_CONTENT_DRIFT; the stored document is kept.
#
# Sync, catalog and decisions go through the Remote management API
# (/api/v1/repositories/{key}/mcp/{sync,catalog}, docs/mcp-registry.md
# "Management API"). The first pass has no watermark and lists the upstream
# without include_deleted, so a version already deleted upstream before the
# first sync is never seen; deleted-status mirroring is proven on a version
# deleted after it was ingested.
#
# Gates: mcp_require_registry mcp_mirror; mcp_create_proxy_repo (older
# backends refuse Remote mcp repos -> mcp_registry_proxy exemption); the
# management sync route (router 404/405 -> mcp_skip_later_phase mcp_mirror);
# then a BEHAVIOUR probe. Settings are echoed with defaults by the Phase 2/3
# scaffold before the behaviour ships, so the probe is not the echo: with
# mcp_remote_mode=mirror and a sync, a backend that ships mirror mode stores
# the unapproved upstream versions as artifacts of the Remote (or records an
# MCP_MIRROR_SYNCED audit event for it). Neither within the probe window ->
# mcp_skip_later_phase mcp_mirror.
#
# Requires: curl, jq, python3, MOCK_UPSTREAM_HOSTNAME.

# shellcheck source=../lib/common.sh disable=SC1091
source "$(dirname "$0")/../lib/common.sh"
# shellcheck source=../lib/mcp-helpers.sh disable=SC1091
source "$(dirname "$0")/../lib/mcp-helpers.sh"

begin_suite "mcp-mirror-sync"
auth_admin
setup_workdir
require_cmd curl
require_cmd jq
require_cmd python3
mcp_require_registry mcp_mirror
mcp_require_dialback

# --- Contract (docs/mcp-registry.md "Repository settings", "Sync") ---------
MIRROR_KEY="mcp_remote_mode"          # allowlist | mirror
MIRROR_VALUE="mirror"
DRIFT_AUDIT_ACTION="MCP_SERVER_CONTENT_DRIFT"           # docs/audit-events.md
MIRROR_AUDIT_ACTION="MCP_MIRROR_SYNCED"                 # docs/audit-events.md
DRIFT_HOLD="content_drift"                              # formats/mcp.rs HoldKind
PROBE_WINDOW_SECS="${MCP_MIRROR_PROBE_SECS:-60}"
SYNC_WAIT_SECS="${MCP_REMOTE_SYNC_SECS:-90}"

NS="io.github.ak-fixture"
REMOTE="mcp-mirror-${RUN_ID}"
CUR_ROWS="${WORK_DIR}/curation.json"
SUITE_START_ISO=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# ---------------------------------------------------------------------------
# Local helpers
# ---------------------------------------------------------------------------

served_pairs() {
  local repo="$1" auth="${2:-admin}" cursor="" url pages=0
  while :; do
    url="$(mcp_base "$repo")/servers?limit=100"
    [ -n "$cursor" ] && url="${url}&cursor=$(jq -rn --arg c "$cursor" '$c|@uri')"
    mcp_req GET "$url" "$auth"
    [ "$MCP_STATUS" = "200" ] || return 1
    mcp_json '.servers[]? | "\(.server.name)@\(.server.version)"'
    cursor=$(mcp_json '.metadata.nextCursor // empty')
    pages=$(( pages + 1 ))
    if [ -z "$cursor" ] || [ "$pages" -ge 200 ]; then
      break
    fi
  done
}

served_has() {
  served_pairs "$1" "${3:-admin}" | grep -qxF "$2"
}

# cur_load: the Remote's catalog (a CatalogItem array) into CUR_ROWS.
cur_load() {
  mcp_catalog_load "$REMOTE" "$CUR_ROWS"
}

# cur_statuses NAME: "*=<name status>" then "<version>=<status>[+drift]"
# for each name@version row (pins and drift re-queues) of NAME.
cur_statuses() {
  jq -r --arg n "$1" 'map(select(.name == $n))[0] // {}
    | (["*=\(.status)"] + [(.pins // [])[] | "\(.version)=\(.status)\(if .contentDrift then "+drift" else "" end)"]) | join(" ")' \
    "$CUR_ROWS" 2>/dev/null || true
}

# cur_approve NAME: POST .../mcp/catalog/{id}/approve on NAME's row.
cur_approve() {
  cur_load
  local id
  id=$(jq -r --arg n "$1" 'map(select(.name == $n))[0].id // empty' "$CUR_ROWS")
  [ -n "$id" ] || return 1
  mcp_catalog_decide "$REMOTE" "$id" approve
}

# remote_sync: one synchronous pass (POST .../mcp/sync). SYNC_SUMMARY is
# the pass's SyncSummary.
remote_sync() {
  mcp_remote_sync "$REMOTE" admin || true
  SYNC_STATUS="$MCP_SYNC_STATUS"
  SYNC_SUMMARY=$(mcp_json '.summary // {}' | jq -c . 2>/dev/null || echo '{}')
  wait_for_counter_stable "${MCP_MOCK_STATE_DIR}/request-count" 60 3 >/dev/null || true
}

# artifact_paths: the Remote's artifact paths, sorted.
artifact_paths() {
  curl -s "${CURL_TIMEOUT_ARGS[@]}" -H "$(auth_header)" \
    "${BASE_URL}/api/v1/repositories/${REMOTE}/artifacts?per_page=500" 2>/dev/null \
    | jq -r '(.items // .artifacts // .data // .)[]? | .path // empty' 2>/dev/null | sort
}

# expected_paths: servers/{name}/{version}/server.json for every fixture
# entry that is not deleted upstream (the first pass has no updated_since
# watermark and does not ask for deleted entries).
expected_paths() {
  jq -r 'select((._meta["io.modelcontextprotocol.registry/official"].status // "active") != "deleted")
    | "servers/\(.server.name)/\(.server.version)/server.json"' "${MCP_MOCK_STATE_DIR}"/servers/*.json | sort
}

has_all_artifacts() {
  [ -z "$(comm -23 <(expected_paths) <(artifact_paths))" ]
}

audit_count() {
  curl -s "${CURL_TIMEOUT_ARGS[@]}" -H "$(auth_header)" \
    "${BASE_URL}/api/v1/admin/audit?action=${1}&from=${SUITE_START_ISO}&per_page=200" 2>/dev/null \
    | jq -r --arg id "${2:-}" '[.items[]? | select($id == "" or .resource_id == $id or ((.details // {}) | tostring | contains($id)))] | length' 2>/dev/null || echo 0
}

# stored_sha: checksum_sha256 of the stored alpha 1.1.0 document.
stored_sha() {
  curl -s "${CURL_TIMEOUT_ARGS[@]}" -H "$(auth_header)" \
    "${BASE_URL}/api/v1/repositories/${REMOTE}/artifacts/servers/${NS}/alpha/1.1.0/server.json" 2>/dev/null \
    | jq -r '.checksum_sha256 // empty' 2>/dev/null || true
}

mirror_probe() {
  [ -n "$(artifact_paths)" ] && return 0
  [ "$(audit_count "$MIRROR_AUDIT_ACTION" "$REMOTE_ID")" -gt 0 ]
}

# ---------------------------------------------------------------------------
# Setup and the behaviour probe
# ---------------------------------------------------------------------------

begin_test "Setup: mock upstream and a Remote in ${MIRROR_KEY}=${MIRROR_VALUE}"
if ! start_mock_mcp_upstream "${WORK_DIR}/mcp-upstream"; then
  infra_fail "mock-mcp-upstream did not start" "$(head -c 400 "${WORK_DIR}/mock-mcp-upstream.err" 2>/dev/null)"
  end_suite
fi
if ! mcp_create_proxy_repo "$REMOTE" remote "$MCP_MOCK_BASE_URL"; then
  fail_fatal "create Remote mcp repository" "$MCP_CREATE_ERROR"
fi
REMOTE_ID=$(mcp_repo_id "$REMOTE")
[ -n "$REMOTE_ID" ] || fail_fatal "Remote ${REMOTE} has no id"
mcp_patch_repo "$REMOTE" "$(jq -cn --arg k "$MIRROR_KEY" --arg v "$MIRROR_VALUE" '{($k):$v}')"
PATCH_STATUS="$MCP_STATUS"
echoed=$(curl -s "${CURL_TIMEOUT_ARGS[@]}" -H "$(auth_header)" "${BASE_URL}/api/v1/repositories/${REMOTE}" | jq -r --arg k "$MIRROR_KEY" '.[$k] // empty')
pass

remote_sync
if ! mcp_remote_mounted; then
  mcp_skip_later_phase mcp_mirror "POST /api/v1/repositories/${REMOTE}/mcp/sync on a Remote mcp repository answered ${SYNC_STATUS}: the Remote management API is not mounted"
fi
if ! wait_until "mirror sync stores upstream versions" "$PROBE_WINDOW_SECS" mirror_probe; then
  mcp_skip_later_phase mcp_mirror "Remote ${REMOTE} with ${MIRROR_KEY}=${MIRROR_VALUE} (PATCH ${PATCH_STATUS}, echoed '${echoed}'), sync answered ${SYNC_STATUS}: no artifact in /api/v1/repositories/${REMOTE}/artifacts and no ${MIRROR_AUDIT_ACTION} audit event within ${PROBE_WINDOW_SECS}s"
fi

# ---------------------------------------------------------------------------
# Assertions
# ---------------------------------------------------------------------------

begin_test "${MIRROR_KEY} is echoed as ${MIRROR_VALUE}"
if [ "$echoed" = "$MIRROR_VALUE" ]; then
  pass
else
  fail "GET /api/v1/repositories/${REMOTE} echoed ${MIRROR_KEY}='${echoed}' after PATCH ${PATCH_STATUS}"
fi

begin_test "Every upstream version becomes an artifact of the Remote"
if wait_until "all fixture versions stored" "$SYNC_WAIT_SECS" has_all_artifacts; then
  pass
else
  fail "versions missing from the Remote's artifacts" "$(comm -23 <(expected_paths) <(artifact_paths))"
fi

begin_test "Mirror mode still serves curated: nothing listed before an approval"
pairs=$(served_pairs "$REMOTE" anon) || pairs="HTTP-${MCP_STATUS}"
mcp_get "$REMOTE" "$(mcp_version_path "${NS}/alpha" 1.1.0)" admin
if [ -n "$pairs" ]; then
  fail "mirrored but unapproved entries are served" "$pairs"
elif ! why=$(mcp_check_problem 404 mcp_pending_review); then
  fail "admin read of a mirrored, unapproved version: ${why}"
else
  pass
fi

begin_test "Upstream status is mirrored (deprecated listed, a later upstream delete hidden) once approved"
cur_approve "${NS}/bravo" && cur_approve "${NS}/charlie"
if wait_until "bravo 1.0.0 and charlie 2.0.0 served" "$SYNC_WAIT_SECS" served_has "$REMOTE" "${NS}/bravo@1.0.0" anon \
  && served_has "$REMOTE" "${NS}/charlie@2.0.0" anon; then
  mcp_get "$REMOTE" "$(mcp_version_path "${NS}/bravo" 1.0.0)" anon
  b_status=$(mcp_json '._meta["io.modelcontextprotocol.registry/official"].status')
  cf="${MCP_MOCK_STATE_DIR}/servers/io.github.ak-fixture__charlie@2.0.0.json"
  jq --arg u "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '._meta["io.modelcontextprotocol.registry/official"].status = "deleted" | ._meta["io.modelcontextprotocol.registry/official"].updatedAt = $u' \
    "$cf" > "${cf}.tmp" && mv "${cf}.tmp" "$cf"
  remote_sync
  _charlie_hidden() {
    ! served_pairs "$REMOTE" anon | grep -qxF "${NS}/charlie@2.0.0"
  }
  wait_until "charlie 2.0.0 leaves the listing" "$SYNC_WAIT_SECS" _charlie_hidden || true
  c_listed=$(served_pairs "$REMOTE" anon | grep -cxF "${NS}/charlie@2.0.0" || true)
  mcp_get "$REMOTE" "$(mcp_version_path "${NS}/charlie" 2.0.0)?include_deleted=true" anon
  c_status="${MCP_STATUS}:$(mcp_json '._meta["io.modelcontextprotocol.registry/official"].status')"
  if [ "$b_status" = "deprecated" ] && [ "$c_status" = "200:deleted" ] && [ "$c_listed" = "0" ]; then
    pass
  else
    fail "bravo 1.0.0 status '${b_status}' (want deprecated), charlie 2.0.0 include_deleted '${c_status}' (want 200:deleted), listed ${c_listed} (sync ${SYNC_STATUS} ${SYNC_SUMMARY})"
  fi
else
  fail "approved bravo/charlie not served"
fi

begin_test "Approve alpha: 1.1.0 is served from the mirrored artifact"
if cur_approve "${NS}/alpha" && wait_until "alpha 1.1.0 served" "$SYNC_WAIT_SECS" served_has "$REMOTE" "${NS}/alpha@1.1.0" anon; then
  BEFORE_SHA=$(stored_sha)
  mcp_get "$REMOTE" "$(mcp_version_path "${NS}/alpha" 1.1.0)" anon
  src=$(mcp_json '._meta["com.artifactkeeper.registry/source"] | "\(.origin)|\(.kind)|\(.upstreamUrl)"')
  if [ -z "$BEFORE_SHA" ]; then
    fail_fatal "no stored artifact for alpha 1.1.0 (GET /api/v1/repositories/${REMOTE}/artifacts/servers/${NS}/alpha/1.1.0/server.json)"
  elif [ "$src" != "mirror|upstream|${MCP_MOCK_BASE_URL}" ]; then
    fail "mirrored alpha 1.1.0 source block origin|kind|upstreamUrl is '${src}', expected 'mirror|upstream|${MCP_MOCK_BASE_URL}'"
  else
    pass
  fi
else
  fail_fatal "approved alpha 1.1.0 never served (approve answered ${MCP_STATUS})"
fi

begin_test "Content drift on an approved version revokes its approval"
DRIFT_DESC="Alpha fixture server (changed upstream ${RUN_ID})"
f="${MCP_MOCK_STATE_DIR}/servers/io.github.ak-fixture__alpha@1.1.0.json"
jq --arg d "$DRIFT_DESC" --arg u "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  '.server.description = $d | ._meta["io.modelcontextprotocol.registry/official"].updatedAt = $u' "$f" > "${f}.tmp" && mv "${f}.tmp" "$f"
remote_sync
DRIFT_SUMMARY="$SYNC_SUMMARY"
_alpha_hidden() {
  mcp_get "$REMOTE" "$(mcp_version_path "${NS}/alpha" 1.1.0)" anon
  [ "$MCP_STATUS" = "404" ]
}
if wait_until "alpha 1.1.0 hidden after drift" "$SYNC_WAIT_SECS" _alpha_hidden; then
  mcp_get "$REMOTE" "$(mcp_version_path "${NS}/alpha" 1.1.0)" anon
  if ! why=$(mcp_check_plain_404); then
    fail "anonymous read of the drifted version: ${why}"
  else
    mcp_get "$REMOTE" "$(mcp_version_path "${NS}/alpha" 1.1.0)" admin
    hold=$(mcp_json '.hold // empty')
    if ! why=$(mcp_check_problem 404 mcp_pending_review); then
      fail "admin read of the drifted version: ${why}"
    elif [ "$hold" != "$DRIFT_HOLD" ]; then
      fail "drifted version hold is '${hold}', expected ${DRIFT_HOLD}: $(mcp_snip)"
    elif served_pairs "$REMOTE" anon | grep -qxF "${NS}/alpha@1.1.0"; then
      fail "drifted version still listed"
    else
      pass
    fi
  fi
else
  fail "alpha 1.1.0 still served after its upstream content changed (sync answered ${SYNC_STATUS} ${DRIFT_SUMMARY})"
fi

begin_test "The drifted version's stored document was not overwritten"
# Ingested documents are write-once (phase23 brief decision 1): the stored
# artifact keeps its checksum after the upstream bytes changed.
after_sha=$(stored_sha)
if [ -z "$after_sha" ]; then
  fail "alpha 1.1.0 artifact missing after drift"
elif [ "$after_sha" != "$BEFORE_SHA" ]; then
  fail "the drifted upstream bytes overwrote the ingested document (sha ${BEFORE_SHA} -> ${after_sha})"
else
  pass
fi

begin_test "The drifted version is re-queued (catalog pin 1.1.0 in review with contentDrift); other versions still served"
cur_load
statuses=$(cur_statuses "${NS}/alpha")
alpha_other=$(served_pairs "$REMOTE" anon | grep -c "^${NS}/alpha@1.0.0$" || true)
drifted=$(printf '%s' "$DRIFT_SUMMARY" | jq -r '.drifted // 0' 2>/dev/null || echo 0)
if ! printf '%s' "$statuses" | grep -qE '(^| )1\.1\.0=review\+drift( |$)'; then
  fail "no name@version row 1.1.0=review with contentDrift for alpha after drift: ${statuses}"
elif ! printf '%s' "$statuses" | grep -qE '^\*=approved( |$)'; then
  fail "the drift re-queue changed the name-level decision: ${statuses}"
elif [ "$alpha_other" != "1" ]; then
  fail "revoking 1.1.0 also hid alpha 1.0.0 (statuses: ${statuses})"
elif [ "$drifted" -lt 1 ] 2>/dev/null; then
  fail "the drift sync's summary reports drifted=${drifted}: ${DRIFT_SUMMARY}"
else
  pass
fi

begin_test "Content drift is audited ${DRIFT_AUDIT_ACTION}"
if [ "$(audit_count "$DRIFT_AUDIT_ACTION")" -gt 0 ]; then
  pass
else
  fail "no ${DRIFT_AUDIT_ACTION} audit event since ${SUITE_START_ISO}"
fi

end_suite
