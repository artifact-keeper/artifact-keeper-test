#!/usr/bin/env bash
# test-mcp-proxy-curation.sh - MCP Remote curation is a security control
# (artifact-keeper#5253 Phase 2, issue 3.3, 3.4, 4.4 and 8).
#
#   - a lookalike of an approved namespace (io.github.acrne-tools vs
#     io.github.acme-tools, "rn" for "m") is flagged for review at ingest and
#     never served
#   - approval needs an instance administrator: a user holding write on the
#     Remote gets 403 from approve and bulk-approve
#   - unapproved entries never appear on /v0.1 for any caller, admin
#     included (list, search, versions, exact, include_deleted): browsing them
#     is UI-only
#   - mcp_remote_posture_locked: a repository administrator cannot relax the
#     posture an instance administrator locked
#   - mcp_server_deny (case-insensitive glob, `*` crosses `/`) wins over an
#     approval
#
# Gates: mcp_require_registry mcp_registry_proxy; mcp_create_proxy_repo
# (older backends refuse Remote mcp repos -> mcp_registry_proxy exemption);
# then the behaviour probe (sync reaches the mock or records curation rows,
# else mcp_skip_later_phase mcp_registry_proxy).
#
# Requires: curl, jq, python3, MOCK_UPSTREAM_HOSTNAME.

# shellcheck source=../lib/common.sh disable=SC1091
source "$(dirname "$0")/../lib/common.sh"
# shellcheck source=../lib/mcp-helpers.sh disable=SC1091
source "$(dirname "$0")/../lib/mcp-helpers.sh"

begin_suite "mcp-proxy-curation"
auth_admin
setup_workdir
require_cmd curl
require_cmd jq
require_cmd python3
mcp_require_registry mcp_registry_proxy
mcp_require_dialback

# --- Contract names not pinned by the docs yet (guesses) -------------------
CURATION_SYNC_PATH="/api/v1/curation/repos/%s/sync"   # task brief / stream A
CURATION_LIST_PATH="/api/v1/curation/packages"
CURATION_NAME_LEVEL_VERSION="*"                         # phase23 brief
# Typosquat flag: the row goes to `review` (issue 3.4 "flags route to
# review"); a flag in the row metadata naming it is accepted too.
TYPOSQUAT_FLAG_RE='typosquat|lookalike|confusable|similar'
# Repository-administrator grant (permission actions on the repository).
REPO_ADMIN_ACTIONS='["read","write","delete","admin"]'
PROBE_WINDOW_SECS="${MCP_REMOTE_PROBE_SECS:-45}"
SYNC_WAIT_SECS="${MCP_REMOTE_SYNC_SECS:-90}"

GOOD="io.github.acme-tools/widget"
LOOKALIKE="io.github.acrne-tools/widget"
PENDING="io.github.acme-tools/unapproved"
REMOTE="mcp-curation-${RUN_ID}"
CUR_ROWS="${WORK_DIR}/curation.json"
SEED="${WORK_DIR}/seed"

# ---------------------------------------------------------------------------
# Local helpers
# ---------------------------------------------------------------------------

served_pairs() {
  local repo="$1" auth="${2:-admin}" extra="${3:-}" cursor="" url pages=0
  while :; do
    url="$(mcp_base "$repo")/servers?limit=100${extra}"
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

cur_load() {
  curl -s "${CURL_TIMEOUT_ARGS[@]}" -H "$(auth_header)" \
    "${BASE_URL}${CURATION_LIST_PATH}?staging_repo_id=${REMOTE_ID}&limit=500" -o "$CUR_ROWS" 2>/dev/null || echo '[]' > "$CUR_ROWS"
  jq -e 'type == "array"' "$CUR_ROWS" >/dev/null 2>&1 || echo '[]' > "$CUR_ROWS"
}

cur_row() {
  jq -c --arg n "$1" --arg v "$CURATION_NAME_LEVEL_VERSION" \
    '[.[] | select(.package_name == $n)] | ((map(select(.version == $v))[0]) // .[0]) // empty' "$CUR_ROWS" 2>/dev/null || true
}

cur_has() {
  cur_load
  [ -n "$(cur_row "$1")" ]
}

# cur_approve NAME [AUTH]
cur_approve() {
  cur_load
  local id
  id=$(cur_row "$1" | jq -r '.id // empty')
  if [ -z "$id" ]; then
    MCP_STATUS="no-row"
    return 1
  fi
  mcp_req POST "${BASE_URL}/api/v1/curation/packages/${id}/approve" "${2:-admin}" -H "Content-Type: application/json" -d '{}'
  [ "${MCP_STATUS:0:1}" = "2" ]
}

remote_sync() {
  # shellcheck disable=SC2059
  mcp_req POST "${BASE_URL}$(printf "$CURATION_SYNC_PATH" "$REMOTE")" admin -H "Content-Type: application/json" -d '{}'
  SYNC_STATUS="$MCP_STATUS"
  sleep 1
  wait_for_counter_stable "${MCP_MOCK_STATE_DIR}/request-count" 60 3 >/dev/null || true
}

seed_entry() {
  # seed_entry DIR NAME VERSION UPDATED_AT
  jq -n --arg s "$MCP_SCHEMA_URL" --arg n "$2" --arg v "$3" --arg u "$4" \
    '{"_meta":{"io.modelcontextprotocol.registry/official":{status:"active",publishedAt:$u,updatedAt:$u}},
      "server":{"$schema":$s,name:$n,description:"Widget MCP server",version:$v,
                remotes:[{type:"streamable-http",url:"https://widget.mcp.example.invalid/mcp"}]}}' \
    > "${1}/${2//\//__}@${3}.json"
}

repo_field() {
  curl -s "${CURL_TIMEOUT_ARGS[@]}" -H "$(auth_header)" "${BASE_URL}/api/v1/repositories/${REMOTE}" | jq -r --arg k "$1" '.[$k] // empty'
}

# patch_as TOKEN JSON: PATCH the Remote as another user.
patch_as() {
  mcp_req PATCH "${BASE_URL}/api/v1/repositories/${REMOTE}" "$1" -H "Content-Type: application/json" -d "$2"
}

# ---------------------------------------------------------------------------
# Setup and the behaviour probe
# ---------------------------------------------------------------------------

begin_test "Setup: mock upstream with an acme-tools catalog and the Remote over it"
mkdir -p "$SEED"
seed_entry "$SEED" "$GOOD" 1.0.0 "2026-10-01T00:00:00Z"
seed_entry "$SEED" "$PENDING" 1.0.0 "2026-10-01T00:00:00Z"
if ! start_mock_mcp_upstream "${WORK_DIR}/mcp-upstream" "$SEED"; then
  infra_fail "mock-mcp-upstream did not start" "$(head -c 400 "${WORK_DIR}/mock-mcp-upstream.err" 2>/dev/null)"
  end_suite
fi
if ! mcp_create_proxy_repo "$REMOTE" remote "$MCP_MOCK_BASE_URL"; then
  fail_fatal "create Remote mcp repository" "$MCP_CREATE_ERROR"
fi
REMOTE_ID=$(mcp_repo_id "$REMOTE")
[ -n "$REMOTE_ID" ] || fail_fatal "Remote ${REMOTE} has no id"
pass

_probe_contacted() {
  grep -qE ' GET /v0(\.1)?/servers(\?|$)' "${MCP_MOCK_STATE_DIR}/request-log.txt" 2>/dev/null && return 0
  cur_load
  [ "$(jq 'length' "$CUR_ROWS" 2>/dev/null || echo 0)" -gt 0 ]
}
# shellcheck disable=SC2059
mcp_req POST "${BASE_URL}$(printf "$CURATION_SYNC_PATH" "$REMOTE")" admin -H "Content-Type: application/json" -d '{}'
SYNC_STATUS="$MCP_STATUS"
if ! wait_until "the Remote syncs from the mock" "$PROBE_WINDOW_SECS" _probe_contacted; then
  mcp_skip_later_phase mcp_registry_proxy "Remote ${REMOTE} over the mock upstream: POST $(printf "$CURATION_SYNC_PATH" "$REMOTE") answered ${SYNC_STATUS}, the mock saw no /servers request and GET ${CURATION_LIST_PATH}?staging_repo_id=<remote> listed no rows within ${PROBE_WINDOW_SECS}s"
fi
wait_until "curation rows for the seed" "$SYNC_WAIT_SECS" cur_has "$PENDING" || true

begin_test "Setup: a write-grant user and a repository-admin user on the Remote"
mcp_make_user "mcp-cur-writer-${RUN_ID}" > "${WORK_DIR}/writer.tok" || true
WRITER_TOKEN=$(cat "${WORK_DIR}/writer.tok" 2>/dev/null)
WRITER_ID="${MCP_USER_ID:-}"
mcp_make_user "mcp-cur-repoadmin-${RUN_ID}" > "${WORK_DIR}/repoadmin.tok" || true
REPOADMIN_TOKEN=$(cat "${WORK_DIR}/repoadmin.tok" 2>/dev/null)
REPOADMIN_ID="${MCP_USER_ID:-}"
if [ -z "$WRITER_TOKEN" ] || [ -z "$REPOADMIN_TOKEN" ] || [ "$WRITER_ID" = "$REPOADMIN_ID" ]; then
  fail_fatal "could not create the test users"
fi
if ! mcp_grant "$WRITER_ID" "$REMOTE" '["read","write"]'; then
  fail_fatal "grant write on ${REMOTE}" "HTTP ${MCP_STATUS}: $(mcp_snip)"
fi
REPOADMIN_GRANTED=1
mcp_grant "$REPOADMIN_ID" "$REMOTE" "$REPO_ADMIN_ACTIONS" || REPOADMIN_GRANTED=0
pass

# ---------------------------------------------------------------------------
# Assertions
# ---------------------------------------------------------------------------

begin_test "Approve ${GOOD}: served"
if cur_approve "$GOOD" && wait_until "${GOOD} served" "$SYNC_WAIT_SECS" served_has "$REMOTE" "${GOOD}@1.0.0" anon; then
  pass
else
  fail "approved ${GOOD} not served (approve answered ${MCP_STATUS})"
fi

begin_test "A lookalike namespace (${LOOKALIKE}) is flagged for review at ingest"
seed_entry "${MCP_MOCK_STATE_DIR}/servers" "$LOOKALIKE" 1.0.0 "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
remote_sync "$REMOTE"
if wait_until "a curation row for ${LOOKALIKE}" "$SYNC_WAIT_SECS" cur_has "$LOOKALIKE"; then
  row=$(cur_row "$LOOKALIKE")
  status=$(printf '%s' "$row" | jq -r '.status')
  if [ "$status" = "review" ] || printf '%s' "$row" | jq -r '.metadata // {} | tostring' | grep -qiE "$TYPOSQUAT_FLAG_RE"; then
    if [ "$status" = "approved" ]; then
      fail "the lookalike was approved: ${row}"
    else
      pass
    fi
  else
    fail "lookalike not flagged (status '${status}')" "$row"
  fi
else
  fail "no curation row for ${LOOKALIKE} after sync (sync answered ${SYNC_STATUS})"
fi

begin_test "Approval needs an instance administrator: a write-grant user gets 403"
cur_approve "$LOOKALIKE" "$WRITER_TOKEN"
approve_status="$MCP_STATUS"
lookalike_id=$(cur_row "$LOOKALIKE" | jq -r '.id // empty')
mcp_req POST "${BASE_URL}/api/v1/curation/packages/bulk-approve" "$WRITER_TOKEN" -H "Content-Type: application/json" \
  -d "$(jq -cn --arg id "$lookalike_id" '{ids:[$id],reason:"release-gate non-admin bulk approve"}')"
bulk_status="$MCP_STATUS"
cur_load
after=$(cur_row "$LOOKALIKE" | jq -r '.status')
if [ "$approve_status" = "403" ] && [ "$bulk_status" = "403" ] && [ "$after" != "approved" ]; then
  pass
else
  fail "non-admin approve ${approve_status}, bulk-approve ${bulk_status} (both want 403); row status now '${after}'"
fi

begin_test "Unapproved entries never appear on /v0.1, for anonymous, a reader or the admin"
leaks=""
for who in anon "$WRITER_TOKEN" admin; do
  label="$who"
  [ "$who" = "$WRITER_TOKEN" ] && label="writer"
  pairs=$(served_pairs "$REMOTE" "$who") || pairs="HTTP-${MCP_STATUS}"
  searched=$(served_pairs "$REMOTE" "$who" "&search=widget") || searched="HTTP-${MCP_STATUS}"
  deleted=$(served_pairs "$REMOTE" "$who" "&include_deleted=true") || deleted="HTTP-${MCP_STATUS}"
  for n in "$LOOKALIKE" "$PENDING"; do
    if printf '%s\n%s\n%s\n' "$pairs" "$searched" "$deleted" | grep -q "^${n}@"; then
      leaks="${leaks} ${label}:list:${n}"
    fi
    mcp_get "$REMOTE" "servers/$(mcp_encode_name "$n")/versions" "$who"
    [ "$MCP_STATUS" = "404" ] || leaks="${leaks} ${label}:versions:${n}=${MCP_STATUS}"
    mcp_get "$REMOTE" "$(mcp_version_path "$n" 1.0.0)?include_deleted=true" "$who"
    [ "$MCP_STATUS" = "404" ] || leaks="${leaks} ${label}:exact:${n}=${MCP_STATUS}"
  done
done
mcp_get "$REMOTE" "$(mcp_version_path "$PENDING" 1.0.0)" admin
admin_why=$(mcp_check_problem 404 mcp_pending_review) || leaks="${leaks} admin-reason:${admin_why}"
mcp_get "$REMOTE" "$(mcp_version_path "$PENDING" 1.0.0)" anon
anon_why=$(mcp_check_plain_404) || leaks="${leaks} anon-plain:${anon_why}"
if [ -z "$leaks" ]; then
  pass
else
  fail "unapproved entries reachable on /v0.1:${leaks}"
fi

begin_test "An instance-locked posture cannot be relaxed by a repository administrator"
if [ "$REPOADMIN_GRANTED" != "1" ]; then
  skip "the backend refused the repository-admin grant ${REPO_ADMIN_ACTIONS} (HTTP ${MCP_STATUS}); no repository administrator to test the lock with"
elif ! mcp_patch_repo "$REMOTE" '{"mcp_remote_posture_locked":true}'; then
  fail "instance admin could not set mcp_remote_posture_locked (HTTP ${MCP_STATUS}): $(mcp_snip)"
else
  # Discriminator: the repository admin can change an unlocked setting.
  patch_as "$REPOADMIN_TOKEN" '{"mcp_oci_floating_tag_policy":"pin"}'
  unlocked_status="$MCP_STATUS"
  if [ "${unlocked_status:0:1}" != "2" ]; then
    skip "a repository-admin grant cannot PATCH this repository at all (HTTP ${unlocked_status}), so a 403 on the posture would not prove the lock"
  else
    patch_as "$REPOADMIN_TOKEN" '{"mcp_remote_posture":"allow_with_gates"}'
    relax_status="$MCP_STATUS"
    patch_as "$REPOADMIN_TOKEN" '{"mcp_remote_posture_locked":false}'
    unlock_status="$MCP_STATUS"
    posture=$(repo_field mcp_remote_posture)
    locked=$(repo_field mcp_remote_posture_locked)
    if [ "$relax_status" = "403" ] && [ "$unlock_status" = "403" ] && [ "$posture" = "approval_required" ] && [ "$locked" = "true" ]; then
      pass
    else
      fail "repo admin: relax ${relax_status}, unlock ${unlock_status} (want 403/403); posture '${posture}', locked '${locked}'"
    fi
  fi
fi

begin_test "mcp_server_deny (case-insensitive, * crosses /) wins over an approval"
if mcp_patch_repo "$REMOTE" '{"mcp_server_deny":["IO.GITHUB.ACME-*"]}'; then
  _good_hidden() {
    local p
    p=$(served_pairs "$REMOTE" anon) || return 1
    ! printf '%s\n' "$p" | grep -q "^${GOOD}@"
  }
  if wait_until "${GOOD} hidden" 30 _good_hidden; then
    mcp_get "$REMOTE" "$(mcp_version_path "$GOOD" 1.0.0)" admin
    if why=$(mcp_check_problem 404 mcp_rejected); then
      mcp_get "$REMOTE" "$(mcp_version_path "$GOOD" 1.0.0)" anon
      if why=$(mcp_check_plain_404); then
        pass
      else
        fail "anonymous read of a denied name: ${why}"
      fi
    else
      fail "admin read of a denied, approved name: ${why}"
    fi
  else
    fail "deny glob did not hide approved ${GOOD}"
  fi
else
  fail "PATCH mcp_server_deny answered ${MCP_STATUS}: $(mcp_snip)"
fi

end_suite
