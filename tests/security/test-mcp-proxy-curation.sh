#!/usr/bin/env bash
# test-mcp-proxy-curation.sh - MCP Remote curation is a security control
# (artifact-keeper#5253 Phase 2, issue 3.3, 3.4, 4.4 and 8).
#
#   - a lookalike of an approved namespace (io.github.acrne-tools vs
#     io.github.acme-tools, "rn" for "m") is flagged for review at ingest
#     (catalog item status review, flags.typosquat.similarTo) and never served
#   - decisions need repository administration: a user holding read and
#     write on the Remote gets 403 from the catalog approve, bulk-approve,
#     bulk-block and bulk-decide
#     (POST /api/v1/repositories/{key}/mcp/catalog/{id}/approve,
#     .../catalog/bulk-{approve,block,decide}) and from the generic curation
#     approve (POST /api/v1/curation/packages/{id}/approve, instance
#     administrators)
#   - unapproved entries never appear on /v0.1 for any caller, admin
#     included (list, search, versions, exact, include_deleted): browsing them
#     is UI-only
#   - mcp_caller_is_repo_admin / mcp_caller_can_lock on the repository
#     response match the caller (instance admin true/true, repository admin
#     true/false, writer and reader false/false)
#   - catalog views: requests for approval are recorded per requester
#     (approvalRequests.requesters, administrators only); a holder (read
#     grant) sees decisions without other users (evaluatedBy null,
#     approvalRequests {count}); a plain reader of the public Remote sees no
#     flags, denied, evaluationReason or summary.lint. summary carries the
#     risk inputs of the upstream document
#   - GET /api/v1/mcp/pending-summary counts this Remote's queue (401
#     anonymous)
#   - mcp_remote_posture_locked: a repository administrator cannot relax the
#     posture an instance administrator locked, change
#     mcp_auto_approve_namespaces, or bulk-approve with a namespace-spanning
#     pattern (403, dry runs included); naming the namespace and bulk blocks
#     stay allowed, and the instance administrator is not restricted
#   - bulk patterns are full-name globs: a bare namespace is 422, a malformed
#     pattern 400; dryRun answers the complete BulkResult
#     {approved, blocked, names, skippedDenied, skippedReview, dryRun} and
#     writes nothing; bulk-block blocks the matches
#   - mcp_server_deny (case-insensitive glob, `*` crosses `/`; a bare
#     namespace is 400) wins over an approval, and bulk approvals skip denied
#     names (skippedDenied)
#   - bulk-decide by ids answers {action, decided, unchanged, skippedDenied,
#     notFound}; no ids or more than 500 is 400, another action 422
#
# Gates: mcp_require_registry mcp_registry_proxy; mcp_create_proxy_repo
# (older backends refuse Remote mcp repos -> mcp_registry_proxy exemption);
# then the route and behaviour probe (POST .../mcp/sync answering the
# router's 404/405, or a sync that neither reaches the mock nor records a
# catalog row -> mcp_skip_later_phase mcp_registry_proxy).
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

# --- Contract (docs/mcp-registry.md "Remote repositories") ------------------
# Sync, catalog and decisions: the management API helpers in mcp-helpers.sh.
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

# cur_load: the Remote's catalog (a CatalogItem array) into CUR_ROWS.
cur_load() {
  mcp_catalog_load "$REMOTE" "$CUR_ROWS" || true
}

cur_row() {
  mcp_catalog_item "$CUR_ROWS" "$1"
}

cur_has() {
  cur_load
  [ -n "$(cur_row "$1")" ]
}

# cur_approve NAME [AUTH]: POST .../mcp/catalog/{id}/approve.
cur_approve() {
  cur_load
  local id
  id=$(cur_row "$1" | jq -r '.id // empty')
  if [ -z "$id" ]; then
    MCP_STATUS="no-row"
    return 1
  fi
  mcp_catalog_decide "$REMOTE" "$id" approve "${2:-admin}"
}

remote_sync() {
  mcp_remote_sync "$REMOTE" admin || true
  SYNC_STATUS="$MCP_SYNC_STATUS"
  wait_for_counter_stable "${MCP_MOCK_STATE_DIR}/request-count" 60 3 >/dev/null || true
}

# bulk ROUTE AUTH JSON: POST .../mcp/catalog/ROUTE (bulk-approve,
# bulk-block, bulk-decide).
bulk() {
  mcp_req POST "$(mcp_mgmt_url "$REMOTE" "catalog/$1")" "$2" -H "Content-Type: application/json" -d "$3"
}

# bulk_result: the last BulkResult, names sorted, as compact JSON.
bulk_result() {
  jq -cS '{approved, blocked, names: ((.names // []) | sort), skippedDenied, skippedReview, dryRun}' "$MCP_BODY" 2>/dev/null || true
}

# want_bulk APPROVED BLOCKED NAMES_JSON SKIPPED_DENIED SKIPPED_REVIEW DRY_RUN
want_bulk() {
  jq -cnS --argjson a "$1" --argjson b "$2" --argjson n "$3" --argjson d "$4" --argjson r "$5" --argjson dry "$6" \
    '{approved:$a, blocked:$b, names:($n | sort), skippedDenied:$d, skippedReview:$r, dryRun:$dry}'
}

# decide_result: the last BulkDecideResult, id lists sorted.
decide_result() {
  jq -cS '{action, decided: ((.decided // []) | sort), unchanged: ((.unchanged // []) | sort),
           skippedDenied: ((.skippedDenied // []) | sort), notFound: ((.notFound // []) | sort)}' "$MCP_BODY" 2>/dev/null || true
}

# want_decide ACTION DECIDED UNCHANGED SKIPPED_DENIED NOT_FOUND (JSON arrays)
want_decide() {
  jq -cnS --arg a "$1" --argjson d "$2" --argjson u "$3" --argjson s "$4" --argjson n "$5" \
    '{action:$a, decided:($d|sort), unchanged:($u|sort), skippedDenied:($s|sort), notFound:($n|sort)}'
}

cur_status() {
  cur_row "$1" | jq -r '.status // empty'
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
remote_sync
if ! mcp_remote_mounted; then
  mcp_skip_later_phase mcp_registry_proxy "POST /api/v1/repositories/${REMOTE}/mcp/sync on a Remote mcp repository answered ${SYNC_STATUS}: the Remote management API is not mounted"
fi
if ! wait_until "the Remote syncs from the mock" "$PROBE_WINDOW_SECS" _probe_contacted; then
  mcp_skip_later_phase mcp_registry_proxy "Remote ${REMOTE} over the mock upstream: POST /api/v1/repositories/${REMOTE}/mcp/sync answered ${SYNC_STATUS}, the mock saw no /servers request and GET /api/v1/repositories/${REMOTE}/mcp/catalog listed no rows within ${PROBE_WINDOW_SECS}s"
fi
wait_until "catalog rows for the seed" "$SYNC_WAIT_SECS" cur_has "$PENDING" || true

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
remote_sync
if wait_until "a catalog row for ${LOOKALIKE}" "$SYNC_WAIT_SECS" cur_has "$LOOKALIKE"; then
  row=$(cur_row "$LOOKALIKE")
  status=$(printf '%s' "$row" | jq -r '.status')
  similar=$(printf '%s' "$row" | jq -r '.flags.typosquat.similarTo // empty')
  if [ "$status" != "review" ]; then
    fail "lookalike not routed to review (status '${status}')" "$row"
  elif [ "$similar" != "$GOOD" ]; then
    fail "lookalike flags.typosquat.similarTo is '${similar}', expected ${GOOD}" "$row"
  else
    pass
  fi
else
  fail "no catalog row for ${LOOKALIKE} after sync (sync answered ${SYNC_STATUS})"
fi

begin_test "Decisions need repository administration: a read+write user gets 403"
cur_approve "$LOOKALIKE" "$WRITER_TOKEN" || true
approve_status="$MCP_STATUS"
lookalike_id=$(cur_row "$LOOKALIKE" | jq -r '.id // empty')
mcp_req POST "$(mcp_mgmt_url "$REMOTE" catalog/bulk-approve)" "$WRITER_TOKEN" -H "Content-Type: application/json" \
  -d '{"pattern":"io.github.acrne-tools/*","includeReview":true,"reason":"release-gate non-admin bulk approve"}'
bulk_status="$MCP_STATUS"
bulk bulk-block "$WRITER_TOKEN" '{"pattern":"io.github.acrne-tools/*","reason":"release-gate non-admin bulk block"}'
bulk_block_status="$MCP_STATUS"
bulk bulk-decide "$WRITER_TOKEN" "$(jq -cn --arg i "$lookalike_id" '{ids:[$i],action:"approve"}')"
bulk_decide_status="$MCP_STATUS"
mcp_req POST "${BASE_URL}/api/v1/curation/packages/${lookalike_id}/approve" "$WRITER_TOKEN" -H "Content-Type: application/json" -d '{}'
generic_status="$MCP_STATUS"
cur_load
after=$(cur_row "$LOOKALIKE" | jq -r '.status')
if [ "$approve_status" = "403" ] && [ "$bulk_status" = "403" ] && [ "$bulk_block_status" = "403" ] \
  && [ "$bulk_decide_status" = "403" ] && [ "$generic_status" = "403" ] && [ "$after" = "review" ]; then
  pass
else
  fail "read+write user: catalog approve ${approve_status}, bulk-approve ${bulk_status}, bulk-block ${bulk_block_status}, bulk-decide ${bulk_decide_status}, generic curation approve ${generic_status} (all want 403); row status now '${after}'"
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

# ---------------------------------------------------------------------------
# Who sees what
# ---------------------------------------------------------------------------

begin_test "Setup: a plain reader (no grant) of the public Remote"
mcp_make_user "mcp-cur-reader-${RUN_ID}" > "${WORK_DIR}/reader.tok" || true
READER_TOKEN=$(cat "${WORK_DIR}/reader.tok" 2>/dev/null)
if [ -n "$READER_TOKEN" ]; then
  pass
else
  fail_fatal "could not create the reader user"
fi

begin_test "mcp_caller_is_repo_admin and mcp_caller_can_lock answer for the caller"
caller_flags() {
  mcp_req GET "${BASE_URL}/api/v1/repositories/${REMOTE}" "$1"
  mcp_json '"\(.mcp_caller_is_repo_admin)|\(.mcp_caller_can_lock)"'
}
f_admin=$(caller_flags admin)
f_writer=$(caller_flags "$WRITER_TOKEN")
f_reader=$(caller_flags "$READER_TOKEN")
f_repoadmin=$(caller_flags "$REPOADMIN_TOKEN")
want_repoadmin="true|false"
[ "$REPOADMIN_GRANTED" = "1" ] || want_repoadmin="false|false"
if [ "$f_admin" = "true|true" ] && [ "$f_writer" = "false|false" ] && [ "$f_reader" = "false|false" ] \
  && [ "$f_repoadmin" = "$want_repoadmin" ]; then
  pass
else
  fail "is_repo_admin|can_lock: admin '${f_admin}' (want true|true), repository admin '${f_repoadmin}' (want ${want_repoadmin}), writer '${f_writer}' and reader '${f_reader}' (want false|false)"
fi

begin_test "Requests for approval are recorded per requester; administrators see who asked"
cur_load
PENDING_ID=$(cur_row "$PENDING" | jq -r '.id // empty')
GOOD_ID=$(cur_row "$GOOD" | jq -r '.id // empty')
LOOKALIKE_ID=$(cur_row "$LOOKALIKE" | jq -r '.id // empty')
NOTE1="needed for release-gate ${RUN_ID}"
NOTE2="still needed for release-gate ${RUN_ID}"
ask() {
  mcp_req POST "$(mcp_mgmt_url "$REMOTE" "catalog/${PENDING_ID}/request-approval")" "$1" -H "Content-Type: application/json" -d "$2"
  printf '%s' "$MCP_STATUS"
}
a1=$(ask "$WRITER_TOKEN" "$(jq -cn --arg n "$NOTE1" '{note:$n}')")
a2=$(ask "$WRITER_TOKEN" "$(jq -cn --arg n "$NOTE2" '{note:$n}')")
a3=$(ask "$READER_TOKEN" '{}')
cur_load
requests=$(cur_row "$PENDING" | jq -c '.approvalRequests // {}')
got=$(printf '%s' "$requests" | jq -r --arg w "$WRITER_ID" '"\(.count)|\(.requesters | length)|\(.requesters[$w].note)"' 2>/dev/null)
if [ "$a1|$a2|$a3" != "200|200|200" ]; then
  fail "request-approval answered ${a1}, ${a2} (writer) and ${a3} (reader), want 200 each"
elif [ "$got" != "2|2|${NOTE2}" ]; then
  fail "admin view of approvalRequests count|requesters|writer note is '${got}', want '2|2|${NOTE2}' (asking again replaces only the caller's note)" "$requests"
else
  pass
fi

begin_test "Catalog views: a holder sees decisions without other users; a plain reader sees upstream facts only"
H_ROWS="${WORK_DIR}/catalog-holder.json"
R_ROWS="${WORK_DIR}/catalog-reader.json"
mcp_catalog_load "$REMOTE" "$H_ROWS" "$WRITER_TOKEN" || true
h_status="$MCP_STATUS"
mcp_catalog_load "$REMOTE" "$R_ROWS" "$READER_TOKEN" || true
r_status="$MCP_STATUS"
item() { mcp_catalog_item "$1" "$2"; }
admin_by=$(cur_row "$GOOD" | jq -r '.evaluatedBy // empty')
h_good=$(item "$H_ROWS" "$GOOD" | jq -c '{evaluatedBy, hasReason: (.evaluationReason != null)}')
h_req=$(item "$H_ROWS" "$PENDING" | jq -c '.approvalRequests')
h_flag=$(item "$H_ROWS" "$LOOKALIKE" | jq -r '.flags.typosquat.similarTo // empty')
r_good=$(item "$R_ROWS" "$GOOD" | jq -c '{evaluatedBy, evaluationReason, pins: [.pins[]? | {evaluationReason, contentDrift}] | unique}')
r_req=$(item "$R_ROWS" "$PENDING" | jq -c '.approvalRequests')
r_flags=$(item "$R_ROWS" "$LOOKALIKE" | jq -c '.flags')
r_leaks=$(jq -c '[.[] | select(has("denied") or (.summary.lint != null) or ([.ingested[]?.unresolved[]?] | length > 0)) | .name]' "$R_ROWS" 2>/dev/null)
if [ "$h_status" != "200" ] || [ "$r_status" != "200" ]; then
  fail "catalog for the holder answered ${h_status}, for the plain reader ${r_status} (want 200: the Remote is public)"
elif [ -z "$admin_by" ]; then
  fail "the administrator's view of ${GOOD} has no evaluatedBy" "$(cur_row "$GOOD")"
elif [ "$h_good" != '{"evaluatedBy":null,"hasReason":true}' ] || [ "$h_req" != '{"count":2}' ] || [ "$h_flag" != "$GOOD" ]; then
  fail "holder view: ${GOOD} ${h_good} (want evaluatedBy null, a reason), ${PENDING} approvalRequests ${h_req} (want {\"count\":2}), ${LOOKALIKE} similarTo '${h_flag}'"
elif [ "$r_good" != '{"evaluatedBy":null,"evaluationReason":null,"pins":[]}' ] && [ "$r_good" != '{"evaluatedBy":null,"evaluationReason":null,"pins":[{"contentDrift":null,"evaluationReason":null}]}' ]; then
  fail "plain reader view of ${GOOD} discloses decision detail: ${r_good}"
elif [ "$r_req" != '{"count":2}' ] || [ "$r_flags" != "{}" ] || [ "$r_leaks" != "[]" ]; then
  fail "plain reader view: approvalRequests ${r_req} (want {\"count\":2}), ${LOOKALIKE} flags ${r_flags} (want {}), items with denied/summary.lint/unresolved: ${r_leaks}"
else
  pass
fi

begin_test "Catalog summary carries the upstream document's risk inputs"
want_sum='{"packagesCount":0,"registryTypes":[],"remotesCount":1,"secretsCount":0,"transports":["streamable-http"]}'
s_good=$(cur_row "$GOOD" | jq -cS '.summary | if type == "object" then del(.lint) else . end')
s_pending=$(cur_row "$PENDING" | jq -cS '.summary | if type == "object" then del(.lint) else . end')
s_lint=$(cur_row "$GOOD" | jq -c '.summary.lint // {} | keys')
if [ "$s_good" != "$want_sum" ] || [ "$s_pending" != "$want_sum" ]; then
  fail "summary of ${GOOD} '${s_good}', of ${PENDING} '${s_pending}', want ${want_sum}"
elif [ "$s_lint" != "[]" ] && [ "$s_lint" != '["block","review","version","warn"]' ]; then
  fail "summary.lint of the ingested ${GOOD} has keys ${s_lint}, want {version, block, review, warn}"
else
  pass
fi

begin_test "GET /api/v1/mcp/pending-summary counts this Remote's queue; anonymous is 401"
want_q=$(jq -r '"\([.[] | select(.status == "pending")] | length)|\([.[] | select(.status == "review")] | length)|\([.[] | .pins[]? | select(.status == "pending" or .status == "review")] | length)"' "$CUR_ROWS")
mcp_req GET "${BASE_URL}/api/v1/mcp/pending-summary" admin
q_status="$MCP_STATUS"
got_q=$(jq -r --arg k "$REMOTE" '[.repositories[]? | select(.key == $k)][0] // {} | "\(.pending)|\(.review)|\(.drifted)"' "$MCP_BODY" 2>/dev/null || true)
q_total=$(mcp_json '(.total == (.pending + .review + .drifted)) and (.pending >= 0)')
mcp_req GET "${BASE_URL}/api/v1/mcp/pending-summary" anon
anon_q="$MCP_STATUS"
if [ "$q_status" != "200" ]; then
  fail "pending-summary answered ${q_status}: $(mcp_snip)"
elif [ "$got_q" != "$want_q" ]; then
  fail "pending-summary for ${REMOTE} pending|review|drifted is '${got_q}', the catalog says '${want_q}'"
elif [ "$q_total" != "true" ]; then
  fail "pending-summary total is not pending + review + drifted"
elif [ "$anon_q" != "401" ]; then
  fail "anonymous pending-summary answered ${anon_q}, want 401"
else
  pass
fi

LOCK_SET=0
begin_test "An instance-locked posture cannot be relaxed by a repository administrator"
if [ "$REPOADMIN_GRANTED" != "1" ]; then
  skip "the backend refused the repository-admin grant ${REPO_ADMIN_ACTIONS} (HTTP ${MCP_STATUS}); no repository administrator to test the lock with"
elif ! mcp_patch_repo "$REMOTE" '{"mcp_remote_posture_locked":true}'; then
  fail "instance admin could not set mcp_remote_posture_locked (HTTP ${MCP_STATUS}): $(mcp_snip)"
else
  LOCK_SET=1
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

begin_test "Under the posture lock only an instance administrator bulk-approves across namespaces"
if [ "$REPOADMIN_GRANTED" != "1" ] || [ "$LOCK_SET" != "1" ]; then
  skip "no repository administrator (grant ${REPOADMIN_GRANTED}) or no posture lock (${LOCK_SET}) to test with"
else
  bulk bulk-approve "$REPOADMIN_TOKEN" '{"pattern":"*","dryRun":true}'
  ra_star="$MCP_STATUS"
  bulk bulk-approve "$REPOADMIN_TOKEN" '{"pattern":"io.github.*/*","dryRun":true}'
  ra_span="$MCP_STATUS"
  bulk bulk-approve "$REPOADMIN_TOKEN" '{"pattern":"io.github.acme-tools/*","dryRun":true}'
  ra_named="$MCP_STATUS:$(mcp_json '.dryRun')"
  bulk bulk-block "$REPOADMIN_TOKEN" '{"pattern":"*","dryRun":true}'
  ra_block="$MCP_STATUS"
  bulk bulk-approve admin '{"pattern":"*","dryRun":true}'
  ia_star="$MCP_STATUS"
  patch_as "$REPOADMIN_TOKEN" '{"mcp_auto_approve_namespaces":["io.github.acme-tools/*"]}'
  ra_auto="$MCP_STATUS"
  if [ "$ra_star|$ra_span|$ra_named|$ra_block|$ia_star|$ra_auto" = "403|403|200:true|200|200|403" ]; then
    pass
  else
    fail "posture lock: repository admin bulk-approve '*' ${ra_star}, 'io.github.*/*' ${ra_span} (want 403), named namespace ${ra_named} (want 200:true), bulk-block '*' ${ra_block} (want 200); instance admin '*' ${ia_star} (want 200); repository admin PATCH mcp_auto_approve_namespaces ${ra_auto} (want 403)"
  fi
fi

begin_test "Bulk patterns are full-name globs: a bare namespace is 422, a malformed pattern 400"
bulk bulk-approve admin '{"pattern":"io.github.acme-tools","dryRun":true}'
p_bare_a="$MCP_STATUS"
bulk bulk-block admin '{"pattern":"io.github.acme-tools","dryRun":true}'
p_bare_b="$MCP_STATUS"
bulk bulk-approve admin '{"pattern":"not a pattern!","dryRun":true}'
p_bad="$MCP_STATUS"
if [ "$p_bare_a|$p_bare_b|$p_bad" = "422|422|400" ]; then
  pass
else
  fail "bulk-approve bare namespace ${p_bare_a}, bulk-block bare namespace ${p_bare_b} (want 422), malformed pattern ${p_bad} (want 400)"
fi

begin_test "bulk-approve dryRun answers the complete BulkResult and writes nothing"
bulk bulk-approve admin '{"pattern":"io.github.acme-tools/*","dryRun":true,"reason":"release-gate dry run"}'
dry_a="$MCP_STATUS:$(bulk_result)"
want_a="200:$(want_bulk 1 0 "[\"${PENDING}\"]" 0 0 true)"
bulk bulk-approve admin '{"pattern":"io.github.acrne-tools/*","dryRun":true}'
dry_r="$MCP_STATUS:$(bulk_result)"
want_r="200:$(want_bulk 0 0 '[]' 0 1 true)"
cur_load
if [ "$dry_a" != "$want_a" ]; then
  fail "dry-run bulk-approve io.github.acme-tools/* answered '${dry_a}', want '${want_a}'"
elif [ "$dry_r" != "$want_r" ]; then
  fail "dry-run bulk-approve of the flagged lookalike without includeReview answered '${dry_r}', want '${want_r}' (skippedReview)"
elif [ "$(cur_status "$PENDING")" != "pending" ] || [ "$(cur_status "$LOOKALIKE")" != "review" ]; then
  fail "a dry run changed a row: ${PENDING} '$(cur_status "$PENDING")', ${LOOKALIKE} '$(cur_status "$LOOKALIKE")'"
else
  pass
fi

begin_test "bulk-block: a dry run changes nothing, the real call blocks the match"
bulk bulk-block admin '{"pattern":"io.github.acrne-tools/*","dryRun":true}'
dry_b="$MCP_STATUS:$(bulk_result)"
cur_load
after_dry=$(cur_status "$LOOKALIKE")
bulk bulk-block admin '{"pattern":"io.github.acrne-tools/*","reason":"release-gate bulk block"}'
real_b="$MCP_STATUS:$(bulk_result)"
cur_load
after_real=$(cur_status "$LOOKALIKE")
mcp_get "$REMOTE" "$(mcp_version_path "$LOOKALIKE" 1.0.0)" anon
lookalike_plain=$(mcp_check_plain_404) && lookalike_plain=ok
if [ "$dry_b" != "200:$(want_bulk 0 1 "[\"${LOOKALIKE}\"]" 0 0 true)" ] || [ "$after_dry" != "review" ]; then
  fail "dry-run bulk-block answered '${dry_b}', row now '${after_dry}' (want blocked 1, names [${LOOKALIKE}], dryRun true; row still review)"
elif [ "$real_b" != "200:$(want_bulk 0 1 "[\"${LOOKALIKE}\"]" 0 0 false)" ] || [ "$after_real" != "blocked" ]; then
  fail "bulk-block answered '${real_b}', row now '${after_real}' (want blocked 1, dryRun false; row blocked)"
elif [ "$lookalike_plain" != "ok" ]; then
  fail "the blocked lookalike is served: ${lookalike_plain}"
else
  pass
fi

begin_test "mcp_server_deny: a bare namespace is 400 (the globs match the full name)"
mcp_patch_repo "$REMOTE" '{"mcp_server_deny":["io.github.acme-tools"]}' || true
bare_deny="$MCP_STATUS"
stored_deny=$(repo_field mcp_server_deny || true)
if [ "$bare_deny" = "400" ] && { [ -z "$stored_deny" ] || [ "$stored_deny" = "[]" ]; }; then
  pass
else
  fail "PATCH mcp_server_deny [io.github.acme-tools] answered ${bare_deny} (want 400); stored '${stored_deny}'"
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

begin_test "A bulk approval skips denied names (skippedDenied)"
bulk bulk-approve admin '{"pattern":"io.github.acme-tools/*","dryRun":true}'
got_d="$MCP_STATUS:$(bulk_result)"
want_d="200:$(want_bulk 0 0 '[]' 1 0 true)"
if [ "$got_d" = "$want_d" ]; then
  pass
else
  fail "dry-run bulk-approve over the denied ${PENDING} answered '${got_d}', want '${want_d}'"
fi

begin_test "bulk-decide by ids: decided, unchanged, skippedDenied, notFound"
UNKNOWN_ID=$(python3 -c 'import uuid; print(uuid.uuid4())')
bulk bulk-decide admin "$(jq -cn --arg p "$PENDING_ID" --arg g "$GOOD_ID" --arg u "$UNKNOWN_ID" '{ids:[$p,$g,$u],action:"approve",reason:"release-gate bulk decide"}')"
dec_a="$MCP_STATUS:$(decide_result)"
want_a="200:$(want_decide approve '[]' "[\"${GOOD_ID}\"]" "[\"${PENDING_ID}\"]" "[\"${UNKNOWN_ID}\"]")"
bulk bulk-decide admin "$(jq -cn --arg g "$GOOD_ID" --arg l "$LOOKALIKE_ID" '{ids:[$g,$l],action:"block"}')"
dec_b="$MCP_STATUS:$(decide_result)"
want_b="200:$(want_decide block "[\"${GOOD_ID}\"]" "[\"${LOOKALIKE_ID}\"]" '[]' '[]')"
cur_load
good_after=$(cur_status "$GOOD")
if [ -z "$PENDING_ID" ] || [ -z "$GOOD_ID" ] || [ -z "$LOOKALIKE_ID" ]; then
  fail "catalog ids missing: pending '${PENDING_ID}', good '${GOOD_ID}', lookalike '${LOOKALIKE_ID}'"
elif [ "$dec_a" != "$want_a" ]; then
  fail "bulk-decide approve answered '${dec_a}', want '${want_a}'"
elif [ "$dec_b" != "$want_b" ] || [ "$good_after" != "blocked" ]; then
  fail "bulk-decide block answered '${dec_b}' (want '${want_b}'); ${GOOD} is now '${good_after}'"
else
  pass
fi

begin_test "bulk-decide refuses no ids or more than 500 (400) and another action (422)"
bulk bulk-decide admin '{"ids":[],"action":"approve"}'
none="$MCP_STATUS"
many=$(python3 -c 'import json, uuid; print(json.dumps({"ids": [str(uuid.uuid4()) for _ in range(501)], "action": "block"}))')
bulk bulk-decide admin "$many"
over="$MCP_STATUS"
bulk bulk-decide admin "$(jq -cn --arg g "$GOOD_ID" '{ids:[$g],action:"reopen"}')"
other="$MCP_STATUS"
if [ "$none|$over|$other" = "400|400|422" ]; then
  pass
else
  fail "bulk-decide with no ids ${none}, 501 ids ${over} (want 400), action reopen ${other} (want 422)"
fi

end_suite
