#!/usr/bin/env bash
# test-mcp-upstream-sync-cursor.sh - MCP Remote sync pages the upstream
# registry correctly (artifact-keeper#5253 Phase 2, issue 3.4 and 4.1).
#
# The mock upstream caps every page at 3 entries whatever limit Artifact
# Keeper asks for, over the 14 fixture entries (8 names) in
# tests/fixtures/mcp/upstream/servers. The request log proves:
#   - the first sync walks every page: 5 list requests, each page after the
#     first carrying the previous page's nextCursor. The first pass has no
#     watermark, so it asks `?limit=100&include_deleted=true` (docs "Sync"):
#     a version already deleted upstream (charlie 2.1.0) is recorded too and
#     shows up in its name's catalog item `versions`
#   - the catalog item's `summary` carries the risk inputs of the name's
#     latest non-deleted upstream document (transports, registryTypes,
#     secretsCount, packagesCount, remotesCount), also for unapproved names
#   - a second sync without upstream changes is one updated_since request
#     (updated_since implies include_deleted, so deletions are seen from
#     then on) and no version document fetch (no amplification)
#   - a changed entry (bumped updatedAt, new description on the latest
#     version) is the only entry the next sync picks up, and its catalog
#     item (GET /api/v1/repositories/{key}/mcp/catalog) carries the new
#     summary
#   - an upstream status change to deleted mirrors: the version leaves the
#     listing, its exact read is 404 and include_deleted=true shows it deleted
#
# Gates: mcp_require_registry mcp_registry_proxy; mcp_create_proxy_repo
# (older backends refuse Remote mcp repos -> mcp_registry_proxy exemption);
# then the route and behaviour probe: POST /api/v1/repositories/{key}/mcp/sync
# answering the router's 404/405, or a sync after which the mock saw no
# /servers request and the catalog lists no row -> mcp_skip_later_phase
# mcp_registry_proxy.
#
# Requires: curl, jq, python3, MOCK_UPSTREAM_HOSTNAME.

# shellcheck source=../lib/common.sh disable=SC1091
source "$(dirname "$0")/../lib/common.sh"
# shellcheck source=../lib/mcp-helpers.sh disable=SC1091
source "$(dirname "$0")/../lib/mcp-helpers.sh"

begin_suite "mcp-upstream-sync-cursor"
auth_admin
setup_workdir
require_cmd curl
require_cmd jq
require_cmd python3
mcp_require_registry mcp_registry_proxy
mcp_require_dialback

# Sync and catalog: the management API helpers in mcp-helpers.sh.
PROBE_WINDOW_SECS="${MCP_REMOTE_PROBE_SECS:-45}"
SYNC_WAIT_SECS="${MCP_REMOTE_SYNC_SECS:-90}"

NS="io.github.ak-fixture"
PAGE_SIZE=3
REMOTE="mcp-sync-${RUN_ID}"
CUR_ROWS="${WORK_DIR}/curation.json"
LOG=""

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
  mcp_catalog_load "$REMOTE" "$CUR_ROWS" || true
}

cur_row() {
  mcp_catalog_item "$CUR_ROWS" "$1"
}

cur_names() {
  jq -r '[.[].name] | unique | .[]' "$CUR_ROWS" 2>/dev/null || true
}

cur_has_names() {
  cur_load
  [ "$(cur_names | wc -l)" -ge "$1" ]
}

cur_row_mentions() {
  cur_load
  cur_row "$1" | grep -qF "$2"
}

cur_approve() {
  cur_load
  local id
  id=$(cur_row "$1" | jq -r '.id // empty')
  [ -n "$id" ] || return 1
  mcp_catalog_decide "$REMOTE" "$id" approve
}

log_lines() {
  wc -l < "$LOG" 2>/dev/null | tr -d ' ' || echo 0
}

# requests_since N: request-log lines after line N.
requests_since() {
  tail -n +"$(( $1 + 1 ))" "$LOG" 2>/dev/null || true
}

list_requests() {
  grep -E ' GET /v0(\.1)?/servers(\?|$)' || true
}

version_requests() {
  grep -E ' GET /v0(\.1)?/servers/.+/versions' || true
}

remote_sync() {
  mcp_remote_sync "$REMOTE" admin || true
  SYNC_STATUS="$MCP_SYNC_STATUS"
  wait_for_counter_stable "${MCP_MOCK_STATE_DIR}/request-count" 60 3 >/dev/null || true
}

query_param() {
  python3 -c '
import sys, urllib.parse
q = urllib.parse.parse_qs(urllib.parse.urlsplit(sys.argv[1]).query, keep_blank_values=True)
print(q.get(sys.argv[2], [""])[-1])
' "$1" "$2"
}

# expected_cursors EXTRA_QUERY: the nextCursor values the mock hands out
# walking the whole catalog at PAGE_SIZE with EXTRA_QUERY
# ("&include_deleted=true", what the first pass asks), in order.
expected_cursors() {
  local cursor="" url
  while :; do
    url="${MCP_MOCK_LOCAL_URL}/v0.1/servers?limit=100${1}"
    [ -n "$cursor" ] && url="${url}&cursor=${cursor}"
    cursor=$(curl -s --max-time 10 "$url" | jq -r '.metadata.nextCursor // empty')
    [ -n "$cursor" ] || break
    echo "$cursor"
  done
}

fixture_set() {
  # fixture_set FILE JQ_FILTER [ARGS...]: rewrite one mock fixture in place.
  local file="${MCP_MOCK_STATE_DIR}/servers/$1" filter="$2"
  shift 2
  jq "$@" "$filter" "$file" > "${file}.tmp" && mv "${file}.tmp" "$file"
}

# ---------------------------------------------------------------------------
# Setup and the behaviour probe
# ---------------------------------------------------------------------------

begin_test "Setup: mock upstream at page size ${PAGE_SIZE} and the Remote over it"
if ! start_mock_mcp_upstream "${WORK_DIR}/mcp-upstream"; then
  infra_fail "mock-mcp-upstream did not start" "$(head -c 400 "${WORK_DIR}/mock-mcp-upstream.err" 2>/dev/null)"
  end_suite
fi
echo "$PAGE_SIZE" > "${MCP_MOCK_STATE_DIR}/page-size"
LOG="${MCP_MOCK_STATE_DIR}/request-log.txt"
FIXTURE_COUNT=$(find "${MCP_MOCK_STATE_DIR}/servers" -name '*.json' | wc -l | tr -d ' ')
LIVE_COUNT=$(jq -r 'select((._meta["io.modelcontextprotocol.registry/official"].status // "active") != "deleted") | .server.name' \
  "${MCP_MOCK_STATE_DIR}"/servers/*.json | wc -l | tr -d ' ')
FIXTURE_NAMES=$(jq -r '.server.name' "${MCP_MOCK_STATE_DIR}"/servers/*.json | sort -u | wc -l | tr -d ' ')
PAGES_ALL=$(( (FIXTURE_COUNT + PAGE_SIZE - 1) / PAGE_SIZE ))
mapfile -t CURSORS_ALL < <(expected_cursors "&include_deleted=true")
if [ "$FIXTURE_COUNT" != "14" ] || [ "$LIVE_COUNT" != "13" ] \
  || [ "${#CURSORS_ALL[@]}" != "$(( PAGES_ALL - 1 ))" ]; then
  infra_fail "fixture catalog drifted: ${FIXTURE_COUNT} entries (${LIVE_COUNT} not deleted), ${#CURSORS_ALL[@]} cursors at page size ${PAGE_SIZE}"
  end_suite
fi
# Reading the mock to precompute cursors logged requests: start the log over.
: > "$LOG"
if ! mcp_create_proxy_repo "$REMOTE" remote "$MCP_MOCK_BASE_URL"; then
  fail_fatal "create Remote mcp repository" "$MCP_CREATE_ERROR"
fi
REMOTE_ID=$(mcp_repo_id "$REMOTE")
[ -n "$REMOTE_ID" ] || fail_fatal "Remote ${REMOTE} has no id"
pass

_probe_contacted() {
  [ -n "$(list_requests < "$LOG")" ] && return 0
  cur_load
  [ "$(jq 'length' "$CUR_ROWS" 2>/dev/null || echo 0)" -gt 0 ]
}
FIRST_SYNC_START=$(log_lines)
mcp_remote_sync "$REMOTE" admin || true
SYNC_STATUS="$MCP_SYNC_STATUS"
if ! mcp_remote_mounted; then
  mcp_skip_later_phase mcp_registry_proxy "POST /api/v1/repositories/${REMOTE}/mcp/sync on a Remote mcp repository answered ${SYNC_STATUS}: the Remote management API is not mounted"
fi
if ! wait_until "the Remote syncs from the mock" "$PROBE_WINDOW_SECS" _probe_contacted; then
  mcp_skip_later_phase mcp_registry_proxy "Remote ${REMOTE} over the mock upstream: POST /api/v1/repositories/${REMOTE}/mcp/sync answered ${SYNC_STATUS}, the mock saw no /servers request and GET /api/v1/repositories/${REMOTE}/mcp/catalog listed no rows within ${PROBE_WINDOW_SECS}s"
fi
wait_until "every fixture name recorded" "$SYNC_WAIT_SECS" cur_has_names "$FIXTURE_NAMES" || true
wait_for_counter_stable "${MCP_MOCK_STATE_DIR}/request-count" 60 3 >/dev/null || true

# ---------------------------------------------------------------------------
# First sync: every page
# ---------------------------------------------------------------------------

FIRST=$(requests_since "$FIRST_SYNC_START" | list_requests)
# A creation-time sync plus the manual one may both have run: take one
# complete walk (the first request without a cursor up to the last cursor)
# rather than all requests.
walk=$(printf '%s\n' "$FIRST" | awk '/cursor=/{print; next} {if (seen) exit; seen=1; print}')
first_path=$(printf '%s\n' "$walk" | head -1 | awk '{print $3}')

begin_test "The first sync (no watermark) asks for deleted entries: include_deleted=true, no updated_since"
if [ "$(query_param "${first_path:-/}" include_deleted)" = "true" ] && [ -z "$(query_param "${first_path:-/}" updated_since)" ]; then
  pass
else
  fail "the first list request was '${first_path}', expected ?limit=100&include_deleted=true without updated_since" "$FIRST"
fi

begin_test "First sync walks every page (${PAGES_ALL} list requests at page size ${PAGE_SIZE}, deleted entries included)"
pages=$(printf '%s\n' "$walk" | grep -c . || true)
if [ "$pages" = "$PAGES_ALL" ]; then
  pass
else
  fail "one sync made ${pages} list request(s), expected ${PAGES_ALL}" "$FIRST"
fi

begin_test "Each page after the first carries the previous page's nextCursor"
got=()
while read -r _ts _m path; do
  [ -n "${path:-}" ] || continue
  c=$(query_param "$path" cursor)
  [ -n "$c" ] && got+=("$c")
done <<< "$walk"
if [ "${got[*]}" = "${CURSORS_ALL[*]}" ]; then
  pass
else
  fail "cursor sequence differs" "expected: ${CURSORS_ALL[*]}
got:      ${got[*]}"
fi

begin_test "Every upstream name has a catalog row after the first sync"
cur_load
if [ "$(cur_names | wc -l | tr -d ' ')" = "$FIXTURE_NAMES" ]; then
  pass
else
  fail "catalog rows for $(cur_names | wc -l | tr -d ' ') of ${FIXTURE_NAMES} names" "$(cur_names)"
fi

begin_test "A version already deleted upstream is recorded by the first sync (charlie 2.1.0 in versions, not latest)"
charlie=$(cur_row "${NS}/charlie")
c_versions=$(printf '%s' "$charlie" | jq -r '(.versions // []) | join(",")' 2>/dev/null)
c_latest=$(printf '%s' "$charlie" | jq -r '.latestVersion // empty' 2>/dev/null)
if [ -z "$charlie" ]; then
  fail "no catalog item for ${NS}/charlie"
elif ! printf ',%s,' "$c_versions" | grep -qF ',2.1.0,' || ! printf ',%s,' "$c_versions" | grep -qF ',2.0.0,'; then
  fail "charlie's catalog versions are '${c_versions}', expected 2.1.0 (deleted upstream) and 2.0.0" "$charlie"
elif [ "$c_latest" != "2.0.0" ]; then
  fail "charlie's latestVersion is '${c_latest}', expected 2.0.0 (a deleted version is never latest)"
else
  pass
fi

begin_test "Catalog items carry the risk summary of the latest upstream document, approved or not"
# server_risk_summary of the fixtures: npm-backed has one stdio npm package,
# alpha one streamable-http remote; no fixture marks anything isSecret.
want_npm='{"packagesCount":1,"registryTypes":["npm"],"remotesCount":0,"secretsCount":0,"transports":["stdio"]}'
want_alpha='{"packagesCount":0,"registryTypes":[],"remotesCount":1,"secretsCount":0,"transports":["streamable-http"]}'
got_npm=$(cur_row "${NS}/npm-backed" | jq -cS '.summary | if type == "object" then del(.lint) else . end' 2>/dev/null)
got_alpha=$(cur_row "${NS}/alpha" | jq -cS '.summary | if type == "object" then del(.lint) else . end' 2>/dev/null)
if [ "$got_npm" = "$want_npm" ] && [ "$got_alpha" = "$want_alpha" ]; then
  pass
else
  fail "catalog summary: npm-backed '${got_npm}' (want ${want_npm}), alpha '${got_alpha}' (want ${want_alpha})"
fi

# Approve alpha so its versions are ingested (deleted-status mirroring below
# needs an ingested version).
cur_approve "${NS}/alpha" || true
remote_sync "$REMOTE"
wait_until "alpha served" "$SYNC_WAIT_SECS" served_has "$REMOTE" "${NS}/alpha@1.1.0" anon || true

# ---------------------------------------------------------------------------
# No amplification
# ---------------------------------------------------------------------------

begin_test "A second sync without upstream changes is one updated_since request and no version fetch"
start=$(log_lines)
remote_sync "$REMOTE"
second=$(requests_since "$start")
lists=$(printf '%s\n' "$second" | list_requests)
n_lists=$(printf '%s\n' "$lists" | grep -c . || true)
n_versions=$(printf '%s\n' "$second" | version_requests | grep -c . || true)
since=$(printf '%s\n' "$lists" | head -1 | awk '{print $3}')
if [ "$n_lists" = "1" ] && [ "$n_versions" = "0" ] && [ -n "$(query_param "${since:-/}" updated_since)" ]; then
  pass
else
  fail "unchanged catalog: ${n_lists} list request(s), ${n_versions} version fetch(es) (sync answered ${SYNC_STATUS})" "$second"
fi

# ---------------------------------------------------------------------------
# A changed entry is fetched alone
# ---------------------------------------------------------------------------

begin_test "A changed entry (bumped updatedAt) is the only entry the next sync picks up"
# bravo 1.0.0 is bravo's upstream latest, whose title and description the
# catalog summary caches.
NEW_DESC="Bravo fixture server, revised ${RUN_ID}"
NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
# shellcheck disable=SC2016 # jq variables, not shell
fixture_set "io.github.ak-fixture__bravo@1.0.0.json" \
  '.server.description = $d | ._meta["io.modelcontextprotocol.registry/official"].updatedAt = $u' \
  --arg d "$NEW_DESC" --arg u "$NOW"
start=$(log_lines)
remote_sync "$REMOTE"
third=$(requests_since "$start")
lists=$(printf '%s\n' "$third" | list_requests)
n_lists=$(printf '%s\n' "$lists" | grep -c . || true)
others=$(printf '%s\n' "$third" | version_requests | grep -v 'bravo' || true)
# What that updated_since page answers, asked of the mock directly.
since_path=$(printf '%s\n' "$lists" | head -1 | awk '{print $3}')
since_val=$(query_param "${since_path:-/}" updated_since)
picked=$(curl -s --max-time 10 "${MCP_MOCK_LOCAL_URL}/v0.1/servers?updated_since=$(jq -rn --arg v "$since_val" '$v|@uri')" \
  | jq -r '[.servers[] | "\(.server.name)@\(.server.version)"] | join(",")')
if [ "$n_lists" != "1" ] || [ -z "$since_val" ]; then
  fail "expected one updated_since page, got ${n_lists}" "$third"
elif [ "$picked" != "${NS}/bravo@1.0.0" ]; then
  fail "the sync's updated_since (${since_val}) selects '${picked}', expected only ${NS}/bravo@1.0.0"
elif [ -n "$others" ]; then
  fail "the sync fetched version documents of unchanged names" "$others"
elif ! wait_until "bravo's catalog item carries the new summary" 30 cur_row_mentions "${NS}/bravo" "$NEW_DESC"; then
  fail "bravo's catalog item does not reflect the changed upstream entry" "$(cur_row "${NS}/bravo" | head -c 600)"
else
  pass
fi

# ---------------------------------------------------------------------------
# Deleted status mirrors
# ---------------------------------------------------------------------------

begin_test "An upstream status change to deleted mirrors on the next sync"
NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
# shellcheck disable=SC2016 # jq variables, not shell
fixture_set "io.github.ak-fixture__alpha@1.0.0.json" \
  '._meta["io.modelcontextprotocol.registry/official"].status = "deleted" | ._meta["io.modelcontextprotocol.registry/official"].updatedAt = $u' \
  --arg u "$NOW"
remote_sync "$REMOTE"
_alpha_100_hidden() {
  ! served_pairs "$REMOTE" anon | grep -qxF "${NS}/alpha@1.0.0"
}
if ! served_has "$REMOTE" "${NS}/alpha@1.1.0" anon; then
  fail "approved alpha 1.1.0 is not served (prerequisite)"
elif wait_until "alpha 1.0.0 leaves the listing" "$SYNC_WAIT_SECS" _alpha_100_hidden; then
  mcp_get "$REMOTE" "$(mcp_version_path "${NS}/alpha" 1.0.0)" anon
  if ! why=$(mcp_check_plain_404); then
    fail "exact read of the deleted version: ${why}"
  else
    mcp_get "$REMOTE" "$(mcp_version_path "${NS}/alpha" 1.0.0)?include_deleted=true" anon
    st=$(mcp_json '._meta["io.modelcontextprotocol.registry/official"].status')
    if [ "$MCP_STATUS" = "200" ] && [ "$st" = "deleted" ]; then
      pass
    else
      fail "include_deleted=true answered ${MCP_STATUS} status '${st}', expected 200 deleted: $(mcp_snip)"
    fi
  fi
else
  fail "upstream deletion of alpha 1.0.0 did not mirror"
fi

end_suite
