#!/usr/bin/env bash
# test-mcp-upstream-sync-cursor.sh - MCP Remote sync pages the upstream
# registry correctly (artifact-keeper#5253 Phase 2, issue 3.4 and 4.1).
#
# The mock upstream caps every page at 3 entries whatever limit Artifact
# Keeper asks for, over the 14 fixture entries (8 names) in
# tests/fixtures/mcp/upstream/servers. The request log proves:
#   - the first sync walks every page: ceil(14/3) = 5 list requests, each
#     page after the first carrying the previous page's nextCursor, with
#     include_deleted forwarded (or updated_since, which implies it) so
#     upstream deletions are seen
#   - a second sync without upstream changes is one updated_since request
#     and no version document fetch (no amplification)
#   - a changed entry (bumped updatedAt, new description) is the only entry
#     the next sync picks up, and its curation row carries the new summary
#   - an upstream status change to deleted mirrors: the version leaves the
#     listing, its exact read is 404 and include_deleted=true shows it deleted
#
# Gates: mcp_require_registry mcp_registry_proxy; mcp_create_proxy_repo
# (older backends refuse Remote mcp repos -> mcp_registry_proxy exemption);
# then the behaviour probe: after POST /api/v1/curation/repos/{key}/sync a
# backend that ships the Remote asks the mock for /servers or records
# curation rows. Neither -> mcp_skip_later_phase mcp_registry_proxy.
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

# --- Contract names not pinned by the docs yet (guesses) -------------------
# Manual sync trigger (task brief; phase23 stream A reuses the curation route).
CURATION_SYNC_PATH="/api/v1/curation/repos/%s/sync"
CURATION_LIST_PATH="/api/v1/curation/packages"
CURATION_NAME_LEVEL_VERSION="*"
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

cur_load() {
  curl -s "${CURL_TIMEOUT_ARGS[@]}" -H "$(auth_header)" \
    "${BASE_URL}${CURATION_LIST_PATH}?staging_repo_id=${REMOTE_ID}&limit=500" -o "$CUR_ROWS" 2>/dev/null || echo '[]' > "$CUR_ROWS"
  jq -e 'type == "array"' "$CUR_ROWS" >/dev/null 2>&1 || echo '[]' > "$CUR_ROWS"
}

cur_row() {
  jq -c --arg n "$1" --arg v "$CURATION_NAME_LEVEL_VERSION" \
    '[.[] | select(.package_name == $n)] | ((map(select(.version == $v))[0]) // .[0]) // empty' "$CUR_ROWS" 2>/dev/null || true
}

cur_names() {
  jq -r '[.[].package_name] | unique | .[]' "$CUR_ROWS" 2>/dev/null || true
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
  mcp_req POST "${BASE_URL}/api/v1/curation/packages/${id}/approve" admin -H "Content-Type: application/json" -d '{}'
  [ "${MCP_STATUS:0:1}" = "2" ]
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
  # shellcheck disable=SC2059
  mcp_req POST "${BASE_URL}$(printf "$CURATION_SYNC_PATH" "$REMOTE")" admin -H "Content-Type: application/json" -d '{}'
  SYNC_STATUS="$MCP_STATUS"
  sleep 1
  wait_for_counter_stable "${MCP_MOCK_STATE_DIR}/request-count" 60 3 >/dev/null || true
}

query_param() {
  python3 -c '
import sys, urllib.parse
q = urllib.parse.parse_qs(urllib.parse.urlsplit(sys.argv[1]).query, keep_blank_values=True)
print(q.get(sys.argv[2], [""])[-1])
' "$1" "$2"
}

# expected_cursors: the nextCursor values the mock hands out walking the
# whole catalog at PAGE_SIZE (include_deleted), in order.
expected_cursors() {
  local cursor="" url
  while :; do
    url="${MCP_MOCK_LOCAL_URL}/v0.1/servers?limit=100&include_deleted=true"
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
FIXTURE_NAMES=$(jq -r '.server.name' "${MCP_MOCK_STATE_DIR}"/servers/*.json | sort -u | wc -l | tr -d ' ')
EXPECTED_PAGES=$(( (FIXTURE_COUNT + PAGE_SIZE - 1) / PAGE_SIZE ))
mapfile -t EXPECTED_CURSORS < <(expected_cursors)
if [ "$FIXTURE_COUNT" != "14" ] || [ "${#EXPECTED_CURSORS[@]}" != "$(( EXPECTED_PAGES - 1 ))" ]; then
  infra_fail "fixture catalog drifted: ${FIXTURE_COUNT} entries, ${#EXPECTED_CURSORS[@]} cursors at page size ${PAGE_SIZE}"
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
# shellcheck disable=SC2059
mcp_req POST "${BASE_URL}$(printf "$CURATION_SYNC_PATH" "$REMOTE")" admin -H "Content-Type: application/json" -d '{}'
SYNC_STATUS="$MCP_STATUS"
if ! wait_until "the Remote syncs from the mock" "$PROBE_WINDOW_SECS" _probe_contacted; then
  mcp_skip_later_phase mcp_registry_proxy "Remote ${REMOTE} over the mock upstream: POST $(printf "$CURATION_SYNC_PATH" "$REMOTE") answered ${SYNC_STATUS}, the mock saw no /servers request and GET ${CURATION_LIST_PATH}?staging_repo_id=<remote> listed no rows within ${PROBE_WINDOW_SECS}s"
fi
wait_until "every fixture name recorded" "$SYNC_WAIT_SECS" cur_has_names "$FIXTURE_NAMES" || true
wait_for_counter_stable "${MCP_MOCK_STATE_DIR}/request-count" 60 3 >/dev/null || true

# ---------------------------------------------------------------------------
# First sync: every page
# ---------------------------------------------------------------------------

FIRST=$(requests_since "$FIRST_SYNC_START" | list_requests)

begin_test "First sync walks every page (${EXPECTED_PAGES} list requests at page size ${PAGE_SIZE})"
# A creation-time sync plus the manual one may both have run: count the
# pages of one complete walk (the first request without a cursor up to the
# last cursor) rather than all requests.
walk=$(printf '%s\n' "$FIRST" | awk '/cursor=/{print; next} {if (seen) exit; seen=1; print}')
pages=$(printf '%s\n' "$walk" | grep -c . || true)
if [ "$pages" = "$EXPECTED_PAGES" ]; then
  pass
else
  fail "one sync made ${pages} list request(s), expected ${EXPECTED_PAGES}" "$FIRST"
fi

begin_test "Each page after the first carries the previous page's nextCursor"
got=()
while read -r _ts _m path; do
  [ -n "${path:-}" ] || continue
  c=$(query_param "$path" cursor)
  [ -n "$c" ] && got+=("$c")
done <<< "$walk"
if [ "${got[*]}" = "${EXPECTED_CURSORS[*]}" ]; then
  pass
else
  fail "cursor sequence differs" "expected: ${EXPECTED_CURSORS[*]}
got:      ${got[*]}"
fi

begin_test "Sync asks for deleted entries too (include_deleted=true or updated_since)"
missing=0
while read -r _ts _m path; do
  [ -n "${path:-}" ] || continue
  if [ "$(query_param "$path" include_deleted)" != "true" ] && [ -z "$(query_param "$path" updated_since)" ]; then
    missing=$(( missing + 1 ))
  fi
done <<< "$walk"
if [ "$missing" = "0" ]; then
  pass
else
  fail "${missing} page request(s) would miss upstream deletions" "$walk"
fi

begin_test "Every upstream name has a curation row after the first sync"
cur_load
if [ "$(cur_names | wc -l | tr -d ' ')" = "$FIXTURE_NAMES" ]; then
  pass
else
  fail "curation rows for $(cur_names | wc -l | tr -d ' ') of ${FIXTURE_NAMES} names" "$(cur_names)"
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
NEW_DESC="Alpha fixture server, revised ${RUN_ID}"
NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
fixture_set "io.github.ak-fixture__bravo@0.9.0.json" \
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
elif [ "$picked" != "${NS}/bravo@0.9.0" ]; then
  fail "the sync's updated_since (${since_val}) selects '${picked}', expected only ${NS}/bravo@0.9.0"
elif [ -n "$others" ]; then
  fail "the sync fetched version documents of unchanged names" "$others"
elif ! wait_until "bravo's curation row carries the new summary" 30 cur_row_mentions "${NS}/bravo" "$NEW_DESC"; then
  fail "bravo's curation row does not reflect the changed upstream entry" "$(cur_row "${NS}/bravo" | head -c 600)"
else
  pass
fi

# ---------------------------------------------------------------------------
# Deleted status mirrors
# ---------------------------------------------------------------------------

begin_test "An upstream status change to deleted mirrors on the next sync"
NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
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
