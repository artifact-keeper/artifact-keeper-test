#!/usr/bin/env bash
# test-mcp-remote.sh - MCP Registry Remote and Virtual repositories
# (artifact-keeper#5253 Phase 2, issue sections 3.3, 3.4, 4.4 and 8).
#
# A Remote `mcp` repository is "an allowlist that happens to be populated
# from the public registry, not a mirror of it": a sync pages the upstream
# /v0.1/servers, records one catalog row per server name (read through the
# management API, GET /api/v1/repositories/{key}/mcp/catalog), and /v0.1
# serves ONLY approved names whose versions pass the gates. Unapproved
# entries are browsable through the catalog API and the web UI only.
#
# Mock leg (tests/lib/mock-mcp-upstream.py over tests/fixtures/mcp/upstream):
#   - deny by default: nothing listed, nothing ingested; an exact read is
#     the plain unknown-name 404 for anonymous and the admin alike
#   - approve one name -> served with its versions; approval is name-level,
#     so a new upstream version flows after a sync without a new approval
#   - mcp_auto_approve_namespaces ["io.github.ak-fixture-other/*"] admits
#     that namespace and not io.github.ak-fixture/*; a bare namespace entry is
#     422 (the globs match the full server name)
#   - mcp_server_deny wins over an approval (404 mcp_rejected for the admin)
#   - upstream deleted version hidden, deprecated listed with its message.
#     The first sync asks include_deleted=true (proven in
#     test-mcp-upstream-sync-cursor.sh and test-mcp-mirror-sync.sh), so a
#     version already deleted upstream is recorded and stored deleted:
#     include_deleted=true answers 200 with status deleted
#   - the npm-backed entry is unresolvable (its package is in no backing repo)
#   - the oci-floating entry is never served unpinned; `hide` hides it
#   - reads never call upstream; a second sync without changes fetches no
#     version document again
#   - an ingested version's _meta["com.artifactkeeper.registry/source"] says
#     origin remote, kind upstream, upstreamUrl = the Remote's upstream_url,
#     upstreamVerified false (the mock is neither the official registry nor
#     an Artifact Keeper)
#   - publish and status changes on the Remote -> 405 mcp_read_only
#   - upstream 503: the listing keeps answering from what was synced
#     (assumption: 503 mcp_gate_unavailable is reserved for a gate that
#     cannot be EVALUATED, issue 4.4; an upstream outage is not a gate
#     failure, because /v0.1 serves stored rows and never calls upstream)
#
# Virtual leg: a Local mcp repository publishing io.github.ak-fixture/shared
# @9.0.0 plus the Remote as members: merged listing de-duplicated, hosted
# shadows remote on a name collision (shared shows only 9.0.0 and the mock
# sees no request for shared while the Virtual is read), a remote-only
# approved server resolves through the Virtual (its source block names the
# member and adds virtualRepository), a cursor walk at limit=3 is complete and
# non-overlapping, a malformed cursor is 400 mcp_invalid_query (the hosted
# answer), publish and status changes -> 405 mcp_read_only, POST /validate
# -> 501 mcp_not_implemented.
#
# Public leg (optional): AK_TEST_MCP_PUBLIC_UPSTREAM=1 also proxies
# registry.modelcontextprotocol.io and checks deny by default there.
#
# Capability gates, in order: mcp_require_registry mcp_registry_proxy (flag
# layer); mcp_create_proxy_repo (older backends refuse Remote mcp repos with
# the Phase 1 400 -> mcp_registry_proxy exemption); then a route and
# BEHAVIOUR probe: POST /api/v1/repositories/{key}/mcp/sync answering the
# router's 404/405 (management API not mounted), or a sync after which the
# mock saw no /servers request and the catalog lists no row within the probe
# window -> mcp_skip_later_phase mcp_registry_proxy.
#
# Requires: curl, jq, python3, MOCK_UPSTREAM_HOSTNAME (dial-back address).

# shellcheck source=../lib/common.sh disable=SC1091
source "$(dirname "$0")/../lib/common.sh"
# shellcheck source=../lib/mcp-helpers.sh disable=SC1091
source "$(dirname "$0")/../lib/mcp-helpers.sh"

begin_suite "mcp-remote"
auth_admin
setup_workdir
require_cmd curl
require_cmd jq
require_cmd python3
mcp_require_registry mcp_registry_proxy
mcp_require_dialback

# --- Contract (docs/mcp-registry.md "Remote repositories") ------------------
# Sync, catalog and decisions go through the management API helpers in
# mcp-helpers.sh (mcp_remote_sync, mcp_catalog_load, mcp_catalog_decide).
# Globs over the FULL server name approved on sync ("Repository settings").
AUTO_APPROVE_KEY="mcp_auto_approve_namespaces"
# How long the behaviour probe waits for the first sync to reach the mock.
PROBE_WINDOW_SECS="${MCP_REMOTE_PROBE_SECS:-45}"
# How long a sync is given to land (ingest, approval flow-through).
SYNC_WAIT_SECS="${MCP_REMOTE_SYNC_SECS:-90}"

NS="io.github.ak-fixture"
NS_OTHER="io.github.ak-fixture-other"
REMOTE="mcp-remote-${RUN_ID}"
LOCAL="mcp-remote-local-${RUN_ID}"
VIRTUAL="mcp-remote-virtual-${RUN_ID}"
CUR_ROWS="${WORK_DIR}/curation.json"
FIXTURE_NAMES=("${NS}/alpha" "${NS}/bravo" "${NS}/charlie" "${NS}/delta" "${NS}/npm-backed" "${NS}/oci-floating" "${NS}/shared" "${NS_OTHER}/echo")

# ---------------------------------------------------------------------------
# Local helpers
# ---------------------------------------------------------------------------

# served_pairs REPO [AUTH] [LIMIT]: walk /servers to the end, one
# "name@version" per line. Returns 1 when a page is not 200.
served_pairs() {
  local repo="$1" auth="${2:-admin}" limit="${3:-100}" cursor="" url pages=0
  while :; do
    url="$(mcp_base "$repo")/servers?limit=${limit}"
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

# served_lacks_name REPO NAME [AUTH]: the listing answers 200 and has no
# version of NAME.
served_lacks_name() {
  local p
  p=$(served_pairs "$1" "${3:-admin}") || return 1
  ! printf '%s\n' "$p" | grep -q "^${2}@"
}

# cur_load [KEY]: the Remote's catalog (a CatalogItem array) into CUR_ROWS.
cur_load() {
  mcp_catalog_load "${1:-$REMOTE}" "$CUR_ROWS" || true
}

# cur_field NAME FIELD: FIELD of NAME's catalog item (id, status, ...).
cur_field() {
  jq -r --arg n "$1" --arg f "$2" \
    'map(select(.name == $n))[0] | .[$f] // empty' "$CUR_ROWS" 2>/dev/null || true
}

cur_has_all_names() {
  cur_load
  local n
  for n in "${FIXTURE_NAMES[@]}"; do
    [ -n "$(cur_field "$n" id)" ] || return 1
  done
}

# cur_approve NAME [AUTH]: POST .../mcp/catalog/{id}/approve (the approval
# ingests the name before it answers).
cur_approve() {
  cur_load
  local id
  id=$(cur_field "$1" id)
  if [ -z "$id" ]; then
    MCP_STATUS="no-row"
    return 1
  fi
  mcp_catalog_decide "$REMOTE" "$id" approve "${2:-admin}"
}

# remote_sync KEY: one synchronous sync pass (POST .../mcp/sync), then wait
# until the mock has been quiet for 3 s.
remote_sync() {
  mcp_remote_sync "$1" admin || true
  SYNC_STATUS="$MCP_SYNC_STATUS"
  wait_for_counter_stable "${MCP_MOCK_STATE_DIR}/request-count" 60 3 >/dev/null || true
}

mock_list_requests() {
  local _n
  _n=$(grep -cE ' GET /v0(\.1)?/servers(\?|$)' "${MCP_MOCK_STATE_DIR}/request-log.txt" 2>/dev/null) || true
  echo "${_n:-0}"
}

mock_requests_matching() {
  local _n
  _n=$(grep -cE "$1" "${MCP_MOCK_STATE_DIR}/request-log.txt" 2>/dev/null) || true
  echo "${_n:-0}"
}

# fixture_write NAME VERSION STATUS UPDATED_AT DESCRIPTION: (re)write one
# upstream entry in the mock's catalog (the mock re-reads it per request).
fixture_write() {
  local name="$1" version="$2" status="$3" updated="$4" desc="$5" file
  file="${MCP_MOCK_STATE_DIR}/servers/${name//\//__}@${version}.json"
  jq -n --arg s "$MCP_SCHEMA_URL" --arg n "$name" --arg v "$version" --arg st "$status" \
    --arg u "$updated" --arg d "$desc" --arg url "https://${name##*/}.mcp.example.invalid/mcp" \
    '{"_meta":{"io.modelcontextprotocol.registry/official":{status:$st,publishedAt:$u,updatedAt:$u}},
      "server":{"$schema":$s,name:$n,description:$d,version:$v,remotes:[{type:"streamable-http",url:$url}]}}' > "$file"
}

now_utc() {
  date -u +%Y-%m-%dT%H:%M:%SZ
}

# admin_detail_error REPO NAME VERSION: the admin's .error on an exact read
# ("200" when it is served).
admin_detail_error() {
  mcp_get "$1" "$(mcp_version_path "$2" "$3")" admin
  if [ "$MCP_STATUS" = "200" ]; then
    echo "200"
  else
    mcp_json '.error // empty'
  fi
}

detail_not_pending() {
  local e
  e=$(admin_detail_error "$@")
  [ -n "$e" ] && [ "$e" != "mcp_pending_review" ]
}

# ---------------------------------------------------------------------------
# Setup and the behaviour probe
# ---------------------------------------------------------------------------

begin_test "Setup: mock upstream registry and the Remote over it"
if ! start_mock_mcp_upstream "${WORK_DIR}/mcp-upstream"; then
  infra_fail "mock-mcp-upstream did not start" "$(head -c 400 "${WORK_DIR}/mock-mcp-upstream.err" 2>/dev/null)"
  end_suite
fi
# Older backends stand the suite down here (mcp_registry_proxy exemption).
if ! mcp_create_proxy_repo "$REMOTE" remote "$MCP_MOCK_BASE_URL"; then
  fail_fatal "create Remote mcp repository" "$MCP_CREATE_ERROR"
fi
REMOTE_ID=$(mcp_repo_id "$REMOTE")
if [ -z "$REMOTE_ID" ]; then
  fail_fatal "Remote ${REMOTE} has no id"
fi
pass

_probe_contacted() {
  [ "$(mock_list_requests)" -gt 0 ] && return 0
  cur_load
  [ "$(jq 'length' "$CUR_ROWS" 2>/dev/null || echo 0)" -gt 0 ]
}
mcp_remote_sync "$REMOTE" admin || true
SYNC_STATUS="$MCP_SYNC_STATUS"
if ! mcp_remote_mounted; then
  mcp_skip_later_phase mcp_registry_proxy "POST /api/v1/repositories/${REMOTE}/mcp/sync on a Remote mcp repository answered ${SYNC_STATUS}: the Remote management API is not mounted"
fi
if ! wait_until "the Remote syncs from the mock" "$PROBE_WINDOW_SECS" _probe_contacted; then
  mcp_skip_later_phase mcp_registry_proxy "Remote ${REMOTE} over the mock upstream: POST /api/v1/repositories/${REMOTE}/mcp/sync answered ${SYNC_STATUS}, the mock saw no /servers request and GET /api/v1/repositories/${REMOTE}/mcp/catalog listed no rows within ${PROBE_WINDOW_SECS}s"
fi
wait_for_counter_stable "${MCP_MOCK_STATE_DIR}/request-count" 60 3 >/dev/null || true

begin_test "Setup: map npm on the Remote to an (empty) npm Local"
# The npm-backed upstream entry then names a package that is not in its
# backing repository, which makes it unresolvable at sync.
mcp_create_backing_repos "mcp-remote-${RUN_ID}" || fail_fatal "create the npm backing repository"
if mcp_patch_repo "$REMOTE" "$(jq -cn --arg n "$MCP_NPM_KEY" '{mcp_package_repos:{npm:$n}}')"; then
  pass
else
  fail "map npm to ${MCP_NPM_KEY} on the Remote" "HTTP ${MCP_STATUS}: $(mcp_snip)"
fi

# ---------------------------------------------------------------------------
# Mock leg
# ---------------------------------------------------------------------------

begin_test "Sync records one catalog row per upstream server name, none approved"
if wait_until "a curation row for every fixture name" "$SYNC_WAIT_SECS" cur_has_all_names; then
  bad=""
  for n in "${FIXTURE_NAMES[@]}"; do
    st=$(cur_field "$n" status)
    case "$st" in
      pending|review) ;;
      *) bad="${bad} ${n}=${st}" ;;
    esac
  done
  if [ -z "$bad" ]; then
    pass
  else
    fail "default posture approval_required must leave every row pending/review:${bad}"
  fi
else
  fail "catalog rows missing after sync (sync answered ${SYNC_STATUS})" "$(jq -c '[.[] | {name, status}]' "$CUR_ROWS" 2>/dev/null | head -c 800)"
fi

begin_test "Default posture is approval_required (echoed)"
posture=$(curl -s "${CURL_TIMEOUT_ARGS[@]}" -H "$(auth_header)" "${BASE_URL}/api/v1/repositories/${REMOTE}" | jq -r '.mcp_remote_posture // empty')
if [ "$posture" = "approval_required" ]; then
  pass
else
  fail "mcp_remote_posture echoed '${posture}', expected approval_required"
fi

begin_test "Deny by default: /servers lists nothing for anonymous or admin"
anon_pairs=$(served_pairs "$REMOTE" anon) || anon_pairs="HTTP-${MCP_STATUS}"
admin_pairs=$(served_pairs "$REMOTE" admin) || admin_pairs="HTTP-${MCP_STATUS}"
mcp_get "$REMOTE" "servers?search=alpha" anon
search_count=$(mcp_json '.servers | length')
if [ -z "$anon_pairs" ] && [ -z "$admin_pairs" ] && [ "$search_count" = "0" ]; then
  pass
else
  fail "unapproved upstream entries leaked into /v0.1/servers" "anon: ${anon_pairs}
admin: ${admin_pairs}
search=alpha count: ${search_count}"
fi

begin_test "Unapproved exact read: anonymous gets the plain 404, byte-identical to an unknown name"
mcp_get "$REMOTE" "$(mcp_version_path "${NS}/no-such-${RUN_ID}" 1.0.0)" anon
unknown_hdrs=$(mcp_stable_headers "$MCP_HDRS")
mcp_get "$REMOTE" "$(mcp_version_path "${NS}/alpha" 1.1.0)" anon
if why=$(mcp_check_plain_404); then
  if [ "$(mcp_stable_headers "$MCP_HDRS")" = "$unknown_hdrs" ]; then
    pass
  else
    fail "held answer headers differ from the unknown-name answer" "$(diff <(echo "$unknown_hdrs") <(mcp_stable_headers "$MCP_HDRS"))"
  fi
else
  fail "$why"
fi

# Under mcp_remote_mode=allowlist with approval_required (the defaults) the
# sync ingests approved names only ("Sync", step 2), so an unapproved name
# has a catalog row and no stored version. The hold table in "What a Remote
# serves" applies to stored rows; with nothing stored, a repository holder
# gets the same unknown-name 404 as anyone else (no reason body, no upstream
# URL).
begin_test "Unapproved exact read and latest: nothing is ingested, so the admin also gets the unknown-name 404"
mcp_get "$REMOTE" "$(mcp_version_path "${NS}/alpha" 1.1.0)" admin
if why=$(mcp_check_plain_404); then
  if grep -q "${MCP_MOCK_PORT}" "$MCP_BODY"; then
    fail "404 body discloses the upstream URL: $(mcp_snip)"
  else
    mcp_get "$REMOTE" "servers/$(mcp_encode_name "${NS}/alpha")/versions/latest" admin
    if why=$(mcp_check_plain_404); then
      pass
    else
      fail "admin latest of an unapproved name: ${why}"
    fi
  fi
else
  fail "admin exact read of an unapproved, never-ingested name: ${why}"
fi

begin_test "Approve one name: it is served with its upstream versions"
if cur_approve "${NS}/alpha"; then
  if wait_until "alpha 1.0.0 and 1.1.0 served" "$SYNC_WAIT_SECS" served_has "$REMOTE" "${NS}/alpha@1.1.0" anon \
    && served_has "$REMOTE" "${NS}/alpha@1.0.0" anon; then
    mcp_get "$REMOTE" "servers/$(mcp_encode_name "${NS}/alpha")/versions/latest" anon
    latest=$(mcp_json '.server.version')
    status=$(mcp_json '._meta["io.modelcontextprotocol.registry/official"].status')
    src=$(mcp_json '._meta["com.artifactkeeper.registry/source"] | "\(.repository)|\(.origin)|\(.kind)|\(.upstreamUrl)|\(.upstreamVerified)"')
    want_src="${REMOTE}|remote|upstream|${MCP_MOCK_BASE_URL}|false"
    if [ "$latest" != "1.1.0" ] || [ "$status" != "active" ]; then
      fail "alpha latest=${latest} status=${status}, expected 1.1.0 active: $(mcp_snip)"
    elif [ "$src" != "$want_src" ]; then
      fail "ingested alpha source block repository|origin|kind|upstreamUrl|upstreamVerified is '${src}', expected '${want_src}'"
    else
      pass
    fi
  else
    fail "approved alpha not served" "$(served_pairs "$REMOTE" anon | head -20)"
  fi
else
  fail "approve alpha answered ${MCP_STATUS}: $(mcp_snip)"
fi

begin_test "Name-level approval: a new upstream version flows after a sync"
fixture_write "${NS}/alpha" 1.2.0 active "$(now_utc)" "Alpha fixture server"
remote_sync "$REMOTE"
if wait_until "alpha 1.2.0 served" "$SYNC_WAIT_SECS" served_has "$REMOTE" "${NS}/alpha@1.2.0" anon; then
  mcp_get "$REMOTE" "servers/$(mcp_encode_name "${NS}/alpha")/versions/latest" anon
  if [ "$(mcp_json '.server.version')" = "1.2.0" ]; then
    pass
  else
    fail "latest did not move to 1.2.0: $(mcp_snip)"
  fi
else
  fail "new upstream version of an approved name did not flow (sync answered ${SYNC_STATUS})"
fi

begin_test "${AUTO_APPROVE_KEY}: a bare namespace is 422 (the globs match the full name)"
mcp_patch_repo "$REMOTE" "$(jq -cn --arg k "$AUTO_APPROVE_KEY" --arg g "$NS_OTHER" '{($k):[$g]}')" || true
bare_status="$MCP_STATUS"
echoed_globs=$(curl -s "${CURL_TIMEOUT_ARGS[@]}" -H "$(auth_header)" "${BASE_URL}/api/v1/repositories/${REMOTE}" | jq -c --arg k "$AUTO_APPROVE_KEY" '.[$k] // []')
if [ "$bare_status" = "422" ] && [ "$echoed_globs" = "[]" ]; then
  pass
else
  fail "PATCH ${AUTO_APPROVE_KEY}=[${NS_OTHER}] answered ${bare_status} (want 422); stored ${echoed_globs}"
fi

begin_test "Namespace auto-approve ${NS_OTHER}/* admits that namespace and not ${NS}/*"
if mcp_patch_repo "$REMOTE" "$(jq -cn --arg k "$AUTO_APPROVE_KEY" --arg g "${NS_OTHER}/*" '{($k):[$g]}')"; then
  remote_sync "$REMOTE"
  if wait_until "${NS_OTHER}/echo served" "$SYNC_WAIT_SECS" served_has "$REMOTE" "${NS_OTHER}/echo@1.1.0" anon; then
    leaked=$(served_pairs "$REMOTE" anon | grep -E "^${NS//./\\.}/(bravo|charlie|delta|shared|npm-backed|oci-floating)@" || true)
    cur_load
    if [ -n "$leaked" ]; then
      fail "a glob for ${NS_OTHER} approved names in ${NS}" "$leaked"
    elif [ "$(cur_field "${NS}/bravo" status)" = "approved" ]; then
      fail "${NS}/bravo was approved by the ${NS_OTHER} glob"
    else
      pass
    fi
  else
    fail "${NS_OTHER}/echo not served after auto-approve + sync" "$(served_pairs "$REMOTE" anon | head -20)"
  fi
else
  fail "PATCH ${AUTO_APPROVE_KEY} answered ${MCP_STATUS}: $(mcp_snip)"
fi

begin_test "Upstream deprecated version is listed with its message; deleted version is hidden"
cur_approve "${NS}/bravo" || true; cur_approve "${NS}/charlie" || true
if wait_until "bravo 1.0.0 and charlie 2.0.0 served" "$SYNC_WAIT_SECS" served_has "$REMOTE" "${NS}/bravo@1.0.0" anon \
  && served_has "$REMOTE" "${NS}/charlie@2.0.0" anon; then
  mcp_get "$REMOTE" "$(mcp_version_path "${NS}/bravo" 1.0.0)" anon
  b_status=$(mcp_json '._meta["io.modelcontextprotocol.registry/official"].status')
  b_msg=$(mcp_json '._meta["io.modelcontextprotocol.registry/official"].statusMessage // empty')
  in_list=$(served_pairs "$REMOTE" anon | grep -cxF "${NS}/charlie@2.1.0" || true)
  mcp_get "$REMOTE" "$(mcp_version_path "${NS}/charlie" 2.1.0)" anon
  plain=$(mcp_check_plain_404) && plain=ok
  mcp_get "$REMOTE" "servers/$(mcp_encode_name "${NS}/charlie")/versions/latest" anon
  c_latest=$(mcp_json '.server.version')
  mcp_get "$REMOTE" "$(mcp_version_path "${NS}/charlie" 2.1.0)?include_deleted=true" anon
  widened="$MCP_STATUS:$(mcp_json '._meta["io.modelcontextprotocol.registry/official"].status // empty')"
  if [ "$b_status" != "deprecated" ] || [ "$b_msg" != "use charlie" ]; then
    fail "bravo 1.0.0 status='${b_status}' message='${b_msg}', expected deprecated / 'use charlie'"
  elif [ "$in_list" != "0" ] || [ "$plain" != "ok" ]; then
    fail "deleted charlie 2.1.0 visible: listed=${in_list} exact=${plain}"
  elif [ "$c_latest" != "2.0.0" ]; then
    fail "charlie latest is '${c_latest}', expected 2.0.0 (deleted versions are never latest)"
  elif [ "$widened" != "200:deleted" ]; then
    fail "include_deleted=true on charlie 2.1.0 answered ${widened}, expected 200 status deleted (a version deleted upstream before the first sync is recorded)"
  else
    pass
  fi
else
  fail "approved bravo/charlie not served" "$(served_pairs "$REMOTE" anon | head -20)"
fi

begin_test "mcp_server_deny wins over an approval"
cur_approve "${NS}/delta" || true
if wait_until "delta 1.10.0 served" "$SYNC_WAIT_SECS" served_has "$REMOTE" "${NS}/delta@1.10.0" anon; then
  if mcp_patch_repo "$REMOTE" "$(jq -cn --arg g "${NS}/del*" '{mcp_server_deny:[$g]}')"; then
    if wait_until "delta hidden" 30 served_lacks_name "$REMOTE" "${NS}/delta" anon; then
      mcp_get "$REMOTE" "$(mcp_version_path "${NS}/delta" 1.10.0)" anon
      if ! why=$(mcp_check_plain_404); then
        fail "anonymous read of a denied name: ${why}"
      else
        mcp_get "$REMOTE" "$(mcp_version_path "${NS}/delta" 1.10.0)" admin
        if why=$(mcp_check_problem 404 mcp_rejected); then
          pass
        else
          fail "admin read of a denied, approved name: ${why}"
        fi
      fi
    else
      fail "deny glob ${NS}/del* did not hide approved delta"
    fi
  else
    fail "PATCH mcp_server_deny answered ${MCP_STATUS}: $(mcp_snip)"
  fi
else
  fail "approved delta not served"
fi

begin_test "Upstream npm-backed entry with its package in no backing repo is unresolvable and hidden"
cur_approve "${NS}/npm-backed" || true
remote_sync "$REMOTE"
if wait_until "npm-backed ingested" "$SYNC_WAIT_SECS" detail_not_pending "$REMOTE" "${NS}/npm-backed" 1.0.0; then
  err=$(admin_detail_error "$REMOTE" "${NS}/npm-backed" 1.0.0)
  if [ "$err" = "mcp_unresolvable" ] && served_lacks_name "$REMOTE" "${NS}/npm-backed" anon; then
    pass
  else
    fail "npm-backed: admin read error='${err}' (expected mcp_unresolvable), listed: $(served_pairs "$REMOTE" anon | grep -c npm-backed)"
  fi
else
  fail "npm-backed still pending after approval + sync"
fi

begin_test "Upstream OCI entry on a floating tag is never served unpinned; hide hides it"
cur_approve "${NS}/oci-floating" || true
remote_sync "$REMOTE"
if wait_until "oci-floating ingested" "$SYNC_WAIT_SECS" detail_not_pending "$REMOTE" "${NS}/oci-floating" 1.0.0; then
  mcp_get "$REMOTE" "$(mcp_version_path "${NS}/oci-floating" 1.0.0)" admin
  pin_ok=0
  if [ "$MCP_STATUS" = "200" ]; then
    ident=$(mcp_json '.server.packages[0].identifier')
    case "$ident" in
      *@sha256:*) pin_ok=1 ;;
    esac
  elif [ "$(mcp_json '.error')" = "mcp_unresolvable" ]; then
    # No OCI backing repo maps ghcr.io here, so pinning has nothing to pin to.
    pin_ok=1
  fi
  if [ "$pin_ok" != "1" ]; then
    fail "pin policy served the floating entry unpinned or with an unexpected refusal: HTTP ${MCP_STATUS} $(mcp_snip)"
  elif ! mcp_patch_repo "$REMOTE" '{"mcp_oci_floating_tag_policy":"hide"}'; then
    fail "PATCH mcp_oci_floating_tag_policy=hide answered ${MCP_STATUS}: $(mcp_snip)"
  else
    remote_sync "$REMOTE"
    mcp_get "$REMOTE" "$(mcp_version_path "${NS}/oci-floating" 1.0.0)" anon
    if why=$(mcp_check_plain_404) && served_lacks_name "$REMOTE" "${NS}/oci-floating" admin; then
      pass
    else
      fail "hide policy still serves oci-floating: ${why:-listed}"
    fi
  fi
else
  fail "oci-floating still pending after approval + sync"
fi

begin_test "Reads are answered from stored rows: the mock sees no request"
before=$(mcp_mock_count)
served_pairs "$REMOTE" anon >/dev/null
mcp_get "$REMOTE" "$(mcp_version_path "${NS}/alpha" 1.1.0)" anon
mcp_get "$REMOTE" "$(mcp_version_path "${NS}/alpha" 1.1.0)" anon
mcp_get "$REMOTE" "servers/$(mcp_encode_name "${NS}/alpha")/versions" anon
mcp_get "$REMOTE" "servers/$(mcp_encode_name "${NS}/alpha")/versions/latest" admin
after=$(mcp_mock_count)
if [ "$after" = "$before" ]; then
  pass
else
  fail "reads on the Remote made $(( after - before )) upstream request(s)" "$(tail -n $(( after - before )) "${MCP_MOCK_STATE_DIR}/request-log.txt")"
fi

begin_test "A second sync without upstream changes fetches no version document again"
ver_before=$(mock_requests_matching ' GET /v0(\.1)?/servers/.+/versions')
list_before=$(mock_list_requests)
remote_sync "$REMOTE"
ver_after=$(mock_requests_matching ' GET /v0(\.1)?/servers/.+/versions')
list_after=$(mock_list_requests)
if [ "$ver_after" = "$ver_before" ] && [ $(( list_after - list_before )) -le 1 ]; then
  pass
else
  fail "unchanged catalog re-fetched: $(( ver_after - ver_before )) version request(s), $(( list_after - list_before )) list page(s) (sync answered ${SYNC_STATUS})" \
    "$(tail -n 20 "${MCP_MOCK_STATE_DIR}/request-log.txt")"
fi

begin_test "Publish and status changes on a Remote are 405 mcp_read_only and never reach upstream"
mcp_server_json "${NS}/alpha" 9.9.9 "" "$(mcp_remote_json "https://alpha.mcp.example.invalid/mcp")" > "${WORK_DIR}/remote-publish.json"
before=$(mcp_mock_count)
mcp_publish "$REMOTE" "${WORK_DIR}/remote-publish.json"
pub_why=$(mcp_check_problem 405 mcp_read_only) || true
mcp_patch_status "$REMOTE" "${NS}/alpha" 1.2.0 deprecated "release-gate"
status_why=$(mcp_check_problem 405 mcp_read_only) || true
if [ -n "$pub_why" ] || [ -n "$status_why" ]; then
  fail "write on the Remote: publish ${pub_why:-ok}; status PATCH ${status_why:-ok}"
elif [ "$(mcp_mock_count)" != "$before" ]; then
  fail "a write to the Remote was forwarded upstream"
else
  pass
fi

begin_test "Upstream outage: the Remote keeps serving what it synced"
echo 503 > "${MCP_MOCK_STATE_DIR}/error-status"
remote_sync "$REMOTE"
mcp_get "$REMOTE" "$(mcp_version_path "${NS}/alpha" 1.2.0)" anon
detail_status="$MCP_STATUS"
pairs=$(served_pairs "$REMOTE" anon) || pairs="HTTP-${MCP_STATUS}"
rm -f "${MCP_MOCK_STATE_DIR}/error-status"
if [ "$detail_status" = "200" ] && printf '%s\n' "$pairs" | grep -qxF "${NS}/alpha@1.2.0"; then
  pass
else
  fail "upstream 503 broke stored serving: detail ${detail_status}, listing: $(printf '%s' "$pairs" | head -c 300)"
fi

# ---------------------------------------------------------------------------
# Virtual leg
# ---------------------------------------------------------------------------

begin_test "Virtual setup: Local member publishes ${NS}/shared@9.0.0; Remote serves shared"
if ! mcp_create_repo "$LOCAL"; then
  fail_fatal "create Local mcp repository" "$MCP_CREATE_ERROR"
fi
mcp_server_json "${NS}/shared" 9.0.0 "" "$(mcp_remote_json "https://shared.hosted.example.invalid/mcp")" "Shared name, hosted copy" > "${WORK_DIR}/shared.json"
mcp_publish "$LOCAL" "${WORK_DIR}/shared.json"
if [ "$MCP_STATUS" != "200" ]; then
  fail_fatal "publish shared@9.0.0 to ${LOCAL}" "HTTP ${MCP_STATUS}: $(mcp_snip)"
fi
cur_approve "${NS}/shared" || true
if wait_until "Remote serves shared 1.1.0" "$SYNC_WAIT_SECS" served_has "$REMOTE" "${NS}/shared@1.1.0" anon; then
  pass
else
  fail_fatal "Remote never served approved shared (needed to prove shadowing)"
fi

begin_test "Create the Virtual with the Local first and the Remote second"
if mcp_create_proxy_repo "$VIRTUAL" virtual "${LOCAL},${REMOTE}"; then
  pass
else
  fail_fatal "create Virtual mcp repository" "${MCP_CREATE_ERROR:-members HTTP ${MCP_STATUS}: $(mcp_snip)}"
fi

begin_test "Hosted shadows remote on a name collision; the mock is not asked for shared"
shared_before=$(mock_requests_matching 'shared')
mcp_get "$VIRTUAL" "servers/$(mcp_encode_name "${NS}/shared")/versions" anon
versions=$(mcp_json '[.servers[].server.version] | join(",")')
mcp_get "$VIRTUAL" "$(mcp_version_path "${NS}/shared" 1.1.0)" anon
remote_copy="$MCP_STATUS"
mcp_get "$VIRTUAL" "servers/$(mcp_encode_name "${NS}/shared")/versions/latest" anon
latest=$(mcp_json '.server.version')
listed=$(served_pairs "$VIRTUAL" anon | grep "^${NS}/shared@" | tr '\n' ' ')
shared_after=$(mock_requests_matching 'shared')
if [ "$versions" = "9.0.0" ] && [ "$remote_copy" = "404" ] && [ "$latest" = "9.0.0" ] \
  && [ "$listed" = "${NS}/shared@9.0.0 " ] && [ "$shared_after" = "$shared_before" ]; then
  pass
else
  fail "shadowing broken: versions=${versions} remote-copy-detail=${remote_copy} latest=${latest} listed='${listed}' mock shared requests +$(( shared_after - shared_before ))"
fi

begin_test "A remote-only approved server resolves through the Virtual"
mcp_get "$VIRTUAL" "$(mcp_version_path "${NS}/alpha" 1.2.0)" anon
st="$MCP_STATUS"
vsrc=$(mcp_json '._meta["com.artifactkeeper.registry/source"] | "\(.repository)|\(.virtualRepository)|\(.origin)"')
mcp_get "$VIRTUAL" "servers/$(mcp_encode_name "${NS}/alpha")/versions/latest" anon
if [ "$st" != "200" ] || [ "$(mcp_json '.server.version')" != "1.2.0" ]; then
  fail "alpha through the Virtual: exact ${st}, latest '$(mcp_json '.server.version')'"
elif [ "$vsrc" != "${REMOTE}|${VIRTUAL}|remote" ]; then
  fail "Virtual entry source block repository|virtualRepository|origin is '${vsrc}', expected '${REMOTE}|${VIRTUAL}|remote'"
else
  pass
fi

begin_test "Virtual listing is de-duplicated and equals hosted union first, then remote names not hosted"
local_pairs=$(served_pairs "$LOCAL" anon | sort)
remote_pairs=$(served_pairs "$REMOTE" anon | sort)
local_names=$(printf '%s\n' "$local_pairs" | sed 's/@.*//' | sort -u)
expected=$( { printf '%s\n' "$local_pairs"; printf '%s\n' "$remote_pairs" | grep -vF -f <(printf '%s\n' "$local_names" | sed '/^$/d; s/$/@/') || true; } | grep -v '^$' | sort)
virtual_all=$(served_pairs "$VIRTUAL" anon)
dups=$(printf '%s\n' "$virtual_all" | sort | uniq -d)
if [ -n "$dups" ]; then
  fail "duplicate (name, version) in the Virtual listing" "$dups"
elif [ "$(printf '%s\n' "$virtual_all" | sort)" != "$expected" ]; then
  fail "Virtual listing differs from the expected merge" "$(diff <(echo "$expected") <(printf '%s\n' "$virtual_all" | sort))"
else
  pass
fi

begin_test "Cursor walk at limit=3 is complete and non-overlapping"
walk=$(served_pairs "$VIRTUAL" anon 3)
walk_status="$?"
dups=$(printf '%s\n' "$walk" | sort | uniq -d)
if [ "$walk_status" != "0" ]; then
  fail "a page of the limit=3 walk failed"
elif [ -n "$dups" ]; then
  fail "pages overlap" "$dups"
elif [ "$(printf '%s\n' "$walk" | sort)" != "$expected" ]; then
  fail "limit=3 walk is incomplete" "$(diff <(echo "$expected") <(printf '%s\n' "$walk" | sort))"
else
  pass
fi

begin_test "A malformed Virtual cursor is 400 mcp_invalid_query, as on a hosted repository"
mcp_get "$VIRTUAL" "servers?cursor=not-a-cursor%21%21" anon
if why=$(mcp_check_problem 400 mcp_invalid_query); then
  pass
else
  fail "malformed Virtual cursor: ${why}"
fi

begin_test "Publish and status changes on a Virtual are 405 mcp_read_only"
mcp_server_json "${NS}/virtual-write-${RUN_ID}" 1.0.0 "" "$(mcp_remote_json "https://v.example.invalid/mcp")" > "${WORK_DIR}/virtual-publish.json"
mcp_publish "$VIRTUAL" "${WORK_DIR}/virtual-publish.json"
pub_why=$(mcp_check_problem 405 mcp_read_only) || true
mcp_patch_status "$VIRTUAL" "${NS}/shared" 9.0.0 deprecated "release-gate"
status_why=$(mcp_check_problem 405 mcp_read_only) || true
mcp_get "$LOCAL" "$(mcp_version_path "${NS}/virtual-write-${RUN_ID}" 1.0.0)" admin
landed="$MCP_STATUS"
mcp_get "$LOCAL" "$(mcp_version_path "${NS}/shared" 9.0.0)" anon
shared_status=$(mcp_json '._meta["io.modelcontextprotocol.registry/official"].status // empty')
if [ -n "$pub_why" ] || [ -n "$status_why" ]; then
  fail "write on the Virtual: publish ${pub_why:-ok}; status PATCH ${status_why:-ok}"
elif [ "$landed" != "404" ] || [ "$shared_status" != "active" ]; then
  fail "a Virtual write reached a member: published version HTTP ${landed}, shared 9.0.0 status '${shared_status}'"
else
  pass
fi

begin_test "POST /validate on a Virtual is 501 mcp_not_implemented"
mcp_req POST "$(mcp_base "$VIRTUAL")/validate" anon -H "Content-Type: application/json" --data-binary "@${WORK_DIR}/virtual-publish.json"
if why=$(mcp_check_problem 501 mcp_not_implemented); then
  pass
else
  fail "Virtual validate: ${why}"
fi

# ---------------------------------------------------------------------------
# Public leg (optional)
# ---------------------------------------------------------------------------

begin_test "Public upstream: registry.modelcontextprotocol.io is deny by default"
if [ "${AK_TEST_MCP_PUBLIC_UPSTREAM:-0}" != "1" ]; then
  skip "AK_TEST_MCP_PUBLIC_UPSTREAM not set; the public-registry leg is opt-in"
else
  PUBLIC="mcp-remote-public-${RUN_ID}"
  if mcp_create_proxy_repo "$PUBLIC" remote "https://registry.modelcontextprotocol.io"; then
    remote_sync "$PUBLIC"
    _public_rows() {
      mcp_req GET "$(mcp_mgmt_url "$PUBLIC" catalog)?limit=5" admin
      [ "$(mcp_json '.items | length')" -gt 0 ] 2>/dev/null
    }
    if wait_until "public catalog rows" 180 _public_rows; then
      if [ -z "$(served_pairs "$PUBLIC" anon 10)" ]; then
        pass
      else
        fail "the public Remote serves unapproved entries"
      fi
    else
      fail "no catalog rows from the public registry within 180s (sync answered ${SYNC_STATUS})"
    fi
  else
    fail "create public Remote: ${MCP_CREATE_ERROR}"
  fi
fi

end_suite
