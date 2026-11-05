#!/usr/bin/env bash
# test-mcp-age-gate.sh - an age-gated backing package holds the MCP server
# version (artifact-keeper#5253, issue 4.4 row "backing package age-gated").
#
# services/mcp_packages.rs evaluates a Remote backing repository's age gate
# for every pin without an upstream call, so the hold itself is Phase 1 code.
# Getting a Remote-backed pin in the first place is not, on a Phase 1
# backend: issue 4.2 says a Remote backing repo needs the package "pulled
# through AK already", but proxy-cached objects never get an `artifacts` row
# (#1278/#1280: they live in proxy_cache_artifacts), and the own-repos lookup
# reads `artifacts`, so a real pull-through still answers 422
# mcp_package_not_found. Phase 2 (docs/mcp-registry.md "Packages in a Remote
# backing repository") finds the package in the Remote's proxy cache and
# pins its cache path and sha256, or fills it (202, hold resolving) when it
# is not cached yet. The suite therefore runs the documented flow:
#
#   1. a mock npm upstream (tests/lib/mock-upstream.py) serves
#      @ak-age/echo-<run>@1.0.0 (the zero-dependency echo server)
#   2. an npm Remote over it; the tarball is pulled through AK (now in the
#      Remote's proxy cache, which has no `artifacts` row)
#   3. a Local mcp repository maps npm to that Remote and publishes a server
#      naming the package: 200, served
#   4. the Remote's age gate is turned on (7 days, upstream_publish_time):
#      the cached copy is 0 days old, so the version is held:
#        - listing and latest omit it for every caller
#        - a reader (anonymous on the public repo) gets the plain 404,
#          byte-identical to an unknown name
#        - the admin gets 404 mcp_age_gate_blocked with gate age_gate,
#          review_id, min_age_days 7, requested_age_days 0, and no backing
#          repository key
#   5. approving the age-gate review (POST /api/v1/admin/age-gate/reviews/
#      {id}/approve) restores the version for everyone
#
# Gates: mcp_require_registry mcp_registry_proxy; then the behaviour probe:
# the publish naming the VERIFIED pulled-through package. 422
# mcp_package_not_found there is the Phase 1 answer (no Remote fill) ->
# mcp_skip_later_phase. 200 (resolved) or 202 (resolving, then served) runs
# the assertions. The age-gate API itself is not MCP specific.
#
# Requires: curl, jq, tar, openssl, python3, MOCK_UPSTREAM_HOSTNAME.

# shellcheck source=../lib/common.sh disable=SC1091
source "$(dirname "$0")/../lib/common.sh"
# shellcheck source=../lib/mcp-helpers.sh disable=SC1091
source "$(dirname "$0")/../lib/mcp-helpers.sh"

begin_suite "mcp-age-gate"
auth_admin
setup_workdir
require_cmd curl
require_cmd jq
require_cmd tar
require_cmd openssl
require_cmd python3
mcp_require_registry mcp_registry_proxy
mcp_require_dialback

MIN_AGE_DAYS=7
SCOPE="@ak-age"
SHORT="echo-${RUN_ID}"
PKG="${SCOPE}/${SHORT}"
PKG_ENC="${SCOPE}%2F${SHORT}"
VER="1.0.0"
TGZ_NAME="${SHORT}-${VER}.tgz"
MCP_REPO="mcp-age-${RUN_ID}"
NPM_REMOTE="mcp-age-npm-remote-${RUN_ID}"
SERVER="io.github.ak-age/echo-${RUN_ID}"
SERVER_DETAIL="$(mcp_version_path "$SERVER" "$VER")"

served_has() {
  mcp_get "$1" "servers?limit=100" "${3:-anon}"
  [ "$MCP_STATUS" = "200" ] && mcp_json '.servers[] | "\(.server.name)@\(.server.version)"' | grep -qxF "$2"
}

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

begin_test "Setup: mock npm upstream serving ${PKG}@${VER}"
if ! start_mock_upstream "${WORK_DIR}/npm-upstream"; then
  infra_fail "mock-upstream did not start" "$(head -c 400 "${WORK_DIR}/mock.err" 2>/dev/null)"
  end_suite
fi
NPM_STATE="$MOCK_STATE_DIR"
mcp_render_echo_package "${WORK_DIR}/pkg" "$PKG" "$VER" "$SERVER"
mkdir -p "${NPM_STATE}/files/${PKG}/-"
tar -czf "${NPM_STATE}/files/${PKG}/-/${TGZ_NAME}" -C "${WORK_DIR}/pkg" package
TGZ="${NPM_STATE}/files/${PKG}/-/${TGZ_NAME}"
jq -n --arg name "$PKG" --arg v "$VER" --arg url "${MOCK_BASE_URL}/${PKG}/-/${TGZ_NAME}" \
  --arg integrity "sha512-$(openssl dgst -sha512 -binary "$TGZ" | base64 | tr -d '\n')" \
  --arg shasum "$(openssl dgst -sha1 "$TGZ" | awk '{print $NF}')" \
  --slurpfile pj "${WORK_DIR}/pkg/package/package.json" \
  '{_id: $name, name: $name, "dist-tags": {latest: $v},
    versions: {($v): ($pj[0] + {dist: {tarball: $url, integrity: $integrity, shasum: $shasum}})},
    time: {created: "2026-01-01T00:00:00.000Z", ($v): "2026-01-01T00:00:00.000Z"}}' \
  > "${NPM_STATE}/files/${PKG_ENC}"
pass

begin_test "Setup: npm Remote over the mock; the tarball is pulled through AK"
if ! create_remote_repo "$NPM_REMOTE" npm "$MOCK_BASE_URL"; then
  fail_fatal "create npm Remote ${NPM_REMOTE}"
fi
mcp_delete_repo_on_exit "$NPM_REMOTE"
# The way npm installs: the packument through AK, then the tarball it names.
curl -s -o "${WORK_DIR}/packument.json" "${CURL_TIMEOUT_ARGS[@]}" -H "$(format_auth_header)" \
  "${BASE_URL}/npm/${NPM_REMOTE}/${PKG_ENC}" 2>/dev/null || true
tarball_url=$(jq -r --arg v "$VER" '.versions[$v].dist.tarball // empty' "${WORK_DIR}/packument.json" 2>/dev/null)
[ -n "$tarball_url" ] || tarball_url="${BASE_URL}/npm/${NPM_REMOTE}/${PKG}/-/${TGZ_NAME}"
code=$(curl -s -o "${WORK_DIR}/pulled.tgz" -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" -H "$(format_auth_header)" \
  "${BASE_URL}$(mcp_url_path "$tarball_url")" 2>/dev/null) || code="000"
# A pull-through lands in the Remote's proxy cache, not as an artifact row,
# so there is nothing to poll for: the publish below finds the cache entry.
if [ "$code" != "200" ] || ! cmp -s "${WORK_DIR}/pulled.tgz" "$TGZ"; then
  fail_fatal "pull-through of ${PKG}@${VER} answered ${code} (or different bytes)" "$(head -n 5 "${NPM_STATE}/request-log.txt" 2>/dev/null)"
else
  pass
fi

begin_test "Setup: Local mcp repository backed by the npm Remote; publish ${SERVER}@${VER}"
if ! mcp_create_repo "$MCP_REPO" "$(jq -cn --arg n "$NPM_REMOTE" '{mcp_package_repos:{npm:$n}}')"; then
  fail_fatal "create mcp repository" "$MCP_CREATE_ERROR"
fi
mcp_server_json "$SERVER" "$VER" "$(mcp_npm_package_json "$PKG" "$VER")" > "${WORK_DIR}/server.json"
mcp_publish "$MCP_REPO" "${WORK_DIR}/server.json"
if [ "$MCP_STATUS" = "422" ] && [ "$(mcp_json '.error')" = "mcp_package_not_found" ]; then
  mcp_skip_later_phase mcp_registry_proxy "publish naming ${PKG}@${VER}, verified pulled through npm Remote ${NPM_REMOTE}, answered 422 mcp_package_not_found (no Remote backing fill)"
fi
if [ "$MCP_STATUS" != "200" ] && [ "$MCP_STATUS" != "202" ]; then
  fail_fatal "publish naming the pulled-through package answered ${MCP_STATUS}" "$(mcp_snip)"
fi
served_base=$(mcp_json '.server.packages[0].registryBaseUrl')
case "$(mcp_url_path "$served_base")" in
  "/npm/${NPM_REMOTE}"|"/npm/${NPM_REMOTE}/") pass ;;
  *) fail "served registryBaseUrl '${served_base}' does not name /npm/${NPM_REMOTE}" ;;
esac

begin_test "Before the age gate: the version is served to anonymous"
_served_anon() {
  mcp_get "$MCP_REPO" "$SERVER_DETAIL" anon
  [ "$MCP_STATUS" = "200" ]
}
# A 202 (resolving) publish is served once the resolver pins the package.
wait_until "the version resolves" 60 _served_anon || true
mcp_get "$MCP_REPO" "$SERVER_DETAIL" anon
if [ "$MCP_STATUS" = "200" ] && served_has "$MCP_REPO" "${SERVER}@${VER}" anon; then
  pass
else
  fail_fatal "baseline read answered ${MCP_STATUS}: $(mcp_snip)"
fi

begin_test "Enable the age gate on the npm Remote (${MIN_AGE_DAYS} days)"
mcp_req PUT "${BASE_URL}/api/v1/repositories/${NPM_REMOTE}/age-gate" admin -H "Content-Type: application/json" \
  -d "{\"enabled\":true,\"min_age_days\":${MIN_AGE_DAYS},\"mode\":\"upstream_publish_time\"}"
if [ "${MCP_STATUS:0:1}" = "2" ]; then
  pass
else
  fail_fatal "PUT /api/v1/repositories/${NPM_REMOTE}/age-gate answered ${MCP_STATUS}" "$(mcp_snip)"
fi

# ---------------------------------------------------------------------------
# Held
# ---------------------------------------------------------------------------

begin_test "Held: listing and latest omit the version for every caller"
mcp_get "$MCP_REPO" "servers/$(mcp_encode_name "$SERVER")/versions/latest" anon
latest_anon="$MCP_STATUS"
mcp_get "$MCP_REPO" "servers/$(mcp_encode_name "$SERVER")/versions" admin
versions_admin="$MCP_STATUS"
if served_has "$MCP_REPO" "${SERVER}@${VER}" anon || served_has "$MCP_REPO" "${SERVER}@${VER}" admin; then
  fail "an age-gated version is listed"
elif [ "$latest_anon" != "404" ] || [ "$versions_admin" != "404" ]; then
  fail "latest (anon) answered ${latest_anon}, versions (admin) ${versions_admin}; both want 404 with the only version held"
else
  pass
fi

begin_test "Held: a reader gets the plain 404, byte-identical to an unknown name"
mcp_get "$MCP_REPO" "$(mcp_version_path "io.github.ak-age/no-such-${RUN_ID}" "$VER")" anon
unknown_hdrs=$(mcp_stable_headers "$MCP_HDRS")
mcp_get "$MCP_REPO" "$SERVER_DETAIL" anon
if why=$(mcp_check_plain_404); then
  if [ "$(mcp_stable_headers "$MCP_HDRS")" = "$unknown_hdrs" ]; then
    pass
  else
    fail "held answer headers differ from the unknown-name answer" "$(diff <(echo "$unknown_hdrs") <(mcp_stable_headers "$MCP_HDRS"))"
  fi
else
  fail "$why"
fi

begin_test "Held: the admin gets 404 mcp_age_gate_blocked with review_id, min_age_days, requested_age_days"
mcp_get "$MCP_REPO" "$SERVER_DETAIL" admin
REVIEW_ID=""
if why=$(mcp_check_problem 404 mcp_age_gate_blocked); then
  REVIEW_ID=$(mcp_json '.review_id // empty')
  min=$(mcp_json '.min_age_days')
  req=$(mcp_json '.requested_age_days')
  gate=$(mcp_json '.gate')
  if [ "$gate" != "age_gate" ] || [ "$min" != "$MIN_AGE_DAYS" ] || [ "$req" != "0" ]; then
    fail "reason body gate='${gate}' min_age_days='${min}' requested_age_days='${req}' (want age_gate/${MIN_AGE_DAYS}/0): $(mcp_snip)"
  elif [ -z "$REVIEW_ID" ]; then
    fail "reason body has no review_id to approve: $(mcp_snip)"
  elif grep -q "$NPM_REMOTE" "$MCP_BODY"; then
    fail "reason body discloses the backing repository key: $(mcp_snip)"
  elif [ "$(mcp_json '.name')" != "$SERVER" ] || [ "$(mcp_json '.version')" != "$VER" ]; then
    fail "reason body does not name ${SERVER}@${VER}: $(mcp_snip)"
  else
    pass
  fi
else
  fail "$why"
fi

# ---------------------------------------------------------------------------
# Approve the review
# ---------------------------------------------------------------------------

begin_test "Approving the age-gate review restores the version for everyone"
if [ -z "$REVIEW_ID" ]; then
  fail "no review_id from the previous test"
else
  mcp_req POST "${BASE_URL}/api/v1/admin/age-gate/reviews/${REVIEW_ID}/approve" admin -H "Content-Type: application/json" \
    -d '{"reason":"release-gate MCP age-gate approve"}'
  approve_status="$MCP_STATUS"
  _restored() {
    mcp_get "$MCP_REPO" "$SERVER_DETAIL" anon
    [ "$MCP_STATUS" = "200" ]
  }
  if [ "${approve_status:0:1}" != "2" ]; then
    fail "approve review ${REVIEW_ID} answered ${approve_status}: $(mcp_snip)"
  elif ! wait_until "the version is served again" 30 _restored; then
    fail "approved review did not restore the version (anonymous detail ${MCP_STATUS})"
  else
    mcp_get "$MCP_REPO" "servers/$(mcp_encode_name "$SERVER")/versions/latest" anon
    if [ "$(mcp_json '.server.version')" = "$VER" ] && served_has "$MCP_REPO" "${SERVER}@${VER}" anon; then
      pass
    else
      fail "restored version missing from latest/listing: $(mcp_snip)"
    fi
  fi
fi

end_suite
