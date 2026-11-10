#!/usr/bin/env bash
# test-mcp-tombstone.sh - a name@version can never come back with other bytes
# (artifact-keeper#5253, issue 4.2 409 rule; Phase 2 "Tombstone for purged
# name@version"; Phase 3 DELETE .../versions/{version}).
#
# A client that pinned io.example/x@1.0.0 must never get a different recipe
# under the same coordinate. Phase 1 already guarantees this while the
# deleted server.json sits in the artifact trash (the soft-deleted row keeps
# the path: 409 mcp_version_exists). It does NOT after a trash purge: the
# Phase 1 backend accepts a republish with different bytes then. Phase 2 adds
# a tombstone that survives the purge; Phase 3 adds DELETE
# .../versions/{version} (status deleted + tombstone).
#
#   Base assertions: soft-delete the version through the registry route
#   (DELETE .../versions/{version}; the generic artifact DELETE answers 400 on
#   an MCP repository since artifact-keeper#5257) -> hidden; republish
#   different bytes -> 409 mcp_version_exists; purge it with the admin
#   POST .../versions/{version}/purge (#5368), which trashes the server.json.
#   mcp_tombstone (gated): republish different bytes after the purge -> 409.
#   Phase 3 DELETE route (gated): soft delete, include_deleted shows it
#   deleted, republish -> 409; the server health roll-up
#   (GET /api/v1/repositories/{key}/mcp/servers/{name}/versions/{v}/health)
#   of the soft-deleted version is 404 unless include_deleted=true (anything
#   but true/false there is 400).
#
# Gates. The suite runs on mcp_registry. The two later-phase parts skip per
# test (the suite has Phase 1 passes, so this is not an all-skipped suite):
#   - tombstone: the discriminating answer is the republish itself (200 =
#     no tombstone). Because a broken tombstone answers the same way, a 200
#     only counts as "not shipped" when the routes that ship with it in the
#     same stream (POST /validate, DELETE .../versions/{v}) are also absent
#     (mcp_probe_route router fallback); otherwise it is a failure.
#   - DELETE: mcp_probe_route on a throwaway version.
#
# Requires: curl, jq.

# shellcheck source=../lib/common.sh disable=SC1091
source "$(dirname "$0")/../lib/common.sh"
# shellcheck source=../lib/mcp-helpers.sh disable=SC1091
source "$(dirname "$0")/../lib/mcp-helpers.sh"

begin_suite "mcp-tombstone"
auth_admin
setup_workdir
require_cmd curl
require_cmd jq
mcp_require_registry

LATER_PREFIX="MCP Registry later-phase capability not shipped by this backend"
REPO="mcp-tombstone-${RUN_ID}"
NAME="io.github.ak-tomb/server-${RUN_ID}"
REMOTE_A="https://original.example.invalid/mcp"
REMOTE_B="https://replacement.example.invalid/mcp"

doc() {
  # doc VERSION REMOTE_URL DESCRIPTION OUT
  mcp_server_json "$NAME" "$1" "" "$(mcp_remote_json "$2")" "$3" > "$4"
}

art_path() {
  printf 'servers/%s/%s/server.json' "$NAME" "$1"
}

# ---------------------------------------------------------------------------
# Phase 1
# ---------------------------------------------------------------------------

begin_test "Setup: publish ${NAME}@1.0.0"
if ! mcp_create_repo "$REPO"; then
  fail_fatal "create mcp repository" "$MCP_CREATE_ERROR"
fi
doc 1.0.0 "$REMOTE_A" "Original recipe" "${WORK_DIR}/a.json"
doc 1.0.0 "$REMOTE_B" "Replacement recipe" "${WORK_DIR}/b.json"
mcp_publish "$REPO" "${WORK_DIR}/a.json"
[ "$MCP_STATUS" = "200" ] || fail_fatal "publish answered ${MCP_STATUS}" "$(mcp_snip)"
ART_ID=$(mcp_artifact_id "$REPO" "^$(art_path 1.0.0)$")
[ -n "$ART_ID" ] || fail_fatal "no artifact row for ${NAME}@1.0.0"
pass

begin_test "Delete the version through DELETE .../versions/{version}: the version is hidden"
# The generic artifact DELETE refuses MCP repositories (400, admins included;
# docs/mcp-registry.md "DELETE .../versions/{version}"): a server version is
# deleted only through the registry route.
mcp_req DELETE "$(mcp_base "$REPO")/$(mcp_version_path "$NAME" 1.0.0)" admin
del_status="$MCP_STATUS"
del_state=$(mcp_json '._meta["io.modelcontextprotocol.registry/official"].status // empty')
mcp_get "$REPO" "$(mcp_version_path "$NAME" 1.0.0)" anon
if [ "$del_status" != "200" ] || [ "$del_state" != "deleted" ]; then
  fail "version DELETE answered ${del_status} status '${del_state}', want 200 with status deleted"
elif why=$(mcp_check_plain_404); then
  pass
else
  fail "deleted version still answered: ${why}"
fi

begin_test "Republish different bytes over the soft-deleted version: 409 mcp_version_exists"
mcp_publish "$REPO" "${WORK_DIR}/b.json"
if why=$(mcp_check_problem 409 mcp_version_exists); then
  pass
else
  fail "$why"
fi

begin_test "Purge the soft-deleted version (POST .../versions/{version}/purge)"
mcp_req POST "$(mcp_base "$REPO")/$(mcp_version_path "$NAME" 1.0.0)/purge" admin
if [ "$MCP_STATUS" = "200" ] && [ "$(mcp_json '.purged')" = "true" ] \
  && jq -e --arg p "$(art_path 1.0.0)" '.trashed | index($p) != null' "$MCP_BODY" >/dev/null 2>&1; then
  pass
else
  fail_fatal "purge answered ${MCP_STATUS} (want 200, purged true, trashed naming $(art_path 1.0.0))" "$(mcp_snip)"
fi

# ---------------------------------------------------------------------------
# Later phases: route probes first (they decide what a 200 below means)
# ---------------------------------------------------------------------------

VALIDATE_MOUNTED=0
mcp_server_json "${NAME}-probe" 1.0.0 "" "$(mcp_remote_json "$REMOTE_A")" > "${WORK_DIR}/probe.json"
if mcp_probe_route POST "$(mcp_base "$REPO")/validate" "$(cat "${WORK_DIR}/probe.json")"; then
  VALIDATE_MOUNTED=1
fi
VALIDATE_PROBE="POST .../validate answered ${MCP_STATUS}"
DELETE_MOUNTED=0
doc 9.9.9 "$REMOTE_A" "Throwaway for the DELETE probe" "${WORK_DIR}/throwaway.json"
mcp_publish "$REPO" "${WORK_DIR}/throwaway.json"
if [ "$MCP_STATUS" = "200" ] && mcp_probe_route DELETE "$(mcp_base "$REPO")/$(mcp_version_path "$NAME" 9.9.9)"; then
  DELETE_MOUNTED=1
fi
DELETE_PROBE="DELETE .../versions/9.9.9 answered ${MCP_STATUS}"
# The soft delete answers 200 with the served entry, status deleted.
DELETE_ANSWER="${MCP_STATUS}:$(mcp_json '._meta["io.modelcontextprotocol.registry/official"].status // empty')"

begin_test "Tombstone: republish different bytes after the purge is still 409 mcp_version_exists"
if ! mcp_require_feature mcp_tombstone; then
  : # require_feature recorded the skip
else
  mcp_publish "$REPO" "${WORK_DIR}/b.json"
  if why=$(mcp_check_problem 409 mcp_version_exists); then
    pass
  elif [ "$MCP_STATUS" = "200" ] && [ "$VALIDATE_MOUNTED" = "0" ] && [ "$DELETE_MOUNTED" = "0" ]; then
    skip "${LATER_PREFIX} (probe: republish of a purged ${NAME}@1.0.0 with different bytes answered 200, and the routes that ship with the tombstone are absent: ${VALIDATE_PROBE}, ${DELETE_PROBE} with the router fallback); capability mcp_tombstone"
  else
    mcp_get "$REPO" "$(mcp_version_path "$NAME" 1.0.0)" anon
    fail "a purged name@version accepted different bytes: ${why}" "now served: $(mcp_snip)"
  fi
fi

begin_test "DELETE .../versions/{version}: soft delete, include_deleted shows it deleted, republish 409"
if [ "$DELETE_MOUNTED" != "1" ]; then
  skip "${LATER_PREFIX} (probe: ${DELETE_PROBE} with the router fallback); capability mcp_tombstone (Phase 3 DELETE)"
else
  # The probe already deleted 9.9.9; a second DELETE is 400 (already deleted).
  mcp_req DELETE "$(mcp_base "$REPO")/$(mcp_version_path "$NAME" 9.9.9)" admin
  again="$MCP_STATUS"
  mcp_get "$REPO" "$(mcp_version_path "$NAME" 9.9.9)" anon
  plain=$(mcp_check_plain_404) && plain=ok
  mcp_get "$REPO" "$(mcp_version_path "$NAME" 9.9.9)?include_deleted=true" anon
  widened="${MCP_STATUS}:$(mcp_json '._meta["io.modelcontextprotocol.registry/official"].status // empty')"
  doc 9.9.9 "$REMOTE_B" "Replacement after DELETE" "${WORK_DIR}/throwaway-b.json"
  mcp_publish "$REPO" "${WORK_DIR}/throwaway-b.json"
  repub=$(mcp_check_problem 409 mcp_version_exists) && repub=ok
  if [ "$DELETE_ANSWER" != "200:deleted" ]; then
    fail "DELETE answered ${DELETE_ANSWER}, want 200 with the served entry in status deleted"
  elif [ "$again" != "400" ]; then
    fail "a second DELETE of the deleted version answered ${again}, want 400"
  elif [ "$plain" != "ok" ]; then
    fail "deleted version still served: ${plain}"
  elif [ "$widened" != "200:deleted" ]; then
    fail "include_deleted=true answered ${widened}, want 200 status deleted"
  elif [ "$repub" != "ok" ]; then
    fail "republish after DELETE: ${repub}"
  else
    pass
  fi
fi

begin_test "Health of a soft-deleted version is 404 unless include_deleted=true"
if [ "$DELETE_MOUNTED" != "1" ]; then
  skip "${LATER_PREFIX} (probe: ${DELETE_PROBE} with the router fallback); capability mcp_tombstone (Phase 3 DELETE)"
else
  HEALTH_URL="${BASE_URL}/api/v1/repositories/${REPO}/mcp/$(mcp_version_path "$NAME" 9.9.9)/health"
  mcp_req GET "$HEALTH_URL" admin
  plain_h="$MCP_STATUS"
  mcp_req GET "${HEALTH_URL}?include_deleted=true" admin
  wide_h="${MCP_STATUS}:$(mcp_json '"\(.name)@\(.version)"')"
  mcp_req GET "${HEALTH_URL}?include_deleted=maybe" admin
  bad_h="$MCP_STATUS"
  if [ "$plain_h" != "404" ]; then
    fail "health of the soft-deleted ${NAME}@9.9.9 answered ${plain_h}, want 404"
  elif [ "$wide_h" != "200:${NAME}@9.9.9" ]; then
    fail "health with include_deleted=true answered '${wide_h}', want 200 for ${NAME}@9.9.9"
  elif [ "$bad_h" != "400" ]; then
    fail "health with include_deleted=maybe answered ${bad_h}, want 400"
  else
    pass
  fi
fi

end_suite
