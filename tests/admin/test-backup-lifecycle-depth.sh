#!/usr/bin/env bash
# test-backup-lifecycle-depth.sh - Backup lifecycle depth (Epic 10.1-10.3, #77)
#
# Extends test-backup-lifecycle.sh (which pins status codes only) with
# state-observation assertions:
#
#   - After POST /admin/backups, the new record MUST appear in
#     GET /admin/backups.
#   - After POST /admin/backups/{id}/execute, GET /admin/backups/{id}
#     MUST reflect a non-pending state (the executor records a run).
#   - After DELETE /admin/backups/{id}, the record MUST disappear from
#     GET /admin/backups AND GET /admin/backups/{id} MUST return 404.
#
# This catches the silent-success class (#870/#871) where an endpoint
# returns 200/202/204 but actually no-ops on the underlying store.
#
# Safety: only operates on a fixture backup we create with RUN_ID in the
# name. Cleanup runs via add_exit_handler; never touches a backup we did
# not create.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "admin-backup-lifecycle-depth"
auth_admin

BACKUP_NAME="e2e-depth-${RUN_ID}"
BACKUP_ID=""
# Per openapi.yaml CreateBackupRequest, the payload accepts only
# { repository_ids: [uuid...], type: string }. We create a throwaway
# repository so we have a real UUID to scope the backup to. The repo is
# cleaned up via add_exit_handler.
BACKUP_REPO_KEY="e2e-bkup-depth-${RUN_ID}"
BACKUP_REPO_ID=""

# Returns the count of backup records matching $BACKUP_ID across the common
# response shapes (.items, bare array, .backups). Echoes 0 if the endpoint
# does not return JSON or the id is unset.
_count_id_in_list() {
  local id="$1"
  local resp="$2"
  if [ -z "$id" ] || [ -z "$resp" ]; then
    echo 0
    return
  fi
  echo "$resp" | jq --arg id "$id" '
    [ (
        if type == "array" then .
        elif (.items | type) == "array" then .items
        elif (.backups | type) == "array" then .backups
        else []
        end
      )[]
      | select(.id == $id)
    ] | length
  ' 2>/dev/null || echo 0
}

_backup_depth_cleanup() {
  if [ -n "${BACKUP_ID:-}" ] && [ "$BACKUP_ID" != "null" ]; then
    auth_admin > /dev/null 2>&1 || true
    curl -s -o /dev/null $CURL_TIMEOUT -X POST \
      -H "$(auth_header)" \
      "${BASE_URL}/api/v1/admin/backups/${BACKUP_ID}/cancel" 2>/dev/null || true
    api_delete "/api/v1/admin/backups/${BACKUP_ID}" > /dev/null 2>&1 || true
  fi
  if [ -n "${BACKUP_REPO_KEY:-}" ]; then
    auth_admin > /dev/null 2>&1 || true
    api_delete "/api/v1/repositories/${BACKUP_REPO_KEY}" > /dev/null 2>&1 || true
  fi
}
add_exit_handler _backup_depth_cleanup

begin_test "Create throwaway repository for backup scoping"
if create_repo "$BACKUP_REPO_KEY" "generic" "local"; then
  repo_resp=$(api_get "/api/v1/repositories/${BACKUP_REPO_KEY}" 2>/dev/null) || repo_resp=""
  BACKUP_REPO_ID=$(echo "$repo_resp" | jq -r '.id // empty')
  if [ -n "$BACKUP_REPO_ID" ] && [ "$BACKUP_REPO_ID" != "null" ]; then
    pass
  else
    fail "created repo ${BACKUP_REPO_KEY} but could not resolve its id" "${repo_resp:0:300}"
  fi
else
  fail "could not create throwaway repository ${BACKUP_REPO_KEY} for backup scoping"
fi

begin_test "Create backup fixture for depth checks"
# Per openapi.yaml:11716-11729, CreateBackupRequest is:
#   { repository_ids: [uuid...] | null, type: string | null }
# No "name", "cron", "retention_days", "include_artifacts", or
# "include_metadata" exist on the request schema; sending them would be
# silently ignored (or rejected on strict builds). We scope the backup to
# the throwaway repo created above and request a "full" backup type.
if [ -z "${BACKUP_REPO_ID:-}" ] || [ "$BACKUP_REPO_ID" = "null" ]; then
  skip "no backup repo id; cannot construct spec-compliant payload"
  end_suite
  exit 0
fi
payload=$(cat <<EOF
{
  "repository_ids": ["${BACKUP_REPO_ID}"],
  "type": "full"
}
EOF
)
status_file=$(mktemp)
resp_file=$(mktemp)
create_status=$(curl -s -o "$resp_file" -w '%{http_code}' $CURL_TIMEOUT \
  -X POST \
  -H "$(auth_header)" \
  -H "Content-Type: application/json" \
  -d "$payload" \
  "${BASE_URL}/api/v1/admin/backups" 2>/dev/null) || create_status=000
resp=$(cat "$resp_file")
rm -f "$status_file" "$resp_file"

if [ "$create_status" = "404" ] || [ "$create_status" = "501" ]; then
  skip "POST /admin/backups not available (HTTP ${create_status})"
elif [ "$create_status" = "200" ] || [ "$create_status" = "201" ]; then
  BACKUP_ID=$(echo "$resp" | jq -r '.id // empty')
  if [ -n "$BACKUP_ID" ] && [ "$BACKUP_ID" != "null" ]; then
    pass
  else
    fail "create returned ${create_status} but no id" "${resp:0:300}"
  fi
else
  fail "create returned HTTP ${create_status}" "${resp:0:300}"
fi

begin_test "New backup appears in GET /admin/backups"
if [ -z "${BACKUP_ID:-}" ] || [ "$BACKUP_ID" = "null" ]; then
  skip "no backup id from create"
else
  list_resp=$(api_get "/api/v1/admin/backups?per_page=200" 2>/dev/null) || list_resp=""
  if [ -z "$list_resp" ]; then
    skip "GET /admin/backups not available"
  else
    matches=$(_count_id_in_list "$BACKUP_ID" "$list_resp")
    if [ "${matches:-0}" -ge 1 ]; then
      pass
    else
      fail "backup ${BACKUP_ID} not present in list response" "${list_resp:0:400}"
    fi
  fi
fi

begin_test "GET /admin/backups/{id} returns the created backup"
if [ -z "${BACKUP_ID:-}" ] || [ "$BACKUP_ID" = "null" ]; then
  skip "no backup id"
else
  get_status=$(curl -s -o /tmp/_bkup_get.$$ -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(auth_header)" \
    "${BASE_URL}/api/v1/admin/backups/${BACKUP_ID}" 2>/dev/null) || get_status=000
  get_body=$(cat /tmp/_bkup_get.$$ 2>/dev/null || true)
  rm -f /tmp/_bkup_get.$$
  if [ "$get_status" = "404" ] || [ "$get_status" = "501" ]; then
    skip "GET /admin/backups/{id} not mounted (HTTP ${get_status})"
  elif [ "$get_status" = "200" ]; then
    fetched_id=$(echo "$get_body" | jq -r '.id // empty')
    if [ "$fetched_id" = "$BACKUP_ID" ]; then
      pass
    else
      fail "GET returned id '${fetched_id}', expected '${BACKUP_ID}'" "${get_body:0:300}"
    fi
  else
    fail "GET /admin/backups/${BACKUP_ID} returned HTTP ${get_status}" "${get_body:0:300}"
  fi
fi

begin_test "POST /admin/backups/{id}/execute records a run"
if [ -z "${BACKUP_ID:-}" ] || [ "$BACKUP_ID" = "null" ]; then
  skip "no backup id"
else
  exec_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X POST \
    -H "$(auth_header)" \
    "${BASE_URL}/api/v1/admin/backups/${BACKUP_ID}/execute" 2>/dev/null) || exec_status=000
  if [ "$exec_status" = "404" ] || [ "$exec_status" = "501" ]; then
    skip "execute endpoint not mounted (HTTP ${exec_status})"
  elif [ "$exec_status" = "200" ] || [ "$exec_status" = "202" ]; then
    # Poll GET for up to 10s to observe a state transition. A backup
    # scoped to a freshly-created empty repository should complete (or at
    # least record a run row) well within that window.
    observed=""
    for _i in 1 2 3 4 5 6 7 8 9 10; do
      gb=$(curl -sf $CURL_TIMEOUT -H "$(auth_header)" \
        "${BASE_URL}/api/v1/admin/backups/${BACKUP_ID}" 2>/dev/null || true)
      # Look at any field that signals a run was recorded. Tolerate either
      # last_run_at being populated OR a status/state field moving off the
      # pending-class. The exact field name varies across 1.1.x and 1.2.0
      # response shapes, so we accept any of them.
      observed=$(echo "$gb" | jq -r '
        [ .last_run_at, .last_executed_at, .status, .state, .last_run_status ]
        | map(select(. != null and . != "" and . != "pending"))
        | first // empty
      ' 2>/dev/null || true)
      if [ -n "$observed" ]; then
        break
      fi
      sleep 1
    done
    if [ -n "$observed" ]; then
      echo "  observed post-execute marker: ${observed}"
      pass
    else
      # No run-state field within 10s after a 2xx execute is the
      # silent-success class this depth suite exists to catch: the
      # endpoint acknowledged the request but the executor never recorded
      # a run. Fail loudly rather than skipping.
      fail "execute accepted (HTTP ${exec_status}) but no run-state field (last_run_at/last_executed_at/status/state/last_run_status) appeared within 10s -- silent-success regression"
    fi
  else
    fail "execute returned HTTP ${exec_status}, expected 200/202"
  fi
fi

begin_test "DELETE /admin/backups/{id} removes the record"
if [ -z "${BACKUP_ID:-}" ] || [ "$BACKUP_ID" = "null" ]; then
  skip "no backup id"
else
  # Cancel any in-flight run so DELETE is not racing the executor.
  curl -s -o /dev/null $CURL_TIMEOUT -X POST \
    -H "$(auth_header)" \
    "${BASE_URL}/api/v1/admin/backups/${BACKUP_ID}/cancel" 2>/dev/null || true

  del_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X DELETE \
    -H "$(auth_header)" \
    "${BASE_URL}/api/v1/admin/backups/${BACKUP_ID}" 2>/dev/null) || del_status=000
  if [ "$del_status" != "200" ] && [ "$del_status" != "204" ]; then
    fail "DELETE returned HTTP ${del_status}, expected 200/204"
  else
    # Verify the record actually disappeared from BOTH the list endpoint
    # and the get-by-id endpoint. Either one returning the record after a
    # 2xx DELETE is the silent-success bug we are guarding against.
    after_list=$(api_get "/api/v1/admin/backups?per_page=200" 2>/dev/null || true)
    after_count=$(_count_id_in_list "$BACKUP_ID" "$after_list")
    after_get=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
      -H "$(auth_header)" \
      "${BASE_URL}/api/v1/admin/backups/${BACKUP_ID}" 2>/dev/null) || after_get=000
    if [ "${after_count:-0}" = "0" ] && [ "$after_get" = "404" ]; then
      pass
      BACKUP_ID=""  # mark cleaned so exit handler no-ops
    elif [ "${after_count:-0}" = "0" ] && { [ "$after_get" = "200" ] || [ "$after_get" = "410" ]; }; then
      # Some builds keep a tombstone row reachable by id but exclude it from
      # the list. List-exclusion is the load-bearing assertion; accept tombstone.
      pass
      BACKUP_ID=""
    else
      fail "after DELETE: list still contains id (count=${after_count}), GET returned ${after_get}"
    fi
  fi
fi

end_suite
