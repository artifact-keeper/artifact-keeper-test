#!/usr/bin/env bash
# test-admin-settings.sh - Admin settings read/update round-trip (Epic 10.8, #77)
#
# GET  /api/v1/admin/settings  -> SystemSettings
# POST /api/v1/admin/settings  -> SystemSettings  (full-document update)
#
# Per openapi.yaml SystemSettings, the required fields are:
#   storage_backend, storage_path, allow_anonymous_download,
#   max_upload_size_bytes, retention_days, audit_retention_days,
#   backup_retention_count, edge_stale_threshold_minutes
#
# Test plan:
#   1. GET current settings, snapshot the whole document.
#   2. POST a copy with edge_stale_threshold_minutes bumped by a known
#      delta. This field is the safest knob to flip in a release-gate run:
#      it has no side effect on storage, auth, or retention; it only
#      affects the edge-staleness UI threshold.
#   3. GET again, verify the new value sticks.
#   4. POST the original document back. Verify it round-trips.
#
# Mutating storage_backend/storage_path/retention_days mid-test would
# destabilise other suites running in parallel, so we deliberately avoid
# those.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "admin-settings"
auth_admin

ORIGINAL_SETTINGS=""
ORIGINAL_THRESHOLD=""
NEW_THRESHOLD=""
SETTINGS_AVAILABLE=0

_restore_settings() {
  if [ "$SETTINGS_AVAILABLE" = "1" ] && [ -n "$ORIGINAL_SETTINGS" ]; then
    auth_admin > /dev/null 2>&1 || true
    curl -s -o /dev/null $CURL_TIMEOUT -X POST \
      -H "$(auth_header)" \
      -H "Content-Type: application/json" \
      -d "$ORIGINAL_SETTINGS" \
      "${BASE_URL}/api/v1/admin/settings" 2>/dev/null || true
  fi
}
add_exit_handler _restore_settings

begin_test "GET /admin/settings returns SystemSettings document"
tmp=$(mktemp)
status=$(curl -s -o "$tmp" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/admin/settings" 2>/dev/null) || status=000
ORIGINAL_SETTINGS=$(cat "$tmp")
rm -f "$tmp"

if [ "$status" = "404" ] || [ "$status" = "501" ]; then
  skip "GET /admin/settings not mounted (HTTP ${status})"
elif [ "$status" = "200" ]; then
  # Validate the load-bearing field (edge_stale_threshold_minutes) is
  # present and integer-shaped. If GET ever stops returning it we cannot
  # round-trip the document via POST, so it is a real precondition.
  ORIGINAL_THRESHOLD=$(echo "$ORIGINAL_SETTINGS" | jq -r '.edge_stale_threshold_minutes // empty')
  if [ -n "$ORIGINAL_THRESHOLD" ] && [[ "$ORIGINAL_THRESHOLD" =~ ^[0-9]+$ ]]; then
    SETTINGS_AVAILABLE=1
    echo "  original edge_stale_threshold_minutes: ${ORIGINAL_THRESHOLD}"
    pass
  else
    fail "edge_stale_threshold_minutes is missing or not an int" "${ORIGINAL_SETTINGS:0:300}"
  fi
else
  fail "GET /admin/settings returned HTTP ${status}" "${ORIGINAL_SETTINGS:0:300}"
fi

begin_test "POST /admin/settings persists a changed value"
if [ "$SETTINGS_AVAILABLE" != "1" ]; then
  skip "GET did not yield a settings document"
else
  # Bump threshold by 1. Pick a delta that is harmless and easy to spot
  # in the GET-after-POST. Avoid 0 (could clash with default), avoid
  # large jumps (would mask off-by-one).
  NEW_THRESHOLD=$(( ORIGINAL_THRESHOLD + 1 ))
  MUTATED=$(echo "$ORIGINAL_SETTINGS" | jq --argjson v "$NEW_THRESHOLD" '.edge_stale_threshold_minutes = $v')

  tmp=$(mktemp)
  post_status=$(curl -s -o "$tmp" -w '%{http_code}' $CURL_TIMEOUT \
    -X POST \
    -H "$(auth_header)" \
    -H "Content-Type: application/json" \
    -d "$MUTATED" \
    "${BASE_URL}/api/v1/admin/settings" 2>/dev/null) || post_status=000
  post_body=$(cat "$tmp"); rm -f "$tmp"

  if [ "$post_status" = "200" ] || [ "$post_status" = "204" ]; then
    pass
  elif [ "$post_status" = "404" ] || [ "$post_status" = "501" ]; then
    skip "POST /admin/settings not mounted (HTTP ${post_status})"
  else
    fail "POST returned HTTP ${post_status}" "${post_body:0:400}"
  fi
fi

begin_test "GET /admin/settings reflects the updated value"
if [ "$SETTINGS_AVAILABLE" != "1" ]; then
  skip "settings unavailable"
else
  # Brief pause: some builds write-through to disk on POST and the next
  # GET races the flush. 1s is well under the per-test timeout budget.
  sleep 1
  reread=$(api_get "/api/v1/admin/settings" 2>/dev/null) || reread=""
  if [ -z "$reread" ]; then
    fail "GET-after-POST returned empty body"
  else
    current=$(echo "$reread" | jq -r '.edge_stale_threshold_minutes // empty')
    if [ "$current" = "$NEW_THRESHOLD" ]; then
      pass
    else
      fail "expected edge_stale_threshold_minutes=${NEW_THRESHOLD}, got '${current}'" "${reread:0:300}"
    fi
  fi
fi

begin_test "POST original settings restores the document"
if [ "$SETTINGS_AVAILABLE" != "1" ]; then
  skip "settings unavailable"
else
  tmp=$(mktemp)
  restore_status=$(curl -s -o "$tmp" -w '%{http_code}' $CURL_TIMEOUT \
    -X POST \
    -H "$(auth_header)" \
    -H "Content-Type: application/json" \
    -d "$ORIGINAL_SETTINGS" \
    "${BASE_URL}/api/v1/admin/settings" 2>/dev/null) || restore_status=000
  body=$(cat "$tmp"); rm -f "$tmp"
  if [ "$restore_status" = "200" ] || [ "$restore_status" = "204" ]; then
    sleep 1
    final=$(api_get "/api/v1/admin/settings" 2>/dev/null) || final=""
    final_threshold=$(echo "$final" | jq -r '.edge_stale_threshold_minutes // empty')
    if [ "$final_threshold" = "$ORIGINAL_THRESHOLD" ]; then
      pass
      # Successful explicit restore: clear so exit handler does not POST again.
      SETTINGS_AVAILABLE=0
    else
      fail "restore POST succeeded but threshold=${final_threshold}, expected ${ORIGINAL_THRESHOLD}"
    fi
  else
    fail "restore POST returned HTTP ${restore_status}" "${body:0:300}"
  fi
fi

end_suite
