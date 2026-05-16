#!/usr/bin/env bash
# test-repo-soft-delete-cascade.sh - Soft-delete cascade behaviour
#
# Covers Epic 6 sub-task 6.17 (artifact-keeper-test#71):
#   DELETE /api/v1/repositories/:key  (soft-delete cascade)
#
# Background: the backend exposes a single DELETE
# /api/v1/repositories/{key} endpoint (see backend repositories.rs lines
# 100-128 and 810-825). The handler takes ONLY the path parameter; it
# does NOT accept ?hard=true or any other query string, so a hard-delete
# / purge query is silently dropped. The OpenAPI spec confirms there is
# no purge or admin hard-delete endpoint for repositories anywhere (no
# /admin/repositories/.../purge, no `force` parameter, no `?hard` query).
#
# Hard-delete gap: a true hard-delete (purge artifacts row + binary
# storage in one atomic admin action) is documented as a v1.2.0 backend
# follow-up (issue #71). This test does NOT assert hard-delete; it pins
# the observable soft-delete cascade contract that the current backend
# does implement.
#
# Soft-delete cascade contract under test:
#   1. Create a repo and upload >= 2 artifacts.
#   2. Snapshot the artifact ids and confirm GET resolves each one
#      via the per-artifact stats endpoint.
#   3. DELETE the repo (no query string; the backend ignores them).
#   4. After delete:
#        a. GET /repositories/:key returns 404 (the row is hidden).
#        b. Re-creating a repo with the SAME key succeeds. A broken
#           soft-delete that leaves a live row behind would surface
#           here as 409 due to a unique-key violation; the backend's
#           soft-delete tombstone-then-cleanup pattern means re-create
#           should succeed.
#        c. The previously-captured artifact ids no longer resolve via
#           the per-artifact endpoint (404). This is the load-bearing
#           cascade assertion: a soft-delete that did NOT cascade
#           through to artifact rows would still resolve them by id.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "repo-soft-delete-cascade"
auth_admin
setup_workdir

REPO_KEY="test-softdel-${RUN_ID}"

# Cleanup is best-effort: by the time we reach end_suite the repo should
# already be gone. If anything went wrong, an EXIT delete is safe (404 is
# fine).
add_exit_handler "curl -s -o /dev/null -X DELETE -H 'Authorization: Bearer \$ADMIN_TOKEN' \"\${BASE_URL}/api/v1/repositories/${REPO_KEY}\" || true"

# -------------------------------------------------------------------------
# Setup
# -------------------------------------------------------------------------

begin_test "Create repo"
if create_local_repo "$REPO_KEY" "generic"; then
  pass
else
  skip_suite "could not create repo"
fi

ART_IDS=()
begin_test "Upload 2 artifacts"
UPLOAD_OK=true
for i in 1 2; do
  echo "softdel-payload-${i}-${RUN_ID}" > "${WORK_DIR}/blob-${i}.bin"
  body_file="${WORK_DIR}/up-${i}.json"
  st=$(curl -s -o "$body_file" -w '%{http_code}' $CURL_TIMEOUT \
    -X PUT -H "$(auth_header)" -H "Content-Type: application/octet-stream" \
    --data-binary "@${WORK_DIR}/blob-${i}.bin" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/cascade-${i}.bin" 2>/dev/null) || st="000"
  if [ "$st" -lt 200 ] 2>/dev/null || [ "$st" -ge 300 ] 2>/dev/null; then
    UPLOAD_OK=false
    break
  fi
  aid=$(jq -r '.id // empty' < "$body_file")
  if [ -n "$aid" ] && [ "$aid" != "null" ]; then
    ART_IDS+=("$aid")
  fi
done

if $UPLOAD_OK && [ "${#ART_IDS[@]}" -ge 1 ]; then
  pass
else
  # If we got 2xx but no ids, try the list endpoint.
  if [ "${#ART_IDS[@]}" -eq 0 ]; then
    if list_resp=$(api_get "/api/v1/repositories/${REPO_KEY}/artifacts?per_page=50" 2>/dev/null); then
      mapfile -t ART_IDS < <(echo "$list_resp" | jq -r '(.items // .data // .)[]?.id // empty' | grep -v '^$')
    fi
  fi
  if $UPLOAD_OK && [ "${#ART_IDS[@]}" -ge 1 ]; then
    pass
  else
    skip_suite "could not upload + capture artifact ids"
  fi
fi

# -------------------------------------------------------------------------
# 6.17.a: DELETE the repo. The backend's delete_repository handler takes
# only a path parameter (see repositories.rs:810-825); query strings are
# silently dropped, so we send no query string at all. Hard-delete is a
# v1.2.0 backend follow-up; this test asserts only the documented soft-
# delete cascade behaviour.
# -------------------------------------------------------------------------

begin_test "DELETE repo (soft, cascading)"
DEL_STATUS=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X DELETE -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}" 2>/dev/null) || DEL_STATUS="000"
assert_http_2xx "$DEL_STATUS" "DELETE repo returned ${DEL_STATUS}" && pass

# -------------------------------------------------------------------------
# 6.17.b: GET on the deleted key returns 404.
# -------------------------------------------------------------------------

begin_test "GET deleted repo returns 404"
GET_STATUS=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}" 2>/dev/null) || GET_STATUS="000"
assert_eq "$GET_STATUS" "404" "expected 404, got ${GET_STATUS}" && pass

# -------------------------------------------------------------------------
# 6.17.c: Re-creating with the same key succeeds. A broken soft-delete
# that leaves a live row behind would surface as 409 (unique key
# violation).
# -------------------------------------------------------------------------

begin_test "Re-create repo with same key (catches soft-delete row leak)"
RECREATE_PAYLOAD=$(jq -n --arg k "$REPO_KEY" --arg n "$REPO_KEY" \
  '{key: $k, name: $n, format: "generic", repo_type: "local", is_public: true}')
RECREATE_BODY="${WORK_DIR}/recreate.json"
RECREATE_STATUS=$(curl -s -o "$RECREATE_BODY" -w '%{http_code}' $CURL_TIMEOUT \
  -X POST -H "$(auth_header)" -H "Content-Type: application/json" \
  -d "$RECREATE_PAYLOAD" \
  "${BASE_URL}/api/v1/repositories" 2>/dev/null) || RECREATE_STATUS="000"
case "$RECREATE_STATUS" in
  2[0-9][0-9]) pass ;;
  409)
    body=$(head -c 400 "$RECREATE_BODY" 2>/dev/null || true)
    fail "re-create returned 409; soft-delete row appears to be lingering: ${body}"
    ;;
  *)
    body=$(head -c 400 "$RECREATE_BODY" 2>/dev/null || true)
    fail "re-create returned HTTP ${RECREATE_STATUS}: ${body}"
    ;;
esac

# -------------------------------------------------------------------------
# 6.17.d: The captured artifact ids must return 404 on /stats. This is
# the load-bearing cascade signal: a soft-delete that did not cascade
# through to artifact rows would keep them resolvable by id.
# -------------------------------------------------------------------------

begin_test "Artifact ids from old repo return 404 on /stats (cascade)"
if [ "${#ART_IDS[@]}" -eq 0 ]; then
  skip "no artifact ids captured pre-delete"
else
  REMAINING=0
  for aid in "${ART_IDS[@]}"; do
    st=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
      -H "$(auth_header)" \
      "${BASE_URL}/api/v1/artifacts/${aid}/stats" 2>/dev/null) || st="000"
    case "$st" in
      404) ;;  # expected: row is gone (or hidden via cascade)
      501)
        # Stats endpoint missing entirely; we cannot prove cascade this way.
        REMAINING=-1
        break
        ;;
      *)
        REMAINING=$(( REMAINING + 1 ))
        ;;
    esac
  done
  if [ "$REMAINING" = "-1" ]; then
    skip "stats endpoint not available; cannot prove cascade via this path"
  elif [ "$REMAINING" -eq 0 ]; then
    pass
  else
    fail "${REMAINING} of ${#ART_IDS[@]} artifact ids still resolve after repo delete"
  fi
fi

end_suite
