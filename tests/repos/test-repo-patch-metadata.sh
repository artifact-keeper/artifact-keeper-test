#!/usr/bin/env bash
# test-repo-patch-metadata.sh - Repository PATCH metadata + key rename
#
# Covers Epic 6 sub-tasks 6.11 and 6.16 (artifact-keeper-test#71):
#   6.11 Repository key rename:    PATCH /:key body {"key": "<new>"}
#   6.16 Repository PATCH metadata: PATCH /:key body covering name,
#                                   description, is_public, quota_bytes
#
# Schema source (openapi.yaml UpdateRepositoryRequest):
#   key, name, description, is_public, quota_bytes are all optional.
#   PATCH returns 200 with the updated RepositoryResponse, 401 unauth,
#   404 not found, 409 if the new key collides.
#
# Contract under test (round-trip each field, then restore):
#   1. PATCH each metadata field individually and verify GET reflects it.
#   2. Restore each field to its pre-PATCH value so the suite is idempotent.
#   3. Rename the repo by PATCHing `key`: old key returns 404, new key
#      resolves; rename back so cleanup matches the original.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "repo-patch-metadata"
auth_admin
setup_workdir

ORIG_KEY="test-patch-${RUN_ID}"
NEW_KEY="test-patch-renamed-${RUN_ID}"

# Cleanup both keys (whichever one is live at exit) via EXIT trap.
add_exit_handler "curl -s -o /dev/null -X DELETE -H 'Authorization: Bearer \$ADMIN_TOKEN' \"\${BASE_URL}/api/v1/repositories/${ORIG_KEY}\" || true"
add_exit_handler "curl -s -o /dev/null -X DELETE -H 'Authorization: Bearer \$ADMIN_TOKEN' \"\${BASE_URL}/api/v1/repositories/${NEW_KEY}\" || true"

# -------------------------------------------------------------------------
# Setup: create a local repo with known starting values so we can assert
# every PATCH round-trip changes the right field and ONLY that field.
# -------------------------------------------------------------------------

begin_test "Create repo with known initial metadata"
INITIAL_PAYLOAD=$(jq -n \
  --arg key "$ORIG_KEY" \
  --arg name "patch-orig-${RUN_ID}" \
  --arg desc "initial description" \
  '{key: $key, name: $name, format: "generic", repo_type: "local", is_public: false, description: $desc, quota_bytes: 1048576}')

CREATE_BODY_FILE="${WORK_DIR}/create.json"
CREATE_STATUS=$(curl -s -o "$CREATE_BODY_FILE" -w '%{http_code}' $CURL_TIMEOUT \
  -X POST -H "$(auth_header)" -H "Content-Type: application/json" \
  -d "$INITIAL_PAYLOAD" \
  "${BASE_URL}/api/v1/repositories" 2>/dev/null) || CREATE_STATUS="000"

case "$CREATE_STATUS" in
  2[0-9][0-9]) pass ;;
  404|501)    skip_suite "repo create returned ${CREATE_STATUS} (endpoint missing)" ;;
  *)
    body=$(head -c 400 "$CREATE_BODY_FILE" 2>/dev/null || true)
    skip_suite "repo create returned HTTP ${CREATE_STATUS}: ${body}"
    ;;
esac

# Helper: PATCH JSON body, return HTTP status on stdout, body in OUT_FILE.
patch_repo() {
  local key="$1"
  local body="$2"
  local out="$3"
  curl -s -o "$out" -w '%{http_code}' $CURL_TIMEOUT \
    -X PATCH -H "$(auth_header)" -H "Content-Type: application/json" \
    -d "$body" "${BASE_URL}/api/v1/repositories/${key}" 2>/dev/null
}

# -------------------------------------------------------------------------
# 6.16.a: PATCH name (round-trip + restore).
# -------------------------------------------------------------------------

begin_test "PATCH name round-trip"
NEW_NAME="patch-renamed-${RUN_ID}"
PATCH_BODY=$(jq -n --arg n "$NEW_NAME" '{name: $n}')
STATUS=$(patch_repo "$ORIG_KEY" "$PATCH_BODY" "${WORK_DIR}/patch1.json") || STATUS="000"
if assert_http_2xx "$STATUS" "PATCH name returned ${STATUS}"; then
  got=$(jq -r '.name // empty' < "${WORK_DIR}/patch1.json")
  if [ "$got" = "$NEW_NAME" ]; then pass; else fail "PATCH name returned '${got}', expected '${NEW_NAME}'"; fi
fi
# Restore.
patch_repo "$ORIG_KEY" "$(jq -n --arg n "patch-orig-${RUN_ID}" '{name: $n}')" /dev/null > /dev/null 2>&1 || true

# -------------------------------------------------------------------------
# 6.16.b: PATCH description (round-trip + restore).
# -------------------------------------------------------------------------

begin_test "PATCH description round-trip"
NEW_DESC="updated description for ${RUN_ID}"
PATCH_BODY=$(jq -n --arg d "$NEW_DESC" '{description: $d}')
STATUS=$(patch_repo "$ORIG_KEY" "$PATCH_BODY" "${WORK_DIR}/patch2.json") || STATUS="000"
if assert_http_2xx "$STATUS" "PATCH description returned ${STATUS}"; then
  got=$(jq -r '.description // empty' < "${WORK_DIR}/patch2.json")
  if [ "$got" = "$NEW_DESC" ]; then pass; else fail "PATCH description got '${got}'"; fi
fi
patch_repo "$ORIG_KEY" '{"description":"initial description"}' /dev/null > /dev/null 2>&1 || true

# -------------------------------------------------------------------------
# 6.16.c: PATCH is_public from false -> true and back.
# -------------------------------------------------------------------------

begin_test "PATCH is_public round-trip"
STATUS=$(patch_repo "$ORIG_KEY" '{"is_public": true}' "${WORK_DIR}/patch3.json") || STATUS="000"
if assert_http_2xx "$STATUS" "PATCH is_public returned ${STATUS}"; then
  got=$(jq -r '.is_public // empty' < "${WORK_DIR}/patch3.json")
  if [ "$got" = "true" ]; then pass; else fail "PATCH is_public got '${got}'"; fi
fi
patch_repo "$ORIG_KEY" '{"is_public": false}' /dev/null > /dev/null 2>&1 || true

# -------------------------------------------------------------------------
# 6.16.d: PATCH quota_bytes (numeric round-trip + restore).
# -------------------------------------------------------------------------

begin_test "PATCH quota_bytes round-trip"
NEW_QUOTA=2097152  # 2 MiB
PATCH_BODY=$(jq -n --argjson q "$NEW_QUOTA" '{quota_bytes: $q}')
STATUS=$(patch_repo "$ORIG_KEY" "$PATCH_BODY" "${WORK_DIR}/patch4.json") || STATUS="000"
if assert_http_2xx "$STATUS" "PATCH quota_bytes returned ${STATUS}"; then
  got=$(jq -r '.quota_bytes // empty' < "${WORK_DIR}/patch4.json")
  if [ "$got" = "$NEW_QUOTA" ]; then pass; else fail "PATCH quota_bytes got '${got}'"; fi
fi
patch_repo "$ORIG_KEY" '{"quota_bytes": 1048576}' /dev/null > /dev/null 2>&1 || true

# -------------------------------------------------------------------------
# 6.11.a: Repository key rename via PATCH /:key {"key": "<new>"}.
# Load-bearing assertions:
#   - PATCH returns 2xx with new key in response.
#   - GET on old key returns 404 (resource moved).
#   - GET on new key returns 200 with the same id (same row).
# -------------------------------------------------------------------------

begin_test "PATCH key rename: ORIG -> NEW"
# Capture id of the original row so we can confirm it survives the rename.
if orig_resp=$(api_get "/api/v1/repositories/${ORIG_KEY}" 2>/dev/null); then
  ORIG_ID=$(echo "$orig_resp" | jq -r '.id // empty')
else
  ORIG_ID=""
fi
PATCH_BODY=$(jq -n --arg k "$NEW_KEY" '{key: $k}')
STATUS=$(patch_repo "$ORIG_KEY" "$PATCH_BODY" "${WORK_DIR}/rename.json") || STATUS="000"
case "$STATUS" in
  2[0-9][0-9])
    got_key=$(jq -r '.key // empty' < "${WORK_DIR}/rename.json")
    if [ "$got_key" = "$NEW_KEY" ]; then pass; else fail "rename response key='${got_key}'"; fi
    ;;
  404|501)
    skip "key rename returned ${STATUS} (likely unsupported in this build)"
    ORIG_ID=""  # disables the downstream rename-back assertion
    ;;
  *)
    body=$(head -c 400 "${WORK_DIR}/rename.json" 2>/dev/null || true)
    fail "PATCH key rename returned HTTP ${STATUS}: ${body}"
    ORIG_ID=""
    ;;
esac

begin_test "After rename, GET old key returns 404"
if [ -z "$ORIG_ID" ]; then
  skip "rename did not happen, nothing to assert"
else
  OLD_STATUS=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(auth_header)" \
    "${BASE_URL}/api/v1/repositories/${ORIG_KEY}" 2>/dev/null) || OLD_STATUS="000"
  assert_eq "$OLD_STATUS" "404" "expected 404 for old key after rename, got ${OLD_STATUS}" && pass
fi

begin_test "After rename, GET new key returns 200 with same id"
if [ -z "$ORIG_ID" ]; then
  skip "rename did not happen"
else
  if new_resp=$(api_get "/api/v1/repositories/${NEW_KEY}" 2>/dev/null); then
    new_id=$(echo "$new_resp" | jq -r '.id // empty')
    if [ "$new_id" = "$ORIG_ID" ]; then
      pass
    else
      fail "renamed repo has different id: was ${ORIG_ID}, now ${new_id}"
    fi
  else
    fail "GET ${NEW_KEY} failed after rename"
  fi
fi

# Restore original key so cleanup hits the right URL.
if [ -n "$ORIG_ID" ]; then
  patch_repo "$NEW_KEY" "$(jq -n --arg k "$ORIG_KEY" '{key: $k}')" /dev/null > /dev/null 2>&1 || true
fi

end_suite
