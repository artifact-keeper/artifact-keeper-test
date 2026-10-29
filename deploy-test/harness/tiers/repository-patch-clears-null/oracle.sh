#!/usr/bin/env bash
# =============================================================================
# tiers/repository-patch-clears-null/oracle.sh
#   #4729 PATCH /api/v1/repositories/{key} with an explicit null clears
#         description and quota_bytes; omitted fields stay untouched
# See the manifest for the gates.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_USER/ADMIN_PASS, COMMON_SH,
# JUNIT_OUTPUT_DIR, DTF_SLOT, RUN_ID, RELEASE_GATE=1.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"
# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every step records its outcome through pass/fail.
set +e

require_cmd jq
require_cmd sha256sum

SUF="$(printf '%s' "${RUN_ID}" | tr -cd '[:alnum:]' | tail -c 8)"
REPO="rpcn-${DTF_SLOT:-x}-${SUF}"
D1="dtf description one ${SUF}"
D2="dtf description two ${SUF}"
D3="dtf description three ${SUF}"
setup_workdir
W="$WORK_DIR"

psql_q() {
  docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '\r'
}
# row: "<description or NULL>|<quota_bytes or NULL>" straight from the table.
row() {
  psql_q "SELECT COALESCE(description, 'NULL') || '|' || COALESCE(quota_bytes::text, 'NULL') FROM repositories WHERE key = '${REPO}';"
}

# patch_repo <json>: PATCH the repository; PATCH_CODE and $W/patch.json.
patch_repo() {
  PATCH_CODE=$(curl -s -o "${W}/patch.json" -w '%{http_code}' $CURL_TIMEOUT -X PATCH \
    -H "$(auth_header)" -H 'Content-Type: application/json' \
    -d "$1" "${BASE_URL}/api/v1/repositories/${REPO}" 2>/dev/null) || PATCH_CODE=000
}
# resp: the same two fields from the PATCH response body, null rendered NULL.
resp() {
  jq -r '(if .description == null then "NULL" else .description end) + "|" + (if .quota_bytes == null then "NULL" else (.quota_bytes | tostring) end)' \
    "${W}/patch.json" 2>/dev/null || echo "unparseable"
}
body_snip() { head -c 300 "${W}/patch.json" 2>/dev/null | tr -c '[:print:]' '.'; }

# seed <description> <quota>: set both through PATCH (works on every image).
seed() {
  patch_repo "$(jq -nc --arg d "$1" --argjson q "$2" '{description:$d, quota_bytes:$q}')"
  [ "$PATCH_CODE" = "200" ] && [ "$(row)" = "$1|$2" ]
}

# Chunked upload (the quota-gated write path, as in quota-admission-o1):
# POST session -> PATCH one chunk -> PUT complete. UPLOAD_STAGE/UPLOAD_CODE;
# returns 0 only when the whole flow succeeded. A quota refusal is 413 at the
# session preflight or 507 at the locked admission on complete.
upload_sized() { # <path> <size-bytes>
  local path="$1" size="$2" body sha sid r
  body="$(head -c "$size" /dev/zero | tr '\0' 'a')"
  sha=$(printf '%s' "$body" | sha256sum | cut -d' ' -f1)
  UPLOAD_STAGE="session"
  r=$(curl -s -w '\n%{http_code}' -X POST "${BASE_URL}/api/v1/uploads" \
    -H "$(auth_header)" -H 'Content-Type: application/json' \
    -d "{\"repository_key\":\"${REPO}\",\"artifact_path\":\"${path}\",\"artifact_name\":\"$(basename "$path")\",\"artifact_version\":\"1.0.0\",\"total_size\":${size},\"checksum_sha256\":\"${sha}\",\"chunk_size\":8388608}" \
    2>/dev/null) || { UPLOAD_CODE=000; return 1; }
  UPLOAD_CODE="$(echo "$r" | tail -n1)"
  sid="$(echo "$r" | head -n -1 | jq -r '.session_id // empty' 2>/dev/null || true)"
  [ -n "$sid" ] || return 1
  UPLOAD_STAGE="chunk"
  curl -s -o /dev/null -X PATCH "${BASE_URL}/api/v1/uploads/${sid}" -H "$(auth_header)" \
    -H "Content-Range: bytes 0-$((size - 1))/${size}" \
    -H 'Content-Type: application/octet-stream' \
    --data-binary "$body" 2>/dev/null || { UPLOAD_CODE=000; return 1; }
  UPLOAD_STAGE="complete"
  UPLOAD_CODE=$(curl -s -o /dev/null -w '%{http_code}' -X PUT \
    "${BASE_URL}/api/v1/uploads/${sid}/complete" -H "$(auth_header)" 2>/dev/null) || UPLOAD_CODE=000
  [ "$UPLOAD_CODE" = "200" ]
}
quota_refused() { [ "$UPLOAD_CODE" = "507" ] || { [ "$UPLOAD_STAGE" = "session" ] && [ "$UPLOAD_CODE" = "413" ]; }; }

begin_suite "repository-patch-clears-null"

auth_admin   # sets ADMIN_TOKEN

# =============================================================================
# Controls
# =============================================================================
begin_test "SETUP: create a local generic repository"
if create_local_repo "$REPO" generic && [ -n "$(psql_q "SELECT id FROM repositories WHERE key = '${REPO}';")" ]; then
  pass
else
  fail_fatal "could not create repository ${REPO}"
fi

begin_test "CONTROL: PATCH with values sets description and quota_bytes (response and row)"
patch_repo "$(jq -nc --arg d "$D1" '{description:$d, quota_bytes:1000}')"
r="$(resp)"; d="$(row)"
if [ "$PATCH_CODE" = "200" ] && [ "$r" = "${D1}|1000" ] && [ "$d" = "${D1}|1000" ]; then
  pass
else
  fail "PATCH HTTP ${PATCH_CODE}; response '${r}', row '${d}', want '${D1}|1000' in both; body: $(body_snip)"
fi

begin_test "CONTROL: a PATCH that omits description and quota_bytes (rename only) leaves both untouched"
patch_repo "$(jq -nc --arg n "${REPO} renamed" '{name:$n}')"
r="$(resp)"; d="$(row)"
if [ "$PATCH_CODE" = "200" ] && [ "$r" = "${D1}|1000" ] && [ "$d" = "${D1}|1000" ]; then
  pass
else
  fail "PATCH HTTP ${PATCH_CODE}; response '${r}', row '${d}', want '${D1}|1000' in both; body: $(body_snip)"
fi

begin_test "CONTROL: with the 1000-byte quota a 600-byte upload is admitted and a second one is refused"
if upload_sized "p/a-600.bin" 600; then
  if upload_sized "p/b-600.bin" 600; then
    fail "the second 600-byte upload was admitted although 1200 bytes exceed the 1000-byte quota"
  elif quota_refused; then
    pass "refused with HTTP ${UPLOAD_CODE} at ${UPLOAD_STAGE}"
  else
    fail "the second upload failed at ${UPLOAD_STAGE} with HTTP ${UPLOAD_CODE}, expected a quota refusal (413 session / 507 complete)"
  fi
else
  fail "the first 600-byte upload failed at ${UPLOAD_STAGE} (HTTP ${UPLOAD_CODE})"
fi

# =============================================================================
# The fix
# =============================================================================
begin_test "FIX(#4729): {\"quota_bytes\": null} clears the quota (response and row); the omitted description stays"
patch_repo '{"quota_bytes":null}'
r="$(resp)"; d="$(row)"
if [ "$PATCH_CODE" = "200" ] && [ "$r" = "${D1}|NULL" ] && [ "$d" = "${D1}|NULL" ]; then
  pass
else
  fail "PATCH HTTP ${PATCH_CODE}; response '${r}', row '${d}', want '${D1}|NULL' in both (an explicit null was read as 'absent'); body: $(body_snip)"
fi

begin_test "FIX(#4729): after clearing the quota the 600-byte upload refused before is admitted"
if upload_sized "p/b-600.bin" 600; then
  pass
else
  fail "upload still failed at ${UPLOAD_STAGE} with HTTP ${UPLOAD_CODE} (row '$(row)'): the old quota is still enforced"
fi

begin_test "FIX(#4729): {\"description\": null} clears the description (response and row); the omitted quota_bytes stays"
if ! seed "$D2" 5000; then
  fail "could not reseed description and quota (HTTP ${PATCH_CODE}, row '$(row)')"
else
  patch_repo '{"description":null}'
  r="$(resp)"; d="$(row)"
  if [ "$PATCH_CODE" = "200" ] && [ "$r" = "NULL|5000" ] && [ "$d" = "NULL|5000" ]; then
    pass
  else
    fail "PATCH HTTP ${PATCH_CODE}; response '${r}', row '${d}', want 'NULL|5000' in both (an explicit null was read as 'absent'); body: $(body_snip)"
  fi
fi

begin_test "FIX(#4729): one PATCH with both fields null clears both"
if ! seed "$D3" 6000; then
  fail "could not reseed description and quota (HTTP ${PATCH_CODE}, row '$(row)')"
else
  patch_repo '{"description":null,"quota_bytes":null}'
  r="$(resp)"; d="$(row)"
  if [ "$PATCH_CODE" = "200" ] && [ "$r" = "NULL|NULL" ] && [ "$d" = "NULL|NULL" ]; then
    pass
  else
    fail "PATCH HTTP ${PATCH_CODE}; response '${r}', row '${d}', want 'NULL|NULL' in both; body: $(body_snip)"
  fi
fi

curl -s -o /dev/null -X DELETE -H "$(auth_header)" "${BASE_URL}/api/v1/repositories/${REPO}" 2>/dev/null || true

end_suite
