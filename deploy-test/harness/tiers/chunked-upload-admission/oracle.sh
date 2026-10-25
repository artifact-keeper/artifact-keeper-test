#!/usr/bin/env bash
# =============================================================================
# tiers/chunked-upload-admission/oracle.sh: chunked uploads apply the quota
# and the upload quarantine hold like native routes (backend #5003 / #4992)
# =============================================================================
# run.sh has stood up filesystem/single with RATE_LIMIT_ENABLED=false and
# exported BASE_URL, DB_CONTAINER, ADMIN_USER/ADMIN_PASS, COMMON_SH,
# JUNIT_OUTPUT_DIR, DTF_SLOT, RUN_ID. See the manifest for the gate list.
#
# Gates:
#   CONTROL quota         non-admin chunked upload within quota -> 200 + download
#   FIX quota             non-admin + replication header over quota -> 413/507
#   FIX quota residue     no artifact row, no stored object, download 404
#   CONTROL trusted       admin + replication header over quota -> 200
#   FIX quarantine        chunked upload into a held repo -> quarantined, 409
#   CONTROL native hold   native PUT into the same repo -> quarantined, 409
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"
# shellcheck source=/dev/null
source "$COMMON_SH"

require_cmd jq
require_cmd sha256sum

BACKEND_CTR="ak-dtf${DTF_SLOT}-backend"
FS_HELPER_IMAGE="postgres:16-alpine"   # already pulled by compose.base.yml
SUF="$(printf '%s' "${RUN_ID}" | tr -cd '[:alnum:]' | tail -c 8)"
QREPO="cua-quota-${DTF_SLOT}-${SUF}"
HREPO="cua-hold-${DTF_SLOT}-${SUF}"
QUOTA=1000
W_USER="cua-w-${DTF_SLOT}-${SUF}"
# Generated per run; never a committed literal.
W_PASS="Cua_$(head -c 12 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 12)_Aa1!"

setup_workdir
W="$WORK_DIR"

psql_q() {
  docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]'
}
fsx() {
  docker run --rm -i --volumes-from "$BACKEND_CTR" --entrypoint sh "$FS_HELPER_IMAGE" -c "$1" 2>/dev/null || true
}

# make_body <file> <size> <marker>: a body of exactly <size> bytes that starts
# with a run-unique marker, so the stored object can be found by content.
make_body() {
  { printf '%s' "$3"; head -c "$2" /dev/zero | tr '\0' 'a'; } | head -c "$2" > "$1"
}

# chunked_upload <token> <repo> <path> <file> [replication]
# POST session -> PATCH one chunk -> PUT complete. Sets UPLOAD_STAGE,
# UPLOAD_CODE and UPLOAD_BODY; returns 0 only when completion answered 200.
chunked_upload() {
  local tok="$1" repo="$2" path="$3" file="$4" repl="${5:-}"
  local size sha sid resp
  local -a rh=()
  [ -n "$repl" ] && rh=(-H 'x-artifact-keeper-replication: true')
  size=$(wc -c < "$file" | tr -d ' ')
  sha=$(sha256sum "$file" | cut -d' ' -f1)
  UPLOAD_STAGE="session"; UPLOAD_BODY=""
  resp=$(curl -s $CURL_TIMEOUT -w '\n%{http_code}' -X POST "${BASE_URL}/api/v1/uploads" \
    -H "Authorization: Bearer ${tok}" -H 'Content-Type: application/json' "${rh[@]}" \
    -d "{\"repository_key\":\"${repo}\",\"artifact_path\":\"${path}\",\"artifact_name\":\"$(basename "$path")\",\"artifact_version\":\"1.0.0\",\"total_size\":${size},\"checksum_sha256\":\"${sha}\",\"chunk_size\":8388608}" \
    2>/dev/null) || { UPLOAD_CODE=000; return 1; }
  UPLOAD_CODE="$(echo "$resp" | tail -n1)"
  UPLOAD_BODY="$(echo "$resp" | head -n -1)"
  sid="$(echo "$UPLOAD_BODY" | jq -r '.session_id // empty' 2>/dev/null || true)"
  [ -n "$sid" ] || return 1
  UPLOAD_STAGE="chunk"
  UPLOAD_CODE=$(curl -s $CURL_TIMEOUT -o /dev/null -w '%{http_code}' -X PATCH \
    "${BASE_URL}/api/v1/uploads/${sid}" -H "Authorization: Bearer ${tok}" "${rh[@]}" \
    -H "Content-Range: bytes 0-$((size - 1))/${size}" \
    -H 'Content-Type: application/octet-stream' \
    --data-binary "@${file}" 2>/dev/null) || UPLOAD_CODE=000
  case "$UPLOAD_CODE" in 2??) ;; *) return 1 ;; esac
  UPLOAD_STAGE="complete"
  resp=$(curl -s $CURL_TIMEOUT -w '\n%{http_code}' -X PUT \
    "${BASE_URL}/api/v1/uploads/${sid}/complete" -H "Authorization: Bearer ${tok}" "${rh[@]}" \
    2>/dev/null) || { UPLOAD_CODE=000; return 1; }
  UPLOAD_CODE="$(echo "$resp" | tail -n1)"
  UPLOAD_BODY="$(echo "$resp" | head -n -1)"
  [ "$UPLOAD_CODE" = "200" ]
}

# download <token> <repo> <path> <outfile> -> echoes the HTTP code
download() {
  curl -s $CURL_TIMEOUT -o "$4" -w '%{http_code}' -H "Authorization: Bearer ${1}" \
    "${BASE_URL}/api/v1/repositories/${2}/download/${3}" 2>/dev/null || echo 000
}

# listing_status <repo> <path> -> quarantine_status from the artifacts listing
listing_status() {
  curl -s $CURL_TIMEOUT -H "$(auth_header)" \
    "${BASE_URL}/api/v1/repositories/${1}/artifacts" 2>/dev/null \
    | jq -r --arg p "$2" '.items[]? | select(.path==$p) | .quarantine_status // empty' 2>/dev/null || true
}

db_status() { # <repo> <path> -> artifacts.quarantine_status ("" when NULL)
  psql_q "SELECT coalesce(a.quarantine_status,'') FROM artifacts a JOIN repositories r ON r.id = a.repository_id WHERE r.key = '${1}' AND a.path = '${2}' AND a.is_deleted = false;"
}

create_private_repo() { # KEY [extra json fields] -> echoes repo id
  curl -s $CURL_TIMEOUT -X POST "${BASE_URL}/api/v1/repositories" \
    -H "$(auth_header)" -H 'Content-Type: application/json' \
    -d "{\"key\":\"${1}\",\"name\":\"${1}\",\"format\":\"generic\",\"repo_type\":\"local\",\"is_public\":false${2:+,$2}}" \
    2>/dev/null | jq -r '.id // empty' 2>/dev/null || true
}

grant_rw() { # USER_ID REPO_ID -> http code
  curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X POST "${BASE_URL}/api/v1/permissions" \
    -H "$(auth_header)" -H 'Content-Type: application/json' \
    -d "{\"principal_type\":\"user\",\"principal_id\":\"${1}\",\"target_type\":\"repository\",\"target_id\":\"${2}\",\"actions\":[\"read\",\"write\"]}" \
    2>/dev/null || echo 000
}

begin_suite "chunked-upload-admission"

auth_admin   # sets ADMIN_TOKEN

# --- setup -------------------------------------------------------------------
begin_test "SETUP: quota repo (${QUOTA} B), quarantine repo, non-admin writer with read+write on both"
SETUP_ERR=""
QREPO_ID="$(create_private_repo "$QREPO" "\"quota_bytes\":${QUOTA}")"
[ -n "$QREPO_ID" ] || SETUP_ERR="${SETUP_ERR} create(${QREPO})"
HREPO_ID="$(create_private_repo "$HREPO")"
[ -n "$HREPO_ID" ] || SETUP_ERR="${SETUP_ERR} create(${HREPO})"
got_quota="$(psql_q "SELECT quota_bytes FROM repositories WHERE key = '${QREPO}';")"
if [ "$got_quota" != "$QUOTA" ]; then
  psql_q "UPDATE repositories SET quota_bytes = ${QUOTA} WHERE key = '${QREPO}';" >/dev/null
  got_quota="$(psql_q "SELECT quota_bytes FROM repositories WHERE key = '${QREPO}';")"
fi
[ "$got_quota" = "$QUOTA" ] || SETUP_ERR="${SETUP_ERR} quota(${got_quota})"
hold_code=$(curl -s $CURL_TIMEOUT -o "$W/hold.json" -w '%{http_code}' -X PATCH \
  "${BASE_URL}/api/v1/repositories/${HREPO}" -H "$(auth_header)" -H 'Content-Type: application/json' \
  -d '{"quarantine_enabled":true,"quarantine_duration_minutes":120}' 2>/dev/null) || hold_code=000
hold_cfg="$(psql_q "SELECT value FROM repository_config c JOIN repositories r ON r.id = c.repository_id WHERE r.key = '${HREPO}' AND c.key = 'quarantine_enabled';")"
[ "$hold_code" = "200" ] && [ "$hold_cfg" = "true" ] || SETUP_ERR="${SETUP_ERR} hold(HTTP ${hold_code}, cfg='${hold_cfg}')"
W_ID="$(create_test_user_with_retry "$W_USER" "$W_PASS" "${W_USER}@t.test" || true)"
[ -n "$W_ID" ] || SETUP_ERR="${SETUP_ERR} user"
for _r in "$QREPO_ID" "$HREPO_ID"; do
  [ -n "$_r" ] && [ -n "$W_ID" ] || continue
  _c="$(grant_rw "$W_ID" "$_r")"
  case "$_c" in 2??) ;; *) SETUP_ERR="${SETUP_ERR} grant(${_r:0:8}:${_c})" ;; esac
done
W_TOKEN="$(login_as "$W_USER" "$W_PASS" || true)"
[ -n "$W_TOKEN" ] || SETUP_ERR="${SETUP_ERR} login"
W_ADMIN="$(curl -s $CURL_TIMEOUT -H "Authorization: Bearer ${W_TOKEN}" "${BASE_URL}/api/v1/auth/me" 2>/dev/null | jq -r '.is_admin // empty' 2>/dev/null || true)"
[ "$W_ADMIN" = "true" ] && SETUP_ERR="${SETUP_ERR} writer-is-admin"
if [ -z "$SETUP_ERR" ]; then
  pass "repos ${QREPO} (quota_bytes=${QUOTA}) and ${HREPO} (quarantine_enabled), writer ${W_USER} (is_admin=${W_ADMIN:-false})"
else
  infra_fail "setup failed:${SETUP_ERR}"
  end_suite
fi

# --- (CONTROL quota) a fitting chunked upload completes and downloads ---------
begin_test "CONTROL quota: non-admin chunked upload of 400 B into a ${QUOTA} B quota -> 200 and downloads"
make_body "$W/fit.bin" 400 "cua-fit-${SUF}-"
if chunked_upload "$W_TOKEN" "$QREPO" "q/fit-400.bin" "$W/fit.bin"; then
  dl="$(download "$W_TOKEN" "$QREPO" "q/fit-400.bin" "$W/fit.out")"
  if [ "$dl" = "200" ] && cmp -s "$W/fit.bin" "$W/fit.out"; then
    pass "admitted and served byte-identical"
  else
    fail "fitting upload completed but download answered HTTP ${dl} (or bytes differ)"
  fi
else
  fail "fitting chunked upload failed at ${UPLOAD_STAGE} (HTTP ${UPLOAD_CODE})" "${UPLOAD_BODY:0:300}"
fi

# --- (FIX quota) the replication header alone does not exempt a session -------
OVER_PATH="q/over-repl-2000.bin"
OVER_MARK="cua-over-${SUF}-$$-"
make_body "$W/over.bin" 2000 "$OVER_MARK"
begin_test "FIX quota: non-admin chunked upload over the quota with x-artifact-keeper-replication: true -> 413 at create (or 507 at completion)"
if chunked_upload "$W_TOKEN" "$QREPO" "$OVER_PATH" "$W/over.bin" repl; then
  fail "over-quota chunked upload was ADMITTED for a non-admin session that only set the replication header (want 413 at session create or 507 at completion; chunked uploads apply the quota unless the session is a trusted replication session)"
elif [ "$UPLOAD_STAGE" = "session" ] && [ "$UPLOAD_CODE" = "413" ]; then
  pass "refused at session create (HTTP 413)"
elif [ "$UPLOAD_STAGE" = "complete" ] && [ "$UPLOAD_CODE" = "507" ]; then
  pass "refused at completion (HTTP 507)"
else
  fail "upload failed at ${UPLOAD_STAGE} with HTTP ${UPLOAD_CODE}, expected a quota refusal (413 create / 507 complete)" "${UPLOAD_BODY:0:300}"
fi

begin_test "FIX quota residue: no artifact row, no stored object, download 404 for the refused upload"
rows="$(psql_q "SELECT count(*) FROM artifacts a JOIN repositories r ON r.id = a.repository_id WHERE r.key = '${QREPO}' AND a.path = '${OVER_PATH}';")"
objs="$(fsx "grep -rlF '${OVER_MARK}' /data/storage 2>/dev/null | wc -l" | tr -d '[:space:]')"
dl="$(download "$ADMIN_TOKEN" "$QREPO" "$OVER_PATH" "$W/over.out")"
if [ "$rows" = "0" ] && [ "$objs" = "0" ] && [ "$dl" = "404" ]; then
  pass "artifact rows=0, stored objects=0, download HTTP 404"
else
  fail "refused upload left residue: artifact rows=${rows:-?} (want 0), stored objects holding its bytes=${objs:-?} (want 0), download HTTP ${dl} (want 404)"
fi

# --- (CONTROL trusted) an administrator's replication session is exempt -------
begin_test "CONTROL trusted: administrator chunked upload over the quota with the replication header -> 200 (trusted replication)"
make_body "$W/trusted.bin" 2000 "cua-trusted-${SUF}-"
if chunked_upload "$ADMIN_TOKEN" "$QREPO" "q/trusted-repl-2000.bin" "$W/trusted.bin" repl; then
  rows="$(psql_q "SELECT count(*) FROM artifacts a JOIN repositories r ON r.id = a.repository_id WHERE r.key = '${QREPO}' AND a.path = 'q/trusted-repl-2000.bin' AND a.is_deleted = false;")"
  if [ "$rows" = "1" ]; then
    pass "trusted replication admitted past the quota (artifact row present)"
  else
    fail "completion answered 200 but artifact rows=${rows:-?} (want 1)"
  fi
else
  fail "administrator replication upload refused at ${UPLOAD_STAGE} (HTTP ${UPLOAD_CODE}); a trusted replication session must be exempt from the quota" "${UPLOAD_BODY:0:300}"
fi

# --- (FIX quarantine) chunked uploads honour the upload quarantine hold --------
begin_test "FIX quarantine: chunked upload into a quarantine-enabled repository -> artifact quarantined, download refused 409"
make_body "$W/held-chunked.bin" 600 "cua-held-c-${SUF}-"
if chunked_upload "$W_TOKEN" "$HREPO" "h/chunked-1.0.0.bin" "$W/held-chunked.bin"; then
  st_list="$(listing_status "$HREPO" "h/chunked-1.0.0.bin")"
  st_db="$(db_status "$HREPO" "h/chunked-1.0.0.bin")"
  dl="$(download "$ADMIN_TOKEN" "$HREPO" "h/chunked-1.0.0.bin" "$W/held-chunked.out")"
  if [ "$st_list" = "quarantined" ] && [ "$st_db" = "quarantined" ] && [ "$dl" = "409" ]; then
    pass "held: listing quarantine_status=quarantined, db=quarantined, download HTTP 409"
  else
    fail "chunked upload into a quarantine-enabled repository was not held: listing quarantine_status='${st_list:-<absent>}', db='${st_db:-<null>}', download HTTP ${dl} (want quarantined / quarantined / 409, as the native upload gets)"
  fi
else
  fail "chunked upload into ${HREPO} failed at ${UPLOAD_STAGE} (HTTP ${UPLOAD_CODE})" "${UPLOAD_BODY:0:300}"
fi

# --- (CONTROL native hold) the native single-request upload is held -----------
begin_test "CONTROL native hold: native PUT into the same repository -> artifact quarantined, download refused 409"
make_body "$W/held-native.bin" 600 "cua-held-n-${SUF}-"
put_code=$(curl -s $CURL_TIMEOUT -o "$W/put.json" -w '%{http_code}' -X PUT \
  -H "Authorization: Bearer ${W_TOKEN}" -H 'Content-Type: application/octet-stream' \
  --data-binary "@$W/held-native.bin" \
  "${BASE_URL}/api/v1/repositories/${HREPO}/artifacts/h/native-1.0.0.bin" 2>/dev/null) || put_code=000
case "$put_code" in
  2??)
    st_list="$(listing_status "$HREPO" "h/native-1.0.0.bin")"
    st_db="$(db_status "$HREPO" "h/native-1.0.0.bin")"
    dl="$(download "$ADMIN_TOKEN" "$HREPO" "h/native-1.0.0.bin" "$W/held-native.out")"
    if [ "$st_list" = "quarantined" ] && [ "$st_db" = "quarantined" ] && [ "$dl" = "409" ]; then
      pass "native upload held: listing quarantined, db quarantined, download HTTP 409"
    else
      fail "native upload not held as expected: listing='${st_list:-<absent>}', db='${st_db:-<null>}', download HTTP ${dl}"
    fi
    ;;
  *) fail "native PUT into ${HREPO} answered HTTP ${put_code}" "$(head -c 300 "$W/put.json" 2>/dev/null)" ;;
esac

# --- cleanup -----------------------------------------------------------------
for _k in "$QREPO" "$HREPO"; do
  curl -s -o /dev/null -X DELETE -H "$(auth_header)" "${BASE_URL}/api/v1/repositories/${_k}" 2>/dev/null || true
done

end_suite
