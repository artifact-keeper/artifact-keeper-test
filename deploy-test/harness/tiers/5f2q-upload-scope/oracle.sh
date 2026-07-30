#!/usr/bin/env bash
# =============================================================================
# tiers/5f2q-upload-scope/oracle.sh — chunked-upload token action-scope (GHSA-5f2q)
# =============================================================================
# run.sh has stood up the `filesystem` profile-set with RATE_LIMIT_ENABLED=false
# and exported BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID,
# RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH. We source common.sh for the
# assertion + JUnit harness, then drive the real HTTP flow against the backend.
#
# The bug (GHSA-5f2q): the /api/v1/uploads/* chunked verbs enforced repo-RBAC
# but NO token ACTION-scope. A READ-scoped token whose owner holds repo write
# could push (init/append/complete) and cancel. The fix adds require_scope:
# write on init/append/complete, delete on cancel -> read-scoped token 403.
#
# Discriminating gates:
#   (CONTROL)  WRITE-scoped token -> POST /uploads 201 (legit path unchanged;
#              its session_id is reused by the read-token append/complete probes).
#   (BOUNDARY) READ-scoped token on create_session/upload_chunk/complete -> 403
#              (GREEN "required scope: write:artifacts"); cancel -> 403
#              ("delete"). On the vulnerable baseline these return 2xx (RED —
#              the push succeeds).
#              A DB assert confirms the read-token create persisted NO session
#              row on the fix (0) vs one on baseline.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

SUF="${RUN_ID##*-}-$$"
REPO="5f2q-repo-${DTF_SLOT:-x}-${SUF}"
USER="5f2q-user-${DTF_SLOT:-x}-${SUF}"
USER_PASS="F5f2q_${SUF}_Aa1!"
WRITE_PATH="uploads/5f2q-write-${SUF}.bin"
READ_PATH="uploads/5f2q-read-${SUF}.bin"

PAYLOAD="5f2q-upload-scope-probe-${SUF}"
LEN="${#PAYLOAD}"
SHA="$(printf '%s' "$PAYLOAD" | sha256sum | cut -d' ' -f1)"

# --- curl helpers -----------------------------------------------------------
# session_json BEARER ARTIFACT_PATH  -> prints the JSON response body
create_session_body() {
  local bearer="$1" apath="$2"
  curl -s $CURL_TIMEOUT -X POST "${BASE_URL}/api/v1/uploads" \
    -H "Authorization: Bearer ${bearer}" -H 'Content-Type: application/json' \
    -d "{\"repository_key\":\"${REPO}\",\"artifact_path\":\"${apath}\",\"total_size\":${LEN},\"checksum_sha256\":\"${SHA}\"}" \
    2>/dev/null || true
}
create_session_code() {
  local bearer="$1" apath="$2"
  curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X POST "${BASE_URL}/api/v1/uploads" \
    -H "Authorization: Bearer ${bearer}" -H 'Content-Type: application/json' \
    -d "{\"repository_key\":\"${REPO}\",\"artifact_path\":\"${apath}\",\"total_size\":${LEN},\"checksum_sha256\":\"${SHA}\"}" \
    2>/dev/null || echo 000
}
upload_chunk_code() { # BEARER SESSION_ID
  curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X PATCH \
    "${BASE_URL}/api/v1/uploads/${2}" \
    -H "Authorization: Bearer ${1}" \
    -H "Content-Range: bytes 0-$((LEN-1))/${LEN}" \
    -H 'Content-Type: application/octet-stream' \
    --data-binary "$PAYLOAD" 2>/dev/null || echo 000
}
complete_code() { # BEARER SESSION_ID
  curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X PUT \
    "${BASE_URL}/api/v1/uploads/${2}/complete" \
    -H "Authorization: Bearer ${1}" 2>/dev/null || echo 000
}
cancel_code() { # BEARER SESSION_ID
  curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X DELETE \
    "${BASE_URL}/api/v1/uploads/${2}" \
    -H "Authorization: Bearer ${1}" 2>/dev/null || echo 000
}

begin_suite "5f2q-upload-token-action-scope"

# --- setup: admin, a non-admin user with repo write, read + write tokens -----
auth_admin   # sets ADMIN_TOKEN

USER_ID="$(create_test_user_with_retry "$USER" "$USER_PASS" "${USER}@t.test")" || true
if [ -z "$USER_ID" ] || [ "$USER_ID" = "null" ]; then
  begin_test "setup: create non-admin user"
  infra_fail "could not create user ${USER}"
  end_suite
fi

USER_TOKEN="$(login_as "$USER" "$USER_PASS")" || true
if [ -z "$USER_TOKEN" ]; then
  begin_test "setup: login non-admin user"
  infra_fail "could not log in as ${USER}"
  end_suite
fi

# A PRIVATE repo the user will hold write RBAC on.
if ! api_post "/api/v1/repositories" \
  "{\"key\":\"${REPO}\",\"name\":\"${REPO}\",\"format\":\"maven\",\"repo_type\":\"local\",\"is_public\":false}" >/dev/null 2>&1; then
  begin_test "setup: create private repo"
  infra_fail "could not create repo ${REPO}"
  end_suite
fi
# Grant the user developer(write) on the repo, so the OWNER genuinely holds repo
# write — the whole point of the advisory is that a READ token of such an owner
# must still be blocked by action-scope, not by repo-RBAC.
docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "
  INSERT INTO role_assignments (user_id, role_id, repository_id)
  SELECT u.id, r.id, repo.id FROM users u, roles r, repositories repo
  WHERE u.username='${USER}' AND r.name='developer' AND repo.key='${REPO}'
  ON CONFLICT DO NOTHING;" >/dev/null 2>&1 || true

# Scope vocabulary: the granular action:resource form (#2989 parent rule,
# #2996 mint validation). The bare pre-1.7.0 names ("read"/"write") were
# removed from the backend's ALLOWED_SCOPES, so minting them now 400s
# VALIDATION_ERROR and this oracle would die at setup with two empty tokens —
# which is exactly how it false-failed the 1.7.0-rc.2 gate. The property under
# test is unchanged and strictly stronger in colon form: a token that may only
# READ artifacts must not be able to drive any chunked-upload write verb.
READ_SCOPE="read:artifacts"
WRITE_SCOPE="write:artifacts"

MINT_LAST_BODY=""
mint_token() { # SCOPE_JSON  -> prints token
  local scopes="$1"
  MINT_LAST_BODY="$(curl -s $CURL_TIMEOUT -X POST "${BASE_URL}/api/v1/auth/tokens" \
    -H "Authorization: Bearer ${USER_TOKEN}" -H 'Content-Type: application/json' \
    -d "{\"name\":\"5f2q-${scopes//[^a-z]/}-${SUF}\",\"scopes\":${scopes}}" 2>/dev/null || true)"
  echo "$MINT_LAST_BODY" | jq -r '.token // empty' 2>/dev/null || true
}
READ_TOKEN="$(mint_token "[\"${READ_SCOPE}\"]")"; MINT_READ_BODY="$MINT_LAST_BODY"
WRITE_TOKEN="$(mint_token "[\"${WRITE_SCOPE}\"]")"; MINT_WRITE_BODY="$MINT_LAST_BODY"
if [ -z "$READ_TOKEN" ] || [ -z "$WRITE_TOKEN" ]; then
  # INFRA, not a verdict: with no probe tokens the oracle never reaches an
  # upload verb, so it has learned NOTHING about the candidate's scope
  # enforcement. Report it as such (#323) instead of as a regression.
  begin_test "setup: mint ${READ_SCOPE} + ${WRITE_SCOPE} tokens"
  infra_fail "could not mint scoped probe tokens (read='${READ_TOKEN:0:8}' write='${WRITE_TOKEN:0:8}'); the tier never probed an upload verb" \
             "POST /api/v1/auth/tokens [${READ_SCOPE}] -> ${MINT_READ_BODY:0:300}
POST /api/v1/auth/tokens [${WRITE_SCOPE}] -> ${MINT_WRITE_BODY:0:300}"
  end_suite
fi

# ---------------------------------------------------------------------------
# (CONTROL) WRITE-scoped token -> create_session 201. Proves the legit push
#           path is unchanged and yields the session the read-token
#           append/complete boundary probes reuse (same owner => same session
#           ownership, so only ACTION-scope, not ownership, gates them).
# ---------------------------------------------------------------------------
begin_test "CONTROL: write-scoped token POST /uploads -> 201 (legit chunked-upload init unchanged)"
WRITE_BODY="$(create_session_body "$WRITE_TOKEN" "$WRITE_PATH")"
SESSION_ID="$(echo "$WRITE_BODY" | jq -r '.session_id // empty' 2>/dev/null || true)"
if [ -n "$SESSION_ID" ] && [ "$SESSION_ID" != "null" ]; then
  pass
else
  fail "write-scoped create_session did not return a session_id (legit path broken)" "resp=${WRITE_BODY:0:300}"
  SESSION_ID=""
fi

# ---------------------------------------------------------------------------
# (BOUNDARY) READ-scoped token -> each write verb 403 (GREEN). Baseline: 2xx.
# ---------------------------------------------------------------------------
begin_test "BOUNDARY: read-scoped token POST /uploads (create_session) -> 403 required-scope:write:artifacts"
RC="$(create_session_code "$READ_TOKEN" "$READ_PATH")"
if [ "$RC" = "403" ]; then
  pass
elif [ "$RC" = "401" ]; then
  fail "read-token create_session returned 401 (unauthenticated) — the token must authenticate; expected 403 scope-denied" "code=${RC}"
else
  fail "SCOPE BYPASS (GHSA-5f2q): read-scoped token create_session returned ${RC}, expected 403. A read-only token pushed a chunked upload (baseline had no action-scope gate on /uploads)." \
       "code=${RC} owner=${USER} readPath=${READ_PATH}"
fi

# DB assert: on the fixed image the read-token create left NO session row for
# READ_PATH; on baseline the 2xx create persisted exactly one.
begin_test "BOUNDARY(DB): read-scoped create_session persisted NO upload_sessions row (fix) — baseline leaves one"
ROWS="$(docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "
  SELECT count(*) FROM upload_sessions us JOIN repositories r ON r.id=us.repository_id
  WHERE r.key='${REPO}' AND us.artifact_path='${READ_PATH}';" 2>/dev/null | tr -d '[:space:]' || true)"
if [ "$ROWS" = "0" ]; then
  pass
else
  fail "read-scoped create_session persisted ${ROWS} upload_sessions row(s) for ${READ_PATH}; a scope-denied create must write none" \
       "rows=${ROWS} repo=${REPO} path=${READ_PATH}"
fi

# upload_chunk (append) with the read token against the write-created session.
begin_test "BOUNDARY: read-scoped token PATCH /uploads/:id (upload_chunk) -> 403 required-scope:write:artifacts"
if [ -n "$SESSION_ID" ]; then
  UC="$(upload_chunk_code "$READ_TOKEN" "$SESSION_ID")"
  if [ "$UC" = "403" ]; then
    pass
  else
    fail "SCOPE BYPASS (GHSA-5f2q): read-scoped upload_chunk returned ${UC}, expected 403. A read-only token appended chunk bytes to a session (same owner => ownership passes; only action-scope should stop it)." \
         "code=${UC} session=${SESSION_ID}"
  fi
else
  fail "no session_id from the write-token control; cannot probe read-token upload_chunk"
fi

# complete with the read token.
begin_test "BOUNDARY: read-scoped token PUT /uploads/:id/complete -> 403 required-scope:write:artifacts"
if [ -n "$SESSION_ID" ]; then
  CC="$(complete_code "$READ_TOKEN" "$SESSION_ID")"
  if [ "$CC" = "403" ]; then
    pass
  else
    fail "SCOPE BYPASS (GHSA-5f2q): read-scoped complete returned ${CC}, expected 403 (a read token must not finalize a chunked upload)." \
         "code=${CC} session=${SESSION_ID}"
  fi
else
  fail "no session_id from the write-token control; cannot probe read-token complete"
fi

# cancel with the read token — needs the "delete" scope, which read lacks.
begin_test "BOUNDARY: read-scoped token DELETE /uploads/:id (cancel) -> 403 required-scope:delete"
if [ -n "$SESSION_ID" ]; then
  XC="$(cancel_code "$READ_TOKEN" "$SESSION_ID")"
  if [ "$XC" = "403" ]; then
    pass
  else
    fail "SCOPE BYPASS (GHSA-5f2q): read-scoped cancel returned ${XC}, expected 403 (cancel requires the delete scope; a read token must not destroy a session)." \
         "code=${XC} session=${SESSION_ID}"
  fi
else
  fail "no session_id from the write-token control; cannot probe read-token cancel"
fi

end_suite
