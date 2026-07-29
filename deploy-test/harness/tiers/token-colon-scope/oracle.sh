#!/usr/bin/env bash
# =============================================================================
# tiers/token-colon-scope/oracle.sh — repo-scoped token colon-scope match (#2989)
# =============================================================================
# run.sh has stood up the `filesystem` profile-set with RATE_LIMIT_ENABLED=false
# and exported BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID,
# RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH. We source common.sh for the
# assertion + JUnit harness, then drive the real HTTP flow against the backend.
#
# The bug (#2989): repo-scoped tokens carry colon-form scopes
# (`write:artifacts`) while the artifact upload/mutation handlers required the
# bare `write` scope — the vocabularies never matched, so a least-privilege
# repo-scoped write token was 403'd on its own repo's upload path.
#
# Discriminating gates:
#   (MAIN)     repo-scoped `write:artifacts` token PUT
#              /repositories/:key/artifacts/*path -> 201 (GREEN). On the
#              pre-fix baseline this returns 403 (RED) with
#              "required scope: write". DB assert: the artifact row exists.
#   (CONTROL)  personal LEGACY bare `write` token -> same PUT 2xx on BOTH
#              images (bare-parent rule; legacy vocabulary keeps working).
#              #2996/#3001 refuse a bare parent at the mint choke-point, so the
#              control row is minted canonically then downgraded in the DB to
#              stand in for a token persisted before that fix.
#   (BOUNDARY) `write:artifacts` token must NOT gain anything else:
#              settings write (PATCH /repositories/:key, bare `write` gate)
#              -> 403; upload to a DIFFERENT repo -> denied (binding intact);
#              repo-scoped `read:artifacts` token upload -> 403 + no DB row.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

SUF="${RUN_ID##*-}-$$"
REPO_A="tcs-a-${DTF_SLOT:-x}-${SUF}"
REPO_B="tcs-b-${DTF_SLOT:-x}-${SUF}"
USER="tcs-user-${DTF_SLOT:-x}-${SUF}"
USER_PASS="Tcs_${SUF}_Aa1!"

WA_PATH="uploads/tcs-wa-${SUF}.bin"     # write:artifacts token (MAIN)
CTL_PATH="uploads/tcs-ctl-${SUF}.bin"   # bare write token (CONTROL)
XREPO_PATH="uploads/tcs-x-${SUF}.bin"   # cross-repo probe
RA_PATH="uploads/tcs-ra-${SUF}.bin"     # read:artifacts probe

PAYLOAD="token-colon-scope-probe-${SUF}"

# --- curl helpers -----------------------------------------------------------
upload_code() { # BEARER REPO PATH -> http code of PUT /repositories/:key/artifacts/*path
  curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X PUT \
    "${BASE_URL}/api/v1/repositories/${2}/artifacts/${3}" \
    -H "Authorization: Bearer ${1}" \
    -H 'Content-Type: application/octet-stream' \
    --data-binary "$PAYLOAD" 2>/dev/null || echo 000
}
upload_body() { # BEARER REPO PATH -> response body
  curl -s $CURL_TIMEOUT -X PUT \
    "${BASE_URL}/api/v1/repositories/${2}/artifacts/${3}" \
    -H "Authorization: Bearer ${1}" \
    -H 'Content-Type: application/octet-stream' \
    --data-binary "$PAYLOAD" 2>/dev/null || true
}
settings_patch_code() { # BEARER REPO -> http code of PATCH /repositories/:key
  curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X PATCH \
    "${BASE_URL}/api/v1/repositories/${2}" \
    -H "Authorization: Bearer ${1}" -H 'Content-Type: application/json' \
    -d '{"description":"tcs-should-be-denied"}' 2>/dev/null || echo 000
}
artifact_rows() { # REPO PATH -> row count
  docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "
    SELECT count(*) FROM artifacts a JOIN repositories r ON r.id=a.repository_id
    WHERE r.key='${1}' AND a.path='${2}';" 2>/dev/null | tr -d '[:space:]' || true
}

begin_suite "token-colon-scope-2989"

# --- setup: admin, non-admin user with repo write on A and B ----------------
auth_admin   # sets ADMIN_TOKEN

USER_ID="$(create_test_user_with_retry "$USER" "$USER_PASS" "${USER}@t.test")" || true
if [ -z "$USER_ID" ] || [ "$USER_ID" = "null" ]; then
  begin_test "setup: create non-admin user"
  fail "could not create user ${USER}"
  end_suite
fi

USER_TOKEN="$(login_as "$USER" "$USER_PASS")" || true
if [ -z "$USER_TOKEN" ]; then
  begin_test "setup: login non-admin user"
  fail "could not log in as ${USER}"
  end_suite
fi

for R in "$REPO_A" "$REPO_B"; do
  if ! api_post "/api/v1/repositories" \
    "{\"key\":\"${R}\",\"name\":\"${R}\",\"format\":\"maven\",\"repo_type\":\"local\",\"is_public\":false}" >/dev/null 2>&1; then
    begin_test "setup: create private repo ${R}"
    fail "could not create repo ${R}"
    end_suite
  fi
done

# The user genuinely holds write RBAC on BOTH repos: the cross-repo boundary
# below must be decided by the TOKEN's repo binding, not by missing user RBAC.
docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "
  INSERT INTO role_assignments (user_id, role_id, repository_id)
  SELECT u.id, r.id, repo.id FROM users u, roles r, repositories repo
  WHERE u.username='${USER}' AND r.name='developer'
    AND repo.key IN ('${REPO_A}','${REPO_B}')
  ON CONFLICT DO NOTHING;" >/dev/null 2>&1 || true

# Repo-scoped tokens on REPO_A (colon-form vocabulary — the #2989 flow).
mint_repo_token() { # SCOPE -> prints token
  curl -s $CURL_TIMEOUT -X POST "${BASE_URL}/api/v1/repositories/${REPO_A}/tokens" \
    -H "Authorization: Bearer ${USER_TOKEN}" -H 'Content-Type: application/json' \
    -d "{\"name\":\"tcs-${1//[^a-z]/}-${SUF}\",\"scopes\":[\"${1}\"]}" 2>/dev/null \
    | jq -r '.token // empty' 2>/dev/null || true
}
WA_TOKEN="$(mint_repo_token 'write:artifacts')"
RA_TOKEN="$(mint_repo_token 'read:artifacts')"

# Personal token carrying the LEGACY BARE vocabulary. #2996/#3001 closed the
# mint choke-point, so a bare parent is no longer mintable over HTTP (400) —
# but tokens minted BEFORE that fix are still persisted and presented, and they
# are exactly the population the #2989 bare-parent rule must keep serving. Mint
# a canonical token (accepted by the mint validator) and rewrite its PERSISTED
# scope array to the bare parent, reproducing a pre-#3001 row without depending
# on the token-hash scheme.
CTL_NAME="tcs-barewrite-${SUF}"
CTL_TOKEN="$(curl -s $CURL_TIMEOUT -X POST "${BASE_URL}/api/v1/auth/tokens" \
  -H "Authorization: Bearer ${USER_TOKEN}" -H 'Content-Type: application/json' \
  -d "{\"name\":\"${CTL_NAME}\",\"scopes\":[\"write:artifacts\"]}" 2>/dev/null \
  | jq -r '.token // empty' 2>/dev/null || true)"

CTL_LEGACY="$(docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "
  UPDATE api_tokens SET scopes = ARRAY['write']::varchar[]
  WHERE name='${CTL_NAME}' RETURNING 1;" 2>/dev/null | head -1 | tr -d '[:space:]' || true)"

if [ -z "$WA_TOKEN" ] || [ -z "$RA_TOKEN" ] || [ -z "$CTL_TOKEN" ]; then
  begin_test "setup: mint write:artifacts + read:artifacts repo tokens + legacy bare-write token"
  fail "could not mint tokens (wa='${WA_TOKEN:0:8}' ra='${RA_TOKEN:0:8}' ctl='${CTL_TOKEN:0:8}')"
  end_suite
fi

if [ "$CTL_LEGACY" != "1" ]; then
  begin_test "setup: downgrade the CONTROL token to the legacy bare 'write' scope"
  fail "could not rewrite api_tokens.scopes to the bare parent for ${CTL_NAME} (returned '${CTL_LEGACY}')"
  end_suite
fi

# ---------------------------------------------------------------------------
# (MAIN) repo-scoped write:artifacts token uploads to ITS repo. RED on the
# pre-fix baseline (403 "required scope: write"), GREEN on the fix (201).
# ---------------------------------------------------------------------------
begin_test "MAIN: repo-scoped write:artifacts token PUT artifact on its repo -> 2xx (baseline: 403 vocabulary mismatch)"
RC="$(upload_code "$WA_TOKEN" "$REPO_A" "$WA_PATH")"
if [ "$RC" = "200" ] || [ "$RC" = "201" ]; then
  pass
else
  BODY="$(upload_body "$WA_TOKEN" "$REPO_A" "${WA_PATH}.retry")"
  fail "VOCABULARY MISMATCH (#2989): write:artifacts repo token got ${RC} on upload to its own repo; the least-privilege repo-scoped-token flow is broken" \
       "code=${RC} body=${BODY:0:200}"
fi

begin_test "MAIN(DB): the write:artifacts upload persisted the artifact row"
ROWS="$(artifact_rows "$REPO_A" "$WA_PATH")"
if [ "$ROWS" = "1" ]; then
  pass
else
  fail "expected exactly 1 artifacts row for ${WA_PATH}, found '${ROWS}'" \
       "rows=${ROWS} repo=${REPO_A} path=${WA_PATH}"
fi

# ---------------------------------------------------------------------------
# (MAIN-FORMAT) the PRIMARY #2989 use case: CI publishing through a package
# manager. The basic-auth format handlers (`require_auth_basic_scope`) carry
# the same vocabulary fix, exercised here via maven PUT with the token as the
# Basic password (`token:<api_token>`, the pip-netrc/Artifactory shape).
# RED on the pre-fix baseline (403), GREEN on the fix (2xx).
# ---------------------------------------------------------------------------
maven_put_code() { # TOKEN REPO PATH
  curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X PUT \
    "${BASE_URL}/maven/${2}/${3}" \
    -u "token:${1}" -H 'Content-Type: application/octet-stream' \
    --data-binary "$PAYLOAD" 2>/dev/null || echo 000
}
MVN_PATH="com/tcs/app/1.0/app-1.0-${SUF}.jar"

begin_test "MAIN-FORMAT: repo-scoped write:artifacts token maven PUT (basic auth) -> 2xx (baseline: 403)"
RC="$(maven_put_code "$WA_TOKEN" "$REPO_A" "$MVN_PATH")"
if [ "$RC" = "200" ] || [ "$RC" = "201" ]; then
  pass
else
  fail "VOCABULARY MISMATCH (#2989, basic-auth path): write:artifacts token got ${RC} on maven publish to its own repo (CI package-manager flow broken)" \
       "code=${RC}"
fi

begin_test "BOUNDARY-FORMAT: write:artifacts token maven PUT on OTHER repo -> denied (401/403/404)"
RC="$(maven_put_code "$WA_TOKEN" "$REPO_B" "$MVN_PATH")"
if [ "$RC" = "401" ] || [ "$RC" = "403" ] || [ "$RC" = "404" ]; then
  pass
else
  fail "REPO-BINDING BYPASS (basic-auth path): repo-A-scoped token got ${RC} on maven publish to repo B" "code=${RC}"
fi

begin_test "BOUNDARY-FORMAT: read:artifacts token maven PUT -> denied (401/403)"
RC="$(maven_put_code "$RA_TOKEN" "$REPO_A" "another-${MVN_PATH}")"
if [ "$RC" = "401" ] || [ "$RC" = "403" ]; then
  pass
else
  fail "READ-TO-WRITE ESCALATION (basic-auth path): read:artifacts token got ${RC} on maven publish" "code=${RC}"
fi

begin_test "CONTROL-FORMAT: personal bare-write token maven PUT -> 2xx (legacy vocabulary unchanged)"
RC="$(maven_put_code "$CTL_TOKEN" "$REPO_A" "ctl-${MVN_PATH}")"
if [ "$RC" = "200" ] || [ "$RC" = "201" ]; then
  pass
else
  fail "bare-write token maven publish returned ${RC}; parent rule regressed on the basic-auth path" "code=${RC}"
fi

# ---------------------------------------------------------------------------
# (CONTROL) personal bare `write` token still uploads on BOTH images — the
# bare-parent rule keeps the legacy vocabulary working (no regression).
# ---------------------------------------------------------------------------
begin_test "CONTROL: personal bare-write token PUT artifact -> 2xx (legacy vocabulary unchanged)"
RC="$(upload_code "$CTL_TOKEN" "$REPO_A" "$CTL_PATH")"
if [ "$RC" = "200" ] || [ "$RC" = "201" ]; then
  pass
else
  fail "bare-write token upload returned ${RC}; broad-covers-specific parent rule regressed" "code=${RC}"
fi

# ---------------------------------------------------------------------------
# (BOUNDARY) write:artifacts must NOT satisfy the bare `write` gate on
# settings-class handlers: PATCH /repositories/:key -> 403 on BOTH images.
# ---------------------------------------------------------------------------
begin_test "BOUNDARY: write:artifacts token PATCH /repositories/:key (settings write) -> 403"
RC="$(settings_patch_code "$WA_TOKEN" "$REPO_A")"
if [ "$RC" = "403" ]; then
  pass
else
  fail "OVER-BROADENING: write:artifacts token got ${RC} on a settings write (expected 403); specific must never satisfy bare/different-resource" \
       "code=${RC}"
fi

# ---------------------------------------------------------------------------
# (BOUNDARY) repo binding intact: the REPO_A-bound token cannot upload to
# REPO_B even though its OWNER holds write RBAC there. 403 (scope-restricted
# token repo set) or 404 (existence hiding) are both denials.
# ---------------------------------------------------------------------------
begin_test "BOUNDARY: write:artifacts token bound to repo A PUT artifact on repo B -> denied (403/404)"
RC="$(upload_code "$WA_TOKEN" "$REPO_B" "$XREPO_PATH")"
if [ "$RC" = "403" ] || [ "$RC" = "404" ]; then
  pass
else
  fail "REPO-BINDING BYPASS: repo-A-scoped token got ${RC} uploading to repo B (expected 403/404)" \
       "code=${RC} repoB=${REPO_B}"
fi

begin_test "BOUNDARY(DB): the cross-repo probe persisted NO artifact row on repo B"
ROWS="$(artifact_rows "$REPO_B" "$XREPO_PATH")"
if [ "$ROWS" = "0" ]; then
  pass
else
  fail "cross-repo upload persisted ${ROWS} row(s) on ${REPO_B}; a denied upload must write none" \
       "rows=${ROWS}"
fi

# ---------------------------------------------------------------------------
# (BOUNDARY) read-family tokens never satisfy the write gate.
# ---------------------------------------------------------------------------
begin_test "BOUNDARY: repo-scoped read:artifacts token PUT artifact -> 403"
RC="$(upload_code "$RA_TOKEN" "$REPO_A" "$RA_PATH")"
if [ "$RC" = "403" ]; then
  pass
else
  fail "READ-TO-WRITE ESCALATION: read:artifacts token got ${RC} on upload (expected 403)" "code=${RC}"
fi

begin_test "BOUNDARY(DB): the read-token probe persisted NO artifact row"
ROWS="$(artifact_rows "$REPO_A" "$RA_PATH")"
if [ "$ROWS" = "0" ]; then
  pass
else
  fail "read-token upload persisted ${ROWS} row(s); a scope-denied upload must write none" "rows=${ROWS}"
fi

end_suite
