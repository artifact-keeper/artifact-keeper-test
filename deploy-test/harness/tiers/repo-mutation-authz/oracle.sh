#!/usr/bin/env bash
# =============================================================================
# tiers/repo-mutation-authz/oracle.sh — repository mutation-authz choke-point (#2603 G1)
# =============================================================================
# run.sh has stood up the `filesystem` profile-set with RATE_LIMIT_ENABLED=false
# and exported BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID,
# RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH. We source common.sh for the
# assertion + JUnit harness, then drive the real HTTP flow against the backend.
#
# The bug (#2603 G1, HIGH): on a PUBLIC repository with NO fine-grained rules,
# the native format write path had no action gate — any authenticated caller
# could PUT/POST/DELETE artifacts (cross-tenant write). The fix routes every
# mutation through `check_repository_action`, deny-by-default: `is_public` is a
# read baseline only; a write needs an action-granting role (or allowing rule).
#
# Discriminating gates (PUBLIC rules-less maven repo):
#   (CONTROL)  developer-MEMBER native maven PUT -> 201 (legit push unchanged).
#   (BOUNDARY) authenticated NON-member native maven PUT -> 403 (GREEN). Baseline
#              returns 201/200 (RED — write succeeds without a grant). DB assert:
#              non-member PUT persisted 0 artifacts rows on the fix vs 1 baseline.
#   (READ)     anonymous GET of the member-pushed artifact -> 200 (public read
#              baseline intact; the fix restricts writes only).
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

SUF="${RUN_ID##*-}-$$"
REPO="rma-repo-${DTF_SLOT:-x}-${SUF}"
MEMBER="rma-member-${DTF_SLOT:-x}-${SUF}"
NONMEMBER="rma-outsider-${DTF_SLOT:-x}-${SUF}"
PASS_MEMBER="Rma_${SUF}_Aa1!"
PASS_OUTSIDER="Rma_${SUF}_Bb2!"

# Distinct maven coordinates so the member-push and non-member-push never alias.
MEMBER_PATH="com/example/rma/1.0.0/rma-1.0.0.jar"
OUTSIDER_PATH="com/evil/rma/9.9.9/rma-9.9.9.jar"
MEMBER_BODY="rma-member-legit-${SUF}"
OUTSIDER_BODY="rma-outsider-poison-${SUF}"

# A separate PUBLIC git-lfs repo for the download-vs-upload discriminator below.
# git-lfs POST /objects/batch is a write HTTP method but the DOWNLOAD batch is a
# read (the mandatory `git lfs pull` negotiation); only the UPLOAD batch is a
# write. A method-based mutation gate that 403s the whole POST breaks download
# negotiation for read-only members / public-repo non-members.
LFS_REPO="rma-lfs-${DTF_SLOT:-x}-${SUF}"
# Any valid 64-char lowercase-hex OID; the object need not exist for the batch
# response to be HTTP 200 (a missing object is a per-object 404 inside the body).
LFS_OID="$(printf 'rma-lfs-%s' "$SUF" | sha256sum | cut -c1-64)"

# native maven PUT: returns just the HTTP code
maven_put_code() { # BEARER PATH BODY
  curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X PUT \
    "${BASE_URL}/maven/${REPO}/${2}" \
    -H "Authorization: Bearer ${1}" \
    -H 'Content-Type: application/octet-stream' \
    --data-binary "${3}" 2>/dev/null || echo 000
}
# anonymous native maven GET: returns just the HTTP code
maven_get_anon_code() { # PATH
  curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    "${BASE_URL}/maven/${REPO}/${1}" 2>/dev/null || echo 000
}
# native git-lfs batch POST: returns just the HTTP code
lfs_batch_code() { # BEARER OPERATION
  curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X POST \
    "${BASE_URL}/lfs/${LFS_REPO}/objects/batch" \
    -H "Authorization: Bearer ${1}" \
    -H 'Content-Type: application/vnd.git-lfs+json' \
    --data "{\"operation\":\"${2}\",\"transfers\":[\"basic\"],\"objects\":[{\"oid\":\"${LFS_OID}\",\"size\":11}]}" \
    2>/dev/null || echo 000
}

begin_suite "repo-mutation-authz-2603-g1"

# --- setup: admin, a member (developer role) and an unrelated non-member ------
auth_admin   # sets ADMIN_TOKEN

MEMBER_ID="$(create_test_user_with_retry "$MEMBER" "$PASS_MEMBER" "${MEMBER}@t.test")" || true
OUT_ID="$(create_test_user_with_retry "$NONMEMBER" "$PASS_OUTSIDER" "${NONMEMBER}@t.test")" || true
if [ -z "$MEMBER_ID" ] || [ "$MEMBER_ID" = "null" ] || [ -z "$OUT_ID" ] || [ "$OUT_ID" = "null" ]; then
  begin_test "setup: create member + non-member users"
  fail "could not create users (member='${MEMBER_ID}' outsider='${OUT_ID}')"
  end_suite
fi

MEMBER_TOKEN="$(login_as "$MEMBER" "$PASS_MEMBER")" || true
OUT_TOKEN="$(login_as "$NONMEMBER" "$PASS_OUTSIDER")" || true
if [ -z "$MEMBER_TOKEN" ] || [ -z "$OUT_TOKEN" ]; then
  begin_test "setup: login member + non-member"
  fail "could not log in (member='${MEMBER_TOKEN:0:8}' outsider='${OUT_TOKEN:0:8}')"
  end_suite
fi

# A PUBLIC maven local repo with NO fine-grained rules — the exact headline
# shape: public visibility, rules-less, so the only pre-fix gate was "is authed".
if ! api_post "/api/v1/repositories" \
  "{\"key\":\"${REPO}\",\"name\":\"${REPO}\",\"format\":\"maven\",\"repo_type\":\"local\",\"is_public\":true}" >/dev/null 2>&1; then
  begin_test "setup: create public rules-less maven repo"
  fail "could not create repo ${REPO}"
  end_suite
fi

# Grant the MEMBER the developer(read+write) role on the repo — a genuine
# write-holding member whose legit push must remain 201 after the fix.
docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "
  INSERT INTO role_assignments (user_id, role_id, repository_id)
  SELECT u.id, r.id, repo.id FROM users u, roles r, repositories repo
  WHERE u.username='${MEMBER}' AND r.name='developer' AND repo.key='${REPO}'
  ON CONFLICT DO NOTHING;" >/dev/null 2>&1 || true

# A PUBLIC, rules-less git-lfs repo for the LFS download-vs-upload discriminator.
# The NON-member (no write grant) is the caller for both LFS batch probes below.
if ! api_post "/api/v1/repositories" \
  "{\"key\":\"${LFS_REPO}\",\"name\":\"${LFS_REPO}\",\"format\":\"gitlfs\",\"repo_type\":\"local\",\"is_public\":true}" >/dev/null 2>&1; then
  begin_test "setup: create public rules-less git-lfs repo"
  fail "could not create repo ${LFS_REPO}"
  end_suite
fi

# ---------------------------------------------------------------------------
# (CONTROL) developer-MEMBER native maven PUT -> 201. Legit write-holding member
#           push must be unchanged by the deny-by-default fix.
# ---------------------------------------------------------------------------
begin_test "CONTROL: developer-member native maven PUT -> 201 (legit push unchanged)"
MC="$(maven_put_code "$MEMBER_TOKEN" "$MEMBER_PATH" "$MEMBER_BODY")"
if [ "$MC" = "201" ] || [ "$MC" = "200" ]; then
  pass
else
  fail "developer-member maven PUT returned ${MC}, expected 201/200 (legit member push broken by the fix)" \
       "code=${MC} repo=${REPO} path=${MEMBER_PATH}"
fi

# ---------------------------------------------------------------------------
# (READ) anonymous GET of the member-pushed artifact on the PUBLIC repo -> 200.
#        Proves the public read baseline is intact (the fix restricts writes).
# ---------------------------------------------------------------------------
begin_test "READ: anonymous GET of member-pushed artifact on public repo -> 200 (read baseline intact)"
RG="$(maven_get_anon_code "$MEMBER_PATH")"
if [ "$RG" = "200" ]; then
  pass
else
  fail "anonymous GET of a public-repo artifact returned ${RG}, expected 200 (public read must survive the write fix)" \
       "code=${RG} repo=${REPO} path=${MEMBER_PATH}"
fi

# ---------------------------------------------------------------------------
# (BOUNDARY) authenticated NON-member native maven PUT -> 403 (GREEN).
#            Baseline: 201/200 (RED — the write succeeds with no grant).
# ---------------------------------------------------------------------------
begin_test "BOUNDARY: authenticated NON-member native maven PUT to public rules-less repo -> 403"
OC="$(maven_put_code "$OUT_TOKEN" "$OUTSIDER_PATH" "$OUTSIDER_BODY")"
if [ "$OC" = "403" ]; then
  pass
elif [ "$OC" = "401" ]; then
  fail "non-member maven PUT returned 401 (unauthenticated); the token must authenticate — expected 403 authz-denied" "code=${OC}"
else
  fail "MUTATION-AUTHZ BYPASS (#2603 G1): non-member maven PUT to a PUBLIC rules-less repo returned ${OC}, expected 403. An authenticated caller with no write grant wrote an artifact (public visibility was treated as a write grant)." \
       "code=${OC} outsider=${NONMEMBER} repo=${REPO} path=${OUTSIDER_PATH}"
fi

# DB assert: on the fix the non-member PUT left NO artifacts row; baseline
# persists exactly one at OUTSIDER_PATH.
begin_test "BOUNDARY(DB): non-member PUT persisted NO artifacts row (fix) — baseline leaves one"
ROWS="$(docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "
  SELECT count(*) FROM artifacts a JOIN repositories r ON r.id=a.repository_id
  WHERE r.key='${REPO}' AND a.path='${OUTSIDER_PATH}';" 2>/dev/null | tr -d '[:space:]' || true)"
if [ "$ROWS" = "0" ]; then
  pass
else
  fail "non-member PUT persisted ${ROWS} artifacts row(s) at ${OUTSIDER_PATH}; a denied write must write none" \
       "rows=${ROWS} repo=${REPO} path=${OUTSIDER_PATH}"
fi

# ---------------------------------------------------------------------------
# (LFS-DOWNLOAD) authenticated NON-member git-lfs DOWNLOAD batch -> 200 (GREEN).
#   The batch POST is the mandatory `git lfs pull` negotiation. A method-based
#   mutation gate that treats every POST as a write 403s this read for a caller
#   with no write grant (RED, the over-restriction regression). The fix
#   classifies the batch POST as non-mutating so the handler self-gates: DOWNLOAD
#   reaches the handler (200) and UPLOAD stays write-gated (next assertion). This
#   probe is discriminating against BOTH the vulnerable pre-#2603 baseline (which
#   never gated batch at all) and the over-restrictive method-only gate (403).
# ---------------------------------------------------------------------------
begin_test "LFS-DOWNLOAD: non-member git-lfs download batch on public rules-less repo -> 200 (read negotiation not blocked)"
LDC="$(lfs_batch_code "$OUT_TOKEN" "download")"
if [ "$LDC" = "200" ]; then
  pass
elif [ "$LDC" = "403" ]; then
  fail "OVER-RESTRICTION: non-member git-lfs DOWNLOAD batch returned 403; the download negotiation is a read and must reach the handler (git lfs pull broken for read-only members / public-repo non-members)" \
       "code=${LDC} repo=${LFS_REPO} op=download"
else
  fail "non-member git-lfs DOWNLOAD batch returned ${LDC}, expected 200" \
       "code=${LDC} repo=${LFS_REPO} op=download"
fi

# ---------------------------------------------------------------------------
# (LFS-UPLOAD) authenticated NON-member git-lfs UPLOAD batch -> 403 (GREEN).
#   The upload negotiation IS a repository write; exempting the batch POST from
#   the middleware write gate must not open an upload hole. The batch handler
#   self-gates uploads through the same deny-by-default action choke-point, so a
#   non-member (no write grant) is still 403 on operation=upload. Same caller and
#   repo as LFS-DOWNLOAD above: download 200 vs upload 403 is the discriminator.
# ---------------------------------------------------------------------------
begin_test "LFS-UPLOAD: non-member git-lfs upload batch on public rules-less repo -> 403 (write gate holds)"
LUC="$(lfs_batch_code "$OUT_TOKEN" "upload")"
if [ "$LUC" = "403" ]; then
  pass
elif [ "$LUC" = "200" ]; then
  fail "MUTATION-AUTHZ BYPASS: non-member git-lfs UPLOAD batch returned 200; the download exemption must not open upload negotiation to a caller with no write grant" \
       "code=${LUC} repo=${LFS_REPO} op=upload"
else
  fail "non-member git-lfs UPLOAD batch returned ${LUC}, expected 403" \
       "code=${LUC} repo=${LFS_REPO} op=upload"
fi

end_suite
