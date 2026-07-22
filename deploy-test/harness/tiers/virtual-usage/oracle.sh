#!/usr/bin/env bash
# =============================================================================
# tiers/virtual-usage/oracle.sh — virtual-repo dedup union + editability (#2785)
# =============================================================================
# run.sh has stood up the `filesystem` profile-set with RATE_LIMIT_ENABLED=false
# and exported BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID,
# RELEASE_GATE=1, JUNIT_OUTPUT_DIR. We source common.sh for the assertion + JUnit
# harness, then drive the real HTTP flow against the live backend.
#
# The feature (#2785): a virtual repo's aggregate over its members is the
# DEDUPLICATED union of the member leaves (shared bytes counted once, NOT
# double-counted), and the member set is EDITABLE after creation under a
# repository:admin gate. See the manifest header.
#
# Two discriminating gates, ALL sub-tests must hold:
#   (A) DEDUP UNION — V over {A,B} reports the shared coordinate once and its
#       aggregate == deduplicated union (< naive per-repo sum). API + DB-checked.
#   (B) EDITABLE    — repo-admin add/remove member persists; non-admin -> 403.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

SUF="${RUN_ID##*-}-$$"
SL="${DTF_SLOT:-x}"
A="vu-a-${SL}-${SUF}"
B="vu-b-${SL}-${SUF}"
C="vu-c-${SL}-${SUF}"
V="vu-virt-${SL}-${SUF}"

# Distinct, known-different byte strings. Shared is byte-identical in A and B at
# the SAME coordinate (so it dedups); each unique artifact is a different length.
SHARED_BYTES="VU-SHARED-CONTENT-${SUF}-PADDED-TO-BE-CLEARLY-LONGER-000000"
UNIQ_A_BYTES="VU-ONLY-A-${SUF}"
UNIQ_B_BYTES="VU-ONLY-B-${SUF}-EXTRA"
SHARED_COORD="com/vu/shared/1.0/shared-1.0-${SUF}.jar"
UNIQ_A_COORD="com/vu/onlya/1.0/onlya-1.0-${SUF}.jar"
UNIQ_B_COORD="com/vu/onlyb/1.0/onlyb-1.0-${SUF}.jar"

# non-admin (member-repo writer, NOT repo-admin) used by the 403 boundary test.
NADMIN="vu-writer-${SL}-${SUF}"
NADMIN_PASS="VuWriter_${SUF}_Aa1!"

# helpers --------------------------------------------------------------------
bearer_code() { # METHOD PATH TOKEN [BODY]
  local m="$1" p="$2" t="$3" b="${4:-}"
  if [ -n "$b" ]; then
    curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X "$m" \
      -H "Authorization: Bearer ${t}" -H 'Content-Type: application/octet-stream' \
      --data-binary "$b" "${BASE_URL}${p}" 2>/dev/null || echo 000
  else
    curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X "$m" \
      -H "Authorization: Bearer ${t}" "${BASE_URL}${p}" 2>/dev/null || echo 000
  fi
}
json_code() { # METHOD PATH TOKEN JSONBODY
  curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X "$1" \
    -H "Authorization: Bearer ${3}" -H 'Content-Type: application/json' \
    -d "${4}" "${BASE_URL}${2}" 2>/dev/null || echo 000
}
db1() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]'; }

begin_suite "virtual-usage-dedup-and-editable-2785"

auth_admin
TOK="$ADMIN_TOKEN"

# --- setup: A,B,V + shared/unique artifacts ---------------------------------
setup_ok=1
for k in "$A" "$B" "$C"; do
  api_post "/api/v1/repositories" \
    "{\"key\":\"${k}\",\"name\":\"${k}\",\"format\":\"maven\",\"repo_type\":\"local\",\"is_public\":true}" \
    >/dev/null 2>&1 || setup_ok=0
done
api_post "/api/v1/repositories" \
  "{\"key\":\"${V}\",\"name\":\"${V}\",\"format\":\"maven\",\"repo_type\":\"virtual\",\"is_public\":true}" \
  >/dev/null 2>&1 || setup_ok=0
# initial members {A,B}
json_code POST "/api/v1/repositories/${V}/members" "$TOK" "{\"member_key\":\"${A}\"}" >/dev/null
json_code POST "/api/v1/repositories/${V}/members" "$TOK" "{\"member_key\":\"${B}\"}" >/dev/null

# uploads: shared bytes to A AND B (same coord), unique to each.
c1="$(bearer_code PUT "/maven/${A}/${SHARED_COORD}" "$TOK" "$SHARED_BYTES")"
c2="$(bearer_code PUT "/maven/${B}/${SHARED_COORD}" "$TOK" "$SHARED_BYTES")"
c3="$(bearer_code PUT "/maven/${A}/${UNIQ_A_COORD}" "$TOK" "$UNIQ_A_BYTES")"
c4="$(bearer_code PUT "/maven/${B}/${UNIQ_B_COORD}" "$TOK" "$UNIQ_B_BYTES")"

begin_test "setup: repos created and 4 maven artifacts uploaded (2 shared coord + 2 unique)"
if [ "$setup_ok" = "1" ] && [ "$c1" = "201" ] && [ "$c2" = "201" ] && [ "$c3" = "201" ] && [ "$c4" = "201" ]; then
  pass
else
  fail "setup failed (repos_ok=${setup_ok} shared_a=${c1} shared_b=${c2} uniq_a=${c3} uniq_b=${c4})"
  end_suite
fi

# --- DB ground truth --------------------------------------------------------
RAW_SUM="$(db1 "SELECT COALESCE(SUM(size_bytes),0) FROM artifacts
  WHERE repository_id IN (SELECT id FROM repositories WHERE key IN ('${A}','${B}')) AND is_deleted=false;")"
DEDUP_UNION="$(db1 "WITH leaves AS (
    SELECT DISTINCT ON (checksum_sha256) checksum_sha256, size_bytes
      FROM artifacts
     WHERE repository_id IN (SELECT id FROM repositories WHERE key IN ('${A}','${B}')) AND is_deleted=false)
  SELECT COALESCE(SUM(size_bytes),0) FROM leaves;")"

# ---------------------------------------------------------------------------
# (A) DEDUP UNION
# ---------------------------------------------------------------------------
begin_test "DEDUP: DB shows shared content, so the deduplicated union is strictly < the naive per-repo sum"
if [[ "$RAW_SUM" =~ ^[0-9]+$ ]] && [[ "$DEDUP_UNION" =~ ^[0-9]+$ ]] && [ "$DEDUP_UNION" -lt "$RAW_SUM" ] && [ "$DEDUP_UNION" -gt 0 ]; then
  pass
else
  fail "expected 0 < dedup_union < raw_sum; got dedup_union=${DEDUP_UNION} raw_sum=${RAW_SUM} (no shared content ⇒ non-discriminating)"
fi

# The aggregated content API is the virtual repo's reported view over members.
V_ARTS="$(api_get "/api/v1/repositories/${V}/artifacts?per_page=100" 2>/dev/null || true)"
V_LIST_SUM="$(echo "$V_ARTS" | jq '[(.items // .)[].size_bytes] | add // 0' 2>/dev/null || echo "")"
SHARED_HITS="$(echo "$V_ARTS" | jq --arg p "$SHARED_COORD" '[(.items // .)[] | select(.path==$p)] | length' 2>/dev/null || echo "")"

begin_test "DEDUP: the virtual repo lists the shared coordinate EXACTLY ONCE (not once per member)"
if [ "$SHARED_HITS" = "1" ]; then
  pass
else
  fail "shared coordinate ${SHARED_COORD} appears ${SHARED_HITS} time(s) in ${V}'s aggregate, expected exactly 1 (double-listing = double-counting)" \
       "$(echo "$V_ARTS" | jq -c '[(.items // .)[].path]' 2>/dev/null)"
fi

begin_test "DEDUP: virtual aggregate size == deduplicated union (shared once), matching the DB, NOT the naive sum"
if [ "$V_LIST_SUM" = "$DEDUP_UNION" ] && [ "$V_LIST_SUM" != "$RAW_SUM" ]; then
  pass
else
  fail "virtual aggregate size ${V_LIST_SUM} != DB dedup_union ${DEDUP_UNION} (raw_sum ${RAW_SUM}); the union must count shared bytes once" \
       "v_list_sum=${V_LIST_SUM} dedup_union=${DEDUP_UNION} raw_sum=${RAW_SUM}"
fi

# Cross-check via the per-repo usage API: A.used + B.used must equal the naive
# raw sum (so the contrast with the deduped union is real, not a fluke).
A_USED="$(api_get "/api/v1/repositories/${A}" 2>/dev/null | jq -r '.storage_used_bytes // empty' 2>/dev/null || true)"
B_USED="$(api_get "/api/v1/repositories/${B}" 2>/dev/null | jq -r '.storage_used_bytes // empty' 2>/dev/null || true)"
begin_test "DEDUP cross-check: per-repo usage API sum (A+B) equals the naive raw sum, and exceeds the deduped virtual union"
if [[ "$A_USED" =~ ^[0-9]+$ ]] && [[ "$B_USED" =~ ^[0-9]+$ ]] && [ "$((A_USED + B_USED))" = "$RAW_SUM" ] && [ "$RAW_SUM" -gt "$DEDUP_UNION" ]; then
  pass
else
  fail "per-repo usage cross-check failed: A.used=${A_USED} B.used=${B_USED} sum=$((A_USED + B_USED)) raw_sum=${RAW_SUM} dedup_union=${DEDUP_UNION}"
fi

# ---------------------------------------------------------------------------
# (B) EDITABLE — repo-admin can change the member set; non-admin cannot.
# ---------------------------------------------------------------------------
members_count() { db1 "SELECT COUNT(*) FROM virtual_repo_members vrm
  JOIN repositories r ON r.id=vrm.virtual_repo_id WHERE r.key='${V}';"; }
member_present() { # member_key -> echoes count (0/1)
  db1 "SELECT COUNT(*) FROM virtual_repo_members vrm
    JOIN repositories vr ON vr.id=vrm.virtual_repo_id
    JOIN repositories mr ON mr.id=vrm.member_repo_id
    WHERE vr.key='${V}' AND mr.key='${1}';"; }

BEFORE_CNT="$(members_count)"
begin_test "EDITABLE: repo-admin ADDs member ${C} after creation -> 2xx and it persists (DB + members API)"
ADD_CODE="$(json_code POST "/api/v1/repositories/${V}/members" "$TOK" "{\"member_key\":\"${C}\"}")"
AFTER_ADD_CNT="$(members_count)"
C_IN_DB="$(member_present "$C")"
C_IN_API="$(api_get "/api/v1/repositories/${V}/members" 2>/dev/null | jq -r --arg k "$C" '[(.members // .items // .)[] | select(.member_repo_key==$k or .member_key==$k)] | length' 2>/dev/null || echo 0)"
if { [ "$ADD_CODE" = "200" ] || [ "$ADD_CODE" = "201" ]; } && [ "$C_IN_DB" = "1" ] && [ "$C_IN_API" = "1" ] && [ "$AFTER_ADD_CNT" -gt "$BEFORE_CNT" ]; then
  pass
else
  fail "add member failed: code=${ADD_CODE} c_in_db=${C_IN_DB} c_in_api=${C_IN_API} before=${BEFORE_CNT} after=${AFTER_ADD_CNT}"
fi

begin_test "EDITABLE: repo-admin REMOVEs member ${C} -> 200 and it is gone (DB + members API)"
DEL_CODE="$(bearer_code DELETE "/api/v1/repositories/${V}/members/${C}" "$TOK")"
AFTER_DEL_CNT="$(members_count)"
C_STILL_DB="$(member_present "$C")"
if [ "$DEL_CODE" = "200" ] && [ "$C_STILL_DB" = "0" ] && [ "$AFTER_DEL_CNT" = "$BEFORE_CNT" ]; then
  pass
else
  fail "remove member failed: code=${DEL_CODE} c_still_db=${C_STILL_DB} after_del=${AFTER_DEL_CNT} expected_back_to=${BEFORE_CNT}"
fi

# non-repo-admin: a user WITH developer(write) on V but WITHOUT repository:admin.
# The 403 must be the admin gate firing (not mere lack of access), so we grant
# write first and confirm the mutation is STILL refused.
NA_ID="$(create_test_user_with_retry "$NADMIN" "$NADMIN_PASS" "${NADMIN}@t.test")" || true
NA_TOK=""
[ -n "$NA_ID" ] && [ "$NA_ID" != "null" ] && NA_TOK="$(login_as "$NADMIN" "$NADMIN_PASS" || true)"
docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "
  INSERT INTO role_assignments (user_id, role_id, repository_id)
  SELECT u.id, r.id, repo.id FROM users u, roles r, repositories repo
  WHERE u.username='${NADMIN}' AND r.name='developer' AND repo.key='${V}'
  ON CONFLICT DO NOTHING;" >/dev/null 2>&1 || true

begin_test "EDITABLE boundary: a member-writer who is NOT repo-admin is REFUSED (403) adding a member, and the set is unchanged"
if [ -z "$NA_TOK" ]; then
  fail "could not set up non-admin writer ${NADMIN} (id=${NA_ID})"
else
  NA_ADD_CODE="$(json_code POST "/api/v1/repositories/${V}/members" "$NA_TOK" "{\"member_key\":\"${C}\"}")"
  UNCHANGED_CNT="$(members_count)"
  NA_C_DB="$(member_present "$C")"
  if [ "$NA_ADD_CODE" = "403" ] && [ "$UNCHANGED_CNT" = "$BEFORE_CNT" ] && [ "$NA_C_DB" = "0" ]; then
    pass
  else
    fail "non-repo-admin member edit was NOT properly refused: code=${NA_ADD_CODE} (expected 403), member_count=${UNCHANGED_CNT} (expected ${BEFORE_CNT}), C_in_db=${NA_C_DB} (expected 0)"
  fi
fi

end_suite
