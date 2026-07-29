#!/usr/bin/env bash
# =============================================================================
# tiers/quota-admission-o1/oracle.sh — O(1) ledger-driven quota admission
# (#2516/F1, slice S2)
# =============================================================================
# run.sh has stood up filesystem/single with RATE_LIMIT_ENABLED=false and
# exported BASE_URL, DB_CONTAINER, ADMIN_USER/ADMIN_PASS, COMMON_SH,
# JUNIT_OUTPUT_DIR, DTF_SLOT, RUN_ID. We source common.sh for the assertion +
# JUnit harness, then drive the real chunked-upload HTTP path with DB truth
# checks against `repository_usage_ledger`.
#
# Gates (see manifest): CHARGE / O1-ADMIT / ENFORCE / RELEASE.
# Reference = main WITH migration 182 (trigger-maintained ledger, admission
# still re-SUMs live tables). O1-ADMIT is the discriminating gate (RED on
# reference, GREEN on fix). CHARGE pins exactly-once accounting (RED on a fix
# that stacks a manual admission charge on the trigger's); ENFORCE and
# RELEASE guard the worse regressions (leaky fast admission / phantom free
# space) and must be GREEN on both images.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"
# shellcheck source=/dev/null
source "$COMMON_SH"

require_cmd jq
require_cmd sha256sum

SUF="$(printf '%s' "${RUN_ID}" | tr -cd '[:alnum:]' | tail -c 8)"
REPO="qadm-${DTF_SLOT:-x}-${SUF}"
QUOTA=1000

psql_q() {
  docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]'
}

# Chunked upload (the universal quota-gated write path): POST session ->
# PATCH single chunk -> PUT complete. Sets UPLOAD_STAGE/UPLOAD_CODE and
# returns 0 only when the whole flow succeeded. A quota rejection can
# legitimately surface as 413 at the session POST (unlocked preflight,
# pre-existing status) or as 507 at complete (the locked ledger-reading
# admission added by #2516/S2), so callers accept either.
upload_sized() { # <path> <size-bytes>
  local path="$1" size="$2" body sha sid
  body="$(head -c "$size" /dev/zero | tr '\0' 'a')"
  sha=$(printf '%s' "$body" | sha256sum | cut -d' ' -f1)
  UPLOAD_STAGE="session"
  local resp
  resp=$(curl -s -w '\n%{http_code}' -X POST "${BASE_URL}/api/v1/uploads" \
    -H "$(auth_header)" -H 'Content-Type: application/json' \
    -d "{\"repository_key\":\"${REPO}\",\"artifact_path\":\"${path}\",\"artifact_name\":\"$(basename "$path")\",\"artifact_version\":\"1.0.0\",\"total_size\":${size},\"checksum_sha256\":\"${sha}\",\"chunk_size\":8388608}" \
    2>/dev/null) || { UPLOAD_CODE=000; return 1; }
  UPLOAD_CODE="$(echo "$resp" | tail -n1)"
  sid="$(echo "$resp" | head -n -1 | jq -r '.session_id // empty' 2>/dev/null || true)"
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

ledger_hosted() {
  psql_q "SELECT hosted_bytes FROM repository_usage_ledger l JOIN repositories r ON r.id = l.repository_id WHERE r.key = '${REPO}';"
}

begin_suite "quota-admission-o1-2516"

auth_admin   # sets ADMIN_TOKEN

# --- setup: quota-bound generic repo -----------------------------------------
begin_test "SETUP: create local generic repo with a ${QUOTA}-byte quota"
setup_ok=1
create_local_repo "$REPO" generic || setup_ok=0
psql_q "UPDATE repositories SET quota_bytes = ${QUOTA} WHERE key = '${REPO}';" >/dev/null || setup_ok=0
got_quota="$(psql_q "SELECT quota_bytes FROM repositories WHERE key = '${REPO}';")"
if [ "$setup_ok" = "1" ] && [ "$got_quota" = "$QUOTA" ]; then
  pass "repo ${REPO} created, quota_bytes=${QUOTA}"
else
  fail "could not create repo / set quota (quota_bytes='${got_quota}')"
  end_suite
fi

# --- (CHARGE) admitted bytes are charged EXACTLY ONCE (trigger, not 2x) ------
begin_test "CHARGE: 400-byte upload -> 200 and ledger hosted_bytes=400 exactly (charged once)"
if upload_sized "q/a-400.bin" 400; then
  hb="$(ledger_hosted)"
  if [ "$hb" = "400" ]; then
    pass "mig-182 trigger charged the ledger exactly once (hosted_bytes=400)"
  else
    fail "ledger hosted_bytes='${hb}' after an admitted 400-byte upload, want exactly 400 (800 = trigger + manual admission charge double-count)"
  fi
else
  fail "baseline 400-byte upload failed at ${UPLOAD_STAGE} (HTTP ${UPLOAD_CODE})"
fi

# --- (O1-ADMIT) admission is served by the counters, not a live re-SUM -------
begin_test "O1-ADMIT: counters=quota-full + live tables under quota -> next upload 507"
psql_q "UPDATE repository_usage_ledger SET hosted_bytes = ${QUOTA} WHERE repository_id = (SELECT id FROM repositories WHERE key = '${REPO}');" >/dev/null
if upload_sized "q/x-400.bin" 400; then
  fail "upload was ADMITTED although the maintained counters are quota-full (pre-fix admission re-SUMs the live tables and ignores the ledger)"
else
  if [ "$UPLOAD_CODE" = "507" ] || { [ "$UPLOAD_STAGE" = "session" ] && [ "$UPLOAD_CODE" = "413" ]; }; then
    pass "rejected (HTTP ${UPLOAD_CODE} at ${UPLOAD_STAGE}) off the O(1) counters"
  else
    fail "upload failed at ${UPLOAD_STAGE} with HTTP ${UPLOAD_CODE}, expected quota rejection (413 session / 507 complete)"
  fi
fi
# Cleanup any admitted probe row + reset counters to live truth so the
# remaining gates are deterministic on BOTH images.
psql_q "DELETE FROM artifacts WHERE path = 'q/x-400.bin' AND repository_id = (SELECT id FROM repositories WHERE key = '${REPO}');" >/dev/null
psql_q "UPDATE repository_usage_ledger SET hosted_bytes = (SELECT COALESCE(SUM(size_bytes),0) FROM artifacts a WHERE a.repository_id = repository_usage_ledger.repository_id AND a.is_deleted = false AND a.storage_key NOT LIKE 'proxy-cache/%') WHERE repository_id = (SELECT id FROM repositories WHERE key = '${REPO}');" >/dev/null

# --- (ENFORCE) quota is still actually enforced ------------------------------
begin_test "ENFORCE-ACCEPT: fitting 500-byte upload (400+500<=1000) -> 200"
if upload_sized "q/b-500.bin" 500; then
  pass "under-quota upload admitted"
else
  fail "fitting upload rejected at ${UPLOAD_STAGE} (HTTP ${UPLOAD_CODE})"
fi

begin_test "ENFORCE-REJECT: over-quota 200-byte upload (900+200>1000) -> quota rejection"
if upload_sized "q/c-200.bin" 200; then
  fail "over-quota upload was ADMITTED — a fast admission that leaks past the quota is worse than the slow one"
else
  if [ "$UPLOAD_CODE" = "507" ] || { [ "$UPLOAD_STAGE" = "session" ] && [ "$UPLOAD_CODE" = "413" ]; }; then
    pass "over-quota upload rejected (HTTP ${UPLOAD_CODE} at ${UPLOAD_STAGE})"
  else
    fail "over-quota upload failed at ${UPLOAD_STAGE} with HTTP ${UPLOAD_CODE}, expected quota rejection (413 session / 507 complete)"
  fi
fi

# --- (RELEASE) delete frees the space immediately ----------------------------
begin_test "RELEASE: DELETE the 400-byte artifact -> hosted_bytes=500 and a 450-byte upload fits"
del_code=$(curl -s -o /dev/null -w '%{http_code}' -X DELETE \
  -H "$(auth_header)" "${BASE_URL}/api/v1/repositories/${REPO}/artifacts/q/a-400.bin" 2>/dev/null) || del_code=000
hb_after="$(ledger_hosted)"
if [ "$del_code" = "200" ] || [ "$del_code" = "204" ]; then
  if [ "$hb_after" = "500" ] && upload_sized "q/d-450.bin" 450; then
    pass "delete released 400 bytes (hosted_bytes=500, mig-182 trigger) and the freed space was admissible immediately"
  else
    fail "after delete: hosted_bytes='${hb_after}' (want exactly 500 — never below the live sum, no phantom free space), follow-up upload stage=${UPLOAD_STAGE:-n/a} HTTP ${UPLOAD_CODE:-n/a}"
  fi
else
  fail "artifact delete returned HTTP ${del_code}"
fi

# --- cleanup -----------------------------------------------------------------
curl -s -o /dev/null -X DELETE -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${REPO}" 2>/dev/null || true

end_suite
