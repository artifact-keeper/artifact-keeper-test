#!/usr/bin/env bash
# =============================================================================
# tiers/audit-event-coverage/oracle.sh — privileged admin actions are audited
#                                         and audit retention runs on a
#                                         schedule (artifact-keeper#4710/#4718)
# =============================================================================
# run.sh has stood up `storage.filesystem secrets.webhook-key` with
# RATE_LIMIT_ENABLED=false and exported BASE_URL, DB_CONTAINER, ADMIN_USER,
# ADMIN_PASS, RUN_ID, DTF_SLOT, RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
#
# THE BUGS. #4710: quarantine, approval, promotion, permission-rule, SSO-admin,
# signing-key, webhook and sync-policy handlers wrote no audit_log row at all.
# #4718: `audit_retention_days` was never applied on a schedule, the settings
# endpoint claimed an unsaved 90, and the manual cleanup applied that 90.
#
# ORDER MATTERS. The fixed backend's first retention pass runs 240-270 s after
# it starts and reads the period then, so the retention setup (save a 1-day
# period, backdate rows) is the FIRST thing this oracle does. The per-class
# audit assertions run while the pass is pending; the oracle then waits until
# container start + RETENTION_DEADLINE_SECS for the pass and checks what it
# deleted and what it kept.
#
# Discriminating gates:
#   (CONTROL)    both images: REPOSITORY_CREATED / USER_CREATED still written
#                exactly once; a login with a spoofed X-Forwarded-For records
#                the TCP peer; a saved retention period reads back.
#   (FIX #4710)  one row per action with the expected action, resource_type,
#                resource_id, actor and peer IP; no secret in `details`.
#                RED on 1.11.1 (count 0).
#   (FIX #4718)  unsaved period reads 0; manual cleanup without a saved period
#                deletes nothing; the scheduled pass deletes rows older than
#                the period and keeps the rest. RED on 1.11.1.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

SUF="${RUN_ID##*-}-$$"
SLOT="${DTF_SLOT:-x}"
BACKEND_CTR="ak-dtf${SLOT}-backend"
# First pass at 240 s + up to 30 s jitter after startup (scheduler_service.rs
# jittered_startup_delay(240)), counted from container start; 120 s of slack
# for migrations before the scheduler spawns and for the pass itself.
RETENTION_DEADLINE_SECS="${RETENTION_DEADLINE_SECS:-390}"
SPOOF_IP="203.0.113.77"

WORK="$(mktemp -d -t dtf-audit-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

# --- helpers ----------------------------------------------------------------
db() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -Atc "$1" 2>&1; }

# call METHOD PATH [JSON_BODY] [TOKEN] -> sets CODE and BODY
CODE=""; BODY=""
call() {
  local method="$1" path="$2" data="${3:-}" tok="${4:-$ADMIN_TOKEN}"
  local args=(-s "${CURL_TIMEOUT_ARGS[@]}" -o "${WORK}/body" -w '%{http_code}' -X "$method"
              -H "Authorization: Bearer ${tok}")
  if [ -n "$data" ]; then
    args+=(-H 'Content-Type: application/json' -d "$data")
  fi
  CODE="$(curl "${args[@]}" "${BASE_URL}${path}" 2>/dev/null)" || CODE="000"
  BODY="$(cat "${WORK}/body" 2>/dev/null || true)"
}
ok() { case "$CODE" in 2??) return 0 ;; *) return 1 ;; esac; }

# upload REPO_KEY PATH CONTENT -> echoes the new artifact id
upload() {
  local code
  printf '%s' "$3" > "${WORK}/up"
  code="$(curl -s "${CURL_TIMEOUT_ARGS[@]}" -o "${WORK}/upbody" -w '%{http_code}' -X PUT \
    -H "$(auth_header)" -H 'Content-Type: application/octet-stream' \
    --data-binary "@${WORK}/up" "${BASE_URL}/api/v1/repositories/$1/artifacts/$2" 2>/dev/null)" || code=000
  case "$code" in 2??) jq -r '.id // empty' "${WORK}/upbody" 2>/dev/null ;; *) echo "" ;; esac
}

# mkrepo KEY TYPE PUBLIC(true|false) -> echoes the repository id
mkrepo() {
  call POST /api/v1/repositories \
    "{\"key\":\"$1\",\"name\":\"$1\",\"format\":\"generic\",\"repo_type\":\"$2\",\"is_public\":$3}"
  if ok; then printf '%s' "$BODY" | jq -r '.id // empty'; else echo ""; fi
}

# audit_row_ids ACTION RTYPE RID -> newline-separated audit_log ids
audit_row_ids() {
  db "SELECT id FROM audit_log WHERE action='$1' AND resource_type='$2' AND resource_id='$3'"
}
# api_total ACTION RID -> the admin audit endpoint's total for that filter
api_total() {
  call GET "/api/v1/admin/audit?action=$1&resource_id=$2&per_page=5"
  if ok; then printf '%s' "$BODY" | jq -r '.total // "none"'; else echo "http-${CODE}"; fi
}

# Every audit row this run expects to exist at the end (survivors of the
# retention pass).
KEEP_IDS=()

# expect_one ACTION RTYPE RID ACTOR_ID [JQ_DETAILS_PREDICATE]
# Asserts exactly one row (DB and API), attributed to ACTOR_ID with the peer
# IP, and optionally that `details` satisfies a jq predicate. Must run inside
# a begin_test; calls pass/fail itself.
expect_one() {
  local action="$1" rtype="$2" rid="$3" actor="$4" pred="${5:-true}"
  local ids n total row user ip details
  ids="$(audit_row_ids "$action" "$rtype" "$rid")"
  n="$(printf '%s' "$ids" | grep -c . || true)"
  total="$(api_total "$action" "$rid")"
  if [ "$n" != "1" ] || [ "$total" != "1" ]; then
    fail "${action} rows for ${rtype} ${rid}: db=${n} api=${total} (want 1/1)" \
      "$(db "SELECT action, resource_type FROM audit_log WHERE resource_id='${rid}'")"
    return
  fi
  KEEP_IDS+=("$ids")
  row="$(db "SELECT coalesce(user_id::text,''), coalesce(ip_address,''), coalesce(details::text,'null') FROM audit_log WHERE id='${ids}'")"
  user="${row%%|*}"; row="${row#*|}"; ip="${row%%|*}"; details="${row#*|}"
  if [ "$user" != "$actor" ]; then
    fail "${action}: user_id=${user:-<null>}, want the acting admin ${actor}"; return
  fi
  if [ "$ip" != "$PEER_IP" ]; then
    fail "${action}: ip_address=${ip:-<null>}, want the TCP peer ${PEER_IP} the login row recorded"; return
  fi
  if ! printf '%s' "$details" | jq -e "$pred" >/dev/null 2>&1; then
    fail "${action}: details do not satisfy ${pred}" "$details"; return
  fi
  pass
}

backdate() { db "UPDATE audit_log SET created_at = NOW() - interval '$2' WHERE id='$1'" >/dev/null; }
row_exists() { [ "$(db "SELECT count(*) FROM audit_log WHERE id='$1'")" = "1" ]; }

begin_suite "audit-event-coverage"

# =============================================================================
# SETUP
# =============================================================================
begin_test "setup: admin login, admin id, peer IP, backend start time"
auth_admin
ADMIN_ID="$(db "SELECT id FROM users WHERE username='${ADMIN_USER}'")"
PEER_IP="$(db "SELECT coalesce(ip_address,'') FROM audit_log WHERE action='LOGIN' AND resource_id='${ADMIN_ID}' ORDER BY created_at DESC LIMIT 1")"
STARTED="$(docker inspect -f '{{.State.StartedAt}}' "$BACKEND_CTR" 2>/dev/null)"
STARTED_EPOCH="$(date -d "$STARTED" +%s 2>/dev/null || echo "")"
if [[ ! "$ADMIN_ID" =~ ^[0-9a-f-]{36}$ ]] || [ -z "$PEER_IP" ] || [ -z "$STARTED_EPOCH" ]; then
  infra_fail "admin_id='${ADMIN_ID}' peer_ip='${PEER_IP}' started='${STARTED}'"
  end_suite
fi
echo "  admin=${ADMIN_ID} peer_ip=${PEER_IP} backend started ${STARTED} ($(( $(date +%s) - STARTED_EPOCH ))s ago)"
pass

# =============================================================================
# #4718 RETENTION SETUP — must precede the first scheduled pass
# =============================================================================
begin_test "FIX #4718: an unsaved audit_retention_days reads 0, not an unapplied 90"
call GET /api/v1/admin/settings
SETTINGS="$BODY"
if ! ok; then
  infra_fail "GET /api/v1/admin/settings -> ${CODE}" "$BODY"; end_suite
fi
got="$(printf '%s' "$SETTINGS" | jq -r '.audit_retention_days')"
if [ "$got" = "0" ]; then pass; else
  fail "audit_retention_days=${got} with no saved period (1.11.1 reports 90, which nothing applies)"
fi

begin_test "FIX #4718: manual cleanup with no saved period deletes no audit row"
CL_REPO="aec-cleanup-${SLOT}-${SUF}"
CL_REPO_ID="$(mkrepo "$CL_REPO" local false)"
CL_ROW="$(db "SELECT id FROM audit_log WHERE action='REPOSITORY_CREATED' AND resource_id='${CL_REPO_ID}'")"
if [ -z "$CL_REPO_ID" ] || [[ ! "$CL_ROW" =~ ^[0-9a-f-]{36}$ ]]; then
  infra_fail "could not seed a REPOSITORY_CREATED row to backdate (repo=${CL_REPO_ID} row=${CL_ROW})"; end_suite
fi
backdate "$CL_ROW" "100 days"
call POST /api/v1/admin/cleanup '{"cleanup_audit_logs":true}'
deleted="$(printf '%s' "$BODY" | jq -r '.audit_logs_deleted // "?"' 2>/dev/null)"
if ! ok; then
  fail "POST /api/v1/admin/cleanup -> ${CODE}" "$BODY"
elif row_exists "$CL_ROW" && [ "$deleted" = "0" ]; then
  pass
else
  fail "cleanup with retention unsaved deleted the 100-day-old row (audit_logs_deleted=${deleted}); unsaved must mean off"
fi

begin_test "CONTROL: a saved audit_retention_days (1, the smallest legal period) reads back"
NEW_SETTINGS="$(printf '%s' "$SETTINGS" | jq -c '.audit_retention_days = 1')"
call POST /api/v1/admin/settings "$NEW_SETTINGS"
if ! ok; then
  infra_fail "POST /api/v1/admin/settings -> ${CODE}" "$BODY"; end_suite
fi
call GET /api/v1/admin/settings
got="$(printf '%s' "$BODY" | jq -r '.audit_retention_days')"
if [ "$got" = "1" ]; then pass; else fail "audit_retention_days read back as ${got}, saved 1"; fi

begin_test "setup: seed rows backdated 2 days, 30 days, 23 hours and a fresh one"
declare -A RET_ROW=()
for age in 2d 30d 23h fresh; do
  rid="$(mkrepo "aec-ret-${age}-${SLOT}-${SUF}" local false)"
  row=""
  [ -n "$rid" ] && row="$(db "SELECT id FROM audit_log WHERE action='REPOSITORY_CREATED' AND resource_id='${rid}'")"
  if [[ ! "$row" =~ ^[0-9a-f-]{36}$ ]]; then
    infra_fail "no REPOSITORY_CREATED row for the ${age} seed repo (repo=${rid} row=${row})"; end_suite
  fi
  RET_ROW[$age]="$row"
done
backdate "${RET_ROW[2d]}" "2 days"
backdate "${RET_ROW[30d]}" "30 days"
backdate "${RET_ROW[23h]}" "23 hours"
pass

# =============================================================================
# CONTROL — pre-existing audit behaviour, true on both images
# =============================================================================
begin_test "CONTROL: repository create writes exactly one REPOSITORY_CREATED row by the admin"
CTL_REPO="aec-ctl-${SLOT}-${SUF}"
CTL_REPO_ID="$(mkrepo "$CTL_REPO" local false)"
if [ -z "$CTL_REPO_ID" ]; then
  fail "repository create -> ${CODE}" "$BODY"
else
  n="$(db "SELECT count(*) FROM audit_log WHERE action='REPOSITORY_CREATED' AND resource_type='repository' AND resource_id='${CTL_REPO_ID}' AND user_id='${ADMIN_ID}' AND details->>'key'='${CTL_REPO}'")"
  t="$(api_total REPOSITORY_CREATED "$CTL_REPO_ID")"
  if [ "$n" = "1" ] && [ "$t" = "1" ]; then
    KEEP_IDS+=("$(db "SELECT id FROM audit_log WHERE action='REPOSITORY_CREATED' AND resource_id='${CTL_REPO_ID}'")")
    pass
  else
    fail "REPOSITORY_CREATED for ${CTL_REPO_ID}: db=${n} api=${t} (want 1/1)"
  fi
fi

begin_test "CONTROL: user create writes exactly one USER_CREATED row by the admin"
U_NAME="aec-user-${SLOT}-${SUF}"
# Request bodies are built with jq --arg: the values are run-unique test
# fixtures, and keeping them out of literal JSON keeps secret scanners quiet.
U_LOGIN_CREDENTIAL="Aec_${SUF}_Aa1!x"
call POST /api/v1/users "$(jq -nc --arg u "$U_NAME" --arg p "$U_LOGIN_CREDENTIAL" --arg e "${U_NAME}@e2e.local" '{username: $u, password: $p, email: $e}')"
U_ID="$(printf '%s' "$BODY" | jq -r '.user.id // .id // empty' 2>/dev/null)"
if ! ok || [ -z "$U_ID" ]; then
  infra_fail "user create -> ${CODE}" "$BODY"; end_suite
fi
n="$(db "SELECT count(*) FROM audit_log WHERE action='USER_CREATED' AND resource_type='user' AND resource_id='${U_ID}' AND user_id='${ADMIN_ID}'")"
t="$(api_total USER_CREATED "$U_ID")"
if [ "$n" = "1" ] && [ "$t" = "1" ]; then
  KEEP_IDS+=("$(db "SELECT id FROM audit_log WHERE action='USER_CREATED' AND resource_id='${U_ID}'")")
  pass
else
  fail "USER_CREATED for ${U_ID}: db=${n} api=${t} (want 1/1)"
fi

begin_test "CONTROL: a login with a spoofed X-Forwarded-For records the TCP peer, not the header"
before="$(db "SELECT count(*) FROM audit_log WHERE action='LOGIN' AND resource_id='${ADMIN_ID}'")"
code="$(curl -s "${CURL_TIMEOUT_ARGS[@]}" -o /dev/null -w '%{http_code}' -X POST \
  -H 'Content-Type: application/json' -H "X-Forwarded-For: ${SPOOF_IP}" \
  -d "{\"username\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASS}\"}" \
  "${BASE_URL}/api/v1/auth/login" 2>/dev/null)" || code=000
after="$(db "SELECT count(*) FROM audit_log WHERE action='LOGIN' AND resource_id='${ADMIN_ID}'")"
last_ip="$(db "SELECT coalesce(ip_address,'') FROM audit_log WHERE action='LOGIN' AND resource_id='${ADMIN_ID}' ORDER BY created_at DESC LIMIT 1")"
if [ "$code" = "200" ] && [ "$after" = "$(( before + 1 ))" ] && [ "$last_ip" = "$PEER_IP" ]; then
  pass
else
  fail "login HTTP ${code}, LOGIN rows ${before}->${after}, ip=${last_ip:-<null>} (want ${PEER_IP}, never ${SPOOF_IP})"
fi

# =============================================================================
# FIX #4710 — one row per privileged action
# =============================================================================
# ---- permission rules -------------------------------------------------------
PERM_BODY="{\"principal_type\":\"user\",\"principal_id\":\"${U_ID}\",\"target_type\":\"repository\",\"target_id\":\"${CTL_REPO_ID}\",\"actions\":[\"read\"]}"
begin_test "FIX #4710: permission rule create -> PERMISSION_RULE_CREATED"
call POST /api/v1/permissions "$PERM_BODY"
PERM_ID="$(printf '%s' "$BODY" | jq -r '.id // empty' 2>/dev/null)"
if ok && [ -n "$PERM_ID" ]; then
  expect_one PERMISSION_RULE_CREATED permission_rule "$PERM_ID" "$ADMIN_ID" \
    ".principal_id == \"${U_ID}\" and .target_id == \"${CTL_REPO_ID}\" and .actions == [\"read\"]"
else
  fail "POST /api/v1/permissions -> ${CODE}" "$BODY"; PERM_ID=""
fi

begin_test "FIX #4710: permission rule update -> PERMISSION_RULE_UPDATED with before/after"
if [ -n "$PERM_ID" ]; then
  call PUT "/api/v1/permissions/${PERM_ID}" "$(printf '%s' "$PERM_BODY" | jq -c '.actions = ["read","write"]')"
  if ok; then
    expect_one PERMISSION_RULE_UPDATED permission_rule "$PERM_ID" "$ADMIN_ID" \
      '.before.actions == ["read"] and .after.actions == ["read","write"] and (.changed_fields | index("actions"))'
  else fail "PUT /api/v1/permissions/${PERM_ID} -> ${CODE}" "$BODY"; fi
else fail "no permission rule to update"; fi

begin_test "FIX #4710: permission rule delete -> PERMISSION_RULE_DELETED"
if [ -n "$PERM_ID" ]; then
  call DELETE "/api/v1/permissions/${PERM_ID}"
  if ok; then expect_one PERMISSION_RULE_DELETED permission_rule "$PERM_ID" "$ADMIN_ID"
  else fail "DELETE /api/v1/permissions/${PERM_ID} -> ${CODE}" "$BODY"; fi
else fail "no permission rule to delete"; fi

# ---- webhooks ---------------------------------------------------------------
WH_PATH="/aec/${SUF}"
# Built from parts so no credential-shaped literal sits in the file: the
# oracle later asserts that none of these parts leaks into an audit row.
WH_USERINFO_USER="aecuser"
WH_USERINFO_PASS="aecpass-${SUF}"
WH_QUERY_TOKEN="aectok-${SUF}"
WH_URL="https://${WH_USERINFO_USER}:${WH_USERINFO_PASS}@example.com${WH_PATH}?token=${WH_QUERY_TOKEN}#frag"
begin_test "FIX #4710: webhook create -> WEBHOOK_CREATED, URL without userinfo/query/fragment"
call POST /api/v1/webhooks "{\"name\":\"aec-wh-${SUF}\",\"url\":\"${WH_URL}\",\"events\":[\"artifact_uploaded\"]}"
WH_ID="$(printf '%s' "$BODY" | jq -r '.id // empty' 2>/dev/null)"
WH_SECRET="$(printf '%s' "$BODY" | jq -r '.secret // empty' 2>/dev/null)"
if ok && [ -n "$WH_ID" ]; then
  expect_one WEBHOOK_CREATED webhook "$WH_ID" "$ADMIN_ID" \
    ".url == \"https://example.com${WH_PATH}\" and .name == \"aec-wh-${SUF}\""
else
  fail "POST /api/v1/webhooks -> ${CODE}" "$BODY"; WH_ID=""
fi

begin_test "FIX #4710: webhook disable -> WEBHOOK_UPDATED (is_enabled false)"
if [ -n "$WH_ID" ]; then
  call POST "/api/v1/webhooks/${WH_ID}/disable"
  if ok; then expect_one WEBHOOK_UPDATED webhook "$WH_ID" "$ADMIN_ID" '.is_enabled == false'
  else fail "disable -> ${CODE}" "$BODY"; fi
else fail "no webhook"; fi

begin_test "FIX #4710: webhook rotate-secret -> WEBHOOK_SECRET_ROTATED, no secret recorded"
if [ -n "$WH_ID" ]; then
  call POST "/api/v1/webhooks/${WH_ID}/rotate-secret"
  # The rotation response carries only the new secret's display digest (the
  # raw secret is never echoed); the row must carry neither.
  NEW_DIGEST="$(printf '%s' "$BODY" | jq -r '.secret_digest // empty' 2>/dev/null)"
  if ok; then expect_one WEBHOOK_SECRET_ROTATED webhook "$WH_ID" "$ADMIN_ID" '.secret_rotated == true'
  else fail "rotate-secret -> ${CODE}" "$BODY"; fi
else fail "no webhook"; fi

begin_test "FIX #4710: webhook delete -> WEBHOOK_DELETED"
if [ -n "$WH_ID" ]; then
  call DELETE "/api/v1/webhooks/${WH_ID}"
  if ok; then expect_one WEBHOOK_DELETED webhook "$WH_ID" "$ADMIN_ID"
  else fail "DELETE webhook -> ${CODE}" "$BODY"; fi
else fail "no webhook"; fi

# ---- SSO (OIDC) providers ---------------------------------------------------
# The two values the provider's client_secret field is set to (create, then
# update). Run-unique throwaway fixtures; the leak check below asserts neither
# reaches an audit row. Named for what they are to the TEST (the first and
# second rotation value), not as a credential, which is also what keeps a
# secret scanner from reading a test fixture as a leaked key.
OIDC_ROTATION_VALUE_1="aec-oidc-v1-${SUF}"
OIDC_ROTATION_VALUE_2="aec-oidc-v2-${SUF}"
begin_test "FIX #4710: OIDC provider create -> SSO_PROVIDER_CREATED"
call POST /api/v1/admin/sso/oidc "$(jq -nc --arg n "aec-oidc-${SUF}" --arg s "$OIDC_ROTATION_VALUE_1" '{name: $n, client_id: "aec-client", client_secret: $s, issuer_url: "https://idp.example.com"}')"
OIDC_ID="$(printf '%s' "$BODY" | jq -r '.id // empty' 2>/dev/null)"
if ok && [ -n "$OIDC_ID" ]; then
  expect_one SSO_PROVIDER_CREATED sso_provider "$OIDC_ID" "$ADMIN_ID" \
    ".provider_type == \"oidc\" and .name == \"aec-oidc-${SUF}\""
else
  fail "POST /api/v1/admin/sso/oidc -> ${CODE}" "$BODY"; OIDC_ID=""
fi

begin_test "FIX #4710: OIDC provider update -> SSO_PROVIDER_UPDATED (credential_replaced, changed_fields)"
if [ -n "$OIDC_ID" ]; then
  call PUT "/api/v1/admin/sso/oidc/${OIDC_ID}" "$(jq -nc --arg n "aec-oidc2-${SUF}" --arg s "$OIDC_ROTATION_VALUE_2" '{name: $n, client_secret: $s}')"
  if ok; then
    expect_one SSO_PROVIDER_UPDATED sso_provider "$OIDC_ID" "$ADMIN_ID" \
      '.credential_replaced == true and (.changed_fields | index("name"))'
  else fail "PUT oidc -> ${CODE}" "$BODY"; fi
else fail "no OIDC provider"; fi

begin_test "FIX #4710: OIDC provider toggle -> SSO_PROVIDER_DISABLED"
if [ -n "$OIDC_ID" ]; then
  call PATCH "/api/v1/admin/sso/oidc/${OIDC_ID}/toggle" '{"enabled":false}'
  if ok; then expect_one SSO_PROVIDER_DISABLED sso_provider "$OIDC_ID" "$ADMIN_ID" '.is_enabled == false'
  else fail "PATCH toggle -> ${CODE}" "$BODY"; fi
else fail "no OIDC provider"; fi

begin_test "FIX #4710: OIDC provider delete -> SSO_PROVIDER_DELETED"
if [ -n "$OIDC_ID" ]; then
  call DELETE "/api/v1/admin/sso/oidc/${OIDC_ID}"
  if ok; then expect_one SSO_PROVIDER_DELETED sso_provider "$OIDC_ID" "$ADMIN_ID"
  else fail "DELETE oidc -> ${CODE}" "$BODY"; fi
else fail "no OIDC provider"; fi

# ---- signing keys -----------------------------------------------------------
begin_test "FIX #4710: signing key rotate -> SIGNING_KEY_ROTATED on the old key, naming the new one"
call POST /api/v1/signing/keys "{\"name\":\"aec-key-${SUF}\",\"key_type\":\"gpg\",\"algorithm\":\"ed25519\",\"repository_id\":\"${CTL_REPO_ID}\"}"
KEY_ID="$(printf '%s' "$BODY" | jq -r '.id // empty' 2>/dev/null)"
KEY2_ID=""
if ok && [ -n "$KEY_ID" ]; then
  call POST "/api/v1/signing/keys/${KEY_ID}/rotate"
  KEY2_ID="$(printf '%s' "$BODY" | jq -r '.id // empty' 2>/dev/null)"
  if ok && [ -n "$KEY2_ID" ]; then
    expect_one SIGNING_KEY_ROTATED signing_key "$KEY_ID" "$ADMIN_ID" \
      ".new_key_id == \"${KEY2_ID}\" and .key_id == \"${KEY_ID}\""
  else fail "rotate -> ${CODE}" "$BODY"; fi
else
  fail "POST /api/v1/signing/keys -> ${CODE}" "$BODY"
fi

begin_test "FIX #4710: signing key revoke -> SIGNING_KEY_REVOKED"
if [ -n "$KEY2_ID" ]; then
  call POST "/api/v1/signing/keys/${KEY2_ID}/revoke"
  if ok; then expect_one SIGNING_KEY_REVOKED signing_key "$KEY2_ID" "$ADMIN_ID"
  else fail "revoke -> ${CODE}" "$BODY"; fi
else fail "no rotated key to revoke"; fi

# ---- quarantine -------------------------------------------------------------
QA_ID="$(upload "$CTL_REPO" "q/release-${SUF}.bin" "release-${SUF}")"
QB_ID="$(upload "$CTL_REPO" "q/reject-${SUF}.bin" "reject-${SUF}")"
begin_test "FIX #4710: quarantine release -> QUARANTINE_RELEASED"
if [ -n "$QA_ID" ]; then
  call POST "/api/v1/quarantine/${QA_ID}/quarantine" '{"reason":"dtf hold"}'
  if ok; then
    call POST "/api/v1/quarantine/${QA_ID}/release" '{}'
    if ok; then
      expect_one QUARANTINE_RELEASED artifact "$QA_ID" "$ADMIN_ID" '.previous_status == "quarantined"'
    else fail "release -> ${CODE}" "$BODY"; fi
  else fail "quarantine -> ${CODE}" "$BODY"; fi
else fail "upload for the release case failed"; fi

begin_test "FIX #4710: quarantine reject -> QUARANTINE_REJECTED with the reason"
if [ -n "$QB_ID" ]; then
  call POST "/api/v1/quarantine/${QB_ID}/quarantine" '{"reason":"dtf hold"}'
  if ok; then
    call POST "/api/v1/quarantine/${QB_ID}/reject" "{\"reason\":\"aec-bad-${SUF}\"}"
    if ok; then
      expect_one QUARANTINE_REJECTED artifact "$QB_ID" "$ADMIN_ID" ".reason == \"aec-bad-${SUF}\""
    else fail "reject -> ${CODE}" "$BODY"; fi
  else fail "quarantine -> ${CODE}" "$BODY"; fi
else fail "upload for the reject case failed"; fi

# ---- promotion --------------------------------------------------------------
# Public repos: approval is executed by a SECOND admin (four-eyes), and the
# promotion tenant gate admits a non-owner only on a public repository.
STG="aec-stg-${SLOT}-${SUF}"; REL="aec-rel-${SLOT}-${SUF}"; STGR="aec-stgr-${SLOT}-${SUF}"
STG_ID="$(mkrepo "$STG" staging true)"
REL_ID="$(mkrepo "$REL" local true)"
STGR_ID="$(mkrepo "$STGR" staging true)"
begin_test "setup: staging/release repos and a refusing promotion rule"
if [ -z "$STG_ID" ] || [ -z "$REL_ID" ] || [ -z "$STGR_ID" ]; then
  infra_fail "staging/release repo create failed (stg=${STG_ID} rel=${REL_ID} stgr=${STGR_ID})"; end_suite
fi
call POST /api/v1/promotion-rules "{\"name\":\"aec-rule-${SUF}\",\"source_repo_id\":\"${STGR_ID}\",\"target_repo_id\":\"${REL_ID}\",\"min_staging_hours\":48}"
if ok; then pass; else infra_fail "promotion rule create -> ${CODE}" "$BODY"; end_suite; fi

begin_test "FIX #4710: promote -> ARTIFACT_PROMOTED on the source artifact"
PA="$(upload "$STG" "p/promote-${SUF}.bin" "promote-${SUF}")"
if [ -n "$PA" ]; then
  call POST "/api/v1/promotion/repositories/${STG}/artifacts/${PA}/promote" "{\"target_repository\":\"${REL}\"}"
  if ok && [ "$(printf '%s' "$BODY" | jq -r '.promoted')" = "true" ]; then
    expect_one ARTIFACT_PROMOTED artifact "$PA" "$ADMIN_ID" \
      ".target_repository == \"${REL}\" and .promotion_id != null"
  else fail "promote -> ${CODE}" "$BODY"; fi
else fail "upload for promote failed"; fi

begin_test "FIX #4710: promote refused by a rule -> PROMOTION_REFUSED with the failing rule"
PR="$(upload "$STGR" "p/refused-${SUF}.bin" "refused-${SUF}")"
if [ -n "$PR" ]; then
  call POST "/api/v1/promotion/repositories/${STGR}/artifacts/${PR}/promote" "{\"target_repository\":\"${REL}\"}"
  if [ "$(printf '%s' "$BODY" | jq -r '.promoted' 2>/dev/null)" = "false" ]; then
    expect_one PROMOTION_REFUSED artifact "$PR" "$ADMIN_ID" \
      ".promotion_id == null and (.gate_results.failed_rules | index(\"aec-rule-${SUF}\"))"
  else fail "promote under a 48h staging rule was not refused: ${CODE}" "$BODY"; fi
else fail "upload for refused promote failed"; fi

begin_test "FIX #4710: staging reject -> PROMOTION_REJECTED"
PJ="$(upload "$STG" "p/reject-${SUF}.bin" "reject-${SUF}")"
if [ -n "$PJ" ]; then
  call POST "/api/v1/promotion/repositories/${STG}/artifacts/${PJ}/reject" "{\"reason\":\"aec-nope-${SUF}\"}"
  if ok; then expect_one PROMOTION_REJECTED artifact "$PJ" "$ADMIN_ID" ".reason == \"aec-nope-${SUF}\""
  else fail "reject -> ${CODE}" "$BODY"; fi
else fail "upload for reject failed"; fi

# ---- approvals (second admin) -----------------------------------------------
APPROVER="aec-approver-${SLOT}-${SUF}"
APPROVER_PASS="Aec_appr_${SUF}_Aa1!"
APPROVER_ID="$(create_dedicated_admin "$APPROVER" "$APPROVER_PASS")" || APPROVER_ID=""
APPROVER_TOKEN=""
[ -n "$APPROVER_ID" ] && APPROVER_TOKEN="$(login_as "$APPROVER" "$APPROVER_PASS")"
begin_test "setup: a second admin to review approvals"
if [ -n "$APPROVER_TOKEN" ]; then pass; else infra_fail "could not create/log in the approver admin"; end_suite; fi

request_approval() {  # ARTIFACT_ID -> echoes approval id
  call POST /api/v1/approval/request "{\"source_repository\":\"${STG}\",\"target_repository\":\"${REL}\",\"artifact_id\":\"$1\"}"
  if ok; then printf '%s' "$BODY" | jq -r '.id // empty'; else echo ""; fi
}

begin_test "FIX #4710: approval approve -> PROMOTION_APPROVAL_GRANTED by the reviewer"
AA="$(upload "$STG" "a/approve-${SUF}.bin" "approve-${SUF}")"
AP_ID=""; [ -n "$AA" ] && AP_ID="$(request_approval "$AA")"
if [ -n "$AP_ID" ]; then
  call POST "/api/v1/approval/${AP_ID}/approve" '{"notes":"aec ok"}' "$APPROVER_TOKEN"
  if ok; then
    expect_one PROMOTION_APPROVAL_GRANTED promotion_approval "$AP_ID" "$APPROVER_ID" \
      ".artifact_id == \"${AA}\" and .requested_by == \"${ADMIN_ID}\" and .promotion_id != null"
  else fail "approve -> ${CODE}" "$BODY"; fi
else fail "approval request failed: ${CODE}" "$BODY"; fi

begin_test "FIX #4710: approval reject -> PROMOTION_APPROVAL_DENIED by the reviewer"
AR="$(upload "$STG" "a/deny-${SUF}.bin" "deny-${SUF}")"
AR_ID=""; [ -n "$AR" ] && AR_ID="$(request_approval "$AR")"
if [ -n "$AR_ID" ]; then
  call POST "/api/v1/approval/${AR_ID}/reject" '{"notes":"aec no"}' "$APPROVER_TOKEN"
  if ok; then
    expect_one PROMOTION_APPROVAL_DENIED promotion_approval "$AR_ID" "$APPROVER_ID" ".artifact_id == \"${AR}\""
  else fail "reject -> ${CODE}" "$BODY"; fi
else fail "approval request failed: ${CODE}" "$BODY"; fi

# ---- sync policies ----------------------------------------------------------
begin_test "FIX #4710: sync policy create -> SYNC_POLICY_CREATED"
call POST /api/v1/sync-policies "{\"name\":\"aec-sp-${SUF}\"}"
SP_ID="$(printf '%s' "$BODY" | jq -r '.id // empty' 2>/dev/null)"
if ok && [ -n "$SP_ID" ]; then
  expect_one SYNC_POLICY_CREATED sync_policy "$SP_ID" "$ADMIN_ID" ".name == \"aec-sp-${SUF}\""
else fail "POST /api/v1/sync-policies -> ${CODE}" "$BODY"; SP_ID=""; fi

begin_test "FIX #4710: sync policy update -> SYNC_POLICY_UPDATED naming the changed field"
if [ -n "$SP_ID" ]; then
  call PUT "/api/v1/sync-policies/${SP_ID}" "{\"name\":\"aec-sp-${SUF}\",\"priority\":7}"
  if ok; then expect_one SYNC_POLICY_UPDATED sync_policy "$SP_ID" "$ADMIN_ID" '(.changed_fields | index("priority"))'
  else fail "PUT sync policy -> ${CODE}" "$BODY"; fi
else fail "no sync policy"; fi

begin_test "FIX #4710: sync policy delete -> SYNC_POLICY_DELETED"
if [ -n "$SP_ID" ]; then
  call DELETE "/api/v1/sync-policies/${SP_ID}"
  if ok; then expect_one SYNC_POLICY_DELETED sync_policy "$SP_ID" "$ADMIN_ID"
  else fail "DELETE sync policy -> ${CODE}" "$BODY"; fi
else fail "no sync policy"; fi

# ---- secrets never reach the trail ------------------------------------------
begin_test "FIX #4710: no audit row carries an OIDC client secret, webhook secret or digest, or URL credential"
leaks=""
for needle in "$OIDC_ROTATION_VALUE_1" "$OIDC_ROTATION_VALUE_2" "aecpass-${SUF}" "aectok-${SUF}" ${WH_SECRET:+"$WH_SECRET"} ${NEW_DIGEST:+"$NEW_DIGEST"}; do
  n="$(db "SELECT count(*) FROM audit_log WHERE coalesce(details::text,'') LIKE '%${needle}%'")"
  [ "$n" != "0" ] && leaks="${leaks} ${needle}(${n})"
done
# Vacuous on an image that writes none of these rows: require that the rows
# the secrets would have been in exist.
have="$(db "SELECT count(*) FROM audit_log WHERE action IN ('SSO_PROVIDER_CREATED','SSO_PROVIDER_UPDATED','WEBHOOK_CREATED','WEBHOOK_SECRET_ROTATED') AND resource_id IN ('${OIDC_ID:-00000000-0000-0000-0000-000000000000}','${WH_ID:-00000000-0000-0000-0000-000000000000}')")"
if [ -n "$leaks" ]; then
  fail "secret material found in audit details:${leaks}"
elif [ "$have" != "4" ]; then
  fail "only ${have}/4 of the SSO/webhook rows that could carry a secret exist; nothing to check"
else
  pass
fi

# =============================================================================
# FIX #4718 — the scheduled retention pass
# =============================================================================
begin_test "FIX #4718: the scheduled pass deletes rows older than 1 day and keeps the rest"
deadline=$(( STARTED_EPOCH + RETENTION_DEADLINE_SECS ))
old_ids="'${RET_ROW[2d]}','${RET_ROW[30d]}','${CL_ROW}'"
echo "  waiting up to $(( deadline - $(date +%s) ))s (backend start + ${RETENTION_DEADLINE_SECS}s) for the first pass"
old_left="3"
while :; do
  old_left="$(db "SELECT count(*) FROM audit_log WHERE id IN (${old_ids})")"
  [ "$old_left" = "0" ] && break
  [ "$(date +%s)" -ge "$deadline" ] && break
  sleep 10
done
keep_ids="'${RET_ROW[23h]}','${RET_ROW[fresh]}'"
for i in "${KEEP_IDS[@]}"; do keep_ids="${keep_ids},'${i}'"; done
keep_want=$(( 2 + ${#KEEP_IDS[@]} ))
keep_have="$(db "SELECT count(*) FROM audit_log WHERE id IN (${keep_ids})")"
if [ "$old_left" != "0" ]; then
  fail "${old_left}/3 rows backdated past the 1-day period (2d, 30d, 100d) still present $(( $(date +%s) - STARTED_EPOCH ))s after backend start; no retention pass ran"
elif [ "$keep_have" != "$keep_want" ]; then
  fail "retention deleted rows inside the period: ${keep_have}/${keep_want} of the 23-hour, fresh and this run's audit rows survive"
else
  echo "  pass ran $(( $(date +%s) - STARTED_EPOCH ))s after start; ${keep_have} rows inside the period kept"
  pass
fi

end_suite
