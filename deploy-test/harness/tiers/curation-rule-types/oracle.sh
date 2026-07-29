#!/usr/bin/env bash
# =============================================================================
# tiers/curation-rule-types/oracle.sh — typed curation rules foundation (#2947)
# =============================================================================
# run.sh has stood up the `filesystem` profile-set with RATE_LIMIT_ENABLED=false
# and exported BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID,
# JUNIT_OUTPUT_DIR, COMMON_SH. We source common.sh for the assertion + JUnit
# harness, then drive the real HTTP flow against the backend.
#
# Gates:
#   (TYPED)      global publisher_trust rule: POST /api/v1/curation/rules with
#                rule_type/config/scope=global -> 201, response echoes all
#                three; GET /rules?scope=global contains it. Pre-#2947 images
#                silently drop the unknown fields -> RED.
#   (VALIDATE)   rule_type=mystery -> 400. Pre-#2947 -> 201 (RED).
#   (REGRESSION) legacy 3-field pattern rule still enforces: staging-scoped
#                'telnet*' block + seeded pending package telnet-server ->
#                POST /packages/re-evaluate (default allow) -> blocked.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

SUF="${RUN_ID##*-}-$$"
REPO="crt-staging-${DTF_SLOT:-x}-${SUF}"

begin_suite "curation-rule-types-2947"

auth_admin   # sets ADMIN_TOKEN

api_call() { # METHOD PATH [BODY] -> sets API_STATUS + API_BODY (no subshell)
  local method="$1" path="$2" body="${3:-}" tmp
  tmp=$(mktemp)
  if [ -n "$body" ]; then
    API_STATUS=$(curl -s -o "$tmp" -w '%{http_code}' -X "$method" \
      -H "$(auth_header)" -H 'Content-Type: application/json' \
      -d "$body" "${BASE_URL}${path}" 2>/dev/null) || API_STATUS=000
  else
    API_STATUS=$(curl -s -o "$tmp" -w '%{http_code}' -X "$method" \
      -H "$(auth_header)" "${BASE_URL}${path}" 2>/dev/null) || API_STATUS=000
  fi
  API_BODY="$(cat "$tmp")"; rm -f "$tmp"
}

# --- (TYPED) global publisher_trust rule round-trip --------------------------
begin_test "TYPED: create global publisher_trust rule -> 201 + rule_type/config/scope echoed"
BODY='{"action":"block","reason":"crt-2947 typed probe","rule_type":"publisher_trust","config":{"min_trust":0.9},"scope":"global","priority":42}'
api_call POST /api/v1/curation/rules "$BODY"; RESP="$API_BODY"
RULE_ID="$(echo "$RESP" | jq -r '.id // empty' 2>/dev/null || true)"
R_TYPE="$(echo "$RESP" | jq -r '.rule_type // empty' 2>/dev/null || true)"
R_SCOPE="$(echo "$RESP" | jq -r '.scope // empty' 2>/dev/null || true)"
R_CFG="$(echo "$RESP" | jq -r '.config.min_trust // empty' 2>/dev/null || true)"
if [ "$API_STATUS" = "201" ] && [ "$R_TYPE" = "publisher_trust" ] && \
   [ "$R_SCOPE" = "global" ] && [ "$R_CFG" = "0.9" ]; then
  pass
else
  fail "typed rule did not round-trip (#2947): status=${API_STATUS} rule_type='${R_TYPE}' scope='${R_SCOPE}' config.min_trust='${R_CFG}' (pre-#2947 drops the fields)" \
       "resp=${RESP}"
fi

begin_test "TYPED: GET /rules?scope=global lists the typed rule"
api_call GET '/api/v1/curation/rules?scope=global'; LIST="$API_BODY"
FOUND="$(echo "$LIST" | jq -r --arg id "$RULE_ID" '[.[]? | select(.id == $id and .rule_type == "publisher_trust")] | length' 2>/dev/null || echo 0)"
if [ "$API_STATUS" = "200" ] && [ "$FOUND" = "1" ]; then
  pass
else
  fail "global-baseline listing missing the typed rule: status=${API_STATUS} found=${FOUND}" \
       "list=$(echo "$LIST" | head -c 400)"
fi

# --- (VALIDATE) unknown rule_type rejected -----------------------------------
begin_test "VALIDATE: rule_type=mystery -> 400"
api_call POST /api/v1/curation/rules '{"action":"block","reason":"crt bad","rule_type":"mystery"}'; MRESP="$API_BODY"
if [ "$API_STATUS" = "400" ]; then
  pass
else
  fail "unknown rule_type accepted: status=${API_STATUS}, expected 400 (pre-#2947 returns 201)" \
       "resp=${MRESP}"
  # If it slipped in, clean it up so re-runs stay deterministic.
  MID="$(echo "$MRESP" | jq -r '.id // empty' 2>/dev/null || true)"
  [ -n "$MID" ] && api_call DELETE "/api/v1/curation/rules/${MID}"
fi

# --- (REGRESSION) legacy pattern rule still enforces -------------------------
create_repo "$REPO" "rpm" "local"
STAGING_ID="$(docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc \
  "SELECT id FROM repositories WHERE key='${REPO}'")"

begin_test "REGRESSION: legacy 3-field pattern rule create -> 201 (no typed fields required)"
PBODY="{\"staging_repo_id\":\"${STAGING_ID}\",\"package_pattern\":\"telnet*\",\"action\":\"block\",\"reason\":\"crt-2947 pattern regression\"}"
api_call POST /api/v1/curation/rules "$PBODY"; PRESP="$API_BODY"
PRULE_ID="$(echo "$PRESP" | jq -r '.id // empty' 2>/dev/null || true)"
P_TYPE="$(echo "$PRESP" | jq -r '.rule_type // "pattern"' 2>/dev/null || true)"
if [ "$API_STATUS" = "201" ] && [ -n "$PRULE_ID" ] && [ "$P_TYPE" = "pattern" ]; then
  pass
else
  fail "legacy pattern-rule create broke: status=${API_STATUS} rule_type='${P_TYPE}'" \
       "resp=${PRESP}"
fi

begin_test "REGRESSION: pattern rule blocks a seeded pending package via re-evaluate"
docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "
  INSERT INTO curation_packages
    (staging_repo_id, remote_repo_id, format, package_name, version, upstream_path, status)
  VALUES ('${STAGING_ID}', '${STAGING_ID}', 'rpm', 'telnet-server', '1.0', '/telnet-server', 'pending')" >/dev/null
REBODY="{\"staging_repo_id\":\"${STAGING_ID}\",\"default_action\":\"allow\"}"
api_call POST /api/v1/curation/packages/re-evaluate "$REBODY"; RECOUNT="$API_BODY"
BLOCKED="$(docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc \
  "SELECT count(*) FROM curation_packages
   WHERE staging_repo_id='${STAGING_ID}' AND package_name='telnet-server' AND status='blocked'")"
if [ "$API_STATUS" = "200" ] && [ "$BLOCKED" = "1" ]; then
  pass
else
  fail "pattern enforcement regressed: re-evaluate status=${API_STATUS} count=${RECOUNT} blocked_rows=${BLOCKED} (expected the telnet* block rule to blocklist telnet-server)" \
       "staging=${STAGING_ID}"
fi

# --- cleanup -----------------------------------------------------------------
[ -n "${RULE_ID:-}" ] && api_call DELETE "/api/v1/curation/rules/${RULE_ID}"
[ -n "${PRULE_ID:-}" ] && api_call DELETE "/api/v1/curation/rules/${PRULE_ID}"
docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc \
  "DELETE FROM curation_packages WHERE staging_repo_id='${STAGING_ID}'" >/dev/null 2>&1
api_call DELETE "/api/v1/repositories/${REPO}" 2>/dev/null

end_suite
