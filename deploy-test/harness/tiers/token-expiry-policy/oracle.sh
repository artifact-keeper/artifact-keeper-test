#!/usr/bin/env bash
# =============================================================================
# tiers/token-expiry-policy/oracle.sh — mandatory API token expiration (#3460)
# =============================================================================
# run.sh has stood up the `filesystem` profile-set with RATE_LIMIT_ENABLED=false
# and exported BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID,
# RELEASE_GATE=1, JUNIT_OUTPUT_DIR. We source common.sh for the assertion +
# JUnit harness, then drive the real HTTP flow against the live backend.
#
# Gates (ALL must hold, see the manifest for the full rationale):
#   (A) ENFORCEMENT  policy on -> omitted expiry is DEFAULTED (non-NULL
#                    expires_at in the DB), out-of-range is 400.
#   (B) EXEMPTION    service-account mints stay never-expiring until the admin
#                    opts them in; opted-in they are defaulted.
#   (C) MIGRATION    a pre-policy never-expiring token still authenticates
#                    under enforcement and is surfaced in the inventory.
#   (D) EXCHANGE CAP /v2/token never mints a bearer outliving the credential.
#   (E) DISABLE      turning the policy off restores historical behaviour.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

SUF="${RUN_ID##*-}-$$"
POLICY_URL="${BASE_URL}/api/v1/admin/settings/token-policy"

# --- helpers -----------------------------------------------------------------
# Callers use `BODY="$(req ...)"` (a subshell), so the status code cannot come
# back via a shell variable — req writes it to CODE_FILE and callers read it
# afterwards with `req_code`.
CODE_FILE="$(mktemp)"
trap 'rm -f "$CODE_FILE"' EXIT
req() { # METHOD URL BEARER [JSON_BODY] -> body on stdout, code via req_code
  local m="$1" url="$2" tok="$3" body="${4:-}" out
  if [ -n "$body" ]; then
    out="$(curl -s -w $'\n%{http_code}' $CURL_TIMEOUT -X "$m" \
      -H "Authorization: Bearer ${tok}" -H 'Content-Type: application/json' \
      -d "$body" "$url" 2>/dev/null)" || { printf '000' >"$CODE_FILE"; return 0; }
  else
    out="$(curl -s -w $'\n%{http_code}' $CURL_TIMEOUT -X "$m" \
      -H "Authorization: Bearer ${tok}" "$url" 2>/dev/null)" || { printf '000' >"$CODE_FILE"; return 0; }
  fi
  printf '%s' "${out##*$'\n'}" >"$CODE_FILE"
  printf '%s' "${out%$'\n'*}"
}
req_code() { cat "$CODE_FILE" 2>/dev/null || echo 000; }

put_policy() { # REQUIRED MIN MAX DEFAULT SA -> code via req_code
  req PUT "$POLICY_URL" "$ADMIN_TOKEN" \
    "{\"policy\":{\"require_expiration\":${1},\"min_days\":${2},\"max_days\":${3},\"default_days\":${4},\"apply_to_service_accounts\":${5}}}" \
    >/dev/null
}

mint() { # NAME EXPIRES(json: number or null) [SCOPE] -> body; code via req_code
  local scope="${3:-read:artifacts}"
  req POST "${BASE_URL}/api/v1/auth/tokens" "$ADMIN_TOKEN" \
    "{\"name\":\"${1}-${SUF}\",\"scopes\":[\"${scope}\"],\"expires_in_days\":${2}}"
}

db_expiry() { # TOKEN_ID -> "null" | timestamp | "?"
  docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc \
    "SELECT COALESCE(expires_at::text,'null') FROM api_tokens WHERE id='${1}';" 2>/dev/null \
    | tr -d '[:space:]' || echo "?"
}

v2_expires_in() { # RAW_TOKEN -> expires_in from the docker-login exchange
  curl -s $CURL_TIMEOUT -u "oracle:${1}" "${BASE_URL}/v2/token" 2>/dev/null \
    | jq -r '.expires_in // empty' 2>/dev/null || true
}

begin_suite "token-expiry-policy-3460"

auth_admin   # sets ADMIN_TOKEN from ADMIN_USER/ADMIN_PASS

# --- fixture: a never-expiring token minted BEFORE any policy ---------------
begin_test "fixture: policy off -> a never-expiring mint is accepted (historical behaviour)"
put_policy false 1 90 90 false
SETUP_PUT_CODE="$(req_code)"
LEGACY_BODY="$(mint legacy-preexisting null read:repositories)"; LEGACY_CODE="$(req_code)"
LEGACY_TOKEN="$(printf '%s' "$LEGACY_BODY" | jq -r '.token // empty' 2>/dev/null || true)"
LEGACY_ID="$(printf '%s' "$LEGACY_BODY" | jq -r '.id // empty' 2>/dev/null || true)"
if [ "$SETUP_PUT_CODE" != "200" ]; then
  fail "PUT ${POLICY_URL} -> ${SETUP_PUT_CODE} (pre-#3460 baseline has no policy endpoint = RED)"
elif [ "$LEGACY_CODE" = "200" ] && [ -n "$LEGACY_TOKEN" ] && [ "$(db_expiry "$LEGACY_ID")" = "null" ]; then
  pass
else
  fail "never-expiring mint refused or stamped while policy off: code=${LEGACY_CODE} db_expiry=$(db_expiry "$LEGACY_ID")"
fi

# --- (A) enforcement ---------------------------------------------------------
begin_test "(A) enable 1..30d/default-7 policy; omitted expiry is DEFAULTED not rejected (DB-asserted)"
put_policy true 1 30 7 false
PUT_CODE="$(req_code)"
DEF_BODY="$(mint defaulted null)"; DEF_CODE="$(req_code)"
DEF_ID="$(printf '%s' "$DEF_BODY" | jq -r '.id // empty' 2>/dev/null || true)"
DEF_EXP_FIELD="$(printf '%s' "$DEF_BODY" | jq -r '.expires_at // empty' 2>/dev/null || true)"
DEF_APPLIED="$(printf '%s' "$DEF_BODY" | jq -r '.policy_applied // empty' 2>/dev/null || true)"
DEF_DB="$(db_expiry "$DEF_ID")"
if [ "$PUT_CODE" != "200" ]; then
  fail "PUT enforcing policy -> ${PUT_CODE}"
elif [ "$DEF_CODE" = "200" ] && [ -n "$DEF_EXP_FIELD" ] && [ "$DEF_APPLIED" = "true" ] \
     && [ "$DEF_DB" != "null" ] && [ "$DEF_DB" != "?" ] && [ -n "$DEF_DB" ]; then
  pass
else
  fail "omitted-expiry mint under policy: code=${DEF_CODE} expires_at='${DEF_EXP_FIELD}' policy_applied='${DEF_APPLIED}' db='${DEF_DB}'"
fi

begin_test "(A) an explicit out-of-range mint (90d > max 30d) is rejected naming the range"
OOR_BODY="$(mint too-long 90)"; OOR_CODE="$(req_code)"
if [ "$OOR_CODE" = "400" ] && printf '%s' "$OOR_BODY" | grep -q "between 1 and 30"; then
  pass
else
  fail "90d mint under a 30d-max policy: code=${OOR_CODE} body=${OOR_BODY:0:200} (baseline mints it never-expiring = RED)"
fi

# --- (B) service-account exemption ------------------------------------------
begin_test "(B) service-account mint stays never-expiring under the enforced policy (exempt by default)"
SA_BODY="$(req POST "${BASE_URL}/api/v1/service-accounts" "$ADMIN_TOKEN" \
  "{\"name\":\"tep-${SUF}\",\"description\":\"dtf 3460\"}")"
SA_ID="$(printf '%s' "$SA_BODY" | jq -r '.id // empty' 2>/dev/null || true)"
SA_TOK_BODY="$(req POST "${BASE_URL}/api/v1/service-accounts/${SA_ID}/tokens" "$ADMIN_TOKEN" \
  "{\"name\":\"ci-${SUF}\",\"scopes\":[\"read:artifacts\"],\"expires_in_days\":null}")"
SA_TOK_CODE="$(req_code)"
SA_TOK_ID="$(printf '%s' "$SA_TOK_BODY" | jq -r '.id // empty' 2>/dev/null || true)"
if [ -z "$SA_ID" ]; then
  fail "could not create service account: ${SA_BODY:0:200}"
elif [ "$SA_TOK_CODE" = "200" ] && [ "$(db_expiry "$SA_TOK_ID")" = "null" ]; then
  pass
else
  fail "exempt SA mint: code=${SA_TOK_CODE} db_expiry=$(db_expiry "$SA_TOK_ID") (a defaulted/rejected SA mint = CI outage on a schedule)"
fi

begin_test "(B) apply_to_service_accounts=true subjects the SAME mint to the default (the exemption is a toggle)"
put_policy true 1 30 7 true
SA2_BODY="$(req POST "${BASE_URL}/api/v1/service-accounts/${SA_ID}/tokens" "$ADMIN_TOKEN" \
  "{\"name\":\"ci2-${SUF}\",\"scopes\":[\"read:artifacts\"],\"expires_in_days\":null}")"
SA2_CODE="$(req_code)"
SA2_ID="$(printf '%s' "$SA2_BODY" | jq -r '.id // empty' 2>/dev/null || true)"
SA2_DB="$(db_expiry "$SA2_ID")"
if [ "$SA2_CODE" = "200" ] && [ "$SA2_DB" != "null" ] && [ "$SA2_DB" != "?" ] && [ -n "$SA2_DB" ]; then
  pass
else
  fail "opted-in SA mint: code=${SA2_CODE} db_expiry='${SA2_DB}'"
fi
put_policy true 1 30 7 false

# --- (C) migration story -----------------------------------------------------
begin_test "(C) the pre-policy never-expiring token STILL authenticates under full enforcement"
ME_BODY="$(req GET "${BASE_URL}/api/v1/repositories" "$LEGACY_TOKEN")"
ME_CODE="$(req_code)"
if [ "$ME_CODE" = "200" ]; then
  pass
else
  fail "legacy token rejected after enabling the policy (code=${ME_CODE}) — enforcement must be mint-time only, or upgrades break running CI"
fi

begin_test "(C) GET surfaces the never-expiring inventory for deliberate rotation"
INV_BODY="$(req GET "$POLICY_URL" "$ADMIN_TOKEN")"
INV_CODE="$(req_code)"
INV_USERS="$(printf '%s' "$INV_BODY" | jq -r '.non_expiring_user_tokens // empty' 2>/dev/null || true)"
if [ "$INV_CODE" = "200" ] && [ -n "$INV_USERS" ] && [ "$INV_USERS" -ge 1 ] 2>/dev/null; then
  pass
else
  fail "inventory: code=${INV_CODE} non_expiring_user_tokens='${INV_USERS}' (legacy token must be visible)"
fi

# --- (D) /v2/token exchange cap ---------------------------------------------
begin_test "(D) negative control: a far-expiry token exchanges into the FULL base TTL"
FAR_BODY="$(mint cap-far 30)"
FAR_TOKEN="$(printf '%s' "$FAR_BODY" | jq -r '.token // empty' 2>/dev/null || true)"
FAR_EXP="$(v2_expires_in "$FAR_TOKEN")"
if [ -n "$FAR_EXP" ] && [ "$FAR_EXP" -ge 1200 ] 2>/dev/null; then
  pass
else
  fail "far-expiry exchange expires_in='${FAR_EXP}' (expected the uncapped base TTL, ~1800)"
fi

begin_test "(D) a token with ~5 minutes of life exchanges into a bearer capped <= 300s"
NEAR_BODY="$(mint cap-near 1)"
NEAR_TOKEN="$(printf '%s' "$NEAR_BODY" | jq -r '.token // empty' 2>/dev/null || true)"
NEAR_ID="$(printf '%s' "$NEAR_BODY" | jq -r '.id // empty' 2>/dev/null || true)"
docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc \
  "UPDATE api_tokens SET expires_at = NOW() + interval '5 minutes' WHERE id='${NEAR_ID}';" >/dev/null 2>&1 || true
NEAR_EXP="$(v2_expires_in "$NEAR_TOKEN")"
if [ -n "$NEAR_EXP" ] && [ "$NEAR_EXP" -le 300 ] 2>/dev/null && [ "$NEAR_EXP" -ge 60 ] 2>/dev/null; then
  pass
else
  fail "near-expiry exchange expires_in='${NEAR_EXP}' (a bearer outliving its credential lets swap-chains renew forever = RED on baseline)"
fi

# --- (E) disable restores historical behaviour -------------------------------
begin_test "(E) require_expiration=false -> an omitted-expiry mint is never-expiring again"
put_policy false 1 90 90 false
OFF_BODY="$(mint policy-off null)"; OFF_CODE="$(req_code)"
OFF_ID="$(printf '%s' "$OFF_BODY" | jq -r '.id // empty' 2>/dev/null || true)"
if [ "$OFF_CODE" = "200" ] && [ "$(db_expiry "$OFF_ID")" = "null" ]; then
  pass
else
  fail "post-disable mint: code=${OFF_CODE} db_expiry=$(db_expiry "$OFF_ID")"
fi

end_suite
