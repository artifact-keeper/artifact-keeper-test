#!/usr/bin/env bash
# =============================================================================
# tiers/restricted-token-refresh/oracle.sh
#   #4261  a repository-restricted session keeps its allow-list and scopes
#          across POST /api/v1/auth/refresh rotations (and the OCI
#          offline-token refresh), and a revoked, consumed or expired refresh
#          token is refused (#4663: no expiry leeway on AK's own tokens).
# See the manifest for the bug, how the restricted refresh token is obtained,
# and the gates.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID,
# DTF_SLOT, RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"
: "${DTF_SLOT:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

SUF="${RUN_ID##*-}-$$"
SLOT="$DTF_SLOT"
BACKEND_CONTAINER="ak-dtf${SLOT}-backend"
RA="rtr-a-${SLOT}-${SUF}"; RB="rtr-b-${SLOT}-${SUF}"
BYTES_A="rtr-bytes-A-${SUF}"; BYTES_B="rtr-bytes-B-${SUF}"
USER_NAME="rtr-user-${SLOT}-${SUF}"; USER_PASS="Rtr_${SUF}_Aa1!"
USER2_NAME="rtr-user2-${SLOT}-${SUF}"

WORK="$(mktemp -d -t dtf-rtr-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

req() {
  local method="$1" path="$2" tok="$3" data="${4:-}"
  local -a args=(-s "${CURL_TIMEOUT_ARGS[@]}" -X "$method" -o "$WORK/body" -w '%{http_code}')
  [ -n "$tok" ] && args+=(-H "Authorization: Bearer ${tok}")
  [ -n "$data" ] && args+=(-H 'Content-Type: application/json' --data "$data")
  : > "$WORK/body"
  curl "${args[@]}" "${BASE_URL}${path}" 2>/dev/null || echo 000
}
body() { cat "$WORK/body" 2>/dev/null || true; }
snip() { body | head -c 300 || true; }
jr() { body | jq -r "$1" 2>/dev/null || true; }
is_2xx() { case "$1" in 2??) return 0 ;; *) return 1 ;; esac; }
is_denied() { case "$1" in 403|404) return 0 ;; *) return 1 ;; esac; }
db() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -Atc "$1" 2>/dev/null || echo "?"; }
now() { date +%s; }

# --- JWT helpers (HS256, the deployment's own secret) ------------------------
b64u() { base64 -w0 | tr '+/' '-_' | tr -d '='; }
b64d() {
  local s="$1" pad
  pad=$(( (4 - ${#s} % 4) % 4 ))
  [ "$pad" -gt 0 ] && s="${s}$(printf '%*s' "$pad" '' | tr ' ' '=')"
  printf '%s' "$s" | tr -- '-_' '+/' | base64 -d 2>/dev/null || true
}
# claims JWT -> payload JSON
claims() { b64d "$(printf '%s' "$1" | cut -d. -f2)"; }
# cj JWT FILTER -> compact jq of the payload
cj() { claims "$1" | jq -c "$2" 2>/dev/null || true; }
# resign JWT JQ_FILTER -> the same header, the filtered payload, a fresh HS256 signature
resign() {
  local h p
  h="$(printf '%s' "$1" | cut -d. -f1)"
  p="$(claims "$1" | jq -c "$2" | b64u)"
  printf '%s.%s.%s' "$h" "$p" "$(printf '%s.%s' "$h" "$p" | openssl dgst -sha256 -hmac "$JWT_SECRET" -binary | b64u)"
}

# refresh RT -> HTTP code of POST /auth/refresh; body in $WORK/body
refresh() { req POST /api/v1/auth/refresh "" "{\"refresh_token\":\"$1\"}"; }
# oci_refresh RT -> HTTP code of the registry refresh grant
oci_refresh() {
  : > "$WORK/body"
  curl -s "${CURL_TIMEOUT_ARGS[@]}" -o "$WORK/body" -w '%{http_code}' -X POST \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode "grant_type=refresh_token" --data-urlencode "refresh_token=$1" \
    --data-urlencode "service=artifact-keeper" "${BASE_URL}/v2/token" 2>/dev/null || echo 000
}
login_pair() { # USER PASS -> sets LP_ACCESS LP_REFRESH
  req POST /api/v1/auth/login "" "{\"username\":\"$1\",\"password\":\"$2\"}" >/dev/null
  LP_ACCESS="$(jr '.access_token // empty')"; LP_REFRESH="$(jr '.refresh_token // empty')"
}
dl() { req GET "/api/v1/repositories/$1/download/obj.txt" "$2"; }
put_obj() { # REPO TOKEN BYTES -> code
  printf '%s' "$3" > "$WORK/up"
  curl -s "${CURL_TIMEOUT_ARGS[@]}" -o "$WORK/body" -w '%{http_code}' -X PUT \
    -H "Authorization: Bearer $2" --data-binary "@$WORK/up" \
    "${BASE_URL}/api/v1/repositories/$1/artifacts/w-${SUF}.txt" 2>/dev/null || echo 000
}
# confined ACCESS WHAT: claims [A] / [read:artifacts], reads A, refused B, cannot write A
confined() {
  local code
  [ "$(cj "$1" '.allowed_repo_ids')" = "[\"${A_ID}\"]" ] || gate "$2: access allowed_repo_ids=$(cj "$1" '.allowed_repo_ids'), expected [A]"
  [ "$(cj "$1" '.scopes')" = '["read:artifacts"]' ] || gate "$2: access scopes=$(cj "$1" '.scopes'), expected [read:artifacts]"
  code="$(dl "$RA" "$1")"
  [ "$code" = "200" ] && [ "$(body)" = "$BYTES_A" ] || gate "$2: download A answered ${code}"
  code="$(dl "$RB" "$1")"
  is_denied "$code" || gate "$2: download B answered ${code}, expected 403/404"
  body | grep -q "$BYTES_B" && gate "$2: read B's bytes"
  code="$(put_obj "$RA" "$1" "w")"
  is_denied "$code" || gate "$2: upload to A answered ${code}, expected 403 (scope read:artifacts)"
  return 0
}
refused() { # CODE WHAT
  [ "$1" = "401" ] || gate "$2 answered $1, expected 401: $(snip | head -c 160)"
  [ -z "$(jr '.access_token // empty')" ] || gate "$2 returned an access_token"
  return 0
}

FAILS=0
DETAIL=""
gate(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

# =============================================================================
begin_suite "restricted-token-refresh"

begin_test "setup: private repos A and B, a user with read+write on both, a selector token on A, the deployment's JWT secret"
auth_admin
SETUP_ERR=""
JWT_SECRET="$(docker inspect "$BACKEND_CONTAINER" --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null \
  | sed -n 's/^JWT_SECRET=//p' | head -n1)"
[ -n "$JWT_SECRET" ] || SETUP_ERR="${SETUP_ERR} jwt-secret"
mk_repo() {
  req POST /api/v1/repositories "$ADMIN_TOKEN" \
    "{\"key\":\"$1\",\"name\":\"$1\",\"format\":\"generic\",\"repo_type\":\"local\",\"is_public\":false}" >/dev/null
  jr '.id // empty'
}
A_ID="$(mk_repo "$RA")"; B_ID="$(mk_repo "$RB")"
[ -n "$A_ID" ] && [ -n "$B_ID" ] || SETUP_ERR="${SETUP_ERR} repos"
for pair in "$RA|$BYTES_A" "$RB|$BYTES_B"; do
  printf '%s' "${pair##*|}" > "$WORK/up"
  code="$(curl -s "${CURL_TIMEOUT_ARGS[@]}" -o /dev/null -w '%{http_code}' -X PUT -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    --data-binary "@$WORK/up" "${BASE_URL}/api/v1/repositories/${pair%%|*}/artifacts/obj.txt" 2>/dev/null || echo 000)"
  is_2xx "$code" || SETUP_ERR="${SETUP_ERR} upload(${pair%%|*}:${code})"
done
U_ID="$(create_test_user_with_retry "$USER_NAME" "$USER_PASS" "${USER_NAME}@dtf.test" 2>/dev/null || true)"
U2_ID="$(create_test_user_with_retry "$USER2_NAME" "$USER_PASS" "${USER2_NAME}@dtf.test" 2>/dev/null || true)"
[ -n "$U_ID" ] && [ -n "$U2_ID" ] || SETUP_ERR="${SETUP_ERR} users"
for uid in "$U_ID" "$U2_ID"; do
  for r in "$A_ID" "$B_ID"; do
    code="$(req POST /api/v1/permissions "$ADMIN_TOKEN" \
      "{\"principal_type\":\"user\",\"principal_id\":\"${uid}\",\"target_type\":\"repository\",\"target_id\":\"${r}\",\"actions\":[\"read\",\"write\"]}")"
    is_2xx "$code" || SETUP_ERR="${SETUP_ERR} grant(${code})"
  done
done
login_pair "$USER_NAME" "$USER_PASS"; UT="$LP_ACCESS"
[ -n "$UT" ] || SETUP_ERR="${SETUP_ERR} login"
req POST /api/v1/auth/tokens "$UT" "{\"name\":\"rtr-ta-${SUF}\",\"scopes\":[\"read:artifacts\"],\"repo_selector\":{\"match_repos\":[\"${A_ID}\"]}}" >/dev/null
TA="$(jr '.token // empty')"
[ -n "$TA" ] || SETUP_ERR="${SETUP_ERR} selector-token($(snip | head -c 120))"
if [ -n "$SETUP_ERR" ]; then infra_fail "setup failed:${SETUP_ERR}"; end_suite; fi
code="$(dl "$RB" "$UT")"
[ "$code" = "200" ] || { infra_fail "the user's own session cannot read B (${code}); every denial would be hollow"; end_suite; }
echo "-- A=${RA} (${A_ID}) B=${RB} (${B_ID}) user=${USER_NAME}"
pass

# Restricted refresh token: a real login family, re-signed with the restriction.
login_pair "$USER_NAME" "$USER_PASS"
R0="$(resign "$LP_REFRESH" ".allowed_repo_ids=[\"${A_ID}\"] | .scopes=[\"read:artifacts\"]")"
FAMILY="$(cj "$LP_REFRESH" '.family_id' | tr -d '"')"

# =============================================================================
# CONTROLS (both images)
# =============================================================================
begin_test "CONTROL: the /v2/token exchange of a restricted API token is restricted and hands out no refresh token"
reset_case
code="$(curl -s "${CURL_TIMEOUT_ARGS[@]}" -o "$WORK/body" -w '%{http_code}' -u "${USER_NAME}:${TA}" \
  "${BASE_URL}/v2/token?service=artifact-keeper&offline_token=true" 2>/dev/null || echo 000)"
tok="$(jr '.token // empty')"
note "/v2/token with the selector token: ${code} keys=$(jr 'keys | join(",")') claims=$(cj "$tok" '{allowed_repo_ids,scopes}')"
[ "$code" = "200" ] && [ -n "$tok" ] || gate "/v2/token answered ${code}"
[ -z "$(jr '.refresh_token // empty')" ] || gate "a refresh token was handed out for an API-token exchange"
[ "$(cj "$tok" '.allowed_repo_ids')" = "[\"${A_ID}\"]" ] || gate "exchanged access token allowed_repo_ids=$(cj "$tok" '.allowed_repo_ids')"
finish_case "the API-token exchange widened, or leaked a refresh token"

begin_test "CONTROL: the first rotation of a restricted refresh token mints a restricted, read-only access token"
reset_case
code="$(refresh "$R0")"
A1="$(jr '.access_token // empty')"; R1="$(jr '.refresh_token // empty')"
note "rotation 1: ${code} access=$(cj "$A1" '{allowed_repo_ids,scopes}')"
[ "$code" = "200" ] && [ -n "$A1" ] && [ -n "$R1" ] || gate "rotation 1 answered ${code}: $(snip)"
[ -n "$A1" ] && confined "$A1" "rotation 1"
finish_case "the refresh path does not honour the claims it is given"

begin_test "CONTROL: the OCI offline-token refresh keeps the restriction across two rotations"
reset_case
code="$(curl -s "${CURL_TIMEOUT_ARGS[@]}" -o "$WORK/body" -w '%{http_code}' -u "${USER_NAME}:${USER_PASS}" \
  "${BASE_URL}/v2/token?service=artifact-keeper&offline_token=true" 2>/dev/null || echo 000)"
ORT="$(jr '.refresh_token // empty')"
note "offline token: ${code} type=$(cj "$ORT" '.token_type')"
if [ -z "$ORT" ]; then
  gate "no offline refresh token for a password login (${code})"
else
  O0="$(resign "$ORT" ".allowed_repo_ids=[\"${A_ID}\"] | .scopes=[\"read:artifacts\"]")"
  code="$(oci_refresh "$O0")"; O1="$(jr '.refresh_token // empty')"
  note "OCI rotation 1: ${code} refresh=$(cj "$O1" '{token_type,allowed_repo_ids,scopes}')"
  [ "$code" = "200" ] && [ -n "$O1" ] || gate "OCI rotation 1 answered ${code}: $(snip)"
  code="$(oci_refresh "$O1")"; OA2="$(jr '.access_token // empty')"
  note "OCI rotation 2: ${code} access=$(cj "$OA2" '{allowed_repo_ids,scopes}')"
  [ "$code" = "200" ] && [ -n "$OA2" ] || gate "OCI rotation 2 answered ${code}: $(snip)"
  [ -n "$OA2" ] && [ "$(cj "$OA2" '.allowed_repo_ids')" = "[\"${A_ID}\"]" ] \
    || gate "OCI rotation 2 access allowed_repo_ids=$(cj "$OA2" '.allowed_repo_ids'), expected [A]"
  code="$(dl "$RB" "$OA2")"; is_denied "$code" || gate "OCI rotation 2 token download B answered ${code}"
fi
finish_case "the OCI offline-token refresh widens a restricted grant"

begin_test "CONTROL: a consumed refresh token replayed, an access token presented as one, and one 120 s past exp are refused"
reset_case
# A separate family: a genuine replay revokes the whole family, and R0's
# family is the one the FIX cases keep rotating.
login_pair "$USER_NAME" "$USER_PASS"; RP="$LP_REFRESH"
code="$(refresh "$RP")"; [ "$code" = "200" ] || gate "first use of a fresh refresh token answered ${code}"
code="$(refresh "$RP")"; note "replaying a consumed refresh token: ${code}"; refused "$code" "replay of a consumed refresh token"
login_pair "$USER_NAME" "$USER_PASS"
code="$(refresh "$LP_ACCESS")"; note "access token as refresh token: ${code}"; refused "$code" "an access token presented as a refresh token"
E120="$(resign "$LP_REFRESH" ".exp=$(( $(now) - 120 ))")"
code="$(refresh "$E120")"; note "refresh token 120 s past exp: ${code} $(jr '.message')"; refused "$code" "a refresh token 120 s past exp"
code="$(refresh "$LP_REFRESH")"; note "the same family's live token: ${code}"
[ "$code" = "200" ] || gate "the unexpired original of that token answered ${code} (the refusals above would be hollow)"
finish_case "a consumed, mistyped or long-expired refresh token rotates"

begin_test "CONTROL: logout revokes the session's refresh family; a deactivated user cannot refresh"
reset_case
login_pair "$USER_NAME" "$USER_PASS"; LA="$LP_ACCESS"; LR="$LP_REFRESH"; LF="$(cj "$LR" '.family_id' | tr -d '"')"
code="$(req POST /api/v1/auth/logout "$LA" "{\"refresh_token\":\"${LR}\"}")"
is_2xx "$code" || gate "logout answered ${code}"
code="$(refresh "$LR")"; note "refresh after logout: ${code}"; refused "$code" "refresh after logout"
live="$(db "SELECT count(*) FROM refresh_token_jti WHERE family_id = '${LF}' AND revoked_at IS NULL")"
[ "$live" = "0" ] || gate "${live} unrevoked refresh_token_jti row(s) remain in the logged-out family"
login_pair "$USER2_NAME" "$USER_PASS"; R2U="$LP_REFRESH"
code="$(req PATCH "/api/v1/users/${U2_ID}" "$ADMIN_TOKEN" '{"is_active":false}')"
is_2xx "$code" || gate "deactivating user2 answered ${code}"
code="$(refresh "$R2U")"; note "refresh for a deactivated user: ${code}"; refused "$code" "refresh for a deactivated user"
finish_case "a revoked session or a deactivated account refreshes"

# =============================================================================
# FIX #4261 (RED on 1.11.0)
# =============================================================================
begin_test "FIX #4261: the refresh token the server mints on rotation carries the allow-list and the scope ceiling"
reset_case
note "rotation 1's server-minted refresh token: $(cj "$R1" '{token_type,allowed_repo_ids,scopes}')"
[ "$(cj "$R1" '.token_type')" = '"refresh"' ] || gate "R1 token_type=$(cj "$R1" '.token_type')"
[ "$(cj "$R1" '.allowed_repo_ids')" = "[\"${A_ID}\"]" ] || gate "R1 allowed_repo_ids=$(cj "$R1" '.allowed_repo_ids'), expected [A] (1.11.0 signs it null)"
[ "$(cj "$R1" '.scopes')" = '["read:artifacts"]' ] || gate "R1 scopes=$(cj "$R1" '.scopes'), expected [read:artifacts]"
finish_case "the rotated refresh token drops the repository restriction"

begin_test "FIX #4261: the second and third rotations still mint access tokens confined to A and read-only"
reset_case
code="$(refresh "$R1")"; A2="$(jr '.access_token // empty')"; R2="$(jr '.refresh_token // empty')"
note "rotation 2: ${code} access=$(cj "$A2" '{allowed_repo_ids,scopes}')"
[ "$code" = "200" ] && [ -n "$A2" ] || gate "rotation 2 answered ${code}: $(snip)"
[ -n "$A2" ] && confined "$A2" "rotation 2"
if [ -n "$R2" ]; then
  code="$(refresh "$R2")"; A3="$(jr '.access_token // empty')"
  note "rotation 3: ${code} access=$(cj "$A3" '{allowed_repo_ids,scopes}')"
  [ "$code" = "200" ] && [ -n "$A3" ] || gate "rotation 3 answered ${code}"
  [ -n "$A3" ] && confined "$A3" "rotation 3"
fi
n="$(db "SELECT count(*) FROM refresh_token_jti WHERE family_id = '${FAMILY}'")"
note "refresh_token_jti rows in the restricted family: ${n}"
finish_case "a restricted session comes back unrestricted after a refresh"

# =============================================================================
# FIX #4663, refresh half (RED on 1.11.0)
# =============================================================================
begin_test "FIX #4663: a refresh token 5 s past its exp is refused (no validation leeway on AK's own tokens)"
reset_case
login_pair "$USER_NAME" "$USER_PASS"
E5="$(resign "$LP_REFRESH" ".exp=$(( $(now) - 5 ))")"
code="$(refresh "$E5")"
note "refresh token 5 s past exp: ${code} $(jr '.message // empty')"
refused "$code" "a refresh token 5 s past exp"
finish_case "an expired refresh token rotates inside the 60 s leeway"

end_suite
