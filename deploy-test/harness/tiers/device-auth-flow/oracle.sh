#!/usr/bin/env bash
# =============================================================================
# tiers/device-auth-flow/oracle.sh
#   #3461 RFC 8628 device authorization grant, end to end with curl: issue,
#         pending, slow_down, approve as a non-admin, redeem once, scope cap,
#         throttle, refused approvers, sign-out voiding, audit trail, and the
#         DEVICE_AUTH_ENABLED kill switch.
# See the manifest for THE FEATURE and the gates.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# DTF_DIR, BACKEND_IMAGE and the slot port block (HTTP_PORT, GRPC_PORT,
# PG_PORT), RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"
: "${DTF_SLOT:?}"; : "${RUN_ID:?}"; : "${DTF_DIR:?}"; : "${BACKEND_IMAGE:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

BASE="$BASE_URL"
SUF="${DTF_SLOT}-${RUN_ID##*-}"
CLIENT="dtf-cli-${SUF}"
GRANT="urn:ietf:params:oauth:grant-type:device_code"
INTERVAL=2            # DEVICE_AUTH_POLL_INTERVAL_SECS in profiles/auth.device.yml
USER_BUDGET=5         # DEVICE_AUTH_MAX_FAILED_ATTEMPTS_PER_USER (shipped default)

setup_workdir
W="$WORK_DIR"

jqr(){ jq -r "$1" 2>/dev/null || true; }
db(){ docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]' || true; }
sha(){ printf '%s' "$1" | sha256sum | awk '{print $1}'; }
jwt_claims(){ printf '%s' "$1" | cut -d. -f2 | tr '_-' '/+' | awk '{l=length($0)%4; if(l==2)$0=$0"=="; else if(l==3)$0=$0"="; print}' | base64 -d 2>/dev/null || true; }

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

# login <user> <pass> -> full JSON login response
login_json(){
  curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg u "$1" --arg p "$2" '{username:$u,password:$p}')" || true
}

# All helpers write the body to $W/body and the headers to $W/hdr and echo the
# HTTP status.
body(){ cat "$W/body" 2>/dev/null || true; }
hdr(){ grep -i "^$1:" "$W/hdr" 2>/dev/null | head -1 | cut -d: -f2- | tr -d '\r' | sed 's/^ *//' || true; }

# device_code_req <form-urlencoded body>
device_code_req(){
  curl -s -D "$W/hdr" -o "$W/body" -w '%{http_code}' -X POST \
    -H 'Content-Type: application/x-www-form-urlencoded' --data "$1" \
    "$BASE/api/v1/auth/device/code" || echo 000
}
# poll <device_code> [client_id]
poll(){
  curl -s -D "$W/hdr" -o "$W/body" -w '%{http_code}' -X POST \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode "grant_type=$GRANT" --data-urlencode "device_code=$1" \
    --data-urlencode "client_id=${2:-$CLIENT}" "$BASE/api/v1/auth/device/token" || echo 000
}
# decide <verify|approve|deny> <authorization header value> <user_code>
decide(){
  curl -s -D "$W/hdr" -o "$W/body" -w '%{http_code}' -X POST \
    -H "Authorization: $2" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg c "$3" '{user_code:$c}')" "$BASE/api/v1/auth/device/$1" || echo 000
}
# start_flow <scope string> -> sets DC UC (empty on failure), status in START_ST
start_flow(){
  START_ST=$(device_code_req "client_id=${CLIENT}&scope=$(printf '%s' "$1" | sed 's/ /+/g')")
  DC=$(body | jqr '.device_code // empty'); UC=$(body | jqr '.user_code // empty')
}
session_col(){ db "SELECT $2 FROM device_sessions WHERE device_code_hash='$(sha "$1")'"; }
# audit_has <sql predicate on audit_log> -> waits up to 10 s for a row (audit is fire-and-forget)
audit_has(){
  local i n
  for i in $(seq 1 20); do
    n=$(db "SELECT count(*) FROM audit_log WHERE $1")
    [ -n "$n" ] && [ "$n" != "0" ] && { echo "$n"; return 0; }
    [ "$i" -lt 20 ] && sleep 0.5
  done
  echo "${n:-0}"; return 1
}
# A syntactically valid user code that is (with overwhelming probability) not
# live: 8 letters from the RFC 8628 alphabet.
WRONG_CODES=(BBBB-BBBB CCCC-CCCC DDDD-DDDD FFFF-FFFF GGGG-GGGG HHHH-HHHH JJJJ-JJJJ)

begin_suite "device-auth-flow"
auth_admin

# ---------------------------------------------------------------------------
begin_test "CONTROL setup + login: four non-admin users sign in; /auth/me resolves each session; an API token authenticates"
reset_case
mk_user(){ # <name> -> sets <uid> on stdout
  create_test_user_with_retry "$1" "$2" "$1@dtf.test" || true
}
U1="dtf-dev-approver-${SUF}"; U2="dtf-dev-guesser-${SUF}"; U3="dtf-dev-locked-${SUF}"; U4="dtf-dev-signout-${SUF}"
PW="DtfDevice!${SUF}-Strong"
U1ID=$(mk_user "$U1" "$PW"); U2ID=$(mk_user "$U2" "$PW"); U3ID=$(mk_user "$U3" "$PW"); U4ID=$(mk_user "$U4" "$PW")
[ -n "$U1ID" ] && [ -n "$U2ID" ] && [ -n "$U3ID" ] && [ -n "$U4ID" ] || fail_g "user create failed ($U1ID/$U2ID/$U3ID/$U4ID)"
T1=$(login_json "$U1" "$PW" | jqr '.access_token // empty')
T2=$(login_json "$U2" "$PW" | jqr '.access_token // empty')
T3=$(login_json "$U3" "$PW" | jqr '.access_token // empty')
L4=$(login_json "$U4" "$PW"); T4=$(echo "$L4" | jqr '.access_token // empty'); R4=$(echo "$L4" | jqr '.refresh_token // empty')
[ -n "$T1" ] && [ -n "$T2" ] && [ -n "$T3" ] && [ -n "$T4" ] && [ -n "$R4" ] || fail_g "a non-admin login returned no token pair"
ME=$(curl -s "$BASE/api/v1/auth/me" -H "Authorization: Bearer $T1" | jqr '.username // empty')
[ "$ME" = "$U1" ] || fail_g "/auth/me with U1's session = '$ME' (expected $U1)"
APIT=$(curl -s -X POST "$BASE/api/v1/auth/tokens" -H "Authorization: Bearer $T1" -H 'Content-Type: application/json' \
  -d "{\"name\":\"dtf-dev-${SUF}\",\"scopes\":[\"read:artifacts\"],\"repo_selector\":{\"match_pattern\":\"dtf-dev-${SUF}-*\"}}" | jqr '.token // empty')
[ -n "$APIT" ] || fail_g "repo-restricted API token create failed"
ME=$(curl -s "$BASE/api/v1/auth/me" -H "Authorization: Bearer $APIT" | jqr '.username // empty')
[ "$ME" = "$U1" ] || fail_g "/auth/me with U1's API token = '$ME' (expected $U1)"
finish_case "baseline login / token use broken"

# ---------------------------------------------------------------------------
begin_test "FIX #3461 issue: /device/code -> device_code (64 hex), user_code XXXX-XXXX, verification_uri /device, interval=${INTERVAL}, expires_in=600, no-store; stored as digests"
reset_case
CFG=$(curl -s "$BASE/api/v1/system/config" | jqr '.auth.device_authorization_enabled')
[ "$CFG" = "true" ] || fail_g "/system/config auth.device_authorization_enabled='$CFG' (expected true)"
start_flow "read:artifacts write:artifacts delete:artifacts"
B=$(body); note "device/code -> $START_ST $(echo "$B" | jq -c '.device_code|=(.[0:8]+"...")' 2>/dev/null || echo "$B" | head -c 200)"
[ "$START_ST" = "200" ] || fail_g "device/code answered $START_ST (expected 200)"
[[ "$DC" =~ ^[0-9a-f]{64}$ ]] || fail_g "device_code '$DC' is not 64 hex characters"
[[ "$UC" =~ ^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$ ]] || fail_g "user_code '$UC' not XXXX-XXXX over the RFC 8628 consonant alphabet"
VU=$(echo "$B" | jqr '.verification_uri'); [[ "$VU" == */device ]] || fail_g "verification_uri '$VU' does not end in /device"
[ "$(echo "$B" | jqr '.interval')" = "$INTERVAL" ] || fail_g "interval=$(echo "$B" | jqr '.interval') (expected $INTERVAL)"
[ "$(echo "$B" | jqr '.expires_in')" = "600" ] || fail_g "expires_in=$(echo "$B" | jqr '.expires_in') (expected 600)"
[ "$(echo "$B" | jqr 'has("verification_uri_complete")')" = "false" ] || fail_g "verification_uri_complete present (must be absent)"
hdr cache-control | grep -qi 'no-store' || fail_g "Cache-Control '$(hdr cache-control)' lacks no-store"
FLOW_A_DC="$DC"; FLOW_A_UC="$UC"
[ "$(session_col "$DC" status)" = "pending" ] || fail_g "no pending device_sessions row keyed by sha256(device_code)"
[ "$(db "SELECT count(*) FROM device_sessions WHERE device_code_hash='$DC' OR user_code_hash='$UC' OR user_code_hash='${UC/-/}'")" = "0" ] \
  || fail_g "a plaintext code is stored in device_sessions"
audit_has "action='DEVICE_CODE_ISSUED' AND details->>'client_id'='$CLIENT'" >/dev/null || fail_g "no DEVICE_CODE_ISSUED audit row for $CLIENT"
finish_case "device authorization request not served"

begin_test "FIX #3461 scope refusal: scope=admin and scope=* -> 400 invalid_scope, no row"
reset_case
N0=$(db "SELECT count(*) FROM device_sessions")
for s in admin '*'; do
  C=$(curl -s -o "$W/body" -w '%{http_code}' -X POST "$BASE/api/v1/auth/device/code" \
    --data-urlencode "client_id=$CLIENT" --data-urlencode "scope=$s" || echo 000)
  note "scope=$s -> $C $(body | head -c 160)"
  [ "$C" = "400" ] && [ "$(body | jqr '.error')" = "invalid_scope" ] || fail_g "scope=$s answered $C error='$(body | jqr '.error')' (expected 400 invalid_scope)"
done
[ "$(db "SELECT count(*) FROM device_sessions")" = "$N0" ] || fail_g "a refused scope request created a device_sessions row"
finish_case "ungrantable scopes not refused"

begin_test "FIX #3461 polling: before approval -> authorization_pending; faster than interval -> slow_down (+5 s on the row)"
reset_case
start_flow "read:artifacts"
C1=$(poll "$DC"); E1=$(body | jqr '.error')
C2=$(poll "$DC"); E2=$(body | jqr '.error')
note "poll#1 -> $C1 $E1; immediate poll#2 -> $C2 $E2; row interval_secs=$(session_col "$DC" interval_secs)"
[ "$C1" = "400" ] && [ "$E1" = "authorization_pending" ] || fail_g "first poll $C1/$E1 (expected 400 authorization_pending)"
[ "$C2" = "400" ] && [ "$E2" = "slow_down" ] || fail_g "immediate re-poll $C2/$E2 (expected 400 slow_down)"
[ "$(session_col "$DC" interval_secs)" = "$((INTERVAL + 5))" ] || fail_g "interval_secs after slow_down = '$(session_col "$DC" interval_secs)' (expected $((INTERVAL + 5)))"
# Flow A also gets a pending poll on record (RFC 8628 client behaviour).
C=$(poll "$FLOW_A_DC"); [ "$(body | jqr '.error')" = "authorization_pending" ] || fail_g "flow A poll $C/$(body | jqr '.error') (expected authorization_pending)"
finish_case "RFC 8628 polling errors not served"

begin_test "FIX #3461 approve as a non-admin: verify shows granted vs withheld scopes; approve binds the row to the approver"
reset_case
C=$(decide verify "Bearer $T1" "$(echo "$FLOW_A_UC" | tr '[:upper:]' '[:lower:]' | tr -d '-')"); B=$(body)
note "verify (lower-case, no hyphen) -> $C $B"
[ "$C" = "200" ] || fail_g "verify answered $C (expected 200)"
[ "$(echo "$B" | jqr '.scopes|join(" ")')" = "read:artifacts write:artifacts" ] || fail_g "verify scopes '$(echo "$B" | jqr '.scopes|join(" ")')'"
[ "$(echo "$B" | jqr '.withheld_scopes|join(" ")')" = "delete:artifacts" ] || fail_g "verify withheld '$(echo "$B" | jqr '.withheld_scopes|join(" ")')' (expected delete:artifacts)"
C=$(decide approve "Bearer $T1" "$FLOW_A_UC"); B=$(body)
note "approve -> $C $B"
[ "$C" = "200" ] && [ "$(echo "$B" | jqr '.status')" = "approved" ] || fail_g "approve answered $C status='$(echo "$B" | jqr '.status')'"
[ "$(session_col "$FLOW_A_DC" status)" = "approved" ] || fail_g "row status '$(session_col "$FLOW_A_DC" status)' (expected approved)"
[ "$(session_col "$FLOW_A_DC" decided_by_user_id)" = "$U1ID" ] || fail_g "decided_by_user_id '$(session_col "$FLOW_A_DC" decided_by_user_id)' != U1 $U1ID"
[ "$(session_col "$FLOW_A_DC" "array_to_string(granted_scopes,',')")" = "read:artifacts,write:artifacts" ] || fail_g "granted_scopes '$(session_col "$FLOW_A_DC" "array_to_string(granted_scopes,',')")'"
audit_has "action='DEVICE_AUTHORIZATION_APPROVED' AND user_id='$U1ID'" >/dev/null || fail_g "no DEVICE_AUTHORIZATION_APPROVED audit row for U1"
finish_case "approval by a non-admin session not recorded"

begin_test "FIX #3461 redeem: next poll -> 200 token for the APPROVER at the granted scopes only; /auth/me = approver"
reset_case
sleep "$INTERVAL"
C=$(poll "$FLOW_A_DC"); B=$(body)
note "poll after approval -> $C $(echo "$B" | jq -c '.access_token|=.[0:12]|.refresh_token|=.[0:12]' 2>/dev/null || echo "$B" | head -c 200)"
DAT=$(echo "$B" | jqr '.access_token // empty')
[ "$C" = "200" ] && [ -n "$DAT" ] || fail_g "redemption answered $C (expected 200 + access_token)"
[ "$(echo "$B" | jqr '.token_type')" = "Bearer" ] || fail_g "token_type '$(echo "$B" | jqr '.token_type')'"
[ "$(echo "$B" | jqr '.scope')" = "read:artifacts write:artifacts" ] || fail_g "scope '$(echo "$B" | jqr '.scope')' (expected 'read:artifacts write:artifacts')"
[ -n "$(echo "$B" | jqr '.refresh_token // empty')" ] || fail_g "no refresh_token"
hdr cache-control | grep -qi 'no-store' || fail_g "token response Cache-Control '$(hdr cache-control)' lacks no-store"
if [ -n "$DAT" ]; then
  CL=$(jwt_claims "$DAT")
  note "access_token claims: $(echo "$CL" | jq -c '{sub,username,is_admin,scopes,allowed_repo_ids}' 2>/dev/null)"
  [ "$(echo "$CL" | jqr '.sub')" = "$U1ID" ] || fail_g "token sub '$(echo "$CL" | jqr '.sub')' != approver $U1ID"
  [ "$(echo "$CL" | jqr '(.scopes // [])|sort|join(" ")')" = "read:artifacts write:artifacts" ] || fail_g "token scopes '$(echo "$CL" | jqr '.scopes')'"
  echo "$CL" | jq -e '(.scopes // []) | any(. == "*" or . == "admin" or . == "delete:artifacts") | not' >/dev/null 2>&1 || fail_g "token carries a withheld or admin scope"
  ME=$(curl -s "$BASE/api/v1/auth/me" -H "Authorization: Bearer $DAT" | jqr '.username // empty')
  [ "$ME" = "$U1" ] || fail_g "/auth/me with the device token = '$ME' (expected $U1)"
fi
[ "$(session_col "$FLOW_A_DC" status)" = "consumed" ] || fail_g "row status '$(session_col "$FLOW_A_DC" status)' (expected consumed)"
audit_has "action='LOGIN' AND user_id='$U1ID' AND details->>'auth_method'='device_flow' AND details->>'client_id'='$CLIENT'" >/dev/null \
  || fail_g "no LOGIN audit row with auth_method=device_flow for U1"
finish_case "device token not issued for the approver at the granted scopes"

begin_test "FIX #3461 single use: a second redemption -> invalid_grant + DEVICE_TOKEN_REJECTED(replay)"
reset_case
sleep "$INTERVAL"
C=$(poll "$FLOW_A_DC"); E=$(body | jqr '.error')
note "second redemption -> $C $E"
[ "$C" = "400" ] && [ "$E" = "invalid_grant" ] || fail_g "second redemption $C/$E (expected 400 invalid_grant)"
[ -z "$(body | jqr '.access_token // empty')" ] || fail_g "second redemption returned a token"
audit_has "action='DEVICE_TOKEN_REJECTED' AND details->>'reason'='replay'" >/dev/null || fail_g "no DEVICE_TOKEN_REJECTED replay audit row"
C=$(poll "$FLOW_A_DC" "other-client-${SUF}"); E=$(body | jqr '.error')
[ "$C" = "400" ] && [ "$E" = "invalid_grant" ] || fail_g "redemption under another client_id $C/$E (expected invalid_grant)"
finish_case "device_code redeemable more than once"

begin_test "FIX #3461 deny: a denied code polls access_denied; a request of only admin-only scopes cannot be approved by a non-admin (403)"
reset_case
start_flow "read:artifacts"; DDC="$DC"; DUC="$UC"
C=$(decide deny "Bearer $T1" "$DUC"); note "deny -> $C $(body | head -c 120)"
[ "$C" = "200" ] && [ "$(body | jqr '.status')" = "denied" ] || fail_g "deny answered $C status='$(body | jqr '.status')'"
C=$(poll "$DDC"); E=$(body | jqr '.error'); note "poll denied code -> $C $E"
[ "$E" = "access_denied" ] || fail_g "denied code polled $C/$E (expected access_denied)"
start_flow "delete:artifacts"; ODC="$DC"; OUC="$UC"
C=$(decide approve "Bearer $T1" "$OUC"); note "non-admin approve of delete:artifacts only -> $C $(body | head -c 160)"
[ "$C" = "403" ] || fail_g "approve of admin-only scope answered $C (expected 403)"
[ "$(session_col "$ODC" status)" = "pending" ] || fail_g "admin-only request row status '$(session_col "$ODC" status)' (expected pending)"
audit_has "action='DEVICE_AUTHORIZATION_FAILED' AND user_id='$U1ID' AND details->>'reason'='no_grantable_scope'" >/dev/null || fail_g "no no_grantable_scope audit row"
finish_case "deny / admin-only scope cap"

begin_test "FIX #3461 throttle: ${USER_BUDGET} wrong codes spend the per-user budget; then even the CORRECT code is 429 (budget charged before lookup); another user is unaffected"
reset_case
start_flow "read:artifacts"; TDC="$DC"; TUC="$UC"
CODES=""
for i in $(seq 0 $((USER_BUDGET - 1))); do
  C=$(decide verify "Bearer $T2" "${WRONG_CODES[$i]}"); CODES="$CODES $C"
done
C6=$(decide verify "Bearer $T2" "${WRONG_CODES[$USER_BUDGET]}"); RA=$(hdr retry-after)
CR=$(decide approve "Bearer $T2" "$TUC")
note "wrong x${USER_BUDGET}:${CODES}; wrong #$((USER_BUDGET + 1)) -> $C6 (Retry-After '$RA'); correct code by the same user -> $CR"
[ "$CODES" = "$(printf ' 400%.0s' $(seq 1 "$USER_BUDGET"))" ] || fail_g "wrong codes answered '$CODES' (expected ${USER_BUDGET}x 400)"
[ "$C6" = "429" ] && [ -n "$RA" ] || fail_g "wrong code past the budget answered $C6 Retry-After='$RA' (expected 429 + Retry-After)"
[ "$CR" = "429" ] || fail_g "correct code after the budget was spent answered $CR (expected 429: throttle precedes lookup)"
[ "$(session_col "$TDC" status)" = "pending" ] || fail_g "throttled approve changed the row to '$(session_col "$TDC" status)'"
C=$(decide verify "Bearer $T1" "$TUC"); note "another user verifies the same code -> $C"
[ "$C" = "200" ] || fail_g "U1 verify of the live code answered $C (per-user budget leaked across users)"
N=$(db "SELECT count(*) FROM audit_log WHERE action='DEVICE_AUTHORIZATION_FAILED' AND user_id='$U2ID' AND details->>'reason'='invalid_or_expired_code'")
audit_has "action='DEVICE_AUTHORIZATION_FAILED' AND user_id='$U2ID' AND details->>'reason'='throttled'" >/dev/null || fail_g "no throttled audit row for U2"
[ "${N:-0}" -ge "$USER_BUDGET" ] || fail_g "invalid_or_expired_code audit rows for U2 = $N (expected >= $USER_BUDGET)"
finish_case "wrong-code throttle"

begin_test "FIX #3461 refused approvers (403, audited, row stays pending): locked account, API token, repo-restricted exchanged JWT, Basic, device-issued token"
reset_case
start_flow "read:artifacts"; RDC="$DC"; RUC="$UC"
db "UPDATE users SET locked_until = now() + interval '1 hour' WHERE id='$U3ID'" >/dev/null
C=$(decide approve "Bearer $T3" "$RUC"); note "locked account (session issued before the lock) -> $C $(body | head -c 120)"
[ "$C" = "403" ] || fail_g "locked account approve answered $C (expected 403)"
audit_has "action='DEVICE_AUTHORIZATION_FAILED' AND user_id='$U3ID' AND details->>'reason'='account_not_eligible'" >/dev/null || fail_g "no account_not_eligible audit row"
C=$(decide approve "Bearer $APIT" "$RUC"); note "repo-restricted API token -> $C $(body | head -c 120)"
[ "$C" = "403" ] || fail_g "API token approve answered $C (expected 403)"
XJWT=$(curl -s -u "${U1}:${APIT}" "$BASE/v2/token?service=artifact-keeper&scope=repository:dtf-dev-${SUF}-x/img:pull" | jqr '.token // .access_token // empty')
if [ -z "$XJWT" ]; then
  fail_g "could not exchange the repo-restricted API token at /v2/token"
else
  note "exchanged JWT claims: $(jwt_claims "$XJWT" | jq -c '{scopes,allowed_repo_ids}' 2>/dev/null)"
  C=$(decide approve "Bearer $XJWT" "$RUC"); note "exchanged repo-restricted JWT -> $C $(body | head -c 120)"
  [ "$C" = "403" ] || fail_g "exchanged JWT approve answered $C (expected 403)"
fi
C=$(curl -s -o "$W/body" -w '%{http_code}' -X POST -u "${U1}:${PW}" -H 'Content-Type: application/json' \
  -d "{\"user_code\":\"$RUC\"}" "$BASE/api/v1/auth/device/approve" || echo 000)
note "Basic username:password -> $C"
[ "$C" = "403" ] || fail_g "Basic approve answered $C (expected 403)"
if [ -n "${DAT:-}" ]; then
  C=$(decide approve "Bearer $DAT" "$RUC"); note "device-issued token -> $C"
  [ "$C" = "403" ] || fail_g "device-issued token approve answered $C (expected 403)"
else
  fail_g "no device-issued token from the redeem case to test with"
fi
[ "$(session_col "$RDC" status)" = "pending" ] || fail_g "row status '$(session_col "$RDC" status)' after refused approvals (expected pending)"
for r in api_token not_a_session scoped_credential; do
  audit_has "action='DEVICE_AUTHORIZATION_FAILED' AND details->>'reason'='$r'" >/dev/null || fail_g "no DEVICE_AUTHORIZATION_FAILED reason=$r audit row"
done
finish_case "a non-session or ineligible principal could approve"

begin_test "FIX #3461 sign-out after approval voids it: poll -> invalid_grant + DEVICE_TOKEN_REJECTED(approver_sessions_revoked); the signed-out token can no longer verify"
reset_case
start_flow "read:artifacts"; SDC="$DC"; SUC="$UC"
C=$(decide approve "Bearer $T4" "$SUC"); note "U4 approve -> $C"
[ "$C" = "200" ] || fail_g "U4 approve answered $C (expected 200)"
sleep 1
C=$(curl -s -o "$W/body" -w '%{http_code}' -X POST "$BASE/api/v1/auth/logout" -H "Authorization: Bearer $T4" \
  -H 'Content-Type: application/json' -d "{\"refresh_token\":\"$R4\"}" || echo 000)
note "U4 logout -> $C; refresh family revoked rows=$(db "SELECT count(*) FROM refresh_token_jti WHERE user_id='$U4ID' AND revoked_at IS NOT NULL")"
sleep "$INTERVAL"
C=$(poll "$SDC"); E=$(body | jqr '.error'); note "poll after sign-out -> $C $E"
[ "$C" = "400" ] && [ "$E" = "invalid_grant" ] || fail_g "poll after the approver signed out $C/$E (expected 400 invalid_grant)"
[ -z "$(body | jqr '.access_token // empty')" ] || fail_g "a token was issued after the approving session was signed out"
audit_has "action='DEVICE_TOKEN_REJECTED' AND details->>'reason'='approver_sessions_revoked'" >/dev/null || fail_g "no approver_sessions_revoked audit row"
start_flow "read:artifacts"
C=$(decide verify "Bearer $T4" "$UC"); note "signed-out access token verifies a fresh code -> $C"
[ "$C" = "401" ] || fail_g "signed-out session verify answered $C (expected 401: session no longer valid)"
finish_case "approval survived the approver signing out"

begin_test "FIX #3461 audit trail never contains a code in clear"
reset_case
N=$(db "SELECT count(*) FROM audit_log WHERE action LIKE 'DEVICE_%' OR details->>'auth_method'='device_flow'")
note "device audit rows: $N"
[ "${N:-0}" -ge 8 ] || fail_g "only $N device audit rows"
LEAK=$(db "SELECT count(*) FROM audit_log WHERE details::text LIKE '%${FLOW_A_DC}%' OR details::text LIKE '%${FLOW_A_UC}%' OR details::text LIKE '%${FLOW_A_UC/-/}%'")
[ "$LEAK" = "0" ] || fail_g "$LEAK audit rows contain a device or user code in clear"
finish_case "device audit trail"

# ---------------------------------------------------------------------------
# CONTROL: the kill switch. Recreate ONLY the backend on the same compose
# project with DEVICE_AUTH_ENABLED=false (profiles/auth.device.yml reads it),
# keeping postgres and its data. Every device route then answers 404, to an
# authenticated caller too, and login still works. On 1.11.3 the routes never
# existed, so the same 404s hold there.
# ---------------------------------------------------------------------------
begin_test "CONTROL DEVICE_AUTH_ENABLED=false (same project, backend recreated): every device route 404; login + /auth/me still work"
reset_case
if ! DEVICE_AUTH_ENABLED=false docker compose -p "ak-dtf${DTF_SLOT}" \
     -f "$DTF_DIR/compose.base.yml" -f "$DTF_DIR/profiles/storage.filesystem.yml" -f "$DTF_DIR/profiles/auth.device.yml" \
     up -d --wait --no-deps backend >"$W/recreate.log" 2>&1; then
  fail_g "backend recreate with DEVICE_AUTH_ENABLED=false failed: $(tail -5 "$W/recreate.log")"
else
  ENV_OFF=$(docker exec "${DB_CONTAINER%-db}-backend" printenv DEVICE_AUTH_ENABLED 2>/dev/null || true)
  [ "$ENV_OFF" = "false" ] || fail_g "recreated backend has DEVICE_AUTH_ENABLED='$ENV_OFF'"
  OTOK=$(login_json "$U1" "$PW" | jqr '.access_token // empty')
  [ -n "$OTOK" ] || fail_g "login after recreate failed"
  ME=$(curl -s "$BASE/api/v1/auth/me" -H "Authorization: Bearer $OTOK" | jqr '.username // empty')
  [ "$ME" = "$U1" ] || fail_g "/auth/me after recreate = '$ME'"
  for r in "POST /api/v1/auth/device/code" "POST /api/v1/auth/device/token" "POST /api/v1/auth/device/verify" \
           "POST /api/v1/auth/device/approve" "POST /api/v1/auth/device/deny" "GET /device" "GET /device/app.js"; do
    C=$(curl -s -o "$W/body" -w '%{http_code}' -X "${r%% *}" -H "Authorization: Bearer $OTOK" \
      -H 'Content-Type: application/json' -d '{"client_id":"x","user_code":"BBBB-BBBB"}' "$BASE${r#* }" || echo 000)
    note "$r -> $C"
    [ "$C" = "404" ] || fail_g "$r answered $C with the grant off (expected 404)"
    [ -z "$(body | jqr '.device_code // .access_token // empty' 2>/dev/null)" ] || fail_g "$r returned a code or token with the grant off"
  done
  CFG=$(curl -s "$BASE/api/v1/system/config" | jqr '.auth.device_authorization_enabled')
  [ "$CFG" != "true" ] || fail_g "/system/config still advertises device authorization"
fi
finish_case "grant not fully off without DEVICE_AUTH_ENABLED (or login broken)"

end_suite
