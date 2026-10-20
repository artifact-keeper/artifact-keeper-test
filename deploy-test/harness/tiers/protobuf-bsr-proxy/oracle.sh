#!/usr/bin/env bash
# =============================================================================
# tiers/protobuf-bsr-proxy/oracle.sh
#   #4284 (PR #4276) allowlisted read-only buf.registry.module.v1 Connect RPCs
#         that have no local route are reverse-proxied to a remote protobuf
#         repository's upstream (or a virtual's readable remote members), with
#         request and response header allowlists, upstream errors turned into
#         our own Connect errors without the upstream body, and a 16 MiB / 60 s
#         cap.
# See the manifest for THE FEATURE, the primitives and the gates.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# TRIVY_PORT (the mock's published control port), RELEASE_GATE=1,
# JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"
: "${DTF_SLOT:?}"; : "${TRIVY_PORT:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

BASE="$BASE_URL"
BACKEND_CTR="${DB_CONTAINER%-db}-backend"
MOCK="http://127.0.0.1:${TRIVY_PORT}"
# The address the BACKEND reaches the mock at (profiles/upstreams.mock-bsr.yml).
MOCK_HOST="172.16.${DTF_SLOT}.71"
# Must match fixtures/mock_bsr.py.
SECRET_BODY_MARK="MOCK-BSR-UPSTREAM-BODY"
SECRET_HDR_VALUE="mock-upstream-secret-7c1e"
CAP_BYTES=16777216
SVC_MOD="buf.registry.module.v1.ModuleService"
SVC_LBL="buf.registry.module.v1.LabelService"

setup_workdir
W="$WORK_DIR"

jqr(){ jq -r "$1" 2>/dev/null || true; }

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

# --- mock upstream control ---------------------------------------------------
mock_count(){ curl -s --max-time 5 "${MOCK}/__requests?path=$1" | jqr '.count // empty'; }
mock_mode(){ curl -s --max-time 5 -X POST "${MOCK}/__mode?path=$1&mode=$2" | jqr '.mode // empty'; }
mock_headers(){ curl -s --max-time 5 "${MOCK}/__headers?path=$1"; }

# rpc <token> <repo> <Service/Method> [max_time] -> "<http_code> <curl_rc>"
# Body in $W/rpc.body, response headers (lower-cased) in $W/rpc.hdr.
# Sends the client-side headers the request allowlist must drop.
rpc(){
  local code rc
  rm -f "$W/rpc.body" "$W/rpc.hdr"
  code="$(curl -s --max-time "${4:-30}" -o "$W/rpc.body" -D "$W/rpc.hdr.raw" -w '%{http_code}' \
    -X POST "$BASE/proto/$2/$3" \
    -H "Authorization: Bearer $1" -H 'Content-Type: application/json' \
    -H 'Connect-Protocol-Version: 1' \
    -H "Cookie: ak_session=caller-cookie-${SUF}" -H "buf-token: caller-buf-token-${SUF}" \
    -H "X-Caller-Secret: caller-secret-${SUF}" \
    -d '{}')"; rc=$?
  [ -f "$W/rpc.body" ] || : > "$W/rpc.body"
  tr '[:upper:]' '[:lower:]' < "$W/rpc.hdr.raw" 2>/dev/null | tr -d '\r' > "$W/rpc.hdr" || : > "$W/rpc.hdr"
  echo "${code:-000} ${rc}"
}
body(){ cat "$W/rpc.body" 2>/dev/null || true; }
hdr(){ sed -n "s/^$1: //p" "$W/rpc.hdr" 2>/dev/null | head -1; }
backend_log_since(){ docker logs --since "$1" "$BACKEND_CTR" 2>&1 | sed 's/\x1b\[[0-9;]*m//g' || true; }

# The Connect error shape every #4276 error path answers: {"code","message"}.
connect_code(){ body | jqr '.code // empty'; }

# =============================================================================
begin_suite "protobuf-bsr-proxy"

begin_test "setup: admin login, remote protobuf repos on the mock BSR, a virtual, two users"
TOK="$(curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"${ADMIN_PASS}\"}" | jqr '.access_token // .token // empty')"
if [ -z "$TOK" ]; then infra_fail "admin login failed at $BASE"; end_suite; fi
if [ "$(curl -s --max-time 5 "${MOCK}/__readyz" || true)" != "ok" ]; then
  infra_fail "mock BSR not reachable on ${MOCK} (profiles/upstreams.mock-bsr.yml)"; end_suite
fi
SUF="${RUN_ID##*-}-$$"
SUF="$(printf '%s' "$SUF" | tr -c 'a-zA-Z0-9-' '-')"
# The remote's upstream carries userinfo credentials; they must reach the
# upstream as the remote's own auth and never surface in a log or a body.
UP_USER="bsruser"; UP_PASS="bsrpw-${SUF}-q7"
adm(){ curl -s -X "$1" "$BASE$2" -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' ${3:+-d "$3"}; }
mk_remote(){ # <key> <prefix>
  adm POST /api/v1/repositories "$(jq -nc --arg k "$1" --arg u "http://${UP_USER}:${UP_PASS}@${MOCK_HOST}/$2/" \
    '{key:$k,name:$k,format:"protobuf",repo_type:"remote",is_public:false,upstream_url:$u}')" | jqr '.id // empty'
}
SETUP_ERR=""
declare -A RID
for c in ok err500 err404 big reset stall virt; do
  RID[$c]="$(mk_remote "pbx-${c}-${SUF}" "${c}-${SUF}")"
  [ -n "${RID[$c]}" ] || SETUP_ERR="${SETUP_ERR} remote-${c}"
done
R_VIRT="pbx-v-${SUF}"
V_ID="$(adm POST /api/v1/repositories "$(jq -nc --arg k "$R_VIRT" '{key:$k,name:$k,format:"protobuf",repo_type:"virtual",is_public:false}')" | jqr '.id // empty')"
[ -n "$V_ID" ] || SETUP_ERR="${SETUP_ERR} virtual"
[ "$(adm POST "/api/v1/repositories/${R_VIRT}/members" "$(jq -nc --arg k "pbx-virt-${SUF}" '{member_key:$k}')" | jqr '.member_repo_key // empty')" = "pbx-virt-${SUF}" ] \
  || SETUP_ERR="${SETUP_ERR} virtual-member"
mk_user(){ adm POST /api/v1/users "$(jq -nc --arg u "$1" --arg p "$2" '{username:$u,password:$p,email:($u+"@t.test")}')" | jqr '.user.id // .id // empty'; }
grant(){ adm POST /api/v1/permissions "$(jq -nc --arg p "$1" --arg t "$2" --arg a "$3" \
  '{principal_type:"user",principal_id:$p,target_type:"repository",target_id:$t,actions:($a|split(","))}')" | jqr '.id // empty'; }
U_PASS="Pbx-${SUF}-Passw0rd!"
U_OK="pbxok${SUF//-/}"; U_NO="pbxno${SUF//-/}"
U_OK_ID="$(mk_user "$U_OK" "$U_PASS")"; U_NO_ID="$(mk_user "$U_NO" "$U_PASS")"
[ -n "$U_OK_ID" ] && [ -n "$U_NO_ID" ] || SETUP_ERR="${SETUP_ERR} users"
# Both users may write (hence POST) the virtual; only U_OK may read its member.
# U_NO also reads the `ok` remote directly, which is not enough to POST it.
[ -n "$(grant "$U_OK_ID" "$V_ID" read,write)" ] || SETUP_ERR="${SETUP_ERR} grant-ok-virtual"
[ -n "$(grant "$U_OK_ID" "${RID[virt]}" read)" ] || SETUP_ERR="${SETUP_ERR} grant-ok-member"
[ -n "$(grant "$U_NO_ID" "$V_ID" read,write)" ] || SETUP_ERR="${SETUP_ERR} grant-no-virtual"
[ -n "$(grant "$U_NO_ID" "${RID[ok]}" read)" ] || SETUP_ERR="${SETUP_ERR} grant-no-ok-read"
if [ -n "$SETUP_ERR" ]; then infra_fail "setup failed:${SETUP_ERR}"; end_suite; fi
T_OK="$(login_as "$U_OK" "$U_PASS")" || true
T_NO="$(login_as "$U_NO" "$U_PASS")" || true
if [ -z "$T_OK" ] || [ -z "$T_NO" ]; then infra_fail "a test user could not log in"; end_suite; fi
LOG_T0="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "-- remotes pbx-<case>-${SUF} -> http://${UP_USER}:***@${MOCK_HOST}/<case>-${SUF}/, virtual ${R_VIRT}"
pass

# =============================================================================
# CONTROL (both images): the explicit per-method routes that existed before
# #4276 still answer from AK's own store for a remote repo and never reach the
# upstream (they win over the new catch-all).
# =============================================================================
begin_test "CONTROL: the explicit GetModules / GetLabels routes on a remote answer locally (empty) and do not contact the upstream"
reset_case
R="pbx-ok-${SUF}"; PFX="/ok-${SUF}"
for pair in "${SVC_MOD}/GetModules:modules" "${SVC_LBL}/GetLabels:labels"; do
  m="${pair%%:*}"; field="${pair##*:}"
  read -r code rc <<<"$(rpc "$TOK" "$R" "$m")"
  cnt="$(mock_count "${PFX}/${m}")"
  note "${m}: HTTP ${code}, body $(body | head -c 160), upstream calls ${cnt}"
  [ "$code" = "200" ] || fail_g "${m} answered HTTP ${code}, expected 200"
  [ "$(body | jqr ".${field} | length")" = "0" ] || fail_g "${m} body is not an empty .${field} list"
  [ "$(body | jqr '.servedBy // empty')" = "" ] || fail_g "${m} was served by the upstream"
  [ "$cnt" = "0" ] || fail_g "${m} reached the upstream (${cnt} calls)"
done
finish_case "explicit protobuf routes changed behaviour on a remote repository"

begin_test "CONTROL: a caller with only read on a remote cannot POST an allowlisted RPC to it (write gate on /proto POST); the upstream is not contacted"
reset_case
c0="$(mock_count "${PFX}/${SVC_MOD}/ListModules")"
read -r code rc <<<"$(rpc "$T_NO" "$R" "${SVC_MOD}/ListModules")"
c1="$(mock_count "${PFX}/${SVC_MOD}/ListModules")"
note "read-only caller ListModules on ${R}: HTTP ${code}, body $(body | head -c 160); upstream calls ${c0} -> ${c1}"
[ "$code" = "403" ] || [ "$code" = "404" ] || fail_g "expected 403 or 404, got HTTP ${code}"
[ "$c0" = "$c1" ] || fail_g "the upstream was contacted for a refused caller (${c0} -> ${c1})"
body | grep -q 'mock-bsr' && fail_g "the refused caller saw upstream content"
finish_case "a read-only caller reached the BSR upstream through POST"

# =============================================================================
# #4284 FIX: allowlisted reads are proxied, with both header allowlists.
# =============================================================================
begin_test "#4284: allowlisted ListModules / ListLabels on a remote are proxied; only content-type and connect-* come back; caller credentials never reach the upstream"
reset_case
for m in "${SVC_MOD}/ListModules" "${SVC_LBL}/ListLabels"; do
  c0="$(mock_count "${PFX}/${m}")"
  read -r code rc <<<"$(rpc "$TOK" "$R" "$m")"
  c1="$(mock_count "${PFX}/${m}")"
  note "${m}: HTTP ${code}, body $(body | head -c 200); upstream calls ${c0} -> ${c1}"
  [ "$code" = "200" ] || fail_g "${m} answered HTTP ${code}, expected 200 from the upstream"
  [ "$(body | jqr '.servedBy // empty')" = "mock-bsr" ] && [ "$(body | jqr '.rpc // empty')" = "$m" ] \
    || fail_g "${m} body is not the upstream's canned answer"
  [ -n "$c1" ] && [ "$c1" = "$(( ${c0:-0} + 1 ))" ] || fail_g "${m}: upstream calls ${c0} -> ${c1}, expected exactly one"
  note "  relayed headers: $(grep -E '^(content-type|connect-|x-upstream-secret|set-cookie|trailer-)' "$W/rpc.hdr" | tr '\n' ' ')"
  case "$(hdr content-type)" in application/json*) ;; *) fail_g "${m}: content-type '$(hdr content-type)' was not relayed";; esac
  [ "$(hdr connect-mock-trace)" = "mock-trace-1" ] || fail_g "${m}: the upstream's connect-* header was not relayed"
  grep -q "^x-upstream-secret:" "$W/rpc.hdr" && fail_g "${m}: the upstream's X-Upstream-Secret header was relayed"
  grep -qi "${SECRET_HDR_VALUE}" "$W/rpc.hdr" && fail_g "${m}: the upstream secret header value leaked"
  grep -q "^set-cookie: bsr_session" "$W/rpc.hdr" && fail_g "${m}: the upstream's Set-Cookie was relayed"
  mock_headers "${PFX}/${m}" > "$W/up.hdr"
  note "  upstream saw: $(jq -c 'with_entries(select(.key|test("authorization|cookie|buf-token|x-caller|connect-")))' "$W/up.hdr" 2>/dev/null)"
  [ "$(jqr '.cookie // empty' < "$W/up.hdr")" = "" ] || fail_g "${m}: the caller's Cookie reached the upstream"
  [ "$(jqr '."buf-token" // empty' < "$W/up.hdr")" = "" ] || fail_g "${m}: the caller's buf-token reached the upstream"
  [ "$(jqr '."x-caller-secret" // empty' < "$W/up.hdr")" = "" ] || fail_g "${m}: a non-allowlisted caller header reached the upstream"
  case "$(jqr '.authorization // empty' < "$W/up.hdr")" in
    "Bearer ${TOK}") fail_g "${m}: the caller's AK bearer token reached the upstream";;
  esac
  [ "$(jqr '."connect-protocol-version" // empty' < "$W/up.hdr")" = "1" ] || fail_g "${m}: the allowlisted connect-protocol-version header was not forwarded"
done
finish_case "#4284: allowlisted BSR reads are not proxied, or headers cross the allowlists"

begin_test "#4284: a non-allowlisted method (write RPC, other BSR service) is a Connect 404 unimplemented and the upstream is not contacted"
reset_case
for m in "${SVC_MOD}/DeleteModules" "buf.registry.owner.v1.OrganizationService/ListOrganizations" "${SVC_MOD}/UpdateModules"; do
  read -r code rc <<<"$(rpc "$TOK" "$R" "$m")"
  cnt="$(mock_count "${PFX}/${m}")"
  note "${m}: HTTP ${code}, body $(body | head -c 160); upstream calls ${cnt}"
  [ "$code" = "404" ] || fail_g "${m} answered HTTP ${code}, expected 404"
  [ "$(connect_code)" = "unimplemented" ] || fail_g "${m} body is not a Connect unimplemented error"
  [ "$cnt" = "0" ] || fail_g "${m} reached the upstream (${cnt} calls)"
done
finish_case "#4284: a non-allowlisted BSR method is not refused as Connect unimplemented"

# =============================================================================
# #4284 FIX (maintainer commit): upstream errors are wrapped, never relayed.
# =============================================================================
begin_test "#4284: an upstream 500 becomes a Connect 502 unavailable without the upstream body or headers; the backend log names the status with the URL redacted"
reset_case
R="pbx-err500-${SUF}"; PFX="/err500-${SUF}"; M="${SVC_MOD}/ListModules"
[ "$(mock_mode "${PFX}/${M}" err500)" = "err500" ] || { infra_fail "could not set mock mode err500"; end_suite; }
T1="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
read -r code rc <<<"$(rpc "$TOK" "$R" "$M")"
cnt="$(mock_count "${PFX}/${M}")"
note "HTTP ${code}, body $(body | head -c 200); upstream calls ${cnt}"
[ "$cnt" = "1" ] || fail_g "the upstream was not contacted exactly once (${cnt})"
[ "$code" = "502" ] && [ "$(connect_code)" = "unavailable" ] || fail_g "expected 502 {code: unavailable}, got HTTP ${code} code '$(connect_code)'"
body | grep -q "Upstream BSR returned HTTP 500" || fail_g "the Connect message does not name the upstream status"
body | grep -q -e "${SECRET_BODY_MARK}" -e hunter2 && fail_g "the upstream error body was relayed to the client"
grep -qi "${SECRET_HDR_VALUE}" "$W/rpc.hdr" && fail_g "the upstream error's secret header was relayed"
sleep 1
L="$(backend_log_since "$T1" | grep 'protobuf BSR upstream returned non-success' | grep "${PFX}/${M}" | head -1 || true)"
note "log: ${L:0:400}"
[ -n "$L" ] || fail_g "no backend log line 'protobuf BSR upstream returned non-success' for ${PFX}/${M}"
printf '%s' "$L" | grep -q "status=500" || fail_g "the log line does not carry status=500"
printf '%s' "$L" | grep -q "upstream=http://${MOCK_HOST}${PFX}/${M}" || fail_g "the log line does not carry the redacted upstream URL (host and path, no userinfo)"
printf '%s' "$L" | grep -q -e "${UP_PASS}" -e "${UP_USER}@" && fail_g "the log line carries the upstream credentials"
finish_case "#4284: an upstream 500 is relayed or not wrapped as Connect unavailable"

begin_test "#4284: an upstream 404 stays a Connect 404 not_found without the upstream body"
reset_case
R="pbx-err404-${SUF}"; PFX="/err404-${SUF}"; M="${SVC_LBL}/ListLabels"
[ "$(mock_mode "${PFX}/${M}" err404)" = "err404" ] || { infra_fail "could not set mock mode err404"; end_suite; }
read -r code rc <<<"$(rpc "$TOK" "$R" "$M")"
cnt="$(mock_count "${PFX}/${M}")"
note "HTTP ${code}, body $(body | head -c 200); upstream calls ${cnt}"
[ "$cnt" = "1" ] || fail_g "the upstream was not contacted exactly once (${cnt})"
[ "$code" = "404" ] && [ "$(connect_code)" = "not_found" ] || fail_g "expected 404 {code: not_found}, got HTTP ${code} code '$(connect_code)'"
body | grep -q "Upstream BSR returned HTTP 404" || fail_g "the Connect message is not AK's own"
body | grep -q -e "${SECRET_BODY_MARK}" -e hunter2 && fail_g "the upstream 404 body was relayed to the client"
finish_case "#4284: an upstream 404 is relayed raw or not mapped to Connect not_found"

begin_test "#4284: an upstream body over the 16 MiB cap is refused as Connect 502 naming the limit"
reset_case
R="pbx-big-${SUF}"; PFX="/big-${SUF}"; M="${SVC_MOD}/ListModules"
[ "$(mock_mode "${PFX}/${M}" big)" = "big" ] || { infra_fail "could not set mock mode big"; end_suite; }
read -r code rc <<<"$(rpc "$TOK" "$R" "$M" 90)"
sz="$(wc -c < "$W/rpc.body" | tr -d '[:space:]')"
cnt="$(mock_count "${PFX}/${M}")"
note "HTTP ${code}, ${sz} bytes, body $(body | head -c 200); upstream calls ${cnt}"
[ "$cnt" = "1" ] || fail_g "the upstream was not contacted exactly once (${cnt})"
[ "$code" = "502" ] && [ "$(connect_code)" = "unavailable" ] || fail_g "expected 502 {code: unavailable}, got HTTP ${code}"
body | grep -q "exceeded the ${CAP_BYTES}-byte limit" || fail_g "the message does not name the ${CAP_BYTES}-byte cap"
[ "${sz:-0}" -lt 4096 ] || fail_g "the oversized upstream body was relayed (${sz} bytes)"
finish_case "#4284: an oversized upstream body is relayed instead of refused at the cap"

begin_test "#4284: a transport failure (upstream resets the connection) is a Connect 502 with a fixed message; the warn log carries the redacted URL"
reset_case
R="pbx-reset-${SUF}"; PFX="/reset-${SUF}"; M="${SVC_MOD}/ListModules"
[ "$(mock_mode "${PFX}/${M}" reset)" = "reset" ] || { infra_fail "could not set mock mode reset"; end_suite; }
T1="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
read -r code rc <<<"$(rpc "$TOK" "$R" "$M")"
note "HTTP ${code}, body $(body | head -c 200)"
[ "$code" = "502" ] && [ "$(connect_code)" = "unavailable" ] || fail_g "expected 502 {code: unavailable}, got HTTP ${code}"
[ "$(body | jqr '.message // empty')" = "Upstream BSR request failed" ] || fail_g "the message is not the fixed 'Upstream BSR request failed'"
body | grep -q -e "${MOCK_HOST}" -e "${UP_PASS}" && fail_g "the client body carries the upstream URL or credentials"
sleep 1
L="$(backend_log_since "$T1" | grep 'protobuf BSR upstream request failed' | grep "${PFX}/${M}" | head -1 || true)"
note "log: ${L:0:400}"
[ -n "$L" ] || fail_g "no WARN 'protobuf BSR upstream request failed' for ${PFX}/${M}"
printf '%s' "$L" | grep -q "upstream=http://${MOCK_HOST}${PFX}/${M}" || fail_g "the warn does not carry the redacted upstream URL"
printf '%s' "$L" | grep -q -e "${UP_PASS}" -e "${UP_USER}@" && fail_g "the warn carries the upstream credentials"
finish_case "#4284: a BSR transport failure is not wrapped, or logs the upstream credentials"

begin_test "#4284: an upstream that stalls past the 60 s timeout is cut off with a Connect 502 (not held open)"
reset_case
R="pbx-stall-${SUF}"; PFX="/stall-${SUF}"; M="${SVC_LBL}/ListLabels"
[ "$(mock_mode "${PFX}/${M}" stall)" = "stall" ] || { infra_fail "could not set mock mode stall"; end_suite; }
t0="$(date +%s)"
read -r code rc <<<"$(rpc "$TOK" "$R" "$M" 120)"
dt=$(( $(date +%s) - t0 ))
note "HTTP ${code} after ${dt}s (mock stalls 75 s), body $(body | head -c 200)"
[ "$code" = "502" ] && [ "$(connect_code)" = "unavailable" ] || fail_g "expected 502 {code: unavailable}, got HTTP ${code} (curl rc ${rc})"
[ "$dt" -ge 55 ] && [ "$dt" -lt 74 ] || fail_g "answered after ${dt}s, expected the 60 s cap (55..73 s)"
body | grep -q 'mock-bsr' && fail_g "the stalled upstream's late answer was relayed"
finish_case "#4284: a stalled BSR upstream is not cut off at the 60 s cap"

# =============================================================================
# #4284 FIX: a virtual proxies through its readable remote members only.
# =============================================================================
begin_test "#4284: a virtual with the remote as member proxies an allowlisted read for a caller who can read the member"
reset_case
PFX="/virt-${SUF}"; M="${SVC_LBL}/ListLabels"
c0="$(mock_count "${PFX}/${M}")"
read -r code rc <<<"$(rpc "$T_OK" "$R_VIRT" "$M")"
c1="$(mock_count "${PFX}/${M}")"
note "${U_OK} ListLabels via ${R_VIRT}: HTTP ${code}, body $(body | head -c 200); member upstream calls ${c0} -> ${c1}"
[ "$code" = "200" ] && [ "$(body | jqr '.servedBy // empty')" = "mock-bsr" ] || fail_g "expected 200 with the member upstream's answer, got HTTP ${code}"
[ -n "$c1" ] && [ "$c1" = "$(( ${c0:-0} + 1 ))" ] || fail_g "member upstream calls ${c0} -> ${c1}, expected exactly one"
grep -q "^x-upstream-secret:" "$W/rpc.hdr" && fail_g "the member upstream's X-Upstream-Secret was relayed"
finish_case "#4284: a virtual does not proxy BSR reads through its remote member"

begin_test "AUTHZ (both images): a caller with write on the virtual but no read on its remote member is refused and the member upstream is not contacted"
reset_case
c0="$(mock_count "${PFX}/${M}")"
read -r code rc <<<"$(rpc "$T_NO" "$R_VIRT" "$M")"
c1="$(mock_count "${PFX}/${M}")"
note "${U_NO} ListLabels via ${R_VIRT}: HTTP ${code}, body $(body | head -c 200); member upstream calls ${c0} -> ${c1}"
[ "$code" = "403" ] || [ "$code" = "404" ] || fail_g "expected 403 or 404, got HTTP ${code}"
[ "$c0" = "$c1" ] || fail_g "the member upstream was contacted for a caller who cannot read it (${c0} -> ${c1})"
body | grep -q 'mock-bsr' && fail_g "the caller saw the member upstream's answer"
finish_case "a caller without read on the member reached its upstream through the virtual"

begin_test "CONTROL: the remotes' upstream password never appears in the backend log"
reset_case
n="$(backend_log_since "$LOG_T0" | grep -c -e "${UP_PASS}" || true)"
note "occurrences of the upstream password in the backend log since setup: ${n}"
[ "${n:-0}" = "0" ] || fail_g "the upstream password appears ${n} times in the backend log"
finish_case "upstream credentials leaked into the backend log"

end_suite
