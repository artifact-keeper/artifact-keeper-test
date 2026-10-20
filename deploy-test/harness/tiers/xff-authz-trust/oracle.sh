#!/usr/bin/env bash
# jq programs are single-quoted on purpose; their $vars are jq variables.
# shellcheck disable=SC2016
# =============================================================================
# tiers/xff-authz-trust/oracle.sh
#   X-Forwarded-For is not trusted for authorization or audit IPs unless
#   XFF_TRUSTED_FOR_AUTHZ=true (#4681, GHSA-59x8-r6jj-x95h); URL-carried
#   credentials are redacted from the request span uri (#4675); a public
#   Remote with upstream credentials is refused unless the operator accepts it
#   (#4662). All three released in 1.11.1.
# =============================================================================
# run.sh has stood up storage.filesystem + sso.oidc-entra-shape with
# RATE_LIMIT_ENABLED=false and UPSTREAM_ALLOW_PRIVATE_IPS=true, and exported
# BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID, DTF_DIR, DTF_SLOT,
# TRIVY_PORT, BACKEND_IMAGE, RELEASE_GATE=1, JUNIT_OUTPUT_DIR.
#
# sso.oidc-entra-shape is reused for its topology only: the backend has
# RATE_LIMIT_TRUSTED_PROXY_CIDRS=172.16.<slot>.64/28 on the mock network and
# the json-file log driver. A throwaway curl container pinned to
# 172.16.<slot>.70 is a TRUSTED proxy peer, one pinned to .90 is an untrusted
# peer (the oidc-exchange-and-login idiom). mock-oidc doubles as the upstream
# of the Remotes in the #4662 and #4675 cases; its OIDC role is unused.
#
# Two backend boots on the same compose project:
#   phase 1  the profile as is: trusted proxies set, XFF_TRUSTED_FOR_AUTHZ unset
#   phase 2  ONLY the backend recreated with XFF_TRUSTED_FOR_AUTHZ=true (a
#            tier-local override, as qcmj-webhook-authz does)
#
# FIX cases are red on ak-backend:1.11.0 and green on 1.11.1 and later.
# CONTROL cases hold on both.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"; : "${RUN_ID:?}"; : "${DTF_DIR:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every check here records its own pass/fail and
# must not abort the run on a non-matching grep.
set +e

SUF="${RUN_ID##*-}$$"
BACKEND_CTR="ak-dtf${DTF_SLOT}-backend"
MOCK_NET="ak-dtf${DTF_SLOT}-mockoidcentra"
CURL_IMAGE="curlimages/curl:8.11.1"
TRUSTED_PEER="172.16.${DTF_SLOT}.70"     # inside RATE_LIMIT_TRUSTED_PROXY_CIDRS (.64/28)
UNTRUSTED_PEER="172.16.${DTF_SLOT}.90"   # outside it
CLIENT_IP="198.51.100.7"                 # the address a proxy would forward (TEST-NET-2)
XFF_WARN="RATE_LIMIT_TRUSTED_PROXY_CIDRS is set but XFF_TRUSTED_FOR_AUTHZ is not"

U="xffu${DTF_SLOT}${SUF}"; U_PASS="XffUser_${SUF}_Aa1!"
R_XFF="xff-cidr-${DTF_SLOT}-${SUF}"      # grant conditioned on the forwarded client CIDR
R_PEER="xff-peer-${DTF_SLOT}-${SUF}"     # grant conditioned on the untrusted peer's CIDR
R_TICKET="xff-tkt-${DTF_SLOT}-${SUF}"    # Remote whose fetch logs inside the request span
ART="a-${SUF}.bin"; ART_BODY="xff-artifact-${SUF}"

# --- helpers (always return 0) ----------------------------------------------
jqr() { jq -r "$@" 2>/dev/null || true; }
db() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>&1 | tr -d '\r'; }
J() { # METHOD PATH [JSON] -> body, then a final line "HTTP <code>"  (admin bearer)
  local m="$1" p="$2" d="${3:-}"
  if [ -n "$d" ]; then
    curl -s --max-time 30 -w '\nHTTP %{http_code}' -X "$m" -H "Authorization: Bearer ${ADMIN_TOKEN}" \
      -H 'Content-Type: application/json' -d "$d" "${BASE_URL}${p}" 2>/dev/null || echo "HTTP 000"
  else
    curl -s --max-time 30 -w '\nHTTP %{http_code}' -X "$m" -H "Authorization: Bearer ${ADMIN_TOKEN}" \
      "${BASE_URL}${p}" 2>/dev/null || echo "HTTP 000"
  fi
}
code_of() { printf '%s\n' "$1" | tail -1 | sed 's/^HTTP //'; }
body_of() { printf '%s\n' "$1" | sed '$d'; }
# peer IP [curl args...] -> body, then a final line "HTTP <code>"; the request
# comes from a throwaway container pinned to IP on the backend's mock network.
peer() {
  local ip="$1"; shift
  docker run --rm --network "$MOCK_NET" --ip "$ip" "$CURL_IMAGE" \
    -s --max-time 20 -w '\nHTTP %{http_code}' "$@" 2>/dev/null || echo "HTTP 000"
}
peer_download() { # IP REPO
  peer "$1" -H "Authorization: Bearer ${U_TOKEN}" -H "X-Forwarded-For: ${CLIENT_IP}" \
    "http://backend:8080/api/v1/repositories/$2/download/${ART}"
}
peer_login() { # IP XFF -> HTTP code of a login as $U through that peer
  code_of "$(peer "$1" -H "X-Forwarded-For: $2" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg u "$U" --arg p "$U_PASS" '{username:$u,password:$p}')" \
    "http://backend:8080/api/v1/auth/login")"
}
last_login_ip() { # -> ip_address of the newest LOGIN row for $U ("NULL" when null)
  db "SELECT coalesce(ip_address, 'NULL') FROM audit_log WHERE action = 'LOGIN' AND user_id = '${U_ID}' ORDER BY created_at DESC LIMIT 1"
}
is_denied() { case "$1" in 403|404) return 0 ;; *) return 1 ;; esac; }
backend_log() { docker logs "$BACKEND_CTR" 2>&1 | sed 's/\x1b\[[0-9;]*m//g'; }

# recreate_backend_with_xff_trust: phase 2. Same project and overlays as
# run.sh plus XFF_TRUSTED_FOR_AUTHZ=true; --wait health-gates it.
recreate_backend_with_xff_trust() {
  local override rc
  override="$(mktemp "${TMPDIR:-/tmp}/xff-authz-${DTF_SLOT}.XXXXXX.yml")"
  cat > "$override" <<'YML'
services:
  backend:
    environment:
      XFF_TRUSTED_FOR_AUTHZ: "true"
YML
  docker compose -p "ak-dtf${DTF_SLOT}" \
    -f "${DTF_DIR}/compose.base.yml" \
    -f "${DTF_DIR}/profiles/storage.filesystem.yml" \
    -f "${DTF_DIR}/profiles/sso.oidc-entra-shape.yml" \
    -f "$override" \
    up -d --wait backend >/dev/null 2>&1
  rc=$?
  rm -f "$override"
  return "$rc"
}

begin_suite "xff-authz-trust"
auth_admin

# =============================================================================
# setup: a user whose read grants on two private repositories carry
# allowed_cidrs conditions
# =============================================================================
begin_test "setup: user ${U}; private repos with one artifact each; read grants conditioned on ${CLIENT_IP%.*}.0/24 and on the untrusted peer's /28"
SETUP_ERR=""
U_ID="$(create_test_user_with_retry "$U" "$U_PASS" "${U}@dtf.test")" || true
U_TOKEN=""; [ -n "$U_ID" ] && [ "$U_ID" != "null" ] && U_TOKEN="$(login_as "$U" "$U_PASS")" || true
[ -n "$U_TOKEN" ] || SETUP_ERR="${SETUP_ERR} user"
printf '%s' "$ART_BODY" > "${TMPDIR:-/tmp}/xff-art-${DTF_SLOT}-$$"
mkgrant() { # REPO CIDR
  local rid
  [ "$(code_of "$(J POST /api/v1/repositories "{\"key\":\"$1\",\"name\":\"$1\",\"format\":\"generic\",\"repo_type\":\"local\",\"is_public\":false}")")" = "200" ] \
    || [ "$(code_of "$(J GET "/api/v1/repositories/$1")")" = "200" ] || return 1
  curl -s -o /dev/null --max-time 30 -X PUT -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    --data-binary @"${TMPDIR:-/tmp}/xff-art-${DTF_SLOT}-$$" "${BASE_URL}/api/v1/repositories/$1/artifacts/${ART}" || return 1
  rid="$(body_of "$(J GET "/api/v1/repositories/$1")" | jqr '.id')"
  [ -n "$(body_of "$(J POST /api/v1/permissions "$(jq -nc --arg u "$U_ID" --arg r "$rid" --arg c "$2" \
    '{principal_type:"user",principal_id:$u,target_type:"repository",target_id:$r,actions:["read"],conditions:{allowed_cidrs:[$c]}}')")" \
    | jqr '.id // empty')" ]
}
mkgrant "$R_XFF" "${CLIENT_IP%.*}.0/24" || SETUP_ERR="${SETUP_ERR} ${R_XFF}"
mkgrant "$R_PEER" "172.16.${DTF_SLOT}.80/28" || SETUP_ERR="${SETUP_ERR} ${R_PEER}"
rm -f "${TMPDIR:-/tmp}/xff-art-${DTF_SLOT}-$$"
echo "  user id ${U_ID:-<none>}"
if [ -z "$SETUP_ERR" ] && docker image inspect "$CURL_IMAGE" >/dev/null 2>&1; then
  pass
else
  infra_fail "setup failed:${SETUP_ERR:- (curl image ${CURL_IMAGE} missing)}"
  end_suite
fi

# =============================================================================
# Phase 1: trusted proxies configured, XFF_TRUSTED_FOR_AUTHZ unset
# =============================================================================
begin_test "FIX #4681 (phase 1): startup logs the warning that XFF is not trusted for authorization"
W="$(backend_log | grep -F "$XFF_WARN" | head -1)"
echo "  ${W:-<no warning>}" | cut -c1-300
if [ -n "$W" ]; then pass; else fail "expected the startup WARN '${XFF_WARN} ...' (1.11.0 has no such setting)"; fi

begin_test "FIX #4681 (phase 1): from a TRUSTED proxy peer with X-Forwarded-For ${CLIENT_IP}, the CIDR-conditioned grant does NOT match (403/404)"
R="$(peer_download "$TRUSTED_PEER" "$R_XFF")"
echo "  ${TRUSTED_PEER} -> HTTP $(code_of "$R") $(body_of "$R" | head -c 120)"
if is_denied "$(code_of "$R")" && [ "$(body_of "$R")" != "$ART_BODY" ]; then
  pass
else
  fail "expected 403/404: the forwarded address is unverifiable without XFF_TRUSTED_FOR_AUTHZ (1.11.0 honours it and serves the artifact)"
fi

begin_test "FIX #4681 (phase 1): a LOGIN through the TRUSTED peer with X-Forwarded-For records NO client IP in audit_log"
LC="$(peer_login "$TRUSTED_PEER" "$CLIENT_IP")"; IP="$(last_login_ip)"
echo "  login HTTP ${LC}; audit_log LOGIN ip_address = ${IP}"
if [ "$LC" = "200" ] && [ "$IP" = "NULL" ]; then
  pass
else
  fail "expected login 200 and ip_address NULL (1.11.0 records the forwarded ${CLIENT_IP})"
fi

begin_test "CONTROL (phase 1): from an UNTRUSTED peer the TCP peer is used: the forwarded-CIDR grant is denied and the peer-CIDR grant is served"
R1="$(peer_download "$UNTRUSTED_PEER" "$R_XFF")"; R2="$(peer_download "$UNTRUSTED_PEER" "$R_PEER")"
echo "  ${UNTRUSTED_PEER} -> ${R_XFF}: HTTP $(code_of "$R1"); ${R_PEER}: HTTP $(code_of "$R2") '$(body_of "$R2" | head -c 60)'"
if is_denied "$(code_of "$R1")" && [ "$(code_of "$R2")" = "200" ] && [ "$(body_of "$R2")" = "$ART_BODY" ]; then
  pass
else
  fail "expected 403/404 then 200 with the artifact"
fi

begin_test "CONTROL (phase 1): a LOGIN through the UNTRUSTED peer with a spoofed X-Forwarded-For records the TCP peer"
LC="$(peer_login "$UNTRUSTED_PEER" "198.51.100.9")"; IP="$(last_login_ip)"
echo "  login HTTP ${LC}; audit_log LOGIN ip_address = ${IP}"
if [ "$LC" = "200" ] && [ "$IP" = "$UNTRUSTED_PEER" ]; then pass; else fail "expected ip_address ${UNTRUSTED_PEER}"; fi

# =============================================================================
# #4675: URL-carried credentials redacted from the http_request span uri
# =============================================================================
begin_test "setup: a Remote whose fetch logs inside the request span (upstream mock-oidc)"
RC="$(code_of "$(J POST /api/v1/repositories "{\"key\":\"${R_TICKET}\",\"name\":\"${R_TICKET}\",\"format\":\"generic\",\"repo_type\":\"remote\",\"is_public\":false,\"upstream_url\":\"http://mock-oidc/\"}")")"
if [ "$RC" = "200" ] || [ "$RC" = "201" ]; then pass; else infra_fail "could not create ${R_TICKET} (HTTP ${RC})"; end_suite; fi

TICKET="$(body_of "$(J POST /api/v1/auth/ticket '{"purpose":"download"}')" | jqr '.ticket // empty')"
PCT_VAL="pctticket${SUF}"; AMZ_VAL="amzsig${SUF}"; TOK_VAL="tokval${SUF}"; KEEP_VAL="keep${SUF}"
curl -s -o /dev/null --max-time 30 "${BASE_URL}/api/v1/repositories/${R_TICKET}/download/f/t-${SUF}.bin?ticket=${TICKET}" || true
curl -s -o /dev/null --max-time 30 -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  "${BASE_URL}/api/v1/repositories/${R_TICKET}/download/f/p-${SUF}.bin?%74icket=${PCT_VAL}&X-Amz-Signature=${AMZ_VAL}&token=${TOK_VAL}&keepme=${KEEP_VAL}" || true
sleep 1
LOG="$(backend_log)"
T_LINE="$(printf '%s\n' "$LOG" | grep -F "/download/f/t-${SUF}.bin" | grep -F 'uri=' | head -1)"
P_LINE="$(printf '%s\n' "$LOG" | grep -F "/download/f/p-${SUF}.bin" | grep -F 'uri=' | head -1)"
echo "  ticket request span: $(printf '%s' "$T_LINE" | grep -o 'uri=[^ ]*')"
echo "  other request span:  $(printf '%s' "$P_LINE" | grep -o 'uri=[^ ]*')"

begin_test "FIX #4675: a ?ticket= download logs uri ...?ticket=[REDACTED] and the ticket never appears in the log"
if [ -z "$TICKET" ] || [ -z "$T_LINE" ]; then
  fail "no ticket minted ('${TICKET}') or no span line logged for the ticket request"
elif printf '%s\n' "$LOG" | grep -qF "$TICKET"; then
  fail "the live download ticket appears in the backend log"
elif printf '%s' "$T_LINE" | grep -qF 'ticket=[REDACTED]'; then
  pass
else
  fail "expected 'ticket=[REDACTED]' in the span uri"
fi

begin_test "FIX #4675: %74icket= and X-Amz-Signature= values are redacted (name matched after percent-decoding)"
if [ -z "$P_LINE" ]; then
  fail "no span line logged for the request"
elif printf '%s\n' "$LOG" | grep -qE "${PCT_VAL}|${AMZ_VAL}"; then
  fail "a %74icket or X-Amz-Signature value appears in the backend log"
elif printf '%s' "$P_LINE" | grep -qF '%74icket=[REDACTED]' && printf '%s' "$P_LINE" | grep -qF 'X-Amz-Signature=[REDACTED]'; then
  pass
else
  fail "expected '%74icket=[REDACTED]' and 'X-Amz-Signature=[REDACTED]' in the span uri"
fi

begin_test "CONTROL (#544): token= was already redacted and an unrelated parameter is logged unchanged"
if [ -n "$P_LINE" ] && printf '%s' "$P_LINE" | grep -qF 'token=[REDACTED]' && printf '%s' "$P_LINE" | grep -qF "keepme=${KEEP_VAL}" \
   && ! printf '%s\n' "$LOG" | grep -qF "$TOK_VAL"; then
  pass
else
  fail "expected token=[REDACTED] and keepme=${KEEP_VAL} in the span uri"
fi

# =============================================================================
# #4662: public Remote with upstream credentials needs an explicit acceptance
# =============================================================================
pc_create() { # KEY PUBLIC(true|false) CREDS(true|false) ACCEPT(true|"")
  J POST /api/v1/repositories "$(jq -nc --arg k "$1" --argjson pub "$2" --argjson cred "$3" --arg acc "${4:-}" --arg pw "$PC_PW" \
    '{key:$k,name:$k,format:"generic",repo_type:"remote",is_public:$pub,upstream_url:"http://mock-oidc/"}
     + (if $cred then {upstream_auth_type:"basic",upstream_username:"pcuser",upstream_password:$pw} else {} end)
     + (if $acc == "true" then {allow_public_with_upstream_credentials:true} else {} end)')"
}
coded400() { [ "$(code_of "$1")" = "400" ] && [ "$(body_of "$1" | jqr '.code')" = "PUBLIC_REMOTE_UPSTREAM_CREDENTIALS" ]; }
PC_REF="pc-ref-${DTF_SLOT}-${SUF}"; PC_ACC="pc-acc-${DTF_SLOT}-${SUF}"; PC_PRIV="pc-priv-${DTF_SLOT}-${SUF}"
PC_PUB="pc-pub-${DTF_SLOT}-${SUF}"; PC_PUB2="pc-pub2-${DTF_SLOT}-${SUF}"
PC_PW="pcpw${SUF}"   # never sent anywhere that checks it

begin_test "FIX #4662 create: a public Remote with Basic upstream credentials is 400 PUBLIC_REMOTE_UPSTREAM_CREDENTIALS and is not created"
C="$(pc_create "$PC_REF" true true)"
echo "  HTTP $(code_of "$C") code=$(body_of "$C" | jqr '.code'); exists afterwards: HTTP $(code_of "$(J GET "/api/v1/repositories/${PC_REF}")")"
if coded400 "$C" && [ "$(code_of "$(J GET "/api/v1/repositories/${PC_REF}")")" = "404" ]; then pass; else fail "expected 400 PUBLIC_REMOTE_UPSTREAM_CREDENTIALS (1.11.0 creates it)"; fi

begin_test "FIX #4662 create: with allow_public_with_upstream_credentials it is created, reports public_with_upstream_credentials=true, and the audit row carries the acceptance"
C="$(pc_create "$PC_ACC" true true true)"
AUD="$(db "SELECT details->>'allow_public_with_upstream_credentials' FROM audit_log WHERE action = 'REPOSITORY_CREATED' AND details->>'key' = '${PC_ACC}' ORDER BY created_at DESC LIMIT 1")"
echo "  HTTP $(code_of "$C") public_with_upstream_credentials=$(body_of "$C" | jqr '.public_with_upstream_credentials') allow_public_with_upstream_credentials=$(body_of "$C" | jqr '.allow_public_with_upstream_credentials'); audit flag=${AUD:-<none>}"
if [ "$(code_of "$C" | cut -c1)" = "2" ] && [ "$(body_of "$C" | jqr '.public_with_upstream_credentials')" = "true" ] \
   && [ "$(body_of "$C" | jqr '.allow_public_with_upstream_credentials')" = "true" ] && [ "$AUD" = "true" ]; then
  pass
else
  fail "expected 2xx with public_with_upstream_credentials=true, allow_public_with_upstream_credentials=true and the audit flag"
fi

begin_test "FIX #4662 update: making a credentialed private Remote public is 400 without the flag and accepted with it"
pc_create "$PC_PRIV" false true >/dev/null
U1="$(J PATCH "/api/v1/repositories/${PC_PRIV}" '{"is_public":true}')"
PUB1="$(body_of "$(J GET "/api/v1/repositories/${PC_PRIV}")" | jqr '.is_public')"
U2="$(J PATCH "/api/v1/repositories/${PC_PRIV}" '{"is_public":true,"allow_public_with_upstream_credentials":true}')"
echo "  without flag: HTTP $(code_of "$U1") $(body_of "$U1" | jqr '.code'), is_public after=${PUB1}; with flag: HTTP $(code_of "$U2") public_with_upstream_credentials=$(body_of "$U2" | jqr '.public_with_upstream_credentials')"
if coded400 "$U1" && [ "$PUB1" = "false" ] && [ "$(code_of "$U2")" = "200" ] && [ "$(body_of "$U2" | jqr '.public_with_upstream_credentials')" = "true" ]; then
  pass
else
  fail "expected 400 PUBLIC_REMOTE_UPSTREAM_CREDENTIALS leaving it private, then 200 with public_with_upstream_credentials=true"
fi

begin_test "FIX #4662 update: adding user:password@ to a public Remote's upstream_url is 400"
pc_create "$PC_PUB2" true false >/dev/null
U3="$(J PATCH "/api/v1/repositories/${PC_PUB2}" "$(jq -nc --arg pw "$PC_PW" '{upstream_url:("http://pcuser:" + $pw + "@mock-oidc/")}')")"
echo "  HTTP $(code_of "$U3") $(body_of "$U3" | jqr '.code')"
if coded400 "$U3"; then pass; else fail "expected 400 PUBLIC_REMOTE_UPSTREAM_CREDENTIALS"; fi

begin_test "FIX #4662 PUT upstream-auth: credentials on a public Remote are 400 without the flag and accepted with it"
pc_create "$PC_PUB" true false >/dev/null
A1="$(J PUT "/api/v1/repositories/${PC_PUB}/upstream-auth" "{\"auth_type\":\"bearer\",\"password\":\"${PC_PW}\"}")"
TYPE1="$(body_of "$(J GET "/api/v1/repositories/${PC_PUB}")" | jqr '.upstream_auth_type')"
A2="$(J PUT "/api/v1/repositories/${PC_PUB}/upstream-auth" "{\"auth_type\":\"bearer\",\"password\":\"${PC_PW}\",\"allow_public_with_upstream_credentials\":true}")"
G="$(body_of "$(J GET "/api/v1/repositories/${PC_PUB}")")"
echo "  without flag: HTTP $(code_of "$A1") $(body_of "$A1" | jqr '.code'), auth type after=${TYPE1}; with flag: HTTP $(code_of "$A2") $(body_of "$A2" | head -c 120)"
echo "  GET: public_with_upstream_credentials=$(printf '%s' "$G" | jqr '.public_with_upstream_credentials') allow=$(printf '%s' "$G" | jqr '.allow_public_with_upstream_credentials')"
if coded400 "$A1" && [ "$TYPE1" = "null" ] && [ "$(code_of "$A2")" = "200" ] \
   && [ "$(printf '%s' "$G" | jqr '.public_with_upstream_credentials')" = "true" ] && [ "$(printf '%s' "$G" | jqr '.allow_public_with_upstream_credentials')" = "true" ]; then
  pass
else
  fail "expected 400 with no credentials stored, then 200 and the GET reporting both flags true"
fi

begin_test "CONTROL #4662: public without credentials, private with credentials, and an unrelated PATCH of an accepted repo all succeed"
C1="$(code_of "$(pc_create "pc-ok1-${DTF_SLOT}-${SUF}" true false)")"
C2="$(code_of "$(pc_create "pc-ok2-${DTF_SLOT}-${SUF}" false true)")"
C3="$(code_of "$(J PATCH "/api/v1/repositories/${PC_ACC}" "{\"description\":\"d-${SUF}\"}")")"
echo "  public/no-creds: ${C1}; private/creds: ${C2}; PATCH description on ${PC_ACC}: ${C3}"
if [ "${C1:0:1}" = "2" ] && [ "${C2:0:1}" = "2" ] && [ "${C3:0:1}" = "2" ]; then pass; else fail "a legitimate write was refused"; fi

# =============================================================================
# Phase 2: XFF_TRUSTED_FOR_AUTHZ=true
# =============================================================================
begin_test "setup (phase 2): recreate ONLY the backend with XFF_TRUSTED_FOR_AUTHZ=true"
if recreate_backend_with_xff_trust && curl -sf --max-time 10 "${BASE_URL}/health" >/dev/null 2>&1; then
  pass
else
  infra_fail "could not recreate the backend with XFF_TRUSTED_FOR_AUTHZ=true"
  end_suite
fi

begin_test "CONTROL (phase 2): with XFF_TRUSTED_FOR_AUTHZ=true the startup warning is gone"
if backend_log | grep -qF "$XFF_WARN"; then fail "the recreated backend still warns"; else pass; fi

begin_test "CONTROL (phase 2): the TRUSTED peer's X-Forwarded-For ${CLIENT_IP} now satisfies the CIDR grant and is recorded on LOGIN"
R="$(peer_download "$TRUSTED_PEER" "$R_XFF")"
LC="$(peer_login "$TRUSTED_PEER" "$CLIENT_IP")"; IP="$(last_login_ip)"
echo "  download HTTP $(code_of "$R") '$(body_of "$R" | head -c 60)'; login HTTP ${LC}; audit ip_address=${IP}"
if [ "$(code_of "$R")" = "200" ] && [ "$(body_of "$R")" = "$ART_BODY" ] && [ "$LC" = "200" ] && [ "$IP" = "$CLIENT_IP" ]; then
  pass
else
  fail "expected 200 with the artifact and ip_address ${CLIENT_IP} once the operator asserts XFF is trustworthy"
fi

end_suite
