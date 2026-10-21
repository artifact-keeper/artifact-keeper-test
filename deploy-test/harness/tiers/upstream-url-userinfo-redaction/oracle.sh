#!/usr/bin/env bash
# jq programs are single-quoted on purpose; their $vars are jq variables.
# shellcheck disable=SC2016
# =============================================================================
# tiers/upstream-url-userinfo-redaction/oracle.sh
#   Remote upstream_url credentials (`user:password@`) are never echoed by the
#   API, kept in origin / proxy-cache rows, or written to the log; PATCH
#   applies upstream_url (artifact-keeper #4452, #4463, #4467, #4503; 1.11.0)
# =============================================================================
# run.sh has stood up storage.filesystem + upstreams.mock-userinfo with
# RATE_LIMIT_ENABLED=false and UPSTREAM_ALLOW_PRIVATE_IPS=true, and exported
# BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# BACKEND_IMAGE, RELEASE_GATE=1, JUNIT_OUTPUT_DIR. The profile adds two
# recording upstreams (mock-up-a, mock-up-b) and gives the backend an
# S3_PUBLIC_ENDPOINT carrying credentials so the secondary-backend WARN fires.
#
# Every case below is either FIX (red on ak-backend:1.10.0, green on 1.11.0
# and later) or CONTROL (green on both). On 1.10.0 several surfaces do not
# exist yet (`upstream_url_has_credentials`, `artifacts.origin`, the
# S3_PUBLIC_ENDPOINT variable): the FIX cases go red there by the absence AND
# assert the fixed content on the green image, never existence alone.
#
# Not duplicated from redact-userinfo-leak (#2926): that tier proves the
# proxy-fetch 5xx diagnostic log line is redacted. This one covers the API
# responses, the DB rows, the audit trail, the PATCH path and the startup WARN.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"; : "${RUN_ID:?}"; : "${DTF_DIR:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every check here records its own pass/fail and
# must not abort the run on a non-matching grep.
set +e

SUF="${RUN_ID##*-}-$$"
BACKEND_CTR="ak-dtf${DTF_SLOT}-backend"
MOCK_A_CTR="ak-dtf${DTF_SLOT}-mock-up-a"
MOCK_B_CTR="ak-dtf${DTF_SLOT}-mock-up-b"

# Secrets: unique per run so a hit can only come from this run.
U_A="upuser${DTF_SLOT}"; P_A="UrlPwA${SUF//-/}x"
U_B="upuserb${DTF_SLOT}"; P_B="UrlPwB${SUF//-/}x"
U_AUTH="authuser${DTF_SLOT}"; P_AUTH="FieldPw${SUF//-/}x"
P_PUB="PubPw$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')x"   # S3_PUBLIC_ENDPOINT password
P_ORIGIN="OriginPw${SUF//-/}x"
P_PCA="PcaPw${SUF//-/}x"

R_CRED="uur-cred-${DTF_SLOT}-${SUF}"     # Remote with userinfo in upstream_url
R_AUTH="uur-auth-${DTF_SLOT}-${SUF}"     # Remote with upstream-auth fields
R_WS="uur-ws-${DTF_SLOT}-${SUF}"         # whitespace URL (must be refused)

# --- helpers (always return 0) ----------------------------------------------
db() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>&1 | tr -d '\r'; }
J() { # METHOD PATH [JSON] -> body, then a final line "HTTP <code>"
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
jqr() { jq -r "$@" 2>/dev/null || true; }
mock_requests() { # CTR -> /__requests JSON
  docker exec "$1" python3 -c "import urllib.request;print(urllib.request.urlopen('http://127.0.0.1/__requests',timeout=5).read().decode())" 2>/dev/null || echo '{}'
}
mock_count() { mock_requests "$1" | jqr --arg p "$2" '.paths[$p] // 0'; }
mock_auth_for() { mock_requests "$1" | jqr --arg p "$2" '[.auth[] | select(.path == $p) | .auth] | last // "NONE"'; }
basic() { printf 'Basic %s' "$(printf '%s:%s' "$1" "$2" | base64 | tr -d '\n')"; }
backend_log() { docker logs "$BACKEND_CTR" 2>&1 | sed 's/\x1b\[[0-9;]*m//g'; }
mkremote() { # KEY URL [extra-json-object]
  local extra="${3:-{\}}"
  J POST /api/v1/repositories "$(jq -nc --arg k "$1" --arg u "$2" --argjson x "$extra" \
    '{key:$k,name:$k,format:"generic",repo_type:"remote",is_public:false,upstream_url:$u} + $x')"
}
fetch() { # KEY PATH -> "<code>|<body>"
  local b c
  b="$(curl -s --max-time 30 -w '\n%{http_code}' -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    "${BASE_URL}/api/v1/repositories/$1/download/$2" 2>/dev/null || printf '\n000')"
  c="$(printf '%s\n' "$b" | tail -1)"
  printf '%s|%s' "$c" "$(printf '%s\n' "$b" | sed '$d')"
}

# boot_with_public_endpoint: recreate ONLY the backend with S3_BUCKET and a
# credentialed S3_PUBLIC_ENDPOINT (primary storage stays filesystem, so the
# backend only tries to register an ADDITIONAL S3 backend and logs the #4503
# WARN; 192.0.2.1 is TEST-NET-1 and is never contacted). Same compose project
# and overlays as run.sh, so the labels stay intact and `down -v` reclaims it.
boot_with_public_endpoint() {
  local override rc
  override="$(mktemp "${TMPDIR:-/tmp}/uur-pubep-${DTF_SLOT}.XXXXXX.yml")"
  cat > "$override" <<YML
services:
  backend:
    environment:
      S3_BUCKET: "dtf-userinfo-unused"
      S3_PUBLIC_ENDPOINT: "http://dtfpubuser:${P_PUB}@192.0.2.1:9"
YML
  docker compose -p "ak-dtf${DTF_SLOT}" \
    -f "${DTF_DIR}/compose.base.yml" \
    -f "${DTF_DIR}/profiles/storage.filesystem.yml" \
    -f "${DTF_DIR}/profiles/upstreams.mock-userinfo.yml" \
    -f "$override" \
    up -d backend >/dev/null 2>&1
  rc=$?
  rm -f "$override"
  [ "$rc" -eq 0 ] || return "$rc"
  # Not `up --wait`: since artifact-keeper#4530 a skipped secondary backend
  # makes /health (the image HEALTHCHECK) answer 503 by design, so the
  # container never turns healthy. Wait for /readyz, which ignores it.
  wait_backend_ready
}
wait_backend_ready() {
  local _
  for _ in $(seq 1 90); do
    curl -sf --max-time 5 "${BASE_URL}/readyz" >/dev/null 2>&1 && return 0
    sleep 2
  done
  return 1
}

begin_suite "upstream-url-userinfo-redaction"

begin_test "setup: recreate the backend with S3_BUCKET and a credentialed S3_PUBLIC_ENDPOINT (random per run)"
if boot_with_public_endpoint; then
  pass
else
  infra_fail "could not recreate the backend with the S3_PUBLIC_ENDPOINT override"
  end_suite
fi
auth_admin

begin_test "setup: create a Remote whose upstream_url embeds user:password@ and one with upstream-auth fields"
CREATE_RESP="$(mkremote "$R_CRED" "http://${U_A}:${P_A}@mock-up-a/")"
AUTH_RESP="$(mkremote "$R_AUTH" "http://mock-up-a/" \
  "$(jq -nc --arg u "$U_AUTH" --arg p "$P_AUTH" '{upstream_auth_type:"basic",upstream_username:$u,upstream_password:$p}')")"
if [ "$(body_of "$CREATE_RESP" | jqr '.key')" = "$R_CRED" ] && [ "$(body_of "$AUTH_RESP" | jqr '.key')" = "$R_AUTH" ]; then
  pass
else
  infra_fail "could not create the Remotes (cred: $(code_of "$CREATE_RESP"), auth: $(code_of "$AUTH_RESP"))" \
    "$(body_of "$CREATE_RESP" | head -c 400)"
  end_suite
fi

# =============================================================================
# #4452: API responses render upstream_url without userinfo
# =============================================================================
begin_test "FIX #4452: the create response renders upstream_url without the password and sets upstream_url_has_credentials=true"
B="$(body_of "$CREATE_RESP")"
URL="$(printf '%s' "$B" | jqr '.upstream_url')"; HAS="$(printf '%s' "$B" | jqr '.upstream_url_has_credentials')"
echo "  create: upstream_url=${URL} upstream_url_has_credentials=${HAS}"
if printf '%s' "$B" | grep -qF "$P_A"; then
  fail "the create response echoes the upstream password (upstream_url=${URL})"
elif [ "$URL" != "http://mock-up-a/" ] || [ "$HAS" != "true" ]; then
  fail "expected upstream_url=http://mock-up-a/ and upstream_url_has_credentials=true, got ${URL} / ${HAS}"
else
  pass
fi

begin_test "FIX #4452: GET /repositories/{key} and the listing carry no password; the single GET reports upstream_url_has_credentials=true"
G="$(J GET "/api/v1/repositories/${R_CRED}")"; L="$(J GET "/api/v1/repositories?per_page=100")"
GURL="$(body_of "$G" | jqr '.upstream_url')"; GHAS="$(body_of "$G" | jqr '.upstream_url_has_credentials')"
LHITS="$(body_of "$L" | grep -oF "$P_A" | wc -l | tr -d ' ')"
LROW="$(body_of "$L" | jqr --arg k "$R_CRED" '.items[]? | select(.key == $k) | "\(.upstream_url) \(.upstream_url_has_credentials)"')"
echo "  get: ${GURL} has_credentials=${GHAS}; list row: ${LROW:-<missing>}; password occurrences in list: ${LHITS}"
if body_of "$G" | grep -qF "$P_A"; then
  fail "GET /api/v1/repositories/${R_CRED} echoes the upstream password"
elif [ "$LHITS" != "0" ]; then
  fail "the repository listing echoes the upstream password (${LHITS}x)"
elif [ "$GURL" != "http://mock-up-a/" ] || [ "$GHAS" != "true" ] || [ "$LROW" != "http://mock-up-a/ true" ]; then
  fail "expected the redacted URL and upstream_url_has_credentials=true on GET and list, got '${GURL} ${GHAS}' / '${LROW}'"
else
  pass
fi

begin_test "FIX #4452: POST /repositories/{key}/test-upstream renders the URL without the password"
T="$(J POST "/api/v1/repositories/${R_CRED}/test-upstream")"
echo "  test-upstream: HTTP $(code_of "$T") $(body_of "$T" | head -c 300)"
if body_of "$T" | grep -qF "$P_A"; then
  fail "the test-upstream response echoes the upstream password"
elif [ "$(body_of "$T" | jqr '.upstream_url')" != "http://mock-up-a/" ] || [ "$(body_of "$T" | jqr '.upstream_url_has_credentials')" != "true" ]; then
  fail "expected upstream_url=http://mock-up-a/ and upstream_url_has_credentials=true in the test-upstream body"
else
  pass
fi

begin_test "CONTROL: a fetch through the Remote is served by mock-up-a, which still receives the URL credentials as HTTP Basic"
F="$(fetch "$R_CRED" "f/one-${SUF}.txt")"
GOT_AUTH="$(mock_auth_for "$MOCK_A_CTR" "/f/one-${SUF}.txt")"
echo "  fetch: HTTP ${F%%|*} body='${F#*|}'; mock-up-a Authorization: ${GOT_AUTH}"
if [ "${F%%|*}" = "200" ] && [ "${F#*|}" = "mock-up-a served /f/one-${SUF}.txt" ] && [ "$GOT_AUTH" = "$(basic "$U_A" "$P_A")" ]; then
  pass
else
  fail "expected 200 with mock-up-a's body and Authorization '$(basic "$U_A" "$P_A")' at the upstream"
fi

# =============================================================================
# #4463: origin records and the proxy-cache catalogue keep no credentials
# =============================================================================
begin_test "FIX #4463: the proxy-cache catalogue row for the fetched file records the upstream URL without userinfo"
PCA="$(db "SELECT p.upstream_url FROM proxy_cache_artifacts p JOIN repositories r ON r.id = p.repository_id WHERE r.key = '${R_CRED}' AND p.path = 'f/one-${SUF}.txt'")"
echo "  proxy_cache_artifacts.upstream_url = ${PCA:-<no row>}"
if printf '%s' "$PCA" | grep -qF "$P_A"; then
  fail "proxy_cache_artifacts.upstream_url keeps the password: ${PCA}"
elif [ "$PCA" != "http://mock-up-a/f/one-${SUF}.txt" ]; then
  fail "expected proxy_cache_artifacts.upstream_url=http://mock-up-a/f/one-${SUF}.txt, got '${PCA}'"
else
  pass
fi

begin_test "FIX #4463: a write of a credentialed URL into proxy_cache_artifacts.upstream_url is stripped by the database"
PCW="$(db "UPDATE proxy_cache_artifacts p SET upstream_url = 'http://pcauser:${P_PCA}@mock-up-a/f/one-${SUF}.txt' FROM repositories r WHERE r.id = p.repository_id AND r.key = '${R_CRED}' AND p.path = 'f/one-${SUF}.txt' RETURNING p.upstream_url" | head -1)"
echo "  stored after UPDATE: ${PCW}"
if printf '%s' "$PCW" | grep -qF "$P_PCA"; then
  fail "the database kept the credentials written into proxy_cache_artifacts.upstream_url"
elif [ "$PCW" != "http://mock-up-a/f/one-${SUF}.txt" ]; then
  fail "expected the stripped URL http://mock-up-a/f/one-${SUF}.txt, got '${PCW}'"
else
  pass
fi

begin_test "FIX #4463: an artifact row in the credentialed Remote gets an origin without userinfo, filled or explicit, and the artifact API echoes no password"
OF="$(db "INSERT INTO artifacts (repository_id, path, name, size_bytes, checksum_sha256, content_type, storage_key)
          SELECT id, 'seed/fill-${SUF}.bin', 'fill-${SUF}.bin', 3, repeat('a', 64), 'application/octet-stream', 'seed/fill-${SUF}.bin'
          FROM repositories WHERE key = '${R_CRED}' RETURNING id || ' ' || (origin->>'upstream_url')" | head -1)"
OE="$(db "INSERT INTO artifacts (repository_id, path, name, size_bytes, checksum_sha256, content_type, storage_key, origin)
          SELECT id, 'seed/expl-${SUF}.bin', 'expl-${SUF}.bin', 3, repeat('a', 64), 'application/octet-stream', 'seed/expl-${SUF}.bin',
                 jsonb_build_object('v', 1, 'kind', 'proxy', 'repository_key', key, 'upstream_url', 'http://originuser:${P_ORIGIN}@mock-up-a/')
          FROM repositories WHERE key = '${R_CRED}' RETURNING id || ' ' || (origin->>'upstream_url')" | head -1)"
ART_ID="${OF%% *}"
ART="$(J GET "/api/v1/artifacts/${ART_ID}")"
AORIG="$(body_of "$ART" | jqr '.origin.upstream_url')"
echo "  filled: ${OF}"; echo "  explicit: ${OE}"; echo "  GET /api/v1/artifacts/{id}: HTTP $(code_of "$ART") origin.upstream_url=${AORIG}"
if printf '%s %s %s' "$OF" "$OE" "$(body_of "$ART")" | grep -qE "${P_A}|${P_ORIGIN}"; then
  fail "an origin record or the artifact response keeps the credentials"
elif [ "${OF#* }" != "http://mock-up-a" ] || [ "${OE#* }" != "http://mock-up-a" ] || [ "$AORIG" != "http://mock-up-a" ]; then
  fail "expected origin.upstream_url=http://mock-up-a for the filled row, the explicit row and the API (1.10.0 has no origin column)"
else
  pass
fi

begin_test "FIX #4463: an upstream_url containing a tab is refused with 400 VALIDATION_ERROR"
WS="$(mkremote "$R_WS" "$(printf 'http://%s:%s@mock-up-a/\tf/' "$U_A" "$P_A")")"
echo "  create with tab: HTTP $(code_of "$WS") $(body_of "$WS" | head -c 200)"
if [ "$(code_of "$WS")" = "400" ] && [ "$(body_of "$WS" | jqr '.code')" = "VALIDATION_ERROR" ] \
   && body_of "$WS" | grep -qi "whitespace"; then
  pass
else
  fail "expected 400 VALIDATION_ERROR naming whitespace; the URL parser drops the tab, so it would validate and be stored raw"
fi

# =============================================================================
# #4467: PATCH applies upstream_url; cross-origin with credentials is a 409
# =============================================================================
begin_test "FIX #4467: PATCH upstream_url moves the Remote to mock-up-b, redacts the response, and the next fetch reaches B with B's credentials"
P="$(J PATCH "/api/v1/repositories/${R_CRED}" "$(jq -nc --arg u "http://${U_B}:${P_B}@mock-up-b/" '{upstream_url:$u}')")"
PURL="$(body_of "$P" | jqr '.upstream_url')"; PHAS="$(body_of "$P" | jqr '.upstream_url_has_credentials')"
A_BEFORE="$(mock_requests "$MOCK_A_CTR" | jqr '.total')"
F2="$(fetch "$R_CRED" "f/two-${SUF}.txt")"
A_AFTER="$(mock_requests "$MOCK_A_CTR" | jqr '.total')"
B_HITS="$(mock_count "$MOCK_B_CTR" "/f/two-${SUF}.txt")"; B_AUTH="$(mock_auth_for "$MOCK_B_CTR" "/f/two-${SUF}.txt")"
echo "  PATCH: HTTP $(code_of "$P") upstream_url=${PURL} has_credentials=${PHAS}"
echo "  next fetch: HTTP ${F2%%|*} '${F2#*|}'; mock-up-a requests ${A_BEFORE} -> ${A_AFTER}; mock-up-b hits ${B_HITS}, Authorization ${B_AUTH}"
if body_of "$P" | grep -qF "$P_B"; then
  fail "the PATCH response echoes the new upstream password"
elif [ "$(code_of "$P")" != "200" ] || [ "$PURL" != "http://mock-up-b/" ] || [ "$PHAS" != "true" ]; then
  fail "expected 200 with upstream_url=http://mock-up-b/ and upstream_url_has_credentials=true (1.10.0 answers 200 and ignores the field)"
elif [ "${F2#*|}" != "mock-up-b served /f/two-${SUF}.txt" ] || [ "$B_HITS" -lt 1 ] || [ "$A_BEFORE" != "$A_AFTER" ]; then
  fail "the fetch after the PATCH did not move to mock-up-b"
elif [ "$B_AUTH" != "$(basic "$U_B" "$P_B")" ]; then
  fail "mock-up-b did not receive the new URL credentials as Basic auth (got ${B_AUTH})"
else
  pass
fi

begin_test "FIX #4467: the PATCH audit row records both upstream URLs without userinfo and credentials_changed=true"
AU="$(db "SELECT details->'upstream_change' FROM audit_log WHERE action = 'REPOSITORY_UPDATED' AND details->>'key' = '${R_CRED}' AND details ? 'upstream_change' ORDER BY created_at DESC LIMIT 1")"
echo "  upstream_change: ${AU:-<none>}"
if printf '%s' "$AU" | grep -qE "${P_A}|${P_B}"; then
  fail "the audit row keeps an upstream password"
elif [ "$(printf '%s' "$AU" | jqr '.previous_upstream_url')" = "http://mock-up-a/" ] \
  && [ "$(printf '%s' "$AU" | jqr '.upstream_url')" = "http://mock-up-b/" ] \
  && [ "$(printf '%s' "$AU" | jqr '.credentials_changed')" = "true" ]; then
  pass
else
  fail "expected upstream_change {previous_upstream_url: http://mock-up-a/, upstream_url: http://mock-up-b/, credentials_changed: true}"
fi

begin_test "FIX #4467: with upstream-auth configured, a cross-origin PATCH is refused 409 and a same-origin PATCH is applied"
X="$(J PATCH "/api/v1/repositories/${R_AUTH}" '{"upstream_url":"http://mock-up-b/"}')"
XURL="$(body_of "$(J GET "/api/v1/repositories/${R_AUTH}")" | jqr '.upstream_url')"
S="$(J PATCH "/api/v1/repositories/${R_AUTH}" '{"upstream_url":"http://mock-up-a/f/"}')"
SURL="$(body_of "$(J GET "/api/v1/repositories/${R_AUTH}")" | jqr '.upstream_url')"
echo "  cross-origin PATCH: HTTP $(code_of "$X") $(body_of "$X" | jqr '.code') -> stored ${XURL}"
echo "  same-origin PATCH: HTTP $(code_of "$S") -> stored ${SURL}"
if [ "$(code_of "$X")" = "409" ] && [ "$XURL" = "http://mock-up-a/" ] && [ "$(code_of "$S")" = "200" ] && [ "$SURL" = "http://mock-up-a/f/" ]; then
  pass
else
  fail "expected 409 leaving http://mock-up-a/, then 200 storing http://mock-up-a/f/ (1.10.0: 200 and both ignored)"
fi

begin_test "CONTROL: PATCH of an unrelated field (description) is applied"
D="$(J PATCH "/api/v1/repositories/${R_AUTH}" "{\"description\":\"desc-${SUF}\"}")"
if [ "$(code_of "$D")" = "200" ] && [ "$(body_of "$(J GET "/api/v1/repositories/${R_AUTH}")" | jqr '.description')" = "desc-${SUF}" ]; then
  pass
else
  fail "PATCH description: HTTP $(code_of "$D")"
fi

# =============================================================================
# #4851: the listing and the PATCH response report upstream auth like GET
# =============================================================================
begin_test "FIX #4851: the listing and the PATCH response report upstream_auth_type=basic, upstream_auth_configured=true, as GET does"
auth_proj() { jqr '"\(.upstream_auth_type) \(.upstream_auth_configured)"'; }
L="$(J GET "/api/v1/repositories?per_page=100")"
G_AUTH="$(body_of "$(J GET "/api/v1/repositories/${R_AUTH}")" | auth_proj)"
L_AUTH="$(body_of "$L" | jqr --arg k "$R_AUTH" '.items[]? | select(.key == $k) | "\(.upstream_auth_type) \(.upstream_auth_configured)"')"
P_AUTH_ROW="$(body_of "$D" | auth_proj)"
G_CRED="$(body_of "$(J GET "/api/v1/repositories/${R_CRED}")" | auth_proj)"
L_CRED="$(body_of "$L" | jqr --arg k "$R_CRED" '.items[]? | select(.key == $k) | "\(.upstream_auth_type) \(.upstream_auth_configured)"')"
echo "  ${R_AUTH}: get '${G_AUTH}', list '${L_AUTH:-<missing>}', patch '${P_AUTH_ROW}'"
echo "  ${R_CRED} (URL userinfo only, no upstream-auth fields): get '${G_CRED}', list '${L_CRED:-<missing>}'"
if [ "$G_AUTH" != "basic true" ] || [ "$G_CRED" != "null false" ]; then
  fail "GET itself changed: expected 'basic true' for ${R_AUTH} and 'null false' for ${R_CRED}, got '${G_AUTH}' / '${G_CRED}'"
elif [ "$L_AUTH" != "basic true" ] || [ "$P_AUTH_ROW" != "basic true" ]; then
  fail "expected the list row and the PATCH response to report 'basic true' like GET, got list '${L_AUTH:-<missing>}', patch '${P_AUTH_ROW}' (1.11.3: 'null false')"
elif [ "$L_CRED" != "null false" ]; then
  fail "a Remote without upstream-auth fields must list 'null false', got '${L_CRED:-<missing>}'"
else
  pass
fi

# =============================================================================
# #4503: the refused S3_PUBLIC_ENDPOINT is logged redacted
# =============================================================================
begin_test "FIX #4503: the 'Additional S3 storage backend skipped' WARN shows S3_PUBLIC_ENDPOINT as http://***@192.0.2.1:9"
WARN="$(backend_log | grep 'Additional S3 storage backend skipped' | head -1)"
echo "  ${WARN:-<no WARN line>}" | cut -c1-400
if printf '%s' "$WARN" | grep -qF "$P_PUB"; then
  fail "the WARN prints the public endpoint's password"
elif printf '%s' "$WARN" | grep -qF 'http://***@192.0.2.1:9'; then
  pass
else
  fail "expected the WARN with the endpoint redacted to http://***@192.0.2.1:9 (1.10.0 does not read S3_PUBLIC_ENDPOINT)"
fi

# =============================================================================
# Whole-run controls: nothing anywhere carries a password
# =============================================================================
begin_test "CONTROL: no password used in this run appears in the backend log"
LOGHITS="$(backend_log | grep -cE "${P_A}|${P_B}|${P_AUTH}|${P_PUB}|${P_ORIGIN}|${P_PCA}")"
echo "  log lines carrying a password: ${LOGHITS}"
if [ "$LOGHITS" = "0" ]; then pass; else fail "${LOGHITS} backend log line(s) carry a password" "$(backend_log | grep -E "${P_A}|${P_B}|${P_AUTH}|${P_PUB}" | head -3)"; fi

begin_test "CONTROL: no audit_log row carries a password used in this run"
AUHITS="$(db "SELECT count(*) FROM audit_log WHERE details::text ~ '${P_A}|${P_B}|${P_AUTH}'")"
echo "  audit rows carrying a password: ${AUHITS}"
if [ "$AUHITS" = "0" ]; then pass; else fail "${AUHITS} audit row(s) carry a password"; fi

end_suite
