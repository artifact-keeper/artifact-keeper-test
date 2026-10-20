#!/usr/bin/env bash
# =============================================================================
# tiers/ops-endpoints-1110/oracle.sh
#   #4417  S3_PUBLIC_ENDPOINT: presigned download redirects point at the public
#          origin and work from there; a malformed value aborts startup
#   #4610  /readyz reports dependencies; READYZ_REQUIRE_SEARCH gates on search
#   #4591  SMTP_TLS_MODE=starttls-opportunistic, SMTP_TLS_CA_CERT
# See the manifest for the gates.
#
# run.sh exported BASE_URL, S3_PORT, DB_CONTAINER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# DTF_DIR, RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH (and the slot's ports).
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${S3_PORT:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"
: "${DTF_SLOT:?}"; : "${DTF_DIR:?}"; : "${RUN_ID:?}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit. This oracle probes failure paths on purpose
# (curl timeouts, refused sends, a backend that must exit), so every step
# records its outcome through fail_g instead of aborting the suite.
set +e

BASE="$BASE_URL"
FX="${HERE}/fixtures"
PROJECT="ak-dtf${DTF_SLOT}"
BACKEND_CTR="ak-dtf${DTF_SLOT}-backend"
SMTP_CTR="ak-dtf${DTF_SLOT}-mock-smtp"
OS_CTR="ak-dtf${DTF_SLOT}-mock-opensearch"
SFX="${DTF_SLOT}-${RUN_ID##*-}"
PUBLIC="127.0.0.1:${S3_PORT}"

# The manifest's profile list, so a recreate keeps every overlay's env.
PROFILES=""
# shellcheck source=/dev/null
source "${HERE}/manifest"
COMPOSE_ARGS=(-p "$PROJECT" -f "${DTF_DIR}/compose.base.yml")
for p in $PROFILES; do COMPOSE_ARGS+=(-f "${DTF_DIR}/profiles/${p}.yml"); done
COMPOSE_ARGS+=(-f "${FX}/backend.variant.yml")

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

login(){
  TOK="$(curl -s --max-time 15 -X POST "${BASE}/api/v1/auth/login" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg p "$ADMIN_PASS" '{username:"admin",password:$p}')" | jqr '.access_token // empty')"
}
# variant <smtp-mode> <smtp-port> <smtp-ca|""> <s3-public-endpoint> [nowait]
# Recreates only the backend (postgres, MinIO and the mocks stay).
variant(){
  export V_SMTP_TLS_MODE="$1" V_SMTP_PORT="$2" V_SMTP_TLS_CA_CERT="$3" V_S3_PUBLIC_ENDPOINT="$4"
  if [ "${5:-}" = "nowait" ]; then
    docker compose "${COMPOSE_ARGS[@]}" up -d --no-deps --force-recreate backend >"${W}/recreate.log" 2>&1 || true
    return 0
  fi
  docker compose "${COMPOSE_ARGS[@]}" up -d --no-deps --force-recreate --wait backend >"${W}/recreate.log" 2>&1 || true
  login
}
send(){
  : >"${W}/body"
  CODE="$(curl -s -o "${W}/body" -D "${W}/hdr" -w '%{http_code}' --max-time 90 "$@")"
  BODY="$(cat "${W}/body" 2>/dev/null || true)"
}
smtp_test(){
  send -X POST "${BASE}/api/v1/admin/smtp/test" -H "Authorization: Bearer ${TOK}" \
    -H 'Content-Type: application/json' -d "$(jq -nc --arg t "$1" '{to:$t}')"
}
# smtp_rec <rcpt> -> the mock's JSON record lines for that recipient
smtp_rec(){ docker exec "$SMTP_CTR" sh -c 'cat /tmp/smtp/messages.jsonl 2>/dev/null || true' | grep -F "<$1>" || true; }
os_mode(){ docker exec "$OS_CTR" sh -c "echo $1 > /tmp/os/mode"; }
readyz(){ send "${BASE}/readyz"; }

begin_suite "ops-endpoints-1110"

login
[ -n "$TOK" ] || { infra_fail "no admin session"; end_suite; }
docker exec "$SMTP_CTR" sh -c 'echo accept > /tmp/smtp/mode' || { infra_fail "mock SMTP not reachable"; end_suite; }

REPO="ops-gen-${SFX}"
c="$(curl -s -o "${W}/mk" -w '%{http_code}' --max-time 15 -X POST "${BASE}/api/v1/repositories" \
  -H "Authorization: Bearer ${TOK}" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg k "$REPO" '{key:$k,name:$k,format:"generic",repo_type:"local",is_public:false}')")"
[ "$c" = "200" ] || [ "$c" = "201" ] || { infra_fail "could not create ${REPO} (HTTP ${c}: $(head -c 200 "${W}/mk"))"; end_suite; }
head -c 200000 /dev/urandom > "${W}/obj.bin"

# =============================================================================
# #4417: presigned redirects and S3_PUBLIC_ENDPOINT.
# =============================================================================
begin_test "CONTROL: on S3 storage an upload is stored through the internal S3_ENDPOINT and listed"
reset_case
send -X PUT "${BASE}/api/v1/repositories/${REPO}/artifacts/pub/obj.bin" -H "Authorization: Bearer ${TOK}" --data-binary @"${W}/obj.bin"
note "PUT pub/obj.bin -> ${CODE}"
{ [ "$CODE" = "200" ] || [ "$CODE" = "201" ]; } || fail_g "upload answered ${CODE}: ${BODY:0:200}"
send "${BASE}/api/v1/repositories/${REPO}/artifacts" -H "Authorization: Bearer ${TOK}"
grep -q '"pub/obj.bin"' <<<"$BODY" || fail_g "the artifact listing does not show pub/obj.bin (HTTP ${CODE})"
finish_case "S3 uploads through the internal endpoint are broken"

begin_test "FIX #4417: a presigned download redirect points at S3_PUBLIC_ENDPOINT (${PUBLIC}) and the object downloads byte-exact from there"
reset_case
send "${BASE}/api/v1/repositories/${REPO}/download/pub/obj.bin" -H "Authorization: Bearer ${TOK}"
LOC="$(grep -i '^location:' "${W}/hdr" | head -1 | sed 's/^[Ll]ocation: *//' | tr -d '\r')"
note "GET download -> ${CODE} Location: ${LOC:0:120}"
case "$CODE" in 302|303|307) ;; *) fail_g "the download answered ${CODE}, expected a presigned redirect";; esac
LOC_ORIGIN="$(sed -E 's#^(https?://[^/]+).*#\1#' <<<"$LOC")"
[ "$LOC_ORIGIN" = "http://${PUBLIC}" ] || fail_g "the redirect origin is '${LOC_ORIGIN}', expected http://${PUBLIC} (S3_PUBLIC_ENDPOINT)"
grep -q 'X-Amz-Signature=' <<<"$LOC" || fail_g "the redirect is not a presigned URL"
if [ -n "$LOC" ]; then
  c="$(curl -s -o "${W}/via-public" -w '%{http_code}' --max-time 30 "$LOC")"
  note "GET <Location> -> ${c}"
  { [ "$c" = "200" ] && cmp -s "${W}/obj.bin" "${W}/via-public"; } || fail_g "following the redirect answered ${c} or the bytes differ (signature not valid for the public host?)"
fi
finish_case "#4417: presigned redirects do not use S3_PUBLIC_ENDPOINT"

# =============================================================================
# #4610: /readyz dependencies and READYZ_REQUIRE_SEARCH.
# =============================================================================
begin_test "CONTROL: /readyz is 200 ready with database and migrations healthy"
reset_case
readyz
note "/readyz -> ${CODE} $(tr -d '\n' <<<"${BODY:0:300}")"
{ [ "$CODE" = "200" ] && [ "$(jqr '.checks.database.status' <<<"$BODY")" = "healthy" ] \
  && [ "$(jqr '.checks.migrations.status' <<<"$BODY")" = "healthy" ]; } || fail_g "/readyz is not 200 with database and migrations healthy"
finish_case "/readyz is not ready on a healthy stack"

begin_test "FIX #4610: /readyz carries dependencies{opensearch,storage,scanner,ldap} with status and required (opensearch required by READYZ_REQUIRE_SEARCH)"
reset_case
for k in opensearch storage scanner ldap; do
  s="$(jqr ".dependencies.${k}.status // empty" <<<"$BODY")"; r="$(jqr ".dependencies.${k}.required" <<<"$BODY")"
  note "dependencies.${k}: status=${s:-absent} required=${r}"
  [ -n "$s" ] || fail_g "dependencies.${k} is absent"
done
[ "$(jqr '.dependencies.opensearch.status' <<<"$BODY")" = "healthy" ] || fail_g "dependencies.opensearch.status is not healthy"
[ "$(jqr '.dependencies.opensearch.required' <<<"$BODY")" = "true" ] || fail_g "dependencies.opensearch.required is not true under READYZ_REQUIRE_SEARCH=true"
[ "$(jqr '.dependencies.storage.status' <<<"$BODY")" = "healthy" ] || fail_g "dependencies.storage.status is not healthy (S3)"
[ "$(jqr '.dependencies.storage.required' <<<"$BODY")" = "false" ] || fail_g "dependencies.storage.required is not false"
[ "$(jqr '.dependencies.scanner.status' <<<"$BODY")" = "not_configured" ] || fail_g "dependencies.scanner.status is not not_configured"
finish_case "#4610: /readyz does not report its dependencies"

begin_test "FIX #4610: with OpenSearch failing and READYZ_REQUIRE_SEARCH=true, /readyz is 503 with failing == [\"opensearch\"]; it recovers when search does"
reset_case
os_mode down
wait_until "/readyz not ready" 20 sh -c "[ \"\$(curl -s -o /dev/null -w '%{http_code}' '${BASE}/readyz')\" = 503 ]"
readyz
note "OpenSearch down: /readyz -> ${CODE} failing=$(jqr '.failing' <<<"$BODY" | tr -d ' \n') opensearch=$(jqr '.dependencies.opensearch.status' <<<"$BODY")"
[ "$CODE" = "503" ] || fail_g "/readyz answered ${CODE} with OpenSearch failing, expected 503"
[ "$(jqr '.failing | join(",")' <<<"$BODY")" = "opensearch" ] || fail_g "failing is '$(jqr '.failing' <<<"$BODY" | tr -d ' \n')', expected [\"opensearch\"]"
[ "$(jqr '.checks.database.status' <<<"$BODY")" = "healthy" ] || fail_g "the database check is not healthy while only search is down"
os_mode up
wait_until "/readyz ready again" 20 sh -c "[ \"\$(curl -s -o /dev/null -w '%{http_code}' '${BASE}/readyz')\" = 200 ]"
readyz
note "OpenSearch back: /readyz -> ${CODE}"
[ "$CODE" = "200" ] || fail_g "/readyz answered ${CODE} after OpenSearch recovered, expected 200"
finish_case "#4610: READYZ_REQUIRE_SEARCH does not gate readiness on OpenSearch"
os_mode up

# =============================================================================
# #4591: SMTP TLS modes (each a backend recreate).
# =============================================================================
# A throwaway CA and a mock-smtp server certificate, made now so no key
# material lives in the repository. The mock loads its pair from
# /tmp/smtp/tls on every TLS connection. The CA reaches the backend two ways,
# both forms SMTP_TLS_CA_CERT accepts: inline PEM text, and a file path on the
# data volume (which survives the backend recreates).
TLS="${W}/tls"; mkdir -p "$TLS"
CA_PEM=""
if openssl req -x509 -newkey rsa:2048 -nodes -keyout "${TLS}/ca.key" -out "${TLS}/ca.crt" -days 2 \
     -subj "/CN=DTF ${RUN_ID} throwaway SMTP CA" -addext "basicConstraints=critical,CA:TRUE" \
     -addext "keyUsage=critical,keyCertSign,cRLSign" >"${TLS}/gen.log" 2>&1 \
   && openssl req -newkey rsa:2048 -nodes -keyout "${TLS}/smtp.key" -out "${TLS}/smtp.csr" -subj "/CN=mock-smtp" >>"${TLS}/gen.log" 2>&1 \
   && printf 'subjectAltName=DNS:mock-smtp\nbasicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n' >"${TLS}/ext" \
   && openssl x509 -req -in "${TLS}/smtp.csr" -CA "${TLS}/ca.crt" -CAkey "${TLS}/ca.key" -CAcreateserial \
     -out "${TLS}/smtp.crt" -days 2 -extfile "${TLS}/ext" >>"${TLS}/gen.log" 2>&1 \
   && chmod 644 "${TLS}/smtp.key" "${TLS}/ca.crt" \
   && docker exec "$SMTP_CTR" mkdir -p /tmp/smtp/tls \
   && docker cp "${TLS}/smtp.crt" "${SMTP_CTR}:/tmp/smtp/tls/smtp.crt" >/dev/null \
   && docker cp "${TLS}/smtp.key" "${SMTP_CTR}:/tmp/smtp/tls/smtp.key" >/dev/null \
   && docker cp "${TLS}/ca.crt" "${BACKEND_CTR}:/data/dtf-smtp-ca.crt" >/dev/null; then
  CA_PEM="$(cat "${TLS}/ca.crt")"
else
  infra_fail "could not generate or install the throwaway SMTP CA: $(tail -3 "${TLS}/gen.log")"; end_suite
fi
CA_FILE=/data/dtf-smtp-ca.crt
begin_test "CONTROL: SMTP_TLS_MODE=starttls against a server without STARTTLS refuses to send (nothing delivered)"
reset_case
variant starttls 25 "" "http://${PUBLIC}"
[ -n "$TOK" ] || fail_g "no admin session after recreating the backend: $(tail -3 "${W}/recreate.log")"
RC="starttls-${SFX}@dtf.test"
smtp_test "$RC"
note "starttls on :25 -> ${CODE} ${BODY:0:200}"
[ "$CODE" = "200" ] && fail_g "the send succeeded although the server offers no STARTTLS"
[ -z "$(smtp_rec "$RC")" ] || fail_g "the mock received a message under starttls without STARTTLS"
finish_case "SMTP_TLS_MODE=starttls sent without STARTTLS"

begin_test "FIX #4591: SMTP_TLS_MODE=starttls-opportunistic sends unencrypted when the server offers no STARTTLS"
reset_case
variant starttls-opportunistic 25 "" "http://${PUBLIC}"
[ -n "$TOK" ] || fail_g "no admin session after recreating the backend: $(tail -3 "${W}/recreate.log")"
RC="opp-${SFX}@dtf.test"
smtp_test "$RC"
note "starttls-opportunistic on :25 -> ${CODE} ${BODY:0:200}"
[ "$CODE" = "200" ] || fail_g "the send answered ${CODE}, expected 200"
rec="$(smtp_rec "$RC")"; note "mock record: ${rec:-none}"
[ "$(jqr '.tls' <<<"$rec")" = "false" ] || fail_g "the mock did not receive the message in plaintext on :25"
finish_case "#4591: starttls-opportunistic does not fall back to plaintext"

begin_test "FIX #4591: SMTP_TLS_MODE=starttls-opportunistic upgrades with STARTTLS when offered (private CA as inline PEM in SMTP_TLS_CA_CERT)"
reset_case
variant starttls-opportunistic 587 "$CA_PEM" "http://${PUBLIC}"
[ -n "$TOK" ] || fail_g "no admin session after recreating the backend: $(tail -3 "${W}/recreate.log")"
RC="opp-tls-${SFX}@dtf.test"
smtp_test "$RC"
note "starttls-opportunistic on :587 -> ${CODE} ${BODY:0:200}"
[ "$CODE" = "200" ] || fail_g "the send answered ${CODE}, expected 200"
rec="$(smtp_rec "$RC")"; note "mock record: ${rec:-none}"
[ "$(jqr '.tls' <<<"$rec")" = "true" ] || fail_g "the message was not delivered over STARTTLS on :587"
finish_case "#4591: starttls-opportunistic does not upgrade when STARTTLS is offered"

begin_test "FIX #4591: SMTP_TLS_MODE=tls with SMTP_TLS_CA_CERT naming the private CA file delivers over implicit TLS"
reset_case
variant tls 465 "$CA_FILE" "http://${PUBLIC}"
[ -n "$TOK" ] || fail_g "no admin session after recreating the backend: $(tail -3 "${W}/recreate.log")"
RC="tls-ca-${SFX}@dtf.test"
smtp_test "$RC"
note "tls on :465 with SMTP_TLS_CA_CERT -> ${CODE} ${BODY:0:200}"
[ "$CODE" = "200" ] || fail_g "the send answered ${CODE}, expected 200"
rec="$(smtp_rec "$RC")"; note "mock record: ${rec:-none}"
{ [ "$(jqr '.tls' <<<"$rec")" = "true" ] && [ "$(jqr '.port' <<<"$rec")" = "465" ]; } || fail_g "the mock did not receive the message over TLS on :465"
finish_case "#4591: SMTP_TLS_CA_CERT is not trusted for SMTP"

begin_test "FIX #4591: without SMTP_TLS_CA_CERT the private-CA server is refused (nothing delivered) and the 502 points at SMTP_TLS_CA_CERT"
reset_case
variant tls 465 "" "http://${PUBLIC}"
[ -n "$TOK" ] || fail_g "no admin session after recreating the backend: $(tail -3 "${W}/recreate.log")"
RC="tls-noca-${SFX}@dtf.test"
smtp_test "$RC"
note "tls on :465 without the CA -> ${CODE} ${BODY:0:300}"
[ "$CODE" = "200" ] && fail_g "the send succeeded against an untrusted certificate"
[ -z "$(smtp_rec "$RC")" ] || fail_g "the mock received a message although the certificate is untrusted"
[ "$CODE" = "502" ] || fail_g "the refusal answered ${CODE}, expected 502"
grep -qi 'certificate' <<<"$BODY" || fail_g "the message does not mention the certificate"
grep -q 'SMTP_TLS_CA_CERT' <<<"$BODY" || fail_g "the hint does not point at SMTP_TLS_CA_CERT"
finish_case "#4591: an untrusted SMTP certificate is not explained"

# =============================================================================
# #4417: a malformed S3_PUBLIC_ENDPOINT aborts startup. Last: it leaves the
# backend down.
# =============================================================================
begin_test "FIX #4417: S3_PUBLIC_ENDPOINT=ftp://x makes the backend exit non-zero at startup, naming the variable"
reset_case
variant none 25 "" "ftp://dtf-bad-endpoint" nowait
state=""; for _ in $(seq 1 45); do
  state="$(docker inspect -f '{{.State.Status}} {{.State.ExitCode}}' "$BACKEND_CTR" 2>/dev/null || true)"
  case "$state" in exited*|dead*) break;; esac
  [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "${BASE}/health")" = "200" ] && break
  sleep 1
done
note "backend state: ${state}"
note "log: $(docker logs "$BACKEND_CTR" 2>&1 | grep -m2 'S3_PUBLIC_ENDPOINT' | cut -c1-220 | tr '\n' '|')"
case "$state" in
  exited\ 0|running*) fail_g "the backend did not exit non-zero with S3_PUBLIC_ENDPOINT=ftp://dtf-bad-endpoint (${state})";;
  exited*) ;;
  *) fail_g "unexpected backend state '${state}'";;
esac
docker logs "$BACKEND_CTR" 2>&1 | grep -q 'S3_PUBLIC_ENDPOINT' || fail_g "the startup error does not name S3_PUBLIC_ENDPOINT"
finish_case "#4417: a malformed S3_PUBLIC_ENDPOINT does not abort startup"

end_suite
