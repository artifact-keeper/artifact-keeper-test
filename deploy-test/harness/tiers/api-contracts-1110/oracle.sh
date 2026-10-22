#!/usr/bin/env bash
# shellcheck disable=SC2016  # jq programs use jq $variables, not shell ones
# =============================================================================
# tiers/api-contracts-1110/oracle.sh
#   Pure-API contracts added or fixed in 1.11.0 that nothing else asserts:
#   #4399/#840 upstream filter, #4400 bundles skeleton, #4401 Ed25519 webhook
#   signing + JWKS, #4402 safetensors metadata, #4405/#3427 artifacts-missing
#   + skip_if_present, #3869 lifecycle enabled:false, #4083 format strings,
#   #4095 + #3977 OpenAPI entries, #3924 409 body on an immutable completion,
#   #3917 storage_backend, #3066 search quarantine_status, #4423 virtual
#   storage usage, #4157 /general 405 + repo_type hosted, #4258 Debian local
#   defaults.
# See the manifest for the gates and which image each case goes red on.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# TRIVY_PORT (the mock receiver's control port), RELEASE_GATE=1,
# JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"; : "${DTF_SLOT:?}"
: "${RUN_ID:?}"; : "${TRIVY_PORT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every probe here records its outcome instead.
set +e

BASE="$BASE_URL"
MOCK="http://127.0.0.1:${TRIVY_PORT}"
# The address the BACKEND reaches the mock at (profiles/webhooks.mock-receiver.yml).
MOCK_IN="http://172.16.${DTF_SLOT}.78"
SFX="${DTF_SLOT}-${RUN_ID##*-}-$$"

setup_workdir
W="$WORK_DIR"

# jqr [jq options] <filter>: jq -r that never fails the oracle.
jqr(){ jq -r "$@" 2>/dev/null || true; }

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

# req <METHOD> <PATH> <TOKEN or -> [JSON body | @file]: sets CODE and BODY.
req(){
  local m="$1" p="$2" t="$3" d="${4:-}"
  local -a ca=(-s -o "${W}/body" -w '%{http_code}' --max-time 60 -X "$m")
  [ "$t" != "-" ] && ca+=(-H "Authorization: Bearer ${t}")
  [ -n "$d" ] && ca+=(-H 'Content-Type: application/json' --data-binary "$d")
  : >"${W}/body"
  CODE="$(curl "${ca[@]}" "${BASE}${p}")"
  BODY="$(cat "${W}/body" 2>/dev/null || true)"
}
# put_file <TOKEN> <PATH> <file>: raw upload, sets CODE and BODY.
put_file(){
  : >"${W}/body"
  CODE="$(curl -s -o "${W}/body" -w '%{http_code}' --max-time 60 -X PUT \
    -H "Authorization: Bearer $1" -H 'Content-Type: application/octet-stream' \
    --data-binary "@$3" "${BASE}$2")"
  BODY="$(cat "${W}/body" 2>/dev/null || true)"
}
mk_repo(){ # <key> <format> <type> [upstream]
  req POST /api/v1/repositories "$TOK" "$(jq -nc --arg k "$1" --arg f "$2" --arg t "$3" --arg u "${4:-}" \
    '{key:$k,name:$k,format:$f,repo_type:$t,is_public:false} + (if $u == "" then {} else {upstream_url:$u} end)')"
}
is_2xx(){ case "$1" in 2??) return 0;; *) return 1;; esac; }
is_denied(){ [ "$1" = "403" ] || [ "$1" = "404" ]; }
sha_of(){ sha256sum "$1" | cut -d' ' -f1; }
mock_log(){ curl -s --max-time 10 "${MOCK}/__log"; }
up_hits(){ mock_log | jq --arg p "/up/$1" '[.[] | select(.path == $p)] | length' 2>/dev/null || echo "?"; }
# b64url <s>: decode unpadded base64url to stdout.
b64url(){ local s; s="$(tr '_-' '/+' <<<"$1")"; while [ $(( ${#s} % 4 )) -ne 0 ]; do s="${s}="; done; base64 -d <<<"$s" 2>/dev/null; }
# last_hook <path>: the newest delivery the receiver saw at <path> (JSON object).
last_hook(){ mock_log | jq -c --arg p "$1" '[.[] | select(.path == $p and .method == "POST")] | last // empty' 2>/dev/null; }

begin_suite "api-contracts-1110"

# =============================================================================
begin_test "setup: admin session, mock receiver up, a plain user, a hosted generic repo with one artifact"
TOK="$(curl -s --max-time 15 -X POST "${BASE}/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg p "$ADMIN_PASS" '{username:"admin",password:$p}')" | jqr '.access_token // empty')"
[ -n "$TOK" ] || { infra_fail "no admin session"; end_suite; }
[ "$(curl -s --max-time 5 "${MOCK}/__readyz")" = "ok" ] || { infra_fail "mock receiver not reachable on ${MOCK} (profiles/webhooks.mock-receiver.yml)"; end_suite; }
U_NAME="ac-user-${SFX}"; U_PASS="AcUser!${SFX}x9Q"
req POST /api/v1/users "$TOK" "$(jq -nc --arg u "$U_NAME" --arg p "$U_PASS" '{username:$u,password:$p,email:"\($u)@example.test"}')"
is_2xx "$CODE" || { infra_fail "creating the plain user answered ${CODE}: ${BODY:0:200}"; end_suite; }
UTOK="$(curl -s --max-time 15 -X POST "${BASE}/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg u "$U_NAME" --arg p "$U_PASS" '{username:$u,password:$p}')" | jqr '.access_token // empty')"
[ -n "$UTOK" ] || { infra_fail "the plain user cannot log in"; end_suite; }
R_GEN="ac-gen-${SFX}"
mk_repo "$R_GEN" generic local
is_2xx "$CODE" || { infra_fail "creating ${R_GEN} answered ${CODE}: ${BODY:0:200}"; end_suite; }
printf 'api-contracts-1110 presence %s\n' "$SFX" > "${W}/p.txt"
P_SHA="$(sha_of "${W}/p.txt")"; P_SIZE="$(wc -c <"${W}/p.txt" | tr -d ' ')"
put_file "$TOK" "/api/v1/repositories/${R_GEN}/artifacts/a/p.txt" "${W}/p.txt"
is_2xx "$CODE" || { infra_fail "uploading a/p.txt answered ${CODE}: ${BODY:0:200}"; end_suite; }
P_ID="$(jqr '.id // empty' <<<"$BODY")"
echo "-- user ${U_NAME}, repo ${R_GEN}, artifact ${P_ID}"
pass

# =============================================================================
# CONTROLS: hold on every image.
# =============================================================================
begin_test "CONTROL: a generic upload round-trips byte-exact and the repository reads back with its key and format"
reset_case
curl -s -o "${W}/p.dl" --max-time 30 -H "Authorization: Bearer ${TOK}" "${BASE}/api/v1/repositories/${R_GEN}/download/a/p.txt"
[ "$(sha_of "${W}/p.dl")" = "$P_SHA" ] || fail_g "download of a/p.txt is not the uploaded bytes"
req GET "/api/v1/repositories/${R_GEN}" "$TOK"
note "GET repo: ${CODE} key=$(jqr .key <<<"$BODY") format=$(jqr .format <<<"$BODY")"
[ "$CODE" = "200" ] && [ "$(jqr .key <<<"$BODY")" = "$R_GEN" ] && [ "$(jqr .format <<<"$BODY")" = "generic" ] || fail_g "repository GET does not carry key/format"
finish_case "basic repository/artifact API broken"

begin_test "CONTROL: an hmac webhook's test delivery carries t= and a v1= HMAC that verifies with its secret, and no v2= token"
reset_case
req POST /api/v1/webhooks "$TOK" "$(jq -nc --arg u "${MOCK_IN}/hook/hmac-${SFX}" '{name:"ac-hmac",url:$u,events:["artifact_uploaded"]}')"
WH_H="$(jqr '.id // empty' <<<"$BODY")"; WH_H_SECRET="$(jqr '.secret // empty' <<<"$BODY")"
note "create hmac webhook: ${CODE} id=${WH_H}"
is_2xx "$CODE" && [ -n "$WH_H" ] && [ -n "$WH_H_SECRET" ] || fail_g "hmac webhook create answered ${CODE}: ${BODY:0:200}"
req POST "/api/v1/webhooks/${WH_H}/test" "$TOK"
note "test delivery: ${CODE} $(jqr -c '{success,status_code}' <<<"$BODY")"
H="$(last_hook "/hook/hmac-${SFX}")"
SIG="$(jqr '.headers["x-artifactkeeper-signature"] // empty' <<<"$H")"
note "X-ArtifactKeeper-Signature: ${SIG:-absent}"
TS="${SIG#t=}"; TS="${TS%%,*}"
V1="$(tr ',' '\n' <<<"$SIG" | sed -n 's/^v1=//p' | head -1)"
jqr '.body_b64' <<<"$H" | base64 -d > "${W}/hmac.body" 2>/dev/null
WANT="$( { printf '%s.' "$TS"; cat "${W}/hmac.body"; } | openssl dgst -sha256 -hmac "$WH_H_SECRET" -r | cut -d' ' -f1)"
[ -n "$V1" ] && [ "$V1" = "$WANT" ] || fail_g "v1= signature ${V1:-absent} does not verify (expected ${WANT})"
case "$SIG" in *v2=*) fail_g "an hmac webhook's delivery carries a v2= token";; esac
finish_case "hmac webhook signing broken"

begin_test "CONTROL: a Remote generic repository fetches an unfiltered path from the mock upstream"
reset_case
R_REM="ac-rem-${SFX}"
mk_repo "$R_REM" generic remote "${MOCK_IN}/up/"
is_2xx "$CODE" || fail_g "creating the remote answered ${CODE}: ${BODY:0:200}"
req GET "/api/v1/repositories/${R_REM}/download/ok/a-${SFX}.bin" "$TOK"
note "GET ok/a: ${CODE} body='${BODY%$'\n'}' upstream hits=$(up_hits "ok/a-${SFX}.bin")"
[ "$CODE" = "200" ] && [ "$BODY" = "upstream:ok/a-${SFX}.bin" ] || fail_g "unfiltered fetch answered ${CODE} '${BODY:0:80}'"
finish_case "Remote proxying broken"

begin_test "CONTROL: a Debian local repository without a debian object is created; chunked upload to a fresh path completes"
reset_case
mk_repo "ac-deb0-${SFX}" debian local
note "debian local, no debian object: ${CODE}"
is_2xx "$CODE" || fail_g "plain Debian local create answered ${CODE}: ${BODY:0:200}"
printf 'fresh chunked %s\n' "$SFX" > "${W}/c.txt"
C_SHA="$(sha_of "${W}/c.txt")"; C_SIZE="$(wc -c <"${W}/c.txt" | tr -d ' ')"
req POST /api/v1/uploads "$TOK" "$(jq -nc --arg r "$R_GEN" --arg s "$C_SHA" --argjson n "$C_SIZE" '{repository_key:$r,artifact_path:"c/fresh.txt",total_size:$n,checksum_sha256:$s}')"
SID="$(jqr '.session_id // empty' <<<"$BODY")"
curl -s -o /dev/null --max-time 30 -X PATCH -H "Authorization: Bearer ${TOK}" -H 'Content-Type: application/octet-stream' \
  -H "Content-Range: bytes 0-$((C_SIZE-1))/${C_SIZE}" --data-binary "@${W}/c.txt" "${BASE}/api/v1/uploads/${SID}"
req PUT "/api/v1/uploads/${SID}/complete" "$TOK"
note "chunked init session=${SID:-none}; complete: ${CODE}"
[ "$CODE" = "200" ] || fail_g "completing a fresh chunked upload answered ${CODE}: ${BODY:0:200}"
finish_case "repository create or chunked upload broken"

begin_test "CONTROL: the OpenAPI document is served and parses"
reset_case
req GET /api/v1/openapi.json "$TOK"
cp "${W}/body" "${W}/openapi.json"
OA_OK=0
[ "$CODE" = "200" ] && jq -e '.paths | length > 0' "${W}/openapi.json" >/dev/null 2>&1 && OA_OK=1
note "openapi.json: ${CODE}, $(jq '.paths | length' "${W}/openapi.json" 2>/dev/null || echo '?') paths"
[ "$OA_OK" = "1" ] || fail_g "openapi.json not served (ENABLE_SWAGGER profile api.swagger)"
finish_case "OpenAPI document not served"

# =============================================================================
# FIX CASES
# =============================================================================
begin_test "#4399/#840: a Remote's upstream filter refuses a non-matching path with 404 and no upstream request; a bad regex is 400"
reset_case
req PUT "/api/v1/repositories/${R_REM}/upstream-filter" "$TOK" '{"include_patterns":["^ok/"]}'
note "PUT filter {include:[^ok/]}: ${CODE} $(jqr -c '{include_patterns,active}' <<<"$BODY")"
[ "$CODE" = "200" ] && [ "$(jqr '.active' <<<"$BODY")" = "true" ] && [ "$(jqr '.include_patterns[0]' <<<"$BODY")" = "^ok/" ] \
  || fail_g "saving the filter answered ${CODE}: ${BODY:0:200}"
req GET "/api/v1/repositories/${R_REM}/upstream-filter" "$TOK"
[ "$CODE" = "200" ] && [ "$(jqr '.include_patterns[0]' <<<"$BODY")" = "^ok/" ] || fail_g "GET filter answered ${CODE}: ${BODY:0:200}"
req GET "/api/v1/repositories/${R_REM}/download/no/b-${SFX}.bin" "$TOK"
HITS="$(up_hits "no/b-${SFX}.bin")"
note "GET no/b (filtered): ${CODE}; upstream hits=${HITS}"
[ "$CODE" = "404" ] || fail_g "filtered path answered ${CODE}, expected 404"
[ "$HITS" = "0" ] || fail_g "filtered path reached the upstream ${HITS} time(s)"
req GET "/api/v1/repositories/${R_REM}/download/ok/c-${SFX}.bin" "$TOK"
note "GET ok/c (admitted): ${CODE}"
[ "$CODE" = "200" ] && [ "$BODY" = "upstream:ok/c-${SFX}.bin" ] || fail_g "admitted path answered ${CODE}"
req PUT "/api/v1/repositories/${R_REM}/upstream-filter" "$TOK" '{"include_patterns":["("]}'
note "PUT filter {include:[\"(\"]}: ${CODE} $(jqr '.message // empty' <<<"$BODY" | head -1)"
{ [ "$CODE" = "400" ] && grep -q 'include_patterns\[0\]' <<<"$BODY"; } || fail_g "invalid regex answered ${CODE}, expected 400 naming include_patterns[0]"
req PUT "/api/v1/repositories/${R_GEN}/upstream-filter" "$TOK" '{"include_patterns":["^x/"]}'
note "PUT filter on a hosted repo: ${CODE}"
[ "$CODE" = "400" ] || fail_g "a filter on a hosted repository answered ${CODE}, expected 400"
req PUT "/api/v1/repositories/${R_REM}/upstream-filter" "$UTOK" '{"include_patterns":[]}'
note "PUT filter as a plain user: ${CODE}"
is_denied "$CODE" || fail_g "a plain user changed the filter (${CODE})"
finish_case "the upstream filter is missing or does not gate upstream contact"

begin_test "#4400: /api/v1/bundles: format description, manifest validation report, 501 exports/imports, admin only"
reset_case
req GET /api/v1/bundles/format "$TOK"
note "GET format: ${CODE} $(jqr -c '{format,container,export_available,import_available}' <<<"$BODY")"
[ "$CODE" = "200" ] && [ "$(jqr .format <<<"$BODY")" = "akbundle" ] && [ "$(jqr .container <<<"$BODY")" = "tar" ] \
  && [ "$(jqr '.layout | index("manifest.json") != null' <<<"$BODY")" = "true" ] || fail_g "format answered ${CODE}: ${BODY:0:200}"
req POST /api/v1/bundles/manifest/validate "$TOK" '{"nope":1}'
note "validate junk: ${CODE} valid=$(jqr .valid <<<"$BODY") problems=$(jqr -c .problems <<<"$BODY")"
[ "$CODE" = "200" ] && [ "$(jqr .valid <<<"$BODY")" = "false" ] && [ "$(jqr '.problems | length' <<<"$BODY")" -ge 1 ] 2>/dev/null \
  && [ "$(jqr '.manifest_sha256 | length' <<<"$BODY")" = "64" ] || fail_g "manifest validation answered ${CODE}: ${BODY:0:200}"
req POST /api/v1/bundles/exports "$TOK" "{\"repository_keys\":[\"${R_GEN}\"]}"
note "POST exports: ${CODE} $(jqr -c '{code,tracking_issue}' <<<"$BODY")"
[ "$CODE" = "501" ] && [ "$(jqr .code <<<"$BODY")" = "NOT_IMPLEMENTED" ] || fail_g "exports answered ${CODE}, expected 501 NOT_IMPLEMENTED"
req POST /api/v1/bundles/exports "$TOK" '{"repository_keys":[]}'
note "POST exports with no repositories: ${CODE}"
[ "$CODE" = "400" ] || fail_g "an empty export request answered ${CODE}, expected 400"
req POST /api/v1/bundles/imports "$TOK"
note "POST imports: ${CODE}"
[ "$CODE" = "501" ] && [ "$(jqr .code <<<"$BODY")" = "NOT_IMPLEMENTED" ] || fail_g "imports answered ${CODE}, expected 501"
req GET /api/v1/bundles/format "$UTOK"
note "GET format as a plain user: ${CODE}"
is_denied "$CODE" || fail_g "a plain user read /bundles/format (${CODE})"
finish_case "the bundles API skeleton is missing or wrong"

begin_test "#4401: an asymmetric webhook delivers v2=<kid>:<sig> + X-ArtifactKeeper-Webhook-Id, verifiable against the anonymous JWKS"
reset_case
req POST /api/v1/webhooks "$TOK" "$(jq -nc --arg u "${MOCK_IN}/hook/asym-${SFX}" '{name:"ac-asym",url:$u,events:["artifact_uploaded"],signing_mode:"asymmetric"}')"
WH_A="$(jqr '.id // empty' <<<"$BODY")"
note "create asymmetric webhook: ${CODE} signing_mode=$(jqr .signing_mode <<<"$BODY")"
is_2xx "$CODE" && [ -n "$WH_A" ] || fail_g "asymmetric webhook create answered ${CODE}"
[ "$(jqr .signing_mode <<<"$BODY")" = "asymmetric" ] || fail_g "create response signing_mode is $(jqr .signing_mode <<<"$BODY")"
req GET "/api/v1/webhooks/${WH_A}" "$TOK"
[ "$(jqr .signing_mode <<<"$BODY")" = "asymmetric" ] || fail_g "GET webhook signing_mode is $(jqr .signing_mode <<<"$BODY")"
req GET "/api/v1/webhooks/${WH_H}" "$TOK"
[ "$(jqr .signing_mode <<<"$BODY")" = "hmac" ] || fail_g "the default webhook's signing_mode is $(jqr .signing_mode <<<"$BODY"), expected hmac"
req GET /api/v1/webhooks/jwks -
cp "${W}/body" "${W}/jwks.json"
note "anonymous GET jwks: ${CODE} $(jq -c '[.keys[]? | {kty,crv,alg,kid}]' "${W}/jwks.json" 2>/dev/null)"
[ "$CODE" = "200" ] && [ "$(jq -r '.keys[0].crv // empty' "${W}/jwks.json" 2>/dev/null)" = "Ed25519" ] || fail_g "jwks answered ${CODE}: ${BODY:0:200}"
req POST "/api/v1/webhooks/${WH_A}/test" "$TOK"
H="$(last_hook "/hook/asym-${SFX}")"
SIG="$(jqr '.headers["x-artifactkeeper-signature"] // empty' <<<"$H")"
HWID="$(jqr '.headers["x-artifactkeeper-webhook-id"] // empty' <<<"$H")"
note "delivery: signature=${SIG:-absent}; webhook-id=${HWID:-absent}"
[ -n "$WH_A" ] && [ "$HWID" = "$WH_A" ] || fail_g "X-ArtifactKeeper-Webhook-Id is '${HWID}', expected ${WH_A}"
case "$SIG" in *v1=*) fail_g "an asymmetric webhook's delivery carries a v1= HMAC token";; esac
TS="${SIG#t=}"; TS="${TS%%,*}"
V2="$(tr ',' '\n' <<<"$SIG" | sed -n 's/^v2=//p' | head -1)"
KID="${V2%%:*}"; S64="${V2#*:}"
X="$(jq -r --arg k "$KID" '.keys[]? | select(.kid == $k) | .x' "${W}/jwks.json" 2>/dev/null)"
VERIFIED=0
if [ -n "$V2" ] && [ -n "$X" ]; then
  # SubjectPublicKeyInfo prefix for an Ed25519 raw key (RFC 8410), written
  # with printf escapes: the gate runners do not ship xxd.
  { printf '\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00'; b64url "$X"; } > "${W}/pub.der"
  b64url "$S64" > "${W}/sig.bin"
  { printf '%s.%s.' "$TS" "$HWID"; jqr '.body_b64' <<<"$H" | base64 -d; } > "${W}/msg.bin"
  openssl pkeyutl -verify -pubin -inkey "${W}/pub.der" -keyform DER -rawin -in "${W}/msg.bin" -sigfile "${W}/sig.bin" >/dev/null 2>&1 && VERIFIED=1
  # A signature over the same body for another webhook id must not verify.
  { printf '%s.%s.' "$TS" "$WH_H"; jqr '.body_b64' <<<"$H" | base64 -d; } > "${W}/msg2.bin"
  if openssl pkeyutl -verify -pubin -inkey "${W}/pub.der" -keyform DER -rawin -in "${W}/msg2.bin" -sigfile "${W}/sig.bin" >/dev/null 2>&1; then
    fail_g "the v2= signature also verifies for another webhook id"
  fi
fi
note "v2 kid=${KID:-absent} in jwks=$([ -n "$X" ] && echo yes || echo no) verified=${VERIFIED}"
[ "$VERIFIED" = "1" ] || fail_g "the v2= Ed25519 signature over <t>.<webhook_id>.<body> did not verify against the JWKS key"
finish_case "asymmetric webhook signing or the JWKS is missing or wrong"

begin_test "#4402: a .safetensors upload to an mlmodel repo records the header summary; a malformed header records safetensors_error"
reset_case
R_ML="ac-ml-${SFX}"
mk_repo "$R_ML" mlmodel local
is_2xx "$CODE" || fail_g "creating the mlmodel repo answered ${CODE}"
python3 -I - "${W}/ok.safetensors" "${W}/bad.safetensors" <<'PY'
import json, struct, sys
h = json.dumps({"w": {"dtype": "F32", "shape": [2, 3], "data_offsets": [0, 24]},
                "b": {"dtype": "F16", "shape": [4], "data_offsets": [24, 32]},
                "__metadata__": {"format": "pt"}}).encode()
open(sys.argv[1], "wb").write(struct.pack("<Q", len(h)) + h + b"\0" * 32)
open(sys.argv[2], "wb").write(struct.pack("<Q", 10**9) + b"{garbage")
PY
put_file "$TOK" "/api/v1/repositories/${R_ML}/artifacts/m/ok.safetensors" "${W}/ok.safetensors"
OK_ID="$(jqr '.id // empty' <<<"$BODY")"; note "upload ok.safetensors: ${CODE}"
is_2xx "$CODE" || fail_g "valid safetensors upload answered ${CODE}"
put_file "$TOK" "/api/v1/repositories/${R_ML}/artifacts/m/bad.safetensors" "${W}/bad.safetensors"
BAD_ID="$(jqr '.id // empty' <<<"$BODY")"; note "upload bad.safetensors: ${CODE}"
is_2xx "$CODE" || fail_g "malformed safetensors upload answered ${CODE} (must still be accepted)"
req GET "/api/v1/artifacts/${OK_ID}/metadata" "$TOK"
ST="$(jqr -c '.metadata.safetensors // empty' <<<"$BODY")"
note "ok metadata: ${CODE} ${ST:0:260}"
[ "$(jqr '.tensors.w.dtype' <<<"$ST")" = "F32" ] && [ "$(jqr -c '.tensors.w.shape' <<<"$ST")" = "[2,3]" ] \
  && [ "$(jqr '.tensors.b.dtype' <<<"$ST")" = "F16" ] && [ "$(jqr '.total_parameters' <<<"$ST")" = "10" ] \
  && [ "$(jqr '.tensor_count' <<<"$ST")" = "2" ] && [ "$(jqr '.tensors_truncated' <<<"$ST")" = "false" ] \
  && [ "$(jqr '.metadata.format' <<<"$ST")" = "pt" ] || fail_g "safetensors summary missing or wrong"
req GET "/api/v1/artifacts/${BAD_ID}/metadata" "$TOK"
note "bad metadata: ${CODE} $(jqr -c '.metadata // empty' <<<"$BODY")"
[ -n "$(jqr '.metadata.safetensors_error // empty' <<<"$BODY")" ] && [ -z "$(jqr '.metadata.safetensors // empty' <<<"$BODY")" ] \
  || fail_g "malformed header did not record safetensors_error"
finish_case "safetensors header metadata not recorded"

begin_test "#4405/#3427: artifacts-missing returns only the missing items with a reason; >1000 is 400; a non-reader gets 404; skip_if_present short-circuits"
reset_case
ZERO="$(printf '%064d' 1)"
req POST "/api/v1/repositories/${R_GEN}/artifacts-missing" "$TOK" \
  "$(jq -nc --arg s "$P_SHA" --arg z "$ZERO" '{items:[{path:"a/p.txt",sha256:$s},{path:"a/p.txt",sha256:$z},{path:"a/none.txt",sha256:$s}]}')"
note "bulk check: ${CODE} $(jqr -c '{checked, missing:[.missing[]?|{path,reason}]}' <<<"$BODY")"
[ "$CODE" = "200" ] && [ "$(jqr .checked <<<"$BODY")" = "3" ] && [ "$(jqr '.missing | length' <<<"$BODY")" = "2" ] \
  && [ "$(jqr '.missing[0].reason' <<<"$BODY")" = "checksum_mismatch" ] && [ "$(jqr '.missing[1].reason' <<<"$BODY")" = "not_found" ] \
  && [ "$(jqr '.missing[1].path' <<<"$BODY")" = "a/none.txt" ] || fail_g "bulk existence check wrong: ${CODE} ${BODY:0:300}"
jq -nc --arg s "$P_SHA" '{items:[range(1001)|{path:"x/\(.)",sha256:$s}]}' > "${W}/big.json"
req POST "/api/v1/repositories/${R_GEN}/artifacts-missing" "$TOK" "@${W}/big.json"
note "1001 items: ${CODE} $(jqr '.message // empty' <<<"$BODY")"
[ "$CODE" = "400" ] || fail_g "1001 items answered ${CODE}, expected 400"
req POST "/api/v1/repositories/${R_GEN}/artifacts-missing" "$UTOK" "$(jq -nc --arg s "$P_SHA" '{items:[{path:"a/p.txt",sha256:$s}]}')"
note "plain user (no read): ${CODE}"
[ "$CODE" = "404" ] || fail_g "a non-reader's bulk check answered ${CODE}, expected 404"
req POST /api/v1/uploads "$TOK" "$(jq -nc --arg r "$R_GEN" --arg s "$P_SHA" --argjson n "$P_SIZE" '{repository_key:$r,artifact_path:"a/p.txt",total_size:$n,checksum_sha256:$s,skip_if_present:true}')"
note "upload init skip_if_present on identical: ${CODE} $(jqr -c '{already_present,artifact_id,session_id}' <<<"$BODY")"
[ "$CODE" = "200" ] && [ "$(jqr .already_present <<<"$BODY")" = "true" ] && [ "$(jqr .artifact_id <<<"$BODY")" = "$P_ID" ] \
  && [ -z "$(jqr '.session_id // empty' <<<"$BODY")" ] || fail_g "skip_if_present did not short-circuit (${CODE})"
finish_case "bulk presence check or skip_if_present missing or wrong"

begin_test "#3869: a lifecycle policy created with enabled:false stays disabled; omitted means enabled"
reset_case
req POST /api/v1/admin/lifecycle "$TOK" "{\"name\":\"ac-off-${SFX}\",\"policy_type\":\"max_age_days\",\"config\":{\"days\":3650},\"enabled\":false}"
LP_OFF="$(jqr '.id // empty' <<<"$BODY")"
note "create enabled:false: ${CODE} enabled=$(jqr .enabled <<<"$BODY")"
[ "$(jqr .enabled <<<"$BODY")" = "false" ] || fail_g "create response enabled=$(jqr .enabled <<<"$BODY")"
row="$(docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "SELECT enabled FROM lifecycle_policies WHERE id = '${LP_OFF}'" 2>/dev/null | tr -d '[:space:]')"
note "lifecycle_policies.enabled row: ${row:-absent}"
[ "$row" = "f" ] || fail_g "stored row enabled=${row:-absent}, expected f"
req POST /api/v1/admin/lifecycle "$TOK" "{\"name\":\"ac-on-${SFX}\",\"policy_type\":\"max_age_days\",\"config\":{\"days\":3650}}"
note "create without enabled: ${CODE} enabled=$(jqr .enabled <<<"$BODY")"
[ "$(jqr .enabled <<<"$BODY")" = "true" ] || fail_g "omitted enabled gave $(jqr .enabled <<<"$BODY")"
finish_case "lifecycle enabled:false ignored at create"

begin_test "#4083: wasm_oci, helm_oci and conda_native round-trip in the repository format string"
reset_case
for f in wasm_oci helm_oci conda_native; do
  k="ac-${f//_/-}-${SFX}"
  mk_repo "$k" "$f" local
  c1="$CODE"; f1="$(jqr .format <<<"$BODY")"
  req GET "/api/v1/repositories/${k}" "$TOK"
  f2="$(jqr .format <<<"$BODY")"
  note "${f}: create ${c1} -> ${f1}; GET -> ${f2}"
  [ "$f1" = "$f" ] && [ "$f2" = "$f" ] || fail_g "${f} reads back as ${f1}/${f2}"
done
finish_case "format strings do not round-trip"

begin_test "#4095/#3977: the OpenAPI document lists proxy-sbom and package-analysis, and promotion operations document 400"
reset_case
if [ "$OA_OK" = "1" ]; then
  for p in '/api/v1/repositories/{key}/security/proxy-sbom' '/api/v1/artifacts/{id}/package-analysis'; do
    has="$(jq --arg p "$p" '.paths | has($p)' "${W}/openapi.json")"
    note "paths[${p}]: ${has}"
    [ "$has" = "true" ] || fail_g "OpenAPI lacks ${p}"
  done
  PROMO="$(jq -c '[.paths | to_entries[] | select(.key | test("^/api/v1/promotion/.*promote$")) | .value | to_entries[] | select(.key == "post") | (.value.responses | has("400"))]' "${W}/openapi.json")"
  note "promotion POST ops documenting 400: ${PROMO}"
  [ "$(jq 'length > 0 and all' <<<"$PROMO")" = "true" ] || fail_g "not every promotion operation documents 400"
else
  fail_g "OpenAPI document unavailable"
fi
finish_case "OpenAPI entries missing"

begin_test "#3924: completing a chunked upload onto an occupied immutable path is 409 {code: CONFLICT}, the session stays open and the bytes are unchanged"
reset_case
printf 'different bytes %s\n' "$SFX" > "${W}/d.txt"
D_SHA="$(sha_of "${W}/d.txt")"; D_SIZE="$(wc -c <"${W}/d.txt" | tr -d ' ')"
req POST /api/v1/uploads "$TOK" "$(jq -nc --arg r "$R_GEN" --arg s "$D_SHA" --argjson n "$D_SIZE" '{repository_key:$r,artifact_path:"a/p.txt",total_size:$n,checksum_sha256:$s}')"
SID="$(jqr '.session_id // empty' <<<"$BODY")"
curl -s -o /dev/null --max-time 30 -X PATCH -H "Authorization: Bearer ${TOK}" -H 'Content-Type: application/octet-stream' \
  -H "Content-Range: bytes 0-$((D_SIZE-1))/${D_SIZE}" --data-binary "@${W}/d.txt" "${BASE}/api/v1/uploads/${SID}"
req PUT "/api/v1/uploads/${SID}/complete" "$TOK"
note "complete onto a/p.txt: ${CODE} ${BODY:0:200}"
[ "$CODE" = "409" ] && [ "$(jqr .code <<<"$BODY")" = "CONFLICT" ] || fail_g "completion answered ${CODE}, expected 409 code CONFLICT"
req GET "/api/v1/uploads/${SID}" "$TOK"
note "session after refusal: ${CODE} status=$(jqr .status <<<"$BODY")"
[ "$(jqr .status <<<"$BODY")" != "completed" ] && [ "$CODE" = "200" ] || fail_g "the refused session is ${CODE}/$(jqr .status <<<"$BODY"), expected still open"
curl -s -o "${W}/p.dl2" --max-time 30 -H "Authorization: Bearer ${TOK}" "${BASE}/api/v1/repositories/${R_GEN}/download/a/p.txt"
[ "$(sha_of "${W}/p.dl2")" = "$P_SHA" ] || fail_g "the stored bytes at a/p.txt changed"
finish_case "immutable completion conflict is not a clean 409"

begin_test "#3917: storage_backend is returned on repository GET and in the listing"
reset_case
req GET "/api/v1/repositories/${R_GEN}" "$TOK"
sb1="$(jqr '.storage_backend // empty' <<<"$BODY")"
req GET "/api/v1/repositories?per_page=200" "$TOK"
sb2="$(jqr --arg k "$R_GEN" '.items[]? | select(.key == $k) | .storage_backend // empty' <<<"$BODY")"
dbv="$(docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "SELECT storage_backend FROM repositories WHERE key = '${R_GEN}'" 2>/dev/null | tr -d '[:space:]')"
note "GET: ${sb1:-absent}; list: ${sb2:-absent}; DB: ${dbv:-?}"
[ -n "$sb1" ] && [ "$sb1" = "$dbv" ] && [ "$sb2" = "$dbv" ] || fail_g "storage_backend not exposed or not the stored value"
finish_case "storage_backend not exposed"

begin_test "#3066: search results carry quarantine_status (quick, advanced, recent)"
reset_case
req GET "/api/v1/search/quick?q=p.txt" "$TOK"
q="$(jqr --arg i "$P_ID" '[.results[]?, .items[]?] | map(select(.id == $i)) | .[0].quarantine_status // empty' <<<"$BODY")"
req GET "/api/v1/search/advanced?query=p.txt" "$TOK"
a="$(jqr --arg i "$P_ID" '[.items[]?] | map(select(.id == $i)) | .[0].quarantine_status // empty' <<<"$BODY")"
req GET "/api/v1/search/recent" "$TOK"
r="$(jqr '[(if type == "array" then .[] else (.items[]?) end)] | map(select(has("quarantine_status") | not)) | length' <<<"$BODY")"
rn="$(jqr '[(if type == "array" then .[] else (.items[]?) end)] | length' <<<"$BODY")"
note "quick: ${q:-absent}; advanced: ${a:-absent}; recent: ${rn} items, ${r} without quarantine_status"
[ "$q" = "not_quarantined" ] || fail_g "quick search item quarantine_status=${q:-absent}"
[ "$a" = "not_quarantined" ] || fail_g "advanced search item quarantine_status=${a:-absent}"
[ "${rn:-0}" -ge 1 ] 2>/dev/null && [ "$r" = "0" ] || fail_g "recent items lack quarantine_status"
finish_case "search results lack quarantine_status"

begin_test "#4423: a virtual reports storage_used_bytes 0 and its members' total in member_storage_used_bytes; non-virtual null"
reset_case
R_VIRT="ac-virt-${SFX}"
mk_repo "$R_VIRT" generic virtual
req POST "/api/v1/repositories/${R_VIRT}/members" "$TOK" "{\"member_key\":\"${R_GEN}\",\"priority\":1}"
is_2xx "$CODE" || fail_g "adding the member answered ${CODE}"
req GET "/api/v1/repositories/${R_GEN}" "$TOK"
MEMB="$(jqr .storage_used_bytes <<<"$BODY")"; MNULL="$(jqr '.member_storage_used_bytes' <<<"$BODY")"
req GET "/api/v1/repositories/${R_VIRT}" "$TOK"
note "hosted: used=${MEMB} member_used=${MNULL}; virtual: $(jqr -c '{storage_used_bytes,member_storage_used_bytes}' <<<"$BODY")"
[ "$(jqr .storage_used_bytes <<<"$BODY")" = "0" ] || fail_g "virtual storage_used_bytes=$(jqr .storage_used_bytes <<<"$BODY"), expected 0"
[ "${MEMB:-0}" -gt 0 ] 2>/dev/null && [ "$(jqr .member_storage_used_bytes <<<"$BODY")" = "$MEMB" ] || fail_g "member_storage_used_bytes is not the member's ${MEMB}"
[ "$MNULL" = "null" ] || fail_g "a hosted repo's member_storage_used_bytes is ${MNULL}, expected null"
finish_case "virtual storage usage not split"

begin_test "#4157: a write on /general is a JSON 405 with Allow: GET, HEAD naming the upload route; repo_type hosted is accepted as local"
reset_case
: >"${W}/h"
CODE="$(curl -s -D "${W}/h" -o "${W}/body" -w '%{http_code}' --max-time 30 -X PUT -H "Authorization: Bearer ${TOK}" \
  --data-binary 'x' "${BASE}/general/${R_GEN}/a/z.txt")"
BODY="$(cat "${W}/body")"
ALLOW="$(grep -i '^allow:' "${W}/h" | cut -d: -f2- | tr -d '\r' | sed 's/^ *//')"
note "PUT /general: ${CODE} Allow='${ALLOW}' body=${BODY:0:200}"
{ [ "$CODE" = "405" ] && [ "$(jqr .code <<<"$BODY")" = "METHOD_NOT_ALLOWED" ] \
  && grep -q "/api/v1/repositories/${R_GEN}/artifacts/a/z.txt" <<<"$BODY"; } || fail_g "PUT /general is not a JSON 405 naming the upload route"
[ "$ALLOW" = "GET, HEAD" ] || fail_g "Allow header is '${ALLOW}'"
mk_repo "ac-hosted-${SFX}" generic hosted
note "repo_type hosted: ${CODE} repo_type=$(jqr .repo_type <<<"$BODY")"
is_2xx "$CODE" && [ "$(jqr .repo_type <<<"$BODY")" = "local" ] || fail_g "repo_type hosted answered ${CODE}: ${BODY:0:200}"
finish_case "/general 405 or repo_type hosted wrong"

begin_test "#4258: a Debian local repository accepts an all-default debian object; a non-empty one is still 400"
reset_case
req POST /api/v1/repositories "$TOK" "{\"key\":\"ac-deb1-${SFX}\",\"name\":\"d\",\"format\":\"debian\",\"repo_type\":\"local\",\"debian\":{\"distribution_paths\":[],\"components\":[],\"architectures\":[]}}"
note "all-default debian object: ${CODE} ${BODY:0:160}"
is_2xx "$CODE" || fail_g "all-default debian object answered ${CODE}"
req POST /api/v1/repositories "$TOK" "{\"key\":\"ac-deb2-${SFX}\",\"name\":\"d\",\"format\":\"debian\",\"repo_type\":\"local\",\"debian\":{\"distribution_paths\":[],\"components\":[\"main\"],\"architectures\":[]}}"
note "non-empty debian object: ${CODE}"
[ "$CODE" = "400" ] || fail_g "non-empty debian object on a local repo answered ${CODE}, expected 400"
finish_case "Debian local all-default payload refused"

end_suite
