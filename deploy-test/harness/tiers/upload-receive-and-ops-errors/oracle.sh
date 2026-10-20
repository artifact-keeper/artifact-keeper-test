#!/usr/bin/env bash
# =============================================================================
# tiers/upload-receive-and-ops-errors/oracle.sh
#   #4609  a publish body cut short is 408 incomplete_body, not 400
#   #4595  Git LFS PUT over MAX_UPLOAD_SIZE is 413 before the body is read
#   #4023  an oversized multipart publish (JetBrains, Swift) is 413, not 400
#   #4591  POST /admin/smtp/test explains failures (502 + EHLO + hint), bounds
#          a silent server at 60 s, and answers a bad recipient with 400
#   #3907  /health storage check never echoes the OS error text
# See the manifest for the gates and which image each case goes red on.
#
# run.sh exported BASE_URL, HTTP_PORT, DB_CONTAINER, ADMIN_PASS, RUN_ID,
# DTF_SLOT, DTF_DIR, RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${HTTP_PORT:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"
: "${DTF_SLOT:?}"; : "${RUN_ID:?}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit. This oracle probes failure paths on purpose
# (curl timeouts, refused sends, a backend that must exit), so every step
# records its outcome through fail_g instead of aborting the suite.
set +e

BASE="$BASE_URL"
FX="${HERE}/fixtures"
BACKEND_CTR="ak-dtf${DTF_SLOT}-backend"
SMTP_CTR="ak-dtf${DTF_SLOT}-mock-smtp"
DATA_VOL="ak-dtf${DTF_SLOT}_data"
SFX="${DTF_SLOT}-${RUN_ID##*-}"
LIMIT=1048576

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

# Root shell on the backend's data volume (the backend image has no shell).
on_data(){ docker run --rm -u 0 --security-opt label=disable -v "${DATA_VOL}:/data" python:3.12-slim sh -c "$1"; }
smtp_mode(){ docker exec "$SMTP_CTR" sh -c "echo $1 > /tmp/smtp/mode"; }
smtp_msgs(){ docker exec "$SMTP_CTR" sh -c 'cat /tmp/smtp/messages.jsonl 2>/dev/null || true' | grep -c "$1" || true; }

# short <METHOD> <PATH> <DECLARED> <SENT> [extra header]: body cut short, then FIN.
short(){
  python3 -I "${FX}/short_body.py" 127.0.0.1 "$HTTP_PORT" "$1" "$2" "$3" "$4" \
    "Authorization: Bearer ${TOK}" "${5:-Content-Type: application/octet-stream}" >"${W}/short" 2>&1
  CODE="$(head -1 "${W}/short")"; BODY="$(tail -n +2 "${W}/short")"
}
# send <curl args...>: CODE / BODY
send(){
  : >"${W}/body"
  CODE="$(curl -s -o "${W}/body" -w '%{http_code}' --max-time 90 "$@")"
  BODY="$(cat "${W}/body" 2>/dev/null || true)"
}
smtp_test(){
  send -X POST "${BASE}/api/v1/admin/smtp/test" -H "Authorization: Bearer ${TOK}" \
    -H 'Content-Type: application/json' -d "$(jq -nc --arg t "$1" '{to:$t}')"
}
health(){ send "${BASE}/health"; STORAGE_MSG="$(jqr '.checks.storage.message // empty' <<<"$BODY")"; }

begin_suite "upload-receive-and-ops-errors"

TOK="$(curl -s --max-time 15 -X POST "${BASE}/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg p "$ADMIN_PASS" '{username:"admin",password:$p}')" | jqr '.access_token // empty')"
[ -n "$TOK" ] || { infra_fail "no admin session"; end_suite; }

declare -A REPO
for f in npm cargo conda gitlfs jetbrains swift generic; do
  REPO[$f]="ur-${f}-${SFX}"
  c="$(curl -s -o "${W}/mk" -w '%{http_code}' --max-time 15 -X POST "${BASE}/api/v1/repositories" \
    -H "Authorization: Bearer ${TOK}" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg k "${REPO[$f]}" --arg f "$f" '{key:$k,name:$k,format:$f,repo_type:"local",is_public:false}')")"
  [ "$c" = "200" ] || [ "$c" = "201" ] || { infra_fail "could not create the ${f} repository (HTTP ${c}: $(head -c 200 "${W}/mk"))"; end_suite; }
done
head -c 2097152 /dev/urandom > "${W}/big.bin"
head -c 4096 /dev/urandom > "${W}/small.bin"
BIG_OID="$(sha256sum "${W}/big.bin" | cut -d' ' -f1)"
SMALL_OID="$(sha256sum "${W}/small.bin" | cut -d' ' -f1)"

# =============================================================================
# #4609: a body shorter than its Content-Length.
# =============================================================================
begin_test "FIX #4609: npm, Cargo and conda publishes whose body ends before Content-Length answer 408 incomplete_body (not 400 'Failed to buffer')"
reset_case
for spec in "PUT /npm/${REPO[npm]}/dtf-short Content-Type: application/json" \
            "PUT /cargo/${REPO[cargo]}/api/v1/crates/new Content-Type: application/octet-stream" \
            "POST /conda/${REPO[conda]}/upload Content-Type: application/octet-stream"; do
  m="${spec%% *}"; rest="${spec#* }"; p="${rest%% *}"; h="${rest#* }"
  short "$m" "$p" 65536 32768 "$h"
  note "${m} ${p} (Content-Length 65536, 32768 sent, FIN) -> ${CODE} ${BODY:0:120}"
  { [ "$CODE" = "408" ] && [ "$(jqr '.code // empty' <<<"$BODY")" = "incomplete_body" ]; } \
    || fail_g "${p} answered ${CODE} (${BODY:0:120}), expected 408 {code: incomplete_body}"
  grep -q 'received 32768 of 65536' <<<"$BODY" || fail_g "${p}: the 408 message does not say how much of the declared body arrived"
done
finish_case "#4609: a cut-short publish body is still reported as a client error other than 408 incomplete_body"

begin_test "CONTROL: a complete but invalid npm or Cargo publish body is still 400 (400 means the package itself is bad)"
reset_case
send -X PUT "${BASE}/npm/${REPO[npm]}/dtf-short" -H "Authorization: Bearer ${TOK}" -H 'Content-Type: application/json' \
  --data-binary '{"name":"dtf-short","versions":'
note "npm complete invalid JSON -> ${CODE} ${BODY:0:100}"
[ "$CODE" = "400" ] || fail_g "npm complete invalid body answered ${CODE}, expected 400"
send -X PUT "${BASE}/cargo/${REPO[cargo]}/api/v1/crates/new" -H "Authorization: Bearer ${TOK}" --data-binary 'garbage-crate'
note "cargo complete invalid body -> ${CODE} ${BODY:0:100}"
[ "$CODE" = "400" ] || fail_g "cargo complete invalid body answered ${CODE}, expected 400"
finish_case "a complete invalid package is no longer a 400"

# =============================================================================
# #4595 / #4023: MAX_UPLOAD_SIZE = 1 MiB.
# =============================================================================
begin_test "CONTROL: MAX_UPLOAD_SIZE is 1 MiB: a 2 MiB raw generic upload is 413 and an under-limit Git LFS object round-trips byte-exact"
reset_case
send -X PUT "${BASE}/api/v1/repositories/${REPO[generic]}/artifacts/big.bin" -H "Authorization: Bearer ${TOK}" --data-binary @"${W}/big.bin"
note "generic PUT 2 MiB -> ${CODE} ${BODY:0:100}"
[ "$CODE" = "413" ] || fail_g "a 2 MiB raw upload answered ${CODE}, expected 413 (is MAX_UPLOAD_SIZE in force?)"
send -X PUT -u "admin:${ADMIN_PASS}" -H 'Content-Type: application/octet-stream' --data-binary @"${W}/small.bin" \
  "${BASE}/lfs/${REPO[gitlfs]}/objects/${SMALL_OID}"
note "LFS PUT 4 KiB -> ${CODE}"
[ "$CODE" = "200" ] || fail_g "an under-limit LFS object answered ${CODE}, expected 200"
c="$(curl -s -o "${W}/lfs-get" -w '%{http_code}' --max-time 15 -u "admin:${ADMIN_PASS}" "${BASE}/lfs/${REPO[gitlfs]}/objects/${SMALL_OID}")"
{ [ "$c" = "200" ] && cmp -s "${W}/small.bin" "${W}/lfs-get"; } || fail_g "the LFS object did not download byte-exact (HTTP ${c})"
finish_case "the 1 MiB upload limit or the LFS round trip is broken"

begin_test "FIX #4595: a Git LFS PUT whose declared Content-Length exceeds MAX_UPLOAD_SIZE is refused 413 on the header, before the body is read, and nothing is stored"
reset_case
# Declared 2 MiB, only 4 KiB sent, then FIN. Refusing on the declared length
# (the #4595 fix) answers 413 without waiting for the body; a server that
# only counts bytes as they stream never reaches the limit here.
lfs_auth="Authorization: Basic $(printf 'admin:%s' "$ADMIN_PASS" | base64 | tr -d '\n')"
python3 -I "${FX}/short_body.py" 127.0.0.1 "$HTTP_PORT" PUT "/lfs/${REPO[gitlfs]}/objects/${BIG_OID}" 2097152 4096 \
  "$lfs_auth" "Content-Type: application/octet-stream" >"${W}/short" 2>&1
CODE="$(head -1 "${W}/short")"; BODY="$(tail -n +2 "${W}/short")"
note "LFS PUT declaring 2 MiB, 4 KiB sent, FIN -> ${CODE} ${BODY:0:120}"
[ "$CODE" = "413" ] || fail_g "the declared-oversize LFS PUT answered ${CODE}, expected 413 before the body is read"
grep -q "Object exceeds the maximum allowed size of ${LIMIT} bytes" <<<"$BODY" || fail_g "the refusal does not name the ${LIMIT}-byte object limit"
send -X PUT -u "admin:${ADMIN_PASS}" -H 'Content-Type: application/octet-stream' --data-binary @"${W}/big.bin" \
  "${BASE}/lfs/${REPO[gitlfs]}/objects/${BIG_OID}"
note "LFS PUT 2 MiB in full -> ${CODE} ${BODY:0:120}"
[ "$CODE" = "413" ] || fail_g "a full 2 MiB LFS object answered ${CODE}, expected 413 under MAX_UPLOAD_SIZE=${LIMIT}"
c="$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 -u "admin:${ADMIN_PASS}" "${BASE}/lfs/${REPO[gitlfs]}/objects/${BIG_OID}")"
note "GET of the refused object -> ${c}"
[ "$c" = "404" ] || fail_g "the refused LFS object is downloadable (HTTP ${c})"
finish_case "#4595: LFS uploads are not bounded by MAX_UPLOAD_SIZE on the declared length"

begin_test "FIX #4023: a 2 MiB multipart JetBrains plugin upload and Swift publish are 413 (one-piece and chunked), not 400 'malformed'"
reset_case
for te in "" "Transfer-Encoding: chunked"; do
  shape="${te:+chunked}"; shape="${shape:-one-piece}"
  send -X POST "${BASE}/jetbrains/${REPO[jetbrains]}/plugin/uploadPlugin" -H "Authorization: Bearer ${TOK}" \
    ${te:+-H "$te"} -F "file=@${W}/big.bin;filename=dtf-plugin.zip"
  note "JetBrains uploadPlugin multipart 2 MiB (${shape}) -> ${CODE} ${BODY:0:100}"
  [ "$CODE" = "413" ] || fail_g "JetBrains ${shape} answered ${CODE}, expected 413"
  send -X PUT "${BASE}/swift/${REPO[swift]}/dtf/pkg${DTF_SLOT}/1.0.0" -H "Authorization: Bearer ${TOK}" \
    -H 'Accept: application/vnd.swift.registry.v1+json' ${te:+-H "$te"} -F "source-archive=@${W}/big.bin;type=application/zip"
  note "Swift publish multipart 2 MiB (${shape}) -> ${CODE} ${BODY:0:100}"
  [ "$CODE" = "413" ] || fail_g "Swift ${shape} answered ${CODE}, expected 413"
done
finish_case "#4023: oversized multipart publishes are not 413"

# =============================================================================
# #4591: SMTP test endpoint against the mock.
# =============================================================================
begin_test "CONTROL: against an accepting SMTP server POST /admin/smtp/test is 200 and the mock receives the message"
reset_case
smtp_mode accept
before="$(smtp_msgs "ok-${SFX}@dtf.test")"
smtp_test "ok-${SFX}@dtf.test"
note "smtp/test (accept) -> ${CODE} ${BODY:0:100}"
{ [ "$CODE" = "200" ] && [ "$(jqr '.success' <<<"$BODY")" = "true" ]; } || fail_g "the SMTP test answered ${CODE}, expected 200 {success: true}"
after="$(smtp_msgs "ok-${SFX}@dtf.test")"
[ "$after" -gt "$before" ] || fail_g "the mock SMTP server recorded no message to ok-${SFX}@dtf.test"
finish_case "SMTP delivery to an accepting server is broken"

begin_test "FIX #4591: an SMTP 535 answers 502 carrying the server's reply, what EHLO advertised and the AUTH hint (not a bare 500)"
reset_case
smtp_mode reject535
smtp_test "rej-${SFX}@dtf.test"
note "smtp/test (535) -> ${CODE} ${BODY:0:300}"
[ "$CODE" = "502" ] || fail_g "the SMTP test answered ${CODE}, expected 502"
MSG="$(jqr '.message // empty' <<<"$BODY")"
grep -q '535' <<<"$MSG" || fail_g "the message does not carry the server's 535 reply"
grep -q 'Authentication unsuccessful' <<<"$MSG" || fail_g "the message does not carry the server's reply text"
grep -q 'server advertised before TLS: no STARTTLS, AUTH PLAIN LOGIN' <<<"$MSG" || fail_g "the message does not list what EHLO advertised"
grep -q 'hint: the server rejected the username or password' <<<"$MSG" || fail_g "the message has no AUTH hint"
smtp_mode accept
finish_case "#4591: an SMTP auth failure is not explained"

begin_test "FIX #4591: an invalid recipient on POST /admin/smtp/test is 400 naming the address (not 500)"
reset_case
smtp_test "not an address"
note "smtp/test {to: 'not an address'} -> ${CODE} ${BODY:0:160}"
[ "$CODE" = "400" ] || fail_g "an invalid recipient answered ${CODE}, expected 400"
grep -q 'invalid recipient address' <<<"$BODY" || fail_g "the 400 does not say the recipient address is invalid"
finish_case "#4591: an invalid recipient is not a 400"

begin_test "FIX #4591: a server that accepts and never speaks fails the send after 60 s with 502 'no SMTP reply within 60s' (the send does not hang)"
reset_case
smtp_mode silent-once
t0="$(date +%s)"
smtp_test "silent-${SFX}@dtf.test"
dt=$(( $(date +%s) - t0 ))
note "smtp/test (silent server) -> ${CODE} after ${dt}s ${BODY:0:200}"
[ "$CODE" = "502" ] || fail_g "the SMTP test against a silent server answered ${CODE} after ${dt}s, expected 502"
grep -q 'no SMTP reply within 60s' <<<"$BODY" || fail_g "the message does not say 'no SMTP reply within 60s'"
grep -q 'hint: ' <<<"$BODY" || fail_g "the message has no hint"
{ [ "$dt" -ge 55 ] && [ "$dt" -le 85 ]; } || fail_g "the send took ${dt}s, expected about 60 s"
smtp_mode accept
finish_case "#4591: a silent SMTP server is not bounded at 60 s"

# =============================================================================
# #3907: /health storage message.
# =============================================================================
restore_storage(){
  on_data '[ -d /data/storage.dtf-away ] || exit 0; rm -rf /data/storage; mv /data/storage.dtf-away /data/storage' >/dev/null 2>&1 || true
}
add_exit_handler restore_storage

begin_test "FIX #3907: with the storage path missing or unwritable, /health reports exactly 'Storage path not accessible' / 'Storage write failed' with no OS error text"
reset_case
if ! on_data 'mv /data/storage /data/storage.dtf-away' >"${W}/mv.log" 2>&1; then
  fail_g "could not move the storage directory aside: $(tail -2 "${W}/mv.log")"
else
  wait_until "storage reported unhealthy (missing)" 20 sh -c "curl -s '${BASE}/health' | grep -q 'Storage path not accessible'"
  health
  note "storage dir missing: /health -> ${CODE} storage.message='${STORAGE_MSG}'"
  [ "$STORAGE_MSG" = "Storage path not accessible" ] || fail_g "missing storage path: message is '${STORAGE_MSG}', expected exactly 'Storage path not accessible'"
  grep -qi 'os error\|No such file' <<<"$BODY" && fail_g "the /health body carries OS error text"
  on_data 'mkdir /data/storage && chown 1001 /data/storage && chmod 000 /data/storage' >/dev/null 2>&1 || fail_g "could not create an unwritable storage directory"
  wait_until "storage reported unhealthy (unwritable)" 20 sh -c "curl -s '${BASE}/health' | grep -q 'Storage write failed'"
  health
  note "storage dir unwritable: /health -> ${CODE} storage.message='${STORAGE_MSG}'"
  [ "$STORAGE_MSG" = "Storage write failed" ] || fail_g "unwritable storage: message is '${STORAGE_MSG}', expected exactly 'Storage write failed'"
  grep -qi 'os error\|Permission denied' <<<"$BODY" && fail_g "the /health body carries OS error text"
  if docker logs "$BACKEND_CTR" 2>&1 | grep -q 'Storage write failed.*Permission denied'; then
    note "the OS error is in the backend log (server side)"
  else
    note "the OS error text was not found in the backend log (informational)"
  fi
fi
restore_storage
finish_case "#3907: the health payload echoes the raw storage error"

begin_test "CONTROL: with the storage directory restored, /health storage is healthy with no message"
reset_case
wait_until "storage healthy again" 30 sh -c "curl -s '${BASE}/health' | jq -e '.checks.storage.status == \"healthy\"'"
health
note "/health -> ${CODE} storage=$(jqr '.checks.storage' <<<"$BODY" | tr -d ' \n')"
{ [ "$CODE" = "200" ] && [ "$(jqr '.checks.storage.status' <<<"$BODY")" = "healthy" ] && [ -z "$STORAGE_MSG" ]; } \
  || fail_g "/health did not recover (HTTP ${CODE}, storage message '${STORAGE_MSG}')"
finish_case "storage health does not recover"

end_suite
