#!/usr/bin/env bash
# shellcheck disable=SC2016  # jq programs use jq $variables, not shell ones
# =============================================================================
# tiers/webhook-response-body-bound/oracle.sh
#   artifact-keeper#6403: a webhook receiver's response body is read and
#   stored up to 4 KiB plus a truncation marker, on the delivery worker, the
#   test endpoint and a manual redelivery, without buffering the rest. See the
#   manifest.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID,
# DTF_SLOT, DTF_DIR, RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"; : "${DTF_SLOT:?}"
: "${RUN_ID:?}"; : "${DB_CONTAINER:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every probe here records its outcome instead.
set +e

BASE="$BASE_URL"
SFX="${RUN_ID##*-}$$"
SFX="${SFX: -8}"
setup_workdir
W="$WORK_DIR"
jqr(){ jq -r "$@" 2>/dev/null || true; }

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

SINK_CTR="ak-dtf${DTF_SLOT}-hook-sink"
SINK_IP="172.16.${DTF_SLOT}.79"
BACKEND_CTR="ak-dtf${DTF_SLOT}-backend"
CAP=4096
BIG=$((64 * 1024 * 1024))
# A stored excerpt is CAP bytes plus a marker of at most this many bytes.
MARKER_MAX=64
# Peak RSS growth the three 64 MiB answers may cost a bounded reader.
RSS_BOUND_KB=$((32 * 1024))

api(){ # <METHOD> <PATH> [JSON]: admin bearer call, sets CODE and BODY.
  local -a ca=(-s -o "${W}/body" -w '%{http_code}' --max-time 120 -X "$1" -H "Authorization: Bearer ${TOK}")
  [ -n "${3:-}" ] && ca+=(-H 'Content-Type: application/json' --data-binary "$3")
  : >"${W}/body"
  CODE="$(curl "${ca[@]}" "${BASE}$2" 2>/dev/null)"
  BODY="$(cat "${W}/body" 2>/dev/null || true)"
}
is_2xx(){ case "$1" in 2??) return 0;; *) return 1;; esac; }
psql_q(){ docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tA -F '|' -c "$1" 2>/dev/null; }
sink_get(){ # <control path>
  docker exec "$SINK_CTR" python3 -c "import urllib.request,sys; sys.stdout.write(urllib.request.urlopen('http://127.0.0.1$1', timeout=10).read().decode())" 2>/dev/null
}
# backend_hwm: the artifact-keeper process's peak resident set (kB), read
# from the host (the image has no shell): /proc/<pid>/status of the process
# `docker top` reports for the backend container, as go-zip-gomod-size-bound.
backend_pid(){ docker top "$BACKEND_CTR" -eo pid,comm 2>/dev/null | awk '$2=="artifact-keeper"{print $1; exit}'; }
backend_hwm(){ awk '/^VmHWM:/{print $2}' "/proc/$(backend_pid)/status" 2>/dev/null; }
mk_hook(){ # <name> <path> <repo-id>: echoes the webhook id
  api POST /api/v1/webhooks "$(jq -nc --arg n "$1" --arg u "http://${SINK_IP}$2" --arg r "$3" \
    '{name:$n,url:$u,events:["artifact_uploaded"],repository_id:$r,enabled:true}')"
  is_2xx "$CODE" && jqr '.id // empty' <<<"$BODY"
}
# The first <n> bytes of the sink's pattern, for comparing a stored excerpt.
pattern(){ python3 -I -c 'import sys; sys.stdout.write(("0123456789abcdef" * 65536)[: int(sys.argv[1])])' "$1"; }
# check_excerpt <what> <text file> <marker regex>: CAP pattern bytes + marker.
check_excerpt(){
  local what="$1" f="$2" re="$3" len
  len="$(wc -c < "$f" | tr -d ' ')"
  note "${what}: ${len} bytes stored, ends '$(tail -c 48 "$f" | tr -d '\n')'"
  [ "$len" -le $((CAP + MARKER_MAX)) ] 2>/dev/null || fail_g "${what}: ${len} bytes kept, want at most ${CAP} + a marker (#6403)"
  cmp -s <(head -c "$CAP" "$f") <(pattern "$CAP") || fail_g "${what}: the first ${CAP} bytes are not the receiver's body"
  [ "$len" -gt "$CAP" ] && tail -c +$((CAP + 1)) "$f" | grep -Eq "^${re}\$" || fail_g "${what}: no truncation marker matching '${re}'"
}

begin_suite "webhook-response-body-bound"

# =============================================================================
begin_test "setup: admin session, a generic repository with seven webhooks on the sink"
TOK="$(curl -s --max-time 15 -X POST "${BASE}/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg u "${ADMIN_USER:-admin}" --arg p "$ADMIN_PASS" '{username:$u,password:$p}')" | jqr '.access_token // empty')"
[ -n "$TOK" ] || { infra_fail "no admin session"; end_suite; }
[ "$(sink_get /__log | jqr 'type')" = "array" ] || { infra_fail "the hook sink does not answer"; end_suite; }
REPO="wrb-${SFX}"
api POST /api/v1/repositories "$(jq -nc --arg k "$REPO" '{key:$k,name:$k,format:"generic",repo_type:"local"}')"
is_2xx "$CODE" || { infra_fail "creating ${REPO} answered ${CODE}: ${BODY:0:200}"; end_suite; }
api GET "/api/v1/repositories/${REPO}"; RID="$(jqr '.id // empty' <<<"$BODY")"
declare -A HOOK PATHS
PATHS=(
  [cl]="/body/cl/${BIG}/${SFX}"
  [close]="/body/close/${BIG}/${SFX}"
  [chunked]="/body/chunked/${BIG}/${SFX}"
  [small]="/hook/small-${SFX}"
  [exactcl]="/body/cl/${CAP}/${SFX}"
  [exactchunked]="/body/chunked/${CAP}/${SFX}"
)
for k in cl close chunked small exactcl exactchunked; do
  HOOK[$k]="$(mk_hook "wrb-${k}-${SFX}" "${PATHS[$k]}" "$RID")"
  [ -n "${HOOK[$k]}" ] || { infra_fail "creating the ${k} webhook answered ${CODE}: ${BODY:0:200}"; end_suite; }
done
# A seventh webhook, for the redelivery, so its row is not the worker's cl row.
PATHS[redeliver]="/body/close/${BIG}/${SFX}-r"
HOOK[redeliver]="$(mk_hook "wrb-redeliver-${SFX}" "${PATHS[redeliver]}" "$RID")"
[ -n "${HOOK[redeliver]}" ] || { infra_fail "creating the redeliver webhook failed"; end_suite; }
pass

# =============================================================================
# The delivery worker
# =============================================================================
HWM0="$(backend_hwm)"
case "$HWM0" in ''|*[!0-9]*) HWM0="" ;; esac
printf 'webhook-response-body-bound %s\n' "$SFX" > "${W}/a.bin"
c="$(curl -s -o /dev/null -w '%{http_code}' --max-time 60 -X PUT -H "Authorization: Bearer ${TOK}" \
  -H 'Content-Type: application/octet-stream' --data-binary "@${W}/a.bin" \
  "${BASE}/api/v1/repositories/${REPO}/artifacts/wrb/a.bin" 2>/dev/null)"
NAMES="'wrb-cl-${SFX}','wrb-close-${SFX}','wrb-chunked-${SFX}','wrb-small-${SFX}','wrb-exactcl-${SFX}','wrb-exactchunked-${SFX}','wrb-redeliver-${SFX}'"
done_n=0
for _ in $(seq 1 60); do
  done_n="$(psql_q "SELECT count(*) FROM webhook_deliveries d JOIN webhooks w ON w.id = d.webhook_id WHERE w.name IN (${NAMES}) AND d.response_status IS NOT NULL")"
  [ "${done_n:-0}" -ge 7 ] 2>/dev/null && break
  sleep 2
done
sleep 2
HWM1="$(backend_hwm)"
case "$HWM1" in ''|*[!0-9]*) HWM1="" ;; esac
# stored <key> <out>: the worker's stored response_body for that webhook
stored(){
  psql_q "SELECT encode(convert_to(coalesce(d.response_body, ''), 'UTF8'), 'base64') FROM webhook_deliveries d JOIN webhooks w ON w.id = d.webhook_id WHERE w.name = 'wrb-$1-${SFX}' ORDER BY d.created_at LIMIT 1" \
    | tr -d '\n' | base64 -d > "$2" 2>/dev/null
}
row(){ psql_q "SELECT d.response_status || ' ' || d.success FROM webhook_deliveries d JOIN webhooks w ON w.id = d.webhook_id WHERE w.name = 'wrb-$1-${SFX}' ORDER BY d.created_at LIMIT 1"; }
SENT="$(sink_get /__sent)"
sent_of(){ jq -r --arg p "$1" '.[$p] // 0' <<<"$SENT" 2>/dev/null || echo 0; }

begin_test "setup: one upload, seven deliveries answered"
note "upload ${c}; ${done_n:-0}/7 deliveries have a response status"
if is_2xx "$c" && [ "${done_n:-0}" -ge 7 ] 2>/dev/null; then pass
else fail "the upload answered ${c}; only ${done_n:-0} of 7 deliveries were answered within 120 s" \
  "$(psql_q "SELECT w.name, d.response_status, d.success, octet_length(d.response_body) FROM webhook_deliveries d JOIN webhooks w ON w.id = d.webhook_id WHERE w.name IN (${NAMES})")"; fi

begin_test "FIX #6403: a 64 MiB answer with Content-Length is stored as 4 KiB plus '[truncated, 4096 of ${BIG} bytes]'"
reset_case
stored cl "${W}/cl.txt"
check_excerpt "worker, Content-Length" "${W}/cl.txt" " \.\.\. \[truncated, ${CAP} of ${BIG} bytes\]"
[ "$(row cl)" = "200 true" ] || fail_g "the delivery row is '$(row cl)', want '200 true' (success is the status code's)"
finish_case "the delivery worker stored the receiver's whole Content-Length body"

for mode in close chunked; do
  begin_test "FIX #6403: a 64 MiB answer framed by ${mode} is stored as 4 KiB plus '[truncated, 4096+ bytes]'"
  reset_case
  stored "$mode" "${W}/${mode}.txt"
  check_excerpt "worker, ${mode}" "${W}/${mode}.txt" " \.\.\. \[truncated, ${CAP}\+ bytes\]"
  [ "$(row "$mode")" = "200 true" ] || fail_g "the delivery row is '$(row "$mode")', want '200 true'"
  finish_case "the delivery worker stored the receiver's whole ${mode} body"
done

begin_test "FIX #6403: the backend stopped reading: the receiver could not write the 64 MiB bodies"
reset_case
for k in cl close chunked; do
  s="$(sent_of "${PATHS[$k]}")"
  note "${k}: the receiver wrote ${s} of ${BIG} bytes"
  [ "${s:-0}" -lt "$BIG" ] 2>/dev/null || fail_g "${k}: the receiver wrote all ${BIG} bytes; the backend read the whole body"
done
finish_case "the backend read the whole oversized receiver body"

begin_test "FIX #6403: the backend's peak RSS grew by less than $((RSS_BOUND_KB / 1024)) MiB over the three 64 MiB answers"
reset_case
note "VmHWM ${HWM0:-?} kB before the upload, ${HWM1:-?} kB after the deliveries (+$(( ${HWM1:-0} - ${HWM0:-0} )) kB)"
if [ -z "$HWM0" ] || [ -z "$HWM1" ]; then fail_g "could not read the backend's VmHWM"
elif [ $((HWM1 - HWM0)) -ge "$RSS_BOUND_KB" ]; then fail_g "peak RSS grew by $(( (HWM1 - HWM0) / 1024 )) MiB: the bodies were buffered"; fi
finish_case "the backend buffered the oversized receiver bodies"

begin_test "CONTROL: a small answer and answers of exactly 4096 bytes are stored verbatim, no marker"
reset_case
stored small "${W}/small.txt"
[ "$(cat "${W}/small.txt")" = '{"ok":true}' ] || fail_g "the small answer was stored as '$(head -c 80 "${W}/small.txt")'"
for k in exactcl exactchunked; do
  stored "$k" "${W}/${k}.txt"
  cmp -s "${W}/${k}.txt" <(pattern "$CAP") || fail_g "${k}: stored $(wc -c < "${W}/${k}.txt" | tr -d ' ') bytes, want the ${CAP}-byte body verbatim ($(tail -c 40 "${W}/${k}.txt"))"
done
for k in small exactcl exactchunked; do [ "$(row "$k")" = "200 true" ] || fail_g "${k}: the row is '$(row "$k")'"; done
finish_case "a body within the cap is not stored verbatim"

# =============================================================================
# The test endpoint and a manual redelivery
# =============================================================================
begin_test "FIX #6403: the test endpoint returns 4 KiB plus the marker for the Content-Length and chunked receivers"
reset_case
for k in cl chunked; do
  api POST "/api/v1/webhooks/${HOOK[$k]}/test"
  jqr '.response_body // ""' <<<"$BODY" | head -c -1 > "${W}/test.${k}.txt" 2>/dev/null || true
  re=" \.\.\. \[truncated, ${CAP}\+ bytes\]"; [ "$k" = cl ] && re=" \.\.\. \[truncated, ${CAP} of ${BIG} bytes\]"
  [ "$CODE" = "200" ] && [ "$(jqr '.status_code' <<<"$BODY")" = "200" ] && [ "$(jqr '.success' <<<"$BODY")" = "true" ] \
    || fail_g "test ${k}: HTTP ${CODE}, status_code $(jqr '.status_code' <<<"$BODY"), success $(jqr '.success' <<<"$BODY")"
  check_excerpt "test endpoint, ${k}" "${W}/test.${k}.txt" "$re"
done
finish_case "the test endpoint returned the receiver's whole body"

begin_test "FIX #6403: a manual redelivery stores 4 KiB plus the marker"
reset_case
DID="$(psql_q "SELECT d.id FROM webhook_deliveries d JOIN webhooks w ON w.id = d.webhook_id WHERE w.name = 'wrb-redeliver-${SFX}' ORDER BY d.created_at LIMIT 1")"
# Redelivery updates the worker's row in place. Blank its body first, so the
# row check below sees only what the redelivery wrote, not the worker's copy.
psql_q "UPDATE webhook_deliveries SET response_body = NULL WHERE id = '${DID}'" >/dev/null
[ -z "$(psql_q "SELECT response_body FROM webhook_deliveries WHERE id = '${DID}'")" ] || fail_g "could not blank the worker's response_body before the redelivery"
api POST "/api/v1/webhooks/${HOOK[redeliver]}/deliveries/${DID}/redeliver"
note "redeliver ${DID:-none}: HTTP ${CODE}, attempts $(jqr '.attempts' <<<"$BODY"), success $(jqr '.success' <<<"$BODY")"
[ "$CODE" = "200" ] && [ "$(jqr '.success' <<<"$BODY")" = "true" ] || fail_g "redeliver answered ${CODE}: ${BODY:0:200}"
jqr '.response_body // ""' <<<"$BODY" | head -c -1 > "${W}/redeliver.resp.txt" 2>/dev/null || true
check_excerpt "redeliver response" "${W}/redeliver.resp.txt" " \.\.\. \[truncated, ${CAP}\+ bytes\]"
stored redeliver "${W}/redeliver.row.txt"
check_excerpt "redeliver row (written by the redelivery)" "${W}/redeliver.row.txt" " \.\.\. \[truncated, ${CAP}\+ bytes\]"
finish_case "a manual redelivery stored the receiver's whole body"

end_suite
