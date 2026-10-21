#!/usr/bin/env bash
# =============================================================================
# tiers/upload-slot-exhaustion/oracle.sh
#   GHSA-9f9r-c4w8-rjv9 (1.11.0, #4588) slow or stalled uploads cannot hold
#         every global request slot:
#         - one principal may hold at most UPLOAD_MAX_IN_FLIGHT_PER_PRINCIPAL
#           uploads; the next is 429 + Retry-After, while another principal's
#           upload still proceeds
#         - an upload body below the progress floor is aborted 408 after
#           UPLOAD_PROGRESS_WINDOW_SECS (generic artifact PUT and Git LFS)
#         - /health, /healthz, /ready, /readyz and /livez are never shed by
#           the global concurrency limit, even when uploads hold all of it
#   #4162 (1.11.0) concurrent anonymous Composer v1 provider lookups no longer
#         deadlock the shared buffered-metadata budget
# See the manifest for the topology and the limits.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH, DTF_DIR.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"
: "${RUN_ID:?}"; : "${DTF_SLOT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

BASE="$BASE_URL"
PORT="${BASE##*:}"
DBC="$DB_CONTAINER"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOLD="${HERE}/fixtures/slot_hold.py"
UPSTREAM="http://172.16.${DTF_SLOT}.72/"   # profiles/upstreams.mock-composer-v1.yml
PER_PRINCIPAL=8      # UPLOAD_MAX_IN_FLIGHT_PER_PRINCIPAL in profiles/limits.upload-slots.yml
GLOBAL=32            # GLOBAL_MAX_CONCURRENCY in the same profile
WINDOW=5             # UPLOAD_PROGRESS_WINDOW_SECS in the same profile
DECLARED=1048576     # Content-Length every held upload declares
RATE=8192            # bytes/s a held upload sends: above the 16 KiB per 5 s floor
USER_PASS='Dtf-slots-Passw0rd!2026'

setup_workdir
W="$WORK_DIR"

jqr(){ jq -r "$1" 2>/dev/null || true; }
psql_q(){ docker exec "$DBC" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]' || true; }
hold(){ python3 -I "$HOLD" "$PORT" "$@" 2>&1 || true; }
stored(){ psql_q "SELECT COUNT(*) FROM artifacts a JOIN repositories r ON r.id = a.repository_id WHERE r.key = '$1' AND a.path = '$2' AND NOT a.is_deleted"; }

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

put_small(){ # <token> <repo> <path> <file> -> http code
  curl -s -o "$W/put.json" -w '%{http_code}' --max-time 20 -X PUT -H "Authorization: Bearer $1" \
    --data-binary @"$4" "$BASE/api/v1/repositories/$2/artifacts/$3" || echo 000
}
statuses(){ jq -r '.status' "$1" 2>/dev/null | sort | uniq -c | awk '{printf "%sx%s ", $2, $1}'; }

# =============================================================================
begin_suite "upload-slot-exhaustion"

begin_test "setup: admin login, generic + Git LFS local repos, public Remote Composer on the v1 mock, four upload users"
if ! command -v python3 >/dev/null 2>&1; then infra_fail "python3 is required for the socket holders"; end_suite; fi
TOK="$(curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"${ADMIN_PASS}\"}" | jqr '.access_token // .token // empty')"
if [ -z "$TOK" ]; then infra_fail "admin login failed at $BASE"; end_suite; fi
SUF="${RUN_ID##*-}-$$"
R_GEN="use-gen-${SUF}"; R_LFS="use-lfs-${SUF}"; R_CMP="use-cmp-${SUF}"
mk(){ # <key> <format> <type> <public> [upstream]
  curl -s -X POST "$BASE/api/v1/repositories" -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
    -d "$(jq -n --arg k "$1" --arg f "$2" --arg t "$3" --argjson p "$4" --arg u "${5:-}" \
      '{key:$k,name:$k,format:$f,repo_type:$t,is_public:$p} + (if $u == "" then {} else {upstream_url:$u} end)')" \
    | jqr '.key // empty'
}
SETUP_ERR=""
[ "$(mk "$R_GEN" generic local false)" = "$R_GEN" ] || SETUP_ERR="${SETUP_ERR} generic"
[ "$(mk "$R_LFS" gitlfs local false)" = "$R_LFS" ] || SETUP_ERR="${SETUP_ERR} gitlfs"
[ "$(mk "$R_CMP" composer remote true "$UPSTREAM")" = "$R_CMP" ] || SETUP_ERR="${SETUP_ERR} composer-remote"
declare -A UTOK
for u in a b c d; do
  name="use-${u}-${SUF}"
  curl -s -o /dev/null -X POST "$BASE/api/v1/users" -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
    -d "$(jq -n --arg n "$name" --arg p "$USER_PASS" '{username:$n,password:$p,email:($n+"@dtf.example"),is_admin:true}')"
  UTOK[$u]="$(curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
    -d "$(jq -n --arg n "$name" --arg p "$USER_PASS" '{username:$n,password:$p}')" | jqr '.access_token // empty')"
  [ -n "${UTOK[$u]}" ] || SETUP_ERR="${SETUP_ERR} user-${u}"
done
if [ -n "$SETUP_ERR" ]; then infra_fail "setup failed:${SETUP_ERR}"; end_suite; fi
echo "-- repos: ${R_GEN}, ${R_LFS}, ${R_CMP} -> ${UPSTREAM}; users use-{a,b,c,d}-${SUF}"
pass

begin_test "CONTROL: a small generic upload is 201 and downloads byte-identical"
reset_case
printf 'dtf-upload-slot-%s' "$SUF" > "$W/small.bin"
code="$(put_small "${UTOK[a]}" "$R_GEN" ctl/small.bin "$W/small.bin")"
note "PUT ctl/small.bin: HTTP ${code}"
[ "$code" = "201" ] || fail_g "small upload answered ${code}: $(head -c 200 "$W/put.json")"
curl -s -o "$W/small.get" -H "Authorization: Bearer $TOK" "$BASE/api/v1/repositories/${R_GEN}/download/ctl/small.bin" || true
cmp -s "$W/small.bin" "$W/small.get" || fail_g "download of ctl/small.bin does not match"
finish_case "a plain upload must work"

begin_test "CONTROL: one anonymous Composer v1 provider lookup through the Remote resolves the package document"
reset_case
code="$(curl -s -o "$W/widget.json" -w '%{http_code}' --max-time 30 "$BASE/composer/${R_CMP}/p/dtf/widget\$0.json" || echo 000)"
note "GET p/dtf/widget\$0.json: HTTP ${code}"
[ "$code" = "200" ] || fail_g "v1 lookup answered ${code}"
[ "$(jqr '.packages["dtf/widget"]["1.0.0"].version // empty' < "$W/widget.json")" = "1.0.0" ] \
  || fail_g "the v1 document does not carry dtf/widget 1.0.0: $(head -c 200 "$W/widget.json")"
finish_case "the v1 provider fallback must resolve against the mock"

# =============================================================================
# GHSA-9f9r: per-principal in-flight cap, with a second principal unaffected
# =============================================================================
begin_test "GHSA-9f9r: with ${PER_PRINCIPAL} uploads held by one user, that user's next upload is 429 + Retry-After and is not stored"
reset_case
hold PUT "/api/v1/repositories/${R_GEN}/artifacts/held-a/{i}.bin" "Bearer ${UTOK[a]}" \
  "$PER_PRINCIPAL" "$DECLARED" "$RATE" 10 "$W/held-a.jsonl" > "$W/held-a.sum" &
HOLD_PID=$!
sleep 2
printf 'ninth' > "$W/ninth.bin"
code="$(curl -s -o "$W/ninth.body" -D "$W/ninth.h" -w '%{http_code}' --max-time 20 -X PUT \
  -H "Authorization: Bearer ${UTOK[a]}" --data-binary @"$W/ninth.bin" \
  "$BASE/api/v1/repositories/${R_GEN}/artifacts/held-a/ninth.bin" || echo 000)"
ra="$(grep -i '^retry-after:' "$W/ninth.h" | cut -d: -f2 | tr -d '[:space:]' || true)"
# The second principal's upload is sent while user a's uploads are still held.
printf 'other-principal' > "$W/other.bin"
code_b="$(put_small "${UTOK[b]}" "$R_GEN" other/b.bin "$W/other.bin")"
wait "$HOLD_PID"
note "held uploads by user a: $(statuses "$W/held-a.jsonl")(none = still sending when released)"
note "upload #$((PER_PRINCIPAL + 1)) by user a: HTTP ${code}, Retry-After=${ra:-<none>}, body: $(head -c 120 "$W/ninth.body")"
note "stored rows for held-a/ninth.bin: $(stored "$R_GEN" held-a/ninth.bin)"
[ "$code" = "429" ] || fail_g "upload #$((PER_PRINCIPAL + 1)) answered ${code}, expected 429"
[ "${ra:-0}" -gt 0 ] 2>/dev/null || fail_g "the 429 carries no positive Retry-After"
[ "$(stored "$R_GEN" held-a/ninth.bin)" = "0" ] || fail_g "the refused upload was stored"
B_CODE="$code_b"
finish_case "one principal must not be able to hold more than its in-flight share"

begin_test "CONTROL: user a's ${PER_PRINCIPAL} held uploads were all admitted, user b's upload in the same window is 201, and user a can upload again once they end"
reset_case
n_admitted="$(jq -r 'select(.status == "none") | .i' "$W/held-a.jsonl" 2>/dev/null | wc -l | tr -d ' ')"
note "held uploads still in flight at release: ${n_admitted}/${PER_PRINCIPAL}; user b during the hold: HTTP ${B_CODE}"
[ "$n_admitted" = "$PER_PRINCIPAL" ] || fail_g "only ${n_admitted} of ${PER_PRINCIPAL} held uploads were admitted ($(statuses "$W/held-a.jsonl"))"
[ "$B_CODE" = "201" ] || fail_g "a second principal's upload during the hold answered ${B_CODE}"
code=000
for _ in 1 2 3 4 5; do
  code="$(put_small "${UTOK[a]}" "$R_GEN" after/a.bin "$W/small.bin")"
  [ "$code" = "201" ] && break
  sleep 1
done
note "user a after the hold: HTTP ${code}"
[ "$code" = "201" ] || fail_g "user a still cannot upload after its held uploads ended (HTTP ${code}): slots leaked"
finish_case "the cap must not affect other principals or outlive the uploads that hold it"

# =============================================================================
# GHSA-9f9r: progress floor
# =============================================================================
begin_test "GHSA-9f9r: an upload trickling 1 byte per 2 s is aborted 408 within ${WINDOW}+5 s on the generic route and on Git LFS, and nothing is stored"
reset_case
OID="$(printf 'dtf-lfs-%s' "$SUF" | sha256sum | awk '{print $1}')"
hold PUT "/api/v1/repositories/${R_GEN}/artifacts/trickle/{i}.bin" "Bearer ${UTOK[b]}" 1 "$DECLARED" 0 20 "$W/trickle-gen.jsonl" >/dev/null &
hold PUT "/lfs/${R_LFS}/objects/${OID}" "Bearer ${UTOK[c]}" 1 "$DECLARED" 0 20 "$W/trickle-lfs.jsonl" >/dev/null &
wait
lim=$((WINDOW + 5))
for f in gen lfs; do
  st="$(jqr '.status' < "$W/trickle-${f}.jsonl")"; secs="$(jqr '.secs' < "$W/trickle-${f}.jsonl")"
  note "${f}: status ${st} after ${secs}s ($(jqr '.sent' < "$W/trickle-${f}.jsonl") bytes sent) $(jqr '.body' < "$W/trickle-${f}.jsonl" | head -c 100)"
  if [ "$st" != "408" ]; then
    fail_g "${f} trickle answered '${st}' within 20 s, expected 408"
  elif ! awk -v s="$secs" -v l="$lim" 'BEGIN{exit !(s <= l)}'; then
    fail_g "${f} trickle took ${secs}s to be refused, expected within ${lim}s"
  fi
done
[ "$(stored "$R_GEN" trickle/0.bin)" = "0" ] || fail_g "the stalled generic upload was stored"
lfs_rows="$(psql_q "SELECT COUNT(*) FROM artifacts a JOIN repositories r ON r.id = a.repository_id WHERE r.key = '${R_LFS}' AND NOT a.is_deleted")"
note "artifact rows in ${R_LFS}: ${lfs_rows}"
[ "$lfs_rows" = "0" ] || fail_g "the stalled LFS object was stored"
finish_case "a stalled upload must release its slot after the progress window"

# =============================================================================
# GHSA-9f9r: probes bypass the global pool
# =============================================================================
# Fill every global slot with progressing uploads from four principals
# (8 each, the per-principal cap), then probe while they are held. The
# measurements are judged by the two cases below.
for u in a b c d; do
  hold PUT "/api/v1/repositories/${R_GEN}/artifacts/fill-${u}/{i}.bin" "Bearer ${UTOK[$u]}" \
    "$PER_PRINCIPAL" "$DECLARED" "$RATE" 14 "$W/fill-${u}.jsonl" >/dev/null &
done
sleep 4
FILL_API="$(curl -s -o "$W/api.json" -w '%{http_code}' --max-time 5 -H "Authorization: Bearer $TOK" "$BASE/api/v1/repositories?per_page=1" || echo 000)"
PROBES=""
for p in /health /healthz /ready /readyz /livez; do
  c="$(curl -s -o "$W/probe${p//\//_}.json" -w '%{http_code}' --max-time 5 "$BASE$p" || echo 000)"
  PROBES="${PROBES} ${p}:${c}"
done
wait
FILL_AFTER="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 -H "Authorization: Bearer $TOK" "$BASE/api/v1/repositories?per_page=1" || echo 000)"

begin_test "CONTROL: ${GLOBAL} progressing uploads from four principals fill the global pool: an ordinary API call is shed 503, and the API recovers once they end"
reset_case
for u in a b c d; do note "fill by user ${u}: $(statuses "$W/fill-${u}.jsonl")(none = still sending when released)"; done
note "during the fill: GET /api/v1/repositories=${FILL_API} ($(jqr '.code // empty' < "$W/api.json")); after: ${FILL_AFTER}"
[ "$FILL_API" = "503" ] || fail_g "an ordinary API call answered ${FILL_API}, expected 503 (the uploads did not fill the ${GLOBAL}-slot pool)"
[ "$FILL_AFTER" = "200" ] || fail_g "the API did not recover after the uploads ended (${FILL_AFTER})"
finish_case "the fill must really hold every global slot for the probe case to mean anything"

begin_test "GHSA-9f9r: while uploads hold every global slot, /health, /healthz, /ready, /readyz and /livez answer 200 with a status"
reset_case
note "probes during the fill:${PROBES}"
for pc in $PROBES; do
  p="${pc%%:*}"; c="${pc##*:}"
  s="$(jqr '.status // empty' < "$W/probe${p//\//_}.json")"
  if [ "$c" != "200" ]; then
    fail_g "${p} answered ${c}: $(head -c 100 "$W/probe${p//\//_}.json")"
  elif [ -z "$s" ]; then
    fail_g "${p} 200 carries no status field"
  fi
done
finish_case "health and readiness probes must never be shed by the global concurrency limit"

# =============================================================================
# #4162: Composer v1 fallback and the shared buffered-metadata budget
# =============================================================================
begin_test "#4162: 8 concurrent anonymous Composer v1 lookups all resolve within 30 s, and a lookup started during them returns within 10 s"
reset_case
for i in $(seq 1 8); do
  ( c="$(curl -s -o "$W/burst.$i.json" -w '%{http_code}:%{time_total}' --max-time 30 \
      "$BASE/composer/${R_CMP}/p/dtf/gadget\$${i}.json" || true)"; echo "${c:-000:30}" > "$W/burst.$i.code" ) &
done
sleep 2
side="$(curl -s -o "$W/side.json" -w '%{http_code}:%{time_total}' --max-time 10 \
  "$BASE/composer/${R_CMP}/p/dtf/widget\$side.json" || true)"
wait
ok=0; codes=""
for i in $(seq 1 8); do
  r="$(cat "$W/burst.$i.code" 2>/dev/null || echo 000:30)"
  codes="${codes} ${r}"
  if [ "${r%%:*}" = "200" ] && [ "$(jqr '.packages["dtf/gadget"]["1.0.0"].version // empty' < "$W/burst.$i.json")" = "1.0.0" ]; then
    ok=$((ok + 1))
  fi
done
note "burst (code:secs):${codes}"
note "lookup during the burst: ${side:-000}"
[ "$ok" = "8" ] || fail_g "${ok}/8 concurrent v1 lookups resolved dtf/gadget within 30 s"
[ "${side%%:*}" = "200" ] || fail_g "a lookup started during the burst did not return within 10 s (${side:-000})"
finish_case "concurrent v1 provider fallbacks must not deadlock the shared metadata budget"

end_suite
