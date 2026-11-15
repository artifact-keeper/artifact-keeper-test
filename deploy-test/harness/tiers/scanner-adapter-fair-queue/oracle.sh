#!/usr/bin/env bash
# =============================================================================
# tiers/scanner-adapter-fair-queue/oracle.sh
#   #5944 the scanner adapter shared by several Artifact Keeper instances or
#         clients: per-client limits (SCANNER_CLIENT_LIMITS_FILE), weighted
#         fair queueing, a background priority band and queue metrics
#         (SCANNER_METRICS_ADDR)
# See the manifest for the gates.
#
# Everything goes through the adapter's own HTTP API on 127.0.0.1:$TRIVY_PORT.
# The images live in a stdlib mock registry (fixtures/ocireg.py) reachable from
# the adapter as http://dtf-rega:5000 and http://dtf-regb:5000: two registry
# hosts, so two clients of the adapter. A repository named .../hold-<x> holds
# its manifest until the oracle releases it, so a scan keeps its slot for as
# long as the oracle wants; /tmp/arrivals in the registry records the order in
# which scans reached it (= the order they were given a slot).
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# DTF_DIR, TRIVY_PORT (the adapter's published port), RELEASE_GATE=1,
# JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"; : "${DTF_DIR:?}"
: "${TRIVY_PORT:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every probe below judges its own result.
set +e

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FX="${HERE}/fixtures"
PROJECT="ak-dtf${DTF_SLOT}"
ADAPTER="ak-dtf${DTF_SLOT}-trivy"
ADAPTER_URL="http://127.0.0.1:${TRIVY_PORT}"
REG="ak-dtf${DTF_SLOT}-fqreg"
NET="ak-dtf${DTF_SLOT}-net"
FILES=(-f "${DTF_DIR}/compose.base.yml" -f "${DTF_DIR}/profiles/storage.filesystem.yml"
       -f "${DTF_DIR}/profiles/scanners.trivy.yml" -f "${FX}/fair-queue.yml")
REPORT_ACCEPT='application/vnd.security.vulnerability.report; version=1.1'
WINDOW=10         # seconds a queued scan must stay queued (not reach the registry)
ARRIVE_WAIT=120   # seconds for a scan given a slot to reach the registry
QUEUE_WAIT=20     # seconds for a submitted scan to report Queued
DONE_WAIT=240     # seconds for a released scan to finish

setup_workdir
W="$WORK_DIR"
require_cmd python3

cleanup(){ docker rm -f "$REG" >/dev/null 2>&1 || true; }
trap cleanup EXIT

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; CASE_REPOS=(); [ -z "$CFG_ERR" ] || fail_g "$CFG_ERR"; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

CFG_ERR=""
CASE_REPOS=()
declare -A JOB=()

# ---------------------------------------------------------------- adapter ----
adapter_ready(){ curl -sf --max-time 5 "${ADAPTER_URL}/probe/ready" >/dev/null 2>&1; }
wait_adapter_ready(){ local t=0; while [ "$t" -lt 180 ] && ! adapter_ready; do sleep 1; t=$((t+1)); done; adapter_ready; }
adapter_env(){ docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$ADAPTER" 2>/dev/null | grep "^$1=" | cut -d= -f2-; }

# configure <slots> <limits file under fixtures/ or ""> <metrics addr or "">:
# recreate the adapter once for the cases that follow. Sets CFG_ERR.
configure(){
  local slots="$1" limits="${2:+/dtf-fq/$2}" maddr="$3"
  echo "== adapter: SCANNER_MAX_CONCURRENT_SCANS=${slots} SCANNER_CLIENT_LIMITS_FILE=${limits:-<unset>} SCANNER_METRICS_ADDR=${maddr:-<unset>}"
  CFG_ERR=""
  if ! DTF_FQ_SLOTS="$slots" DTF_FQ_LIMITS="$limits" DTF_FQ_METRICS_ADDR="$maddr" DTF_FQ_FIXTURES="$FX" \
      docker compose -p "$PROJECT" "${FILES[@]}" up -d --no-deps --force-recreate --wait trivy \
      >"${W}/up-trivy.log" 2>&1; then
    CFG_ERR="recreate the adapter (slots ${slots}, limits ${limits:-none}): $(tail -3 "${W}/up-trivy.log" | tr '\n' ' ' | head -c 300)"
    return
  fi
  wait_adapter_ready || { CFG_ERR="adapter not ready within 180s of the recreate"; return; }
  [ "$(adapter_env SCANNER_MAX_CONCURRENT_SCANS)" = "$slots" ] || CFG_ERR="adapter does not carry SCANNER_MAX_CONCURRENT_SCANS=${slots}"
  [ "$(adapter_env SCANNER_CLIENT_LIMITS_FILE)" = "$limits" ] || CFG_ERR="adapter does not carry SCANNER_CLIENT_LIMITS_FILE=${limits}"
}

# submit <host> <repo> [priority]: POST a scan of <host>/<repo>:v1. Sets
# SUB_CODE and JOB[<repo>].
submit(){
  local host="$1" repo="$2" prio="${3:-}" body
  body="{\"registry\":{\"url\":\"http://${host}:5000\"},\"artifact\":{\"repository\":\"${repo}\",\"tag\":\"v1\",\"mime_type\":\"application/vnd.oci.image.manifest.v1+json\"}"
  [ -n "$prio" ] && body="${body},\"priority\":\"${prio}\""
  body="${body}}"
  SUB_CODE="$(curl -s --max-time 15 -o "$W/submit.out" -w '%{http_code}' -X POST \
    -H 'Content-Type: application/json' -d "$body" "${ADAPTER_URL}/api/v1/scan" 2>/dev/null)" || SUB_CODE=000
  JOB[$repo]="$(jq -r '.id // empty' "$W/submit.out" 2>/dev/null)"
  CASE_REPOS+=("$repo")
}
# state <repo>: 200, 500, 302:<X-Scan-Status>, or the HTTP code
state(){
  local id="${JOB[$1]:-}" code st
  [ -n "$id" ] || { echo none; return; }
  code="$(curl -s --max-time 15 -o "$W/report.out" -D "$W/report.hdr" -w '%{http_code}' \
    -H "Accept: ${REPORT_ACCEPT}" "${ADAPTER_URL}/api/v1/scan/${id}/report" 2>/dev/null)" || code=000
  if [ "$code" = 302 ]; then
    st="$(grep -i '^x-scan-status:' "$W/report.hdr" | head -1 | cut -d: -f2- | tr -d ' \r')"
    echo "302:${st}"
  else
    echo "$code"
  fi
}
# wait_state <repo> <want> <timeout>
wait_state(){
  local end=$((SECONDS + $3))
  while [ "$SECONDS" -lt "$end" ]; do
    [ "$(state "$1")" = "$2" ] && return 0
    sleep 0.5
  done
  [ "$(state "$1")" = "$2" ]
}
wait_done(){ # <repo> <timeout seconds>
  local end=$((SECONDS + $2)) s
  while [ "$SECONDS" -lt "$end" ]; do
    s="$(state "$1")"; case "$s" in 200|500|404|none) return 0 ;; esac
    sleep 1
  done
  return 1
}
# submit_queued <host> <repo> [priority]: submit and wait until it is Queued
# (or QUEUE_WAIT passes); echoes nothing, sets SUB_STATE.
submit_queued(){
  submit "$@"
  wait_state "$2" "302:Queued" "$QUEUE_WAIT"
  SUB_STATE="$(state "$2")"
  # The job is marked Queued just before it waits for its slot.
  sleep 0.5
}

# --------------------------------------------------------------- registry ----
arrivals(){ docker exec "$REG" cat /tmp/arrivals 2>/dev/null; }
arrived(){ arrivals | awk -v r="$1" '$3==r' | grep -c . ; }
wait_arrived(){ # <repo> <timeout>
  local end=$((SECONDS + $2))
  while [ "$SECONDS" -lt "$end" ]; do
    [ "$(arrived "$1")" -ge 1 ] && return 0
    sleep 0.5
  done
  [ "$(arrived "$1")" -ge 1 ]
}
release(){ docker exec "$REG" touch "/tmp/release/${1//\//__}" >/dev/null 2>&1; }
# arrival_order <prefix>: the scans of <prefix>/ in the order they reached the
# registry, as "<label>@<host>" (label = the repo name after "hold-")
arrival_order(){
  arrivals | awk -v p="$1/" 'index($3,p)==1 {sub(/^.*\/hold-/,"",$3); h=$2; sub(/:5000$/,"",h); sub(/^dtf-/,"",h); printf "%s@%s ", $3, h}' | sed 's/ $//'
}
# drain_in_order <prefix> <n>: release each scan of <prefix>/ as it reaches
# the registry, until <n> have. Sets ORDER (labels in arrival order).
drain_in_order(){
  local p="$1" n="$2" seen=0 cnt last="$SECONDS" r
  local -A done_r=()
  while :; do
    cnt=0
    while read -r r; do
      [ -n "$r" ] || continue
      cnt=$((cnt+1))
      if [ -z "${done_r[$r]:-}" ]; then release "$r"; done_r[$r]=1; fi
    done < <(arrivals | awk -v p="$p/" 'index($3,p)==1 {print $3}')
    [ "$cnt" -ge "$n" ] && break
    if [ "$cnt" -gt "$seen" ]; then seen="$cnt"; last="$SECONDS"; fi
    [ $((SECONDS - last)) -ge "$ARRIVE_WAIT" ] && break
    sleep 0.5
  done
  ORDER="$(arrival_order "$p" | sed 's/@[a-z]*//g')"
}
# end_case_scans: release every hold of this case and wait for its scans to
# finish, so nothing occupies a slot in the next case.
end_case_scans(){
  local r
  for r in "${CASE_REPOS[@]}"; do release "$r"; done
  for r in "${CASE_REPOS[@]}"; do
    wait_done "$r" "$DONE_WAIT" || fail_g "scan of ${r} still $(state "$r") ${DONE_WAIT}s after its release"
  done
}
not_started(){ # <repo>: 0 when the scan has not reached the registry and reports Queued
  local a s
  a="$(arrived "$1")"; s="$(state "$1")"
  note "${1}: reached the registry ${a} time(s), report ${s}"
  [ "$a" = 0 ] && [ "$s" = "302:Queued" ]
}

# ---------------------------------------------------------------- metrics ----
metrics(){ docker exec "$ADAPTER" wget -qO- -T 5 http://127.0.0.1:9090/metrics 2>/dev/null; }
mval(){ printf '%s\n' "$2" | awk -v m="$1" '$1==m {print $2; exit}'; }
# wait_metrics <timeout> <want: name=value ...>: poll until every series reads
# its value. Sets MSNAP (the last scrape, the series asked for).
wait_metrics(){
  local end=$((SECONDS + $1)) ok kv out; shift
  while :; do
    out="$(metrics)"; ok=1; MSNAP=""
    for kv in "$@"; do
      MSNAP="${MSNAP}${kv%=*}=$(mval "${kv%=*}" "$out") "
      [ "$(mval "${kv%=*}" "$out")" = "${kv##*=}" ] || ok=0
    done
    [ "$ok" = 1 ] && return 0
    [ "$SECONDS" -ge "$end" ] && return 1
    sleep 1
  done
}

begin_suite "scanner-adapter-fair-queue"

# =============================================================================
begin_test "setup: mock registry with two client hosts, held and plain images, warm Trivy DB"
reset_case
mkdir -p "$W/regdata"
REPOS="c1/hold-a1 c1/hold-a2 c1/hold-a3 c1/hold-b1
       m1/hold-a1 m1/hold-a2 m1/hold-a3 m1/hold-g1 m1/hold-b1
       f1/hold-a1 f1/hold-a2 f1/hold-a3 f1/hold-a4 f1/hold-a5 f1/hold-a6 f1/hold-b1
       p1/hold-a1 p1/hold-g1 p1/hold-a2
       o1/hold-a1 o1/hold-a2 o1/hold-a3 o1/hold-b1 o2/plain"
for r in $REPOS; do
  python3 -I "$FX/mkimage.py" "$W/regdata" "$r" v1 >/dev/null || fail_g "mkimage ${r} failed"
done
docker rm -f "$REG" >/dev/null 2>&1
docker run -d --name "$REG" --network "$NET" --network-alias dtf-rega --network-alias dtf-regb \
  --security-opt label=disable -v "$FX/ocireg.py:/app/ocireg.py:ro" python:3.12-slim \
  python3 /app/ocireg.py >/dev/null 2>"$W/reg.err" || fail_g "start the mock registry: $(head -c 300 "$W/reg.err")"
docker cp "$W/regdata" "${REG}:/data" >/dev/null 2>&1 || fail_g "copy the images into the mock registry"
up=0
for _ in $(seq 1 30); do
  docker exec "$REG" python3 -c 'import urllib.request;urllib.request.urlopen("http://127.0.0.1:5000/v2/")' >/dev/null 2>&1 && { up=1; break; }
  sleep 1
done
[ "$up" = 1 ] || fail_g "mock registry not answering on :5000"
warmed=0
for attempt in 1 2 3 4 5; do
  if docker exec "$ADAPTER" sh -c 'trivy image --cache-dir "${SCANNER_TRIVY_CACHE_DIR:-/home/scanner/.cache/trivy}" --download-db-only' >/dev/null 2>&1; then
    warmed=1; break
  fi
  echo "   DB warm attempt ${attempt}/5 failed; retrying in 5s"; sleep 5
done
[ "$warmed" = 1 ] || fail_g "could not download the Trivy DB in ${ADAPTER} (ghcr.io/aquasecurity/trivy-db)"
finish_case "setup failed"
[ "$FAILS" -eq 0 ] || { cleanup; end_suite; }

# =============================================================================
# Configuration 1: 4 global slots, dtf-rega:5000 capped at 1, metrics on :9090
configure 4 limits-cap.json :9090

# =============================================================================
begin_test "FIX #5944: a client capped at max_concurrent 1 stays at its cap while global slots are free; a release starts exactly its next scan"
reset_case
submit dtf-rega c1/hold-a1; c1="$SUB_CODE"
wait_arrived c1/hold-a1 "$ARRIVE_WAIT" || fail_g "A's first scan (POST -> ${c1}) never reached the registry"
submit_queued dtf-rega c1/hold-a2; note "A2: POST -> ${SUB_CODE}, ${SUB_STATE}"
submit_queued dtf-rega c1/hold-a3; note "A3: POST -> ${SUB_CODE}, ${SUB_STATE}"
submit dtf-regb c1/hold-b1
wait_arrived c1/hold-b1 "$ARRIVE_WAIT" || fail_g "client B's scan did not start although 2 of 4 global slots were free"
sleep "$WINDOW"
note "arrivals with A1 holding its slot: $(arrival_order c1)"
not_started c1/hold-a2 || fail_g "A2 started while A1 holds A's only slot (cap 1, global slots free); pre-fix every scan starts while global slots are free"
not_started c1/hold-a3 || fail_g "A3 started while A1 holds A's only slot"
release c1/hold-a1
wait_arrived c1/hold-a2 "$ARRIVE_WAIT" || fail_g "releasing A1 did not start A2 within ${ARRIVE_WAIT}s"
sleep "$WINDOW"
not_started c1/hold-a3 || fail_g "releasing A1 started more than one of A's queued scans"
release c1/hold-a2
wait_arrived c1/hold-a3 "$ARRIVE_WAIT" || fail_g "releasing A2 did not start A3 within ${ARRIVE_WAIT}s"
note "arrival order: $(arrival_order c1)"
end_case_scans
finish_case "the per-client cap in SCANNER_CLIENT_LIMITS_FILE is not enforced"

# =============================================================================
begin_test "FIX #5944: the metrics listener reports queued (by band), running and slot capacity, and reads zero after the queue drains"
reset_case
submit dtf-rega m1/hold-a1
wait_arrived m1/hold-a1 "$ARRIVE_WAIT" || fail_g "A1 never reached the registry"
submit_queued dtf-rega m1/hold-a2
submit_queued dtf-rega m1/hold-a3
submit_queued dtf-rega m1/hold-g1 background; note "A background scan: POST -> ${SUB_CODE}, ${SUB_STATE}"
submit dtf-regb m1/hold-b1
wait_arrived m1/hold-b1 "$ARRIVE_WAIT" || fail_g "B1 never reached the registry"
if [ -z "$(metrics)" ]; then
  fail_g "no metrics on SCANNER_METRICS_ADDR=:9090 (GET http://127.0.0.1:9090/metrics inside the adapter); pre-fix the adapter has no metrics listener"
else
  wait_metrics 30 'scanner_adapter_jobs_queued{priority="interactive"}=2' 'scanner_adapter_jobs_queued{priority="background"}=1' \
    scanner_adapter_jobs_running=2 scanner_adapter_slots_capacity=4 \
    || fail_g "with A1 and B1 holding slots, A2, A3 and A's background scan queued: expected queued interactive 2, background 1, running 2, capacity 4"
  note "held: ${MSNAP}"
fi
end_case_scans
if [ -n "$(metrics)" ]; then
  wait_metrics 30 'scanner_adapter_jobs_queued{priority="interactive"}=0' 'scanner_adapter_jobs_queued{priority="background"}=0' \
    scanner_adapter_jobs_running=0 || fail_g "after every scan finished the queue gauges do not read 0"
  note "drained: ${MSNAP}"
  note "$(metrics | grep -E '^scanner_adapter_(jobs_total|queue_wait_seconds_count)' | tr '\n' ' ')"
fi
finish_case "the adapter does not report its queue"

# =============================================================================
# Configuration 2: 1 global slot, a limits file with only a default entry
configure 1 limits-default.json ""

# =============================================================================
begin_test "FIX #5944: a second client's scan is not starved behind the first client's backlog (fair queueing, FIFO within a client)"
reset_case
submit dtf-rega f1/hold-a1
wait_arrived f1/hold-a1 "$ARRIVE_WAIT" || fail_g "A1 never reached the registry"
for i in 2 3 4 5 6; do
  submit_queued dtf-rega "f1/hold-a$i"
  [ "$SUB_STATE" = "302:Queued" ] || fail_g "A${i}: ${SUB_STATE}, expected Queued behind A1 (1 global slot)"
done
submit_queued dtf-regb f1/hold-b1
[ "$SUB_STATE" = "302:Queued" ] || fail_g "B1: ${SUB_STATE}, expected Queued"
drain_in_order f1 7
note "start order (A queued 6, then B 1): ${ORDER}"
pos=0; i=0
for l in $ORDER; do i=$((i+1)); [ "$l" = b1 ] && pos=$i; done
[ "$pos" -ge 1 ] && [ "$pos" -le 3 ] || fail_g "B1 started at position ${pos:-never} of 7, expected within the first 3 (pre-fix: 7th, after A's whole backlog)"
a_order="$(echo "$ORDER" | tr ' ' '\n' | grep '^a' | tr '\n' ' ' | sed 's/ $//')"
[ "$a_order" = "a1 a2 a3 a4 a5 a6" ] || fail_g "A's scans started as '${a_order}', expected FIFO a1..a6"
end_case_scans
finish_case "a client's backlog starves another client"

# =============================================================================
begin_test "FIX #5944: a queued background-priority scan yields to an interactive scan queued after it"
reset_case
submit dtf-rega p1/hold-a1
wait_arrived p1/hold-a1 "$ARRIVE_WAIT" || fail_g "A1 never reached the registry"
submit_queued dtf-regb p1/hold-g1 background
bg_code="$SUB_CODE"; note "background scan (client B): POST with \"priority\":\"background\" -> ${bg_code}, ${SUB_STATE}"
[ "$bg_code" = 202 ] || fail_g "the background scan was refused (${bg_code}: $(head -c 200 "$W/submit.out"))"
submit_queued dtf-rega p1/hold-a2
note "interactive scan (client A) queued after it: ${SUB_STATE}"
drain_in_order p1 3
note "start order: ${ORDER}"
[ "$ORDER" = "a1 a2 g1" ] || fail_g "start order '${ORDER}', expected 'a1 a2 g1': the interactive scan goes ahead of the earlier background one (pre-fix: arrival order, the priority field is ignored)"
end_case_scans
finish_case "background priority does not yield to interactive scans"

# =============================================================================
# Configuration 3: 1 global slot, no limits file (the 1.11.x configuration)
configure 1 "" ""

# =============================================================================
begin_test "CONTROL: without a limits file queued scans start in strict arrival order, across clients"
reset_case
submit dtf-rega o1/hold-a1
wait_arrived o1/hold-a1 "$ARRIVE_WAIT" || fail_g "A1 never reached the registry"
for r in o1/hold-a2 o1/hold-a3; do
  submit_queued dtf-rega "$r"; [ "$SUB_STATE" = "302:Queued" ] || fail_g "${r}: ${SUB_STATE}, expected Queued"
done
submit_queued dtf-regb o1/hold-b1; [ "$SUB_STATE" = "302:Queued" ] || fail_g "B1: ${SUB_STATE}, expected Queued"
drain_in_order o1 4
note "start order: ${ORDER}"
[ "$ORDER" = "a1 a2 a3 b1" ] || fail_g "start order '${ORDER}', expected arrival order 'a1 a2 a3 b1'"
end_case_scans
finish_case "the default (no limits file) order is not FIFO"

# =============================================================================
begin_test "CONTROL: a scan request without a priority field (1.11.x-shaped body) is accepted and reports libcrypto1.1's CVEs"
reset_case
submit dtf-rega o2/plain
note "POST -> ${SUB_CODE}"
[ "$SUB_CODE" = 202 ] || fail_g "POST -> ${SUB_CODE} $(head -c 200 "$W/submit.out"), expected 202"
wait_done o2/plain "$DONE_WAIT" || true
s="$(state o2/plain)"
n="$(jq -r '.vulnerabilities | length' "$W/report.out" 2>/dev/null)"
note "report -> ${s}, ${n:-no} vulnerabilities"
[ "$s" = 200 ] || fail_g "report -> ${s}, expected 200"
[ "${n:-0}" -ge 1 ] 2>/dev/null || fail_g "the report lists ${n:-no} vulnerabilities, expected libcrypto1.1's CVEs"
finish_case "a request without priority does not scan as before"

cleanup
end_suite
