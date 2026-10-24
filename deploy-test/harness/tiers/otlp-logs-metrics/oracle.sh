#!/usr/bin/env bash
# =============================================================================
# tiers/otlp-logs-metrics/oracle.sh
#   #4337 OTLP log records and metric points reach the collector on their own
#         paths when opted in; nothing but traces otherwise; no SQL text in log
#         bodies; a down collector slows neither startup, requests nor shutdown
# See the manifest for the legs and gates.
#
# run.sh exported BASE_URL, ADMIN_PASS, RUN_ID, DTF_SLOT, DTF_DIR, TRIVY_PORT
# (the sink's control port), RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"
: "${DTF_SLOT:?}"; : "${DTF_DIR:?}"; : "${RUN_ID:?}"; : "${TRIVY_PORT:?}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; this oracle stops containers on purpose, so each
# step records its outcome through fail_g instead of aborting the suite.
set +e

BASE="$BASE_URL"
FX="${HERE}/fixtures"
PROJECT="ak-dtf${DTF_SLOT}"
BACKEND_CTR="ak-dtf${DTF_SLOT}-backend"
SINK_CTR="ak-dtf${DTF_SLOT}-otlp-sink"
SINK="http://127.0.0.1:${TRIVY_PORT}"
MK="otlm${DTF_SLOT}${RUN_ID##*-}"

PROFILES=""
# shellcheck source=/dev/null
source "${HERE}/manifest"
COMPOSE_BASE=(-p "$PROJECT" -f "${DTF_DIR}/compose.base.yml")
for p in $PROFILES; do COMPOSE_BASE+=(-f "${DTF_DIR}/profiles/${p}.yml"); done
COMPOSE_BASE+=(-f "${FX}/backend.common.yml")
COMPOSE_ON=("${COMPOSE_BASE[@]}" -f "${FX}/backend.signals.yml")

setup_workdir
W="$WORK_DIR"

jqr(){ jq -r "$1" 2>/dev/null || true; }
now_ms(){ date +%s%3N; }

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

backend_logs(){ docker logs "$BACKEND_CTR" 2>&1 | sed 's/\x1b\[[0-9;]*m//g'; }
login(){
  TOK="$(curl -s --max-time 15 -X POST "${BASE}/api/v1/auth/login" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg p "$ADMIN_PASS" '{username:"admin",password:$p}')" | jqr '.access_token // empty')"
}

# Sink control: since_mode counts reset with POST /__mode.
sink_reset(){ curl -s --max-time 5 -X POST "${SINK}/__mode?status=200" >/dev/null 2>&1; }
sink_count(){ curl -s --max-time 5 "${SINK}/__stats" 2>/dev/null | jq -r --arg p "$1" '.since_mode[$p] // 0' 2>/dev/null || echo 0; }
sink_grep(){ curl -s --max-time 5 -G "${SINK}/__grep" --data-urlencode "needle=$1" --data-urlencode "path=$2" 2>/dev/null | jq -r '.hits // 0' 2>/dev/null || echo 0; }

# recreate <compose-array-name>: stop the running backend first (its shutdown
# flush lands before the sink reset), reset the sink, start the backend, and
# time how long /readyz takes to answer 200 (READY_MS, -1 if it never did).
recreate(){
  local -n _args="$1"
  docker stop -t 30 "$BACKEND_CTR" >/dev/null 2>&1
  [ "${2:-}" = "keep-sink" ] || sink_reset
  local t0; t0="$(now_ms)"
  docker compose "${_args[@]}" up -d --no-deps --force-recreate backend >"${W}/recreate.log" 2>&1
  READY_MS=-1
  local i
  for i in $(seq 1 480); do
    if [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "${BASE}/readyz" 2>/dev/null)" = "200" ]; then
      READY_MS=$(( $(now_ms) - t0 )); break
    fi
    sleep 0.25
  done
  login
}

# traffic <tag>: 10 authenticated requests carrying the marker; per-request
# latencies (ms) -> $W/lat.<tag>, the X-Correlation-ID each response echoes
# (also a field of its "Request completed" log event) -> $W/cid.<tag>.
traffic(){
  : > "${W}/lat.$1"; : > "${W}/cid.$1"
  local i t
  for i in $(seq 1 10); do
    t="$(curl -s -o /dev/null -D "${W}/hdr" -w '%{time_total}' --max-time 15 -H "Authorization: Bearer ${TOK}" \
      "${BASE}/api/v1/repositories/dtf-otlp-${MK}-$1-${i}" 2>/dev/null || echo 15)"
    awk -v t="$t" 'BEGIN{printf "%d\n", t*1000}' >> "${W}/lat.$1"
    grep -i '^x-correlation-id:' "${W}/hdr" | cut -d: -f2- | tr -d ' \r' >> "${W}/cid.$1"
  done
}
# cid_hits <tag> <path>: how many of the leg's correlation ids occur in bodies on <path>.
cid_hits(){ local n=0 c; while read -r c; do [ -n "$c" ] && has_hits "$c" "$2" && n=$((n+1)); done < "${W}/cid.$1"; echo "$n"; }
median_ms(){ sort -n "$1" | awk '{a[NR]=$1} END{print (NR ? a[int((NR+1)/2)] : -1)}'; }
under_ms(){ awk -v b="$2" '$1 < b {n++} END{print n+0}' "$1"; }

# wait_for <description> <seconds> <cmd...>: poll until cmd succeeds.
wait_for(){ local d="$1" s="$2"; shift 2; local i; for i in $(seq 1 $((s * 2))); do "$@" && return 0; sleep 0.5; done; return 1; }
has_hits(){ [ "$(sink_grep "$1" "$2")" -gt 0 ] 2>/dev/null; }
has_posts(){ [ "$(sink_count "$1")" -gt 0 ] 2>/dev/null; }

begin_suite "otlp-logs-metrics"

curl -s --max-time 5 "${SINK}/__readyz" | grep -q ok || { infra_fail "the OTLP sink is not reachable at ${SINK}"; end_suite; exit $?; }

# =============================================================================
# Leg U: exporters unset (traces only).
# =============================================================================
recreate COMPOSE_BASE
U_READY="$READY_MS"
[ -n "$TOK" ] || { infra_fail "no admin session after recreating the backend (exporters unset), ready=${READY_MS} ms: $(tail -3 "${W}/recreate.log")"; end_suite; exit $?; }
traffic u
wait_for "spans" 20 has_hits "dtf-otlp-${MK}-u-10" /v1/traces
sleep 6   # three 2 s metric intervals: a wrongly enabled signal would arrive

begin_test "CONTROL: exporters unset, spans arrive on /v1/traces and nothing arrives on /v1/logs or /v1/metrics"
reset_case
t="$(sink_count /v1/traces)"; l="$(sink_count /v1/logs)"; m="$(sink_count /v1/metrics)"
note "ready in ${U_READY} ms; POSTs since start: /v1/traces=${t} /v1/logs=${l} /v1/metrics=${m}; marker in trace bodies: $(sink_grep "dtf-otlp-${MK}-u-" /v1/traces)"
[ "$t" -gt 0 ] 2>/dev/null || fail_g "no span export reached /v1/traces"
has_hits "dtf-otlp-${MK}-u-" /v1/traces || fail_g "no exported span carries the request marker"
[ "$l" = "0" ] || fail_g "${l} log export(s) arrived although OTEL_LOGS_EXPORTER is unset"
[ "$m" = "0" ] || fail_g "${m} metric export(s) arrived although OTEL_METRICS_EXPORTER is unset"
finish_case "with the logs and metrics exporters unset the backend must export traces only"

# =============================================================================
# Leg O: OTEL_LOGS_EXPORTER=otlp, OTEL_METRICS_EXPORTER=otlp.
# =============================================================================
recreate COMPOSE_ON
O_READY="$READY_MS"
[ -n "$TOK" ] || { infra_fail "no admin session after recreating the backend (signals on), ready=${READY_MS} ms: $(tail -3 "${W}/recreate.log")"; end_suite; exit $?; }
traffic o
wait_for "spans" 20 has_hits "dtf-otlp-${MK}-o-10" /v1/traces
wait_for "logs" 15 has_hits "$(tail -1 "${W}/cid.o" 2>/dev/null)" /v1/logs
wait_for "metrics" 15 has_hits "ak_http_requests_total" /v1/metrics
LOGS="$(backend_logs)"

begin_test "CONTROL: with the signals on, spans still arrive on /v1/traces with the request marker and the startup line prints"
reset_case
note "ready in ${O_READY} ms; /v1/traces POSTs=$(sink_count /v1/traces), marker hits=$(sink_grep "dtf-otlp-${MK}-o-" /v1/traces)"
has_hits "dtf-otlp-${MK}-o-" /v1/traces || fail_g "no exported span carries the request marker"
SL="$(grep -m1 'OpenTelemetry tracing enabled' <<<"$LOGS")"
note "startup: ${SL:0:300}"
[ -n "$SL" ] || fail_g "the 'OpenTelemetry tracing enabled' startup line is missing"
finish_case "trace export broke with the logs and metrics exporters on"

begin_test "FIX(#4337): OTEL_LOGS_EXPORTER=otlp sends log records to /v1/logs, carrying the requests' access-log events and the startup record"
reset_case
l="$(sink_count /v1/logs)"; ch="$(cid_hits o /v1/logs)"
note "/v1/logs POSTs=${l}; 'Request completed' hits=$(sink_grep 'Request completed' /v1/logs); correlation ids of the 10 requests found: ${ch}; 'Starting Artifact Keeper' hits=$(sink_grep 'Starting Artifact Keeper' /v1/logs)"
[ "$l" -gt 0 ] 2>/dev/null || fail_g "no log export reached /v1/logs"
has_hits "Request completed" /v1/logs || fail_g "no exported 'Request completed' access-log record"
[ "$ch" -ge 8 ] 2>/dev/null || fail_g "only ${ch} of the 10 requests' correlation ids are in exported log records"
has_hits "Starting Artifact Keeper" /v1/logs || fail_g "the startup record was not exported"
has_hits "dtf-otlp-${MK}-o-" /v1/metrics && fail_g "a request URI landed in a /v1/metrics body (logs sent to the metrics path)"
finish_case "#4337: log records are not exported to /v1/logs"

begin_test "FIX(#4337): OTEL_METRICS_EXPORTER=otlp sends metric points to /v1/metrics (ak_http_requests_total, ak_http_request_duration_seconds)"
reset_case
m="$(sink_count /v1/metrics)"
note "/v1/metrics POSTs=${m}; ak_http_requests_total hits=$(sink_grep ak_http_requests_total /v1/metrics); ak_http_request_duration_seconds hits=$(sink_grep ak_http_request_duration_seconds /v1/metrics)"
[ "$m" -gt 0 ] 2>/dev/null || fail_g "no metric export reached /v1/metrics"
has_hits ak_http_requests_total /v1/metrics || fail_g "no exported metric named ak_http_requests_total"
has_hits ak_http_request_duration_seconds /v1/metrics || fail_g "no exported metric named ak_http_request_duration_seconds"
has_hits ak_http_requests_total /v1/traces && fail_g "metric names landed in a /v1/traces body (metrics sent to the traces path)"
finish_case "#4337: metric points are not exported to /v1/metrics"

begin_test "FIX(#4337): no SQL statement text appears in exported log bodies, although stdout carries it (sqlx::query=debug)"
reset_case
sql_stdout="$(grep -cE 'SELECT .* FROM |INSERT INTO ' <<<"$LOGS")"
l="$(sink_count /v1/logs)"
note "stdout lines with SQL text: ${sql_stdout}; /v1/logs POSTs: ${l}"
[ "$l" -gt 0 ] 2>/dev/null || fail_g "no log bodies to inspect (log export is off)"
[ "${sql_stdout:-0}" -gt 0 ] || fail_g "precondition: stdout shows no SQL statement text, so the filter is not exercised"
for needle in "SELECT " "INSERT INTO " "DELETE FROM " "pg_try_advisory_lock" "FROM users"; do
  h="$(sink_grep "$needle" /v1/logs)"
  [ "$h" = "0" ] || fail_g "${h} exported log bod(y/ies) contain '${needle}'"
done
finish_case "#4337: SQL statement text reaches the collector in log records"

# Baseline request latency with a healthy collector.
O_MED="$(median_ms "${W}/lat.o")"

# =============================================================================
# Leg D: signals on, collector down.
# =============================================================================
docker stop -t 5 "$SINK_CTR" >/dev/null 2>&1
recreate COMPOSE_ON keep-sink
D_READY="$READY_MS"
traffic d
sleep 3   # let a log batch and a metric push hit the dead endpoint

begin_test "GUARD: with the collector down, /readyz answers within the normal startup time"
reset_case
base=$(( U_READY > O_READY ? U_READY : O_READY ))
note "ready: unset ${U_READY} ms, on ${O_READY} ms, collector down ${D_READY} ms (bound $((base + 15000)) ms)"
[ "$D_READY" -ge 0 ] || fail_g "/readyz never answered 200 within 120 s"
[ "$D_READY" -le $((base + 15000)) ] || fail_g "/readyz took ${D_READY} ms, more than 15 s over the healthy-collector startup (${base} ms)"
[ -n "$TOK" ] || fail_g "admin login failed with the collector down"
finish_case "a down collector delays startup"

begin_test "GUARD: with the collector down, request latency stays normal"
reset_case
D_MED="$(median_ms "${W}/lat.d")"; D_UNDER="$(under_ms "${W}/lat.d" 1000)"
note "latency ms, collector up: $(paste -sd' ' "${W}/lat.o") (median ${O_MED}); down: $(paste -sd' ' "${W}/lat.d") (median ${D_MED}, ${D_UNDER}/10 under 1 s)"
[ "$D_UNDER" -ge 8 ] || fail_g "only ${D_UNDER} of 10 requests finished in under 1 s"
[ "$D_MED" -le $((O_MED + 300)) ] || fail_g "median ${D_MED} ms is more than 300 ms over the healthy-collector median ${O_MED} ms"
finish_case "a down collector slows requests"

begin_test "GUARD: with the collector down, shutdown completes promptly and cleanly"
reset_case
t0="$(now_ms)"
docker stop -t 60 "$BACKEND_CTR" >/dev/null 2>&1
STOP_MS=$(( $(now_ms) - t0 ))
EXIT="$(docker inspect -f '{{.State.ExitCode}}' "$BACKEND_CTR" 2>/dev/null)"
LOGS="$(backend_logs)"
note "docker stop took ${STOP_MS} ms, exit code ${EXIT}"
[ "$STOP_MS" -le 25000 ] || fail_g "shutdown took ${STOP_MS} ms (bound 25000)"
[ "$EXIT" != "137" ] || fail_g "the backend had to be killed (exit 137)"
grep -q 'panicked' <<<"$LOGS" && fail_g "the backend logged a panic: $(grep -m1 'panicked' <<<"$LOGS" | head -c 300)"
finish_case "a down collector stalls or breaks shutdown"

end_suite
