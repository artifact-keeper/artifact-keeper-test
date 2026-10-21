#!/usr/bin/env bash
# =============================================================================
# tiers/bind-ip-and-otel/oracle.sh
#   #2161  GRPC_BIND_IP / METRICS_BIND_IP bind the listeners; invalid -> exit
#   #3833  OTLP http/protobuf actually exports spans
#   #4029  inbound traceparent is joined, entry span is SERVER; all-zero ids
#          start a fresh trace; OTEL_TRACES_SAMPLER / _ARG
#   #4455  the http_request span carries http.route and the status code
# See the manifest for the gates.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# DTF_DIR, RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"
: "${DTF_SLOT:?}"; : "${DTF_DIR:?}"; : "${RUN_ID:?}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit. This oracle probes refused connections and a
# backend that must exit, so every step records its outcome through fail_g
# instead of aborting the suite.
set +e

BASE="$BASE_URL"
FX="${HERE}/fixtures"
PROJECT="ak-dtf${DTF_SLOT}"
BACKEND_CTR="ak-dtf${DTF_SLOT}-backend"
SPANS_CTR="ak-dtf${DTF_SLOT}-otlp-spans"
MK="o${DTF_SLOT}${RUN_ID##*-}"

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

# backend_logs: the container log with ANSI colour codes stripped (1.11.0 and
# 1.11.1 colour their text logs by default; LOG_ANSI arrived in 1.11.2).
backend_logs(){ docker logs "$BACKEND_CTR" 2>&1 | sed 's/\x1b\[[0-9;]*m//g'; }
login(){
  TOK="$(curl -s --max-time 15 -X POST "${BASE}/api/v1/auth/login" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg p "$ADMIN_PASS" '{username:"admin",password:$p}')" | jqr '.access_token // empty')"
}
# variant <grpc-bind> <metrics-bind> <sampler> <sampler-arg> [nowait]
variant(){
  export V_GRPC_BIND_IP="$1" V_METRICS_BIND_IP="$2" V_SAMPLER="$3" V_SAMPLER_ARG="$4"
  if [ "${5:-}" = "nowait" ]; then
    docker compose "${COMPOSE_ARGS[@]}" up -d --no-deps --force-recreate backend >"${W}/recreate.log" 2>&1
    return 0
  fi
  docker compose "${COMPOSE_ARGS[@]}" up -d --no-deps --force-recreate --wait backend >"${W}/recreate.log" 2>&1
  login
  LOGS="$(backend_logs)"
}
# reach <port>: 0 when a TCP connect from the sibling container to backend:<port> succeeds.
reach(){
  docker exec "$SPANS_CTR" python3 -c "import socket,sys; s=socket.socket(); s.settimeout(3); sys.exit(0 if s.connect_ex(('backend', $1)) == 0 else 1)"
}
# traced <marker> [traceparent]: one authenticated request whose uri carries the marker.
traced(){
  local hdr=()
  [ -n "${2:-}" ] && hdr=(-H "traceparent: $2")
  curl -s -o "${W}/traced" -D "${W}/traced.hdr" -w '%{http_code}' --max-time 15 "${hdr[@]}" \
    -H "Authorization: Bearer ${TOK}" "${BASE}/api/v1/repositories/dtf-otel-$1"
}
# span_for <marker>: the exported http_request span(s) whose uri carries the marker (JSON lines).
span_for(){
  docker exec "$SPANS_CTR" cat /tmp/otlp/spans.jsonl 2>/dev/null \
    | jq -c --arg m "dtf-otel-$1" 'select(.name == "http_request" and ((.attrs.uri // "") | contains($m)))' 2>/dev/null
}
wait_span(){ wait_until "exported span for $1" "${2:-20}" sh -c "docker exec '$SPANS_CTR' cat /tmp/otlp/spans.jsonl | grep -q 'dtf-otel-$1'"; }

begin_suite "bind-ip-and-otel"

# =============================================================================
# Leg A: listeners on every interface, default sampler.
# =============================================================================
variant 0.0.0.0 0.0.0.0 parentbased_always_on ""
[ -n "$TOK" ] || { infra_fail "no admin session after recreating the backend (default binds): $(tail -3 "${W}/recreate.log")"; end_suite; }

begin_test "CONTROL: with the default (all-interface) binds, HTTP, gRPC and the metrics listener all accept connections from a sibling container"
reset_case
for p in 8080 9090 9091; do
  if reach "$p"; then note "backend:${p} reachable"; else fail_g "backend:${p} refused a connection from the sibling container"; fi
done
finish_case "the sibling-container probe cannot reach the default listeners"

TID="$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
SID="$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')"
code1="$(traced "${MK}a" "00-${TID}-${SID}-01")"
code2="$(traced "${MK}z" "00-00000000000000000000000000000000-0000000000000000-01")"
for i in 1 2 3 4 5; do traced "${MK}n${i}" >/dev/null; done

begin_test "CONTROL: a request carrying a traceparent is served normally (404 for the unknown repository) on every image"
reset_case
note "GET /api/v1/repositories/dtf-otel-${MK}a with traceparent -> ${code1}; all-zero ids -> ${code2}"
[ "$code1" = "404" ] || fail_g "the traced request answered ${code1}, expected 404"
[ "$code2" = "404" ] || fail_g "the all-zero traced request answered ${code2}, expected 404"
finish_case "a traceparent header breaks request handling"

begin_test "FIX #3833: with OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf the collector receives spans, and the exporter never logs AfterShutdown / no reactor running"
reset_case
wait_span "${MK}n5" 20
posts="$(docker exec "$SPANS_CTR" cat /tmp/otlp/posts.log 2>/dev/null)"
nspans="$(docker exec "$SPANS_CTR" cat /tmp/otlp/spans.jsonl 2>/dev/null | wc -l | tr -d ' ')"
svc="$(docker exec "$SPANS_CTR" cat /tmp/otlp/spans.jsonl 2>/dev/null | jq -r '.service' 2>/dev/null | sort -u | tr '\n' ' ')"
note "OTLP POSTs: $(grep -c . <<<"$posts"), spans recorded: ${nspans}, service.name: ${svc}"
[ "${nspans:-0}" -gt 0 ] || fail_g "the collector recorded no spans"
grep -q 'decode-error' <<<"$posts" && fail_g "the sink could not decode an export: $(grep -m1 decode-error <<<"$posts")"
LOGS="$(backend_logs)"
grep -q 'AfterShutdown' <<<"$LOGS" && fail_g "the backend logged BatchSpanProcessor AfterShutdown warnings"
grep -q 'no reactor running' <<<"$LOGS" && fail_g "the backend logged 'no reactor running' (exporter thread panicked)"
finish_case "#3833: http/protobuf does not export spans"

begin_test "FIX #4029: the http_request span joins the inbound traceparent (trace_id and parent_span_id from the header) and is kind SERVER"
reset_case
S="$(span_for "${MK}a" | head -1)"
note "inbound 00-${TID}-${SID}-01 -> span: $(jqr '{trace_id,parent_span_id,kind,name}' <<<"$S" | tr -d ' \n')"
[ -n "$S" ] || fail_g "no exported http_request span for the traced request"
[ "$(jqr '.trace_id' <<<"$S")" = "$TID" ] || fail_g "the span's trace_id is not the inbound ${TID}"
[ "$(jqr '.parent_span_id' <<<"$S")" = "$SID" ] || fail_g "the span's parent_span_id is not the inbound ${SID}"
[ "$(jqr '.kind' <<<"$S")" = "2" ] || fail_g "the span kind is $(jqr '.kind' <<<"$S"), expected 2 (SERVER)"
finish_case "#4029: the backend does not join the caller's trace as a SERVER span"

begin_test "FIX #4029: a traceparent with all-zero ids is invalid and starts a fresh root trace"
reset_case
S="$(span_for "${MK}z" | head -1)"
note "all-zero traceparent -> span: $(jqr '{trace_id,parent_span_id,kind}' <<<"$S" | tr -d ' \n')"
[ -n "$S" ] || fail_g "no exported http_request span for the all-zero request"
tz="$(jqr '.trace_id' <<<"$S")"
{ [ -n "$tz" ] && [ "$tz" != "00000000000000000000000000000000" ] && [ "$tz" != "$TID" ]; } || fail_g "the span's trace_id '${tz}' is not a fresh id"
[ -z "$(jqr '.parent_span_id' <<<"$S")" ] || fail_g "the span has a parent ($(jqr '.parent_span_id' <<<"$S")), expected a root span"
[ "$(jqr '.kind' <<<"$S")" = "2" ] || fail_g "the span kind is $(jqr '.kind' <<<"$S"), expected 2 (SERVER)"
finish_case "#4029: an all-zero traceparent is not treated as invalid"

begin_test "FIX #4455: the http_request span carries the matched http.route and the response status code"
reset_case
S="$(span_for "${MK}a" | head -1)"
route="$(jqr '.attrs["http.route"] // empty' <<<"$S")"; st="$(jqr '.attrs["http.response.status_code"] // empty' <<<"$S")"
note "http.route='${route}' http.response.status_code='${st}' method='$(jqr '.attrs.method // empty' <<<"$S")'"
{ [ -n "$route" ] && [[ "$route" == /api/v1/repositories/* ]] && [[ "$route" != *dtf-otel* ]]; } || fail_g "http.route is '${route}', expected the route template under /api/v1/repositories/"
[ "$st" = "404" ] || fail_g "http.response.status_code is '${st}', expected 404"
finish_case "#4455: the request span lacks route and status"

# =============================================================================
# Leg B: GRPC_BIND_IP / METRICS_BIND_IP = 127.0.0.1.
# =============================================================================
begin_test "FIX #2161: with GRPC_BIND_IP=127.0.0.1 and METRICS_BIND_IP=127.0.0.1 a sibling container cannot connect to gRPC or metrics, while HTTP still serves"
reset_case
variant 127.0.0.1 127.0.0.1 parentbased_always_on ""
if [ -z "$TOK" ]; then
  fail_g "no admin session after recreating the backend with loopback binds: $(tail -3 "${W}/recreate.log")"
else
  if reach 8080; then note "backend:8080 reachable"; else fail_g "HTTP backend:8080 refused a connection"; fi
  if reach 9090; then fail_g "gRPC backend:9090 accepted a connection from the sibling container"; else note "backend:9090 refused"; fi
  if reach 9091; then fail_g "metrics backend:9091 accepted a connection from the sibling container"; else note "backend:9091 refused"; fi
  note "log: $(grep -E 'gRPC server listening on|Metrics listener on' <<<"$LOGS" | sed -E 's/.*(gRPC server listening on [^ ]+|Metrics listener on [^ ]+).*/\1/' | tr '\n' '|')"
  grep -q 'gRPC server listening on 127.0.0.1:9090' <<<"$LOGS" || fail_g "no 'gRPC server listening on 127.0.0.1:9090' line"
  grep -q 'Metrics listener on 127.0.0.1:9091' <<<"$LOGS" || fail_g "no 'Metrics listener on 127.0.0.1:9091' line"
fi
finish_case "#2161: GRPC_BIND_IP / METRICS_BIND_IP do not restrict the listeners"

begin_test "FIX #2161: GRPC_BIND_IP=not-an-ip fails startup (non-zero exit) with an error naming the variable"
reset_case
variant not-an-ip 0.0.0.0 parentbased_always_on "" nowait
state=""; for _ in $(seq 1 45); do
  state="$(docker inspect -f '{{.State.Status}} {{.State.ExitCode}}' "$BACKEND_CTR" 2>/dev/null)"
  case "$state" in exited*|dead*) break;; esac
  [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "${BASE}/health")" = "200" ] && break
  sleep 1
done
note "backend state: ${state}; log: $(docker logs "$BACKEND_CTR" 2>&1 | grep -m1 'GRPC_BIND_IP' | cut -c1-200)"
case "$state" in
  exited\ 0|running*) fail_g "the backend did not exit non-zero with GRPC_BIND_IP=not-an-ip (${state})";;
  exited*) ;;
  *) fail_g "unexpected backend state '${state}'";;
esac
docker logs "$BACKEND_CTR" 2>&1 | grep -q 'GRPC_BIND_IP' || fail_g "the startup error does not name GRPC_BIND_IP"
finish_case "#2161: an invalid GRPC_BIND_IP does not fail startup"

# =============================================================================
# Legs C/D: OTEL_TRACES_SAMPLER.
# =============================================================================
begin_test "FIX #4029: OTEL_TRACES_SAMPLER=always_off is logged at startup and exports no request span"
reset_case
variant 0.0.0.0 0.0.0.0 always_off ""
if [ -z "$TOK" ]; then
  fail_g "no admin session after recreating the backend with always_off: $(tail -3 "${W}/recreate.log")"
else
  grep -qE 'OpenTelemetry tracing enabled.*sampler="?always_off' <<<"$LOGS" || fail_g "the startup line does not report sampler=always_off: $(grep -m1 'OpenTelemetry tracing enabled' <<<"$LOGS" | cut -c1-240)"
  for i in 1 2 3 4 5; do traced "${MK}off${i}" >/dev/null; done
  c="$(traced "${MK}offb" "00-${TID}-${SID}-01")"
  [ "$c" = "404" ] || fail_g "a request under always_off answered ${c}, expected 404"
  # Two batch intervals and then some: a sampled span would have arrived.
  sleep 4
  n="$(span_for "${MK}off" | grep -c .)"
  note "spans exported for the always_off requests: ${n}"
  [ "$n" = "0" ] || fail_g "always_off exported ${n} request spans"
fi
finish_case "#4029: OTEL_TRACES_SAMPLER=always_off is not honoured"

begin_test "FIX #4029: OTEL_TRACES_SAMPLER=traceidratio with an unparseable _ARG falls back to ratio 1.0 (logged) and still exports spans"
reset_case
variant 0.0.0.0 0.0.0.0 traceidratio abc
if [ -z "$TOK" ]; then
  fail_g "no admin session after recreating the backend with traceidratio: $(tail -3 "${W}/recreate.log")"
else
  line="$(grep -m1 'OpenTelemetry tracing enabled' <<<"$LOGS" | cut -c1-300)"
  note "startup: ${line}"
  grep -qE 'sampler="?traceidratio' <<<"$line" || fail_g "the startup line does not report sampler=traceidratio"
  grep -qE 'sampler_ratio=1(\.0)?([^0-9.]|$)' <<<"$line" || fail_g "the startup line does not report the 1.0 fallback ratio"
  for i in 1 2 3; do traced "${MK}ratio${i}" >/dev/null; done
  wait_span "${MK}ratio3" 20
  n="$(span_for "${MK}ratio" | grep -c .)"
  note "spans exported for the traceidratio requests: ${n}"
  [ "$n" -ge 3 ] || fail_g "traceidratio with an unparseable ratio exported ${n} of 3 request spans"
fi
finish_case "#4029: an unparseable sampler ratio does not fall back to 1.0"

end_suite
