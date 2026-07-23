#!/usr/bin/env bash
# =============================================================================
# perf/harness/lib/ports.sh — PTF slot claim + non-colliding port allocation
# =============================================================================
# Same discipline as DTF's harness/lib/ports.sh, but a FRESH port block so a
# PTF slot never collides with the :8080 red target, the 8100+ blue-fix pool,
# or DTF's 8200/9200/30700/9300 block.
#
# PERF port block for slot N:
#     HTTP    = 8300 + N
#     gRPC    = 9500 + N
#     PG      = 30800 + N
#     METRICS = 8350 + N    # unauth /metrics listener (compose.metrics.yml)
#     S3      = 9600 + N     # when the storage.s3 overlay is used
# =============================================================================

PERF_POOL_SIZE="${PERF_POOL_SIZE:-8}"

perf_slot_env() {
  local n="$1"
  export PERF_SLOT="$n"
  export HTTP_PORT="$((8300 + n))"
  export GRPC_PORT="$((9500 + n))"
  export PG_PORT="$((30800 + n))"
  export METRICS_PORT="$((8350 + n))"
  export S3_PORT="$((9600 + n))"
}

# perf_slot_occupied <N> — 0 if ANY container (running OR stopped) or leftover
# network exists in slot N's namespace (ak-perf<N>-*). Mirrors DTF's ps -a fix.
perf_slot_occupied() {
  local n="$1"
  docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q "^ak-perf${n}-" && return 0
  docker network ls --format '{{.Name}}' 2>/dev/null | grep -q "^ak-perf${n}-net$" && return 0
  return 1
}

perf_claim_slot() {
  local n
  for n in $(seq 1 "$PERF_POOL_SIZE"); do
    if ! perf_slot_occupied "$n"; then echo "$n"; return 0; fi
  done
  echo "!! no free PERF slot (PERF_POOL_SIZE=$PERF_POOL_SIZE all occupied)" >&2
  return 1
}

perf_ports() {
  local n="$1"; perf_slot_env "$n"
  echo "slot $n  HTTP=127.0.0.1:${HTTP_PORT}  gRPC=127.0.0.1:${GRPC_PORT}  PG=127.0.0.1:${PG_PORT}  METRICS=127.0.0.1:${METRICS_PORT}"
}
