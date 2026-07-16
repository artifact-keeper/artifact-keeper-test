#!/usr/bin/env bash
# =============================================================================
# harness/lib/ports.sh — DTF slot claim + non-colliding port allocation
# =============================================================================
# Adapted from rig/pool.sh's slot_env / claim discipline. Each slot N gets its
# own compose project (ak-dtf<N>) with a deterministic, non-overlapping port
# block, so N tiers can run concurrently and none touches the red-team target
# on :8080 or the blue-fix pool on 8100+.
#
# DTF port block for slot N (base ranges chosen to avoid :8080 red target,
# the 8100+ blue-fix pool, and the proof rig's 8082/8092/8083 + 9002/9012 +
# 30602/30612 ranges):
#     HTTP           = 8200 + N
#     gRPC           = 9200 + N
#     PG             = 30700 + N
#     S3 (minio api) = 9300 + N
#     S3 console     = 9400 + N
#     TRIVY (future) = 8250 + N
#     NEXUS API      = 8260 + N   (upstreams.nexus profile, brick 2; also clear
#     NEXUS docker   = 8270 + N    of the rig's fixed ak-nexus-2457 :8071/:8072)
#
# GOTCHA (heeded): pool.sh's `is_up` only greps `docker ps` (running), so a
# STOPPED container in a slot is misreported as free and the next `up` collides
# on the container name. dtf_slot_occupied greps `docker ps -a` (running OR
# stopped) — any container in the slot's namespace means the slot is taken.
# =============================================================================

DTF_POOL_SIZE="${DTF_POOL_SIZE:-8}"

# dtf_slot_env <N> — export DTF_SLOT + the full computed port block.
dtf_slot_env() {
  local n="$1"
  export DTF_SLOT="$n"
  export HTTP_PORT="$((8200 + n))"
  export GRPC_PORT="$((9200 + n))"
  export PG_PORT="$((30700 + n))"
  export S3_PORT="$((9300 + n))"
  export S3_CONSOLE_PORT="$((9400 + n))"
  export TRIVY_PORT="$((8250 + n))"
  export NEXUS_API_PORT="$((8260 + n))"
  export NEXUS_DOCKER_PORT="$((8270 + n))"
}

# dtf_slot_occupied <N> — return 0 if ANY container (running OR stopped) exists
# in slot N's namespace (ak-dtf<N>-*). Stopped-but-present counts as occupied.
dtf_slot_occupied() {
  local n="$1"
  docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q "^ak-dtf${n}-" && return 0
  # Also treat a leftover compose project (network/volume) as occupied so a
  # half-torn-down slot is never reused underneath a live network.
  docker network ls --format '{{.Name}}' 2>/dev/null | grep -q "^ak-dtf${n}-net$" && return 0
  return 1
}

# dtf_claim_slot — print the lowest FREE slot index (1..DTF_POOL_SIZE), or fail.
dtf_claim_slot() {
  local n
  for n in $(seq 1 "$DTF_POOL_SIZE"); do
    if ! dtf_slot_occupied "$n"; then
      echo "$n"
      return 0
    fi
  done
  echo "!! no free DTF slot (DTF_POOL_SIZE=$DTF_POOL_SIZE all occupied)" >&2
  return 1
}

# dtf_ports <N> — human-readable port map for slot N.
dtf_ports() {
  local n="$1"; dtf_slot_env "$n"
  echo "slot $n  HTTP=127.0.0.1:${HTTP_PORT}  gRPC=127.0.0.1:${GRPC_PORT}  PG=127.0.0.1:${PG_PORT}  S3=127.0.0.1:${S3_PORT}  S3-console=127.0.0.1:${S3_CONSOLE_PORT}"
}
