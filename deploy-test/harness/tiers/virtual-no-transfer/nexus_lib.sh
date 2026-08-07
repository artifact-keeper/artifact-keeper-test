#!/usr/bin/env bash
# =============================================================================
# tiers/migration/nexus_lib.sh — shared config + helpers for the migration tier
# =============================================================================
# VENDORED + adapted from rig/harness/nexus_common.sh (flagged deviation): the
# rig lib addresses one fixed compose project (ak-nexus-2457, host :8071/:8072)
# and owns the Nexus lifecycle; under DTF the Nexus instance is per-slot
# (ak-dtf<N>-nexus, ports from harness/lib/ports.sh) and run.sh owns the
# compose lifecycle, so the compose helpers are dropped. Credential handling,
# REST helpers, and the containerized-skopeo shim are copied verbatim.
#
# Sourced by nexus_bootstrap.sh, nexus_seed.sh, assert.sh — all of which run
# under the run.sh contract (DTF_SLOT / NEXUS_API_PORT / NEXUS_DOCKER_PORT /
# RESULTS_DIR already exported).
# =============================================================================
set -uo pipefail

: "${DTF_SLOT:?nexus_lib.sh requires DTF_SLOT (run under harness/run.sh)}"
: "${NEXUS_API_PORT:?nexus_lib.sh requires NEXUS_API_PORT (harness/lib/ports.sh)}"
: "${NEXUS_DOCKER_PORT:?nexus_lib.sh requires NEXUS_DOCKER_PORT (harness/lib/ports.sh)}"

# --- Container / endpoint identity (per-slot) ------------------------------
NEXUS_CTR="${NEXUS_CTR:-ak-dtf${DTF_SLOT}-nexus}"
NEXUS_API="${NEXUS_API:-http://127.0.0.1:${NEXUS_API_PORT}}"   # REST API / UI (host)
NEXUS_DOCKER="${NEXUS_DOCKER:-127.0.0.1:${NEXUS_DOCKER_PORT}}" # Docker V2 connector (host)
# In-network endpoint the AK backend reaches over the slot's dtf network
# (compose service DNS name, NOT the container name):
NEXUS_API_INTERNAL="${NEXUS_API_INTERNAL:-http://nexus:8081}"
NEXUS_DOCKER_HTTP_PORT="${NEXUS_DOCKER_HTTP_PORT:-8082}"

# --- Credentials ------------------------------------------------------------
NEXUS_ADMIN_USER="${NEXUS_ADMIN_USER:-admin}"
NEXUS_ADMIN_PASS="${NEXUS_ADMIN_PASS:-Nexus2457!repro}"   # target admin password
NEXUS_DOCKER_REPO="${NEXUS_DOCKER_REPO:-docker-hosted}"

# --- Non-committed state (creds + fixtures), per-run under results/ ---------
NEXUS_STATE_DIR="${NEXUS_STATE_DIR:-${RESULTS_DIR:-/tmp}/nexus-state-slot${DTF_SLOT}}"
NEXUS_PASS_FILE="${NEXUS_STATE_DIR}/admin_password.txt"
NEXUS_FIXTURES_FILE="${NEXUS_STATE_DIR}/fixtures.json"
mkdir -p "${NEXUS_STATE_DIR}" 2>/dev/null || true

# --- skopeo (missing on host -> run containerized, host network) ------------
# PINNED BY DIGEST (v1.22.2, the bytes `latest` has pointed at since
# 2026-05-31). This is a third-party image fetched from quay.io at gate time;
# a floating tag makes a release gate non-deterministic for no benefit, and
# every other image the DTF stands up is already pinned (the backend by
# candidate digest, Nexus at sonatype/nexus3:3.90.4@sha256:...).
SKOPEO_IMAGE="${SKOPEO_IMAGE:-quay.io/skopeo/stable:v1.22.2@sha256:c7d3c512612f52805023cd38351081dad7e2729fc13d14b701e47c7c8bdd6615}"
skopeo() { docker run --rm --network host "${SKOPEO_IMAGE}" "$@"; }

log()  { printf '\033[36m[dtf-migration]\033[0m %s\n' "$*" >&2; }
warn() { printf '\033[33m[dtf-migration]\033[0m %s\n' "$*" >&2; }
err()  { printf '\033[31m[dtf-migration]\033[0m %s\n' "$*" >&2; }
die()  { err "$*"; exit 1; }

# skopeo_ensure_image — materialise the skopeo image ONCE, loudly, before any
# skopeo call.
#
# WHY THIS EXISTS (v1.7.1 release gate, run 31146165373): `skopeo()` is a
# `docker run` shim, so the image is pulled IMPLICITLY by whichever call runs
# first. That call is dest_exists(), which is `>/dev/null 2>&1` — so its pull
# is invisible. On that run the silent pull failed, left a partially
# registered image behind, and the next call died with
#   docker: failed to register layer: mkdirat etc/dnf: no such file or directory
# The tier then reported "nexus_seed.sh failed" with no trace of the pull at
# all. Pull explicitly, print what happened, and on failure drop the
# half-registered image so the retry starts from a clean layer cache.
skopeo_ensure_image() {
  local attempt out
  if docker image inspect "${SKOPEO_IMAGE}" >/dev/null 2>&1; then
    log "skopeo image already present: ${SKOPEO_IMAGE}"
    return 0
  fi
  for attempt in 1 2 3; do
    log "pulling skopeo image (attempt ${attempt}/3): ${SKOPEO_IMAGE}"
    if out=$(docker pull "${SKOPEO_IMAGE}" 2>&1); then
      log "skopeo image ready."
      return 0
    fi
    err "skopeo image pull FAILED (attempt ${attempt}/3):"
    printf '%s\n' "$out" | tail -n 20 >&2
    docker rmi -f "${SKOPEO_IMAGE}" >/dev/null 2>&1 || true
    sleep 5
  done
  err "could not pull ${SKOPEO_IMAGE} after 3 attempts — this is an INFRA failure (third-party registry / local image store), not a candidate verdict"
  return 1
}

# nx_curl METHOD PATH [curl-args...] -> authenticated REST call vs NEXUS_API.
# Uses the *current* admin password from the state file if present, else target.
nx_pass() {
  if [ -f "${NEXUS_PASS_FILE}" ]; then cat "${NEXUS_PASS_FILE}"; else echo "${NEXUS_ADMIN_PASS}"; fi
}
nx_curl() {
  local method="$1" path="$2"; shift 2
  curl -sS -u "${NEXUS_ADMIN_USER}:$(nx_pass)" -X "${method}" "${NEXUS_API}${path}" "$@"
}

nexus_is_up() { docker ps --format '{{.Names}}' | grep -q "^${NEXUS_CTR}$"; }
