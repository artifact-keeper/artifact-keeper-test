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
SKOPEO_IMAGE="${SKOPEO_IMAGE:-quay.io/skopeo/stable:latest}"
skopeo() { docker run --rm --network host "${SKOPEO_IMAGE}" "$@"; }

log()  { printf '\033[36m[dtf-migration]\033[0m %s\n' "$*" >&2; }
warn() { printf '\033[33m[dtf-migration]\033[0m %s\n' "$*" >&2; }
err()  { printf '\033[31m[dtf-migration]\033[0m %s\n' "$*" >&2; }
die()  { err "$*"; exit 1; }

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
