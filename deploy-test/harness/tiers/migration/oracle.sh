#!/usr/bin/env bash
# =============================================================================
# tiers/migration/oracle.sh — migration tier (upstreams=nexus, #2457)
# =============================================================================
# Wraps the vendored Nexus harness under the run.sh contract: run.sh has stood
# up backend+postgres+nexus on this slot (health-gated `up -d --wait`, so the
# heavy 2-3 min Nexus boot is already absorbed) and exported BASE_URL,
# DB_CONTAINER, ADMIN_PASS, BACKEND_IMAGE, DTF_SLOT + the port block,
# RELEASE_GATE=1 and JUNIT_OUTPUT_DIR.
#
# Steps (each a JUnit test):
#   1. nexus_bootstrap.sh  — EULA + admin password rotation (idempotent)
#   2. nexus_seed.sh       — seed single-arch + multi-arch + large-index fixtures
#   3. assert.sh           — real AK migration, then the #2457 assertions:
#                            exit 0 on a fixed image, exit = finding-count on a
#                            hollow-migration image (non-zero-while-bug).
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=/dev/null
source "$COMMON_SH"

begin_suite "migration-nexus-2457"

SETUP_OK=1

# Steps 1 and 2 build the FIXTURE the tier needs (a live Nexus with seeded
# Docker images). A failure there says nothing whatsoever about the candidate,
# so it is an INFRA/SETUP failure (exit 11, #323), not a regression verdict —
# and the sub-script's output is captured and attached, because "nexus_seed.sh
# failed" on its own is unactionable (v1.7.1 release gate, run 31146165373).
# `2>&1 | tee <file>` keeps the sub-script's output LIVE and in order on the
# job log (one fd, so it cannot interleave with this oracle's own writes) AND
# on disk, so the tail can be attached to the JUnit failure. `set -o pipefail`
# at the top of this file makes the pipeline carry the script's exit status,
# not tee's.
SETUP_LOG_DIR="${RESULTS_DIR:-/tmp}"
BOOTSTRAP_LOG="${SETUP_LOG_DIR}/nexus_bootstrap.log"
SEED_LOG="${SETUP_LOG_DIR}/nexus_seed.log"

begin_test "Nexus source bootstrap (EULA accept + admin rotation, per-slot instance)"
if bash "${HERE}/nexus_bootstrap.sh" 2>&1 | tee "$BOOTSTRAP_LOG"; then
  pass
else
  SETUP_OK=0
  infra_fail "nexus_bootstrap.sh failed on slot ${DTF_SLOT}" "$(tail -n 40 "$BOOTSTRAP_LOG" 2>/dev/null)"
fi

begin_test "Seed Docker fixtures into Nexus: single-arch + multi-arch + large-index"
if [ "$SETUP_OK" != "1" ]; then
  infra_fail "skipped: Nexus bootstrap failed earlier in the suite"
elif bash "${HERE}/nexus_seed.sh" 2>&1 | tee "$SEED_LOG"; then
  pass
else
  SETUP_OK=0
  infra_fail "nexus_seed.sh failed on slot ${DTF_SLOT} (fixture seeding — NOT a candidate assertion)" "$(tail -n 40 "$SEED_LOG" 2>/dev/null)"
fi

begin_test "#2457 migrate -> native pull: config blob, multi-arch child manifests, per-image docker pull, oci_blobs, orphan/fidelity invariants"
if [ "$SETUP_OK" = "1" ]; then
  rc=0; bash "${HERE}/assert.sh" || rc=$?
  if [ "$rc" -eq 0 ]; then
    pass
  else
    fail "migration oracle reported ${rc} #2457 finding(s) on ${BASE_URL} (hollow/unpullable migrated images); see stdout above"
  fi
else
  infra_fail "skipped: Nexus setup failed earlier in the suite — the candidate was never exercised"
fi

end_suite
