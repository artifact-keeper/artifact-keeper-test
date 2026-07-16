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

begin_test "Nexus source bootstrap (EULA accept + admin rotation, per-slot instance)"
if bash "${HERE}/nexus_bootstrap.sh"; then
  pass
else
  SETUP_OK=0
  fail "nexus_bootstrap.sh failed on slot ${DTF_SLOT} (see stdout above)"
fi

begin_test "Seed Docker fixtures into Nexus: single-arch + multi-arch + large-index"
if [ "$SETUP_OK" = "1" ] && bash "${HERE}/nexus_seed.sh"; then
  pass
else
  SETUP_OK=0
  fail "nexus_seed.sh failed (or bootstrap already failed) on slot ${DTF_SLOT}"
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
  fail "skipped: Nexus setup failed earlier in the suite"
fi

end_suite
