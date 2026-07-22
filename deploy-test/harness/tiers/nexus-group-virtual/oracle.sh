#!/usr/bin/env bash
# =============================================================================
# tiers/nexus-group-virtual/oracle.sh — nexus-group-virtual tier (#2783)
# =============================================================================
# run.sh has brought backend+postgres+nexus up on this slot (health-gated
# `up -d --wait`, so the 2-3 min Nexus boot is already absorbed) and exported
# BASE_URL, DB_CONTAINER, ADMIN_PASS, BACKEND_IMAGE, DTF_SLOT + the port block,
# RELEASE_GATE=1 and JUNIT_OUTPUT_DIR.
#
# Steps (each a JUnit test):
#   1. nexus_bootstrap.sh  — EULA accept + admin password rotation (idempotent)
#   2. nexus_seed.sh       — seed 3 raw hosted members + a raw group over them
#   3. assert.sh           — real AK migration (members a+b + group, exclude c),
#                            then the #2783 checks: exit 0 on a fixed image,
#                            exit = failed-check count on a pre-#2783 image
#                            (non-zero-while-bug; pre-fix the virtual has 0
#                            members).
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=/dev/null
source "$COMMON_SH"

begin_suite "nexus-group-virtual-2783"

SETUP_OK=1

begin_test "Nexus source bootstrap (EULA accept + admin rotation, per-slot instance)"
if bash "${HERE}/nexus_bootstrap.sh"; then
  pass
else
  SETUP_OK=0
  fail "nexus_bootstrap.sh failed on slot ${DTF_SLOT} (see stdout above)"
fi

begin_test "Seed group + members into Nexus: 3 raw hosted members + a raw group over them"
if [ "$SETUP_OK" = "1" ] && bash "${HERE}/nexus_seed.sh"; then
  pass
else
  SETUP_OK=0
  fail "nexus_seed.sh failed (or bootstrap already failed) on slot ${DTF_SLOT}"
fi

begin_test "#2783 migrate -> assert: group becomes an AK virtual repo whose members are exactly the migrated member ids in order (absent skipped, no dangling)"
if [ "$SETUP_OK" = "1" ]; then
  rc=0; bash "${HERE}/assert.sh" || rc=$?
  if [ "$rc" -eq 0 ]; then
    pass
  else
    fail "nexus-group-virtual oracle reported ${rc} failed #2783 positive check(s) on ${BASE_URL} (virtual repo members missing/misordered/dangling; pre-#2783 the virtual has ZERO members); see stdout above"
  fi
else
  fail "skipped: Nexus setup failed earlier in the suite"
fi

end_suite
