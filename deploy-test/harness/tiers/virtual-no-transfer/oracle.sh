#!/usr/bin/env bash
# =============================================================================
# tiers/virtual-no-transfer/oracle.sh -- virtual-no-transfer tier (#2821)
# =============================================================================
# run.sh has brought backend+postgres+nexus up on this slot (health-gated
# `up -d --wait`, so the 2-3 min Nexus boot is already absorbed) and exported
# BASE_URL, DB_CONTAINER, ADMIN_PASS, BACKEND_IMAGE, DTF_SLOT + the port block,
# RELEASE_GATE=1 and JUNIT_OUTPUT_DIR.
#
# Steps (each a JUnit test):
#   1. nexus_bootstrap.sh  -- EULA accept + admin password rotation (idempotent)
#   2. nexus_seed.sh       -- seed 2 raw hosted members + a raw group over them
#   3. assert.sh           -- real AK migration (members a+b + group), then the
#                            #2821 checks: the group provisions as an AK virtual
#                            repo with correlated members but ZERO own bytes.
#                            exit 0 on a fixed image, exit = failed-check count
#                            on a pre-#2821 image (non-zero-while-bug).
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=/dev/null
source "$COMMON_SH"

begin_suite "virtual-no-transfer-2821"

SETUP_OK=1

begin_test "Nexus source bootstrap (EULA accept + admin rotation, per-slot instance)"
if bash "${HERE}/nexus_bootstrap.sh"; then
  pass
else
  SETUP_OK=0
  fail "nexus_bootstrap.sh failed on slot ${DTF_SLOT} (see stdout above)"
fi

begin_test "Seed group + members into Nexus: 2 raw hosted members + a raw group over them"
if [ "$SETUP_OK" = "1" ] && bash "${HERE}/nexus_seed.sh"; then
  pass
else
  SETUP_OK=0
  fail "nexus_seed.sh failed (or bootstrap already failed) on slot ${DTF_SLOT}"
fi

begin_test "#2821 migrate -> assert: group becomes an AK virtual repo with correlated members but ZERO artifact rows / storage objects of its own (members still transfer)"
if [ "$SETUP_OK" = "1" ]; then
  rc=0; bash "${HERE}/assert.sh" || rc=$?
  if [ "$rc" -eq 0 ]; then
    pass
  else
    fail "virtual-no-transfer oracle reported ${rc} failed #2821 positive check(s) on ${BASE_URL} (virtual repo accrued its own bytes; pre-#2821 the members' aggregated bytes were copied into the virtual repo); see stdout above"
  fi
else
  fail "skipped: Nexus setup failed earlier in the suite"
fi

end_suite
