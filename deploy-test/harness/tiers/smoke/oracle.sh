#!/usr/bin/env bash
# =============================================================================
# tiers/smoke/oracle.sh — real push -> pull -> scan smoke (filesystem/single)
# =============================================================================
# Reuses the existing corpus suite tests/release-gate/test-real-flow-smoke.sh:
# a real npm publish (client wire format) -> npm pack pull-back -> trigger a
# security scan -> poll to a terminal state -> assert numeric findings_count.
# run.sh has already exported BASE_URL / ADMIN_USER / ADMIN_PASS / RUN_ID /
# RELEASE_GATE=1 / JUNIT_OUTPUT_DIR, so the suite sources common.sh and runs
# unchanged. It writes its own JUnit into results/smoke/.
# =============================================================================
set -uo pipefail
: "${AK_TEST_ROOT:?}"; : "${BASE_URL:?}"
SUITE="${AK_TEST_ROOT}/tests/release-gate/test-real-flow-smoke.sh"
if [ ! -f "$SUITE" ]; then
  echo "!! corpus smoke suite not found: ${SUITE}" >&2
  exit 1
fi
echo ">> smoke oracle -> ${SUITE}"
bash "$SUITE"
