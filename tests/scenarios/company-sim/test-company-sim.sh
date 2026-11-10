#!/usr/bin/env bash
# test-company-sim.sh - run-suite.sh entry point for the Halcyon Robotics
# company simulation (./scripts/run-suite.sh --suite scenarios-company-sim).
#
# Founds the company (00-found-company.sh), then runs every role in parallel
# (run-roles.sh). Each step writes its own JUnit suites (company-sim-found,
# company-sim-<role>); this wrapper adds company-sim-scenario with one case
# per step, sourced through lib.sh -> tests/lib/common.sh like every suite.
#
# The whole scenario takes several minutes; run-suite.sh gives this suite a
# longer default per-script timeout (see SUITE_TIMEOUT_DEFAULT there).

source "$(dirname "$0")/lib.sh"   # sources tests/lib/common.sh

cs_begin scenario --no-personas

if bash "${CS_DIR}/00-found-company.sh"; then
  cs_record "found the company (00-found-company.sh)" PASS "personas: ${PERSONAS_ENV}"
else
  rc=$?
  cs_record "found the company (00-found-company.sh)" FAIL "exit ${rc}; roles not run"
  end_suite
fi

if [ -z "$(find "${CS_DIR}/roles" -maxdepth 1 -name '*.sh' ! -name '_*' -type f)" ]; then
  cs_record "run the roles (run-roles.sh)" SKIP "no role scripts yet (only roles/_template.sh)"
else
  if bash "${CS_DIR}/run-roles.sh"; then
    cs_record "run the roles (run-roles.sh)" PASS "$(grep -c '|PASS|' "${COMPANY_SIM_STATE_DIR}/CHECKS.txt" || true) role checks passed"
  else
    rc=$?
    cs_record "run the roles (run-roles.sh)" FAIL "exit ${rc}; see ${COMPANY_SIM_STATE_DIR}/CHECKS.txt and logs/"
  fi
fi

end_suite
