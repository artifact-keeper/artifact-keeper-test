#!/usr/bin/env bash
# roles/<role>.sh - <Persona name>, <job title> at Halcyon Robotics.
#
# Copy this file to roles/<role>.sh (the role name from ROLES.md, e.g.
# firmware.sh) and fill in the workday. run-roles.sh runs every roles/*.sh
# except files starting with '_' in parallel, after 00-found-company.sh.
#
# Contract (tests/lib/common.sh, via lib.sh):
#   - every check goes through cs_expect / cs_expect_body / cs_record, which
#     print PASS/FAIL, write the JUnit case and emit the CHECK line;
#   - names you create carry RUN_ID: build them from $HAL (hal-<rid>) or the
#     HAL_REPO_* keys in personas.env, never a bare constant;
#   - finish with cs_end (writes $JUNIT_OUTPUT_DIR/company-sim-<role>.xml and
#     exits 0 on all-pass, non-zero otherwise).
#   - errexit is off: common.sh sets `set -euo pipefail`, and lib.sh turns
#     `-e` back off right after sourcing it, so a FAILed check never ends the
#     day. Do not add `set +e` or `|| true` after checks. cs_expect still
#     returns 1 on FAIL: use `if cs_expect ...; then <follow-up>; fi` to skip
#     follow-ups that only make sense after a PASS. -u and pipefail stay on.
#   - barriers count only when signalled during this run (CS_RUN_START, see
#     lib.sh); wait with cs_wait NAME (default CS_BARRIER_TIMEOUT, 600 s).
#
# Rules for role scripts:
#   - Act ONLY as your own persona(s) (jwt:/basic:/token: auth specs). The
#     bootstrap admin (auth spec "admin") is for the founder; a role uses it
#     only where ROLES.md says so (reading back state to verify, never to
#     make a check pass).
#   - Expected codes come from the code and the 1.12.0 notes. Cite the source
#     in the check name or note (e.g. "#5458", "repository-visibility.md").
#   - Do not modify objects other roles depend on (README "Shared objects").
#     Publish under names that include your role, e.g. ${HAL}-fw-<thing>.
#   - Wait on other roles only through cs_wait, with a timeout, and record
#     a FAIL ("waited for X") if it expires; never sleep for a fixed time to
#     "let the other role finish".
#   - A deviation that is already filed upstream is a WARN citing the issue;
#     anything else unexpected is a FAIL. Never loosen an expected code to
#     make a run green.
#
# Run one role alone (after the founder):
#   bash tests/scenarios/company-sim/run-roles.sh --only <role>

source "$(dirname "$0")/../lib.sh"

cs_begin template            # <- your role name; JUnit suite company-sim-<role>
auth_admin                   # only if this role needs the admin token at all

# ---------------------------------------------------------------------------
# Morning: sign in
# ---------------------------------------------------------------------------
if cs_login FW_DEV; then
  cs_record "FW_DEV signs in" PASS "JWT issued"
else
  cs_record "FW_DEV signs in" FAIL "login HTTP ${CS_STATUS}" "${CS_BODY:0:300}"
  cs_end
fi

# ---------------------------------------------------------------------------
# Task 1: <what the persona does>
# Expected: <status> because <AK behaviour, file:line or #issue>
# ---------------------------------------------------------------------------
cs_http GET "/api/v1/repositories/${HAL_REPO_FW_CARGO_LOCAL}" jwt:FW_DEV
cs_expect "firmware engineer sees the firmware cargo repo" 200

# Publishing over a native route, using a lib.sh wire helper:
#   cs_publish_cargo "$HAL_REPO_FW_CARGO_LOCAL" "${HAL}-example" 0.1.0 basictoken:FW_DEV:HAL_FW_DEV_TOKEN
#   cs_expect "publish crate with personal token" "200"

# ---------------------------------------------------------------------------
# Things that should NOT work
# ---------------------------------------------------------------------------
cs_http GET "/api/v1/repositories/${HAL_REPO_WEB_NPM_LOCAL}" jwt:FW_DEV
cs_expect "firmware engineer cannot see web-npm-local (deny-by-hide, repository-visibility.md)" 404

# ---------------------------------------------------------------------------
# Sync points with other roles (only where ROLES.md defines one)
# ---------------------------------------------------------------------------
#   cs_signal "fw-released-1.1.0"
#   if cs_wait "leo-offboarded"; then ...; else
#     cs_record "waited for platform-admin to offboard leo" FAIL "barrier timeout"; fi

cs_end
