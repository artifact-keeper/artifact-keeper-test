#!/usr/bin/env bash
# =============================================================================
# tiers/isolation/oracle.sh — cloud cross-tenant isolation oracle (S3 storage)
# =============================================================================
# Wraps the vendored, fail-closed prove.sh (A-F) under the run.sh contract:
# run.sh has already stood up the s3 profile-set and exported BASE_URL,
# DB_CONTAINER, ADMIN_PASS, RELEASE_GATE=1, JUNIT_OUTPUT_DIR.
#
# prove.sh is self-contained (it does its own admin/alice setup + DB probes via
# `docker exec $DB_CONTAINER psql`) and returns:
#   * exit 0  on a FIXED image (isolation holds) — matrix row 1 COVERED
#   * exit 1  on a pre-fix image (cross-tenant leak/regression gate-fails)
#   * exit $DTF_EXIT_INFRA when it could not BUILD the fixture (wrong storage
#     topology, admin/alice login failed, the soft-delete precondition matched
#     no rows). That says nothing about the candidate, so it is mapped to
#     infra_fail — RED, but never reported as a regression (#323).
# We source common.sh only to emit the tier's JUnit and honor RELEASE_GATE.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=/dev/null
source "$COMMON_SH"

begin_suite "isolation-cross-tenant-s3"

begin_test "S3 cross-tenant read/write isolation (prove.sh A-F: cross-repo read, write-poison, checksum/metadata sidecar, soft-delete carve-out, row-less #2574/#2584)"
LABEL="dtf-isolation-slot${DTF_SLOT:-x}"
ADMIN_PASS="${ADMIN_PASS}" bash "${HERE}/prove.sh" "$BASE_URL" "$DB_CONTAINER" "$LABEL"
PROVE_RC=$?
if [ "$PROVE_RC" -eq 0 ]; then
  pass
elif [ "$PROVE_RC" -eq "$DTF_EXIT_INFRA" ]; then
  infra_fail "cross-tenant isolation gate could not be SET UP on ${BASE_URL} (prove.sh exit ${PROVE_RC}); no isolation assertion was evaluated" \
             "see the GATE-INFRA line in the stdout above"
else
  fail "cross-tenant isolation GATE failed (prove.sh reported one or more leaks/regressions on ${BASE_URL}); see stdout above" \
       "prove.sh exit ${PROVE_RC}"
fi

end_suite
