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
#   * exit 1  on a pre-fix image (11 cross-tenant leak/regression gate-fails)
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
if ADMIN_PASS="${ADMIN_PASS}" bash "${HERE}/prove.sh" "$BASE_URL" "$DB_CONTAINER" "$LABEL"; then
  pass
else
  fail "cross-tenant isolation GATE failed (prove.sh reported one or more leaks/regressions on ${BASE_URL}); see stdout above"
fi

end_suite
