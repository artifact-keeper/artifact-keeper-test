#!/usr/bin/env bash
# dtf-advisory-outcome.sh - run a DTF advisory group and report its outcome
# honestly: INFRA as a warning, a product FAIL as a red step
# (artifact-keeper-test#378).
#
# release-gate.yml's dtf-advisory job is SOFT: job-level continue-on-error
# keeps a red leg from failing the called workflow, so it never blocks
# certification. That softness cannot see exit codes, so on its own it showed
# "the harness could not pull skopeo" and "the candidate lost a migration
# assertion" as the same red leg. This wrapper maps run-tiers.sh's aggregate
# exit code (deploy-test/harness/run-tiers.sh, lib/exit_codes.sh) instead:
#
#   0       PASS. Step succeeds.
#   10, 11  INFRA: the candidate could not be pulled (10), or some tier could
#           not be evaluated and none FAILed (11). Nothing was learned about
#           the candidate. Retried ONCE, re-running only the INFRA tiers (all
#           tiers for 10, since none ran), and only when the first pass took
#           at most DTF_ADVISORY_RETRY_BUDGET_S seconds, so the retry (a subset
#           of what already ran) fits the job timeout. Still INFRA after that:
#           a ::warning, a job-summary line, and the step SUCCEEDS.
#   other   product FAIL (an oracle assertion, rc 1; a stack that never came
#           healthy, rc 7; a harness wiring bug, rc 2-6). A ::error and a
#           job-summary line, and the step exits with that code so the leg is
#           red. Still advisory: the job's continue-on-error is what keeps it
#           off certification, not this script.
#
# A product FAIL wins: run-tiers.sh exits 1 when any tier FAILed, even if
# other tiers were INFRA, so such a group is never retried or softened.
#
# Older tests refs: the gate's working tree can be a release/X.Y.x suite
# (scripts/switch-tests-ref.sh) whose run-tiers.sh predates #378 and exits 1
# for INFRA too. It does not create DTF_INFRA_TIERS_FILE, and then rc 1 cannot
# be classified; it is reported as a FAIL (red, as before), with the reason.
#
# Usage: dtf-advisory-outcome.sh --backend-image <img> <tier> [<tier> ...]
# Environment:
#   DTF_GROUP                    matrix group name for messages (default: dtf)
#   RUN_TIERS                    driver (default: deploy-test/harness/run-tiers.sh)
#   DTF_ADVISORY_RETRY_BUDGET_S  retry only if the first pass took <= this
#                                (default 1500; the job timeout is 60 min)
#   GITHUB_STEP_SUMMARY          job summary file (optional)
set -uo pipefail

GROUP="${DTF_GROUP:-dtf}"
RUN_TIERS="${RUN_TIERS:-deploy-test/harness/run-tiers.sh}"
BUDGET="${DTF_ADVISORY_RETRY_BUDGET_S:-1500}"
SUMMARY="${GITHUB_STEP_SUMMARY:-/dev/null}"

if [ "${1:-}" != "--backend-image" ] || [ -z "${2:-}" ] || [ $# -lt 3 ]; then
  echo "usage: $0 --backend-image <img> <tier> [<tier> ...]" >&2
  exit 2
fi
IMG="$2"; shift 2
TIERS=("$@")

INFRA_FILE="$(mktemp)"
trap 'rm -f "$INFRA_FILE"' EXIT

# run_pass <tier>... : runs the driver, sets rc and infra_tiers.
run_pass() {
  rm -f "$INFRA_FILE"
  DTF_INFRA_TIERS_FILE="$INFRA_FILE" "$RUN_TIERS" --backend-image "$IMG" "$@"
  rc=$?
  classified=1
  [ -f "$INFRA_FILE" ] || classified=0
  infra_tiers=()
  if [ "$classified" -eq 1 ]; then
    mapfile -t infra_tiers < "$INFRA_FILE"
  fi
}

is_infra() { [ "$1" -eq 10 ] || [ "$1" -eq 11 ]; }

report_fail() {
  local rc="$1" note="$2"
  echo "::error title=DTF advisory product FAIL (advisory, not blocking)::${GROUP}: run-tiers.sh exited ${rc}${note}; the candidate was evaluated and lost. See the DTF tier summary in this log. This leg does not block certification."
  echo "- dtf-advisory \`${GROUP}\`: **product FAIL** (run-tiers.sh exit ${rc}${note}); advisory, not blocking" >> "$SUMMARY"
  exit "$rc"
}

report_infra() {
  local rc="$1" note="$2" which="$3"
  echo "::warning title=DTF advisory INFRA::${GROUP}: run-tiers.sh exited ${rc}${note}; the harness could not evaluate ${which}, so the candidate is UNJUDGED there. Not a product verdict."
  echo "- dtf-advisory \`${GROUP}\`: INFRA, candidate unjudged on ${which} (run-tiers.sh exit ${rc}${note})" >> "$SUMMARY"
  exit 0
}

start=$SECONDS
run_pass "${TIERS[@]}"
elapsed=$(( SECONDS - start ))

if [ "$rc" -eq 0 ]; then
  echo "- dtf-advisory \`${GROUP}\`: PASS" >> "$SUMMARY"
  exit 0
fi
if [ "$classified" -eq 0 ]; then
  if [ "$rc" -eq 10 ]; then
    report_infra 10 ", no retry: this tests ref's run-tiers.sh predates #378" "every tier (candidate image not pullable)"
  fi
  report_fail "$rc" ", unclassified: this tests ref's run-tiers.sh predates #378 and exits 1 for INFRA too"
fi
if ! is_infra "$rc"; then
  report_fail "$rc" ""
fi

if [ "$rc" -eq 10 ]; then
  retry=("${TIERS[@]}")
else
  retry=("${infra_tiers[@]}")
fi
first_rc=$rc
if [ ${#retry[@]} -eq 0 ]; then
  report_infra "$rc" ", no retry: run-tiers.sh named no INFRA tier" "this group"
fi
if [ "$elapsed" -gt "$BUDGET" ]; then
  report_infra "$rc" ", no retry: first pass took ${elapsed}s, over the ${BUDGET}s retry budget" "${retry[*]}"
fi

echo "::group::dtf-advisory ${GROUP}: retrying INFRA tier(s) once: ${retry[*]}"
run_pass "${retry[@]}"
echo "::endgroup::"

if [ "$rc" -eq 0 ]; then
  echo "::warning title=DTF advisory INFRA::${GROUP}: run-tiers.sh exited ${first_rc} on the first pass (INFRA on ${retry[*]}) and passed on one retry of those tiers."
  echo "- dtf-advisory \`${GROUP}\`: PASS after one retry of INFRA tier(s) ${retry[*]} (first pass exit ${first_rc})" >> "$SUMMARY"
  exit 0
fi
if is_infra "$rc"; then
  report_infra "$rc" " after one retry" "${infra_tiers[*]:-${retry[*]}}"
fi
report_fail "$rc" " on the retry of INFRA tier(s) ${retry[*]}"
