#!/usr/bin/env bash
# =============================================================================
# harness/lib/exit_codes.sh — the DTF exit-code contract (artifact-keeper-test#323)
# =============================================================================
# ONE place that says what a tier's exit code means, sourced by run.sh,
# run-tiers.sh and (when running under the DTF) tests/lib/common.sh, so the
# oracle that raises a code and the driver that labels it can never drift.
#
# WHY THIS EXISTS
# The first real blocking run of the DTF release gate reported four RED tiers
# as "oracle asserted a regression" when every one of them was a harness/setup
# failure and the candidate was clean. A blocking gate that cries "regression"
# at its own broken setup trains operators to override it — the precise
# anti-pattern the release-freeze policy exists to prevent. Infra failures stay
# fail-closed (RED), they just have to be TRUE.
#
#   0   PASS      — the oracle ran and every assertion held.
#   1   FAIL      — the oracle ran and an assertion about the CANDIDATE fired.
#                   This, and only this, is a product verdict.
#   2   run.sh    — bad argument.
#   3   run.sh    — profile overlay not found.
#   4   run.sh    — tier manifest missing/incomplete.
#   5   run.sh    — artifact-keeper-test corpus not locatable.
#   6   run.sh    — no free DTF slot.
#   7   run.sh    — compose stack never became healthy (candidate or sidecar).
#   10  run-tiers — the candidate image could not be pulled and is not local.
#   11  ORACLE INFRA/SETUP — the oracle started but could NOT evaluate the tier:
#                   probe binary missing/unbuildable, token mint returned
#                   empty/4xx, a fixture precondition was not met, the backend
#                   was unreachable. Nothing has been learned about the
#                   candidate. RED (a required tier that cannot run cannot
#                   certify) but NEVER labeled a regression.
#
# Codes 2-7 and 10 are raised by the drivers themselves BEFORE/AROUND the
# oracle; 11 is the code an ORACLE raises, which is why it must not reuse any
# of them.
# =============================================================================

# Exit code an oracle uses for "I could not evaluate this tier".
# Keep in sync with tests/lib/common.sh (which sources this file when DTF_DIR
# is exported, and falls back to the same literal when used standalone).
# shellcheck disable=SC2034  # consumed by the sourcing scripts, not this file
DTF_EXIT_INFRA=11
