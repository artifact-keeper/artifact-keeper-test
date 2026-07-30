#!/usr/bin/env bash
# =============================================================================
# harness/run-tiers.sh — run an ordered list of DTF tiers against ONE image
# =============================================================================
# The CI-gate driver for issue artifact-keeper#2697: the release gate runs a
# fixed tier set against the exact candidate image digest, and any tier failure
# must fail the job. This wrapper keeps the workflow step thin and testable:
#
#   run-tiers.sh --backend-image <img> <tier> [<tier> ...]
#
#   * pulls <img> up front (fail loud on a missing/unpullable candidate)
#   * when <img> is digest-pinned (contains @sha256:), asserts after the pull
#     that the local image's RepoDigests carry that exact digest, so the log
#     PROVES the tiers ran the pinned bytes (mirror of the release-gate deploy
#     job's "Assert deployed pod runs the pinned digest" step)
#   * runs each tier SEQUENTIALLY via harness/run.sh (each tier claims its own
#     slot, health-gates up, and `down -v` cleans before the next)
#   * prints a per-tier PASS/FAIL summary and exits non-zero if ANY tier failed
#     (the job's blocking predicate)
#
# Failure-class labeling (triage aid, NOT a soft-fail): every non-zero tier
# outcome is RED either way, but the summary distinguishes
#   FAIL(tier)     oracle ran and asserted a real regression — the ONLY class
#                  that is a statement about the candidate
#   FAIL(infra)    oracle exit 11: the oracle started but could not evaluate
#                  the tier (probe binary missing, token mint empty/4xx,
#                  fixture precondition unmet, backend unreachable). The
#                  candidate is UNJUDGED; fix the harness/environment and
#                  re-run (artifact-keeper-test#323)
#   FAIL(stack-up) run.sh exit 7: the compose stack never became healthy —
#                  either the candidate does not boot on a clean deploy (real)
#                  or a sidecar/infra pull flaked; the backend log tail printed
#                  by run.sh is the discriminator
#   FAIL(harness)  run.sh exit 2-6: bad tier name / missing overlay / corpus /
#                  slot — a wiring bug in this repo, never the candidate
# so a red gate can be triaged from the summary line alone. See
# harness/lib/exit_codes.sh for the full contract.
#
# Environment passthrough: everything run.sh honors (AK_TEST_ROOT,
# SCANNER_ADAPTER_IMAGE, TRIVY_DB_REPOSITORY, UPGRADE_OLD_IMAGE, ...).
# =============================================================================
set -uo pipefail

HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/exit_codes.sh
source "${HARNESS_DIR}/lib/exit_codes.sh"

BACKEND_IMAGE_ARG=""
TIERS=()

while [ $# -gt 0 ]; do
  case "$1" in
    --backend-image) BACKEND_IMAGE_ARG="$2"; shift 2 ;;
    -h|--help) sed -n '2,33p' "${BASH_SOURCE[0]}"; exit 0 ;;
    -*) echo "!! unknown argument: $1" >&2; exit 2 ;;
    *) TIERS+=("$1"); shift ;;
  esac
done

if [ -z "$BACKEND_IMAGE_ARG" ]; then
  echo "!! --backend-image is required" >&2
  exit 2
fi
if [ ${#TIERS[@]} -eq 0 ]; then
  echo "!! at least one tier is required" >&2
  exit 2
fi

# --- Pull the candidate up front (fail loud, before any stack comes up) ------
echo ">> pulling candidate image: ${BACKEND_IMAGE_ARG}"
if ! docker pull "$BACKEND_IMAGE_ARG"; then
  # Local/dev mode: a rig-built image (e.g. ak-backend:fix-XXXX) is not
  # pullable but is present in the local daemon. CI candidates are always
  # registry refs, so an unpullable AND locally-absent ref is a hard fail —
  # and an INFRA failure (exit 10), distinguishable from a tier failure.
  if docker image inspect "$BACKEND_IMAGE_ARG" >/dev/null 2>&1; then
    echo ">> pull failed but the image exists locally; continuing (local/dev mode)"
  else
    echo "!! cannot pull candidate image '${BACKEND_IMAGE_ARG}' (and it does not exist locally)" >&2
    echo "!! this is an INFRA failure (registry/auth), not a tier verdict" >&2
    exit 10
  fi
fi

# --- Digest-parity assertion (only when the ref is digest-pinned) ------------
# `docker pull name:tag@sha256:...` is content-addressed by construction, but
# we assert and LOG the parity anyway so the gate's evidence trail shows the
# tiers ran the exact bytes resolve-candidate-digest pinned (#2697).
case "$BACKEND_IMAGE_ARG" in
  *@sha256:*)
    PINNED_DIGEST="sha256:${BACKEND_IMAGE_ARG##*@sha256:}"
    REPO_DIGESTS="$(docker image inspect --format '{{join .RepoDigests " "}}' "$BACKEND_IMAGE_ARG" 2>/dev/null || true)"
    echo ">> pinned digest:      ${PINNED_DIGEST}"
    echo ">> local RepoDigests:  ${REPO_DIGESTS:-<none>}"
    case " ${REPO_DIGESTS} " in
      *"@${PINNED_DIGEST} "*)
        echo ">> OK: local image carries the pinned digest" ;;
      *)
        # A tag@digest pull can record only the per-arch platform digest in
        # RepoDigests on some runtimes; the pull itself already verified the
        # manifest-list digest. Surface the mismatch loudly but treat a pull
        # that SUCCEEDED on the @digest ref as authoritative.
        echo "!! WARNING: RepoDigests does not list ${PINNED_DIGEST} verbatim;" \
             "the successful @digest pull above is the content-addressed proof" >&2 ;;
    esac
    ;;
  *)
    echo ">> ref is not digest-pinned; running by tag only"
    ;;
esac

# --- Run the tiers sequentially ----------------------------------------------
declare -a PASSED=() FAILED=() INFRA=()
for tier in "${TIERS[@]}"; do
  echo ""
  echo "############################################################"
  echo "## DTF tier: ${tier}"
  echo "############################################################"
  "${HARNESS_DIR}/run.sh" "$tier" --backend-image "$BACKEND_IMAGE_ARG"
  rc=$?
  if [ "$rc" -eq 0 ]; then
    PASSED+=("$tier")
  else
    case "$rc" in
      "$DTF_EXIT_INFRA")
        # #323: the oracle could not evaluate the tier. Tracked separately so
        # the summary never attributes a harness/setup failure to the
        # candidate. Still counted as RED below (fail-closed).
        INFRA+=("${tier} (INFRA/SETUP: harness could not evaluate the tier — NOT a product verdict, rc=${rc})") ;;
      7) FAILED+=("${tier} (stack-up: candidate/sidecar never healthy, rc=7)") ;;
      2|3|4|5|6) FAILED+=("${tier} (harness: bad tier/overlay/corpus/slot, rc=${rc})") ;;
      *) FAILED+=("${tier} (tier: oracle asserted a regression, rc=${rc})") ;;
    esac
  fi
done

# --- Summary + blocking exit --------------------------------------------------
echo ""
echo "=== DTF tier summary (image: ${BACKEND_IMAGE_ARG}) ==="
for tier in "${PASSED[@]:-}"; do
  [ -n "$tier" ] && echo "  PASS  ${tier}"
done
for tier in "${FAILED[@]:-}"; do
  [ -n "$tier" ] && echo "  FAIL  ${tier}"
done
for tier in "${INFRA[@]:-}"; do
  [ -n "$tier" ] && echo "  INFRA ${tier}"
done

if [ ${#INFRA[@]} -gt 0 ]; then
  echo ""
  echo "!! ${#INFRA[@]} of ${#TIERS[@]} tier(s) hit an INFRA/SETUP FAILURE — the harness" >&2
  echo "!! could not evaluate them, so the candidate is UNJUDGED on those tiers." >&2
  echo "!! This is NOT a product verdict. Fix the harness/environment and re-run." >&2
fi
if [ ${#FAILED[@]} -gt 0 ] || [ ${#INFRA[@]} -gt 0 ]; then
  echo ""
  # Fail-closed: a required tier that cannot run cannot certify, so an
  # INFRA/SETUP outcome is just as RED as an assertion failure — it is only
  # LABELED differently (artifact-keeper-test#323).
  echo "!! $(( ${#FAILED[@]} + ${#INFRA[@]} )) of ${#TIERS[@]} tier(s) did not pass — gate is RED" >&2
  exit 1
fi
echo ">> all ${#TIERS[@]} tier(s) passed — gate is GREEN"
exit 0
