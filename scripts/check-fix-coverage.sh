#!/usr/bin/env bash
# check-fix-coverage.sh - verify the backend issues each DTF tier claims to
# cover, and report whether the tier is wired into the release gate.
#
# A tier's manifest names the artifact-keeper issues it proves with
#   COVERS="5502 5509"
# and each covered issue needs at least one case in the tier labelled
#   begin_test "FIX #5502: ..."
# (controls are `CONTROL: ...`). The backend's release preflight (check 7,
# artifact-keeper scripts/ci/check-e2e-proof.py milestone) reads the same
# COVERS lines and the same gate matrices, and counts a closed bug as proven
# only when a tier that COVERS it is in dtf-gate or dtf-advisory. A COVERS
# number with no FIX case is a claim nothing asserts, so it fails here first.
#
# This runs no tier and touches no container.
#
# Usage: scripts/check-fix-coverage.sh [--require-wired] [--issue N]
#   --require-wired  also fail when a tier with COVERS is in neither gate
#                    matrix (the wiring PR for a wave should pass this)
#   --issue N        print only the tiers that cover backend issue N
#
# Exits 1 if a COVERS line is malformed or names an issue with no FIX case
# (or, with --require-wired, a covering tier is unwired); 0 otherwise.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TIERS_DIR="${TIERS_DIR:-${REPO_ROOT}/deploy-test/harness/tiers}"
GATE_WORKFLOW="${GATE_WORKFLOW:-${REPO_ROOT}/.github/workflows/release-gate.yml}"

require_wired=0
only_issue=""
while [ $# -gt 0 ]; do
  case "$1" in
    --require-wired) require_wired=1; shift ;;
    --issue) only_issue="${2:-}"; shift 2 ;;
    -h|--help) sed -n '2,25p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

[ -d "$TIERS_DIR" ] || { echo "no tiers directory at $TIERS_DIR" >&2; exit 2; }
[ -f "$GATE_WORKFLOW" ] || { echo "no gate workflow at $GATE_WORKFLOW" >&2; exit 2; }

# tier -> job, for every tier named in a dtf-gate / dtf-advisory matrix row.
gate_map="$(awk '
  /^  [A-Za-z0-9_-]+:[[:space:]]*$/ { job = $1; sub(":", "", job); next }
  (job == "dtf-gate" || job == "dtf-advisory") && $1 == "tiers:" {
    for (i = 2; i <= NF; i++) { t = $i; gsub(/["\047]/, "", t); print t, job }
  }' "$GATE_WORKFLOW" | sort -u -k1,1)"

gate_of() { printf '%s\n' "$gate_map" | awk -v t="$1" '$1 == t { print $2; exit }'; }

problems=0
tiers_with=0
issues_total=0
unwired=0
printf '%-44s %-14s %s\n' "TIER" "GATE" "COVERS (FIX cases)"
for manifest in "$TIERS_DIR"/*/manifest; do
  tier="$(basename "$(dirname "$manifest")")"
  line="$(grep -E '^COVERS=' "$manifest" || true)"
  [ -z "$line" ] && continue
  covers="$(printf '%s' "$line" | sed -E 's/^COVERS=//; s/^["\x27]//; s/["\x27][[:space:]]*$//')"
  if ! printf '%s' "$covers" | grep -qE '^[0-9]+( [0-9]+)*$'; then
    echo "FAIL: $tier: malformed COVERS line '$line' (want COVERS=\"N M\", backend issue numbers)"
    problems=$((problems + 1))
    continue
  fi
  if [ -n "$only_issue" ] && ! printf ' %s ' "$covers" | grep -qF " $only_issue "; then
    continue
  fi
  tiers_with=$((tiers_with + 1))
  gate="$(gate_of "$tier")"
  # FIX cases may live in the oracle or in any script the tier dir holds.
  fixes="$(grep -rhoE "begin_test[[:space:]]+[\"']FIX #[0-9]+" "$(dirname "$manifest")" --include='*.sh' \
             | grep -oE '[0-9]+$' | sort -un | tr '\n' ' ')"
  shown=""
  for n in $covers; do
    issues_total=$((issues_total + 1))
    if printf ' %s ' "$fixes" | grep -qF " $n "; then
      shown="$shown #$n"
    else
      shown="$shown #$n(NO FIX CASE)"
      echo "FAIL: $tier: COVERS #$n but has no begin_test \"FIX #$n: ...\" case"
      problems=$((problems + 1))
    fi
  done
  if [ -z "$gate" ]; then
    gate="not wired"
    unwired=$((unwired + 1))
    if [ "$require_wired" = 1 ]; then
      echo "FAIL: $tier: COVERS$shown but is in neither dtf-gate nor dtf-advisory"
      problems=$((problems + 1))
    fi
  fi
  printf '%-44s %-14s%s\n' "$tier" "$gate" "$shown"
done

echo
echo "$tiers_with tier(s) with COVERS, $issues_total issue claim(s), $unwired tier(s) not wired into the release gate."
if [ "$problems" -gt 0 ]; then
  echo "check-fix-coverage: $problems problem(s)."
  exit 1
fi
echo "check-fix-coverage: OK"
