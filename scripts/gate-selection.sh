#!/usr/bin/env bash
# gate-selection.sh - check the release gate's only_jobs input against the
# workflow and say what the run needs (artifact-keeper-test#830).
#
# A candidate rerun (artifact-keeper#6076) runs only the gate jobs, and the
# single DTF legs, that did not pass in the run it follows up. It names them in
# `only_jobs`: gate job ids, and `dtf-gate/<group>` for one leg of the dtf-gate
# matrix. Every job's `if:` matches its own id against that list, so a typo
# would select nothing and a subset run would pass having run nothing. This
# refuses any token that is not a job, or not a dtf-gate group, of the workflow
# file in this checkout, before anything is deployed. validate-gate-inputs.sh
# has already checked the shape.
#
# It also decides whether the run needs the cluster. Only these selected jobs
# run without it: version-set-integrity, format-tests-registration-check,
# build-dtf-probes, dtf-gate (and its legs), dtf-advisory and collect-results.
# A selection made only of those skips clean-install-smoke and therefore
# deploy, every cluster suite and teardown's namespace delete. Anything else
# selected (teardown included) deploys the stack as a full run does.
# clean-install-smoke-with-deps counts only when run_smoke_with_deps is true:
# otherwise it skips by design (and a rerun selects it because the original's
# copy shows 'skipped'), so it must not cost a deploy.
#
# Inputs (environment):
#   GATE_ONLY_JOBS  the only_jobs input; empty = the full gate
#   GATE_WORKFLOW   the gate workflow file (default .github/workflows/release-gate.yml)
#   GATE_RUN_SMOKE_WITH_DEPS  the run_smoke_with_deps input ('true' or not)
#   GITHUB_OUTPUT   where `subset=` and `cluster=` are written (optional)
#
# Exit: 0 = selection valid (or empty), 1 = a token names nothing.
set -uo pipefail

ONLY="${GATE_ONLY_JOBS:-}"
WF="${GATE_WORKFLOW:-.github/workflows/release-gate.yml}"
OUT="${GITHUB_OUTPUT:-/dev/null}"

NO_CLUSTER=" version-set-integrity format-tests-registration-check build-dtf-probes dtf-gate dtf-advisory collect-results "

if [[ -z "$ONLY" ]]; then
  echo "gate-selection: full gate (only_jobs is empty)"
  printf 'subset=false\ncluster=true\n' >> "$OUT"
  exit 0
fi
[[ -f "$WF" ]] || { echo "::error title=Gate selection::cannot read ${WF}" >&2; exit 1; }

# Job ids: the two-space-indented keys under `jobs:`.
jobs="$(awk '/^jobs:/{in_jobs=1; next} in_jobs && /^[^ #]/{in_jobs=0} in_jobs && /^  [a-z0-9][a-z0-9-]*:[[:space:]]*$/{sub(/:.*/, ""); gsub(/ /, ""); print}' "$WF")"
# dtf-gate's matrix groups: `- group: <name>` lines inside that job only.
groups="$(awk '/^  dtf-gate:[[:space:]]*$/{in_job=1; next} in_job && /^  [a-z0-9][a-z0-9-]*:[[:space:]]*$/{in_job=0} in_job && /^[[:space:]]+- group:[[:space:]]/{sub(/^[[:space:]]+- group:[[:space:]]*/, ""); sub(/[[:space:]]*(#.*)?$/, ""); print}' "$WF")"
[[ -n "$jobs" && -n "$groups" ]] || { echo "::error title=Gate selection::could not read the job ids or the dtf-gate groups from ${WF}" >&2; exit 1; }

bad=0
cluster=false
read -r -a tokens <<<"$ONLY"
for t in "${tokens[@]}"; do
  id="${t%%/*}"
  if ! grep -qxF -- "$id" <<<"$jobs"; then
    echo "::error title=Gate selection::only_jobs names '${t}', but ${WF} has no job '${id}'." >&2
    bad=1; continue
  fi
  if [[ "$t" == */* ]]; then
    group="${t#*/}"
    if [[ "$id" != dtf-gate ]]; then
      echo "::error title=Gate selection::only_jobs names '${t}': only dtf-gate legs can be selected one by one; select '${id}' for the whole job." >&2
      bad=1; continue
    fi
    if ! grep -qxF -- "$group" <<<"$groups"; then
      echo "::error title=Gate selection::only_jobs names '${t}', but dtf-gate has no matrix group '${group}'." >&2
      bad=1; continue
    fi
  fi
  if [[ "$id" == clean-install-smoke-with-deps && "${GATE_RUN_SMOKE_WITH_DEPS:-false}" != true ]]; then
    continue
  fi
  [[ "$NO_CLUSTER" == *" ${id} "* ]] || cluster=true
done
[[ "$bad" -eq 0 ]] || exit 1

echo "gate-selection: subset run of ${#tokens[@]} token(s): ${ONLY}"
echo "gate-selection: cluster deploy needed: ${cluster}"
printf 'subset=true\ncluster=%s\n' "$cluster" >> "$OUT"
