#!/usr/bin/env bash
# selftest-release-gate-verdict.sh - every job in release-gate.yml either
# counts in the gate's verdict or cannot veto (artifact-keeper-test#359).
#
# Why this exists
# ---------------
# release-gate.yml is a reusable workflow. Its callers (artifact-keeper's
# release-candidate.yml, release.yml) read `needs.release-gate.result`, which is
# the WORKFLOW conclusion: failure if any job concluded failure. The gate's own
# verdict is collect-results' "Gate check" predicate over `needs.<job>.result`.
# The two agree only if every job is one of:
#
#   * VOTING: in `collect-results.needs` AND named in the predicate, so its
#     failure fails collect-results and is attributed there; or
#   * NON-VETOING: job-level `continue-on-error: true`, so its failure leaves
#     the workflow conclusion alone.
#
# A job that is neither holds a veto the verdict knows nothing about.
# pullthrough-tests, teardown and scan-completion-gate-scaffolds-pending all had
# that shape, and v1.7.2-rc.1 lost a release cycle to it.
#
# Also checked, because each is a quieter way for the two signals to drift:
#   * every job the predicate names is in `collect-results.needs` (an unlisted
#     `needs.X.result` evaluates empty, so its clause can never fire);
#   * every job in `collect-results.needs` is in the summary table loop;
#   * teardown runs only when deploy ran and left a run id
#     (artifact-keeper-test#839), so a skipped deploy does not add a red
#     cleanup job that says nothing.
#
# The checker is exercised against fixtures first (a compliant workflow and
# one broken copy per rule), so a checker that stops detecting anything turns
# this red instead of passing the real file.
#
# Usage: bash scripts/selftest-release-gate-verdict.sh [path/to/release-gate.yml]
# Requires: python3 with PyYAML (preinstalled on GitHub-hosted ubuntu runners).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="${1:-${REPO_ROOT}/.github/workflows/release-gate.yml}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cat > "${WORK}/check.py" <<'PY'
import re
import sys

import yaml

GATE_JOB = "collect-results"
# The full-run verdict; the subset-run step ("Gate check - subset run")
# delegates to scripts/gate-subset-verdict.sh, whose lists
# selftest-gate-subset-verdict.sh pins to this predicate.
GATE_STEP = "Gate check - fail if any required suite"


def problems(path):
    with open(path) as fh:
        wf = yaml.safe_load(fh)
    jobs = wf.get("jobs") or {}
    out = []
    gate = jobs.get(GATE_JOB)
    if gate is None:
        return [f"no {GATE_JOB} job"]
    needs = gate.get("needs") or []
    if isinstance(needs, str):
        needs = [needs]
    needs = set(needs)

    steps = gate.get("steps") or []
    check = [s for s in steps if str(s.get("name", "")).startswith(GATE_STEP)]
    if len(check) != 1:
        return [f"{GATE_JOB} must have exactly one step named '{GATE_STEP}...', found {len(check)}"]
    predicate = str(check[0].get("if", ""))
    on_predicate = set(re.findall(r"needs\.([A-Za-z0-9_-]+)\.result", predicate))
    if not on_predicate:
        out.append(f"'{GATE_STEP}' predicate names no needs.<job>.result")

    summary = set()
    for s in steps:
        m = re.search(r"for job in ([^;\n]+);", str(s.get("run", "")))
        if m:
            summary |= set(m.group(1).split())

    for name, job in jobs.items():
        if name == GATE_JOB:
            continue
        coe = job.get("continue-on-error") is True
        voting = name in needs and name in on_predicate
        if not coe and not voting:
            where = []
            if name not in needs:
                where.append(f"not in {GATE_JOB}.needs")
            if name not in on_predicate:
                where.append("not on the gate predicate")
            out.append(
                f"job '{name}' can veto the release without a verdict "
                f"({', '.join(where)}, and no job-level continue-on-error: true)"
            )

    # #839: teardown must not run without a namespace to tear down.
    td = jobs.get("teardown")
    if td is not None:
        cond = re.sub(r"\s+", " ", str(td.get("if", "")))
        for need in ("needs.deploy.result != 'skipped'", "needs.deploy.outputs.run_id != ''"):
            if need not in cond:
                out.append(f"teardown runs without `{need}` in its if: (artifact-keeper-test#839)")

    for name in sorted(on_predicate - needs):
        out.append(f"predicate names '{name}', which is not in {GATE_JOB}.needs (its clause can never fire)")
    for name in sorted(on_predicate - set(jobs)):
        out.append(f"predicate names '{name}', which is not a job in this workflow")
    if summary:
        for name in sorted(needs - summary):
            out.append(f"'{name}' is in {GATE_JOB}.needs but missing from the summary table loop")
    else:
        out.append("no summary table loop ('for job in ...;') found in collect-results")
    return out


if __name__ == "__main__":
    found = problems(sys.argv[1])
    for p in found:
        print(f"  - {p}")
    sys.exit(1 if found else 0)
PY

# ---------------------------------------------------------------------------
# Fixtures: one compliant workflow, then one broken copy per rule.
# ---------------------------------------------------------------------------
write_fixture() { # NAME, body on stdin
  cat > "${WORK}/$1.yml"
}

write_fixture good <<'YML'
on: workflow_call
jobs:
  deploy:
    runs-on: x
    steps: [{run: "true"}]
  suite-a:
    needs: deploy
    runs-on: x
    steps: [{run: "true"}]
  soft:
    needs: deploy
    continue-on-error: true
    runs-on: x
    steps: [{run: "true"}]
  collect-results:
    needs: [deploy, suite-a, soft]
    if: always()
    runs-on: x
    steps:
      - name: Summary
        run: |
          for job in deploy suite-a soft; do echo "$job"; done
      - name: Gate check - fail if any required suite did not succeed
        if: >-
          needs.deploy.result != 'success' ||
          needs.suite-a.result != 'success'
        run: exit 1
  teardown:
    needs: [deploy, collect-results]
    if: always() && needs.deploy.result != 'skipped' && needs.deploy.outputs.run_id != ''
    continue-on-error: true
    runs-on: x
    steps: [{run: "true"}]
YML

# Rule 1a: a job outside needs and the predicate, without continue-on-error.
python3 - "${WORK}/good.yml" "${WORK}/veto-outside.yml" <<'PY'
import sys
s = open(sys.argv[1]).read()
s = s.replace("  teardown:\n", "  rogue:\n    needs: deploy\n    runs-on: x\n    steps: [{run: \"true\"}]\n  teardown:\n", 1)
open(sys.argv[2], "w").write(s)
PY
# Rule 1b: in needs but off the predicate, without continue-on-error.
python3 - "${WORK}/good.yml" "${WORK}/veto-off-predicate.yml" <<'PY'
import sys
s = open(sys.argv[1]).read()
s = s.replace("  soft:\n    needs: deploy\n    continue-on-error: true\n", "  soft:\n    needs: deploy\n", 1)
open(sys.argv[2], "w").write(s)
PY
# Rule 1c: cleanup job after the verdict, without continue-on-error.
python3 - "${WORK}/good.yml" "${WORK}/veto-teardown.yml" <<'PY'
import sys
s = open(sys.argv[1]).read()
s = s.replace("run_id != ''\n    continue-on-error: true\n", "run_id != ''\n", 1)
open(sys.argv[2], "w").write(s)
PY
# Rule 4 (#839): teardown runs even when deploy was skipped / left no run id.
python3 - "${WORK}/good.yml" "${WORK}/teardown-unguarded.yml" <<'PY'
import sys
s = open(sys.argv[1]).read()
s = s.replace("    if: always() && needs.deploy.result != 'skipped' && needs.deploy.outputs.run_id != ''\n", "    if: always()\n", 1)
open(sys.argv[2], "w").write(s)
PY
# Rule 2: the predicate names a job that is not in needs.
python3 - "${WORK}/good.yml" "${WORK}/predicate-not-needed.yml" <<'PY'
import sys
s = open(sys.argv[1]).read()
s = s.replace("    needs: [deploy, suite-a, soft]\n", "    needs: [deploy, soft]\n", 1)
s = s.replace("for job in deploy suite-a soft;", "for job in deploy soft;", 1)
open(sys.argv[2], "w").write(s)
PY
# Rule 3: a needed job missing from the summary loop.
python3 - "${WORK}/good.yml" "${WORK}/summary-missing.yml" <<'PY'
import sys
s = open(sys.argv[1]).read()
s = s.replace("for job in deploy suite-a soft;", "for job in deploy soft;", 1)
open(sys.argv[2], "w").write(s)
PY

FAILURES=0
expect() { # LABEL EXPECTED_EXIT FILE MUST_CONTAIN|-
  local label="$1" want="$2" file="$3" needle="$4" got=0 out
  out=$(python3 "${WORK}/check.py" "$file" 2>&1) || got=$?
  if [ "$got" -ne "$want" ]; then
    echo "FAIL: ${label}: exit ${got}, want ${want}"
    printf '%s\n' "$out"
    FAILURES=$((FAILURES + 1))
  elif [ "$needle" != "-" ] && ! printf '%s' "$out" | grep -qF -- "$needle"; then
    echo "FAIL: ${label}: output lacks '${needle}'"
    printf '%s\n' "$out"
    FAILURES=$((FAILURES + 1))
  else
    echo "ok:   ${label}"
  fi
}

expect "compliant fixture passes"                      0 "${WORK}/good.yml"                 -
expect "job outside the verdict without c-o-e vetoes"  1 "${WORK}/veto-outside.yml"         "job 'rogue' can veto"
expect "needed job off the predicate without c-o-e"    1 "${WORK}/veto-off-predicate.yml"   "job 'soft' can veto"
expect "post-verdict cleanup without c-o-e vetoes"     1 "${WORK}/veto-teardown.yml"        "job 'teardown' can veto"
expect "teardown without the deploy/run-id guard"       1 "${WORK}/teardown-unguarded.yml"   "teardown runs without"
expect "predicate clause on an unlisted job"           1 "${WORK}/predicate-not-needed.yml" "predicate names 'suite-a'"
expect "needed job missing from the summary"           1 "${WORK}/summary-missing.yml"      "'suite-a' is in collect-results.needs but missing"

if [ "$FAILURES" -ne 0 ]; then
  echo "checker self-test failed (${FAILURES}); not trusting it on ${TARGET}"
  exit 1
fi

echo "--- ${TARGET#"${REPO_ROOT}"/}"
if python3 "${WORK}/check.py" "$TARGET"; then
  echo "ok:   every job counts in the verdict or cannot veto"
else
  echo "FAIL: release gate verdict and workflow conclusion can disagree (artifact-keeper-test#359)"
  exit 1
fi
