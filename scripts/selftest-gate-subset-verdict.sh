#!/usr/bin/env bash
# selftest-gate-subset-verdict.sh - pins the release gate's subset run
# (artifact-keeper-test#830): what only_jobs may name (gate-selection.sh) and
# how a subset run is judged (gate-subset-verdict.sh).
#
# The dangerous direction is a subset run that passes having proved nothing: a
# selected job that skipped, a typo that selected no job, or a required suite
# the full predicate gained that the subset verdict never heard of. Each is
# constructed here and must fail. The selection cases run against the real
# release-gate.yml, and the required lists are compared with the full-run
# predicate in that file, so adding a required suite to one and not the other
# turns this red. No network, no cluster; about a second.
#
# Usage: bash scripts/selftest-gate-subset-verdict.sh
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WF="$ROOT/.github/workflows/release-gate.yml"
SEL="$ROOT/scripts/gate-selection.sh"
VERDICT="$ROOT/scripts/gate-subset-verdict.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fails=0
pass() { echo "  PASS  $*"; }
fail() { echo "  FAIL  $*"; fails=$((fails + 1)); }

# ---------------------------------------------------------------------------
echo "gate-subset-verdict.sh: its required lists match the full-run predicate"
pred="$(awk '/- name: Gate check - fail if any required suite did not succeed/{on=1} on && /^        run: /{exit} on' "$WF")"
[[ -n "$pred" ]] || fail "could not find the full-run Gate check step in release-gate.yml"
from_yaml() { grep -oE "needs\.[a-z0-9-]+\.result $1" <<<"$pred" | sed -E 's/^needs\.([a-z0-9-]+)\.result.*/\1/' | sort -u; }
yaml_loose="$(from_yaml "== 'failure'")"
yaml_strict="$(from_yaml "!= 'success'")"
policy="$(bash "$VERDICT" --print-policy)"
script_loose="$(sed -n 's/^loose //p' <<<"$policy" | tr ' ' '\n' | sort -u)"
script_strict="$(sed -n 's/^strict //p' <<<"$policy" | tr ' ' '\n' | sort -u)"
if [[ "$yaml_loose" == "$script_loose" ]]; then pass "loose list ($(wc -l <<<"$yaml_loose") jobs)"
else fail "loose list differs from the predicate:"; diff <(echo "$yaml_loose") <(echo "$script_loose") | sed 's/^/        /'; fi
if [[ "$yaml_strict" == "$script_strict" ]]; then pass "strict list ($(wc -l <<<"$yaml_strict") jobs)"
else fail "strict list differs from the predicate:"; diff <(echo "$yaml_strict") <(echo "$script_strict") | sed 's/^/        /'; fi
collect_needs="$(awk '/^  collect-results:/{on=1} on && /^    needs:/{print; exit}' "$WF")"
for j in $script_loose $script_strict; do
  [[ "$collect_needs" == *" ${j},"* || "$collect_needs" == *" ${j}]"* || "$collect_needs" == *"[${j},"* ]] \
    || fail "required job '${j}' is not in collect-results' needs, so the verdict would read it as absent"
done

# ---------------------------------------------------------------------------
echo "gate-selection.sh: against release-gate.yml"
# sel_case <want rc> <want subset|-> <want cluster|-> <label> [VAR=value ...]
sel_case() {
  local want_rc="$1" want_subset="$2" want_cluster="$3" label="$4"; shift 4
  local out="$WORK/out" rc
  : > "$out"
  env -i PATH="$PATH" GATE_WORKFLOW="$WF" GITHUB_OUTPUT="$out" "$@" bash "$SEL" >/dev/null 2>&1; rc=$?
  local subset cluster
  subset="$(sed -n 's/^subset=//p' "$out")"; cluster="$(sed -n 's/^cluster=//p' "$out")"
  if [[ "$rc" == "$want_rc" && ( "$want_subset" == - || "$subset" == "$want_subset" ) && ( "$want_cluster" == - || "$cluster" == "$want_cluster" ) ]]; then
    pass "$label"
  else
    fail "$label: exit $rc (want $want_rc), subset '$subset' (want $want_subset), cluster '$cluster' (want $want_cluster)"
  fi
}
sel_case 0 false true  "empty: the full gate"
sel_case 0 true  false "DTF legs only: no cluster"                 GATE_ONLY_JOBS='dtf-gate/core dtf-gate/upgrade-origins collect-results'
sel_case 0 true  false "the opt-in smoke, not enabled: no cluster" GATE_ONLY_JOBS='dtf-gate/core clean-install-smoke-with-deps'
sel_case 0 true  true  "the opt-in smoke, enabled: cluster"        GATE_ONLY_JOBS='clean-install-smoke-with-deps' GATE_RUN_SMOKE_WITH_DEPS=true
sel_case 0 true  true  "a cluster suite: cluster"                  GATE_ONLY_JOBS='dtf-gate/core webhook-tests'
sel_case 0 true  true  "teardown: cluster"                         GATE_ONLY_JOBS='teardown'
sel_case 0 true  false "the whole dtf-gate job"                    GATE_ONLY_JOBS='dtf-gate build-dtf-probes'
sel_case 1 -     -     "an unknown job"                            GATE_ONLY_JOBS='repo-test'
sel_case 1 -     -     "an unknown dtf-gate group"                 GATE_ONLY_JOBS='dtf-gate/no-such-group'
sel_case 1 -     -     "a dtf-advisory group (legs are dtf-gate only)" GATE_ONLY_JOBS='dtf-advisory/supply-chain'
sel_case 1 -     -     "one good token does not excuse a bad one"  GATE_ONLY_JOBS='repo-tests auth-test'
sel_case 1 -     -     "a step name is not a job"                  GATE_ONLY_JOBS='steps'
every_group="$(awk '/^  dtf-gate:/{on=1; next} on && /^  [a-z0-9-]+:[[:space:]]*$/{on=0} on && /^[[:space:]]+- group:/{print "dtf-gate/" $3}' "$WF" | tr '\n' ' ')"
sel_case 0 true  false "every dtf-gate group by name"              GATE_ONLY_JOBS="${every_group% }"

# ---------------------------------------------------------------------------
echo "gate-subset-verdict.sh: judging a subset run"
ALL_JOBS="$(printf '%s\n' "$script_loose" "$script_strict" cli-smoke format-tests-audit security-grype-scan-completes stress-tests mesh-tests dtf-advisory | sort -u)"
# needs <default result> [job=result ...] -> a toJSON(needs)-shaped object
needs() {
  local def="$1"; shift
  local args=() j
  for j in $ALL_JOBS; do args+=("$j=$def"); done
  args+=("$@")
  printf '%s\n' "${args[@]}" | jq -Rn '[inputs | split("=") | {key: .[0], value: {result: .[1], outputs: {}}}] | from_entries'
}
# v_case <want rc> <label> <only_jobs> <cluster> <needs json> [TEST_SUITE]
v_case() {
  local want="$1" label="$2" only="$3" cluster="$4" nj="$5" suite="${6:-all}" rc
  env -i PATH="$PATH" GATE_ONLY_JOBS="$only" CLUSTER="$cluster" TEST_SUITE="$suite" NEEDS_JSON="$nj" bash "$VERDICT" >"$WORK/v.log" 2>&1; rc=$?
  if [[ "$rc" == "$want" ]]; then pass "$label"
  else fail "$label: exit $rc, want $want"; sed 's/^/        /' "$WORK/v.log"; fi
}
DTF_OK="$(needs skipped version-set-integrity=success dtf-gate=success)"
v_case 0 "DTF legs selected and green, nothing else ran"   'dtf-gate/core collect-results' false "$DTF_OK"
v_case 1 "a selected DTF leg failed"                       'dtf-gate/core' false "$(needs skipped version-set-integrity=success dtf-gate=failure)"
v_case 1 "a selected DTF job that SKIPPED is not a pass"   'dtf-gate/core' false "$(needs skipped version-set-integrity=success)"
v_case 1 "version-set-integrity failed"                    'dtf-gate/core' false "$(needs skipped version-set-integrity=failure dtf-gate=success)"
CL="version-set-integrity=success clean-install-smoke=success deploy=success"
# shellcheck disable=SC2086 # word splitting of $CL into job=result pairs is the point
v_case 0 "a cluster suite selected and green"              'webhook-tests' true "$(needs skipped $CL webhook-tests=success)"
# shellcheck disable=SC2086
v_case 1 "a selected loose suite that skipped"             'webhook-tests' true "$(needs skipped $CL)"
# shellcheck disable=SC2086
v_case 1 "a selected loose suite that failed"              'webhook-tests' true "$(needs skipped $CL webhook-tests=failure)"
v_case 1 "the deploy skipped though the cluster is needed" 'webhook-tests' true "$(needs skipped version-set-integrity=success clean-install-smoke=success webhook-tests=success)"
# shellcheck disable=SC2086
v_case 1 "an unselected required job failed"               'webhook-tests' true "$(needs skipped $CL webhook-tests=success repo-tests=failure)"
# shellcheck disable=SC2086
v_case 1 "an unselected required job was cancelled"        'webhook-tests' true "$(needs skipped $CL webhook-tests=success pinned-cve-gate=cancelled)"
v_case 0 "the opt-in smoke selected and skipped by design" 'dtf-gate/core clean-install-smoke-with-deps' false "$DTF_OK"
v_case 0 "an advisory job selected and red is not judged"  'dtf-gate/core mesh-tests stress-tests' false "$(needs skipped version-set-integrity=success dtf-gate=success mesh-tests=failure stress-tests=failure)"
# shellcheck disable=SC2086
v_case 0 "platform-tests with its auth-tests prerequisite" 'platform-tests' true "$(needs skipped $CL platform-tests=success auth-tests=success)"
# shellcheck disable=SC2086
v_case 1 "the prerequisite auth-tests failed"              'platform-tests' true "$(needs skipped $CL platform-tests=skipped auth-tests=failure)"
v_case 0 "security-tests is not judged for test_suite=dtf" 'dtf-gate/core' false "$DTF_OK" dtf
v_case 1 "a required job missing from needs"               'dtf-gate/core' false "$(needs skipped version-set-integrity=success dtf-gate=success | jq 'del(."repo-tests")')"
v_case 2 "CLUSTER unset (selection did not run)"           'dtf-gate/core' '' "$DTF_OK"
v_case 2 "only_jobs empty is the full gate's business"     '' false "$DTF_OK"
v_case 2 "NEEDS_JSON is not JSON"                          'dtf-gate/core' false 'not json'

if [[ "$fails" -ne 0 ]]; then
  echo "gate subset run: $fails case(s) FAILED"
  exit 1
fi
echo "gate subset run: all cases passed"
