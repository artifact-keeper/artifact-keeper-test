#!/usr/bin/env bash
# gate-subset-verdict.sh - the release gate's verdict for a run that ran only
# the jobs named in only_jobs (artifact-keeper-test#830, artifact-keeper#6076).
#
# A full run keeps its own predicate (the `if:` of collect-results' "Gate
# check" step), untouched. That predicate cannot judge a subset run: it uses
# `!= 'success'` for the silent-success gates, so every unselected one would
# fail it, and its looser `failure || cancelled` form would let a SELECTED job
# that ended up skipped pass, which is the one outcome a rerun must never
# accept: the caller certifies on "the original passed everything else, and
# this run passed what it was asked to run".
#
# So, in a subset run, for every job the full predicate requires:
#   selected      -> its result must be 'success' (the opt-in
#                    clean-install-smoke-with-deps keeps the full predicate's
#                    loose form, so it can skip when run_smoke_with_deps is
#                    false, as it does in every full run)
#   not selected  -> it must not be 'failure' or 'cancelled' (it is skipped)
# version-set-integrity always runs, and clean-install-smoke and deploy run
# whenever the selection needs the cluster (gate-selection.sh); in those cases
# they count as selected. dtf-gate counts as selected when the job or any of
# its legs is named, and only for the suites that run it, like security-tests.
# Advisory jobs (cli-smoke, format-tests-audit, security-grype-scan-completes,
# stress-tests, mesh-tests, dtf-advisory) are reported, never judged, exactly
# as in a full run.
#
# The REQUIRED lists below mirror that predicate. selftest-gate-subset-verdict.sh
# compares them with the predicate in release-gate.yml, so adding a required
# suite there without adding it here turns the self-test red.
#
# Inputs (environment):
#   NEEDS_JSON      toJSON(needs) of collect-results
#   GATE_ONLY_JOBS  the only_jobs input (must be non-empty)
#   TEST_SUITE      the test_suite input (default all)
#   CLUSTER         gate-selection.sh's cluster output ('true' or 'false')
#   GITHUB_STEP_SUMMARY  optional
#
# `--print-policy` prints the two lists and exits, for the self-test.
# Exit: 0 = the subset passed, 1 = it did not, 2 = could not judge.
set -uo pipefail

# needs.<job>.result == 'failure' || ... == 'cancelled' in the full predicate.
REQUIRED_LOOSE="version-set-integrity clean-install-smoke clean-install-smoke-with-deps chart-upgrade-smoke real-flow-smoke deploy format-tests format-tests-registration-check compatibility-tests repo-tests promotion-tests rbac-tests lifecycle-tests webhook-tests search-tests platform-tests auth-tests admin-tests resilience-tests"
# needs.<job>.result != 'success' in the full predicate (the last two only for
# the suites that run them).
REQUIRED_STRICT="scan-completion-gate sbom-correctness-gate pinned-cve-gate pinned-cve-image-gate security-tests dtf-gate"

if [[ "${1:-}" == --print-policy ]]; then
  echo "loose ${REQUIRED_LOOSE}"
  echo "strict ${REQUIRED_STRICT}"
  exit 0
fi

ONLY="${GATE_ONLY_JOBS:-}"
SUITE="${TEST_SUITE:-all}"
CLUSTER="${CLUSTER:-}"
SUMMARY="${GITHUB_STEP_SUMMARY:-/dev/null}"

command -v jq >/dev/null 2>&1 || { echo "::error title=Gate subset verdict::jq is not on PATH" >&2; exit 2; }
[[ -n "$ONLY" ]] || { echo "::error title=Gate subset verdict::only_jobs is empty; this is the full gate's job, not this script's" >&2; exit 2; }
[[ "$CLUSTER" == true || "$CLUSTER" == false ]] || { echo "::error title=Gate subset verdict::CLUSTER is '${CLUSTER}', expected true or false (gate-selection.sh did not run?)" >&2; exit 2; }
jq -e 'type == "object"' <<<"${NEEDS_JSON:-}" >/dev/null 2>&1 || { echo "::error title=Gate subset verdict::NEEDS_JSON is not a JSON object" >&2; exit 2; }

sel=" ${ONLY} "
selected() { # <job>
  case "$1" in
    version-set-integrity) return 0 ;;
    clean-install-smoke|deploy) [[ "$CLUSTER" == true ]] ;;
    dtf-gate) [[ "$sel" == *" dtf-gate "* || "$sel" == *" dtf-gate/"* ]] ;;
    *) [[ "$sel" == *" $1 "* ]] ;;
  esac
}
applies() { # <job>: does the full predicate judge it for this test_suite?
  case "$1" in
    security-tests) [[ "$SUITE" == all || "$SUITE" == security ]] ;;
    dtf-gate) [[ "$SUITE" == all || "$SUITE" == security || "$SUITE" == dtf ]] ;;
    *) return 0 ;;
  esac
}

bad=0
{
  echo "## Release Gate: subset verdict"
  echo
  echo "Selected: \`${ONLY}\` (cluster deploy: ${CLUSTER})"
  echo
  echo "| required job | selected | result | verdict |"
  echo "|---|---|---|---|"
} >> "$SUMMARY"
for job in $REQUIRED_LOOSE $REQUIRED_STRICT; do
  applies "$job" || continue
  result="$(jq -r --arg j "$job" '.[$j].result // "absent"' <<<"$NEEDS_JSON")"
  if selected "$job"; then
    s=yes
    if [[ "$job" == clean-install-smoke-with-deps ]]; then
      [[ "$result" == failure || "$result" == cancelled || "$result" == absent ]] && v=FAIL || v=ok
    else
      [[ "$result" == success ]] && v=ok || v=FAIL
    fi
  else
    s=no
    [[ "$result" == failure || "$result" == cancelled || "$result" == absent ]] && v=FAIL || v=ok
  fi
  if [[ "$v" == FAIL ]]; then
    bad=1
    if [[ "$s" == yes ]]; then
      echo "::error title=Release gate subset FAILED::${job} was selected and is required, but its result is '${result}'. A selected job must succeed; skipped is not a pass."
    else
      echo "::error title=Release gate subset FAILED::${job} was not selected but its result is '${result}'."
    fi
  fi
  echo "| ${job} | ${s} | ${result} | ${v} |" >> "$SUMMARY"
  printf '  %-34s selected=%-3s result=%-9s %s\n' "$job" "$s" "$result" "$v"
done

if [[ "$bad" -ne 0 ]]; then
  echo "Release gate subset FAILED: see the errors above."
  exit 1
fi
echo "Release gate subset PASSED: every selected required job succeeded and nothing else failed."
