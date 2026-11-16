#!/usr/bin/env bash
#
# Self-test for require_wait_budget in tests/lib/common.sh and the
# TEST_TIMEOUT hand-off in scripts/run-suite.sh (artifact-keeper-test#832).
#
# run-suite.sh kills each script at TEST_TIMEOUT (exit 124). A script whose own
# waits cannot fit inside that cap must fail loudly at the start, naming both
# numbers, instead of being killed mid-poll. Cases:
#
#   budget + margin <= TEST_TIMEOUT  -> runs on, exit 0, prints nothing
#   budget + margin >  TEST_TIMEOUT  -> FAIL naming both numbers, suite aborts, exit 1
#   boundary (90 + 30 = 120 at 120)  -> fits; 91 does not
#   WAIT_BUDGET_MARGIN override      -> honoured
#   non-integer budget               -> FAIL, exit 1
#   run by hand (no run-suite.sh)    -> nothing to fit, not checked
#   run-suite.sh                     -> exports the cap it enforces (RUN_SUITE_TIMEOUT
#                                       and TEST_TIMEOUT),
#                                       so an over-budget script fails with the
#                                       message under the default cap, not 124
#
# Runs offline (no backend). Run from anywhere:
#   bash tests/lib/selftest-wait-budget.sh
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP_OUT=$(mktemp -d)
trap 'rm -rf "$TMP_OUT"' EXIT

inner_suite() {
  local budget="$1"
  cat <<INNER
source "${REPO_ROOT}/tests/lib/common.sh"
begin_suite "wait-budget-self-test"
require_wait_budget ${budget} "self-test waits"
echo "REACHED-AFTER-BUDGET"
begin_test "stub"
pass
end_suite
INNER
}

fails=0

# run_case LABEL RUN_SUITE_TIMEOUT MARGIN BUDGET WANT_EXIT WANT_REACHED [WANT_GREP]
run_case() {
  local label="$1" cap="$2" margin="$3" budget="$4" want_exit="$5" want_reached="$6" want_grep="${7:-}"
  local out actual reached=no
  local -a capenv=(-u RUN_SUITE_TIMEOUT)
  [ -n "$cap" ] && capenv=(RUN_SUITE_TIMEOUT="$cap" TEST_TIMEOUT="$cap")
  out=$(env -u RELEASE_GATE "${capenv[@]}" JUNIT_OUTPUT_DIR="${TMP_OUT}/junit" WAIT_BUDGET_MARGIN="$margin" \
    bash -c "$(inner_suite "$budget")" 2>&1)
  actual=$?
  printf '%s' "$out" | grep -q "REACHED-AFTER-BUDGET" && reached=yes
  if [ "$actual" != "$want_exit" ] || [ "$reached" != "$want_reached" ]; then
    echo "  FAIL: ${label}: exit=${actual} (want ${want_exit}) reached=${reached} (want ${want_reached})"
    printf '%s\n' "$out" | sed 's/^/      /' | head -20
    fails=$((fails+1))
    return
  fi
  if [ -n "$want_grep" ] && ! printf '%s' "$out" | grep -qF -- "$want_grep"; then
    echo "  FAIL: ${label}: output lacks '${want_grep}'"
    printf '%s\n' "$out" | sed 's/^/      /' | head -20
    fails=$((fails+1))
    return
  fi
  if [ "$want_exit" = "0" ] && printf '%s' "$out" | grep -q "Wait budget fits TEST_TIMEOUT"; then
    echo "  FAIL: ${label}: a fitting budget must print nothing"
    fails=$((fails+1))
    return
  fi
  echo "  PASS: ${label} (exit=${actual})"
}

run_case "180s wait under TEST_TIMEOUT=300 fits"          300 30 180 0 yes
run_case "180s wait under TEST_TIMEOUT=120 fails loudly"  120 30 180 1 no "more than TEST_TIMEOUT=120s"
run_case "the failure names the script's own wait"        120 30 180 1 no "can take 180s (+30s setup margin = 210s)"
run_case "boundary: 90s + 30s margin fits 120s"           120 30 90  0 yes
run_case "boundary: 91s + 30s margin does not fit 120s"   120 30 91  1 no "TEST_TIMEOUT=120s"
run_case "WAIT_BUDGET_MARGIN=0 lets 120s fit 120s"        120 0  120 0 yes
run_case "a non-integer budget fails"                     120 30 abc 1 no "non-integer budget 'abc'"
run_case "run by hand (no run-suite.sh cap): not checked" ""  30 180 0 yes

# run-suite.sh: build a throwaway repo layout around copies of the real
# run-suite.sh and common.sh, with one suite whose script prints the
# TEST_TIMEOUT it sees and one whose waits exceed the default cap.
FAKE="${TMP_OUT}/repo"
mkdir -p "${FAKE}/scripts" "${FAKE}/tests/lib" "${FAKE}/tests/seecap" "${FAKE}/tests/overbudget"
cp "${REPO_ROOT}/scripts/run-suite.sh" "${FAKE}/scripts/run-suite.sh"
cp "${REPO_ROOT}/tests/lib/common.sh" "${FAKE}/tests/lib/common.sh"
cat > "${FAKE}/tests/seecap/test-seecap.sh" <<'S'
echo "SEEN_TEST_TIMEOUT=${TEST_TIMEOUT:-unset}"
echo "SEEN_RUN_SUITE_TIMEOUT=${RUN_SUITE_TIMEOUT:-unset}"
S
cat > "${FAKE}/tests/overbudget/test-overbudget.sh" <<'S'
source "$(dirname "$0")/../lib/common.sh"
begin_suite "overbudget"
require_wait_budget 180 "scheduler-tick wait"
sleep 300
end_suite
S

seen=$(cd "$FAKE" && env -u TEST_TIMEOUT -u RUN_SUITE_TIMEOUT JUNIT_OUTPUT_DIR="${TMP_OUT}/junit" \
  bash scripts/run-suite.sh --suite seecap 2>&1 | grep -o 'SEEN_TEST_TIMEOUT=[a-z0-9]*')
if [ "$seen" = "SEEN_TEST_TIMEOUT=120" ]; then
  echo "  PASS: run-suite.sh exports its default cap as TEST_TIMEOUT (${seen})"
else
  echo "  FAIL: run-suite.sh did not export its default cap: got '${seen}', want SEEN_TEST_TIMEOUT=120"
  fails=$((fails+1))
fi

seen=$(cd "$FAKE" && TEST_TIMEOUT=300 JUNIT_OUTPUT_DIR="${TMP_OUT}/junit" \
  bash scripts/run-suite.sh --suite seecap 2>&1 | grep -o 'SEEN_TEST_TIMEOUT=[a-z0-9]*')
if [ "$seen" = "SEEN_TEST_TIMEOUT=300" ]; then
  echo "  PASS: run-suite.sh passes a job's TEST_TIMEOUT through (${seen})"
else
  echo "  FAIL: run-suite.sh did not pass TEST_TIMEOUT=300 through: got '${seen}'"
  fails=$((fails+1))
fi

start=$(date +%s)
out=$(cd "$FAKE" && env -u TEST_TIMEOUT -u RUN_SUITE_TIMEOUT -u RELEASE_GATE JUNIT_OUTPUT_DIR="${TMP_OUT}/junit" \
  bash scripts/run-suite.sh --suite overbudget 2>&1)
rc=$?
took=$(( $(date +%s) - start ))
if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -qF "more than TEST_TIMEOUT=120s" \
   && printf '%s' "$out" | grep -q "RESULT: FAIL (exit code: 1)" && [ "$took" -lt 60 ]; then
  echo "  PASS: an over-budget script fails at once with the message, not exit 124 (${took}s)"
else
  echo "  FAIL: over-budget script under run-suite.sh: rc=${rc} took=${took}s"
  printf '%s\n' "$out" | sed 's/^/      /' | tail -15
  fails=$((fails+1))
fi

echo ""
if [ "$fails" -eq 0 ]; then
  echo "All require_wait_budget cases passed."
  exit 0
fi
echo "${fails} case(s) failed."
exit 1
