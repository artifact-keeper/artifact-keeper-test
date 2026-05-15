#!/usr/bin/env bash
#
# Self-test for the EXPECT_FAILURE=1 inversion in tests/lib/common.sh.
# Verifies the four truth-table cases:
#
#   default   + pass()  -> exit 0
#   default   + fail()  -> exit 1
#   EXPECT=1  + pass()  -> exit 1   (test author expected a failure, didn't get one)
#   EXPECT=1  + fail()  -> exit 0   (test author expected a failure, got it)
#
# Run from repo root: bash scripts/tests/test-expect-failure-self.sh
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP_OUT=$(mktemp -d)
trap 'rm -rf "$TMP_OUT"' EXIT

inner_suite() {
  local outcome="$1"  # "pass" or "fail"
  cat <<INNER
source "${REPO_ROOT}/tests/lib/common.sh"
JUNIT_OUTPUT_DIR="${TMP_OUT}"
begin_suite "self-test"
begin_test "stub"
${outcome} "self-test stub"
end_suite
INNER
}

run_case() {
  local label="$1" expect="$2" outcome="$3" want_exit="$4"
  local actual
  EXPECT_FAILURE="$expect" bash -c "$(inner_suite "$outcome")" >/dev/null 2>&1
  actual=$?
  if [ "$actual" = "$want_exit" ]; then
    echo "  PASS: ${label} (exit=${actual})"
    return 0
  fi
  echo "  FAIL: ${label} expected exit=${want_exit} got exit=${actual}"
  return 1
}

fails=0
run_case "default + pass()       -> exit 0" "0" "pass" "0" || fails=$((fails+1))
run_case "default + fail()       -> exit 1" "0" "fail" "1" || fails=$((fails+1))
run_case "EXPECT_FAILURE + fail()-> exit 0" "1" "fail" "0" || fails=$((fails+1))
run_case "EXPECT_FAILURE + pass()-> exit 1" "1" "pass" "1" || fails=$((fails+1))

echo ""
if [ "$fails" -eq 0 ]; then
  echo "All EXPECT_FAILURE truth-table cases passed."
  exit 0
fi
echo "${fails} case(s) failed."
exit 1
