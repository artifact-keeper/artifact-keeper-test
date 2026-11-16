#!/usr/bin/env bash
# selftest-dtf-advisory-outcome.sh - pins how the dtf-advisory job tells INFRA
# from a product FAIL (artifact-keeper-test#378).
#
# Two halves, both with stubs (no docker, no network, well under a second):
#
#   1. deploy-test/harness/run-tiers.sh's aggregate exit code, run against a
#      stub run.sh and a stub docker: 11 only when tiers were INFRA and none
#      FAILed, 1 as soon as one FAILed (a product FAIL wins), 10 for an
#      unpullable candidate, and DTF_INFRA_TIERS_FILE naming the INFRA tiers.
#   2. scripts/ci/dtf-advisory-outcome.sh against a stub run-tiers.sh: INFRA is
#      retried once (only the INFRA tiers), then warned about and the step
#      succeeds; anything else is a ::error and a non-zero step.
#
# Loosen either half and an advisory product regression goes quiet again, or
# a registry outage reads as a regression. This turns red instead.
#
# Usage: scripts/ci/selftest-dtf-advisory-outcome.sh
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTCOME="$ROOT/scripts/ci/dtf-advisory-outcome.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fails=0

ok()  { echo "  PASS  $1"; }
bad() { echo "  FAIL  $1"; fails=$((fails + 1)); }

# --- 1. run-tiers.sh aggregate ------------------------------------------------
H="$WORK/dt/harness"
mkdir -p "$H/lib" "$WORK/bin"
cp "$ROOT/deploy-test/harness/run-tiers.sh" "$H/run-tiers.sh"
cp "$ROOT/deploy-test/harness/lib/exit_codes.sh" "$H/lib/exit_codes.sh"
# Stub run.sh: a tier named rc<N>-<anything> exits N.
cat > "$H/run.sh" <<'EOF'
#!/usr/bin/env bash
t="${1%%-*}"; exit "${t#rc}"
EOF
# Stub docker: pull/inspect succeed unless STUB_PULL_FAIL is set.
cat > "$WORK/bin/docker" <<'EOF'
#!/usr/bin/env bash
[ -n "${STUB_PULL_FAIL:-}" ] && exit 1
exit 0
EOF
chmod +x "$H/run-tiers.sh" "$H/run.sh" "$WORK/bin/docker"

# tiers_expect <want rc> <want infra-file contents> <label> [VAR=v ...] -- <tier>...
tiers_expect() {
  local want="$1" want_infra="$2" label="$3"; shift 3
  local envs=()
  while [ "$1" != "--" ]; do envs+=("$1"); shift; done; shift
  local out rc got
  out="$(env -i PATH="$WORK/bin:$PATH" DTF_INFRA_TIERS_FILE="$WORK/infra" "${envs[@]}" \
    "$H/run-tiers.sh" --backend-image img:t "$@" 2>&1)"; rc=$?
  got="$(tr '\n' ' ' < "$WORK/infra" 2>/dev/null | sed 's/ $//')"
  if [ "$rc" = "$want" ] && [ "$got" = "$want_infra" ]; then
    ok "$label"
  else
    bad "$label: exit $rc (want $want), infra file '$got' (want '$want_infra')"
    printf '%s\n' "$out" | tail -n 12 | sed 's/^/        /'
  fi
  rm -f "$WORK/infra"
}

echo "run-tiers.sh: aggregate exit code"
tiers_expect 0 ""            "all tiers pass"                   -- rc0-a rc0-b
tiers_expect 11 "rc11-b"     "one INFRA tier, none FAIL -> 11"  -- rc0-a rc11-b
tiers_expect 11 "rc11-a rc11-b" "two INFRA tiers -> 11"         -- rc11-a rc11-b
tiers_expect 1 "rc11-a"      "INFRA then FAIL -> 1 (FAIL wins)" -- rc11-a rc1-b
tiers_expect 1 "rc11-b"      "FAIL then INFRA -> 1 (FAIL wins)" -- rc1-a rc11-b
tiers_expect 1 ""            "stack-up (7) is a FAIL"           -- rc7-a
tiers_expect 1 ""            "harness wiring (4) is a FAIL"     -- rc4-a
tiers_expect 1 ""            "rc 12 without a line marker is a FAIL" -- rc12-a
tiers_expect 10 ""           "unpullable candidate -> 10"       STUB_PULL_FAIL=1 -- rc0-a
tiers_expect 2 ""            "no tiers -> 2" --

# --- 2. dtf-advisory-outcome.sh -----------------------------------------------
# Stub run-tiers.sh. Invocation N exits word N of STUB_RCS and writes word N of
# STUB_INFRA (tiers joined by ',', '-' for none) to DTF_INFRA_TIERS_FILE,
# unless STUB_LEGACY is set (a pre-#378 driver that never creates the file).
# Each invocation's tier arguments are appended to $WORK/calls.
STUB="$WORK/run-tiers-stub.sh"
cat > "$STUB" <<'EOF'
#!/usr/bin/env bash
n=$(( $(wc -l < "$CALLS" 2>/dev/null || echo 0) + 1 ))
shift 2
echo "$*" >> "$CALLS"
read -r -a rcs <<< "$STUB_RCS"; read -r -a inf <<< "${STUB_INFRA:-}"
if [ -z "${STUB_LEGACY:-}" ]; then
  : > "$DTF_INFRA_TIERS_FILE"
  i="${inf[$((n-1))]:--}"
  [ "$i" = "-" ] || tr ',' '\n' <<< "$i" > "$DTF_INFRA_TIERS_FILE"
fi
exit "${rcs[$((n-1))]}"
EOF
chmod +x "$STUB"

# outcome_expect <want rc> <want calls (';'-joined)> <must-match regex> <label> [VAR=v ...]
# Always runs the tiers "a b c".
outcome_expect() {
  local want="$1" want_calls="$2" re="$3" label="$4"; shift 4
  local out rc calls
  rm -f "$WORK/calls" "$WORK/summary"
  out="$(env -i PATH="$PATH" RUN_TIERS="$STUB" CALLS="$WORK/calls" DTF_GROUP=g \
    GITHUB_STEP_SUMMARY="$WORK/summary" "$@" bash "$OUTCOME" --backend-image img:t a b c 2>&1)"; rc=$?
  calls="$(paste -sd';' "$WORK/calls")"
  out="$out
$(cat "$WORK/summary" 2>/dev/null)"
  if [ "$rc" = "$want" ] && [ "$calls" = "$want_calls" ] && grep -Eq -- "$re" <<< "$out"; then
    ok "$label"
  else
    bad "$label: exit $rc (want $want), calls '$calls' (want '$want_calls'), /$re/ $(grep -Eq -- "$re" <<< "$out" && echo matched || echo 'not matched')"
    printf '%s\n' "$out" | sed 's/^/        /'
  fi
}

ERR='^::error title=DTF advisory product FAIL \(advisory, not blocking\)::'
WARN='^::warning title=DTF advisory INFRA::'

echo "dtf-advisory-outcome.sh: outcome mapping"
# shellcheck disable=SC2016 # literal backticks in the summary line
outcome_expect 0 "a b c" '^- dtf-advisory `g`: PASS$'         "PASS"                          STUB_RCS=0
outcome_expect 1 "a b c" "$ERR"                               "product FAIL is red, no retry" STUB_RCS=1
outcome_expect 7 "a b c" "$ERR"                               "stack-up (7) is red, no retry" STUB_RCS=7
outcome_expect 1 "a b c" "$ERR"                               "FAIL with INFRA tiers is red, no retry" STUB_RCS=1 STUB_INFRA=b
outcome_expect 0 "a b c;b" 'passed on one retry'              "INFRA retried (INFRA tier only), passes" STUB_RCS="11 0" STUB_INFRA="b -"
outcome_expect 0 "a b c;a c" "$WARN"                          "INFRA twice -> warning, step succeeds" STUB_RCS="11 11" STUB_INFRA="a,c a,c"
outcome_expect 0 "a b c;a c" "after one retry"                "two INFRA tiers retried together" STUB_RCS="11 11" STUB_INFRA="a,c a,c"
outcome_expect 1 "a b c;b" "$ERR"                             "INFRA then FAIL on retry -> red" STUB_RCS="11 1" STUB_INFRA="b -"
outcome_expect 0 "a b c;a b c" "$WARN"                        "unpullable (10) retried with all tiers, then warned" STUB_RCS="10 10"
outcome_expect 0 "a b c" 'over the -1s retry budget'          "no retry past the time budget" STUB_RCS=11 STUB_INFRA=b DTF_ADVISORY_RETRY_BUDGET_S=-1
outcome_expect 0 "a b c" 'named no INFRA tier'                "rc 11 naming no tier: warned, no retry" STUB_RCS=11
outcome_expect 1 "a b c" "${ERR}.*predates #378"              "pre-#378 driver: rc 1 stays red, says why" STUB_RCS=1 STUB_LEGACY=1
outcome_expect 0 "a b c" "${WARN}.*predates #378"             "pre-#378 driver: rc 10 is still INFRA" STUB_RCS=10 STUB_LEGACY=1
if bash "$OUTCOME" --backend-image img:t >/dev/null 2>&1; [ $? -eq 2 ]; then
  ok "no tiers is a usage error (2)"
else
  bad "no tiers is not a usage error"
fi

if [ "$fails" -ne 0 ]; then
  echo "dtf-advisory outcome selftest: $fails case(s) FAILED"
  exit 1
fi
echo "dtf-advisory outcome selftest: all cases passed"
