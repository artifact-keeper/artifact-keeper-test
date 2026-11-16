#!/usr/bin/env bash
# selftest-switch-tests-ref.sh - pins how scripts/switch-tests-ref.sh picks and
# pins the tests tree (artifact-keeper-test#830).
#
# The script decides which suite a candidate is gated by: main, or the
# release/X.Y.x branch for its line, and, with GATE_TESTS_SHA, one exact commit
# of that branch. Both directions matter: a pin must land on exactly the commit
# asked for, and a pin that is not part of the branch the candidate is gated by
# (an unmerged commit, or another line's tree) must fail the job rather than
# quietly run something else.
#
# The fixture is a local bare repository standing in for origin, with a main and
# a release/1.11.x branch. BACKEND_TAG is a plain version, so the script reads
# no Cargo.toml and makes no network call. Well under a second.
#
# Usage: bash scripts/selftest-switch-tests-ref.sh
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT/scripts/switch-tests-ref.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fails=0

g() { git -c user.name=t -c user.email=t@example.invalid -c init.defaultBranch=main "$@"; }

# origin: main has M1 <- M2; release/1.11.x forks at M1 and adds R1; U1 is a
# commit that no branch contains.
g init -q --bare "$WORK/origin.git"
g init -q "$WORK/seed"
(
  cd "$WORK/seed" || exit 1
  mkdir -p deploy-test
  echo m1 > f; g add f; g commit -qm M1
  g branch release/1.11.x
  echo m2 > f; g commit -qam M2
  g checkout -q release/1.11.x
  echo r1 > f; g commit -qam R1
  g checkout -q -b stray
  echo u1 > f; g commit -qam U1
  g remote add origin "$WORK/origin.git"
  g push -q origin main release/1.11.x
) || { echo "fixture setup failed"; exit 2; }
rev() { g -C "$WORK/seed" rev-parse "$1"; }
M1="$(rev main~1)"; M2="$(rev main)"; R1="$(rev release/1.11.x)"; U1="$(rev stray)"

# expect <want rc> <want HEAD|-> <want marker|-|none> <label> [VAR=value ...]
# Each case gets a fresh shallow clone, like actions/checkout's.
n=0
expect() {
  local want_rc="$1" want_head="$2" want_marker="$3" label="$4"; shift 4
  n=$((n + 1))
  local dir="$WORK/clone$n" out rc head marker
  g clone -q --depth 1 "file://$WORK/origin.git" "$dir"
  mkdir -p "$dir/deploy-test"
  out="$(cd "$dir" && env -i PATH="$PATH" HOME="$WORK" "$@" bash "$SCRIPT" 2>&1)"; rc=$?
  head="$(g -C "$dir" rev-parse HEAD)"
  marker="none"; [[ -f "$dir/deploy-test/.tests-ref" ]] && marker="$(cat "$dir/deploy-test/.tests-ref")"
  if [[ "$rc" == "$want_rc" && ( "$want_head" == - || "$head" == "$want_head" ) \
        && ( "$want_marker" == - || "$marker" == "$want_marker" ) ]]; then
    echo "  PASS  $label"
  else
    echo "  FAIL  $label: exit $rc (want $want_rc), HEAD ${head:0:7} (want ${want_head:0:7}), marker '$marker' (want '$want_marker')"
    printf '%s\n' "$out" | sed 's/^/        /'
    fails=$((fails + 1))
  fi
}

echo "switch-tests-ref.sh: without a pin (today's behaviour)"
expect 0 "$M2" none           "no release branch for the line: main's tip"      BACKEND_TAG=1.12.0
expect 0 "$R1" release/1.11.x "a release branch for the line: its tip, marked"  BACKEND_TAG=1.11.13
expect 0 "$M2" none           "a tag naming no version: main"                   BACKEND_TAG=dev

echo "switch-tests-ref.sh: with GATE_TESTS_SHA"
expect 0 "$M2" none           "main's tip, pinned"                              BACKEND_TAG=1.12.0 GATE_TESTS_SHA="$M2"
expect 0 "$M1" none           "an earlier main commit"                          BACKEND_TAG=1.12.0 GATE_TESTS_SHA="$M1"
expect 0 "$M1" none           "an earlier main commit, no version in the tag"   BACKEND_TAG=dev GATE_TESTS_SHA="$M1"
expect 0 "$R1" release/1.11.x "the line's tip, pinned and marked"               BACKEND_TAG=1.11.13 GATE_TESTS_SHA="$R1"
expect 0 "$M1" release/1.11.x "the fork point is part of the line"              BACKEND_TAG=1.11.13 GATE_TESTS_SHA="$M1"
expect 1 -    -               "main's tip is not on the line's branch"          BACKEND_TAG=1.11.13 GATE_TESTS_SHA="$M2"
expect 1 -    -               "the line's commit is not on main"                BACKEND_TAG=1.12.0 GATE_TESTS_SHA="$R1"
expect 1 -    -               "a commit no branch contains"                     BACKEND_TAG=1.12.0 GATE_TESTS_SHA="$U1"
expect 1 -    -               "an unknown commit"                               BACKEND_TAG=1.12.0 GATE_TESTS_SHA=0000000000000000000000000000000000000000
expect 1 -    -               "a short sha"                                     BACKEND_TAG=1.12.0 GATE_TESTS_SHA="${M1:0:7}"

if [[ "$fails" -ne 0 ]]; then
  echo "switch-tests-ref.sh: $fails case(s) FAILED"
  exit 1
fi
echo "switch-tests-ref.sh: all cases passed"
