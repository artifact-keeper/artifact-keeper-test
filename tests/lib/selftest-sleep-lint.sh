#!/usr/bin/env bash
# selftest-sleep-lint.sh - no unexplained fixed sleep in a blocking suite
# (artifact-keeper-test#364).
#
# Why this exists
# ---------------
# The dominant false-red class in the release gate was `sleep N; assert ...`:
# a fixed sleep standing in for an asynchronous precondition (an index
# refresh, a 202-then-background job, a delivery row, a cache writer task).
# It is dead time on an idle backend and too short on a loaded one, and a
# loaded backend is exactly what a release candidate runs on. #364 counted
# 204 such sites across 124 blocking suites and drained them by area onto
# `wait_until` / `assert_eventually` and the purpose-built wait helpers in
# tests/lib/common.sh.
#
# This lint keeps the 205th from being written. In the suite directories the
# release gate runs as blocking jobs, every whole-second `sleep N` (N >= 1)
# must either be gone, or carry a reason on the same line:
#
#     sleep 3  # sleep-ok: cache TTL is 2 s; the entry must have expired
#
# Legitimate reasons are passage of time the test is ABOUT (TTL or cache
# expiry, rate-limit windows, timestamp-second separation, a "nothing happens
# within N s" negative check) and the interval of an already-bounded poll
# loop. Sub-second sleeps (`sleep 0.2`) and variable intervals
# (`sleep "$interval"`) are poll intervals by construction and are not
# matched.
#
# The checker runs against fixtures first (one compliant file, one broken
# copy per rule), so a checker that stops detecting anything turns this red
# instead of passing the real tree.
#
# Usage: bash tests/lib/selftest-sleep-lint.sh [repo-root]
# Exits 0 when the fixtures behave and the tree is clean, 1 otherwise.
set -uo pipefail

SELFTEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="${1:-$(cd "${SELFTEST_DIR}/../.." && pwd)}"

# The blocking suite directories: each is a `run-suite.sh --suite <dir>`
# job on the release gate's verdict predicate (or security's, which gates
# the strict form). Advisory-only trees (stress, resilience, mesh,
# scenarios) are out of scope.
BLOCKING_DIRS="admin auth compatibility formats lifecycle platform promotion pullthrough rbac repos search security webhooks"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# lint_tree ROOT DIRS...: prints one "path:line: text" per unexplained sleep.
lint_tree() {
  local root="$1"; shift
  local d
  for d in "$@"; do
    [ -d "${root}/tests/${d}" ] || continue
    find "${root}/tests/${d}" -type f -name '*.sh' -print0
  done | sort -z | xargs -0 -r awk -v root="${root}/" '
    # A literal `sleep N` with N >= 1 used as a command: at the start of the
    # line, or after ; & | then do else. Comments are stripped first.
    {
      line = $0
      code = line
      sub(/#.*/, "", code)
      rest = code
      hit = 0
      while (match(rest, /(^|[;&|]|[[:space:]]then|[[:space:]]do|[[:space:]]else)[[:space:]]*sleep[[:space:]]+[0-9]+(\.[0-9]+)?([[:space:];&|)]|$)/)) {
        seg = substr(rest, RSTART, RLENGTH)
        sub(/.*sleep[[:space:]]+/, "", seg)
        if (seg + 0 >= 1) { hit = 1; break }
        rest = substr(rest, RSTART + RLENGTH)
      }
      if (hit && line !~ /#[[:space:]]*sleep-ok:[[:space:]]*[^[:space:]]/) {
        f = FILENAME
        sub("^" root, "", f)
        printf "%s:%d: %s\n", f, FNR, line
      }
    }'
}

fail_count=0
expect() { # LABEL WANT_HITS FIXTURE_ROOT
  local label="$1" want="$2" froot="$3" got
  got=$(lint_tree "$froot" fx | wc -l | tr -d ' ')
  if [ "$got" -ne "$want" ]; then
    echo "FAIL: ${label}: ${got} hits, want ${want}"
    lint_tree "$froot" fx | sed 's/^/    /'
    fail_count=$((fail_count + 1))
  else
    echo "ok:   ${label}"
  fi
}

mkfx() { # NAME, body on stdin
  mkdir -p "${WORK}/$1/tests/fx"
  cat > "${WORK}/$1/tests/fx/test-x.sh"
}

mkfx good <<'SH'
#!/usr/bin/env bash
sleep 0.2
sleep 0.25
sleep "$interval"
sleep "${WAIT_UNTIL_INTERVAL:-1}"
sleep 3  # sleep-ok: TTL is 2 s, the entry must have expired
for i in 1 2 3; do curl x || sleep 1; done  # sleep-ok: poll interval
# sleep 5 in a comment is not a command
SH

mkfx bare <<'SH'
sleep 1
SH
mkfx indented <<'SH'
if true; then
    sleep 2
fi
SH
mkfx chained <<'SH'
upload x && sleep 5
SH
mkfx inline-then <<'SH'
if true; then sleep 2; fi
SH
mkfx reasonless <<'SH'
sleep 2  # sleep-ok:
SH
mkfx other-comment <<'SH'
sleep 2  # give the indexer a moment
SH
mkfx fractional-long <<'SH'
sleep 1.5
SH

expect "compliant fixture is clean"                0 "${WORK}/good"
expect "bare sleep 1"                              1 "${WORK}/bare"
expect "indented sleep 2"                          1 "${WORK}/indented"
expect "sleep after &&"                            1 "${WORK}/chained"
expect "sleep after then on one line"              1 "${WORK}/inline-then"
expect "sleep-ok marker without a reason"          1 "${WORK}/reasonless"
expect "an ordinary comment is not a reason"       1 "${WORK}/other-comment"
expect "sleep 1.5 is a whole-second-scale guess"   1 "${WORK}/fractional-long"

if [ "$fail_count" -ne 0 ]; then
  echo "sleep lint self-test failed (${fail_count}); not trusting it on ${ROOT}"
  exit 1
fi

# shellcheck disable=SC2086 # BLOCKING_DIRS is a word list by design
hits=$(lint_tree "$ROOT" $BLOCKING_DIRS)
if [ -n "$hits" ]; then
  echo "--- tests/{${BLOCKING_DIRS// /,}}"
  printf '%s\n' "$hits"
  echo "FAIL: $(printf '%s\n' "$hits" | wc -l | tr -d ' ') fixed sleep(s) in blocking suites without a '# sleep-ok: <reason>' (artifact-keeper-test#364)."
  echo "Replace each with a bounded poll on the precondition the next assertion needs (wait_until / assert_eventually in tests/lib/common.sh), or, when the passage of time is itself the point, keep it and say why on the same line."
  exit 1
fi
echo "--- tests/{${BLOCKING_DIRS// /,}}"
echo "ok:   no unexplained fixed sleep in a blocking suite"
