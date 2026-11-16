#!/usr/bin/env bash
# The inner scripts below are single-quoted on purpose: they expand in the
# inner shell, not here.
# shellcheck disable=SC2016
# selftest-work-parent.sh - meta-test pinning where common.sh puts work dirs
# (artifact-keeper-test#732).
#
# Why this exists
# ---------------
# On the gate's dind runner pool the docker daemon runs in a sidecar that
# shares only the runner's work volume (which holds RUNNER_TEMP), not the
# runner's /tmp. A work dir under /tmp that a tier hands to `docker run -v` is
# mounted EMPTY, so the tier fails or reads as INFRA instead of giving its
# verdict, and it passes on every non-dind host. The 1.12.0 candidate run
# 42767020927 hit it twice (secrets-file-env #729, repo-delete-reclaims-
# storage-job #731). The fix is one line of parameter expansion in
# setup_workdir / dtf_mktemp_dir, which is easy to "simplify" back to a bare
# `mktemp -d` without anything going red until the next gate run.
#
# Pinned here, by running the real helpers in a fresh shell per case:
#   1. RUNNER_TEMP set              -> dirs are created under RUNNER_TEMP
#   2. DTF_WORK_PARENT set          -> it wins over RUNNER_TEMP
#   3. neither, TMPDIR set          -> under TMPDIR
#   4. neither, TMPDIR unset        -> under /tmp
#   5. an explicit parent argument (the tier-local alias knobs) wins; an
#      empty one means the default
#   6. an unwritable parent falls back to TMPDIR instead of aborting
#   7. every dir is removed on exit, and the cleanup composes with handlers
#      registered before it (add_exit_handler, not a clobbering trap)
#   8. assert_bind_mount_visible ends the suite with exit 11 (INFRA) when a
#      container provably does not see the dir, and stays out of the way when
#      it does or when the probe cannot run (docker is a stub here)
#
# Needs no deployment and no docker. Usage:
#   bash tests/lib/selftest-work-parent.sh
# Exits 0 if every case holds, 1 otherwise.

set -uo pipefail

SELFTEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMMON_SH="${SELFTEST_DIR}/common.sh"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

CASES_RUN=0
CASES_FAILED=0

ok() { echo "  PASS: $1"; }
bad() { echo "  FAIL: $1"; CASES_FAILED=$((CASES_FAILED + 1)); }

# run_inner ENV... -- SCRIPT
#   Run SCRIPT in a clean bash that sources common.sh. RUNNER_TEMP,
#   DTF_WORK_PARENT, TMPDIR and DTF_DIR are unset first (a hosted runner sets
#   RUNNER_TEMP for this very job), then ENV... (NAME=value) applied. Prints
#   Sets INNER_OUT (stdout) and INNER_RC (exit code). Call it directly, not
#   in $(...), or both are lost with the subshell.
INNER_RC=0
INNER_OUT=""
run_inner() {
  local envs=()
  while [ $# -gt 0 ] && [ "$1" != "--" ]; do envs+=("$1"); shift; done
  shift
  local script="$1"
  INNER_OUT="$(env -u RUNNER_TEMP -u DTF_WORK_PARENT -u TMPDIR -u DTF_DIR \
    JUNIT_OUTPUT_DIR="${WORK}/junit" STRESS_LOG_DIR="${WORK}/stress" \
    BASE_URL="http://127.0.0.1:1" RUN_ID="selftest-work-parent" \
    ${envs[@]+"${envs[@]}"} \
    bash -c "source \"${COMMON_SH}\"
${script}" 2>"${WORK}/inner.err")"
  INNER_RC=$?
}

# Prints "<dir> <exists:0|1>" for setup_workdir and for dtf_mktemp_dir.
PROBE='setup_workdir
dtf_mktemp_dir H selftest
printf "%s %s\n" "$WORK_DIR" "$([ -d "$WORK_DIR" ] && echo 1 || echo 0)"
printf "%s %s\n" "$H" "$([ -d "$H" ] && echo 1 || echo 0)"'

# expect_under LABEL PARENT OUTPUT
#   Every line of OUTPUT is "<dir> 1" with <dir> directly under PARENT, and
#   <dir> no longer exists now that the inner shell has exited.
expect_under() {
  local label="$1" parent="${2%/}" out="$3" line dir seen n=0 good=1
  CASES_RUN=$((CASES_RUN + 1))
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    n=$((n + 1))
    dir="${line% *}"; seen="${line##* }"
    if [ "$(dirname "$dir")" != "$parent" ]; then
      bad "${label}: ${dir} is not under ${parent}"; good=0
    elif [ "$seen" != "1" ]; then
      bad "${label}: ${dir} did not exist inside the suite"; good=0
    elif [ -e "$dir" ]; then
      bad "${label}: ${dir} still exists after the suite exited (cleanup broken)"; good=0
    fi
  done <<< "$out"
  if [ "$n" -lt 2 ]; then
    bad "${label}: expected 2 dirs, got ${n} (rc=${INNER_RC}; $(head -c 300 "${WORK}/inner.err"))"
    return
  fi
  [ "$good" = 1 ] && ok "$label"
}

echo "Work-dir parent contract (artifact-keeper-test#732)"

RT="${WORK}/runner-temp"; mkdir -p "$RT"
DP="${WORK}/dtf-parent"            # deliberately not pre-created
TD="${WORK}/tmpdir"; mkdir -p "$TD"
AL="${WORK}/alias"

run_inner "RUNNER_TEMP=${RT}" -- "$PROBE"
out="$INNER_OUT"
expect_under "RUNNER_TEMP set -> setup_workdir and dtf_mktemp_dir use it" "$RT" "$out"

run_inner "RUNNER_TEMP=${RT}" "DTF_WORK_PARENT=${DP}" "TMPDIR=${TD}" -- "$PROBE"
out="$INNER_OUT"
expect_under "DTF_WORK_PARENT set -> wins over RUNNER_TEMP and TMPDIR (created if missing)" "$DP" "$out"

run_inner "TMPDIR=${TD}" -- "$PROBE"
out="$INNER_OUT"
expect_under "neither set, TMPDIR set -> TMPDIR" "$TD" "$out"

run_inner -- "$PROBE"
out="$INNER_OUT"
expect_under "neither set, TMPDIR unset -> /tmp" "/tmp" "$out"

# 5. explicit parent argument (SF_SECRETS_PARENT / RDRS_WORK_PARENT shape).
run_inner "RUNNER_TEMP=${RT}" "DTF_WORK_PARENT=${DP}" "SF_SECRETS_PARENT=${AL}" -- '
dtf_mktemp_dir A alias "${SF_SECRETS_PARENT:-}"
dtf_mktemp_dir B alias "${RDRS_WORK_PARENT:-}"
printf "%s %s\n" "$A" "$([ -d "$A" ] && echo 1 || echo 0)"
printf "%s %s\n" "$B" "$([ -d "$B" ] && echo 1 || echo 0)"'
out="$INNER_OUT"
alias_line="$(printf '%s\n' "$out" | sed -n 1p)"
default_line="$(printf '%s\n' "$out" | sed -n 2p)"
expect_under "tier alias set -> wins over DTF_WORK_PARENT" "$AL" "$alias_line
$alias_line"
expect_under "tier alias empty -> falls through to DTF_WORK_PARENT" "$DP" "$default_line
$default_line"

# 6. unwritable parent: a regular file cannot be a directory parent.
: > "${WORK}/not-a-dir"
run_inner "DTF_WORK_PARENT=${WORK}/not-a-dir/sub" "TMPDIR=${TD}" -- "$PROBE"
out="$INNER_OUT"
expect_under "unwritable DTF_WORK_PARENT -> falls back to TMPDIR, still cleaned up" "$TD" "$out"

# 7. composes with an earlier handler and keeps the suite's exit code.
CASES_RUN=$((CASES_RUN + 1))
marker="${WORK}/earlier-handler-ran"
run_inner "RUNNER_TEMP=${RT}" -- "
add_exit_handler 'touch \"${marker}\"'
setup_workdir
echo \"\$WORK_DIR\"
exit 7"
out="$INNER_OUT"
if [ "$INNER_RC" = "7" ] && [ -f "$marker" ] && [ -n "$out" ] && [ ! -e "$out" ]; then
  ok "cleanup composes with earlier exit handlers and keeps the exit code"
else
  bad "cleanup composition: rc=${INNER_RC} (want 7), earlier handler ran=$([ -f "$marker" ] && echo yes || echo no), dir=${out:-<none>} exists=$([ -n "$out" ] && [ -e "$out" ] && echo yes || echo no)"
fi

# 8. assert_bind_mount_visible against a stub docker.
STUB="${WORK}/stub-bin"; mkdir -p "$STUB"
cat > "${STUB}/docker" <<'STUBEOF'
#!/usr/bin/env bash
# selftest stub: answer like the probe container would.
case "${DOCKER_STUB_MODE:-}" in
  seen) echo SEEN ;;
  missing) echo MISSING ;;
  *) echo "docker: stub failure" >&2; exit 125 ;;
esac
STUBEOF
chmod +x "${STUB}/docker"

BMV='begin_suite "selftest-bind-mount"
setup_workdir
assert_bind_mount_visible "$WORK_DIR" "${PROBE_IMAGE:-probe:img}"
begin_test "after the preflight"
pass
end_suite'

bmv_case() { # label mode image want_rc
  CASES_RUN=$((CASES_RUN + 1))
  run_inner "PATH=${STUB}:${PATH}" "DOCKER_STUB_MODE=$2" "PROBE_IMAGE=$3" "RUNNER_TEMP=${RT}" -- "$BMV"
  if [ "$INNER_RC" = "$4" ]; then
    ok "$1 (exit ${INNER_RC})"
  else
    bad "$1: want exit $4, got ${INNER_RC}"
  fi
}
bmv_case "assert_bind_mount_visible: container does not see the dir -> INFRA" missing probe:img 11
bmv_case "assert_bind_mount_visible: container sees the dir -> suite continues" seen probe:img 0
bmv_case "assert_bind_mount_visible: probe cannot run -> suite continues" error probe:img 0
CASES_RUN=$((CASES_RUN + 1))
left="$(find "$RT" -mindepth 1 -maxdepth 1 -printf '%f ')"
if [ -z "$left" ]; then
  ok "no work dir or probe sentinel left behind under RUNNER_TEMP"
else
  bad "left behind under RUNNER_TEMP: ${left}"
fi

echo ""
if [ "$CASES_FAILED" -eq 0 ]; then
  echo "All ${CASES_RUN} work-dir parent cases passed."
  exit 0
fi
echo "${CASES_FAILED} of ${CASES_RUN} work-dir parent case(s) failed."
exit 1
