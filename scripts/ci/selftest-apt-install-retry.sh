#!/usr/bin/env bash
# selftest-apt-install-retry.sh - pins what scripts/ci/apt-install-retry.sh
# does when apt succeeds, blips, keeps failing, lies, or installs nothing
# usable (artifact-keeper-test#728).
#
# The helper exists because `apt-get ... || true` turned a mirror blip into a
# missing tool and then into a red suite that read like a product failure. It
# fails safe in one direction only: drop the retry, the index-error check or
# the --require-cmd check and nothing turns red on a healthy mirror. So this
# runs it against stub `apt-get` and `sudo` executables on PATH that act out
# each case, and asserts the exit code, the number of attempts and the INFRA
# annotation. No network, no root, no real apt; well under a second.
#
# Usage: scripts/ci/selftest-apt-install-retry.sh
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
H="$ROOT/scripts/ci/apt-install-retry.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
BIN="$WORK/bin"
mkdir -p "$BIN"
fails=0
ANNOTATION='::error title=Runner toolchain install failed::'

# sudo stub: run the command as-is (the helper only needs the hand-off).
cat > "$BIN/sudo" <<'STUB'
#!/usr/bin/env bash
exec "$@"
STUB

# apt-get stub. STUB_SCRIPT names one behaviour per attempt, comma separated
# (the last one repeats): ok | update-fail | update-silent-err | install-fail |
# install-nothing. Each call is logged to $STUB_STATE/calls. On a successful
# install it puts the STUB_PROVIDES command on PATH, as a real package would.
cat > "$BIN/apt-get" <<'STUB'
#!/usr/bin/env bash
set -u
calls="$STUB_STATE/calls"
sub=""
for a in "$@"; do case "$a" in update|install) sub="$a" ;; esac; done
echo "$sub" >> "$calls"
n=$(grep -c '^update$' "$calls")
IFS=, read -r -a plan <<< "$STUB_SCRIPT"
i=$(( n - 1 )); [ "$i" -lt "${#plan[@]}" ] || i=$(( ${#plan[@]} - 1 ))
mode="${plan[$i]}"
case "$sub:$mode" in
  update:update-fail)
    echo "E: Failed to fetch http://security.ubuntu.com/ubuntu/dists/noble-security/main/binary-amd64/Packages.gz  File has unexpected size (1426608 != 1426588). Mirror sync in progress?"
    echo "E: Some index files failed to download. They have been ignored, or old ones used instead."
    exit 100 ;;
  update:update-silent-err)
    echo "W: Failed to fetch http://azure.archive.ubuntu.com/ubuntu/dists/noble-updates/InRelease  Hash Sum mismatch"
    echo "E: Some index files failed to download. They have been ignored, or old ones used instead."
    exit 0 ;;
  install:install-fail)
    echo "E: Unable to fetch some archives, maybe run apt-get update or try with --fix-missing?"
    exit 100 ;;
  install:install-nothing) exit 0 ;;
  install:*)
    if [ -n "${STUB_PROVIDES:-}" ]; then
      printf '#!/bin/sh\nexit 0\n' > "$STUB_BIN/$STUB_PROVIDES"; chmod +x "$STUB_BIN/$STUB_PROVIDES"
    fi
    exit 0 ;;
esac
exit 0
STUB
chmod +x "$BIN/sudo" "$BIN/apt-get"

# expect <want rc> <updates> <installs> <want annotation 0|1> <label> <plan> [helper args...]
expect() {
  local want="$1" want_upd="$2" want_inst="$3" want_ann="$4" label="$5" plan="$6"; shift 6
  local state out rc upd inst ann bad=""
  state="$(mktemp -d "$WORK/case.XXXXXX")"; : > "$state/calls"
  rm -f "$BIN/fake-tool-728"
  out="$(env -i PATH="$BIN:$PATH" HOME="$WORK" STUB_STATE="$state" STUB_BIN="$BIN" \
    STUB_SCRIPT="$plan" STUB_PROVIDES=fake-tool-728 APT_RETRY_ATTEMPTS="${ATTEMPTS:-3}" APT_RETRY_SLEEP=0 \
    bash "$H" "$@" 2>&1)"; rc=$?
  upd=$(grep -c '^update$' "$state/calls"); inst=$(grep -c '^install$' "$state/calls")
  if grep -qF "$ANNOTATION" <<<"$out" && grep -q 'INFRA failure on the runner' <<<"$out" \
     && grep -q 'not a product verdict' <<<"$out"; then ann=1; else ann=0; fi
  if [ "$want" = "nonzero" ]; then [ "$rc" -ne 0 ] || bad="exit $rc, want non-zero"
  else [ "$rc" = "$want" ] || bad="exit $rc, want $want"; fi
  [ "$upd" = "$want_upd" ] || bad="${bad:+$bad; }$upd update call(s), want $want_upd"
  [ "$inst" = "$want_inst" ] || bad="${bad:+$bad; }$inst install call(s), want $want_inst"
  [ "$ann" = "$want_ann" ] || bad="${bad:+$bad; }INFRA annotation present=$ann, want $want_ann"
  if [ -z "$bad" ]; then
    echo "  PASS  $label"
  else
    echo "  FAIL  $label: $bad"
    printf '%s\n' "$out" | sed 's/^/        /'
    fails=$((fails + 1))
  fi
}

echo "apt-install-retry.sh: healthy and transient apt"
expect 0 1 1 0 "(a) success on the first attempt, required command on PATH" \
  ok --require-cmd fake-tool-728 maven
expect 0 2 1 0 "(b) mirror blip on update, then success: retried, exit 0" \
  update-fail,ok --require-cmd fake-tool-728 oathtool
expect 0 2 2 0 "(b) install fails once, then success: retried, exit 0" \
  install-fail,ok maven
expect 0 2 1 0 "(d) update exits 0 with an index error, then success: retried" \
  update-silent-err,ok openjdk-17-jdk-headless

echo "apt-install-retry.sh: persistent failure is a loud INFRA failure"
expect nonzero 3 3 1 "(c) install keeps failing: 3 attempts, non-zero, INFRA annotation" \
  install-fail maven
expect nonzero 3 0 1 "(c) update keeps failing: 3 attempts, non-zero, INFRA annotation" \
  update-fail python3-venv
ATTEMPTS=2 expect nonzero 2 0 1 "(c) APT_RETRY_ATTEMPTS=2 is honoured" \
  update-fail zip
expect nonzero 3 0 1 "(d) update always exits 0 with an index error: counts as failure" \
  update-silent-err oathtool
expect nonzero 1 1 1 "(e) install 'succeeds' but the required command is missing" \
  install-nothing --require-cmd fake-tool-728 maven

echo "apt-install-retry.sh: bad invocations are refused"
expect 2 0 0 0 "no packages named" ok
expect 2 0 0 0 "--require-cmd without a value" ok maven --require-cmd
ATTEMPTS=0 expect 2 0 0 0 "APT_RETRY_ATTEMPTS=0" ok maven

if [ "$fails" -ne 0 ]; then
  echo "apt-install-retry.sh: $fails case(s) FAILED"
  exit 1
fi
echo "apt-install-retry.sh: all cases passed"
