#!/usr/bin/env bash
# apt-install-retry.sh - install runner toolchain packages with apt-get, retry
# a transient mirror failure, and fail LOUDLY as infrastructure when it cannot.
#
# The release gate used to install its runner tools with
#   sudo apt-get update -qq && sudo apt-get install -y -qq maven > /dev/null || true
# so one apt mirror blip ("File has unexpected size ... Mirror sync in
# progress?", "Some index files failed to download") left mvn off PATH without
# failing the step, and the suite then hard-failed under RELEASE_GATE=1 with a
# message that read like a product failure (artifact-keeper-test#728). The
# same blip took out auth-tests' oathtool install the same night.
#
# This helper:
#   * runs `apt-get update` + `apt-get install -y -qq <pkgs>` (through sudo
#     when not root), up to APT_RETRY_ATTEMPTS times with APT_RETRY_SLEEP
#     seconds between attempts;
#   * treats an `apt-get update` that exits 0 but reports index fetch errors
#     ("E: ...", "Failed to fetch", "Some index files failed to download") as
#     a failed attempt -- apt only turns those into a non-zero exit with
#     APT::Update::Error-Mode=any, which older apt ignores;
#   * after a successful install, checks each --require-cmd is on PATH, since
#     a "successful" install that leaves the tool missing is the #728 failure;
#   * on giving up, exits non-zero and prints a ::error annotation that says
#     this is an INFRA failure of the runner, not a verdict on the candidate.
#
# Usage: scripts/ci/apt-install-retry.sh [--require-cmd CMD]... [--] PKG...
# Environment:
#   APT_RETRY_ATTEMPTS  attempts before giving up (default 3)
#   APT_RETRY_SLEEP     seconds between attempts (default 15)
set -euo pipefail

ATTEMPTS="${APT_RETRY_ATTEMPTS:-3}"
SLEEP_S="${APT_RETRY_SLEEP:-15}"
TITLE="Runner toolchain install failed"

die_usage() { echo "apt-install-retry: $*" >&2; exit 2; }

[[ "$ATTEMPTS" =~ ^[1-9][0-9]*$ ]] || die_usage "APT_RETRY_ATTEMPTS must be a positive integer (got '${ATTEMPTS}')"
[[ "$SLEEP_S" =~ ^[0-9]+$ ]] || die_usage "APT_RETRY_SLEEP must be a non-negative integer (got '${SLEEP_S}')"

pkgs=()
cmds=()
while [ $# -gt 0 ]; do
  case "$1" in
    --require-cmd)
      [ $# -ge 2 ] || die_usage "--require-cmd needs a command name"
      cmds+=("$2"); shift 2 ;;
    --require-cmd=*) cmds+=("${1#*=}"); shift ;;
    --) shift; pkgs+=("$@"); break ;;
    -*) die_usage "unknown option '$1'" ;;
    *) pkgs+=("$1"); shift ;;
  esac
done
[ "${#pkgs[@]}" -gt 0 ] || die_usage "no packages named"

infra_fail() {
  local why="$1"
  echo "::error title=${TITLE}::${why} This is an INFRA failure on the runner (apt mirror, network or runner image), not a product verdict on the candidate: re-run the job."
  exit 1
}

# sudo only when we are not root, and only if it exists.
as_root=()
if [ "$(id -u)" -ne 0 ]; then
  command -v sudo >/dev/null 2>&1 || infra_fail "Not root and sudo is not available, so apt-get cannot install ${pkgs[*]}."
  as_root=(sudo)
fi
apt() { "${as_root[@]}" env DEBIAN_FRONTEND=noninteractive apt-get "$@"; }

log="$(mktemp)"
trap 'rm -f "$log"' EXIT

# An index fetch error apt reported without failing: E: lines, or the
# "Failed to fetch" / "Some index files failed to download" warnings.
index_errors() { grep -E '^E:|Failed to fetch|Some index files failed to download' "$log" || true; }

show_log() { sed 's/^/    | /' "$log" | tail -n 40; }

attempt=1
while :; do
  echo "apt-install-retry: attempt ${attempt}/${ATTEMPTS}: ${pkgs[*]}"
  ok=1
  if ! apt -qq -o APT::Update::Error-Mode=any update >"$log" 2>&1; then
    echo "apt-install-retry: apt-get update failed"; show_log; ok=0
  elif [ -n "$(index_errors)" ]; then
    echo "apt-install-retry: apt-get update exited 0 but reported index fetch errors"; show_log; ok=0
  elif ! apt install -y -qq "${pkgs[@]}" >"$log" 2>&1; then
    echo "apt-install-retry: apt-get install failed"; show_log; ok=0
  fi
  [ "$ok" -eq 1 ] && break
  if [ "$attempt" -ge "$ATTEMPTS" ]; then
    infra_fail "apt-get could not install ${pkgs[*]} after ${ATTEMPTS} attempt(s); last error above."
  fi
  attempt=$((attempt + 1))
  [ "$SLEEP_S" -eq 0 ] || sleep "$SLEEP_S"
done

hash -r
missing=()
for c in "${cmds[@]}"; do
  command -v "$c" >/dev/null 2>&1 || missing+=("$c")
done
if [ "${#missing[@]}" -gt 0 ]; then
  infra_fail "apt-get reported ${pkgs[*]} installed but ${missing[*]} is still not on PATH."
fi
echo "apt-install-retry: installed ${pkgs[*]}${cmds[*]:+ (on PATH: ${cmds[*]})}"
