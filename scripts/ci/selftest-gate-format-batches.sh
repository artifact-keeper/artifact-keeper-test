#!/usr/bin/env bash
# The awk patterns are single-quoted on purpose.
# shellcheck disable=SC2016
#
# Self-test for scripts/ci/gate-format-batches.sh (artifact-keeper#6121).
#
# The nightly S3 format matrix reads its batches, their scripts and the
# toolchain install step out of release-gate.yml at run time. This pins that
# the reader still understands the gate file, and that a gate it cannot read
# is an error, never an empty matrix that passes having run nothing:
#
#   list                  every batch of the real gate, as a JSON array
#   list "<names>"        only those, in gate order; an unknown name is an error
#   scripts <batch>       non-empty, every named script exists in tests/formats
#   install-deps <batch>  the gate's step, batch substituted, no ${{ left
#   coverage              the formats #6121 names are in some batch
#   gate without format-tests, unknown batch -> exit 1
#
# Run from repo root: bash scripts/ci/selftest-gate-format-batches.sh
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SUT="${REPO_ROOT}/scripts/ci/gate-format-batches.sh"
GATE="${REPO_ROOT}/.github/workflows/release-gate.yml"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
fails=0
ok()  { echo "ok   - $*"; }
bad() { echo "FAIL - $*"; fails=$((fails + 1)); }

export GATE_WORKFLOW="$GATE"

json=$(bash "$SUT" list) || bad "list exited non-zero"
if python3 -c 'import json,sys; v=json.loads(sys.argv[1]); assert isinstance(v,list) and len(v)>=9 and all(isinstance(x,str) and x for x in v)' "$json" 2>/dev/null; then
  ok "list returns $(python3 -c 'import json,sys; print(len(json.loads(sys.argv[1])))' "$json") batches"
else
  bad "list is not a JSON array of at least 9 batch names: ${json}"
fi

# Count the gate's batches independently (a `- name:` directly followed by a
# `scripts:` line inside format-tests) so a reader that drops one is caught.
want=$(awk '/^  format-tests:[[:space:]]*$/{j=1; next} j && /^  [a-z0-9][a-z0-9-]*:[[:space:]]*$/{exit} j' "$GATE" | grep -cE '^[[:space:]]+scripts:[[:space:]]+"')
got=$(python3 -c 'import json,sys; print(len(json.loads(sys.argv[1])))' "$json" 2>/dev/null || echo 0)
[[ "$want" == "$got" ]] && ok "batch count matches the gate (${want})" || bad "gate has ${want} batches, reader returned ${got}"

all_scripts=""
for b in $(python3 -c 'import json,sys; print(" ".join(json.loads(sys.argv[1])))' "$json" 2>/dev/null); do
  s=$(bash "$SUT" scripts "$b") || { bad "scripts ${b} exited non-zero"; continue; }
  [[ -n "$s" ]] || { bad "scripts ${b} is empty"; continue; }
  missing=""
  for f in $s; do [[ -f "${REPO_ROOT}/tests/formats/${f}" ]] || missing+=" ${f}"; done
  [[ -z "$missing" ]] && ok "scripts ${b}: $(wc -w <<<"$s") scripts, all present" || bad "scripts ${b} names missing files:${missing}"
  all_scripts+=" ${s}"

  body=$(INSTALL_DRY_RUN=1 bash "$SUT" install-deps "$b") || { bad "install-deps ${b} exited non-zero"; continue; }
  if grep -qF '${{' <<<"$body"; then
    bad "install-deps ${b} still holds an expression"
  elif ! grep -qxF "BATCH=\"${b}\"" <<<"$body"; then
    bad "install-deps ${b} did not substitute the batch name"
  elif ! bash -n <<<"$body"; then
    bad "install-deps ${b} is not valid bash"
  else
    ok "install-deps ${b}: the gate's step, batch substituted"
  fi
done

# artifact-keeper#6121's minimum coverage.
for f in test-npm.sh test-pypi.sh test-maven.sh test-oci.sh test-cargo.sh test-nuget.sh test-helm.sh test-conda.sh test-debian.sh test-rpm.sh; do
  grep -qw -- "$f" <<<"$all_scripts" && ok "covers ${f}" || bad "no batch runs ${f}"
done

# The nightly's skip baseline: <batch> TAB <suite> TAB <check> TAB <why>, and
# every batch it names is a gate batch (a renamed batch would otherwise turn
# its known skips into failures, or a dead entry into a silent allowance).
BASELINE="${REPO_ROOT}/scripts/ci/s3-formats-skip-baseline.txt"
bl_bad=$(awk -F'\t' -v names=" $(python3 -c 'import json,sys; print(" ".join(json.loads(sys.argv[1])))' "$json") " '
  /^#/ || /^[[:space:]]*$/ { next }
  NF != 4 || $4 == "" { print NR ": not 4 fields"; next }
  index(names, " " $1 " ") == 0 { print NR ": unknown batch " $1 }' "$BASELINE")
[[ -z "$bl_bad" ]] && ok "skip baseline is well-formed" || bad "skip baseline: ${bl_bad}"

printf 'name: x\njobs:\n  other:\n    runs-on: x\n' > "$TMP/no-formats.yml"
GATE_WORKFLOW="$TMP/no-formats.yml" bash "$SUT" list >/dev/null 2>&1 && bad "a gate without format-tests listed batches" || ok "a gate without format-tests is an error"
sub=$(bash "$SUT" list "mcp node")
[[ "$sub" == '["node","mcp"]' ]] && ok "list filters to the named batches, gate order" || bad "list 'mcp node' gave ${sub}"
bash "$SUT" list "node nope" >/dev/null 2>&1 && bad "list accepted an unknown batch in the filter" || ok "list refuses an unknown batch in the filter"
bash "$SUT" scripts no-such-batch >/dev/null 2>&1 && bad "an unknown batch was accepted" || ok "an unknown batch is an error"
INSTALL_DRY_RUN=1 bash "$SUT" install-deps no-such-batch >/dev/null 2>&1 && bad "install-deps accepted an unknown batch" || ok "install-deps refuses an unknown batch"

if [[ "$fails" -ne 0 ]]; then
  echo "${fails} check(s) failed"
  exit 1
fi
echo "gate-format-batches self-test: all checks passed"
