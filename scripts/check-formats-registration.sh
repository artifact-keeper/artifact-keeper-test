#!/usr/bin/env bash
# check-formats-registration.sh - verify every tests/formats/test-*.sh script
# is accounted for: either named in a blocking matrix.batch.scripts field, or
# explicitly acknowledged in tests/formats/audit-excluded.txt. Anything in
# neither bucket runs nowhere -- the exact failure mode that left 59 of 120
# formats scripts, including the regression gate test-oci-token-refresh-
# reuse-2477.sh, silently unexecuted (see the formats-autodiscovery issue).
#
# This does not run any test script and touches no cluster. It is meant to
# run as an early, cluster-free job so a stale script reference fails fast,
# before `deploy` spends any runner/cluster time.
#
# Usage: check-formats-registration.sh <workflow-file> [workflow-file ...]
#
# Exits non-zero if:
#   - a batch in a given workflow file names a script that does not exist
#     in tests/formats/ (stale/typo'd reference)
#   - audit-excluded.txt lists a script that does not exist
#   - a script is both blocking in a workflow file AND listed in
#     audit-excluded.txt (ambiguous -- pick one)
#
# It cannot, by construction, find a script that is in neither the blocking
# set nor the audit lane: the audit lane for each workflow file is defined
# at run time as "every discovered script minus that file's own blocking
# set minus audit-excluded.txt" (see the "Run formats audit lane" step in
# format-tests.yml / release-gate.yml). This script's job is to make that
# split legible in CI logs and to catch the two concrete error classes
# above before they cause confusing mid-run failures or silent gaps.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
FORMATS_DIR="${REPO_ROOT}/tests/formats"
EXCLUDE_FILE="${FORMATS_DIR}/audit-excluded.txt"

if [ $# -eq 0 ]; then
  echo "Usage: $0 <workflow-file> [workflow-file ...]"
  exit 1
fi

STATUS=0

contains() {
  # contains <needle> <haystack-array-name>
  local needle="$1"
  shift
  local item
  for item in "$@"; do
    [ "$item" = "$needle" ] && return 0
  done
  return 1
}

# All formats scripts that actually exist on disk right now -- the same
# glob run-suite.sh uses. This is the live, auto-discovered truth; nothing
# here is a hand-maintained list.
mapfile -t ALL < <(find "$FORMATS_DIR" -maxdepth 1 -name 'test-*.sh' -type f -printf '%f\n' | sort)
echo "Discovered ${#ALL[@]} script(s) in tests/formats/"

# Explicitly acknowledged exclusions: scripts that should run in NEITHER
# the blocking gate NOR the audit lane. Empty today -- this exists so a
# future maintainer has a visible, reviewable place to opt a script fully
# out (e.g. a genuinely dead script pending deletion) instead of it just
# quietly falling off a hand-maintained list again.
EXCLUDED_ACK=()
if [ -f "$EXCLUDE_FILE" ]; then
  mapfile -t EXCLUDED_ACK < <(grep -vE '^\s*#|^\s*$' "$EXCLUDE_FILE" | sort -u)
fi
echo "Explicitly acknowledged exclusions (audit-excluded.txt): ${#EXCLUDED_ACK[@]}"
for s in "${EXCLUDED_ACK[@]}"; do
  if ! contains "$s" "${ALL[@]}"; then
    echo "  ERROR: audit-excluded.txt lists '${s}' which does not exist in tests/formats/"
    STATUS=1
  fi
done

for WF in "$@"; do
  if [ ! -f "$WF" ]; then
    echo "ERROR: workflow file not found: ${WF}"
    STATUS=1
    continue
  fi

  # Restrict to lines that declare a batch's script list. `scripts:` is
  # currently unique to the formats matrix in both workflow files (nothing
  # else in .github/workflows uses that key) -- if that ever changes, this
  # will start over- or under-counting and this script's own totals will
  # visibly stop matching `find tests/formats -name 'test-*.sh' | wc -l`.
  mapfile -t BLOCKING < <(grep 'scripts:' "$WF" | grep -oE 'test-[a-zA-Z0-9.-]+\.sh' | sort -u)

  echo ""
  echo "=== ${WF} ==="
  echo "  Blocking (named in a matrix.batch.scripts field): ${#BLOCKING[@]}"

  for s in "${BLOCKING[@]}"; do
    if ! contains "$s" "${ALL[@]}"; then
      echo "  ERROR: '${s}' is named in a batch in ${WF} but no such file exists in tests/formats/"
      STATUS=1
    fi
    if contains "$s" "${EXCLUDED_ACK[@]}"; then
      echo "  ERROR: '${s}' is both blocking in ${WF} and listed in audit-excluded.txt -- pick one"
      STATUS=1
    fi
  done

  AUDIT_COUNT=0
  for s in "${ALL[@]}"; do
    if ! contains "$s" "${BLOCKING[@]}" && ! contains "$s" "${EXCLUDED_ACK[@]}"; then
      AUDIT_COUNT=$(( AUDIT_COUNT + 1 ))
    fi
  done
  echo "  Audit lane (discovered, not blocking, not excluded): ${AUDIT_COUNT}"
  echo "  Accounted for: $(( ${#BLOCKING[@]} + AUDIT_COUNT )) blocking+audit, plus ${#EXCLUDED_ACK[@]} excluded, of ${#ALL[@]} discovered"
done

if [ "$STATUS" -ne 0 ]; then
  echo ""
  echo "FAILED: fix the errors above."
  exit 1
fi

echo ""
echo "OK: every tests/formats/test-*.sh script is accounted for in each workflow checked."
