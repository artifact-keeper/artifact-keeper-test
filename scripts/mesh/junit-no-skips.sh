#!/usr/bin/env bash
# junit-no-skips.sh - fail when a JUnit directory holds a skipped test case
# (artifact-keeper/artifact-keeper#6120)
#
# Usage: scripts/mesh/junit-no-skips.sh <junit-dir>
#
# The reused tests/mesh/ scripts were written for a gate that could not
# replicate, so several report "artifact did not sync" as a SKIP, not a FAIL
# (test-artifact-sync.sh, test-replication-schedule.sh). On the nightly mesh
# topology replication is the thing under test, so in a blocking tier a skip
# is an unproven claim and the tier must go red. Prints each skipped case.
#
# Exit codes: 0 no skips and at least one case, 1 a skip or no cases at all,
# 2 usage.

set -euo pipefail

dir="${1:-}"
[ -n "$dir" ] && [ -d "$dir" ] || { echo "Usage: $0 <junit-dir>" >&2; exit 2; }

# Recursive: a tier that runs one script several times keeps each run's
# JUnit in its own subdirectory (common.sh names the file after the suite).
mapfile -t files < <(find "$dir" -name '*.xml' -type f | sort)
if [ "${#files[@]}" -eq 0 ]; then
  echo "::error::no JUnit files in ${dir}: the tier ran no test"
  exit 1
fi

cases=0 skips=0
for f in "${files[@]}"; do
  while IFS= read -r line; do
    if [[ "$line" == CASES\ * ]]; then
      cases=$(( cases + ${line#CASES } ))
      continue
    fi
    skips=$(( skips + 1 ))
    echo "::error file=${f#"$dir"/}::skipped in a blocking mesh tier: ${line}"
  done < <(python3 -I - "$f" <<'PY'
import sys
import xml.etree.ElementTree as ET
root = ET.parse(sys.argv[1]).getroot()
print(f"CASES {sum(1 for _ in root.iter('testcase'))}")
for tc in root.iter("testcase"):
    sk = tc.find("skipped")
    if sk is not None:
        print(f'{tc.get("classname", "")} / {tc.get("name", "")}: {sk.get("message", "")}')
PY
)
done

echo "JUnit: ${cases} case(s), ${skips} skipped, in ${#files[@]} file(s)"
if [ "$cases" -eq 0 ] || [ "$skips" -gt 0 ]; then
  exit 1
fi
