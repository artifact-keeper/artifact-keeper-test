#!/usr/bin/env bash
# gate-format-batches.sh - read the release gate's format-tests matrix and its
# "Install test dependencies" step, so a lane outside the gate (the nightly S3
# format matrix, artifact-keeper#6121) runs exactly the gate's batches with the
# gate's toolchain setup, without a second hand-kept copy that drifts.
#
# Usage:
#   gate-format-batches.sh list                 JSON array of batch names
#   gate-format-batches.sh scripts <batch>      the batch's scripts, one line
#   gate-format-batches.sh install-deps <batch> run the gate's install step
#
# GATE_WORKFLOW names the gate file (default .github/workflows/release-gate.yml).
# Every lookup that finds nothing is an error (exit 1), never an empty success:
# a parse that silently returned no batches would turn the lane green having
# run nothing.
set -euo pipefail

WF="${GATE_WORKFLOW:-.github/workflows/release-gate.yml}"
[[ -f "$WF" ]] || { echo "::error title=Gate format batches::cannot read ${WF}" >&2; exit 1; }

# The format-tests job body: from `  format-tests:` to the next job key.
job_body() {
  awk '/^  format-tests:[[:space:]]*$/{in_job=1; next}
       in_job && /^  [a-z0-9][a-z0-9-]*:[[:space:]]*$/{exit}
       in_job{print}' "$WF"
}

# "name<TAB>scripts" per matrix batch.
batches() {
  job_body | awk '
    /^[[:space:]]+- name:[[:space:]]/ { n=$0; sub(/^[[:space:]]+- name:[[:space:]]*/, "", n); sub(/[[:space:]]*(#.*)?$/, "", n); next }
    n != "" && /^[[:space:]]+scripts:[[:space:]]/ { s=$0; sub(/^[[:space:]]+scripts:[[:space:]]*"/, "", s); sub(/"[[:space:]]*$/, "", s); print n "\t" s; n="" }'
}

cmd="${1:-}"
case "$cmd" in
  list)
    names="$(batches | cut -f1)"
    [[ -n "$names" ]] || { echo "::error title=Gate format batches::no format-tests batches found in ${WF}" >&2; exit 1; }
    printf '%s\n' "$names" | awk 'BEGIN{printf "["} {printf "%s\"%s\"", (NR>1?",":""), $0} END{print "]"}'
    ;;
  scripts)
    batch="${2:?batch name required}"
    line="$(batches | awk -F'\t' -v b="$batch" '$1==b{print $2}')"
    [[ -n "$line" ]] || { echo "::error title=Gate format batches::batch '${batch}' not found in ${WF}" >&2; exit 1; }
    printf '%s\n' "$line"
    ;;
  install-deps)
    batch="${2:?batch name required}"
    batches | cut -f1 | grep -qxF -- "$batch" \
      || { echo "::error title=Gate format batches::batch '${batch}' not found in ${WF}" >&2; exit 1; }
    # The step's `run: |` block, de-indented. It reads the batch from the
    # expression ${{ matrix.batch.name }}; substitute the literal name.
    script="$(job_body | awk '
      /^[[:space:]]+- name: Install test dependencies[[:space:]]*$/ { found=1; next }
      found && !inrun && /^[[:space:]]+run: \|[[:space:]]*$/ { inrun=1; next }
      inrun {
        if ($0 ~ /^[[:space:]]*$/) { print ""; next }
        match($0, /^[[:space:]]*/); ind=RLENGTH
        if (base == "") base=ind
        if (ind < base) exit
        print substr($0, base+1)
      }')"
    [[ -n "$script" ]] || { echo "::error title=Gate format batches::no 'Install test dependencies' run block in format-tests of ${WF}" >&2; exit 1; }
    grep -qF '${{ matrix.batch.name }}' <<<"$script" \
      || { echo "::error title=Gate format batches::the gate's install step no longer reads \${{ matrix.batch.name }}; update this script" >&2; exit 1; }
    script="${script//'${{ matrix.batch.name }}'/${batch}}"
    if grep -qF '${{' <<<"$script"; then
      echo "::error title=Gate format batches::the gate's install step uses an expression this script cannot evaluate:" >&2
      grep -nF '${{' <<<"$script" >&2
      exit 1
    fi
    if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then printf '%s\n' "$script"; exit 0; fi
    bash -euo pipefail -c "$script"
    ;;
  *)
    echo "Usage: gate-format-batches.sh list | scripts <batch> | install-deps <batch>" >&2
    exit 2
    ;;
esac
