#!/usr/bin/env bash
# render-gate-profiles.sh - `helm template` a chart with every release-gate
# values profile (artifact-keeper/artifact-keeper#4722)
#
# Usage:
#   ./render-gate-profiles.sh --chart-dir <path> [--helm <binary>]
#
# Reads helm/gate-profiles.txt and renders the chart once per profile, layering
# that profile's values files in order. No cluster is needed: this is the
# render-time half of the gate's `helm install`, which is where a chart
# contract change (a new `fail`, a renamed key, a schema rule) refuses the
# gate's values. The 1.11.1 candidate learned that 14 minutes in, at
# `helm install`, after artifact-keeper-iac#380 began refusing ADMIN_PASSWORD
# in backend.env and every profile here still set it that way.
#
# Callers:
#   - artifact-keeper-iac helm-ci.yml, on every chart PR, against this repo's main
#   - artifact-keeper release-candidate.yml `bookkeeping`, against the iac ref
#     the Release Gate will deploy, before the gate is dispatched
#
# Every profile is rendered even after a failure, so one run names all of them.
#
# Exit codes:
#   0  every profile rendered
#   1  at least one profile failed to render (each one named on stderr)
#   2  usage error, or the chart / a values file is missing

set -euo pipefail
# Values-file lists are split on whitespace below; never glob them.
set -f

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROFILES="${REPO_ROOT}/helm/gate-profiles.txt"
CHART_DIR=""
HELM="${HELM:-helm}"

usage() {
  echo "Usage: $0 --chart-dir <path> [--helm <binary>]" >&2
  exit 2
}

while [ $# -gt 0 ]; do
  case "$1" in
    --chart-dir) [ $# -ge 2 ] || usage; CHART_DIR="$2"; shift 2 ;;
    --helm)      [ $# -ge 2 ] || usage; HELM="$2"; shift 2 ;;
    -h|--help)   usage ;;
    *) echo "Unknown argument: $1" >&2; usage ;;
  esac
done

[ -n "$CHART_DIR" ] || usage
if [ ! -f "${CHART_DIR}/Chart.yaml" ]; then
  echo "ERROR: no Chart.yaml in ${CHART_DIR}" >&2
  exit 2
fi
CHART_DIR="$(cd "$CHART_DIR" && pwd)"

annotate() {
  # GitHub Actions error annotation when running there; plain text otherwise.
  local title="$1" msg="$2"
  if [ -n "${GITHUB_ACTIONS:-}" ]; then
    # Annotation messages are single-line: encode newlines as %0A.
    msg="${msg//'%'/'%25'}"
    msg="${msg//$'\r'/}"
    msg="${msg//$'\n'/'%0A'}"
    echo "::error title=${title}::${msg}"
  else
    echo "ERROR: ${title}: ${msg}" >&2
  fi
}

echo "Chart:    ${CHART_DIR} ($(grep -m1 '^version:' "${CHART_DIR}/Chart.yaml" || echo 'version: ?'))"
echo "Profiles: ${PROFILES}"
echo "Helm:     $("$HELM" version --short)"
echo ""

failed=()
count=0
while read -r name files; do
  case "$name" in ''|'#'*) continue ;; esac
  count=$((count + 1))
  args=()
  for f in $files; do
    case "$f" in
      chart:*) path="${CHART_DIR}/${f#chart:}" ;;
      *)       path="${REPO_ROOT}/${f}" ;;
    esac
    if [ ! -f "$path" ]; then
      annotate "Gate profile ${name} is missing a values file" "${path} does not exist (helm/gate-profiles.txt)."
      exit 2
    fi
    args+=(--values "$path")
  done

  # Rendered output is discarded: it carries the profiles' test-only
  # credentials, and only the verdict matters here.
  if out="$("$HELM" template artifact-keeper "$CHART_DIR" "${args[@]}" 2>&1 >/dev/null)"; then
    echo "ok    ${name}  (${files})"
  else
    echo "FAIL  ${name}  (${files})"
    annotate "The chart refuses the release gate's ${name} profile" \
      "helm template with ${files} failed; the Release Gate's install of this profile would fail the same way. ${out}"
    failed+=("$name")
  fi
done < "$PROFILES"

echo ""
if [ "$count" -eq 0 ]; then
  echo "ERROR: no profiles found in ${PROFILES}" >&2
  exit 2
fi
if [ "${#failed[@]}" -gt 0 ]; then
  echo "${#failed[@]} of ${count} gate profile(s) do not render: ${failed[*]}" >&2
  exit 1
fi
echo "All ${count} gate profiles render."
