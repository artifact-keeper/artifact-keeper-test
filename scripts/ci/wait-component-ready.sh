#!/usr/bin/env bash
# wait-component-ready.sh - wait for one chart component's pod to be Ready
# before a suite that depends on it starts (artifact-keeper-test#841).
#
# admin-tests used to wait for OpenSearch with `app.kubernetes.io/name=opensearch`
# and then `app=opensearch`. The chart sets neither (it labels pods
# app.kubernetes.io/component=<name>), so the wait always took its "no pods,
# skipping" branch and test-reindex.sh raced OpenSearch's startup. This goes
# through tests/lib/k8s.sh, the one place the chart's selectors live:
#
#   * no pod matches, or kubectl cannot list pods  -> INFRA, exit 11
#   * a pod is unschedulable or cannot pull        -> INFRA, exit 11
#   * a scheduled pod never becomes Ready          -> FAIL, exit 1
#   * a pod is Ready within the budget             -> exit 0
#
# The outcome is also a JUnit case (suite wait-<component>-ready) in
# JUNIT_OUTPUT_DIR, so a red wait is visible next to the suite it guarded.
#
# The gate installs this script with main's tests/lib/common.sh and k8s.sh
# into $RUNNER_TEMP BEFORE switch-tests-ref.sh moves the tree to a release
# line, so it does not depend on that line carrying the newest helpers.
#
# Usage: wait-component-ready.sh <component> [timeout-seconds]
#   <component>  backend | postgres | opensearch (AK_<NAME>_SELECTOR in k8s.sh)
# Environment:
#   NAMESPACE    the gate's test namespace (required)
#   K8S_LIB_DIR  directory holding common.sh and k8s.sh
#                (default: tests/lib next to this script's repository root)
set -euo pipefail

# Anything that stops the wait before it can look at a pod is gate infra
# (exit 11), never a product verdict.
infra() { echo "::error title=wait-component-ready INFRA::$*" >&2; exit 11; }

component="${1:-}"
timeout="${2:-120}"
[ -n "$component" ] || infra "usage: wait-component-ready.sh <backend|postgres|opensearch> [timeout-seconds]"
[ -n "${NAMESPACE:-}" ] || infra "NAMESPACE is not set; cannot look for the ${component} pod"

LIB_DIR="${K8S_LIB_DIR:-$(cd "$(dirname "$0")/../.." && pwd)/tests/lib}"
[ -f "${LIB_DIR}/common.sh" ] && [ -f "${LIB_DIR}/k8s.sh" ] \
  || infra "common.sh and k8s.sh not found in ${LIB_DIR} (K8S_LIB_DIR)"
# common.sh needs these for its banner only; nothing here talks to the API.
export BASE_URL="${BASE_URL:-unused}" RUN_ID="${RUN_ID:-wait-${component}}"
# shellcheck source=/dev/null
source "${LIB_DIR}/common.sh" || infra "could not source ${LIB_DIR}/common.sh"
# shellcheck source=/dev/null
source "${LIB_DIR}/k8s.sh" || infra "could not source ${LIB_DIR}/k8s.sh"
set +e  # the helpers record outcomes themselves; end_suite owns the exit code

case "$component" in
  backend)    selector="$AK_BACKEND_SELECTOR" ;;
  postgres)   selector="$AK_POSTGRES_SELECTOR" ;;
  opensearch) selector="$AK_OPENSEARCH_SELECTOR" ;;
  *) infra "unknown component '${component}'" ;;
esac

begin_suite "wait-${component}-ready"
begin_test "${component} pod (${selector}) is Ready"
# Zero matches is INFRA and aborts here: the gate deploys this component, so a
# selector that finds nothing means the selector or the deploy is wrong.
k8s_require_pod _pod "$selector" "$component"
if k8s_wait_ready "$selector" "$component" "$timeout"; then
  echo "  ${K8S_READY_POD} Ready after ${K8S_READY_ELAPSED}s"
  pass
fi
end_suite
