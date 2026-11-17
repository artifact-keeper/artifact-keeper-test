#!/usr/bin/env bash
# resilience-fault-injector-detach.sh - make sure the backend runs WITHOUT the
# resilience fault injector (artifact-keeper-test#842).
#
# The network and storage resilience suites patch a fault injector onto the
# backend Deployment (tests/lib/k8s.sh, k8s_fault_injector_attach), and each
# suite removes its own fault when it ends. This is the backstop. The gate
# runs it after the network and storage legs, and before the crash, restart
# and data legs, so no later suite is graded on a pod that still carries a
# fault (an iptables rule, a netem qdisc, a read-only or full storage mount)
# or the injector itself. Removing the injector rolls a fresh pod, and every
# fault lived only in the old pod. A no-op when the Deployment is not
# patched.
#
# The gate runs a copy of this script and of tests/lib/k8s.sh taken from the
# workflow's own checkout BEFORE switch-tests-ref.sh moves the tree (the same
# pattern as scripts/ci/wait-component-ready.sh, #843). A release/X.Y.x tree
# may predate the injector and have neither file; there the suites never
# attach it, and this is a quick no-op. It needs k8s.sh only, not common.sh.
#
# Requires: kubectl, jq, curl, NAMESPACE, BASE_URL.
#   K8S_LIB_DIR  directory holding k8s.sh (default: this checkout's tests/lib)
# Exit: 0 = the backend is unpatched and healthy; 11 = it could not be made
# so, or the helper library is missing (INFRA: the suites after this cannot
# be trusted).
set -uo pipefail

LIB_DIR="${K8S_LIB_DIR:-$(cd "$(dirname "$0")/.." && pwd)/tests/lib}"
if [ ! -f "${LIB_DIR}/k8s.sh" ]; then
  echo "::error title=Fault injector not removed::ak-fault: k8s.sh not found in ${LIB_DIR} (K8S_LIB_DIR); cannot check the backend for the fault injector"
  exit 11
fi
# shellcheck source=../tests/lib/k8s.sh
source "${LIB_DIR}/k8s.sh"

: "${NAMESPACE:?NAMESPACE is required}"
: "${BASE_URL:?BASE_URL is required}"

if out=$(k8s_fault_injector_detach 2>&1); then
  printf '%s\n' "$out"
  exit 0
fi
printf '%s\n' "$out"
echo "::error title=Fault injector not removed::ak-fault: the backend in ${NAMESPACE} could not be returned to an unpatched pod; later resilience suites would run on a faulted backend. $(printf '%s\n' "$out" | tail -1)"
exit 11
