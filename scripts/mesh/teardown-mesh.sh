#!/usr/bin/env bash
# teardown-mesh.sh - collect logs from, then delete, a nightly mesh namespace
# (artifact-keeper/artifact-keeper#6120)
#
# Usage:
#   scripts/mesh/teardown-mesh.sh --namespace <ns> [--logs-dir <dir>] [--sweep-older-than <hours>]
#
# Collects every container's log (ephemeral fault-injection containers
# included), pod descriptions, events and the quota's usage into --logs-dir,
# then deletes the namespace and WAITS until it is gone. Exits non-zero only
# when the namespace still exists after the wait: a leaked namespace on rocky
# is worth a human's look, a missing one (deploy never ran) is not.
#
# --sweep-older-than H also deletes OTHER namespaces this lane created
# (label artifact-keeper.io/lane=nightly-mesh) that are older than H hours: a
# runner that died mid-teardown cannot leave one behind for more than a day.
# Only namespaces carrying that label are ever considered.

set -uo pipefail

NS=""
LOGS_DIR="${RUNNER_TEMP:-/tmp}/mesh-logs"
SWEEP_HOURS=""
WAIT_SECS="${TEARDOWN_WAIT_SECS:-300}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --namespace)        NS="$2"; shift 2 ;;
    --logs-dir)         LOGS_DIR="$2"; shift 2 ;;
    --sweep-older-than) SWEEP_HOURS="$2"; shift 2 ;;
    *) echo "Usage: $0 --namespace <ns> [--logs-dir <dir>] [--sweep-older-than <hours>]" >&2; exit 2 ;;
  esac
done
[ -n "$NS" ] || { echo "--namespace is required" >&2; exit 2; }

# ns_state NS : prints present, gone (a definite NotFound) or error. Only
# NotFound counts as gone: an API hiccup or an RBAC refusal must not read as
# a clean teardown.
ns_state() {
  local out
  if out=$(kubectl get namespace "$1" -o name 2>&1); then
    echo present
  elif printf '%s' "$out" | grep -q 'NotFound'; then
    echo gone
  else
    echo error
  fi
}

delete_and_wait() {
  local ns="$1" deadline
  kubectl delete namespace "$ns" --wait=false >/dev/null 2>&1 || true
  deadline=$(( $(date +%s) + WAIT_SECS ))
  while [ "$(ns_state "$ns")" != gone ]; do
    if [ "$(date +%s)" -ge "$deadline" ]; then
      echo "::error::namespace ${ns} not confirmed gone ${WAIT_SECS}s after delete (state: $(ns_state "$ns"); leaked or unreadable, look at its finalizers)"
      kubectl get namespace "$ns" -o yaml 2>/dev/null | sed -n '/status:/,$p'
      return 1
    fi
    sleep 5
  done
  echo "namespace ${ns} deleted"
  return 0
}

rc=0

state=$(ns_state "$NS")
if [ "$state" = error ]; then
  echo "::error::cannot read namespace ${NS} (API or RBAC error); not claiming a clean teardown"
  kubectl get namespace "$NS" 2>&1 | tail -3
  exit 1
fi
if [ "$state" = present ]; then
  mkdir -p "${LOGS_DIR}/${NS}"
  d="${LOGS_DIR}/${NS}"
  kubectl -n "$NS" get pods -o wide > "${d}/pods.txt" 2>&1 || true
  kubectl -n "$NS" describe pods > "${d}/describe-pods.txt" 2>&1 || true
  kubectl -n "$NS" get events --sort-by=.lastTimestamp > "${d}/events.txt" 2>&1 || true
  kubectl -n "$NS" describe resourcequota > "${d}/quota.txt" 2>&1 || true
  for pod in $(kubectl -n "$NS" get pods -o jsonpath='{.items[*].metadata.name}' 2>/dev/null); do
    for c in $(kubectl -n "$NS" get pod "$pod" -o jsonpath='{.spec.initContainers[*].name} {.spec.containers[*].name} {.spec.ephemeralContainers[*].name}' 2>/dev/null); do
      kubectl -n "$NS" logs "$pod" -c "$c" > "${d}/${pod}.${c}.log" 2>&1 || true
      kubectl -n "$NS" logs "$pod" -c "$c" --previous > "${d}/${pod}.${c}.previous.log" 2>/dev/null || rm -f "${d}/${pod}.${c}.previous.log"
    done
  done
  echo "logs collected in ${d}"
  for r in $(helm list -n "$NS" -q 2>/dev/null); do
    helm uninstall "$r" -n "$NS" --wait=false >/dev/null 2>&1 || true
  done
  delete_and_wait "$NS" || rc=1
else
  echo "namespace ${NS} does not exist (deploy never created it, or it is already gone)"
fi

if [ -n "$SWEEP_HOURS" ]; then
  if ! [[ "$SWEEP_HOURS" =~ ^[0-9]+$ ]]; then
    echo "--sweep-older-than must be whole hours" >&2
    exit 2
  fi
  cutoff=$(( $(date +%s) - SWEEP_HOURS * 3600 ))
  kubectl get namespaces -l artifact-keeper.io/lane=nightly-mesh -o json 2>/dev/null \
    | jq -r '.items[] | .metadata.name + " " + .metadata.creationTimestamp' \
    | while read -r name created; do
        [ "$name" = "$NS" ] && continue
        ts=$(date -d "$created" +%s 2>/dev/null) || continue
        if [ "$ts" -lt "$cutoff" ]; then
          echo "sweeping stale mesh namespace ${name} (created ${created})"
          kubectl delete namespace "$name" --wait=false || true
        fi
      done
fi

exit "$rc"
