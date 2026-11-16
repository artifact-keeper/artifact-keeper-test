# shellcheck shell=bash
# shellcheck disable=SC2034  # K8S_READY_* and <VAR>_UID are outputs read by the caller
# tests/lib/k8s.sh - pod selection and readiness for suites that act on the
# deployed stack with kubectl (tests/resilience/**).
#
# Source AFTER tests/lib/common.sh: the helpers record outcomes through its
# pass/fail/infra_fail/end_suite and read NAMESPACE.
#
# Why this exists (artifact-keeper-test#354)
# ------------------------------------------
# Every resilience script used to select the backend with
# `-l app=artifact-keeper-backend`, a label the chart has never set. The
# selector matched nothing, and each script turned that into something that
# looked like a result:
#   * `kubectl delete pod -l <dead selector>` exits 0 ("No resources found"),
#     so "Force-kill backend pod" PASSED having killed nothing;
#   * the readiness loop never saw a ready pod, burned its whole budget and
#     SKIPPED as "ARC runner timing", a cause nobody ever measured;
#   * scripts that looked the pod up first printed "SKIP: could not find
#     backend pod" and exited 0 with no JUnit case at all.
# The meilisearch restart test had the same defect twice over: the stack runs
# OpenSearch, so `app.kubernetes.io/name=meilisearch` matched nothing either.
#
# The rules here:
#   * selectors come from ONE place, matching the labels the chart sets
#     (artifact-keeper-iac charts/artifact-keeper/templates/_helpers.tpl:
#     app.kubernetes.io/component=<backend|postgres|opensearch>, the same
#     label release-gate.yml waits on);
#   * a selector that matches no pod, or a kubectl that cannot list pods, is
#     an INFRA failure that aborts the suite (exit DTF_EXIT_INFRA = 11). It is
#     never a pass and never a skip: nothing was learned about the candidate;
#   * a readiness timeout is classified from the pod's own state: a pod the
#     cluster could not schedule or pull is INFRA, a pod that was scheduled
#     and never became ready is a product FAIL (the component did not recover).

AK_BACKEND_SELECTOR="${AK_BACKEND_SELECTOR:-app.kubernetes.io/component=backend}"
AK_POSTGRES_SELECTOR="${AK_POSTGRES_SELECTOR:-app.kubernetes.io/component=postgres}"
AK_OPENSEARCH_SELECTOR="${AK_OPENSEARCH_SELECTOR:-app.kubernetes.io/component=opensearch}"

# Poll interval for k8s_wait_ready, seconds. Overridable for the self-test.
K8S_POLL_INTERVAL="${K8S_POLL_INTERVAL:-3}"

# _k8s_pods_json SELECTOR -> pods JSON on stdout; kubectl's stderr folded in on
# failure so the caller can quote it. Returns kubectl's status.
_k8s_pods_json() {
  kubectl get pods -n "${NAMESPACE}" -l "$1" -o json 2>&1
}

# Pod listing with labels, for the diagnostic body of an INFRA failure: the
# operator sees at once which labels the pods really carry.
_k8s_namespace_listing() {
  kubectl get pods -n "${NAMESPACE}" --show-labels 2>&1 | head -40
}

# k8s_require_pod VAR SELECTOR WHAT
#
# Resolve one pod matching SELECTOR in NAMESPACE, store its name in VAR and
# its UID in VAR_UID (pass VAR_UID to k8s_wait_ready to wait for the pod that
# REPLACES it; a StatefulSet replacement keeps the name, never the UID).
# Prefers a Running pod that is not being deleted, then any matching pod.
# On zero matches or a kubectl error: infra_fail inside the CURRENT test, then
# end_suite (exits 11). Call it inside a begin_test.
k8s_require_pod() {
  local __var="$1" sel="$2" what="$3" out pod
  if ! out=$(_k8s_pods_json "$sel"); then
    infra_fail "kubectl could not list ${what} pods (selector '${sel}', namespace ${NAMESPACE})" "$out"
    echo "  ABORTING SUITE: without the ${what} pod nothing in this suite can be evaluated."
    end_suite
  fi
  local pick uid
  pick=$(printf '%s' "$out" | jq -r '
      ([.items[] | select(.metadata.deletionTimestamp == null and .status.phase == "Running")]
       + [.items[]])
      | first | select(. != null) | "\(.metadata.name) \(.metadata.uid)"' 2>/dev/null || true)
  pod="${pick%% *}"
  uid="${pick#* }"
  if [ -z "$pod" ]; then
    infra_fail "selector '${sel}' matches no ${what} pod in namespace ${NAMESPACE}" \
      "The suite cannot act on a pod it cannot find, so it has learned nothing about the candidate. Pods in the namespace:
$(_k8s_namespace_listing)"
    echo "  ABORTING SUITE: without the ${what} pod nothing in this suite can be evaluated."
    end_suite
  fi
  printf -v "$__var" '%s' "$pod"
  printf -v "${__var}_UID" '%s' "$uid"
}

# k8s_wait_ready SELECTOR WHAT TIMEOUT [EXCLUDE_UID]
#
# Wait up to TIMEOUT seconds for a pod matching SELECTOR (and whose UID is not
# EXCLUDE_UID, i.e. not the pod just deleted) that is not being deleted and whose
# containers are all ready. On success sets K8S_READY_POD and
# K8S_READY_ELAPSED and returns 0; the caller records pass(). On timeout it
# records the outcome itself and returns 1:
#   * no pod ever matched, a pod is Unschedulable, or its image cannot be
#     pulled                                  -> infra_fail (cluster, not candidate)
#   * a scheduled pod never became ready      -> fail (the component did not recover)
k8s_wait_ready() {
  local sel="$1" what="$2" timeout="$3" exclude="${4:-}"
  local elapsed=0 out ready_pod
  # shellcheck disable=SC2034  # read by the caller
  K8S_READY_POD=""
  K8S_READY_ELAPSED=0
  while :; do
    if out=$(_k8s_pods_json "$sel"); then
      ready_pod=$(printf '%s' "$out" | jq -r --arg ex "$exclude" '
          [.items[]
           | select(.metadata.deletionTimestamp == null)
           | select(.metadata.uid != $ex)
           | select((.status.containerStatuses // []) | length > 0)
           | select(all(.status.containerStatuses[]; .ready == true))]
          | first | .metadata.name // empty' 2>/dev/null || true)
      if [ -n "$ready_pod" ]; then
        # shellcheck disable=SC2034  # read by the caller
        K8S_READY_POD="$ready_pod"
        K8S_READY_ELAPSED="$elapsed"
        return 0
      fi
    fi
    if [ "$elapsed" -ge "$timeout" ]; then
      break
    fi
    sleep "$K8S_POLL_INTERVAL"
    elapsed=$(( elapsed + K8S_POLL_INTERVAL ))
  done

  # Timed out. Classify from the last observation.
  local state
  state=$(printf '%s' "$out" | jq -r --arg ex "$exclude" '
      [.items[] | select(.metadata.deletionTimestamp == null) | select(.metadata.uid != $ex)] as $live
      | if ($live | length) == 0 then "none"
        elif any($live[];
               ((.status.conditions // []) | any(.type == "PodScheduled" and .status == "False"))
               or ((.status.containerStatuses // []) + (.status.initContainerStatuses // [])
                   | any(.state.waiting.reason? as $r
                         | ["ErrImagePull","ImagePullBackOff","InvalidImageName"] | index($r))))
          then "infra"
        else "notready" end' 2>/dev/null || echo "unknown")
  local diag
  diag="kubectl get pods -l ${sel}:
$(kubectl get pods -n "${NAMESPACE}" -l "$sel" -o wide 2>&1 | head -20)

describe (tail):
$(kubectl describe pods -n "${NAMESPACE}" -l "$sel" 2>&1 | tail -40)"
  case "$state" in
    none)
      infra_fail "no ${what} pod (selector '${sel}') exists after ${timeout}s; the controller did not recreate it or the selector is wrong" \
        "${diag}

Pods in the namespace:
$(_k8s_namespace_listing)"
      ;;
    infra|unknown)
      infra_fail "${what} pod was not ready after ${timeout}s for a cluster reason (unschedulable, image pull, or kubectl unavailable)" "$diag"
      ;;
    *)
      fail "${what} pod was scheduled but did not become ready within ${timeout}s" "$diag"
      ;;
  esac
  return 1
}
