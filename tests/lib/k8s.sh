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

# ===========================================================================
# Fault injection (artifact-keeper-test#842)
# ===========================================================================
#
# The network and storage suites need tc, iptables and mount in the backend's
# namespaces. The backend image ships none of them (no sh either), so
# `kubectl exec <backend> -- tc ...` can never work. Until #842 those suites
# skipped, and nothing was injected or learned.
#
# Why a patched-in sidecar and not `kubectl debug`: on the gate cluster the
# runner's ClusterRole (arc-e2e-runner) has no pods/ephemeralcontainers, so
# ephemeral debug containers are Forbidden. It may patch Deployments in the
# test namespace, so k8s_fault_injector_attach adds two containers to the
# backend Deployment's pod template:
#
#   fault-net  netshoot, root with NET_ADMIN + NET_RAW only. It shares the
#              pod's network namespace, so tc and iptables act on the
#              backend's own traffic.
#   fault-fs   static busybox, privileged. shareProcessNamespace puts the
#              backend's processes in its /proc, and it nsenters the backend
#              container's MOUNT namespace to remount the storage path. It
#              runs /proc/<its shell>/root/bin/busybox there, because the
#              backend's filesystem has no binaries and a static busybox
#              needs no loader.
#
# The change is a runtime patch made ONLY by the resilience scripts that need
# it. The chart, its defaults, the backend image and the values every other
# gate suite deploys with are unchanged. The patch also pins
# kubectl.kubernetes.io/default-container=backend, so a `kubectl exec` or
# `kubectl logs` without -c still reaches the backend. Container statuses
# sort by name, so containerStatuses[0] is still "backend".
#
# Storage faults never touch the node's disk. The gate's PVCs are local-path
# (host directories with no quota), so filling the real volume would fill the
# node, and that node also runs production. Disk-full therefore mounts a small
# fixed-size tmpfs over the storage path inside the backend's mount
# namespace. Read-only is a per-mount `remount,bind,ro` of that path, in that
# namespace only (container mounts are rprivate, so nothing propagates).
#
# Contract: a fault that cannot be set up, or that is set up but cannot be
# shown to have taken effect, is INFRA (infra_fail + end_suite, exit 11),
# never a skip and never a pass.

AK_FAULT_NET_IMAGE="${AK_FAULT_NET_IMAGE:-docker.io/nicolaka/netshoot:v0.13@sha256:a20c2531bf35436ed3766cd6cfe89d352b050ccc4d7005ce6400adf97503da1b}"
AK_FAULT_FS_IMAGE="${AK_FAULT_FS_IMAGE:-docker.io/library/busybox:1.37.0-musl@sha256:f6a95d611e0a8780fabdb2aec43e31275b2720dfefa3e41b16835bfc42454478}"
AK_BACKEND_CONTAINER="${AK_BACKEND_CONTAINER:-backend}"
# The chart mounts the backend's storage volume (subPath storage) here, and
# STORAGE_PATH defaults to it (artifact-keeper-iac values.yaml).
AK_STORAGE_MOUNT="${AK_STORAGE_MOUNT:-/data/storage}"
K8S_FAULT_ROLLOUT_TIMEOUT="${K8S_FAULT_ROLLOUT_TIMEOUT:-420}"
K8S_FAULT_HEALTH_TIMEOUT="${K8S_FAULT_HEALTH_TIMEOUT:-180}"
# Source name of the disk-full tmpfs, so removal unmounts only our mount.
K8S_FAULT_FULL_SOURCE="ak-fault-full"
# Placeholder source for remounts. Given only a target, busybox mount looks
# the mount up in /proc/mounts, and on the gate's backend pod that lookup
# failed ("mount: can't find /data/storage in /proc/mounts", release-gate run
# 43966241690) although the mount is there; the backend's overlay root line
# (one lowerdir per image layer) is the likely culprit. With a source and a
# target busybox does no lookup, and the kernel ignores the source on
# MS_REMOUNT.
K8S_FAULT_REMOUNT_SOURCE="ak-fault-remount"
# Exit status of the fs helper when no process has the storage path mounted.
K8S_FAULT_NO_BACKEND_RC=97

# _k8s_fault_abort MSG [BODY]: an injection that cannot be set up. INFRA in
# the current test, then end the suite (exit 11).
_k8s_fault_abort() {
  infra_fail "$1" "${2:-}"
  echo "  ABORTING SUITE: the fault could not be injected, so nothing here is a verdict on the candidate."
  end_suite
}

# Strategic-merge patch that adds the injector. The images are pinned by
# digest. The sleeps keep the containers idle until a test execs into them.
_k8s_fault_patch_json() {
  jq -cn --arg net "$AK_FAULT_NET_IMAGE" --arg fs "$AK_FAULT_FS_IMAGE" --arg be "$AK_BACKEND_CONTAINER" '{
    spec: {template: {
      metadata: {annotations: {
        "kubectl.kubernetes.io/default-container": $be,
        "artifact-keeper-test/fault-injector": "artifact-keeper-test#842"}},
      spec: {
        shareProcessNamespace: true,
        containers: [
          {name: "fault-net", image: $net, imagePullPolicy: "IfNotPresent",
           command: ["sleep", "2147483647"],
           securityContext: {runAsUser: 0, runAsNonRoot: false, allowPrivilegeEscalation: false,
                             capabilities: {drop: ["ALL"], add: ["NET_ADMIN", "NET_RAW"]}},
           resources: {requests: {cpu: "10m", memory: "16Mi"}, limits: {cpu: "500m", memory: "128Mi"}}},
          {name: "fault-fs", image: $fs, imagePullPolicy: "IfNotPresent",
           command: ["sleep", "2147483647"],
           securityContext: {privileged: true, runAsUser: 0, runAsNonRoot: false},
           resources: {requests: {cpu: "10m", memory: "16Mi"}, limits: {cpu: "500m", memory: "96Mi"}}}
        ]}}}}'
}

# Wait for the backend to answer /health with 200 through the Service. The
# selftest redefines it.
_k8s_fault_wait_health() {
  local waited=0
  while [ "$waited" -lt "$K8S_FAULT_HEALTH_TIMEOUT" ]; do
    if curl -sf -o /dev/null --max-time 5 "${BASE_URL}/health" 2>/dev/null; then
      return 0
    fi
    sleep 3
    waited=$(( waited + 3 ))
  done
  return 1
}

# Like _k8s_fault_wait_health, but 503 counts as an answer too.
_k8s_fault_wait_answer() {
  local waited=0 code
  while [ "$waited" -lt "$K8S_FAULT_HEALTH_TIMEOUT" ]; do
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "${BASE_URL}/health" 2>/dev/null || true)
    case "$code" in 200|503) return 0 ;; esac
    sleep 3
    waited=$(( waited + 3 ))
  done
  return 1
}

# k8s_fault_injector_attach VAR
#
# Make sure the backend pod carries the fault injector, and store the pod's
# name in VAR. The first caller in a namespace patches the Deployment, which
# rolls the backend pod once. Later callers find the patch in place and roll
# nothing. Every failure is INFRA and ends the suite. Call it inside a
# begin_test, then pass() on return.
k8s_fault_injector_attach() {
  local __var="$1" out deploy n has rc
  if ! out=$(kubectl get deployments -n "${NAMESPACE}" -l "$AK_BACKEND_SELECTOR" -o json 2>&1); then
    _k8s_fault_abort "kubectl could not list backend Deployments (selector '${AK_BACKEND_SELECTOR}', namespace ${NAMESPACE})" "$out"
  fi
  n=$(printf '%s' "$out" | jq '.items | length' 2>/dev/null || echo 0)
  if [ "$n" != "1" ]; then
    _k8s_fault_abort "expected exactly one backend Deployment (selector '${AK_BACKEND_SELECTOR}'), found ${n}" \
      "$(kubectl get deployments -n "${NAMESPACE}" --show-labels 2>&1 | head -20)"
  fi
  deploy=$(printf '%s' "$out" | jq -r '.items[0].metadata.name')
  has=$(printf '%s' "$out" | jq -r '[.items[0].spec.template.spec.containers[].name] as $c
        | (($c | index("fault-net")) != null and ($c | index("fault-fs")) != null
           and .items[0].spec.template.spec.shareProcessNamespace == true)')
  if [ "$has" = "true" ]; then
    echo "  Fault injector already on deployment/${deploy}"
  else
    echo "  Patching deployment/${deploy} with the fault injector (fault-net, fault-fs, shareProcessNamespace)"
    echo "    net image: ${AK_FAULT_NET_IMAGE}"
    echo "    fs image:  ${AK_FAULT_FS_IMAGE}"
    if ! out=$(kubectl patch deployment "$deploy" -n "${NAMESPACE}" --type strategic -p "$(_k8s_fault_patch_json)" 2>&1); then
      _k8s_fault_abort "kubectl could not patch deployment/${deploy} with the fault injector" "$out"
    fi
  fi
  if ! out=$(kubectl rollout status "deployment/${deploy}" -n "${NAMESPACE}" --timeout="${K8S_FAULT_ROLLOUT_TIMEOUT}s" 2>&1); then
    _k8s_fault_abort "deployment/${deploy} did not roll out with the fault injector within ${K8S_FAULT_ROLLOUT_TIMEOUT}s" \
      "${out}

$(kubectl get pods -n "${NAMESPACE}" -l "$AK_BACKEND_SELECTOR" -o wide 2>&1 | head -10)

describe (tail):
$(kubectl describe pods -n "${NAMESPACE}" -l "$AK_BACKEND_SELECTOR" 2>&1 | tail -40)"
  fi
  local pod
  if ! out=$(_k8s_pods_json "$AK_BACKEND_SELECTOR"); then
    _k8s_fault_abort "kubectl could not list backend pods after the injector rollout" "$out"
  fi
  pod=$(printf '%s' "$out" | jq -r '
      [.items[]
       | select(.metadata.deletionTimestamp == null and .status.phase == "Running")
       | select([.spec.containers[].name] | (index("fault-net") != null and index("fault-fs") != null))
       | select((.status.containerStatuses // []) | length > 0)
       | select(all(.status.containerStatuses[]; .ready == true))]
      | first | .metadata.name // empty' 2>/dev/null || true)
  if [ -z "$pod" ]; then
    _k8s_fault_abort "rollout finished but no ready backend pod carries the fault injector" "$(_k8s_namespace_listing)"
  fi
  if ! _k8s_fault_wait_health; then
    _k8s_fault_abort "backend pod ${pod} (with the fault injector) did not answer ${BASE_URL}/health with 200 within ${K8S_FAULT_HEALTH_TIMEOUT}s"
  fi
  rc=0
  out=$(k8s_fault_fs "$pod" true 2>&1) || rc=$?
  if [ "$rc" -ne 0 ]; then
    _k8s_fault_abort "fault-fs in ${pod} cannot enter the backend's mount namespace (rc=${rc})" "$out"
  fi
  echo "  Backend pod with fault injector: ${pod}"
  printf -v "$__var" '%s' "$pod"
}

# k8s_fault_net POD CMD...: run CMD in fault-net (the pod's network namespace).
k8s_fault_net() {
  local pod="$1"; shift
  kubectl exec -n "${NAMESPACE}" "$pod" -c fault-net -- "$@"
}

# Shell run by fault-fs: find a backend process (any process with the storage
# path in its mountinfo; every process in the backend container shares that
# mount namespace) and run busybox APPLET ARGS... inside its mount namespace.
# It does not end on the nsenter (busybox sh would exec it in place), so
# /proc/$$ stays a process in fault-fs's own mount namespace and its root
# still holds the static busybox.
# shellcheck disable=SC2016  # expands in fault-fs, not here
_K8S_FAULT_FS_SH='
mnt="$1"; shift
pid=""
for d in /proc/[0-9]*; do
  [ "$d" = "/proc/$$" ] && continue
  if awk -v m="$mnt" '"'"'$5 == m { f = 1 } END { exit !f }'"'"' "$d/mountinfo" 2>/dev/null; then
    pid="${d#/proc/}"; break
  fi
done
if [ -z "$pid" ]; then
  echo "ak-fault: no process has $mnt mounted; the backend is not in this pod'"'"'s PID namespace" >&2
  exit '"${K8S_FAULT_NO_BACKEND_RC}"'
fi
nsenter -t "$pid" -m /proc/$$/root/bin/busybox "$@"
rc=$?
exit $rc
'

# k8s_fault_fs POD APPLET ARGS...: run a busybox applet in the BACKEND
# container's mount namespace (paths are the backend's paths).
k8s_fault_fs() {
  local pod="$1"; shift
  kubectl exec -n "${NAMESPACE}" "$pod" -c fault-fs -- sh -c "$_K8S_FAULT_FS_SH" _ "$AK_STORAGE_MOUNT" "$@"
}

# k8s_fault_storage_mountline POD: the backend's TOP mountinfo line for the
# storage path (the last one, when mounts are stacked).
k8s_fault_storage_mountline() {
  # shellcheck disable=SC2016  # awk program, expands in awk
  k8s_fault_fs "$1" awk -v m="$AK_STORAGE_MOUNT" '$5 == m { l = $0 } END { if (l == "") exit 1; print l }' /proc/self/mountinfo
}

# k8s_fault_storage_write_probe POD: try to create and remove a 4 KiB file
# on the storage path as the kernel sees it from the backend. Prints dd's
# error on failure; returns dd's status.
k8s_fault_storage_write_probe() {
  # Applets only: the backend's filesystem has no binaries, so a busybox sh
  # run there could not find dd or rm on PATH.
  local probe="${AK_STORAGE_MOUNT}/.ak-fault-probe" out rc=0
  out=$(k8s_fault_fs "$1" dd if=/dev/zero of="$probe" bs=4096 count=1 2>&1) || rc=$?
  k8s_fault_fs "$1" rm -f "$probe" >/dev/null 2>&1 || true
  [ "$rc" -eq 0 ] || printf '%s\n' "$out" | grep -v 'records in\|records out\|bytes' || true
  return "$rc"
}

# Mount options of the storage mount (field 6 of mountinfo), e.g.
# rw,nosuid,nodev,relatime.
_k8s_fault_storage_opts() {
  k8s_fault_storage_mountline "$1" | awk '{ print $6 }'
}

# Field helpers for a mountinfo line:
#   id parent maj:min ROOT MOUNTPOINT MOUNT-OPTS [optional...] - FSTYPE SOURCE SUPER-OPTS
# ROOT is the directory of the filesystem this mount shows (a subdirectory
# for a bind or a subPath). MOUNT-OPTS are per-mount flags; SUPER-OPTS belong
# to the filesystem itself, shared by every mount of it, the node's included.
_k8s_mi_root()  { awk '{ print $4 }'; }
_k8s_mi_opts()  { awk '{ print $6 }'; }
_k8s_mi_super() { awk '{ for (i = 7; i <= NF; i++) if ($i == "-") { print $(i + 3); exit } }'; }
# First flag of a comma list: rw or ro.
_k8s_first_flag() { cut -d, -f1; }

# _k8s_fault_remount_bind POD OPTSTR: the only way this library remounts the
# storage path. OPTSTR must start with "remount,bind,": a remount without
# `bind` changes the filesystem's own flags, and on local-path that
# filesystem is the node's root. Anything else is refused (return 4) before
# mount runs.
_k8s_fault_remount_bind() {
  local pod="$1" optstr="$2"
  case "$optstr" in
    remount,bind,*) ;;
    *) echo "ak-fault: refusing mount -o '${optstr}': a storage remount must start with 'remount,bind,'"
       return 4 ;;
  esac
  k8s_fault_fs "$pod" mount -o "$optstr" "$K8S_FAULT_REMOUNT_SOURCE" "$AK_STORAGE_MOUNT"
}

# k8s_fault_storage_readonly POD: make the storage path read-only for the
# backend, in its own mount namespace, and for nothing else.
#
# On local-path the storage path is a bind of a directory on the NODE's root
# filesystem, and fault-fs is privileged. A remount that touched the
# superblock instead of the bind would make the node's root filesystem
# read-only, and an EROFS write probe cannot tell the two cases apart. So:
#   * refuse (return 2) unless the mount is a bind of a subdirectory
#     (mountinfo ROOT != "/") of a filesystem that is read-write;
#   * remount with `bind` (per-mount flag only), keeping the other flags;
#   * re-read mountinfo: if the SUPERBLOCK is no longer rw, put it back at
#     once and return 3 (ak-fault: lines say what happened).
# Sets K8S_FAULT_STORAGE_OPTS to the flags to restore. Returns 0 when the
# mount, and only the mount, is read-only.
k8s_fault_storage_readonly() {
  local pod="$1" line root opts super ro after
  # shellcheck disable=SC2034  # read by the caller and k8s_fault_storage_restore
  K8S_FAULT_STORAGE_OPTS=""
  line=$(k8s_fault_storage_mountline "$pod") || { echo "ak-fault: no mountinfo line for ${AK_STORAGE_MOUNT}"; return 1; }
  root=$(printf '%s\n' "$line" | _k8s_mi_root)
  opts=$(printf '%s\n' "$line" | _k8s_mi_opts)
  super=$(printf '%s\n' "$line" | _k8s_mi_super)
  if [ "$root" = "/" ] || [ -z "$root" ]; then
    echo "ak-fault: refusing to remount ${AK_STORAGE_MOUNT}: it is not a bind of a subdirectory (mountinfo root '${root}'), so a remount could act on a whole filesystem"
    echo "ak-fault: mountinfo: ${line}"
    return 2
  fi
  if [ "$(printf '%s' "$super" | _k8s_first_flag)" != "rw" ] || [ "$(printf '%s' "$opts" | _k8s_first_flag)" != "rw" ]; then
    echo "ak-fault: refusing to remount ${AK_STORAGE_MOUNT}: it is not read-write to begin with (mount '${opts}', superblock '${super}')"
    echo "ak-fault: mountinfo: ${line}"
    return 2
  fi
  K8S_FAULT_STORAGE_OPTS="$opts"
  ro=$(printf '%s' "$opts" | sed -e 's/^rw,/ro,/' -e 's/^rw$/ro/')
  _k8s_fault_remount_bind "$pod" "remount,bind,${ro}" || return 1
  after=$(k8s_fault_storage_mountline "$pod") || { echo "ak-fault: mountinfo unreadable after the remount"; return 1; }
  echo "ak-fault: superblock after remount: $(printf '%s\n' "$after" | _k8s_mi_super)"
  if [ "$(printf '%s\n' "$after" | _k8s_mi_super | _k8s_first_flag)" != "rw" ]; then
    echo "ak-fault: the remount reached the SUPERBLOCK (now '$(printf '%s\n' "$after" | _k8s_mi_super)'), not just the bind; restoring it now"
    k8s_fault_fs "$pod" mount -o remount,rw "$K8S_FAULT_REMOUNT_SOURCE" "$AK_STORAGE_MOUNT" 2>&1 | sed 's/^/ak-fault: /'
    k8s_fault_storage_restore "$pod" 2>&1 | sed 's/^/ak-fault: /'
    echo "ak-fault: superblock now: $(k8s_fault_storage_mountline "$pod" 2>/dev/null | _k8s_mi_super)"
    return 3
  fi
  if [ "$(printf '%s\n' "$after" | _k8s_mi_opts | _k8s_first_flag)" != "ro" ]; then
    echo "ak-fault: the remount returned 0 but the mount is still '$(printf '%s\n' "$after" | _k8s_mi_opts)'"
    return 1
  fi
}

# k8s_fault_storage_restore POD: remount the storage path read-write with
# the flags recorded by k8s_fault_storage_readonly.
k8s_fault_storage_restore() {
  local pod="$1" rw="${K8S_FAULT_STORAGE_OPTS:-rw}"
  rw=$(printf '%s' "$rw" | sed -e 's/^ro,/rw,/' -e 's/^ro$/rw/')
  _k8s_fault_remount_bind "$pod" "remount,bind,${rw}"
}

# k8s_fault_storage_fill POD SIZE: mount a SIZE (e.g. 16m) tmpfs over the
# storage path in the backend's mount namespace, then fill it. The fill
# stops on ENOSPC by design, so its status is not checked here: callers
# verify the result with df and k8s_fault_storage_write_probe.
k8s_fault_storage_fill() {
  local pod="$1" size="$2"
  k8s_fault_fs "$pod" mount -t tmpfs -o "size=${size},mode=1777" "$K8S_FAULT_FULL_SOURCE" "$AK_STORAGE_MOUNT" || return 1
  k8s_fault_fs "$pod" dd if=/dev/zero of="${AK_STORAGE_MOUNT}/.ak-fault-ballast" bs=65536 >/dev/null 2>&1 || true
}

# k8s_fault_storage_unfill POD: unmount the disk-full tmpfs if it is the top
# mount on the storage path. A no-op otherwise, so it is safe in an exit
# handler.
k8s_fault_storage_unfill() {
  local pod="$1" line
  line=$(k8s_fault_storage_mountline "$pod" 2>/dev/null) || return 0
  case "$line" in
    *" - tmpfs ${K8S_FAULT_FULL_SOURCE} "*) k8s_fault_fs "$pod" umount "$AK_STORAGE_MOUNT" ;;
    *) return 0 ;;
  esac
}

# k8s_fault_storage_avail_kb POD: free KiB on the storage path, as the backend
# sees it. statfs via `stat -f`, not df: busybox df finds the filesystem
# through /proc/mounts and printed nothing usable on the gate's backend pod
# (see K8S_FAULT_REMOUNT_SOURCE).
k8s_fault_storage_avail_kb() {
  k8s_fault_fs "$1" stat -f -c '%a %S' "$AK_STORAGE_MOUNT" | awk 'NF == 2 { printf "%d\n", $1 * $2 / 1024 }'
}

# k8s_fault_net_iface POD: the pod's default-route interface (eth0 on flannel).
k8s_fault_net_iface() {
  k8s_fault_net "$1" sh -c "ip route show default | awk '{ for (i = 1; i < NF; i++) if (\$i == \"dev\") { print \$(i + 1); exit } }'"
}

# k8s_fault_net_gateway POD: the pod's default gateway. It answers ICMP on
# every CNI, and the path to it crosses the pod's egress, so pings to it
# measure an egress fault.
k8s_fault_net_gateway() {
  k8s_fault_net "$1" sh -c "ip route show default | awk '{ print \$3; exit }'"
}

# k8s_fault_ping POD TARGET COUNT [INTERVAL]
# Ping TARGET from the pod's network namespace. Sets K8S_PING_LOSS (percent,
# integer part) and K8S_PING_AVG_MS (integer), and prints ping's summary.
# Returns 1 if the output could not be parsed.
k8s_fault_ping() {
  local pod="$1" target="$2" count="$3" interval="${4:-0.2}" out
  K8S_PING_LOSS=""
  K8S_PING_AVG_MS=""
  out=$(k8s_fault_net "$pod" ping -q -n -c "$count" -i "$interval" -W 2 "$target" 2>&1) || true
  printf '%s\n' "$out" | tail -2 | sed 's/^/    ping: /'
  K8S_PING_LOSS=$(printf '%s\n' "$out" | sed -n 's/.* \([0-9][0-9.]*\)% packet loss.*/\1/p' | head -1)
  K8S_PING_LOSS="${K8S_PING_LOSS%%.*}"
  # iputils: "rtt min/avg/max/mdev = a/b/c/d ms"; busybox: "round-trip min/avg/max = a/b/c ms".
  K8S_PING_AVG_MS=$(printf '%s\n' "$out" | awk -F'= ' '/min\/avg\/max/ { split($2, v, "/"); printf "%d", v[2] }')
  [ -n "$K8S_PING_LOSS" ]
}

# k8s_fault_http_ms URL: wall time of one GET to URL from the runner, in ms.
k8s_fault_http_ms() {
  local t
  t=$(curl -s -o /dev/null --max-time 30 -w '%{time_total}' "$1" 2>/dev/null || echo "")
  [ -n "$t" ] || { echo ""; return 1; }
  awk -v t="$t" 'BEGIN { printf "%d", t * 1000 }'
}

# k8s_fault_http_median_ms URL N: median of N timings.
k8s_fault_http_median_ms() {
  local url="$1" n="$2" i vals=""
  for i in $(seq 1 "$n"); do
    vals="${vals}$(k8s_fault_http_ms "$url")
"
  done
  printf '%s' "$vals" | grep -E '^[0-9]+$' | sort -n | awk '{ a[NR] = $1 } END { if (NR == 0) exit 1; print a[int((NR + 1) / 2)] }'
}

# k8s_fault_net_loss_add POD IFACE PERCENT: drop PERCENT% of the packets the
# pod RECEIVES on IFACE. Ingress, not egress: iptables DROP on OUTPUT hands
# EPERM back to the sending socket, which a real lossy wire never does.
# Dropping on input loses data and ACKs in both TCP directions, the way
# netem loss would, and it needs no sch_netem on the node.
k8s_fault_net_loss_add() {
  local pod="$1" ifc="$2" pct="$3" prob
  prob=$(awk -v p="$pct" 'BEGIN { printf "%.4f", p / 100 }')
  k8s_fault_net "$pod" iptables -w -I INPUT 1 -i "$ifc" -m statistic --mode random --probability "$prob" \
    -m comment --comment ak-fault-loss -j DROP
}

# k8s_fault_net_loss_del POD: remove every ak-fault-loss rule. Safe when none.
k8s_fault_net_loss_del() {
  # shellcheck disable=SC2016  # expands in fault-net
  k8s_fault_net "$1" sh -c '/sbin/iptables -w -S INPUT | grep -- "--comment ak-fault-loss" | sed "s/^-A /-D /" | while read -r r; do eval "/sbin/iptables -w $r"; done'
}

# k8s_fault_net_block_port_add POD PORT: drop every TCP packet the pod SENDS
# to PORT (a partition from that service), established connections
# included.
k8s_fault_net_block_port_add() {
  k8s_fault_net "$1" iptables -w -I OUTPUT 1 -p tcp --dport "$2" -m comment --comment ak-fault-partition -j DROP
}

# k8s_fault_net_block_port_del POD: remove every ak-fault-partition rule.
k8s_fault_net_block_port_del() {
  # shellcheck disable=SC2016  # expands in fault-net
  k8s_fault_net "$1" sh -c '/sbin/iptables -w -S OUTPUT | grep -- "--comment ak-fault-partition" | sed "s/^-A /-D /" | while read -r r; do eval "/sbin/iptables -w $r"; done'
}

# k8s_fault_net_rule_packets POD CHAIN COMMENT: packets matched so far by
# the rule tagged COMMENT (0 when absent).
k8s_fault_net_rule_packets() {
  k8s_fault_net "$1" iptables -w -L "$2" -v -n -x | awk -v c="/* $3 */" 'index($0, c) { n += $1 } END { print n + 0 }'
}

# k8s_fault_net_tcp_probe POD HOST PORT: 0 when a TCP connect to HOST:PORT
# from the pod's network namespace succeeds within 3 s.
k8s_fault_net_tcp_probe() {
  k8s_fault_net "$1" timeout 5 nc -z -w 3 "$2" "$3" >/dev/null 2>&1
}

# k8s_fault_net_latency_add POD IFACE MS: delay every packet the pod sends
# on IFACE by MS. Needs the node kernel's sch_netem module. On failure,
# prints tc's error with the likely cause and returns 1.
k8s_fault_net_latency_add() {
  local pod="$1" ifc="$2" ms="$3" out
  if out=$(k8s_fault_net "$pod" tc qdisc add dev "$ifc" root netem delay "${ms}ms" 2>&1); then
    return 0
  fi
  printf '%s\n' "$out"
  case "$out" in
    *"qdisc kind is unknown"*|*"No such file or directory"*|*"not found"*)
      echo "  The node kernel has no sch_netem module. On an EL8 node it ships in kernel-modules-extra (artifact-keeper-test#842)." ;;
  esac
  return 1
}

# k8s_fault_net_latency_del POD IFACE: remove a netem root qdisc if present.
k8s_fault_net_latency_del() {
  local pod="$1" ifc="$2"
  if k8s_fault_net "$pod" tc qdisc show dev "$ifc" 2>/dev/null | grep -q netem; then
    k8s_fault_net "$pod" tc qdisc del dev "$ifc" root
  fi
}

# ---------------------------------------------------------------------------
# Cleanup that checks itself (exit handlers)
#
# Each fault suite registers one of these with add_exit_handler BEFORE it
# injects. They remove the fault if it is still there, then look again. A
# fault that survives is reported as `::error::ak-fault: ...` (a GitHub
# annotation, so the leg shows it), because the next suite would otherwise be
# graded on a faulted pod. The gate also removes the whole injector after
# the network and storage legs (scripts/resilience-fault-injector-detach.sh).
# ---------------------------------------------------------------------------

_k8s_fault_cleanup_error() { echo "::error::ak-fault: $*"; }

k8s_fault_cleanup_latency() { # POD IFACE
  k8s_fault_net_latency_del "$1" "$2" >/dev/null 2>&1 || true
  if k8s_fault_net "$1" tc qdisc show dev "$2" 2>/dev/null | grep -q netem; then
    _k8s_fault_cleanup_error "netem is still on ${2} of pod ${1} after cleanup"
    return 1
  fi
}

k8s_fault_cleanup_loss() { # POD
  k8s_fault_net_loss_del "$1" >/dev/null 2>&1 || true
  if k8s_fault_net "$1" iptables -w -S INPUT 2>/dev/null | grep -q 'ak-fault-loss'; then
    _k8s_fault_cleanup_error "the packet-loss rule is still in pod ${1} after cleanup"
    return 1
  fi
}

k8s_fault_cleanup_partition() { # POD
  k8s_fault_net_block_port_del "$1" >/dev/null 2>&1 || true
  if k8s_fault_net "$1" iptables -w -S OUTPUT 2>/dev/null | grep -q 'ak-fault-partition'; then
    _k8s_fault_cleanup_error "the partition rule is still in pod ${1} after cleanup"
    return 1
  fi
}

k8s_fault_cleanup_readonly() { # POD
  local line
  line=$(k8s_fault_storage_mountline "$1" 2>/dev/null) || { _k8s_fault_cleanup_error "cannot read ${AK_STORAGE_MOUNT} in pod ${1} to check it is writable"; return 1; }
  if [ "$(printf '%s\n' "$line" | _k8s_mi_opts | _k8s_first_flag)" = "ro" ]; then
    k8s_fault_storage_restore "$1" >/dev/null 2>&1 || true
    line=$(k8s_fault_storage_mountline "$1" 2>/dev/null) || true
  fi
  if [ "$(printf '%s\n' "$line" | _k8s_mi_opts | _k8s_first_flag)" != "rw" ] || \
     [ "$(printf '%s\n' "$line" | _k8s_mi_super | _k8s_first_flag)" != "rw" ]; then
    _k8s_fault_cleanup_error "${AK_STORAGE_MOUNT} in pod ${1} is not read-write after cleanup: ${line}"
    return 1
  fi
}

k8s_fault_cleanup_full() { # POD
  local line
  k8s_fault_storage_unfill "$1" >/dev/null 2>&1 || true
  line=$(k8s_fault_storage_mountline "$1" 2>/dev/null) || { _k8s_fault_cleanup_error "cannot read ${AK_STORAGE_MOUNT} in pod ${1} to check the disk-full tmpfs is gone"; return 1; }
  case "$line" in
    *" - tmpfs ${K8S_FAULT_FULL_SOURCE} "*)
      _k8s_fault_cleanup_error "the disk-full tmpfs is still mounted over ${AK_STORAGE_MOUNT} in pod ${1}"
      return 1 ;;
  esac
}

# ---------------------------------------------------------------------------
# Removing the injector
# ---------------------------------------------------------------------------

# k8s_fault_injector_detach: take the injector off the backend Deployment
# (both containers, shareProcessNamespace, the annotations) and wait for a
# fresh, ready pod without it. A pod built without the injector carries no
# fault: rules, qdiscs and mounts all lived in the old pod. A no-op when the
# Deployment is not patched. Prints `ak-fault:` progress lines; returns 1
# (with a reason) when the backend cannot be brought back unpatched.
k8s_fault_injector_detach() {
  local out deploy ops pods
  if ! out=$(kubectl get deployments -n "${NAMESPACE}" -l "$AK_BACKEND_SELECTOR" -o json 2>&1); then
    echo "ak-fault: kubectl could not list backend Deployments: ${out}"; return 1
  fi
  if [ "$(printf '%s' "$out" | jq '.items | length')" != "1" ]; then
    echo "ak-fault: expected exactly one backend Deployment"; return 1
  fi
  deploy=$(printf '%s' "$out" | jq -r '.items[0].metadata.name')
  # JSON-patch ops, container removals from the highest index down so the
  # indices stay valid.
  ops=$(printf '%s' "$out" | jq -c '.items[0].spec.template as $t
    | ([$t.spec.containers | to_entries[] | select(.value.name == "fault-net" or .value.name == "fault-fs") | .key]
       | sort | reverse | map({op: "remove", path: "/spec/template/spec/containers/\(.)"}))
    + (if $t.spec.shareProcessNamespace == true then [{op: "remove", path: "/spec/template/spec/shareProcessNamespace"}] else [] end)
    + ([($t.metadata.annotations // {}) | keys[] | select(. == "artifact-keeper-test/fault-injector" or . == "kubectl.kubernetes.io/default-container")]
       | map({op: "remove", path: "/spec/template/metadata/annotations/\(gsub("~"; "~0") | gsub("/"; "~1"))"}))')
  if [ "$ops" = "[]" ]; then
    echo "ak-fault: deployment/${deploy} carries no fault injector"
  else
    echo "ak-fault: removing the fault injector from deployment/${deploy}"
    if ! out=$(kubectl patch deployment "$deploy" -n "${NAMESPACE}" --type json -p "$ops" 2>&1); then
      echo "ak-fault: kubectl could not patch deployment/${deploy}: ${out}"; return 1
    fi
  fi
  if ! out=$(kubectl rollout status "deployment/${deploy}" -n "${NAMESPACE}" --timeout="${K8S_FAULT_ROLLOUT_TIMEOUT}s" 2>&1); then
    echo "ak-fault: deployment/${deploy} did not roll out without the injector: ${out}"; return 1
  fi
  if ! pods=$(_k8s_pods_json "$AK_BACKEND_SELECTOR"); then
    echo "ak-fault: kubectl could not list backend pods: ${pods}"; return 1
  fi
  if printf '%s' "$pods" | jq -e '[.items[] | select(.metadata.deletionTimestamp == null)
        | select([.spec.containers[].name] | (index("fault-net") != null or index("fault-fs") != null))] | length > 0' >/dev/null; then
    echo "ak-fault: a backend pod still carries the fault injector after the rollout"; return 1
  fi
  # Wait for the Service only when a new pod was rolled. On the no-op path
  # the pod is whatever the previous suites left, and a degraded backend
  # answering 503 (after stress, say) is the next suite's verdict to give,
  # not an INFRA here. After a real rollout, any HTTP answer from /health
  # (200, or 503 for an unhealthy optional service) shows the new pod serves.
  if [ "$ops" != "[]" ] && ! _k8s_fault_wait_answer; then
    echo "ak-fault: the backend did not answer ${BASE_URL}/health (200 or 503) within ${K8S_FAULT_HEALTH_TIMEOUT}s after the injector was removed"; return 1
  fi
  echo "ak-fault: backend pod(s) without the injector: $(printf '%s' "$pods" | jq -r '[.items[] | select(.metadata.deletionTimestamp == null) | .metadata.name] | join(" ")')"
}
