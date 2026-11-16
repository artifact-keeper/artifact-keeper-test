#!/usr/bin/env bash
# netfault.sh - network fault injection from an EPHEMERAL netadmin container
# (artifact-keeper/artifact-keeper#6120)
#
# Source this file. It cuts and restores traffic between a target pod and a
# list of peer addresses, without changing the target's pod spec and without
# giving the workload container NET_ADMIN. The fault comes from an ephemeral
# debug container added through the pods/ephemeralcontainers subresource,
# which is the API that `kubectl debug --profile=netadmin --target=<c>` uses.
# The client is `kubectl debug --profile=netadmin --custom` (detached).
# Every container in a pod shares the pod's network namespace, so iptables
# rules written by the debug container apply to the workload's traffic too.
# The workload container itself is never touched, and it keeps its
# capabilities: drop ALL.
#
# Shape:
#   netfault_preflight NS                       can the caller do this at all?
#   netfault_partition NS POD CONTAINER NAME ADDR...
#                                               start debug container NAME in
#                                               POD and DROP all traffic to and
#                                               from every ADDR (IPs or CIDRs)
#   netfault_heal NS POD NAME                   flush the rules (the container
#                                               stays, idle, until the pod goes)
#   netfault_probe NS POD NAME HOST PORT        TCP connect from inside the pod's
#                                               netns: 0 reachable, 1 not
#
# The rules live in a dedicated chain, AK_NETFAULT, jumped to from INPUT and
# OUTPUT, so heal is a flush of one chain and never touches anything else
# (kube-proxy runs in the node's netns, not the pod's, so nothing else
# writes iptables rules in a pod netns).
#
# Cluster-IP traffic: a pod's packets to a Service ClusterIP are DNATed in the
# NODE's netns, after they leave the pod. Inside the pod netns, OUTPUT still
# sees the ClusterIP as the destination, so pass BOTH the Service ClusterIP
# and the pod IP of the far side to cut a Service-addressed link completely.
#
# Safety: the debug container's main process is a watchdog that flushes the
# chain after NETFAULT_MAX_SECS (default 600 s), even if the caller dies
# before netfault_heal, so a cancelled job cannot leave a permanent
# partition behind in a pod that outlives the job. The namespace is a
# throwaway anyway.
#
# Requirements on the caller's service account, in the target namespace:
# patch on pods/ephemeralcontainers, get on pods, create on pods/exec.
# netfault_preflight checks them with `kubectl auth can-i` and prints an
# INFRA: line naming the one that is missing.
#
# Image: NETFAULT_IMAGE, default nicolaka/netshoot pinned by digest (iptables,
# nc, ip). Pulled once per node.

NETFAULT_IMAGE="${NETFAULT_IMAGE:-docker.io/nicolaka/netshoot:v0.13@sha256:a20c2531bf35436ed3766cd6cfe89d352b050ccc4d7005ce6400adf97503da1b}"
NETFAULT_MAX_SECS="${NETFAULT_MAX_SECS:-600}"
NETFAULT_START_TIMEOUT="${NETFAULT_START_TIMEOUT:-180}"

# netfault_preflight NS
# Returns 0 when the caller may add ephemeral containers and exec in NS.
netfault_preflight() {
  local ns="$1" missing=""
  if [ "$(kubectl auth can-i patch pods --subresource=ephemeralcontainers -n "$ns" 2>/dev/null)" != "yes" ]; then
    missing="${missing} patch:pods/ephemeralcontainers"
  fi
  if [ "$(kubectl auth can-i create pods --subresource=exec -n "$ns" 2>/dev/null)" != "yes" ]; then
    missing="${missing} create:pods/exec"
  fi
  if [ "$(kubectl auth can-i get pods -n "$ns" 2>/dev/null)" != "yes" ]; then
    missing="${missing} get:pods"
  fi
  if [ -n "$missing" ]; then
    echo "INFRA: this runner's service account lacks${missing} in namespace ${ns};" \
      "ephemeral netadmin fault injection needs it (artifact-keeper-arc-runners e2e/runner-rbac.yaml)" >&2
    return 1
  fi
  return 0
}

# _netfault_wait_running NS POD NAME
_netfault_wait_running() {
  local ns="$1" pod="$2" name="$3" deadline state
  deadline=$(( $(date +%s) + NETFAULT_START_TIMEOUT ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    state=$(kubectl -n "$ns" get pod "$pod" -o json 2>/dev/null | jq -r --arg n "$name" '
      [.status.ephemeralContainerStatuses[]? | select(.name == $n)][0].state
      | if . == null then "absent"
        elif .running then "running"
        elif .terminated then "terminated:" + (.terminated.reason // "")
        elif .waiting then "waiting:" + (.waiting.reason // "")
        else "unknown" end' 2>/dev/null) || state="unknown"
    case "$state" in
      running) return 0 ;;
      terminated:*|waiting:ErrImagePull|waiting:ImagePullBackOff|waiting:CreateContainerConfigError|waiting:CreateContainerError)
        echo "netfault: ephemeral container ${name} in ${pod}: ${state}" >&2
        return 1 ;;
    esac
    sleep 2
  done
  echo "netfault: ephemeral container ${name} in ${pod} not running after ${NETFAULT_START_TIMEOUT}s (last state: ${state})" >&2
  return 1
}

# netfault_partition NS POD CONTAINER NAME ADDR...
netfault_partition() {
  local ns="$1" pod="$2" target="$3" name="$4"
  shift 4
  if [ "$#" -eq 0 ]; then
    echo "netfault_partition: no addresses to cut" >&2
    return 2
  fi
  local addr rules=""
  for addr in "$@"; do
    if ! [[ "$addr" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?$ ]]; then
      echo "netfault_partition: '${addr}' is not an IPv4 address or CIDR" >&2
      return 2
    fi
    rules="${rules} ${addr}"
  done

  # The watchdog: set up the chain, add the DROP rules, then sleep up to
  # NETFAULT_MAX_SECS and flush on the way out (normal exit or SIGTERM).
  local script
  # shellcheck disable=SC2016 # $a, $! expand in the container's shell, by design
  script='set -e
iptables -N AK_NETFAULT 2>/dev/null || iptables -F AK_NETFAULT
iptables -C OUTPUT -j AK_NETFAULT 2>/dev/null || iptables -I OUTPUT 1 -j AK_NETFAULT
iptables -C INPUT -j AK_NETFAULT 2>/dev/null || iptables -I INPUT 1 -j AK_NETFAULT
for a in '"${rules}"'; do
  iptables -A AK_NETFAULT -d "$a" -j DROP
  iptables -A AK_NETFAULT -s "$a" -j DROP
done
echo "netfault: AK_NETFAULT armed for'"${rules}"'"
iptables -S AK_NETFAULT
trap "iptables -F AK_NETFAULT; echo netfault: watchdog flushed; exit 0" TERM INT
sleep '"${NETFAULT_MAX_SECS}"' &
wait $!
iptables -F AK_NETFAULT
echo "netfault: watchdog expired after '"${NETFAULT_MAX_SECS}"'s, chain flushed"
sleep 2147483647'

  # `kubectl debug --profile=netadmin` adds NET_ADMIN and NET_RAW but keeps the
  # pod's runAsNonRoot/runAsUser 1001, under which iptables gets EPERM, so
  # --custom makes this one container root. No -i/-t: the runner may not
  # attach (no pods/attach), and the container needs no terminal. kubectl
  # debug is the client for the subresource: `kubectl patch --subresource`
  # only knows status and scale. --custom needs kubectl 1.30+.
  local custom
  custom=$(mktemp)
  jq -n '{securityContext: {runAsUser: 0, runAsNonRoot: false, allowPrivilegeEscalation: false}}' > "$custom"

  echo "netfault: adding ephemeral container ${name} (${NETFAULT_IMAGE}) to ${ns}/${pod}, target ${target}"
  if ! kubectl -n "$ns" debug "$pod" --container="$name" --image="$NETFAULT_IMAGE" \
      --image-pull-policy=IfNotPresent --target="$target" --profile=netadmin \
      --custom="$custom" -- /bin/sh -c "$script" >/dev/null; then
    rm -f "$custom"
    echo "netfault: kubectl debug (pods/ephemeralcontainers) on ${pod} failed" >&2
    return 1
  fi
  rm -f "$custom"
  _netfault_wait_running "$ns" "$pod" "$name" || return 1

  # The container prints its rules once armed; wait for that line so the
  # caller's clock starts with the fault in place.
  for _ in $(seq 1 30); do
    if kubectl -n "$ns" logs "$pod" -c "$name" 2>/dev/null | grep -q "AK_NETFAULT armed"; then
      kubectl -n "$ns" logs "$pod" -c "$name" 2>/dev/null | sed 's/^/  netfault| /'
      return 0
    fi
    sleep 1
  done
  echo "netfault: ${name} running but never reported its rules armed" >&2
  kubectl -n "$ns" logs "$pod" -c "$name" 2>&1 | tail -20 >&2 || true
  return 1
}

# netfault_heal NS POD NAME
netfault_heal() {
  local ns="$1" pod="$2" name="$3"
  if kubectl -n "$ns" exec "$pod" -c "$name" -- iptables -F AK_NETFAULT; then
    echo "netfault: healed ${ns}/${pod} (AK_NETFAULT flushed)"
    return 0
  fi
  echo "netfault: heal of ${ns}/${pod} via ${name} failed" >&2
  return 1
}

# netfault_probe NS POD NAME HOST PORT
# TCP connect from the pod's netns (through the debug container), 3 s limit.
netfault_probe() {
  local ns="$1" pod="$2" name="$3" host="$4" port="$5"
  kubectl -n "$ns" exec "$pod" -c "$name" -- nc -z -w 3 "$host" "$port" >/dev/null 2>&1
}
