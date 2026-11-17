#!/usr/bin/env bash
# The case scripts are single-quoted on purpose: they expand in the inner shell.
# shellcheck disable=SC2016
#
# Self-test for the fault-injection helpers in tests/lib/k8s.sh
# (artifact-keeper-test#842).
#
# The network and storage resilience suites used to skip because the backend
# image has no tc, iptables or sh, and before that a failed injection passed
# as an applied one. This pins the replacement contract with a stub kubectl,
# so no cluster is needed:
#
#   attach  no backend Deployment              -> exit 11 (INFRA)
#   attach  kubectl cannot list Deployments    -> exit 11 (INFRA)
#   attach  patch Forbidden                    -> exit 11 (INFRA), names the patch
#   attach  rollout times out                  -> exit 11 (INFRA)
#   attach  rollout ok, no pod has the injector-> exit 11 (INFRA)
#   attach  fault-fs cannot enter the backend  -> exit 11 (INFRA)
#   attach  fresh Deployment                   -> patches: shareProcessNamespace,
#                                                 both images pinned by digest,
#                                                 default-container=backend
#   attach  already patched                    -> no second patch (no extra rollout)
#   latency node without sch_netem             -> returns 1 and names the module
#   readonly remount keeps the mount's flags and passes a source (no
#            /proc/mounts lookup, which failed on the gate's backend pod)
#   readonly a remount that reached the superblock is restored, rc 3;
#            a mount that is not a bind of a subdirectory, or not rw, is refused
#   cleanup  a fault that survives its exit handler is ::error::ak-fault
#   detach   removes the injector (highest container index first), no-op when
#            absent, fails when a pod still carries it; the script exits 11
#   remount  every storage remount starts with "remount,bind," or is refused
#   tree     each fault suite registers its cleanup before it injects
#   detach   runs from a copy outside the repo (K8S_LIB_DIR, k8s.sh only):
#            no-op success on an unpatched backend, INFRA without its library;
#            the gate installs that copy before switch-tests-ref.sh
#   tree    no resilience script execs into the backend container, and the
#           five fault suites have no skip() path left
#
# Run from repo root: bash tests/lib/selftest-k8s-fault-injector.sh
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin" "$TMP/junit"

# Stub kubectl. Every call is appended to $K8S_STUB_LOG. Behaviour is chosen
# by env: K8S_STUB_DEPLOY (deployments JSON file), K8S_STUB_PODS (pods JSON
# file), K8S_STUB_DEPLOY_FAIL, K8S_STUB_PATCH_FAIL, K8S_STUB_ROLLOUT_FAIL,
# K8S_STUB_FS_RC, K8S_STUB_TC_UNKNOWN.
cat > "$TMP/bin/kubectl" <<'STUB'
#!/usr/bin/env bash
echo "kubectl $*" >> "$K8S_STUB_LOG"
container=""
args=("$@")
for ((i = 0; i < ${#args[@]}; i++)); do
  [ "${args[$i]}" = "--" ] && break
  [ "${args[$i]}" = "-c" ] && container="${args[$((i + 1))]}"
done
case "$1 $2" in
  "get deployments")
    if [ "${K8S_STUB_DEPLOY_FAIL:-0}" = 1 ]; then
      echo 'Error from server (Forbidden): deployments.apps is forbidden' >&2; exit 1
    fi
    case " $* " in *" -o json "*) cat "$K8S_STUB_DEPLOY" ;; *) echo "stub-deployments" ;; esac ;;
  "patch deployment")
    if [ "${K8S_STUB_PATCH_FAIL:-0}" = 1 ]; then
      echo 'Error from server (Forbidden): deployments.apps "artifact-keeper-backend" is forbidden: cannot patch' >&2; exit 1
    fi
    for ((i = 0; i < ${#args[@]}; i++)); do
      [ "${args[$i]}" = "-p" ] && printf '%s' "${args[$((i + 1))]}" > "$K8S_STUB_PATCH_OUT"
    done
    echo "deployment.apps/artifact-keeper-backend patched" ;;
  "rollout status")
    if [ "${K8S_STUB_ROLLOUT_FAIL:-0}" = 1 ]; then
      echo 'error: timed out waiting for the condition' >&2; exit 1
    fi
    echo 'deployment "artifact-keeper-backend" successfully rolled out' ;;
  "get pods")
    case " $* " in *" -o json "*) cat "$K8S_STUB_PODS" ;; *) echo "stub-pods $*" ;; esac ;;
  "exec "*)
    if [ "$container" = "fault-fs" ] && [ -n "${K8S_STUB_FS_RC:-}" ]; then
      echo "ak-fault: no process has /data/storage mounted" >&2; exit "$K8S_STUB_FS_RC"
    fi
    if [ "$container" = "fault-fs" ] && [[ " $* " == *" remount,bind,ro"* ]]; then
      touch "$K8S_STUB_STATE/remounted-ro"
    fi
    if [ "$container" = "fault-fs" ] && [[ " $* " == *" remount,bind,rw"* ]]; then
      rm -f "$K8S_STUB_STATE/remounted-ro"
    fi
    if [ "$container" = "fault-fs" ] && [[ " $* " == *" /proc/self/mountinfo "* ]]; then
      if [ -e "$K8S_STUB_STATE/remounted-ro" ]; then
        echo "${K8S_STUB_MI_AFTER:-47002 46915 253:4 /pvc/storage /data/storage ro,nosuid,relatime - xfs /dev/sda rw,attr2}"
      else
        echo "${K8S_STUB_MI_BEFORE:-47002 46915 253:4 /pvc/storage /data/storage rw,nosuid,relatime - xfs /dev/sda rw,attr2}"
      fi
      exit 0
    fi
    if [ "$container" = "fault-net" ] && [[ " $* " == *" qdisc show "* ]]; then
      [ "${K8S_STUB_NETEM_STUCK:-0}" = 1 ] && echo "qdisc netem 8001: root refcnt 2 limit 1000 delay 500ms"
      exit 0
    fi
    if [ "$container" = "fault-net" ] && [ "${K8S_STUB_TC_UNKNOWN:-0}" = 1 ] && [[ " $* " == *" netem "* ]]; then
      echo 'Error: Specified qdisc kind is unknown.' >&2; exit 2
    fi
    exit 0 ;;
  *) echo "stub-kubectl $*" ;;
esac
STUB
chmod +x "$TMP/bin/kubectl"

deploy_json() { # file attached(true|false)
  local f="$TMP/$1" c='[{"name":"backend"}]' spn=false
  if [ "$2" = true ]; then c='[{"name":"backend"},{"name":"fault-net"},{"name":"fault-fs"}]'; spn=true; fi
  printf '{"items":[{"metadata":{"name":"artifact-keeper-backend"},"spec":{"template":{"spec":{"shareProcessNamespace":%s,"containers":%s}}}}]}' "$spn" "$c" > "$f"
  echo "$f"
}
pods_json() { # file name with-injector(true|false)
  local f="$TMP/$1" c='[{"name":"backend"}]' cs='[{"name":"backend","ready":true}]'
  if [ "$3" = true ]; then
    c='[{"name":"backend"},{"name":"fault-net"},{"name":"fault-fs"}]'
    cs='[{"name":"backend","ready":true},{"name":"fault-fs","ready":true},{"name":"fault-net","ready":true}]'
  fi
  printf '{"items":[{"metadata":{"name":"%s","uid":"u-%s","deletionTimestamp":null},"spec":{"containers":%s},"status":{"phase":"Running","containerStatuses":%s}}]}' \
    "$2" "$2" "$c" "$cs" > "$f"
  echo "$f"
}

NO_DEPLOY="$TMP/none.json"; echo '{"items":[]}' > "$NO_DEPLOY"
FRESH=$(deploy_json fresh.json false)
ATTACHED=$(deploy_json attached.json true)
PODS_INJ=$(pods_json pods-inj.json be-new true)
PODS_PLAIN=$(pods_json pods-plain.json be-old false)

inner() {
  cat <<INNER
source "${REPO_ROOT}/tests/lib/common.sh"
source "${REPO_ROOT}/tests/lib/k8s.sh"
JUNIT_OUTPUT_DIR="${TMP}/junit"
NAMESPACE=test-ns
BASE_URL=http://127.0.0.1:9
K8S_POLL_INTERVAL=1
_k8s_fault_wait_health() { return 0; }
_k8s_fault_wait_answer() { return 0; }
begin_suite "k8s-fault-selftest"
begin_test "stub"
$1
end_suite
INNER
}

fails=0
run_case() { # label want_exit want_grep deploy pods script
  local label="$1" want="$2" grep_for="$3" deploy="$4" pods="$5" script="$6" out actual
  : > "$TMP/log"; rm -f "$TMP/patch.json" "$TMP/state/"*; mkdir -p "$TMP/state"
  out=$(PATH="$TMP/bin:$PATH" K8S_STUB_LOG="$TMP/log" K8S_STUB_PATCH_OUT="$TMP/patch.json" K8S_STUB_STATE="$TMP/state" \
        K8S_STUB_DEPLOY="$deploy" K8S_STUB_PODS="$pods" \
        bash -c "$(inner "$script")" 2>&1)
  actual=$?
  if [ "$actual" != "$want" ]; then
    echo "  FAIL: ${label}: expected exit=${want} got exit=${actual}"
    echo "$out" | sed 's/^/      /' | tail -15
    fails=$((fails+1)); return 1
  fi
  if [ -n "$grep_for" ] && ! grep -qF -- "$grep_for" <<<"$out"; then
    echo "  FAIL: ${label}: output lacks '${grep_for}'"
    echo "$out" | sed 's/^/      /' | tail -15
    fails=$((fails+1)); return 1
  fi
  echo "  PASS: ${label} (exit=${actual})"
}
check() { # label condition-description command...
  local label="$1"; shift
  if "$@"; then echo "  PASS: ${label}"; else echo "  FAIL: ${label}"; fails=$((fails+1)); fi
}

ATTACH='k8s_fault_injector_attach P; echo "POD=${P}"; pass'

run_case "attach: no backend Deployment is INFRA (exit 11)" 11 "expected exactly one backend Deployment" "$NO_DEPLOY" "$PODS_INJ" "$ATTACH"
K8S_STUB_DEPLOY_FAIL=1 run_case "attach: kubectl cannot list Deployments is INFRA (exit 11)" 11 "could not list backend Deployments" "$FRESH" "$PODS_INJ" "$ATTACH"
K8S_STUB_PATCH_FAIL=1 run_case "attach: patch Forbidden is INFRA (exit 11)" 11 "could not patch deployment/artifact-keeper-backend" "$FRESH" "$PODS_INJ" "$ATTACH"
K8S_STUB_ROLLOUT_FAIL=1 run_case "attach: rollout timeout is INFRA (exit 11)" 11 "did not roll out with the fault injector" "$FRESH" "$PODS_INJ" "$ATTACH"
run_case "attach: rolled out but no pod has the injector is INFRA (exit 11)" 11 "no ready backend pod carries the fault injector" "$FRESH" "$PODS_PLAIN" "$ATTACH"
K8S_STUB_FS_RC=97 run_case "attach: fault-fs cannot enter the backend is INFRA (exit 11)" 11 "cannot enter the backend's mount namespace" "$FRESH" "$PODS_INJ" "$ATTACH"
run_case "attach: injection unreachable after INFRA (never reaches the next line)" 11 "" "$NO_DEPLOY" "$PODS_INJ" \
  'k8s_fault_injector_attach P; echo REACHED; exit 0'

if run_case "attach: fresh Deployment is patched and the injector pod returned" 0 "POD=be-new" "$FRESH" "$PODS_INJ" "$ATTACH"; then
  check "attach: patch sets shareProcessNamespace" \
    test "$(jq -r '.spec.template.spec.shareProcessNamespace' "$TMP/patch.json")" = true
  check "attach: both injector images are pinned by digest" \
    test "$(jq -r '[.spec.template.spec.containers[].image | test("@sha256:[0-9a-f]{64}$")] | all' "$TMP/patch.json")" = true
  check "attach: patch adds fault-net (NET_ADMIN, not privileged) and fault-fs" \
    test "$(jq -r '[.spec.template.spec.containers[]
                    | select(.name == "fault-net")
                    | .securityContext | ((.capabilities.add | index("NET_ADMIN")) != null and (.privileged // false) == false)] == [true]
                   and ([.spec.template.spec.containers[].name] | index("fault-fs")) != null' "$TMP/patch.json")" = true
  check "attach: patch keeps kubectl's default container on the backend" \
    test "$(jq -r '.spec.template.metadata.annotations["kubectl.kubernetes.io/default-container"]' "$TMP/patch.json")" = backend
fi
if run_case "attach: already patched Deployment is reused" 0 "POD=be-new" "$ATTACHED" "$PODS_INJ" "$ATTACH"; then
  check "attach: no second patch (no extra rollout)" bash -c "! grep -q '^kubectl patch' '$TMP/log'"
fi
K8S_STUB_TC_UNKNOWN=1 run_case "latency: a node without sch_netem fails and names the module" 0 "sch_netem" "$ATTACHED" "$PODS_INJ" \
  'if k8s_fault_net_latency_add be-new eth0 500; then echo APPLIED; else echo "NOT APPLIED"; fi; pass'

# Remounts must name a source: given only a target, busybox mount looks the
# mount up in /proc/mounts, which failed on the gate's backend pod.
if run_case "readonly: remount keeps the mount's flags and names a source" 0 "OPTS=rw,nosuid,relatime" "$ATTACHED" "$PODS_INJ" \
    'k8s_fault_storage_readonly be-new && k8s_fault_storage_restore be-new && echo "OPTS=${K8S_FAULT_STORAGE_OPTS}"; pass'; then
  check "readonly: ro remount is 'remount,bind,ro,nosuid,relatime <source> /data/storage'" \
    grep -qF -- "remount,bind,ro,nosuid,relatime ak-fault-remount /data/storage" "$TMP/log"
  check "readonly: restore is 'remount,bind,rw,nosuid,relatime <source> /data/storage'" \
    grep -qF -- "remount,bind,rw,nosuid,relatime ak-fault-remount /data/storage" "$TMP/log"
fi

# The read-only remount must never reach the filesystem under the bind: on
# local-path that is the node's root filesystem (review of #851).
SUPER_RO="47002 46915 253:4 /pvc/storage /data/storage ro,nosuid,relatime - xfs /dev/sda ro,attr2"
if K8S_STUB_MI_AFTER="$SUPER_RO" run_case "readonly: a remount that reached the superblock is restored and refused (rc 3)" 0 "RC=3" "$ATTACHED" "$PODS_INJ" \
    'rc=0; k8s_fault_storage_readonly be-new || rc=$?; echo "RC=${rc}"; pass'; then
  check "readonly: superblock put back with a plain 'remount,rw' (no bind)" \
    grep -qE -- " remount,rw ak-fault-remount /data/storage" "$TMP/log"
fi
WHOLE_FS="47002 46915 253:4 / /data/storage rw,nosuid,relatime - xfs /dev/sda rw,attr2"
if K8S_STUB_MI_BEFORE="$WHOLE_FS" run_case "readonly: refuses a mount that is not a bind of a subdirectory (rc 2)" 0 "not a bind of a subdirectory" "$ATTACHED" "$PODS_INJ" \
    'rc=0; k8s_fault_storage_readonly be-new || rc=$?; echo "RC=${rc}"; pass'; then
  check "readonly: and never remounts it" bash -c "! grep -q 'remount' '$TMP/log'"
fi
RO_FS="47002 46915 253:4 /pvc/storage /data/storage rw,nosuid,relatime - xfs /dev/sda ro,attr2"
K8S_STUB_MI_BEFORE="$RO_FS" run_case "readonly: refuses a filesystem that is not read-write to begin with" 0 "not read-write to begin with" "$ATTACHED" "$PODS_INJ" \
  'rc=0; k8s_fault_storage_readonly be-new || rc=$?; echo "RC=${rc}"; pass'

# Every storage remount goes through _k8s_fault_remount_bind, which refuses
# an option string without the leading "remount,bind,".
run_case "remount guard: refuses an option string without 'remount,bind,'" 0 "RC=4" "$ATTACHED" "$PODS_INJ" \
  'rc=0; _k8s_fault_remount_bind be-new "remount,ro" || rc=$?; echo "RC=${rc}"; pass' \
  && check "remount guard: and never calls mount" bash -c "! grep -q ' mount -o ' '$TMP/log'"
check "remount guard: the library has no other storage remount" \
  test "$(grep -cE 'mount -o "(remount|\$optstr)' "${REPO_ROOT}/tests/lib/k8s.sh")" = 1

# Exit-handler cleanup checks itself and says so as a GitHub annotation.
K8S_STUB_NETEM_STUCK=1 run_case "cleanup: a fault that survives cleanup is a ::error::ak-fault annotation" 0 "::error::ak-fault: netem is still on eth0" "$ATTACHED" "$PODS_INJ" \
  'rc=0; k8s_fault_cleanup_latency be-new eth0 || rc=$?; echo "RC=${rc}"; pass'
run_case "cleanup: a clean pod prints no annotation" 0 "RC=0" "$ATTACHED" "$PODS_INJ" \
  'rc=0; k8s_fault_cleanup_latency be-new eth0 || rc=$?; echo "RC=${rc}"; pass'

# Detach: the backstop the gate runs around the network and storage legs.
if run_case "detach: removes both containers, shareProcessNamespace and the annotations" 0 "RC=0" "$ATTACHED" "$PODS_PLAIN" \
    'rc=0; k8s_fault_injector_detach || rc=$?; echo "RC=${rc}"; pass'; then
  check "detach: container removals run from the highest index down" \
    test "$(jq -c '[.[] | select(.path | startswith("/spec/template/spec/containers/")) | .path]' "$TMP/patch.json")" = \
         '["/spec/template/spec/containers/2","/spec/template/spec/containers/1"]'
  check "detach: shareProcessNamespace removed" \
    test "$(jq 'any(.[]; .path == "/spec/template/spec/shareProcessNamespace")' "$TMP/patch.json")" = true
fi
if run_case "detach: unpatched Deployment is a no-op" 0 "carries no fault injector" "$FRESH" "$PODS_PLAIN" \
    'rc=0; k8s_fault_injector_detach || rc=$?; echo "RC=${rc}"; pass'; then
  check "detach: no patch when there is nothing to remove" bash -c "! grep -q '^kubectl patch' '$TMP/log'"
fi
run_case "detach: a pod that still carries the injector is a failure" 0 "RC=1" "$ATTACHED" "$PODS_INJ" \
  'rc=0; k8s_fault_injector_detach || rc=$?; echo "RC=${rc}"; pass'
out=$(PATH="$TMP/bin:$PATH" K8S_STUB_LOG="$TMP/log" K8S_STUB_PATCH_OUT="$TMP/patch.json" K8S_STUB_STATE="$TMP/state" \
      K8S_STUB_DEPLOY="$ATTACHED" K8S_STUB_PODS="$PODS_INJ" NAMESPACE=test-ns BASE_URL=http://127.0.0.1:9 \
      K8S_FAULT_HEALTH_TIMEOUT=1 bash "${REPO_ROOT}/scripts/resilience-fault-injector-detach.sh" 2>&1)
rc=$?
if [ "$rc" = 11 ] && grep -q '::error title=Fault injector not removed::' <<<"$out"; then
  echo "  PASS: detach script: a backend it cannot clean is exit 11 with an ::error annotation"
else
  echo "  FAIL: detach script: expected exit 11 and an ::error annotation, got exit ${rc}"; echo "$out" | tail -5 | sed 's/^/      /'
  fails=$((fails+1))
fi

# The gate runs the detach script from a copy taken before switch-tests-ref.sh
# moves the tree, because a release/X.Y.x tree may not have it (review of
# #851). From a copy outside the repository, with K8S_LIB_DIR, on a backend
# that never had the injector, it must be a quick no-op success.
mkdir -p "$TMP/copy" "$TMP/nolibs" "$TMP/curlbin"
install -m 0755 "${REPO_ROOT}/scripts/resilience-fault-injector-detach.sh" "$TMP/copy/"
cp "${REPO_ROOT}/tests/lib/k8s.sh" "$TMP/copy/"
install -m 0755 "${REPO_ROOT}/scripts/resilience-fault-injector-detach.sh" "$TMP/nolibs/"
printf '#!/usr/bin/env bash\nexit 0\n' > "$TMP/curlbin/curl"; chmod +x "$TMP/curlbin/curl"
: > "$TMP/log"
out=$(cd "$TMP" && PATH="$TMP/curlbin:$TMP/bin:$PATH" K8S_STUB_LOG="$TMP/log" K8S_STUB_PATCH_OUT="$TMP/patch.json" K8S_STUB_STATE="$TMP/state" \
      K8S_STUB_DEPLOY="$FRESH" K8S_STUB_PODS="$PODS_PLAIN" NAMESPACE=test-ns BASE_URL=http://127.0.0.1:9 \
      K8S_LIB_DIR="$TMP/copy" bash "$TMP/copy/resilience-fault-injector-detach.sh" 2>&1)
rc=$?
if [ "$rc" = 0 ] && grep -q 'carries no fault injector' <<<"$out" && ! grep -q '^kubectl patch' "$TMP/log"; then
  echo "  PASS: detach copy outside the repository (K8S_LIB_DIR, no common.sh): unpatched backend is a no-op success"
else
  echo "  FAIL: detach copy outside the repository: expected a no-op exit 0, got exit ${rc}"; echo "$out" | tail -5 | sed 's/^/      /'
  fails=$((fails+1))
fi
# No-op on a degraded backend: nothing was rolled, so /health is not waited
# on (BASE_URL points at a closed port here) and a 503 cannot make it INFRA.
: > "$TMP/log"
out=$(cd "$TMP" && PATH="$TMP/bin:$PATH" K8S_STUB_LOG="$TMP/log" K8S_STUB_PATCH_OUT="$TMP/patch.json" K8S_STUB_STATE="$TMP/state" \
      K8S_STUB_DEPLOY="$FRESH" K8S_STUB_PODS="$PODS_PLAIN" NAMESPACE=test-ns BASE_URL=http://127.0.0.1:9 \
      K8S_FAULT_HEALTH_TIMEOUT=60 K8S_LIB_DIR="$TMP/copy" timeout 20 bash "$TMP/copy/resilience-fault-injector-detach.sh" 2>&1)
rc=$?
if [ "$rc" = 0 ] && grep -q 'carries no fault injector' <<<"$out"; then
  echo "  PASS: detach no-op does not wait on /health (an unanswering or 503 backend is not INFRA)"
else
  echo "  FAIL: detach no-op waited on /health or failed: exit ${rc}"; echo "$out" | tail -3 | sed 's/^/      /'
  fails=$((fails+1))
fi
out=$(cd "$TMP" && PATH="$TMP/curlbin:$TMP/bin:$PATH" K8S_STUB_LOG="$TMP/log" NAMESPACE=test-ns BASE_URL=http://127.0.0.1:9 \
      K8S_LIB_DIR="$TMP/nolibs" bash "$TMP/nolibs/resilience-fault-injector-detach.sh" 2>&1)
rc=$?
if [ "$rc" = 11 ] && grep -q 'k8s.sh not found in' <<<"$out"; then
  echo "  PASS: detach copy without its library is INFRA (exit 11)"
else
  echo "  FAIL: detach copy without its library: expected exit 11, got ${rc}"; echo "$out" | tail -3 | sed 's/^/      /'
  fails=$((fails+1))
fi
# Wiring: in resilience-tests the copy is installed BEFORE the tree switch,
# and every detach step runs the copy, never the switched tree's path.
WF="${REPO_ROOT}/.github/workflows/release-gate.yml"
job=$(awk '/^  resilience-tests:$/ { on = 1; print; next } on && /^  [a-z][a-z0-9-]*:$/ { exit } on' "$WF")
inst=$(grep -n 'Install the fault-injector detach helper from this checkout' <<<"$job" | head -1 | cut -d: -f1)
sw=$(grep -n 'scripts/switch-tests-ref.sh' <<<"$job" | head -1 | cut -d: -f1)
if [ -n "$inst" ] && [ -n "$sw" ] && [ "$inst" -lt "$sw" ] \
   && [ "$(grep -c 'K8S_LIB_DIR: ${{ runner.temp }}/fault-detach' <<<"$job")" -ge 2 ] \
   && ! grep -qE 'run: +scripts/resilience-fault-injector-detach.sh' <<<"$job"; then
  echo "  PASS: resilience-tests installs the detach helper before the tree switch and runs only the copy"
else
  echo "  FAIL: resilience-tests must install the detach helper before switch-tests-ref.sh and run it from \${{ runner.temp }}/fault-detach"
  fails=$((fails+1))
fi

# Tree-wide: the backend container has no tools, so no resilience script may
# exec into it; faults go through the fault-net / fault-fs helpers. Comment
# lines are excluded.
direct=$(grep -rnE 'kubectl exec[^#]*BACKEND_POD' "${REPO_ROOT}/tests/resilience" \
  | grep -vE '^[^:]+:[0-9]+:[[:space:]]*#' || true)
if [ -n "$direct" ]; then
  echo "  FAIL: tests/resilience execs into the backend container (it has no sh/tc/iptables; use k8s_fault_*):"
  echo "$direct" | sed 's/^/      /'
  fails=$((fails+1))
else
  echo "  PASS: no resilience script execs into the backend container"
fi

for s in network/test-latency-injection.sh network/test-packet-loss.sh network/test-partition-heal.sh \
         storage/test-disk-full.sh storage/test-storage-readonly.sh; do
  f="${REPO_ROOT}/tests/resilience/${s}"
  if ! grep -q 'k8s_fault_injector_attach' "$f"; then
    echo "  FAIL: ${s} does not attach the fault injector"; fails=$((fails+1)); continue
  fi
  if grep -nE '^[[:space:]]*skip[[:space:]]' "$f" >/dev/null; then
    echo "  FAIL: ${s} still has a skip() path; an injection that cannot be set up is INFRA"
    grep -nE '^[[:space:]]*skip[[:space:]]' "$f" | sed 's/^/      /'
    fails=$((fails+1)); continue
  fi
  handler=$(grep -nE "^add_exit_handler 'k8s_fault_cleanup_" "$f" | head -1 | cut -d: -f1)
  inject=$(grep -nE 'k8s_fault_(net_latency_add|net_loss_add|net_block_port_add|storage_fill|storage_readonly) ' "$f" | grep -vE '^[0-9]+:[[:space:]]*#' | head -1 | cut -d: -f1)
  if [ -z "$handler" ] || [ -z "$inject" ] || [ "$handler" -ge "$inject" ]; then
    echo "  FAIL: ${s}: its k8s_fault_cleanup_* exit handler (line ${handler:-none}) must be registered before the first injection (line ${inject:-none})"
    fails=$((fails+1)); continue
  fi
  echo "  PASS: ${s} attaches the injector, cannot skip, and registers its cleanup (line ${handler}) before injecting (line ${inject})"
done

echo ""
if [ "$fails" -eq 0 ]; then
  echo "All fault-injector cases passed."
  exit 0
fi
echo "${fails} case(s) failed."
exit 1
