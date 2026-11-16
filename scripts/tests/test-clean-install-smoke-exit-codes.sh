#!/usr/bin/env bash
#
# Self-test for the exit codes of scripts/clean-install-smoke.sh's /readyz
# probe (artifact-keeper-test#835). kubectl and helm are stubbed on PATH in a
# mktemp dir, so no cluster is needed. Cases:
#
#   probe pod Ready,   /readyz 200                  -> exit 0
#   probe pod Ready,   /readyz 503                  -> exit 3   (product)
#   backend has wget,  /readyz 503                  -> exit 3   (product)
#   image pull fails once, then Ready, /readyz 200  -> exit 0   (one retry)
#   image pull fails every time                     -> exit 11  (INFRA, 2 pods)
#   probe pod stuck ContainerCreating               -> exit 11  (INFRA, 1 pod)
#   kubectl run fails                               -> exit 11  (INFRA)
#   --expect-failure + /readyz 503                  -> exit 0   (inverted)
#   --expect-failure + probe pod never starts       -> exit 11  (not inverted)
#
# It also pins that the probe pod image is digest-pinned.
#
# Run from repo root: bash scripts/tests/test-clean-install-smoke-exit-codes.sh
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SMOKE="${REPO_ROOT}/scripts/clean-install-smoke.sh"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

BIN="${WORK}/bin"
CHART="${WORK}/iac/charts/artifact-keeper"
mkdir -p "$BIN" "$CHART"
touch "${CHART}/Chart.yaml" "${CHART}/values-production.yaml"

# helm: every call succeeds.
cat >"${BIN}/helm" <<'STUB'
#!/usr/bin/env bash
exit 0
STUB

# sleep: keep the budget loops fast.
cat >"${BIN}/sleep" <<'STUB'
#!/usr/bin/env bash
exec /bin/sleep 0.1
STUB

# kubectl: behaviour driven by STUB_* env, call log in $STUB_STATE.
#   STUB_BACKEND_WGET  1 = the backend pod has wget (no probe pod)
#   STUB_RUN           ok | fail
#   STUB_PROBE         ready | pullfail-once | pullfail | pending
#   STUB_READYZ        200 | 503
cat >"${BIN}/kubectl" <<'STUB'
#!/usr/bin/env bash
state="$STUB_STATE"
echo "$*" >>"${state}/calls"
case "$1" in
  create) echo "apiVersion: v1"; exit 0 ;;
  apply)  cat >/dev/null; exit 0 ;;
  rollout|describe|logs|delete) exit 0 ;;
  run)
    [ "${STUB_RUN:-ok}" = "fail" ] && exit 1
    echo "$2" >>"${state}/pods"
    printf '%s\n' "$@" | grep -- '^--image=' >>"${state}/images"
    exit 0
    ;;
  exec)
    # kubectl exec -n NS POD -- sh -c CMD
    pod="$4"; cmd="${!#}"
    case "$cmd" in
      "command -v wget >/dev/null")
        [ "${STUB_BACKEND_WGET:-0}" = "1" ] && case "$pod" in ak-smoke-backend-*) exit 0 ;; esac
        exit 1 ;;
      "command -v curl >/dev/null") exit 1 ;;
      *)
        if [ "${STUB_READYZ:-200}" = "200" ]; then echo " HTTP/1.1 200 OK"; exit 0; fi
        echo " HTTP/1.1 503 Service Unavailable"; exit 0 ;;
    esac
    ;;
  get)
    case "$2" in
      deployment) exit 0 ;;
      pods)
        case "$*" in
          *"{.items[0].metadata.name}"*) echo "ak-smoke-backend-abc123" ;;
        esac
        exit 0 ;;
      pod)
        pod="$3"
        case "$*" in *jsonpath*) ;; *) exit 0 ;; esac
        n=$(grep -c . "${state}/pods" 2>/dev/null || echo 0)
        case "${STUB_PROBE:-ready}" in
          ready) echo "Running|true|" ;;
          pullfail) echo "Pending|false|ImagePullBackOff" ;;
          pullfail-once)
            if [ "$n" -ge 2 ]; then echo "Running|true|"; else echo "Pending|false|ErrImagePull"; fi ;;
          pending) echo "Pending|false|ContainerCreating" ;;
        esac
        exit 0 ;;
      *) exit 0 ;;
    esac
    ;;
esac
exit 0
STUB
chmod +x "${BIN}/helm" "${BIN}/sleep" "${BIN}/kubectl"

fails=0
case_n=0

# run_case LABEL WANT_EXIT WANT_PODS [VAR=VALUE ...] [-- extra smoke args]
run_case() {
  local label="$1" want_exit="$2" want_pods="$3"
  shift 3
  local envs=() extra=()
  while [ $# -gt 0 ]; do
    if [ "$1" = "--" ]; then shift; extra=("$@"); break; fi
    envs+=("$1"); shift
  done
  case_n=$((case_n + 1))
  local state="${WORK}/state-${case_n}"
  mkdir -p "$state"
  local actual pods
  env "${envs[@]}" STUB_STATE="$state" PATH="${BIN}:${PATH}" \
    LOGS_DIR="${WORK}/logs" GHCR_DOCKER_CONFIG="" \
    bash "$SMOKE" --run-id "t${case_n}" --backend-tag "sha-0000000" \
      --iac-repo "${WORK}/iac" --timeout 2 "${extra[@]}" \
      >"${state}/out" 2>&1
  actual=$?
  pods=$(grep -c . "${state}/pods" 2>/dev/null || true)
  pods=${pods:-0}
  if [ "$actual" = "$want_exit" ] && [ "$pods" = "$want_pods" ]; then
    echo "  PASS: ${label} (exit=${actual}, probe pods=${pods})"
  else
    echo "  FAIL: ${label} expected exit=${want_exit} probe pods=${want_pods}, got exit=${actual} probe pods=${pods}"
    sed 's/^/      | /' "${state}/out" | tail -25
    fails=$((fails + 1))
  fi
  if [ -s "${state}/images" ] && grep -qv '@sha256:[0-9a-f]\{64\}$' "${state}/images"; then
    echo "  FAIL: ${label}: probe pod image is not digest-pinned: $(sort -u "${state}/images")"
    fails=$((fails + 1))
  fi
}

run_case "probe pod Ready, /readyz 200            -> 0"  0  1 STUB_PROBE=ready STUB_READYZ=200
run_case "probe pod Ready, /readyz 503            -> 3"  3  1 STUB_PROBE=ready STUB_READYZ=503
run_case "backend wget, /readyz 503               -> 3"  3  0 STUB_BACKEND_WGET=1 STUB_READYZ=503
run_case "pull fails once, retry Ready, 200       -> 0"  0  2 STUB_PROBE=pullfail-once STUB_READYZ=200
run_case "pull fails every time                   -> 11" 11 2 STUB_PROBE=pullfail
run_case "probe pod stuck ContainerCreating       -> 11" 11 1 STUB_PROBE=pending
run_case "kubectl run fails                       -> 11" 11 0 STUB_RUN=fail
run_case "--expect-failure + /readyz 503          -> 0"  0  1 STUB_PROBE=ready STUB_READYZ=503 -- --expect-failure
run_case "--expect-failure + probe pod never Ready -> 11" 11 1 STUB_PROBE=pending -- --expect-failure

echo ""
if [ "$fails" -eq 0 ]; then
  echo "All clean-install-smoke exit-code cases passed."
  exit 0
fi
echo "${fails} case(s) failed."
exit 1
