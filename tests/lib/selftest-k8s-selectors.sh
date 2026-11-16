#!/usr/bin/env bash
# The case scripts are single-quoted on purpose: they expand in the inner shell.
# shellcheck disable=SC2016,SC2001
#
# Self-test for tests/lib/k8s.sh (artifact-keeper-test#354).
#
# The resilience suites act on pods they find by label. For months the backend
# selector matched nothing and every suite turned that into a PASS ("killed"
# nothing) or a SKIP ("ARC runner timing"). This pins the replacement contract
# with a stub kubectl, so no cluster is needed:
#
#   k8s_require_pod  zero matches            -> exit 11 (INFRA), names the selector
#   k8s_require_pod  kubectl error           -> exit 11 (INFRA)
#   k8s_require_pod  prefers a Running pod   -> name + UID
#   k8s_wait_ready   replacement ready       -> 0, the NEW pod, not the excluded UID
#   k8s_wait_ready   only the old pod ready  -> not ready (never "recovered")
#   k8s_wait_ready   new pod Unschedulable   -> exit 11 (INFRA)
#   k8s_wait_ready   new pod ImagePullBackOff-> exit 11 (INFRA)
#   k8s_wait_ready   new pod never ready     -> exit 1 (product FAIL)
#   k8s_wait_ready   no pod at all           -> exit 11 (INFRA)
#   default selector is the chart's label    -> app.kubernetes.io/component=backend
#
# Run from repo root: bash tests/lib/selftest-k8s-selectors.sh
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin" "$TMP/junit"

# Stub kubectl: `get pods ... -o json` prints $K8S_STUB_JSON (or fails when
# K8S_STUB_FAIL=1); anything else (describe, --show-labels, -o wide) prints a
# marker so the diagnostic paths run.
cat > "$TMP/bin/kubectl" <<'STUB'
#!/usr/bin/env bash
if [ "${K8S_STUB_FAIL:-0}" = "1" ]; then
  echo 'Error from server (Forbidden): pods is forbidden' >&2
  exit 1
fi
case " $* " in
  *" -o json "*) cat "$K8S_STUB_JSON" ;;
  *) echo "stub-kubectl $*" ;;
esac
STUB
chmod +x "$TMP/bin/kubectl"

pod() { # name uid phase ready [deleting] [waiting-reason] [unschedulable]
  local name="$1" uid="$2" phase="$3" ready="$4" deleting="${5:-}" reason="${6:-}" unsched="${7:-}"
  local del='null' state='{"running":{}}' conds='[]'
  [ -n "$deleting" ] && del='"2026-11-16T00:00:00Z"'
  [ -n "$reason" ] && state="{\"waiting\":{\"reason\":\"${reason}\"}}"
  [ -n "$unsched" ] && conds='[{"type":"PodScheduled","status":"False","reason":"Unschedulable"}]'
  local cs="[{\"name\":\"backend\",\"ready\":${ready},\"state\":${state}}]"
  [ -n "$unsched" ] && cs='[]'
  printf '{"metadata":{"name":"%s","uid":"%s","deletionTimestamp":%s},"status":{"phase":"%s","conditions":%s,"containerStatuses":%s}}' \
    "$name" "$uid" "$del" "$phase" "$conds" "$cs"
}
fixture() { # file pod-json...
  local f="$TMP/$1"; shift
  local IFS=,
  printf '{"items":[%s]}' "$*" > "$f"
  echo "$f"
}

# inner SCRIPT: run SCRIPT in a fresh bash with common.sh + k8s.sh loaded.
inner() {
  cat <<INNER
source "${REPO_ROOT}/tests/lib/common.sh"
source "${REPO_ROOT}/tests/lib/k8s.sh"
JUNIT_OUTPUT_DIR="${TMP}/junit"
NAMESPACE=test-ns
K8S_POLL_INTERVAL=1
begin_suite "k8s-selftest"
begin_test "stub"
$1
end_suite
INNER
}

fails=0
run_case() { # label want_exit want_grep json script
  local label="$1" want="$2" grep_for="$3" json="$4" script="$5" out actual
  out=$(PATH="$TMP/bin:$PATH" K8S_STUB_JSON="$json" K8S_STUB_FAIL="${STUB_FAIL:-0}" \
        bash -c "$(inner "$script")" 2>&1)
  actual=$?
  if [ "$actual" != "$want" ]; then
    echo "  FAIL: ${label}: expected exit=${want} got exit=${actual}"
    echo "$out" | sed 's/^/      /' | tail -15
    fails=$((fails+1)); return
  fi
  if [ -n "$grep_for" ] && ! grep -qF -- "$grep_for" <<<"$out"; then
    echo "  FAIL: ${label}: output lacks '${grep_for}'"
    echo "$out" | sed 's/^/      /' | tail -15
    fails=$((fails+1)); return
  fi
  echo "  PASS: ${label} (exit=${actual})"
}

EMPTY=$(fixture empty.json)
OLD_ONLY=$(fixture old.json "$(pod be-old uid-old Running true)")
MIXED=$(fixture mixed.json "$(pod be-term uid-term Running true yes)" "$(pod be-pend uid-pend Pending false)" "$(pod be-run uid-run Running true)")
REPLACED=$(fixture replaced.json "$(pod be-old uid-old Running true yes)" "$(pod be-new uid-new Running true)")
SAME_NAME=$(fixture samename.json "$(pod pg-0 uid-new Running true)")
UNSCHED=$(fixture unsched.json "$(pod be-new uid-new Pending false "" "" yes)")
PULLFAIL=$(fixture pull.json "$(pod be-new uid-new Pending false "" ImagePullBackOff)")
NOTREADY=$(fixture notready.json "$(pod be-new uid-new Running false "" CrashLoopBackOff)")

run_case "default backend selector is the chart label" 0 "SEL=app.kubernetes.io/component=backend" "$EMPTY" \
  'echo "SEL=${AK_BACKEND_SELECTOR}"; pass'
run_case "require_pod: zero matches is INFRA (exit 11)" 11 "matches no backend pod" "$EMPTY" \
  'k8s_require_pod P "$AK_BACKEND_SELECTOR" backend; pass'
run_case "require_pod: zero matches never reaches the next line" 11 "" "$EMPTY" \
  'k8s_require_pod P "$AK_BACKEND_SELECTOR" backend; echo REACHED; exit 0'
STUB_FAIL=1 run_case "require_pod: kubectl error is INFRA (exit 11)" 11 "could not list backend pods" "$EMPTY" \
  'k8s_require_pod P "$AK_BACKEND_SELECTOR" backend; pass'
run_case "require_pod: prefers Running, not terminating" 0 "GOT=be-run/uid-run" "$MIXED" \
  'k8s_require_pod P "$AK_BACKEND_SELECTOR" backend; echo "GOT=${P}/${P_UID}"; pass'
run_case "wait_ready: replacement ready returns the new pod" 0 "READY=be-new" "$REPLACED" \
  'k8s_wait_ready "$AK_BACKEND_SELECTOR" backend 2 uid-old && { echo "READY=${K8S_READY_POD}"; pass; }'
run_case "wait_ready: same-name StatefulSet replacement matched by UID" 0 "READY=pg-0" "$SAME_NAME" \
  'k8s_wait_ready "$AK_POSTGRES_SELECTOR" PostgreSQL 2 uid-old && { echo "READY=${K8S_READY_POD}"; pass; }'
run_case "wait_ready: only the killed pod ready is not recovery (INFRA: no replacement)" 11 "exists after" "$OLD_ONLY" \
  'k8s_wait_ready "$AK_BACKEND_SELECTOR" backend 2 uid-old && pass'
run_case "wait_ready: Unschedulable replacement is INFRA (exit 11)" 11 "cluster reason" "$UNSCHED" \
  'k8s_wait_ready "$AK_BACKEND_SELECTOR" backend 2 uid-old && pass'
run_case "wait_ready: ImagePullBackOff is INFRA (exit 11)" 11 "cluster reason" "$PULLFAIL" \
  'k8s_wait_ready "$AK_BACKEND_SELECTOR" backend 2 uid-old && pass'
run_case "wait_ready: scheduled but never ready is a product FAIL (exit 1)" 1 "did not become ready" "$NOTREADY" \
  'k8s_wait_ready "$AK_BACKEND_SELECTOR" backend 2 uid-old && pass'
run_case "wait_ready: no pod at all is INFRA (exit 11)" 11 "exists after" "$EMPTY" \
  'k8s_wait_ready "$AK_BACKEND_SELECTOR" backend 2 && pass'

# Tree-wide: no resilience script may go back to a label the chart never set.
# Comment lines are excluded so the history notes can name the old selectors.
dead=$(grep -rnE 'app=artifact-keeper-backend|app\.kubernetes\.io/name=meilisearch' "${REPO_ROOT}/tests/resilience" \
  | grep -vE '^[^:]+:[0-9]+:[[:space:]]*#' || true)
if [ -n "$dead" ]; then
  echo "  FAIL: tests/resilience still uses a selector the chart does not set:"
  echo "$dead" | sed 's/^/      /'
  fails=$((fails+1))
else
  echo "  PASS: no dead selectors under tests/resilience"
fi

echo ""
if [ "$fails" -eq 0 ]; then
  echo "All k8s selector/readiness cases passed."
  exit 0
fi
echo "${fails} case(s) failed."
exit 1
