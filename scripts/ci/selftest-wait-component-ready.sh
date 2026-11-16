#!/usr/bin/env bash
# The grep patterns quote workflow text literally.
# shellcheck disable=SC2016
# Self-test for scripts/ci/wait-component-ready.sh (artifact-keeper-test#841),
# with a stub kubectl so no cluster is needed:
#
#   opensearch pod Ready                     -> exit 0, selector is the chart's
#   no pod matches the selector              -> exit 11 (INFRA), never a skip
#   kubectl cannot list pods                 -> exit 11 (INFRA)
#   pod scheduled, never Ready in the budget -> exit 1 (FAIL)
#   pod unschedulable                        -> exit 11 (INFRA)
#   run from a copy outside the repository   -> K8S_LIB_DIR is honoured
#   libs missing / NAMESPACE unset / unknown -> exit 11 (INFRA), not a FAIL
#   release-gate.yml waits through the helper, not a dead label
#
# Run from repo root: bash scripts/ci/selftest-wait-component-ready.sh
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
HELPER="${REPO_ROOT}/scripts/ci/wait-component-ready.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin" "$TMP/junit"

# Stub kubectl: `get pods -l <sel> -o json` prints $K8S_STUB_JSON and records
# the selector; K8S_STUB_FAIL=1 makes every call fail.
cat > "$TMP/bin/kubectl" <<'STUB'
#!/usr/bin/env bash
if [ "${K8S_STUB_FAIL:-0}" = "1" ]; then
  echo 'Error from server (Forbidden): pods is forbidden' >&2
  exit 1
fi
prev=""
for a in "$@"; do [ "$prev" = "-l" ] && echo "$a" >> "$K8S_STUB_SELECTORS"; prev="$a"; done
case " $* " in
  *" -o json "*) cat "$K8S_STUB_JSON" ;;
  *) echo "stub-kubectl $*" ;;
esac
STUB
chmod +x "$TMP/bin/kubectl"

pod() { # name phase ready [unschedulable]
  local conds='[]' cs="[{\"name\":\"opensearch\",\"ready\":$3,\"state\":{\"running\":{}}}]"
  if [ -n "${4:-}" ]; then
    conds='[{"type":"PodScheduled","status":"False","reason":"Unschedulable"}]'; cs='[]'
  fi
  printf '{"items":[{"metadata":{"name":"%s","uid":"u-%s","deletionTimestamp":null},"status":{"phase":"%s","conditions":%s,"containerStatuses":%s}}]}' \
    "$1" "$1" "$2" "$conds" "$cs"
}
printf '{"items":[]}' > "$TMP/empty.json"
pod opensearch-0 Running true > "$TMP/ready.json"
pod opensearch-0 Running false > "$TMP/notready.json"
pod opensearch-0 Pending false yes > "$TMP/unsched.json"

fails=0
run_case() { # label want_exit want_grep json [helper]
  local label="$1" want="$2" grep_for="$3" json="$4" helper="${5:-$HELPER}" out actual
  : > "$TMP/selectors"
  out=$(PATH="$TMP/bin:$PATH" K8S_STUB_JSON="$json" K8S_STUB_SELECTORS="$TMP/selectors" \
        K8S_STUB_FAIL="${STUB_FAIL:-0}" K8S_POLL_INTERVAL=1 NAMESPACE=test-ns \
        JUNIT_OUTPUT_DIR="$TMP/junit" bash "$helper" opensearch 2 2>&1)
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

run_case "Ready pod passes" 0 "opensearch-0 Ready after" "$TMP/ready.json"
if grep -qxF 'app.kubernetes.io/component=opensearch' "$TMP/selectors" \
   && ! grep -qvxF 'app.kubernetes.io/component=opensearch' "$TMP/selectors"; then
  echo "  PASS: selects app.kubernetes.io/component=opensearch only"
else
  echo "  FAIL: selectors used: $(tr '\n' ' ' < "$TMP/selectors")"; fails=$((fails+1))
fi
if grep -q 'name="opensearch pod' "$TMP/junit/wait-opensearch-ready.xml" 2>/dev/null; then
  echo "  PASS: JUnit case written"
else
  echo "  FAIL: no JUnit case in $TMP/junit"; fails=$((fails+1))
fi
run_case "no matching pod is INFRA, not a skip" 11 "matches no opensearch pod" "$TMP/empty.json"
STUB_FAIL=1 run_case "kubectl error is INFRA" 11 "could not list opensearch pods" "$TMP/empty.json"
run_case "scheduled but never Ready is a FAIL" 1 "did not become ready" "$TMP/notready.json"
run_case "unschedulable pod is INFRA" 11 "cluster reason" "$TMP/unsched.json"

# The gate installs the helper and main's libs into RUNNER_TEMP before the tree
# moves to a release line; the copy must work from there.
mkdir -p "$TMP/copy"
cp "$HELPER" "$TMP/copy/wait-component-ready.sh"
cp "${REPO_ROOT}/tests/lib/common.sh" "${REPO_ROOT}/tests/lib/k8s.sh" "$TMP/copy/"
K8S_LIB_DIR="$TMP/copy" run_case "copy outside the repository with K8S_LIB_DIR" 0 "Ready after" \
  "$TMP/ready.json" "$TMP/copy/wait-component-ready.sh"

# Setup problems before any pod is looked at are INFRA, not a product FAIL.
mkdir -p "$TMP/nolibs"
cp "$HELPER" "$TMP/nolibs/wait-component-ready.sh"
K8S_LIB_DIR="$TMP/nolibs" run_case "missing libs are INFRA" 11 "not found in" \
  "$TMP/ready.json" "$TMP/nolibs/wait-component-ready.sh"
out=$(env -u NAMESPACE bash "$HELPER" opensearch 2 2>&1); rc=$?
if [ "$rc" = 11 ] && grep -q "NAMESPACE is not set" <<<"$out"; then
  echo "  PASS: unset NAMESPACE is INFRA (exit=11)"
else
  echo "  FAIL: unset NAMESPACE: exit=${rc}: ${out}"; fails=$((fails+1))
fi
out=$(NAMESPACE=x bash "$HELPER" nosuch 2 2>&1); rc=$?
if [ "$rc" = 11 ]; then echo "  PASS: unknown component is INFRA (exit=11)"
else echo "  FAIL: unknown component: exit=${rc}"; fails=$((fails+1)); fi

# release-gate.yml must wait through the helper, and no step may select
# OpenSearch by a label the chart does not set.
WF="${REPO_ROOT}/.github/workflows/release-gate.yml"
if grep -qE 'app\.kubernetes\.io/name=opensearch|-l app=opensearch' "$WF"; then
  echo "  FAIL: release-gate.yml still selects OpenSearch by a label the chart does not set"; fails=$((fails+1))
elif ! grep -q 'wait-component-ready.sh" opensearch' "$WF" \
     || ! grep -qF 'K8S_LIB_DIR: ${{ runner.temp }}/component-wait' "$WF" \
     || ! grep -qF 'cp tests/lib/common.sh tests/lib/k8s.sh "$d/"' "$WF"; then
  echo "  FAIL: release-gate.yml does not wait for OpenSearch through wait-component-ready.sh"; fails=$((fails+1))
else
  echo "  PASS: release-gate.yml waits for OpenSearch through the helper"
fi

echo ""
if [ "$fails" -eq 0 ]; then echo "All wait-component-ready cases passed."; exit 0; fi
echo "${fails} case(s) failed."
exit 1
