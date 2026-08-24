#!/usr/bin/env bash
# selftest-release-gate-contract.sh - meta-test pinning common.sh's
# RELEASE_GATE coverage contract (artifact-keeper-test#339).
#
# Why this exists
# ---------------
# `skip_suite` hard-fails under RELEASE_GATE=1 because "a silently skipped
# suite is indistinguishable from a passing one". The per-test `skip` path had
# no equivalent floor, so the same silent success was reachable one level down:
# a suite in which every test skipped exited 0 and certified nothing. The
# widest route to it was `require_feature`, whose only input is a single
# `GET /health` probe that degraded every failure mode — timeout, reset, warm-up
# 503, malformed JSON, missing `.version`, absent `jq` — to the string
# "unknown", cached it, and skipped every feature for the rest of the process.
#
# The fix has three moving parts, and each is easy to silently neuter later:
#
#   1. `get_backend_version` retries the probe. Drop the retry and a single
#      warm-up blip poisons the run again.
#   2. `require_feature` routes an undeterminable version through `infra_fail`
#      when RELEASE_GATE=1, and keeps the graceful skip when it is not.
#      Collapse either half and the gate goes quiet or local dev goes hostile.
#   3. `end_suite` fails a suite that recorded zero passes and at least one
#      skip when RELEASE_GATE=1. Remove it and all-skipped certifies green.
#
# So each part is pinned here by CONSTRUCTING the failure and asserting the
# exit code, not by asserting the current implementation back to itself. Every
# case drives the real helpers through a real suite-shaped script.
#
# Deliberately does NOT need an Artifact Keeper deployment: the fixtures are a
# closed TCP port (probe cannot succeed) and a small python stub that serves
# whatever /health body a case needs. That keeps the meta-test runnable on a
# plain hosted runner and on a laptop.
#
# Usage: bash tests/lib/selftest-release-gate-contract.sh
# Exits 0 if every case holds, 1 otherwise.

set -uo pipefail

SELFTEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMMON_SH="${SELFTEST_DIR}/common.sh"

WORK="$(mktemp -d)"
STUB_PID=""
cleanup() {
  [ -n "$STUB_PID" ] && kill "$STUB_PID" 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT

CASES_RUN=0
CASES_FAILED=0

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

# A port with nothing listening: every /health probe fails at connect.
# Chosen high and checked, so we do not accidentally hit a real service.
find_closed_port() {
  local p
  for p in 45871 45872 45873 45874 45875; do
    if ! (exec 3<>"/dev/tcp/127.0.0.1/${p}") 2>/dev/null; then
      echo "$p"
      return 0
    fi
  done
  echo "45999"
}

# Stub backend. MODE is one of:
#   version:<v>     always serve {"version":"<v>"} on /health
#   noversion       serve a /health body with no .version field
#   flaky:<n>:<v>   fail the first <n> /health requests with 503, then serve <v>
start_stub() {
  local mode="$1" port="$2"
  cat > "${WORK}/stub.py" <<'PYEOF'
import http.server, socketserver, sys, json
MODE = sys.argv[1]
PORT = int(sys.argv[2])
state = {"hits": 0}

class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *a): pass
    def do_GET(self):
        if self.path.split('?')[0] != '/health':
            self.send_response(404); self.send_header('Content-Length', '0'); self.end_headers(); return
        state["hits"] += 1
        kind = MODE.split(':')
        if kind[0] == 'version':
            body = json.dumps({"status": "healthy", "version": kind[1]}).encode()
        elif kind[0] == 'noversion':
            body = json.dumps({"status": "healthy"}).encode()
        elif kind[0] == 'flaky':
            if state["hits"] <= int(kind[1]):
                self.send_response(503); self.send_header('Content-Length', '0'); self.end_headers(); return
            body = json.dumps({"status": "healthy", "version": kind[2]}).encode()
        else:
            self.send_response(500); self.send_header('Content-Length', '0'); self.end_headers(); return
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

class S(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

S(("127.0.0.1", PORT), H).serve_forever()
PYEOF
  python3 "${WORK}/stub.py" "$mode" "$port" >/dev/null 2>&1 &
  STUB_PID=$!
  local _i
  for _i in $(seq 1 40); do
    if (exec 3<>"/dev/tcp/127.0.0.1/${port}") 2>/dev/null; then
      exec 3>&- 2>/dev/null
      return 0
    fi
    sleep 0.25
  done
  echo "FATAL: stub backend did not come up on port ${port}"
  return 1
}

stop_stub() {
  [ -n "$STUB_PID" ] && kill "$STUB_PID" 2>/dev/null
  STUB_PID=""
  sleep 0.2
}

# Write a suite-shaped script. BODY is inserted after begin_suite; the script
# ends with end_suite, exactly like a real suite.
write_suite() {
  local path="$1" name="$2" body="$3"
  cat > "$path" <<EOF
#!/usr/bin/env bash
source "${COMMON_SH}"
begin_suite "${name}"
${body}
end_suite
EOF
}

# run_case <label> <expected_exit> <script> <must_contain|-> <must_not_contain|-> [ENV=VAL ...]
#
# The exit code alone is not always enough: a suite whose only gated test
# skipped exits 0 on the PRE-FIX code for the wrong reason. The substring
# assertions pin WHY a case passed, so this self-test cannot go green against a
# reverted common.sh.
run_case() {
  local label="$1" expected="$2" script="$3" want="$4" unwant="$5"
  shift 5
  CASES_RUN=$(( CASES_RUN + 1 ))
  local out actual problems=""
  out=$(env "$@" JUNIT_OUTPUT_DIR="${WORK}/junit" bash "$script" 2>&1)
  actual=$?
  if [ "$actual" -ne "$expected" ]; then
    problems="${problems}expected exit ${expected}, got ${actual}; "
  fi
  if [ "$want" != "-" ] && ! grep -qF -- "$want" <<<"$out"; then
    problems="${problems}output missing '${want}'; "
  fi
  if [ "$unwant" != "-" ] && grep -qF -- "$unwant" <<<"$out"; then
    problems="${problems}output unexpectedly contains '${unwant}'; "
  fi
  if [ -z "$problems" ]; then
    echo "  ok   ${label} (exit ${actual})"
  else
    CASES_FAILED=$(( CASES_FAILED + 1 ))
    echo "  FAIL ${label}: ${problems%; }"
    echo "$out" | sed 's/^/       | /'
  fi
}

mkdir -p "${WORK}/junit"

# A feature whose floor is low enough that any stub version above it satisfies
# require_feature. Read from the map rather than hardcoded so a future rename
# breaks loudly here instead of silently skipping the case.
FEATURE="sbom_declared_dependencies"
FEATURE_FLOOR=$(BASE_URL="http://127.0.0.1:1" bash -c \
  'source "$1" >/dev/null 2>&1; _feature_min_version "$2"' _ "$COMMON_SH" "$FEATURE")
if [ -z "$FEATURE_FLOOR" ]; then
  echo "FATAL: '${FEATURE}' is not in _feature_min_version; update this self-test"
  exit 1
fi
echo "Pinned feature: ${FEATURE} (floor ${FEATURE_FLOOR})"

CLOSED_PORT="$(find_closed_port)"
DEAD_URL="http://127.0.0.1:${CLOSED_PORT}"
STUB_PORT=45880
STUB_URL="http://127.0.0.1:${STUB_PORT}"

# ---------------------------------------------------------------------------
# Suites under test
# ---------------------------------------------------------------------------

write_suite "${WORK}/suite-feature.sh" "selftest-feature" \
'begin_test "gated"
require_feature "'"${FEATURE}"'" || { end_suite; exit 0; }
pass'

write_suite "${WORK}/suite-allskip.sh" "selftest-allskip" \
'begin_test "one"
skip "capability not provisioned"
begin_test "two"
skip "capability not provisioned"'

write_suite "${WORK}/suite-mixed.sh" "selftest-mixed" \
'begin_test "one"
pass
begin_test "two"
skip "optional sub-behaviour absent"'

write_suite "${WORK}/suite-allpass.sh" "selftest-allpass" \
'begin_test "one"
pass'

# Drives skip_suite with a reason supplied by the case, so the capability
# exemption allowlist can be exercised in both directions from one fixture.
write_suite "${WORK}/suite-skipsuite.sh" "selftest-skipsuite" \
'skip_suite "${SELFTEST_SKIP_REASON}"'

# ---------------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------------

echo ""
echo "1. require_feature: undeterminable backend version"

# The bug: probe fails -> "unknown" -> skip -> suite exits 0 having asserted
# nothing, under the gate. Must now be an INFRA outcome (DTF_EXIT_INFRA=11).
run_case "gate + unreachable backend -> infra exit 11" 11 "${WORK}/suite-feature.sh" \
  "INFRA/SETUP FAILURE" "SKIP:" \
  BASE_URL="$DEAD_URL" RELEASE_GATE=1 \
  BACKEND_VERSION_PROBE_ATTEMPTS=2 BACKEND_VERSION_PROBE_DELAY=0 BACKEND_VERSION_PROBE_TIMEOUT=2

# Negative control: local dev against a stopped backend must stay graceful.
run_case "no gate + unreachable backend -> graceful skip, exit 0" 0 "${WORK}/suite-feature.sh" \
  "SKIP: could not determine backend version" "INFRA/SETUP FAILURE" \
  BASE_URL="$DEAD_URL" \
  BACKEND_VERSION_PROBE_ATTEMPTS=2 BACKEND_VERSION_PROBE_DELAY=0 BACKEND_VERSION_PROBE_TIMEOUT=2

echo ""
echo "2. get_backend_version: /health reachable but carrying no version"

start_stub "noversion" "$STUB_PORT" || exit 1
run_case "gate + /health without .version -> infra exit 11" 11 "${WORK}/suite-feature.sh" \
  "INFRA/SETUP FAILURE" "SKIP:" \
  BASE_URL="$STUB_URL" RELEASE_GATE=1 \
  BACKEND_VERSION_PROBE_ATTEMPTS=2 BACKEND_VERSION_PROBE_DELAY=0 BACKEND_VERSION_PROBE_TIMEOUT=2
stop_stub

echo ""
echo "3. get_backend_version: the retry is load-bearing"

# Two 503s then a good body. With a single-shot probe this suite records a skip
# and (pre-#339) exits 0 having tested nothing; with the retry it resolves the
# version and the gated test actually runs.
start_stub "flaky:2:${FEATURE_FLOOR}" "$STUB_PORT" || exit 1
run_case "gate + /health 503 twice then healthy -> suite runs, exit 0" 0 "${WORK}/suite-feature.sh" \
  "1 passed, 0 failed, 0 skipped" "SKIP:" \
  BASE_URL="$STUB_URL" RELEASE_GATE=1 \
  BACKEND_VERSION_PROBE_ATTEMPTS=4 BACKEND_VERSION_PROBE_DELAY=1 BACKEND_VERSION_PROBE_TIMEOUT=2
stop_stub

# Same fixture, but a retry budget too small to reach the healthy response.
# Pins that case 3 passes because the retry ran, not because the stub is lenient.
start_stub "flaky:2:${FEATURE_FLOOR}" "$STUB_PORT" || exit 1
run_case "gate + same fixture, 1 attempt only -> infra exit 11" 11 "${WORK}/suite-feature.sh" \
  "INFRA/SETUP FAILURE" "-" \
  BASE_URL="$STUB_URL" RELEASE_GATE=1 \
  BACKEND_VERSION_PROBE_ATTEMPTS=1 BACKEND_VERSION_PROBE_DELAY=0 BACKEND_VERSION_PROBE_TIMEOUT=2
stop_stub

echo ""
echo "4. end_suite: RELEASE_GATE coverage floor"

start_stub "version:${FEATURE_FLOOR}" "$STUB_PORT" || exit 1

# The systemic case: every test skipped for a reason that has nothing to do
# with the version probe (a missing CLI, an unprovisioned capability).
run_case "gate + every test skipped -> infra exit 11" 11 "${WORK}/suite-allskip.sh" \
  "suite certified nothing under RELEASE_GATE=1" "-" \
  BASE_URL="$STUB_URL" RELEASE_GATE=1

run_case "no gate + every test skipped -> exit 0" 0 "${WORK}/suite-allskip.sh" \
  "0 passed, 0 failed, 2 skipped" "INFRA/SETUP FAILURE" \
  BASE_URL="$STUB_URL"

# Negative controls: the floor must not fire on suites that did certify
# something. A mixed pass/skip suite is the shape a legitimate version-gated
# skip takes on a run against an older backend_tag.
run_case "gate + mixed pass/skip -> exit 0" 0 "${WORK}/suite-mixed.sh" \
  "1 passed, 0 failed, 1 skipped" "INFRA/SETUP FAILURE" \
  BASE_URL="$STUB_URL" RELEASE_GATE=1

run_case "gate + all pass -> exit 0" 0 "${WORK}/suite-allpass.sh" \
  "1 passed, 0 failed, 0 skipped" "INFRA/SETUP FAILURE" \
  BASE_URL="$STUB_URL" RELEASE_GATE=1

# And the healthy end-to-end path: version resolves, feature floor is met, the
# gated test runs and passes.
run_case "gate + healthy backend at feature floor -> exit 0" 0 "${WORK}/suite-feature.sh" \
  "1 passed, 0 failed, 0 skipped" "SKIP:" \
  BASE_URL="$STUB_URL" RELEASE_GATE=1

stop_stub

echo ""
echo "5. skip_suite: capability-exemption allowlist directionality"

# The allowlist is the one documented escape from the coverage floor, so its
# NARROWNESS is the whole safety argument. Each row must excuse exactly the
# capability it names and nothing adjacent. These cases drive the real
# skip_suite through a real suite script, so a row widened to a generic
# substring (or the allowlist bypassed altogether) turns this red.
#
# A capability whose absence is genuinely not a candidate defect: EXEMPT.
run_case "gate + exempt reason (pypi upstream) -> exit 0, EXEMPT" 0 "${WORK}/suite-skipsuite.sh" \
  "EXEMPT: pullthrough_upstream_unreachable" "FAIL:" \
  RELEASE_GATE=1 \
  SELFTEST_SKIP_REASON="upstream pypi.org unreachable from the gate deploy: reachability probe GET https://pypi.org/simple/flake8/ failed"

run_case "gate + exempt reason (npm upstream) -> exit 0, EXEMPT" 0 "${WORK}/suite-skipsuite.sh" \
  "EXEMPT: pullthrough_upstream_unreachable" "FAIL:" \
  RELEASE_GATE=1 \
  SELFTEST_SKIP_REASON="upstream registry.npmjs.org unreachable from the gate deploy: reachability probe GET https://registry.npmjs.org/@types%2Fnode failed"

# The negative controls are the load-bearing half. Each of these is a string a
# pullthrough suite can plausibly emit, and every one of them must still red
# the gate.
#
# The bare per-test string every gated test in those suites used to emit. If a
# row were keyed on "upstream unreachable" instead of the host, this passes and
# the allowlist becomes a blanket waiver.
run_case "gate + bare 'upstream unreachable' -> hard fail" 1 "${WORK}/suite-skipsuite.sh" \
  "FAIL: skip_suite called with RELEASE_GATE=1" "EXEMPT:" \
  RELEASE_GATE=1 SELFTEST_SKIP_REASON="upstream unreachable"

# The pre-fix wording. Names the same host, but is not the probe-verified
# reason, so it must not be excused either.
run_case "gate + pre-fix pypi wording -> hard fail" 1 "${WORK}/suite-skipsuite.sh" \
  "FAIL: skip_suite called with RELEASE_GATE=1" "EXEMPT:" \
  RELEASE_GATE=1 SELFTEST_SKIP_REASON="pypi.org unreachable from test environment"

# A REACHABLE upstream that the candidate then mishandles. This is the defect
# class the exemption must never swallow.
run_case "gate + reachable upstream, proxy broken -> hard fail" 1 "${WORK}/suite-skipsuite.sh" \
  "FAIL: skip_suite called with RELEASE_GATE=1" "EXEMPT:" \
  RELEASE_GATE=1 SELFTEST_SKIP_REASON="upstream pypi.org reachable but the Remote proxy returned HTTP 502"

# A third-party host that has no row. Adding one is a deliberate act.
run_case "gate + unlisted upstream host -> hard fail" 1 "${WORK}/suite-skipsuite.sh" \
  "FAIL: skip_suite called with RELEASE_GATE=1" "EXEMPT:" \
  RELEASE_GATE=1 SELFTEST_SKIP_REASON="upstream crates.io unreachable from the gate deploy"

# Outside the gate every one of these stays a graceful skip.
run_case "no gate + non-exempt reason -> graceful skip, exit 0" 0 "${WORK}/suite-skipsuite.sh" \
  "SKIP_SUITE: upstream unreachable" "FAIL:" \
  SELFTEST_SKIP_REASON="upstream unreachable"

echo ""
echo "6. discovery contract: every discovered test sources common.sh"

# Why this lives here (artifact-keeper-test#388)
# ----------------------------------------------------
# Everything above pins the SEMANTICS of common.sh. This case pins the
# precondition those semantics depend on: that a script run-suite.sh discovers
# is actually using them.
#
# scripts/run-suite.sh discovers with `find <suite-dir> -name 'test-*.sh'`,
# which is recursive, and judges each script purely on its exit status. A
# script that brings its own framework therefore inherits none of the
# contract -- no JUnit XML, no RELEASE_GATE skip semantics, and, if its own
# fail() forgets to set an exit code, no way to fail at all.
#
# That is not hypothetical. tests/security/redteam/ held 15 such scripts for
# five months inside the BLOCKING security-tests job. Their fail() incremented
# a counter nothing read and all 15 ended in `exit 0`, so run-suite.sh
# recorded PASS unconditionally on every release. See
# tests/security/README-redteam-port.md.
#
# The check is a plain grep over the tree rather than a constructed fixture,
# because the failure mode is a file existing, not a helper misbehaving.

# Scripts that legitimately do not source common.sh. Keep this list at zero
# entries if you can; every row is a script the contract does not cover.
#   tests/release-gate/test-scan-completion-format-matrix.sh
#     A local developer driver, not a run-suite suite: it shells out to the
#     gate primitive per format and already exits non-zero on any failure.
#     tests/release-gate is not passed to run-suite.sh by any workflow.
CONTRACT_EXEMPT=(
  "tests/release-gate/test-scan-completion-format-matrix.sh"
)

REPO_ROOT="$(cd "${SELFTEST_DIR}/../.." && pwd)"
offenders=""
while IFS= read -r script; do
  rel="${script#"${REPO_ROOT}"/}"
  exempt=false
  for allowed in "${CONTRACT_EXEMPT[@]}"; do
    if [ "$rel" = "$allowed" ]; then
      exempt=true
      break
    fi
  done
  $exempt && continue
  if ! grep -q 'lib/common\.sh' "$script"; then
    offenders="${offenders}  ${rel}"$'\n'
  fi
done < <(find "${REPO_ROOT}/tests" -name 'test-*.sh' -type f | sort)

CASES_RUN=$(( CASES_RUN + 1 ))
if [ -z "$offenders" ]; then
  echo "  PASS: every discovered test-*.sh sources tests/lib/common.sh"
else
  CASES_FAILED=$(( CASES_FAILED + 1 ))
  echo "  FAIL: these test scripts do not source tests/lib/common.sh, so"
  echo "        run-suite.sh judges them on their own exit code alone and they"
  echo "        emit no JUnit XML and honour no RELEASE_GATE semantics:"
  printf '%s' "$offenders"
  echo "        Port them onto common.sh, or add a justified row to"
  echo "        CONTRACT_EXEMPT in $(basename "${BASH_SOURCE[0]}")."
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

echo ""
echo "========================================"
echo "  release-gate contract self-test: $(( CASES_RUN - CASES_FAILED ))/${CASES_RUN} cases held"
echo "========================================"
if [ "$CASES_FAILED" -gt 0 ]; then
  exit 1
fi
