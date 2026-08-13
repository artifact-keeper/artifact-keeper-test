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
