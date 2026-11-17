#!/usr/bin/env bash
#
# Self-test for artifact_listed / await_artifact_listed in tests/lib/common.sh
# (artifact-keeper-test#364).
#
# A python stub serves GET /api/v1/repositories/{key}/artifacts?q=... the way
# the backend does (q is a case-insensitive substring of name or path). The
# "late" repository only lists its row from the third request on, standing in
# for an upload that lands after a short delay. Cases:
#
#   needle in name/path, any case             -> listed
#   needle + matching version / path version  -> listed
#   needle + a version that is not there      -> not listed
#   unknown repository (404)                  -> not listed
#   await on a row that appears late          -> returns 0, records nothing
#   await on a row that never appears         -> returns 0, records one FAIL
#                                                case named "Precondition: ...",
#                                                and the current test keeps its
#                                                own name for its own verdict
#
# Runs offline. Run from anywhere: bash tests/lib/selftest-artifact-listed.sh
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP_OUT=$(mktemp -d)
STUB_PID=""
# shellcheck disable=SC2329  # invoked by the EXIT trap
cleanup() {
  [ -n "$STUB_PID" ] && kill "$STUB_PID" 2>/dev/null
  rm -rf "$TMP_OUT"
}
trap cleanup EXIT

cat > "${TMP_OUT}/stub.py" <<'PY'
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

ROWS = {
    "repo-a": [{"name": "Foo-Bar", "path": "foo-bar/-/foo-bar-1.0.0.tgz", "version": "1.0.0"},
               {"name": "other", "path": "modules/o/m/commits/abc123", "version": "abc123"}],
    "late": [{"name": "slow", "path": "slow/2.0.0/slow-2.0.0.tar.gz", "version": "2.0.0"}],
}
HITS = {"late": 0}

class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        u = urlparse(self.path)
        parts = u.path.strip("/").split("/")
        if len(parts) != 5 or parts[:3] != ["api", "v1", "repositories"] or parts[4] != "artifacts":
            return self.send(404, {})
        key = parts[3]
        if key not in ROWS:
            return self.send(404, {"error": "repository not found"})
        rows = ROWS[key]
        if key == "late":
            HITS["late"] += 1
            if HITS["late"] < 3:
                rows = []
        q = parse_qs(u.query).get("q", [""])[0].lower()
        items = [r for r in rows if q in r["name"].lower() or q in r["path"].lower()]
        self.send(200, {"items": items, "pagination": {"page": 1, "per_page": 100,
                                                       "total": len(items), "total_pages": 1}})

srv = HTTPServer(("127.0.0.1", 0), H)
print(srv.server_address[1], flush=True)
srv.serve_forever()
PY

python3 "${TMP_OUT}/stub.py" > "${TMP_OUT}/port" 2>/dev/null &
STUB_PID=$!
for _ in $(seq 1 50); do
  [ -s "${TMP_OUT}/port" ] && break
  sleep 0.1
done
PORT=$(head -1 "${TMP_OUT}/port")
if [ -z "$PORT" ]; then
  echo "FAIL: stub did not start"
  exit 1
fi

# Source common.sh in a subshell per case so its `set -e` and globals stay put.
run() {
  BASE_URL="http://127.0.0.1:${PORT}" ADMIN_TOKEN=selftest WAIT_UNTIL_INTERVAL=0.2 \
    JUNIT_OUTPUT_DIR="${TMP_OUT}/junit" STRESS_LOG_DIR="${TMP_OUT}/stress" \
    bash -c "source '${REPO_ROOT}/tests/lib/common.sh'; set +e; $1" 2>&1
}

fails=0
check() {
  local label="$1" got="$2" want="$3"
  if [ "$got" = "$want" ]; then
    echo "  PASS: ${label}"
  else
    echo "  FAIL: ${label}: got '${got}', want '${want}'"
    fails=$((fails+1))
  fi
}

got=$(run "artifact_listed repo-a FOO-bar; echo rc=\$?")
check "needle matches the name, case-insensitive" "$got" "rc=0"

got=$(run "artifact_listed repo-a foo-bar 1.0.0; echo rc=\$?")
check "needle plus the row's version" "$got" "rc=0"

got=$(run "artifact_listed repo-a modules/o/m/commits/ abc123; echo rc=\$?")
check "needle plus a version found only in the path" "$got" "rc=0"

got=$(run "artifact_listed repo-a foo-bar 2.0.0; echo rc=\$?")
check "a version that is not there is not listed" "$got" "rc=1"

got=$(run "artifact_listed missing foo-bar; echo rc=\$?")
check "an unknown repository is not listed" "$got" "rc=1"

got=$(run "begin_suite s >/dev/null; begin_test t >/dev/null; await_artifact_listed late slow 2.0.0 10 >/dev/null 2>&1; echo \"rc=\$? fail=\$_FAIL_COUNT\"")
check "await on a late row returns once it lands and records nothing" "$got" "rc=0 fail=0"

got=$(run "begin_suite s >/dev/null; begin_test 'Index lists it' >/dev/null; await_artifact_listed repo-a never '' 1 >/dev/null 2>&1; echo \"rc=\$? fail=\$_FAIL_COUNT name=\$_TEST_NAME\"; printf '%s' \"\$_JUNIT_CASES\" | grep -c 'name=\"Precondition: .*never.* listed in repo-a\"'")
check "await on a row that never lands records one Precondition FAIL and keeps the test name" "$got" "rc=0 fail=1 name=Index lists it
1"

echo ""
if [ "$fails" -eq 0 ]; then
  echo "All artifact_listed cases passed."
  exit 0
fi
echo "${fails} case(s) failed."
exit 1
