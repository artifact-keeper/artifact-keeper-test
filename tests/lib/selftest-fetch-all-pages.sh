#!/usr/bin/env bash
#
# Self-test for fetch_all_pages in tests/lib/common.sh (artifact-keeper-test#725).
#
# A python stub serves a paginated {items, pagination} listing of 250 rows
# (per_page capped at 100, as the backend clamps it), a bare JSON array, and a
# 401. Cases:
#
#   250 rows over 3 pages     -> all 250 items, the last row included, exit 0
#   a bare array answer       -> taken as one page
#   401 on page 1             -> exit 1, FETCH_ALL_STATUS 401, the body kept
#   a query string in PATH    -> page/per_page appended with '&'
#
# Runs offline. Run from anywhere: bash tests/lib/selftest-fetch-all-pages.sh
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
import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

ROWS = [{"username": "user-%03d" % i} for i in range(250)]

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
        q = parse_qs(u.query)
        if u.path == "/denied":
            return self.send(401, {"error": "unauthorized"})
        if u.path == "/array":
            return self.send(200, [{"username": "only"}])
        if u.path == "/rows":
            if q.get("filter") not in (None, ["x"]):
                return self.send(400, {"error": "bad filter"})
            page = int(q.get("page", ["1"])[0])
            per = min(int(q.get("per_page", ["20"])[0]), 100)
            total_pages = (len(ROWS) + per - 1) // per
            items = ROWS[(page - 1) * per: page * per]
            return self.send(200, {"items": items, "pagination": {
                "page": page, "per_page": per, "total": len(ROWS), "total_pages": total_pages}})
        self.send(404, {})

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
  BASE_URL="http://127.0.0.1:${PORT}" JUNIT_OUTPUT_DIR="${TMP_OUT}/junit" STRESS_LOG_DIR="${TMP_OUT}/stress" \
    bash -c "source '${REPO_ROOT}/tests/lib/common.sh'; set +e; $1"
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

got=$(run "fetch_all_pages /rows '${TMP_OUT}/rows.json' 'X-Test: 1'; echo \"rc=\$? status=\$FETCH_ALL_STATUS\"; jq -r '[(.items|length), .items[-1].username] | join(\" \")' '${TMP_OUT}/rows.json'")
check "250 rows over 3 pages are all collected" "$got" "rc=0 status=200
250 user-249"

got=$(run "fetch_all_pages '/rows?filter=x' '${TMP_OUT}/q.json'; echo \"rc=\$?\"; jq -r '.items|length' '${TMP_OUT}/q.json'")
check "a query string in PATH gets &page=..&per_page=.." "$got" "rc=0
250"

got=$(run "fetch_all_pages /array '${TMP_OUT}/arr.json'; echo \"rc=\$?\"; jq -r '.items[0].username' '${TMP_OUT}/arr.json'")
check "a bare array answer is one page" "$got" "rc=0
only"

got=$(run "fetch_all_pages /denied '${TMP_OUT}/denied.json'; echo \"rc=\$? status=\$FETCH_ALL_STATUS\"; jq -r '.error' '${TMP_OUT}/denied.json'")
check "a 401 returns 1 with the status and the body kept" "$got" "rc=1 status=401
unauthorized"

got=$(run "FETCH_ALL_MAX_PAGES=2 fetch_all_pages /rows '${TMP_OUT}/cap.json'; echo \"rc=\$?\"; jq -r '.items|length' '${TMP_OUT}/cap.json'")
check "FETCH_ALL_MAX_PAGES bounds the walk" "$got" "rc=0
200"

echo ""
if [ "$fails" -eq 0 ]; then
  echo "All fetch_all_pages cases passed."
  exit 0
fi
echo "${fails} case(s) failed."
exit 1
