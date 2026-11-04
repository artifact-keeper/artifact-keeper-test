#!/usr/bin/env bash
# test-mcp-probe-isolated.sh - the opt-in remote tools/list probe is isolated
# and well-behaved (artifact-keeper#5253 Phase 2, issue 3.3 mcp_probe_remotes,
# 3.4 "Introspection", 8 Capabilities bullet).
#
#   - mcp_probe_remotes defaults to off: publishing a server whose remotes[]
#     names the HTTP mock (tests/lib/mock-mcp-http-server.py) makes no
#     request to it
#   - hosted_only: a publish queues a remote_probe job for the remote
#     (GET .../versions/{v}/capabilities: introspection.remoteProbe
#     hosted_only, probeEnabled true, jobs[] kind remote_probe target
#     remote:0); the separate ak-mcp-introspector worker (worker API
#     /api/v1/mcp/introspection/jobs/claim|{id}/complete, mcp:introspect
#     token) calls server/discover or initialize + tools/list, identifies
#     itself in User-Agent (ak-mcp-introspector/<version>), never calls
#     tools/call and never sends the publisher's remotes[].headers
#   - targets on loopback/private ranges are refused, and a redirect is not
#     followed
#
# Address handling: the gate's mocks run on the runner pod, a PRIVATE address
# (MOCK_UPSTREAM_HOSTNAME), which the probe must refuse by default. So:
#   - by default the suite asserts the refusal: with hosted_only set, the
#     private-address mock still sees zero requests
#   - AK_TEST_MCP_PROBE_REACHABLE=1 declares that an introspector worker is
#     deployed with the runner's CIDR in AK_SSRF_ALLOW_PRIVATE_CIDRS; then the
#     positive leg (the worker reaches a recording MCP server on the runner)
#     and the redirect leg run, and the private-range refusal is asserted on
#     loopback instead. Without it those tests skip with that reason.
#
# Gate: mcp_require_registry mcp_capabilities, then a route probe: the
# probe's snapshots are read back on GET /mcp/<repo>/v0.1/servers/{name}/
# versions/{v}/capabilities, so a backend that answers it with the router
# fallback ships no probe -> mcp_skip_later_phase. (The mcp_probe_remotes
# setting is echoed by the Phase 2/3 settings scaffold before the worker
# exists, so its echo is not a discriminating probe.)
#
# Requires: curl, jq, python3, MOCK_UPSTREAM_HOSTNAME.

# shellcheck source=../lib/common.sh disable=SC1091
source "$(dirname "$0")/../lib/common.sh"
# shellcheck source=../lib/mcp-helpers.sh disable=SC1091
source "$(dirname "$0")/../lib/mcp-helpers.sh"

begin_suite "mcp-probe-isolated"
auth_admin
setup_workdir
require_cmd curl
require_cmd jq
require_cmd python3
mcp_require_registry mcp_capabilities
mcp_require_dialback

# --- Contract (docs/mcp-registry.md "Capabilities and introspection") ------
PROBE_KEY="mcp_probe_remotes"              # "Repository settings"
CAPS_TAIL="capabilities"                    # /v0.1/servers/{name}/versions/{v}/capabilities
# "User-Agent: ak-mcp-introspector/<version> (+<docs>; capability probe; ...)"
PROBE_UA_RE='^ak-mcp-introspector/'
PROBE_QUIET_SECS="${MCP_PROBE_QUIET_SECS:-30}"
PROBE_WAIT_SECS="${MCP_PROBE_WAIT_SECS:-180}"

REPO="mcp-probe-${RUN_ID}"
NS="io.github.ak-probe-${RUN_ID}"
PUB_HEADER="X-Publisher-Token"
PUB_SECRET="pub-secret-${RUN_ID}"
REACHABLE="${AK_TEST_MCP_PROBE_REACHABLE:-0}"

# ---------------------------------------------------------------------------
# A recording MCP server (logs JSON-RPC method, User-Agent and headers) and a
# redirector, both stdlib python written to WORK_DIR.
# ---------------------------------------------------------------------------

RECORDER="${WORK_DIR}/recorder.py"
cat > "$RECORDER" <<'PY'
import http.server, json, os, sys, threading
STATE, PORT, REDIRECT = sys.argv[1], int(sys.argv[2]), (sys.argv[3] if len(sys.argv) > 3 else "")
LOCK = threading.Lock()
TOOLS = [{"name": "echo", "description": "Echo", "inputSchema": {"type": "object"}}]

def log(entry):
    with LOCK:
        with open(os.path.join(STATE, "log.jsonl"), "a") as fh:
            fh.write(json.dumps(entry) + "\n")

class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *a):
        pass
    def _send(self, status, body=b"", headers=None):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)
    def _any(self):
        if self.path == "/__readyz":
            return self._send(200, b"ok")
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b""
        try:
            msg = json.loads(raw.decode() or "null")
        except ValueError:
            msg = None
        method = msg.get("method") if isinstance(msg, dict) else None
        log({"verb": self.command, "path": self.path, "method": method,
             "ua": self.headers.get("User-Agent", ""), "headers": dict(self.headers.items())})
        if REDIRECT:
            return self._send(302, b"", {"Location": REDIRECT})
        if not isinstance(msg, dict) or "id" not in msg:
            return self._send(202)
        if method == "initialize":
            res = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                   "serverInfo": {"name": "ak-e2e-recorder", "version": "1.0.0"}}
        elif method == "tools/list":
            res = {"tools": TOOLS}
        elif method == "server/discover":
            res = {"capabilities": {"tools": {}}, "serverInfo": {"name": "ak-e2e-recorder", "version": "1.0.0"}}
        elif method in ("resources/list", "prompts/list"):
            res = {method.split("/")[0]: []}
        elif method == "tools/call":
            res = {"content": [{"type": "text", "text": "called"}]}
        else:
            return self._send(200, json.dumps({"jsonrpc": "2.0", "id": msg["id"], "error": {"code": -32601, "message": "nope"}}).encode())
        self._send(200, json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": res}).encode())
    do_GET = do_POST = do_DELETE = do_HEAD = _any

class S(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

S(("0.0.0.0", PORT), H).serve_forever()
PY

# start_recorder NAME [REDIRECT_TO]: sets REC_PORT / REC_DIR.
start_recorder() {
  local dir="${WORK_DIR}/rec-$1" port pid _
  mkdir -p "$dir"
  : > "${dir}/log.jsonl"
  port=$(_pick_mock_port)
  python3 -I "$RECORDER" "$dir" "$port" "${2:-}" > "${dir}/out" 2>&1 &
  pid=$!
  disown "$pid" 2>/dev/null || true
  add_exit_handler "kill ${pid} 2>/dev/null || true"
  for _ in $(seq 1 20); do
    [ "$(curl -s --max-time 2 -o /dev/null -w '%{http_code}' "http://127.0.0.1:${port}/__readyz")" = "200" ] && break
    sleep 0.5
  done
  REC_PORT="$port"
  REC_DIR="$dir"
}

rec_count() {
  grep -c . "${1}/log.jsonl" 2>/dev/null || echo 0
}

# publish_remote NAME VERSION URL: publish a remotes-only server whose remote
# carries a publisher header with a secret value (marked isSecret, so the
# lint's secret_unmarked rule does not flag it).
publish_remote() {
  local doc
  doc="${WORK_DIR}/$(echo "$1" | tr '/' '_')-$2.json"
  jq -n --arg s "$MCP_SCHEMA_URL" --arg n "$1" --arg v "$2" --arg u "$3" --arg h "$PUB_HEADER" --arg sec "$PUB_SECRET" \
    '{"$schema":$s,name:$n,description:"Probe target",version:$v,
      remotes:[{type:"streamable-http",url:$u,headers:[{name:$h,value:$sec,isSecret:true,description:"publisher token"}]}]}' > "$doc"
  mcp_publish "$REPO" "$doc"
}

# caps_introspection NAME VERSION: "remoteProbe|probeEnabled|<remote_probe
# job targets>" from the version's capabilities answer (admin: members and
# administrators see the jobs).
caps_introspection() {
  mcp_get "$REPO" "$(mcp_version_path "$1" "$2")/${CAPS_TAIL}" admin
  mcp_json '.introspection | "\(.remoteProbe)|\(.probeEnabled)|\([.jobs[]? | select(.kind == "remote_probe") | .target] | unique | join(","))"'
}

# ---------------------------------------------------------------------------
# Setup and the route probe
# ---------------------------------------------------------------------------

begin_test "Setup: mcp repository and the HTTP MCP mock"
if ! mcp_create_repo "$REPO" '{"mcp_package_policy":"open"}'; then
  fail_fatal "create mcp repository" "$MCP_CREATE_ERROR"
fi
if ! start_mock_mcp_http "${WORK_DIR}/mcp-http"; then
  infra_fail "mock-mcp-http-server did not start" "$(head -c 400 "${WORK_DIR}/mock-mcp-http.err" 2>/dev/null)"
  end_suite
fi
publish_remote "${NS}/off" 1.0.0 "$MCP_HTTP_URL"
[ "$MCP_STATUS" = "200" ] || fail_fatal "publish ${NS}/off answered ${MCP_STATUS}" "$(mcp_snip)"
pass

CAPS_URL="$(mcp_base "$REPO")/$(mcp_version_path "${NS}/off" 1.0.0)/${CAPS_TAIL}"
if ! mcp_probe_route GET "$CAPS_URL"; then
  mcp_skip_later_phase mcp_capabilities "GET $(mcp_url_path "$CAPS_URL") answered ${MCP_STATUS} with the router fallback; no capability snapshots for a remote probe to post to"
fi

# ---------------------------------------------------------------------------
# Default off
# ---------------------------------------------------------------------------

begin_test "${PROBE_KEY} defaults to off and the remote is never contacted"
setting=$(curl -s "${CURL_TIMEOUT_ARGS[@]}" -H "$(auth_header)" "${BASE_URL}/api/v1/repositories/${REPO}" | jq -r --arg k "$PROBE_KEY" '.[$k] // empty')
sleep "$PROBE_QUIET_SECS"
if [ "$setting" != "off" ]; then
  fail "${PROBE_KEY} echoed '${setting}', expected off"
elif [ "$(mcp_http_count)" != "0" ]; then
  fail "with ${PROBE_KEY}=off the remote saw $(mcp_http_count) request(s)" "$(cat "${MCP_HTTP_STATE_DIR}/request-log.txt" 2>/dev/null)"
else
  pass
fi

begin_test "Set ${PROBE_KEY}=hosted_only"
if mcp_patch_repo "$REPO" "$(jq -cn --arg k "$PROBE_KEY" '{($k):"hosted_only"}')"; then
  pass
else
  fail_fatal "PATCH ${PROBE_KEY}=hosted_only answered ${MCP_STATUS}: $(mcp_snip)"
fi

# ---------------------------------------------------------------------------
# Refused targets
# ---------------------------------------------------------------------------

begin_test "hosted_only: a publish queues a remote_probe job (introspection.jobs)"
publish_remote "${NS}/queued" 1.0.0 "https://queued.mcp.example.invalid/mcp"
if [ "$MCP_STATUS" != "200" ]; then
  fail "publish answered ${MCP_STATUS}: $(mcp_snip)"
else
  intro=$(caps_introspection "${NS}/queued" 1.0.0)
  if [ "$intro" = "hosted_only|true|remote:0" ]; then
    pass
  else
    fail "capabilities introspection remoteProbe|probeEnabled|jobs is '${intro}', expected 'hosted_only|true|remote:0'" "$(mcp_snip)"
  fi
fi

begin_test "A private-range remote is refused: the mock on ${MOCK_UPSTREAM_HOSTNAME} sees no request"
if [ "$REACHABLE" = "1" ]; then
  skip "AK_TEST_MCP_PROBE_REACHABLE=1 allows the runner CIDR; the loopback test below covers the refusal"
else
  before=$(mcp_http_count)
  publish_remote "${NS}/private" 1.0.0 "$MCP_HTTP_URL"
  sleep "$PROBE_QUIET_SECS"
  if [ "$MCP_STATUS" != "200" ]; then
    fail "publish answered ${MCP_STATUS}: $(mcp_snip)"
  elif [ "$(mcp_http_count)" != "$before" ]; then
    fail "the probe dialled a private address" "$(tail -n 5 "${MCP_HTTP_STATE_DIR}/request-log.txt")"
  else
    pass
  fi
fi

start_recorder loop
REC_loop_PORT="$REC_PORT"
REC_loop_DIR="$REC_DIR"
begin_test "A loopback remote is refused"
publish_remote "${NS}/loopback" 1.0.0 "http://127.0.0.1:${REC_loop_PORT}/mcp"
sleep "$PROBE_QUIET_SECS"
if [ "$MCP_STATUS" != "200" ]; then
  fail "publish answered ${MCP_STATUS}: $(mcp_snip)"
elif [ "$(rec_count "$REC_loop_DIR")" != "0" ]; then
  fail "the probe dialled loopback" "$(head -c 600 "${REC_loop_DIR}/log.jsonl")"
else
  pass
fi

# ---------------------------------------------------------------------------
# Positive leg and redirects (need a reachable worker)
# ---------------------------------------------------------------------------

start_recorder target
REC_target_PORT="$REC_PORT"
REC_target_DIR="$REC_DIR"
start_recorder final
REC_final_PORT="$REC_PORT"
REC_final_DIR="$REC_DIR"
start_recorder redir "http://$(mcp_mock_host):${REC_final_PORT}/mcp"
REC_redir_PORT="$REC_PORT"
REC_redir_DIR="$REC_DIR"

begin_test "hosted_only: the worker discovers tools, identifies itself, never calls a tool or sends publisher headers"
if [ "$REACHABLE" != "1" ]; then
  skip "AK_TEST_MCP_PROBE_REACHABLE not set: no introspector worker allowed to reach the runner's private address"
else
  publish_remote "${NS}/target" 1.0.0 "http://$(mcp_mock_host):${REC_target_PORT}/mcp"
  _listed() {
    jq -e 'select(.method == "tools/list")' "${REC_target_DIR}/log.jsonl" >/dev/null 2>&1
  }
  if [ "$MCP_STATUS" != "200" ]; then
    fail "publish answered ${MCP_STATUS}: $(mcp_snip)"
  elif ! wait_until "the worker calls tools/list" "$PROBE_WAIT_SECS" _listed; then
    fail "no tools/list from the worker within ${PROBE_WAIT_SECS}s" "$(head -c 800 "${REC_target_DIR}/log.jsonl")"
  else
    sleep 5
    log="${REC_target_DIR}/log.jsonl"
    first=$(jq -r 'select(.method != null) | .method' "$log" | head -1)
    calls=$(jq -r 'select(.method == "tools/call") | .method' "$log" | grep -c . || true)
    bad_ua=$(jq -r '.ua' "$log" | grep -vcE "$PROBE_UA_RE" || true)
    leaked=$(grep -ciF -e "$PUB_SECRET" -e "\"${PUB_HEADER}\"" "$log" || true)
    if [ "$first" != "server/discover" ] && [ "$first" != "initialize" ]; then
      fail "the worker's first JSON-RPC call was '${first}', expected server/discover or initialize"
    elif [ "$calls" != "0" ]; then
      fail "the worker called tools/call ${calls} time(s)"
    elif [ "$bad_ua" != "0" ]; then
      fail "${bad_ua} request(s) without an identifying User-Agent (${PROBE_UA_RE})" "$(jq -r '.ua' "$log" | sort -u)"
    elif [ "$leaked" != "0" ]; then
      fail "the worker sent the publisher header or its value"
    else
      pass
    fi
  fi
fi

begin_test "The worker does not follow a redirect"
if [ "$REACHABLE" != "1" ]; then
  skip "AK_TEST_MCP_PROBE_REACHABLE not set: no introspector worker allowed to reach the runner's private address"
else
  publish_remote "${NS}/redirect" 1.0.0 "http://$(mcp_mock_host):${REC_redir_PORT}/mcp"
  _redirected() {
    [ "$(rec_count "$REC_redir_DIR")" -gt 0 ]
  }
  if ! wait_until "the worker reaches the redirector" "$PROBE_WAIT_SECS" _redirected; then
    fail "the worker never reached the redirecting remote (positive leg prerequisite)"
  else
    sleep 10
    if [ "$(rec_count "$REC_final_DIR")" = "0" ]; then
      pass
    else
      fail "the worker followed a 302 to another host:port" "$(head -c 400 "${REC_final_DIR}/log.jsonl")"
    fi
  fi
fi

end_suite
