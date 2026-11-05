#!/usr/bin/env python3
"""mock-mcp-http-server.py - stdlib MCP server over streamable HTTP.

The `remotes[]` target of the release-gate MCP tests. It exposes the same
single `echo` tool as tests/fixtures/mcp/echo-server, at POST /mcp, and logs
every request so a test can prove who called it: Artifact Keeper must never
dereference a `remotes[].url` (or `websiteUrl`, `icons[].src`,
`repository.url`), so every request in the log should come from the test's
own client (User-Agent `ak-e2e-mcp-client/1`).

Environment:
  MCP_HTTP_STATE_DIR   required; written to:
                         request-log.txt      "<ts> <client-ip> <METHOD> <path> ua=<user-agent>"
                         request-count        total requests (excluding /__readyz)
                         foreign-count        requests whose User-Agent is not the test client's
  MCP_HTTP_PORT        required; binds 0.0.0.0:<port>
  MCP_HTTP_SSE         optional "1": answer requests with a one-event SSE stream
                       instead of a JSON body (both are valid streamable HTTP)

Routes:
  GET  /__readyz       readiness, not logged or counted
  POST /mcp            JSON-RPC (initialize, notifications/*, ping, tools/list, tools/call)
  anything else        404, logged and counted (a probe of any URL path is visible)
"""

import http.server
import json
import os
import sys
import threading
import time
import uuid
from pathlib import Path

STATE = os.environ.get("MCP_HTTP_STATE_DIR")
PORT = os.environ.get("MCP_HTTP_PORT")
if not STATE or not PORT:
    sys.stderr.write("mock-mcp-http-server: MCP_HTTP_STATE_DIR and MCP_HTTP_PORT are required\n")
    sys.exit(2)
STATE_DIR = Path(STATE)
STATE_DIR.mkdir(parents=True, exist_ok=True)
SSE = os.environ.get("MCP_HTTP_SSE") == "1"
CLIENT_UA = "ak-e2e-mcp-client/1"
LOCK = threading.Lock()
SESSIONS = set()

TOOLS = [
    {
        "name": "echo",
        "description": "Return the text argument unchanged.",
        "inputSchema": {
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "required": ["text"],
        },
    }
]


def bump(name):
    path = STATE_DIR / name
    try:
        n = int(path.read_text().strip() or "0")
    except (FileNotFoundError, ValueError):
        n = 0
    tmp = path.with_suffix(".tmp")
    tmp.write_text(str(n + 1))
    os.replace(tmp, path)


def record(handler):
    ua = handler.headers.get("User-Agent", "-")
    line = "%d %s %s %s ua=%s\n" % (int(time.time()), handler.client_address[0], handler.command, handler.path, ua)
    with LOCK:
        with open(STATE_DIR / "request-log.txt", "a", encoding="utf-8") as fh:
            fh.write(line)
        bump("request-count")
        if ua != CLIENT_UA:
            bump("foreign-count")


def answer(msg):
    method = msg.get("method")
    mid = msg.get("id")
    params = msg.get("params") or {}
    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": mid,
            "result": {
                "protocolVersion": params.get("protocolVersion") or "2025-06-18",
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "ak-e2e-echo-http", "version": "1.0.0"},
            },
        }
    if method == "ping":
        return {"jsonrpc": "2.0", "id": mid, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": mid, "result": {"tools": TOOLS}}
    if method == "tools/call":
        if params.get("name") != "echo":
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": "unknown tool"}}
        text = (params.get("arguments") or {}).get("text")
        return {
            "jsonrpc": "2.0",
            "id": mid,
            "result": {"content": [{"type": "text", "text": str(text)}], "isError": False},
        }
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "Method not found"}}


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def _send(self, status, body=b"", ctype="application/json", headers=None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        if self.path == "/__readyz":
            self._send(200, b"ok", "text/plain")
            return
        record(self)
        self._send(404, b"not found", "text/plain")

    def do_HEAD(self):
        record(self)
        self._send(404)

    def do_DELETE(self):
        record(self)
        sid = self.headers.get("Mcp-Session-Id")
        with LOCK:
            SESSIONS.discard(sid)
        self._send(200)

    def do_POST(self):
        record(self)
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        if self.path.split("?", 1)[0] != "/mcp":
            self._send(404, b"not found", "text/plain")
            return
        try:
            msg = json.loads(raw.decode("utf-8"))
        except ValueError:
            self._send(400, json.dumps({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}}).encode())
            return
        if not isinstance(msg, dict):
            self._send(400, b'{"error":"batch not supported"}')
            return
        extra = {}
        if msg.get("method") == "initialize":
            sid = uuid.uuid4().hex
            with LOCK:
                SESSIONS.add(sid)
            extra["Mcp-Session-Id"] = sid
        elif self.headers.get("Mcp-Session-Id") not in SESSIONS:
            self._send(404, b'{"error":"unknown session"}')
            return
        if "id" not in msg:
            self._send(202, headers=extra)
            return
        reply = json.dumps(answer(msg)).encode("utf-8")
        if SSE:
            body = b"event: message\ndata: " + reply + b"\n\n"
            self._send(200, body, "text/event-stream", extra)
        else:
            self._send(200, reply, "application/json", extra)


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


if __name__ == "__main__":
    Server(("0.0.0.0", int(PORT)), Handler).serve_forever()
