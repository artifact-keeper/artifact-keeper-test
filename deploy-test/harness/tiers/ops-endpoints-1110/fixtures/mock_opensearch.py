#!/usr/bin/env python3
"""Minimal OpenSearch stand-in for the /readyz dependency gate (stdlib only).

Used through profiles/search.mock-opensearch.yml by ops-endpoints-1110.

It answers just enough of the REST API for the backend's startup and health
probe: HEAD /<index> -> 200 (indexes exist, nothing is created),
GET /_cluster/health -> {"status": "green"}, POST|GET /<index>/_count ->
{"count": 1} (not empty, so no bootstrap reindex), any other request -> 200 {}.

Mode file /tmp/os/mode (write it with docker exec):
  up    the behaviour above (default)
  down  every request answers 503 {"error": "dtf mock: down"}
Every request is appended to /tmp/os/requests.log as "<METHOD> <path> <status>".
"""
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

STATE = "/tmp/os"
MODE_FILE = os.path.join(STATE, "mode")
LOG_FILE = os.path.join(STATE, "requests.log")
LOCK = threading.Lock()


def mode():
    try:
        with open(MODE_FILE) as f:
            return f.read().strip() or "up"
    except OSError:
        return "up"


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def _answer(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n:
            self.rfile.read(n)
        path = self.path.split("?", 1)[0]
        if path == "/__readyz":
            code, doc = 200, None
            body = b"ok"
        elif mode() == "down":
            code, doc = 503, {"error": "dtf mock: down"}
        elif path == "/_cluster/health":
            code, doc = 200, {"cluster_name": "dtf-mock", "status": "green"}
        elif path.endswith("/_count"):
            code, doc = 200, {"count": 1}
        elif path.endswith("/_search"):
            code, doc = 200, {"took": 1, "hits": {"total": {"value": 0, "relation": "eq"}, "hits": []}}
        else:
            code, doc = 200, {}
        if doc is not None:
            body = json.dumps(doc).encode()
        if path != "/__readyz":
            with LOCK:
                with open(LOG_FILE, "a") as f:
                    f.write("%s %s %d\n" % (self.command, path, code))
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    do_GET = do_POST = do_PUT = do_HEAD = do_DELETE = _answer


if __name__ == "__main__":
    os.makedirs(STATE, exist_ok=True)
    ThreadingHTTPServer(("0.0.0.0", 9200), Handler).serve_forever()
