#!/usr/bin/env python3
# =============================================================================
# mock_adapter.py - a scanner-adapter stand-in that only answers its probes
# =============================================================================
# The health-monitor-dependencies tier (artifact-keeper#5651) points the
# backend's TRIVY_ADAPTER_URL at this server so the health monitor has an
# adapter to probe. The oracle stops and starts the container to stand in for
# an evicted adapter pod; it never scans.
#
#   GET /probe/healthy   200 "ok" (the probe the monitor sends). Hits counted.
#   GET /probe/ready     200 "ok"
#   GET /__hits          {"probe_healthy": n}
#   GET /__readyz        container healthcheck
#
# Stdlib only, single file, stock python image. MOCK_PORT (default 80).
# =============================================================================
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

PORT = int(os.environ.get("MOCK_PORT", "80"))
LOCK = threading.Lock()
HITS = {"probe_healthy": 0}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        print("mock-adapter: " + (fmt % args), flush=True)

    def _send(self, code, data, ctype="text/plain"):
        if isinstance(data, str):
            data = data.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/probe/healthy":
            with LOCK:
                HITS["probe_healthy"] += 1
            return self._send(200, "ok")
        if path in ("/probe/ready", "/__readyz"):
            return self._send(200, "ok")
        if path == "/__hits":
            with LOCK:
                body = json.dumps(HITS)
            return self._send(200, body, "application/json")
        return self._send(404, "not found")


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


if __name__ == "__main__":
    print(f"mock-adapter: listening on :{PORT}", flush=True)
    Server(("0.0.0.0", PORT), Handler).serve_forever()
