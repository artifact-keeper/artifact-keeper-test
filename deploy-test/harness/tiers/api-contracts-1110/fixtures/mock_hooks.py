#!/usr/bin/env python3
# =============================================================================
# mock_hooks.py - a webhook receiver that is also a counting static upstream
# =============================================================================
# One stdlib HTTP server for tiers that need to see exactly what the backend
# sent: webhook deliveries (method, path, every header, the raw body) and
# upstream fetches (how many requests reached a path).
#
#   POST /hook/<name>     record the request, answer 200 {"ok": true}
#   GET/HEAD /up/<path>   record the request, answer 200 with deterministic
#                         bytes ("upstream:<path>\n"); /up/missing/... is 404
#   GET  /__log           every recorded request as a JSON array:
#                         {"method", "path", "headers": {lower-case: value},
#                          "body_b64"}
#   POST /__reset         forget every recorded request
#   GET  /__readyz        container healthcheck ("ok")
#
# Control paths (/__*) are never recorded. Stdlib only, single file, stock
# python image.
# =============================================================================
import base64
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("MOCK_PORT", "80"))
LOCK = threading.Lock()
LOG = []


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # quiet
        pass

    def _send(self, code, body, ctype="application/json", head=False):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if not head:
            self.wfile.write(body)

    def _record(self, body=b""):
        entry = {
            "method": self.command,
            "path": self.path,
            "headers": {k.lower(): v for k, v in self.headers.items()},
            "body_b64": base64.b64encode(body).decode(),
        }
        with LOCK:
            LOG.append(entry)

    def _read_body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n > 0 else b""

    def _up(self, head):
        self._record()
        if self.path.startswith("/up/missing/"):
            return self._send(404, b"not found\n", "text/plain", head)
        return self._send(200, ("upstream:%s\n" % self.path[4:]).encode(),
                          "application/octet-stream", head)

    def do_GET(self):  # noqa: N802
        if self.path == "/__readyz":
            return self._send(200, b"ok", "text/plain")
        if self.path == "/__log":
            with LOCK:
                data = json.dumps(LOG).encode()
            return self._send(200, data)
        if self.path.startswith("/up/"):
            return self._up(False)
        return self._send(404, b'{"error":"no route"}')

    def do_HEAD(self):  # noqa: N802
        if self.path.startswith("/up/"):
            return self._up(True)
        return self._send(404, b"", head=True)

    def do_POST(self):  # noqa: N802
        body = self._read_body()
        if self.path == "/__reset":
            with LOCK:
                LOG.clear()
            return self._send(200, b'{"ok":true}')
        self._record(body)
        return self._send(200, b'{"ok":true}')

    def do_PUT(self):  # noqa: N802
        self._record(self._read_body())
        return self._send(200, b'{"ok":true}')


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
