#!/usr/bin/env python3
# =============================================================================
# web_standin.py - stands in for the web UI container behind the stock Caddy
# =============================================================================
# The stock docker/Caddyfile sends every path it does not route to the
# backend on to `web:3000`, where the Next.js UI answers an HTML 404 for an
# unknown path. This stand-in answers every request the same way and marks
# it, so the oracle can tell "Caddy routed this to the web UI" from "Caddy
# routed this to the backend":
#   any method, any path -> 404 text/html "<html>dtf-web-standin ...</html>"
#                           with header X-DTF-Upstream: web
#   GET /__readyz        -> 200 "ok" (container healthcheck)
# Stdlib only, single file, stock python image.
# =============================================================================
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("MOCK_PORT", "3000"))


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def _answer(self, head=False):
        if self.path == "/__readyz":
            body, code, ctype = b"ok", 200, "text/plain"
        else:
            body = ("<html><body>dtf-web-standin 404 %s</body></html>" % self.path).encode()
            code, ctype = 404, "text/html; charset=utf-8"
        n = int(self.headers.get("Content-Length") or 0)
        if n:
            self.rfile.read(n)
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-DTF-Upstream", "web")
        self.end_headers()
        if not head:
            self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        self._answer()

    def do_HEAD(self):  # noqa: N802
        self._answer(head=True)

    def do_POST(self):  # noqa: N802
        self._answer()

    def do_PUT(self):  # noqa: N802
        self._answer()


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
