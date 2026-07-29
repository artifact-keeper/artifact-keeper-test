#!/usr/bin/env python3
"""Mock upstream that answers every artifact fetch with a non-2xx status.

Tier: redact-userinfo-leak (#2926). AK's proxy renders a client-facing
diagnostic error body (a 5xx from `validate_upstream_status`) when an upstream
returns a server error. This mock guarantees that path is taken: every request
that is not the readiness probe returns HTTP 500 with a short body, so AK builds
its "Upstream returned error status 500: <url>" message. Pre-fix that <url>
still carries the `user:password@` userinfo copied verbatim from the configured
`upstream_url`; the fix redacts it.

Stdlib only (no pip install), mirroring fixtures/mock_pypi.py. Binds 0.0.0.0:80
inside its own container on the slot's private 172.16/12 subnet.
"""
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("MOCK_PORT", "80"))


class Handler(BaseHTTPRequestHandler):
    def _readyz(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok")

    def _fail(self):
        # A real, parseable 5xx so AK's `validate_upstream_status` folds it into
        # a ServiceUnavailable diagnostic that echoes the upstream URL.
        body = b"upstream is intentionally broken for the redact-userinfo-leak tier\n"
        self.send_response(500)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/__readyz":
            self._readyz()
        else:
            self._fail()

    # HEAD is used by some proxy pre-flights; keep it consistent.
    def do_HEAD(self):
        if self.path == "/__readyz":
            self.send_response(200)
            self.end_headers()
        else:
            self.send_response(500)
            self.end_headers()

    def log_message(self, *args):  # keep container logs quiet
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
