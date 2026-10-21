#!/usr/bin/env python3
# =============================================================================
# mock_cred_upstream.py -- a static upstream that records who asked for what
# =============================================================================
# The upstream-url-userinfo-redaction tier runs two copies of this script
# (mock-up-a and mock-up-b) so it can tell which upstream a Remote actually
# fetched from after a PATCH of its upstream_url (#4467), and confirm the
# credentials embedded in the URL still reach the upstream as HTTP Basic auth
# (the write side of #4452 is unchanged on purpose).
#
#   GET/HEAD /f/<name>   200, a small deterministic text body naming the host
#                        and the path. Counted per path.
#   GET /__requests      {"total": n, "paths": {...}, "auth": [...]} every
#                        counted request and the Authorization header it
#                        carried ("NONE" when absent). Not counted.
#   GET /__readyz        container healthcheck.
#   anything else        404.
#
# Every counted request also prints one line to stdout:
#     RECV <METHOD> <PATH> AUTH=<header or NONE>
#
# Stdlib only, single file, stock python image.
#   MOCK_PORT   listen port (default 80)
#   MOCK_NAME   label written into each body (default the hostname)
# =============================================================================
import json
import os
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

PORT = int(os.environ.get("MOCK_PORT", "80"))
NAME = os.environ.get("MOCK_NAME", socket.gethostname())

LOCK = threading.Lock()
PATHS = {}
AUTH = []


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def _send(self, code, data, ctype="application/octet-stream", head=False):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if not head:
            self.wfile.write(data)

    def _count(self, path):
        auth = self.headers.get("Authorization", "NONE")
        with LOCK:
            PATHS[path] = PATHS.get(path, 0) + 1
            AUTH.append({"method": self.command, "path": path, "auth": auth})
        print("RECV {} {} AUTH={}".format(self.command, path, auth), flush=True)

    def _handle(self, head):
        path = urlsplit(self.path).path
        if path == "/__readyz":
            return self._send(200, b"ok", "text/plain", head)
        if path == "/__requests":
            with LOCK:
                body = {"total": sum(PATHS.values()), "paths": dict(PATHS), "auth": list(AUTH)}
            return self._send(200, json.dumps(body).encode(), "application/json", head)
        if path.startswith("/f/"):
            self._count(path)
            return self._send(200, "{} served {}\n".format(NAME, path).encode(), head=head)
        return self._send(404, b"not found", "text/plain", head)

    def do_GET(self):
        self._handle(False)

    def do_HEAD(self):
        self._handle(True)


if __name__ == "__main__":
    ThreadingHTTPServer.daemon_threads = True
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
