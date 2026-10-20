#!/usr/bin/env python3
# =============================================================================
# mock_scanner.py - a security-scanner stand-in whose /healthz can hang
# =============================================================================
# The readyz-hung-dependency tier (artifact-keeper#4781) points the backend's
# TRIVY_URL at this server. /readyz then probes GET <TRIVY_URL>/healthz through
# its per-dependency cache. The tier needs a dependency that HANGS (accepts the
# connection, reads the request, never answers), not one that refuses, and it
# needs to count how often the backend really probed it.
#
#   GET  /healthz            the probe the backend sends. Every hit is recorded
#                            with its arrival time. In mode "ok" it answers 200
#                            "ok". In mode "hang" it holds the request open and
#                            never answers until the client closes the
#                            connection (or 60 s pass, or the mode flips back
#                            to "ok"), and records how long the client waited
#                            before it gave up ("held").
#   POST /__mode?m=ok|hang   switch the mode. Not recorded.
#   GET  /__hits             {"now": t, "hits": [{"t": arrival, "held": s or
#                            null while still open, "mode": m}]}. Times are
#                            seconds on this container's monotonic clock; the
#                            oracle only ever compares them with "now".
#   GET  /__readyz           container healthcheck.
#
# "held" tells the backend's two probers apart: /readyz gives up at its 2 s
# deadline, while the periodic health monitor (every 60 s, same URL, same
# client builder) waits for its 5 s client timeout.
#
# Stdlib only, single file, stock python image. MOCK_PORT (default 80).
# =============================================================================
import json
import os
import select
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

PORT = int(os.environ.get("MOCK_PORT", "80"))
HANG_MAX_SECS = 60.0

LOCK = threading.Lock()
STATE = {"mode": "ok"}
HITS = []


def now():
    return time.monotonic()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        print("mock-scanner: " + (fmt % args), flush=True)

    def _send(self, code, data, ctype="text/plain"):
        if isinstance(data, str):
            data = data.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _client_gone(self):
        # Readable with zero bytes pending == the client closed its side.
        try:
            r, _, _ = select.select([self.connection], [], [], 0.05)
            if not r:
                return False
            return self.connection.recv(1, socket.MSG_PEEK) == b""
        except OSError:
            return True

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/__readyz":
            return self._send(200, "ok")
        if path == "/__hits":
            with LOCK:
                body = json.dumps({"now": now(), "mode": STATE["mode"], "hits": list(HITS)})
            return self._send(200, body, "application/json")
        if path != "/healthz":
            return self._send(404, "not found")

        with LOCK:
            mode = STATE["mode"]
            hit = {"t": now(), "held": None, "mode": mode}
            HITS.append(hit)
        if mode == "ok":
            hit["held"] = 0.0
            return self._send(200, "ok")

        # Hang: never answer while the client is still waiting.
        start = hit["t"]
        while True:
            if self._client_gone():
                with LOCK:
                    hit["held"] = now() - start
                self.close_connection = True
                return
            with LOCK:
                flipped = STATE["mode"] == "ok"
            if flipped or now() - start > HANG_MAX_SECS:
                with LOCK:
                    hit["held"] = now() - start
                try:
                    self._send(200, "ok")
                except OSError:
                    pass
                self.close_connection = True
                return

    def do_POST(self):
        u = urlsplit(self.path)
        if u.path != "/__mode":
            return self._send(404, "not found")
        m = parse_qs(u.query).get("m", [""])[0]
        if m not in ("ok", "hang"):
            return self._send(400, "m must be ok or hang")
        with LOCK:
            STATE["mode"] = m
        return self._send(200, m)


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


if __name__ == "__main__":
    print(f"mock-scanner: listening on :{PORT}", flush=True)
    Server(("0.0.0.0", PORT), Handler).serve_forever()
