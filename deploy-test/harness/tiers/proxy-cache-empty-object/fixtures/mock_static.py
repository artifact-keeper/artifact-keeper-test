#!/usr/bin/env python3
# =============================================================================
# mock_static.py — a steerable static-file upstream for a Remote repository
# =============================================================================
# The proxy-cache-empty-object tier (artifact-keeper#4630) needs an upstream
# whose bytes it knows exactly, whose request count it can read back, and which
# it can make lie about a body on demand. A real registry offers none of that.
#
#   GET  /f/<name>              the artifact. Deterministic bytes derived from
#                               <name>, MOCK_FILE_BYTES long. Counted per path.
#                               Served according to the path's current MODE:
#                                 ok     full body, honest Content-Length
#                                 empty  Content-Length: N, then NO body, close
#                                 short  Content-Length: N, half the body, close
#   POST /__mode?path=&mode=    set a path's mode (default ok). Not counted.
#   GET  /__requests?path=      {"path": ..., "count": n} GETs seen for path.
#   GET  /__golden/<name>       the exact bytes /f/<name> serves in mode ok.
#                               Not counted (the oracle's reference copy).
#   GET  /__readyz              container healthcheck.
#
# The empty/short modes are a truthful protocol violation (the server promises
# N bytes and closes early), so the client side sees an incomplete body, not a
# well-formed short response.
#
# Stdlib only, single file, stock python image.
#   MOCK_PORT        listen port (default 80)
#   MOCK_FILE_BYTES  bytes per artifact (default 262144)
# =============================================================================
import hashlib
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

PORT = int(os.environ.get("MOCK_PORT", "80"))
FILE_BYTES = int(os.environ.get("MOCK_FILE_BYTES", "262144"))

LOCK = threading.Lock()
COUNTS = {}
MODES = {}


def body_for(name):
    out = bytearray()
    i = 0
    while len(out) < FILE_BYTES:
        out += hashlib.sha256(f"{name}:{i}".encode()).digest()
        i += 1
    return bytes(out[:FILE_BYTES])


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # quiet, but keep a trace in docker logs
        print("mock-static: " + (fmt % args), flush=True)

    def _send(self, code, data, ctype="application/octet-stream"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _json(self, code, obj):
        self._send(code, json.dumps(obj).encode(), "application/json")

    def do_GET(self):
        url = urlsplit(self.path)
        q = parse_qs(url.query)
        if url.path == "/__readyz":
            return self._send(200, b"ok", "text/plain")
        if url.path == "/__requests":
            p = q.get("path", [""])[0]
            with LOCK:
                n = COUNTS.get(p, 0)
            return self._json(200, {"path": p, "count": n})
        if url.path.startswith("/__golden/"):
            return self._send(200, body_for(url.path[len("/__golden/"):]))
        if url.path.startswith("/f/"):
            name = url.path[len("/f/"):]
            with LOCK:
                COUNTS[url.path] = COUNTS.get(url.path, 0) + 1
                mode = MODES.get(url.path, "ok")
            data = body_for(name)
            if mode == "ok":
                return self._send(200, data)
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Connection", "close")
            self.end_headers()
            if mode == "short":
                self.wfile.write(data[: len(data) // 2])
            self.wfile.flush()
            self.close_connection = True
            return None
        return self._send(404, b"not found", "text/plain")

    def do_HEAD(self):
        url = urlsplit(self.path)
        if url.path.startswith("/f/"):
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(FILE_BYTES))
            self.end_headers()
            return None
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()
        return None

    def do_POST(self):
        url = urlsplit(self.path)
        q = parse_qs(url.query)
        if url.path == "/__mode":
            p = q.get("path", [""])[0]
            m = q.get("mode", ["ok"])[0]
            if m not in ("ok", "empty", "short") or not p.startswith("/f/"):
                return self._json(400, {"error": "bad path or mode"})
            with LOCK:
                MODES[p] = m
            return self._json(200, {"path": p, "mode": m})
        return self._send(404, b"not found", "text/plain")


if __name__ == "__main__":
    ThreadingHTTPServer.daemon_threads = True
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
