#!/usr/bin/env python3
"""Steerable OTLP/HTTP sink plus an upload-your-own static upstream (stdlib only).

Used by the deps-1.12.0-controls and otlp-logs-metrics tiers
(profiles/telemetry.otlp-sink.yml).

OTLP side
  POST /v1/traces, POST /v1/metrics (any other POST path is counted the same way)
      Counts the request per path, keeps the last 200 bodies per path, answers
      200 with an empty body (an empty ExportTraceServiceRequest response), or
      the status set with /__mode.
Control side (host-published)
  GET  /__readyz                 -> "ok"
  GET  /__stats                  -> {"paths": {path: count}, "mode": int, "since_mode": {path: count}}
  POST /__mode?status=503        -> every OTLP POST answers that status (200 restores)
  GET  /__grep?needle=X          -> {"hits": number of kept bodies (any path) containing X}
  GET  /__grep?needle=X&path=/P  -> the same, counting only bodies POSTed to /P
  PUT  /__fx/<path>              -> store the request body, served as GET /<path>
                                    (query string ignored) with Content-Type from
                                    the X-Fx-Content-Type header
  GET  /<path>                   -> a stored fixture, or 404
"""
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

LOCK = threading.Lock()
COUNTS = {}
SINCE_MODE = {}
BODIES = {}
MODE = {"status": 200}
FIXTURES = {}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # keep container logs quiet
        pass

    def _send(self, code, body=b"", ctype="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n else b""

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path == "/__readyz":
            return self._send(200, b"ok", "text/plain")
        if u.path == "/__stats":
            with LOCK:
                doc = {"paths": dict(COUNTS), "mode": MODE["status"], "since_mode": dict(SINCE_MODE)}
            return self._send(200, json.dumps(doc).encode())
        if u.path == "/__grep":
            needle = q.get("needle", [""])[0].encode()
            only = q.get("path", [None])[0]
            with LOCK:
                hits = sum(
                    1
                    for path, bodies in BODIES.items()
                    if only is None or path == only
                    for b in bodies
                    if needle and needle in b
                )
            return self._send(200, json.dumps({"hits": hits}).encode())
        with LOCK:
            fx = FIXTURES.get(u.path)
        if fx is None:
            return self._send(404, b'{"error":"no fixture"}')
        return self._send(200, fx[0], fx[1])

    do_HEAD = do_GET

    def do_PUT(self):
        u = urlparse(self.path)
        body = self._body()
        if u.path.startswith("/__fx/"):
            ctype = self.headers.get("X-Fx-Content-Type") or "application/octet-stream"
            with LOCK:
                FIXTURES[u.path[len("/__fx"):]] = (body, ctype)
            return self._send(200, b'{"stored":true}')
        return self._send(404)

    def do_POST(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        body = self._body()
        if u.path == "/__mode":
            with LOCK:
                MODE["status"] = int(q.get("status", ["200"])[0])
                SINCE_MODE.clear()
            return self._send(200, json.dumps({"mode": MODE["status"]}).encode())
        with LOCK:
            COUNTS[u.path] = COUNTS.get(u.path, 0) + 1
            SINCE_MODE[u.path] = SINCE_MODE.get(u.path, 0) + 1
            kept = BODIES.setdefault(u.path, [])
            kept.append(body)
            del kept[:-200]
            status = MODE["status"]
        if status == 200:
            return self._send(200, b"", "application/x-protobuf")
        return self._send(status, b"unavailable", "text/plain")


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", int(os.environ.get("SINK_PORT", "80"))), Handler).serve_forever()
