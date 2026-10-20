#!/usr/bin/env python3
# =============================================================================
# mock_bsr.py - a steerable Buf Schema Registry (BSR) Connect upstream
# =============================================================================
# The protobuf-bsr-proxy tier (artifact-keeper#4284, PR #4276) drives AK's
# reverse proxy for allowlisted buf.registry.module.v1 Connect reads against an
# upstream whose answers, request count and received headers it controls. A
# real BSR offers none of that.
#
#   POST <prefix>/<Service>/<Method>
#       A Connect unary call. <prefix> is any path (one per remote repository
#       in the tier, so cases never share a counter). Counted per full path;
#       the request headers are recorded per path. Answered per the path's
#       MODE (default ok):
#         ok      200 application/json with a canned body naming the method,
#                 plus `connect-mock-trace` (must be relayed) and
#                 `X-Upstream-Secret` / `Set-Cookie` (must NOT be relayed)
#         err500  500 whose body carries SECRET_BODY (must NOT be relayed)
#         err404  404 Connect not_found whose message carries SECRET_BODY
#         big     200 with a BIG_BYTES body (over AK's 16 MiB cap)
#         stall   sleep STALL_SECS, then answer ok (past AK's 60 s timeout)
#         reset   read the request and close the socket with no response
#   POST /__mode?path=&mode=   set a path's mode. Not counted.
#   GET  /__requests?path=     {"path":..., "count": n}
#   GET  /__headers?path=      the lower-cased request headers of the last
#                              call to path, as a JSON object
#   GET  /__readyz             healthcheck
#
# Stdlib only, single file, stock python image.
#   MOCK_PORT        listen port (default 80)
#   MOCK_STALL_SECS  stall duration (default 75)
#   MOCK_BIG_BYTES   size of the `big` body (default 17 MiB)
# =============================================================================
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

PORT = int(os.environ.get("MOCK_PORT", "80"))
STALL_SECS = int(os.environ.get("MOCK_STALL_SECS", "75"))
BIG_BYTES = int(os.environ.get("MOCK_BIG_BYTES", str(17 * 1024 * 1024)))
SECRET_BODY = "MOCK-BSR-UPSTREAM-BODY-dbpass=hunter2-trace-at-internal.bsr.example"
UPSTREAM_SECRET_HEADER = "mock-upstream-secret-7c1e"
MODES_ALLOWED = ("ok", "err500", "err404", "big", "stall", "reset")

LOCK = threading.Lock()
COUNTS = {}
MODES = {}
HEADERS = {}


def canned(service, method):
    if method == "ListModules":
        return {"modules": [{"id": "mockmod-0001", "name": "mockmod", "ownerId": "mockowner"}],
                "nextPageToken": "", "servedBy": "mock-bsr", "rpc": f"{service}/{method}"}
    if method == "ListLabels":
        return {"labels": [{"id": "mocklabel-0001", "name": "main"}],
                "nextPageToken": "", "servedBy": "mock-bsr", "rpc": f"{service}/{method}"}
    return {"servedBy": "mock-bsr", "rpc": f"{service}/{method}"}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        print("mock-bsr: " + (fmt % args), flush=True)

    def _send(self, code, data, ctype="application/json", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _json(self, code, obj, extra=None):
        self._send(code, json.dumps(obj).encode(), "application/json", extra)

    def do_GET(self):
        url = urlsplit(self.path)
        q = parse_qs(url.query)
        p = q.get("path", [""])[0]
        if url.path == "/__readyz":
            return self._send(200, b"ok", "text/plain")
        if url.path == "/__requests":
            with LOCK:
                n = COUNTS.get(p, 0)
            return self._json(200, {"path": p, "count": n})
        if url.path == "/__headers":
            with LOCK:
                h = HEADERS.get(p, {})
            return self._json(200, h)
        return self._send(404, b"not found", "text/plain")

    def do_POST(self):
        url = urlsplit(self.path)
        q = parse_qs(url.query)
        if url.path == "/__mode":
            p = q.get("path", [""])[0]
            m = q.get("mode", ["ok"])[0]
            if m not in MODES_ALLOWED or not p.startswith("/"):
                return self._json(400, {"error": "bad path or mode"})
            with LOCK:
                MODES[p] = m
            return self._json(200, {"path": p, "mode": m})

        length = int(self.headers.get("Content-Length", "0") or "0")
        if length:
            self.rfile.read(length)
        parts = url.path.rstrip("/").split("/")
        if len(parts) < 3 or not parts[-2].startswith("buf.registry."):
            return self._send(404, b"not a connect path", "text/plain")
        service, method = parts[-2], parts[-1]
        with LOCK:
            COUNTS[url.path] = COUNTS.get(url.path, 0) + 1
            HEADERS[url.path] = {k.lower(): v for k, v in self.headers.items()}
            mode = MODES.get(url.path, "ok")

        if mode == "reset":
            self.close_connection = True
            try:
                self.connection.shutdown(2)
            except OSError:
                pass
            return None
        if mode == "err500":
            return self._send(500, f"internal error: {SECRET_BODY}".encode(), "text/plain",
                              {"X-Upstream-Secret": UPSTREAM_SECRET_HEADER})
        if mode == "err404":
            return self._json(404, {"code": "not_found", "message": f"no such module ({SECRET_BODY})"},
                              {"X-Upstream-Secret": UPSTREAM_SECRET_HEADER})
        if mode == "big":
            return self._send(200, b"x" * BIG_BYTES, "application/json")
        if mode == "stall":
            time.sleep(STALL_SECS)
        return self._json(200, canned(service, method), {
            "connect-mock-trace": "mock-trace-1",
            "X-Upstream-Secret": UPSTREAM_SECRET_HEADER,
            "Set-Cookie": "bsr_session=mock-session-cookie; Path=/",
        })


if __name__ == "__main__":
    ThreadingHTTPServer.daemon_threads = True
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
