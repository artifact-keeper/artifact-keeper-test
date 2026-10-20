#!/usr/bin/env python3
# =============================================================================
# mock_files.py - an upstream whose files the oracle writes at run time
# =============================================================================
# The proxy accounting tiers (proxy-download-ledger, proxy-cache-ttl-and-refill)
# drive Remote repositories of several formats (generic, Maven, npm, Go, Cargo)
# against an upstream whose exact bytes and request counts they know. Rather
# than one mock per format, this server holds an in-memory file table that the
# oracle fills over a control API before it creates the Remote, so a packument,
# a Go @v/list or a crate tarball is just a file at the path that format's
# client protocol asks for.
#
#   PUT  /__file?path=<p>[&ctype=<t>]  store the request body at <p> (an
#                                      absolute URL path, query not included).
#                                      Replaces any previous body; the ETag is
#                                      derived from the bytes, so new bytes
#                                      mean a new validator.
#   POST /__delay?path=<p>&ms=<n>      hold every GET of <p> n ms before the
#                                      status line (0 clears).
#   GET  /__requests?path=<p>          {"path", "get", "head", "conditional"}:
#                                      requests seen for <p> (any status).
#   GET  /__log                        every request seen, one per line:
#                                      "<METHOD> <path> <status>".
#   GET  /__readyz                     container healthcheck.
#
#   GET/HEAD <p>                       the stored body (200, honest
#                                      Content-Length, ETag), 304 when
#                                      If-None-Match carries the current ETag,
#                                      404 when nothing is stored at <p>.
#
# Every non-control request is counted and logged, whatever it answered, so an
# oracle can tell "the backend asked upstream" from "the backend served from
# its cache" for any path.
#
# Stdlib only, single file, stock python image. MOCK_PORT (default 80).
# =============================================================================
import hashlib
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

PORT = int(os.environ.get("MOCK_PORT", "80"))

LOCK = threading.Lock()
FILES = {}    # path -> (body, ctype, etag)
DELAYS = {}   # path -> ms
COUNTS = {}   # path -> {"get": n, "head": n, "conditional": n}
LOG = []


def etag_of(body):
    return '"' + hashlib.sha256(body).hexdigest()[:24] + '"'


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def _send(self, code, data, ctype="application/octet-stream", extra=None, head=False):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if not head and code != 304:
            self.wfile.write(data)

    def _json(self, code, obj):
        self._send(code, json.dumps(obj).encode(), "application/json")

    def _serve(self, head):
        url = urlsplit(self.path)
        p = url.path
        conditional = self.headers.get("If-None-Match") is not None or \
            self.headers.get("If-Modified-Since") is not None
        with LOCK:
            c = COUNTS.setdefault(p, {"get": 0, "head": 0, "conditional": 0})
            c["head" if head else "get"] += 1
            if conditional:
                c["conditional"] += 1
            entry = FILES.get(p)
            delay = DELAYS.get(p, 0)
        if delay and not head:
            time.sleep(delay / 1000.0)
        if entry is None:
            code = 404
            self._send(404, b'{"errors":[{"detail":"not found"}]}', "application/json", head=head)
        else:
            body, ctype, etag = entry
            inm = self.headers.get("If-None-Match")
            if inm is not None and etag in [t.strip() for t in inm.split(",")]:
                code = 304
                self.send_response(304)
                self.send_header("ETag", etag)
                self.send_header("Content-Length", "0")
                self.end_headers()
            else:
                code = 200
                self._send(200, body, ctype, {"ETag": etag}, head=head)
        with LOCK:
            LOG.append(f"{self.command} {p} {code}")

    def do_HEAD(self):  # noqa: N802
        self._serve(True)

    def do_GET(self):  # noqa: N802
        url = urlsplit(self.path)
        q = parse_qs(url.query)
        if url.path == "/__readyz":
            return self._send(200, b"ok", "text/plain")
        if url.path == "/__requests":
            p = q.get("path", [""])[0]
            with LOCK:
                c = dict(COUNTS.get(p, {"get": 0, "head": 0, "conditional": 0}))
            c["path"] = p
            return self._json(200, c)
        if url.path == "/__log":
            with LOCK:
                data = ("\n".join(LOG) + "\n").encode()
            return self._send(200, data, "text/plain")
        return self._serve(False)

    def do_PUT(self):  # noqa: N802
        url = urlsplit(self.path)
        q = parse_qs(url.query)
        if url.path != "/__file":
            return self._json(405, {"error": "PUT only on /__file"})
        p = q.get("path", [""])[0]
        if not p.startswith("/") or p.startswith("/__"):
            return self._json(400, {"error": "path must be absolute and not a control path"})
        n = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(n) if n else b""
        ctype = q.get("ctype", ["application/octet-stream"])[0]
        etag = etag_of(body)
        with LOCK:
            FILES[p] = (body, ctype, etag)
        return self._json(200, {"path": p, "bytes": len(body), "etag": etag})

    def do_POST(self):  # noqa: N802
        url = urlsplit(self.path)
        q = parse_qs(url.query)
        if url.path == "/__delay":
            p = q.get("path", [""])[0]
            ms = int(q.get("ms", ["0"])[0])
            with LOCK:
                DELAYS[p] = ms
            return self._json(200, {"path": p, "ms": ms})
        return self._json(404, {"error": "unknown control endpoint"})


if __name__ == "__main__":
    ThreadingHTTPServer.daemon_threads = True
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
