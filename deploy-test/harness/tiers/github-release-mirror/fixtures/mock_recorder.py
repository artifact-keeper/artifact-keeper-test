#!/usr/bin/env python3
# =============================================================================
# mock_recorder.py - a two-origin upstream that records who sent what
# =============================================================================
# The github-release-mirror tier (artifact-keeper#3656, #3657, #3658) needs an
# upstream that answers a release download with a cross-origin redirect, the
# way github.com hands a release asset to objects.githubusercontent.com, and
# that records, per request, whether an Authorization header arrived. The
# vscode-gallery-protocol tier reuses it as a mock Open VSX gallery, which
# needs a canned answer to a POST (extensionquery). A run-time file table, as
# in mock_files.py, covers both.
#
# The server listens on every port in MOCK_PORTS (default "80,81"). All ports
# share one table, so a redirect from :80 to :81 is a hop to a second ORIGIN
# (same host, different port: reqwest treats that as cross-origin) that the
# oracle can still observe.
#
#   PUT  /__file?path=<p>[&ctype=<t>][&status=<n>][&location=<url>]
#            store the request body as the answer at <p> (an absolute URL
#            path; the query string of a served request is not part of the
#            match). status defaults to 200; with location the answer is a
#            redirect carrying that Location header. The ETag is derived from
#            the bytes, so new bytes mean a new validator.
#   GET  /__requests?path=<p>
#            {"path", "get", "head", "post", "conditional", "with_auth",
#             "without_auth", "auth_values": [...]}: requests seen for <p> on
#            any port, whatever they answered.
#   GET  /__log
#            every request, one per line:
#            "<port> <METHOD> <path?query> <status> auth=<value or ->"
#   GET  /__readyz
#            container healthcheck.
#
#   GET/HEAD/POST <p>
#            the stored answer (honest Content-Length, ETag); 304 when
#            If-None-Match carries the current ETag; 404 when nothing is
#            stored at <p>. A POST body is read and discarded.
#
# Stdlib only, single file, stock python image.
# =============================================================================
import hashlib
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

PORTS = [int(p) for p in os.environ.get("MOCK_PORTS", "80,81").split(",") if p.strip()]

LOCK = threading.Lock()
FILES = {}    # path -> (body, ctype, etag, status, location)
COUNTS = {}   # path -> counters
LOG = []


def etag_of(body):
    return '"' + hashlib.sha256(body).hexdigest()[:24] + '"'


def blank_counts():
    return {"get": 0, "head": 0, "post": 0, "conditional": 0,
            "with_auth": 0, "without_auth": 0, "auth_values": []}


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

    def _serve(self, method):
        url = urlsplit(self.path)
        p = url.path
        if method == "POST":
            n = int(self.headers.get("Content-Length", "0") or "0")
            if n:
                self.rfile.read(n)
        auth = self.headers.get("Authorization")
        inm = self.headers.get("If-None-Match")
        conditional = inm is not None or self.headers.get("If-Modified-Since") is not None
        with LOCK:
            c = COUNTS.setdefault(p, blank_counts())
            c[method.lower()] += 1
            if conditional:
                c["conditional"] += 1
            if auth is None:
                c["without_auth"] += 1
            else:
                c["with_auth"] += 1
                c["auth_values"].append(auth)
            entry = FILES.get(p)
        head = method == "HEAD"
        if entry is None:
            code = 404
            self._send(404, b'{"message":"Not Found"}', "application/json", head=head)
        else:
            body, ctype, etag, status, location = entry
            if location:
                code = status
                self._send(status, b"", "text/plain", {"Location": location}, head=head)
            elif inm is not None and etag in [t.strip() for t in inm.split(",")]:
                code = 304
                self.send_response(304)
                self.send_header("ETag", etag)
                self.send_header("Content-Length", "0")
                self.end_headers()
            else:
                code = status
                self._send(status, body, ctype, {"ETag": etag} if status == 200 else None, head=head)
        with LOCK:
            LOG.append(f"{self.server.server_address[1]} {method} {self.path} {code} auth={auth or '-'}")

    def do_HEAD(self):  # noqa: N802
        self._serve("HEAD")

    def do_POST(self):  # noqa: N802
        self._serve("POST")

    def do_GET(self):  # noqa: N802
        url = urlsplit(self.path)
        q = parse_qs(url.query)
        if url.path == "/__readyz":
            return self._send(200, b"ok", "text/plain")
        if url.path == "/__requests":
            p = q.get("path", [""])[0]
            with LOCK:
                c = json.loads(json.dumps(COUNTS.get(p, blank_counts())))
            c["path"] = p
            return self._json(200, c)
        if url.path == "/__log":
            with LOCK:
                data = ("\n".join(LOG) + "\n").encode()
            return self._send(200, data, "text/plain")
        return self._serve("GET")

    def do_PUT(self):  # noqa: N802
        url = urlsplit(self.path)
        q = parse_qs(url.query)
        if url.path != "/__file":
            return self._json(405, {"error": "PUT only on /__file"})
        p = q.get("path", [""])[0]
        if not p.startswith("/") or p.startswith("/__"):
            return self._json(400, {"error": "path must be absolute and not a control path"})
        n = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(n) if n else b""
        ctype = q.get("ctype", ["application/octet-stream"])[0]
        status = int(q.get("status", ["302" if q.get("location") else "200"])[0])
        location = q.get("location", [""])[0]
        etag = etag_of(body)
        with LOCK:
            FILES[p] = (body, ctype, etag, status, location)
        return self._json(200, {"path": p, "bytes": len(body), "etag": etag,
                                "status": status, "location": location})


if __name__ == "__main__":
    ThreadingHTTPServer.daemon_threads = True
    servers = [ThreadingHTTPServer(("0.0.0.0", port), Handler) for port in PORTS]
    for s in servers[1:]:
        threading.Thread(target=s.serve_forever, daemon=True).start()
    servers[0].serve_forever()
