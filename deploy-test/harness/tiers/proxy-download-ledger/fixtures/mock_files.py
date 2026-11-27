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
#   PUT  /__file?path=<p>[&ctype=<t>][&cenc=<c>]
#                                      store the request body at <p> (an
#                                      absolute URL path, query not included).
#                                      Replaces any previous body; the ETag is
#                                      derived from the bytes, so new bytes
#                                      mean a new validator. cenc, when given,
#                                      is sent as Content-Encoding with the
#                                      stored (already coded) bytes.
#                                      &gzip=1: the body is stored plain and
#                                      served gzip-coded (Content-Encoding:
#                                      gzip, its own ETag) to a request whose
#                                      Accept-Encoding names gzip, plain
#                                      otherwise, as a CDN does.
#                                      &when_accept=<s>: store a variant of
#                                      <p> served instead when the request's
#                                      Accept header contains <s> (a PEP 691
#                                      JSON page next to the HTML one).
#                                      &noetag=1: serve <p> with no ETag and
#                                      never answer 304 (an upstream without
#                                      validators).
#   POST /__delay?path=<p>&ms=<n>      hold every GET of <p> n ms before the
#                                      status line (0 clears).
#   POST /__status?path=<p>&code=<n>   answer every GET/HEAD of <p> with status
#                                      n and a short body, whatever is stored
#                                      (0 clears). An S3 bucket without list
#                                      permission answers 403 for a missing key.
#                                      Optional &challenge=<v>: also send
#                                      `WWW-Authenticate: <v>` with it (an OCI
#                                      registry's Bearer challenge).
#   GET  /__requests?path=<p>          {"path", "get", "head", "conditional",
#                                      "bytes", "codings"}: requests seen for
#                                      <p> (any status), the body bytes sent
#                                      to its GETs, and the Accept-Encoding
#                                      of each GET ("" when absent).
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
import gzip
import hashlib
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

PORT = int(os.environ.get("MOCK_PORT", "80"))

LOCK = threading.Lock()
FILES = {}    # path -> (body, ctype, etag, cenc or None, gzip-negotiated)
VARIANTS = {}  # path -> [(accept substring, entry)]
DELAYS = {}   # path -> ms
STATUS = {}   # path -> forced status code
CHALLENGE = {}  # path -> WWW-Authenticate sent with the forced status
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
            if not head:
                codings = c.setdefault("codings", [])
                if len(codings) < 200:
                    codings.append(self.headers.get("Accept-Encoding", ""))
            entry = FILES.get(p)
            accept = self.headers.get("Accept", "")
            for token, variant in VARIANTS.get(p, []):
                if token in accept:
                    entry = variant
                    break
            delay = DELAYS.get(p, 0)
            forced = STATUS.get(p, 0)
            challenge = CHALLENGE.get(p)
        if delay and not head:
            time.sleep(delay / 1000.0)
        if forced:
            code = forced
            extra = {"WWW-Authenticate": challenge} if challenge else None
            self._send(forced, b'{"errors":[{"detail":"forced status"}]}', "application/json", extra, head=head)
        elif entry is None:
            code = 404
            self._send(404, b'{"errors":[{"detail":"not found"}]}', "application/json", head=head)
        else:
            body, ctype, etag, cenc, negotiate = entry
            if negotiate:
                wanted = [t.split(";")[0].strip().lower()
                          for t in self.headers.get("Accept-Encoding", "").split(",")]
                if "gzip" in wanted:
                    body = gzip.compress(body, mtime=0)
                    etag = etag[:-1] + '-gzip"' if etag else None
                    cenc = "gzip"
            inm = self.headers.get("If-None-Match")
            if etag and inm is not None and etag in [t.strip() for t in inm.split(",")]:
                code = 304
                self.send_response(304)
                self.send_header("ETag", etag)
                self.send_header("Content-Length", "0")
                self.end_headers()
            else:
                code = 200
                extra = {"ETag": etag} if etag else {}
                if cenc:
                    extra["Content-Encoding"] = cenc
                self._send(200, body, ctype, extra, head=head)
                if not head:
                    with LOCK:
                        COUNTS[p]["bytes"] = COUNTS[p].get("bytes", 0) + len(body)
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
                c = json.loads(json.dumps(COUNTS.get(p, {"get": 0, "head": 0, "conditional": 0})))
            c.setdefault("bytes", 0)
            c.setdefault("codings", [])
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
        cenc = q.get("cenc", [""])[0] or None
        negotiate = q.get("gzip", [""])[0] == "1"
        when_accept = q.get("when_accept", [""])[0]
        etag = None if q.get("noetag", [""])[0] == "1" else etag_of(body)
        entry = (body, ctype, etag, cenc, negotiate)
        with LOCK:
            if when_accept:
                VARIANTS[p] = [v for v in VARIANTS.get(p, []) if v[0] != when_accept]
                VARIANTS[p].append((when_accept, entry))
            else:
                FILES[p] = entry
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
        if url.path == "/__status":
            p = q.get("path", [""])[0]
            code = int(q.get("code", ["0"])[0])
            challenge = q.get("challenge", [""])[0]
            with LOCK:
                if code:
                    STATUS[p] = code
                else:
                    STATUS.pop(p, None)
                if code and challenge:
                    CHALLENGE[p] = challenge
                else:
                    CHALLENGE.pop(p, None)
            return self._json(200, {"path": p, "code": code})
        return self._json(404, {"error": "unknown control endpoint"})


if __name__ == "__main__":
    ThreadingHTTPServer.daemon_threads = True
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
