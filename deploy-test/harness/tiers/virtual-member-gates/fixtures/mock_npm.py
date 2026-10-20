#!/usr/bin/env python3
"""Stdlib-only npm registry upstream for the virtual-member-gates DTF tier.

Serves one package, `dtf-held` 1.0.0, under any path prefix, so two Remote
repositories can point at the same server with different prefixes
(http://<ip>/m1 and http://<ip>/m2) and the request log tells them apart:

  GET /<prefix>/dtf-held                      packument (tarball URL under the
                                              same prefix, publish time = now)
  GET /<prefix>/dtf-held/-/dtf-held-1.0.0.tgz the tarball

Every request is printed as `MOCKNPM <METHOD> <path> <status>` so the oracle
can count, from `docker logs`, which member fetched the tarball.
GET /__readyz answers "ok".
"""
import base64
import datetime
import hashlib
import io
import json
import os
import tarfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("MOCK_PORT", "80"))
PKG = "dtf-held"
VER = "1.0.0"
FILE = f"{PKG}-{VER}.tgz"


def build_tarball():
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data in (
            ("package/package.json", json.dumps({"name": PKG, "version": VER}).encode()),
            ("package/index.js", b"module.exports = 'dtf-held-upstream';\n"),
        ):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mtime = 0
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


TARBALL = build_tarball()
SHASUM = hashlib.sha1(TARBALL).hexdigest()  # noqa: S324 (npm dist.shasum)
INTEGRITY = "sha512-" + base64.b64encode(hashlib.sha512(TARBALL).digest()).decode()


def packument(base):
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    return {
        "name": PKG,
        "dist-tags": {"latest": VER},
        "time": {"created": now, "modified": now, VER: now},
        "versions": {
            VER: {
                "name": PKG,
                "version": VER,
                "dist": {
                    "tarball": f"{base}/{PKG}/-/{FILE}",
                    "shasum": SHASUM,
                    "integrity": INTEGRITY,
                },
            }
        },
    }


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def _send(self, code, ctype, body, head=False):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if not head:
            self.wfile.write(body)
        print(f"MOCKNPM {self.command} {self.path} {code}", flush=True)

    def _route(self, head):
        path = self.path.split("?", 1)[0]
        if path == "/__readyz":
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            if not head:
                self.wfile.write(b"ok")
            return
        parts = [p for p in path.split("/") if p]
        if len(parts) >= 2 and parts[1] == PKG:
            prefix = parts[0]
            rest = parts[2:]
            host = self.headers.get("Host", "127.0.0.1")
            if not rest:
                body = json.dumps(packument(f"http://{host}/{prefix}")).encode()
                return self._send(200, "application/json", body, head)
            if rest == ["-", FILE]:
                return self._send(200, "application/octet-stream", TARBALL, head)
        return self._send(404, "application/json", b'{"error":"not found"}', head)

    def do_GET(self):  # noqa: N802
        self._route(False)

    def do_HEAD(self):  # noqa: N802
        self._route(True)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
