#!/usr/bin/env python3
# =============================================================================
# mock_index_hosts.py -- an upstream index host and a foreign file host
# =============================================================================
# For the index-metadata-cred-scoping tier (GHSA-24rf-2gv2-j47c). One script,
# two roles (env ROLE), both recording the Authorization header of every
# request so the oracle can prove where a Remote's upstream credentials went.
#
# ROLE=index   the Remote's CONFIGURED upstream (host INDEX_HOST).
#   GET /simple/<pkg>/   PyPI simple page. One link:
#                          pkg starts "off"  -> http://FOREIGN_HOST/files/<pkg>-1.0.tar.gz
#                          otherwise         -> http://INDEX_HOST/files/<pkg>-1.0.tar.gz
#                        (both absolute, as index metadata may name them)
#   GET /index.yaml      Helm index with two charts:
#                          offchart  1.0.0 -> http://FOREIGN_HOST/charts/offchart-1.0.0.tgz
#                          samechart 1.0.0 -> http://INDEX_HOST/charts/samechart-1.0.0.tgz
#   GET /redir/<name>    302 to http://FOREIGN_HOST/files/<name> (a redirect,
#                        not index metadata: the HTTP client strips
#                        Authorization on a cross-origin redirect)
# ROLE=foreign the OTHER host that the index names.
# Both roles:
#   GET /files/<name>, /charts/<name>  200, a body naming the role and path
#   GET /__requests      {"total": n, "requests": [{method, path, auth}]}
#   GET /__readyz        healthcheck
# Every counted request also prints:  RECV <METHOD> <PATH> AUTH=<value|NONE>
#
# Stdlib only. Env: MOCK_PORT (80), ROLE, INDEX_HOST, FOREIGN_HOST.
# =============================================================================
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

PORT = int(os.environ.get("MOCK_PORT", "80"))
ROLE = os.environ.get("ROLE", "index")
INDEX_HOST = os.environ.get("INDEX_HOST", "mock-idx")
FOREIGN_HOST = os.environ.get("FOREIGN_HOST", "mock-foreign")

LOCK = threading.Lock()
REQS = []

HELM_INDEX = """apiVersion: v1
entries:
  offchart:
  - apiVersion: v2
    name: offchart
    version: 1.0.0
    created: "2026-01-01T00:00:00Z"
    urls:
    - http://{foreign}/charts/offchart-1.0.0.tgz
  samechart:
  - apiVersion: v2
    name: samechart
    version: 1.0.0
    created: "2026-01-01T00:00:00Z"
    urls:
    - http://{index}/charts/samechart-1.0.0.tgz
generated: "2026-01-01T00:00:00Z"
"""


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def _send(self, code, data, ctype="application/octet-stream", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _record(self, path):
        auth = self.headers.get("Authorization", "NONE")
        with LOCK:
            REQS.append({"method": self.command, "path": path, "auth": auth})
        print("RECV {} {} AUTH={}".format(self.command, path, auth), flush=True)

    def _handle(self):
        path = urlsplit(self.path).path
        if path == "/__readyz":
            return self._send(200, b"ok", "text/plain")
        if path == "/__requests":
            with LOCK:
                body = {"total": len(REQS), "requests": list(REQS)}
            return self._send(200, json.dumps(body).encode(), "application/json")
        self._record(path)
        if path.startswith("/files/") or path.startswith("/charts/"):
            return self._send(200, "{} served {}\n".format(ROLE, path).encode())
        if ROLE == "index":
            if path.startswith("/simple/"):
                pkg = path[len("/simple/"):].strip("/")
                host = FOREIGN_HOST if pkg.startswith("off") else INDEX_HOST
                fname = "{}-1.0.tar.gz".format(pkg)
                html = ('<!DOCTYPE html><html><body>'
                        '<a href="http://{}/files/{}">{}</a>'
                        '</body></html>').format(host, fname, fname)
                return self._send(200, html.encode(), "text/html")
            if path == "/index.yaml":
                return self._send(200, HELM_INDEX.format(foreign=FOREIGN_HOST, index=INDEX_HOST).encode(),
                                  "application/x-yaml")
            if path.startswith("/redir/"):
                loc = "http://{}/files/{}".format(FOREIGN_HOST, path[len("/redir/"):])
                return self._send(302, b"", "text/plain", {"Location": loc})
        return self._send(404, b"not found", "text/plain")

    def do_GET(self):
        self._handle()

    def do_HEAD(self):
        self._handle()


if __name__ == "__main__":
    ThreadingHTTPServer.daemon_threads = True
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
