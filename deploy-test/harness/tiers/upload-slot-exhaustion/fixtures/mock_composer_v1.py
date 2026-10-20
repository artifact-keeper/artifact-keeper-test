#!/usr/bin/env python3
# =============================================================================
# mock_composer_v1.py: a Composer v1 provider-protocol upstream
# =============================================================================
# The upload-slot-exhaustion tier drives a Remote Composer repository's v1
# provider fallback (artifact-keeper#4162). That fallback runs when the
# direct p/<vendor>/<package>.json (or p2/...) fetch 404s, and it walks the
# upstream's root index:
#
#   GET /packages.json
#       {"providers-url": "/p/%package%$%hash%.json",
#        "provider-includes": {"p/provider-dtf$%hash%.json": {"sha256": INC}}}
#       no "metadata-url", so the backend treats it as a v1 upstream
#   GET /p/provider-dtf$INC.json
#       {"providers": {"<vendor>/<package>": {"sha256": PKG}}} for every
#       package name in MOCK_PACKAGES
#   GET /p/<vendor>/<package>$PKG.json
#       {"packages": {"<vendor>/<package>": {"1.0.0": {...}}}}
#   anything else (including p/<vendor>/<package>.json and p2/...): 404
#
# Every request is printed to stdout (docker logs) and counted at
# GET /__requests (a JSON map path -> count).
#
# Stdlib only, single file, stock python image.
#   MOCK_PORT      listen port (default 80)
#   MOCK_PACKAGES  space-separated vendor/package names (default dtf/widget)
# =============================================================================
import hashlib
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlsplit

PORT = int(os.environ.get("MOCK_PORT", "80"))
PACKAGES = os.environ.get("MOCK_PACKAGES", "dtf/widget").split()

LOCK = threading.Lock()
COUNTS = {}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def package_doc(name):
    return json.dumps({"packages": {name: {"1.0.0": {
        "name": name, "version": "1.0.0", "version_normalized": "1.0.0.0",
        "type": "library",
        "dist": {"type": "zip", "url": f"https://example.invalid/{name}-1.0.0.zip",
                 "reference": "1.0.0", "shasum": ""}}}}}).encode()


DOCS = {}
PROVIDERS = {}
for _name in PACKAGES:
    _doc = package_doc(_name)
    _h = sha(_doc)
    PROVIDERS[_name] = {"sha256": _h}
    DOCS[f"/p/{_name}${_h}.json"] = _doc
INCLUDE = json.dumps({"providers": PROVIDERS}).encode()
INCLUDE_HASH = sha(INCLUDE)
DOCS[f"/p/provider-dtf${INCLUDE_HASH}.json"] = INCLUDE
DOCS["/packages.json"] = json.dumps({
    "packages": [],
    "providers-url": "/p/%package%$%hash%.json",
    "provider-includes": {"p/provider-dtf$%hash%.json": {"sha256": INCLUDE_HASH}},
}).encode()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        print("mock-composer: " + (fmt % args), flush=True)

    def _send(self, code, data, ctype="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def do_GET(self):
        path = unquote(urlsplit(self.path).path)
        if path == "/__readyz":
            return self._send(200, b"ok", "text/plain")
        if path == "/__requests":
            with LOCK:
                return self._send(200, json.dumps(COUNTS).encode())
        with LOCK:
            COUNTS[path] = COUNTS.get(path, 0) + 1
        doc = DOCS.get(path)
        if doc is None:
            return self._send(404, b'{"status":"not found"}')
        return self._send(200, doc)

    do_HEAD = do_GET


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
