#!/usr/bin/env python3
# =============================================================================
# mock_npm_tags.py - an npm upstream with dist-tags, for the
# npm-version-route-dist-tags tier (artifact-keeper#5063)
# =============================================================================
# Two packages with one packument shape, `dtf-tags` and `@dtf/tags`:
#
#   versions   1.0.0 (published 2020-01-01), 2.0.0 (published now, so a 7-day age
#              gate withholds it)
#   dist-tags  latest -> 2.0.0, fresh -> 2.0.0, old -> 1.0.0, ghost -> 9.9.9 (a
#              version the packument does not list)
#
# Endpoints: GET /<name> (scoped as @dtf/tags or @dtf%2ftags), GET /__readyz.
# Stdlib only, single file, stock python image. MOCK_PORT: listen port (80).
# =============================================================================
import json
import os
import urllib.parse
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("MOCK_PORT", "80"))
NAMES = ("dtf-tags", "@dtf/tags")


def packument(name):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    base = name.rsplit("/", 1)[-1]
    versions = {
        v: {"name": name, "version": v, "description": f"upstream {v}",
            "dist": {"tarball": f"http://mock-npm-tags/{name}/-/{base}-{v}.tgz",
                     "shasum": "0" * 40}}
        for v in ("1.0.0", "2.0.0")
    }
    return {
        "name": name,
        "dist-tags": {"latest": "2.0.0", "fresh": "2.0.0", "old": "1.0.0", "ghost": "9.9.9"},
        "time": {"created": "2020-01-01T00:00:00.000Z", "modified": now,
                 "1.0.0": "2020-01-01T00:00:00.000Z", "2.0.0": now},
        "versions": versions,
    }


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urllib.parse.unquote(self.path.split("?", 1)[0]).lstrip("/")
        if path == "__readyz":
            return self._send(200, b"ok", "text/plain")
        if path in NAMES:
            return self._send(200, json.dumps(packument(path)).encode())
        return self._send(404, b'{"error":"not found"}')

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
