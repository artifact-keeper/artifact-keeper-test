#!/usr/bin/env python3
# =============================================================================
# mock_conda_stale.py: an upstream conda channel whose repodata changes on
# demand and can answer slowly (conda-virtual-stale-serve, artifact-keeper#4879)
# =============================================================================
# Stdlib only. Serves `<subdir>/repodata.json` for `noarch` and `linux-64`:
# one fixed record (dtfst-base) and one record that names the current
# GENERATION, `dtfst-<subdir>-gen<N>-1.0-0.tar.bz2`, so a reader can tell
# which upstream generation a merged document was built from. Every other
# path (the compressed encodings, channeldata, packages) answers 404, so
# Artifact Keeper's virtual merge falls through to the plain JSON.
#
# Control (read with `docker exec`, never through the backend):
#   /__bump?delay=S  next generation; from now on every repodata.json answer
#                    is held S seconds before it is sent (a slow upstream, so
#                    a rebuild takes measurable time). Answers the new state.
#   /__state         {"generation": N, "delay": S, "requests": {path: count}}
#   /__readyz        `ok` (compose healthcheck)
#
# Env: MOCK_PORT (default 80).
# =============================================================================
import hashlib
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

PORT = int(os.environ.get("MOCK_PORT", "80"))
SUBDIRS = ("noarch", "linux-64")

_lock = threading.Lock()
_state = {"generation": 1, "delay": 0.0, "requests": {}}


def record(name, version, subdir):
    digest = f"{name}-{version}-{subdir}".encode()
    return {
        "name": name,
        "version": version,
        "build": "0",
        "build_number": 0,
        "depends": [],
        "license": "MIT",
        "subdir": subdir,
        "timestamp": 1700000000000,
        "size": 1024,
        "sha256": hashlib.sha256(digest).hexdigest(),
        "md5": hashlib.md5(digest).hexdigest(),  # noqa: S324 (conda field)
    }


def repodata(subdir, generation):
    gen_name = f"dtfst-{subdir}-gen{generation}"
    return json.dumps(
        {
            "info": {"subdir": subdir},
            "packages": {
                "dtfst-base-1.0-0.tar.bz2": record("dtfst-base", "1.0", subdir),
                f"{gen_name}-1.0-0.tar.bz2": record(gen_name, "1.0", subdir),
            },
            "packages.conda": {},
            "removed": [],
            "repodata_version": 1,
        },
        sort_keys=True,
    ).encode()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, code, ctype, body, head=False):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if not head:
            self.wfile.write(body)

    def _route(self, head):
        url = urlsplit(self.path)
        path = url.path
        while "//" in path:
            path = path.replace("//", "/")
        if path == "/__readyz":
            self._send(200, "text/plain", b"ok", head)
            return
        if path == "/__bump":
            delay = float(parse_qs(url.query).get("delay", ["0"])[0])
            with _lock:
                _state["generation"] += 1
                _state["delay"] = delay
                body = json.dumps(_state, sort_keys=True).encode()
            self._send(200, "application/json", body, head)
            return
        if path == "/__state":
            with _lock:
                body = json.dumps(_state, sort_keys=True).encode()
            self._send(200, "application/json", body, head)
            return
        with _lock:
            _state["requests"][path] = _state["requests"].get(path, 0) + 1
            generation, delay = _state["generation"], _state["delay"]
        parts = path.strip("/").split("/")
        if len(parts) == 2 and parts[0] in SUBDIRS and parts[1] == "repodata.json":
            if delay > 0:
                time.sleep(delay)
            self._send(200, "application/json", repodata(parts[0], generation), head)
            return
        self._send(404, "text/plain", b"not found", head)

    def do_GET(self):  # noqa: N802
        self._route(False)

    def do_HEAD(self):  # noqa: N802
        self._route(True)

    def log_message(self, fmt, *args):
        print("mock-conda-stale: " + fmt % args, flush=True)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
