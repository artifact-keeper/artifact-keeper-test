#!/usr/bin/env python3
# =============================================================================
# mock_pypi_agegate.py - canned PyPI upstream for the pypi-age-gate-pep440-lookup
# tier (artifact-keeper#4907, PR #4908)
# =============================================================================
# A stdlib-only PyPI upstream that serves one project, `cuda-toolkit`, in the
# shape that broke `pip install torch==2.14.1` behind an age-gated remote: the
# distribution filename spells the version differently from the Warehouse
# release key, although the two are equal under PEP 440.
#
# Warehouse JSON (/pypi/cuda-toolkit/json), `releases` keyed:
#   13.0.3   uploaded 2026-04-14 (old)    file cuda_toolkit-13.0.3.0-...whl
#   13.4.2   uploaded 2026-09-16 (old)    file cuda_toolkit-13.4.2-...whl
#   13.5.0   uploaded now minus 1 day     file cuda_toolkit-13.5.0-...whl
# The simple index additionally lists cuda_toolkit-13.0.3.1-...whl, which has
# NO PEP 440-equal release key, so it must stay gated on every image.
#
# Simple index: HTML (PEP 503) by default, PEP 691 JSON when the request
# Accept header asks for application/vnd.pypi.simple.v1+json. The JSON form
# deliberately carries NO PEP 700 `upload-time`, so the backend has to fall
# back to the Warehouse JSON publish times (`fill_missing_publish_times`).
#
# Every href points back at this mock (`/files/<filename>`, with a sha256
# fragment). Wheel bytes are generated at start-up (a real zip in memory), so
# no binary is committed. GET /__log returns the request paths seen so far.
# =============================================================================
import hashlib
import io
import json
import os
import zipfile
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("MOCK_PORT", "80"))
HOST = os.environ.get("MOCK_HOST", "mock-pypi")
PROJECT = "cuda-toolkit"
DIST = "cuda_toolkit"
TAG = "py2.py3-none-any"

NOW = datetime.now(timezone.utc)
YOUNG = (NOW - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

# release key -> (upload time, [filenames])
RELEASES = {
    "13.0.3": ("2026-04-14T17:03:21.000000Z", [f"{DIST}-13.0.3.0-{TAG}.whl"]),
    "13.4.2": ("2026-09-16T09:12:44.000000Z", [f"{DIST}-13.4.2-{TAG}.whl"]),
    "13.5.0": (YOUNG, [f"{DIST}-13.5.0-{TAG}.whl"]),
}
# Listed in the simple index, but no release key is PEP 440-equal to 13.0.3.1.
ORPHAN = f"{DIST}-13.0.3.1-{TAG}.whl"


def _wheel(filename: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("cuda_toolkit/__init__.py", f"# {filename}\n")
        zf.writestr(
            filename[: -len(f"-{TAG}.whl")] + ".dist-info/WHEEL",
            f"Wheel-Version: 1.0\nGenerator: dtf-mock\nRoot-Is-Purelib: true\nTag: {TAG}\n",
        )
    return buf.getvalue()


FILES = {}
for _ver, (_ts, _fns) in RELEASES.items():
    for _fn in _fns:
        FILES[_fn] = _wheel(_fn)
FILES[ORPHAN] = _wheel(ORPHAN)
SHA = {fn: hashlib.sha256(b).hexdigest() for fn, b in FILES.items()}
LISTED = [fn for _, fns in RELEASES.values() for fn in fns] + [ORPHAN]


def _warehouse_json() -> bytes:
    releases = {}
    for ver, (ts, fns) in RELEASES.items():
        releases[ver] = [
            {
                "filename": fn,
                "packagetype": "bdist_wheel",
                "python_version": "py2.py3",
                "size": len(FILES[fn]),
                "digests": {"sha256": SHA[fn]},
                "upload_time": ts[:19],
                "upload_time_iso_8601": ts,
                "url": f"http://{HOST}/files/{fn}",
                "yanked": False,
            }
            for fn in fns
        ]
    body = {
        "info": {"name": PROJECT, "version": "13.5.0"},
        "releases": releases,
        "urls": releases["13.5.0"],
    }
    return json.dumps(body).encode("utf-8")


def _simple_html() -> bytes:
    lines = [
        "<!DOCTYPE html>",
        "<html><head>",
        '<meta name="pypi:repository-version" content="1.0"/>',
        f"<title>Links for {PROJECT}</title>",
        "</head><body>",
        f"<h1>Links for {PROJECT}</h1>",
    ]
    for fn in LISTED:
        lines.append(f'<a href="http://{HOST}/files/{fn}#sha256={SHA[fn]}">{fn}</a><br/>')
    lines.append("</body></html>")
    return ("\n".join(lines) + "\n").encode("utf-8")


def _simple_json() -> bytes:
    body = {
        "meta": {"api-version": "1.1"},
        "name": PROJECT,
        "versions": ["13.0.3.0", "13.0.3.1", "13.4.2", "13.5.0"],
        # No PEP 700 `upload-time`: forces the Warehouse JSON fallback.
        "files": [
            {
                "filename": fn,
                "url": f"http://{HOST}/files/{fn}",
                "hashes": {"sha256": SHA[fn]},
                "size": len(FILES[fn]),
            }
            for fn in LISTED
        ],
    }
    return json.dumps(body).encode("utf-8")


WAREHOUSE = _warehouse_json()
SIMPLE_HTML = _simple_html()
SIMPLE_JSON = _simple_json()
LOG = []


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, code, ctype, body):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/__readyz":
            self._send(200, "text/plain", b"ok")
            return
        if path == "/__log":
            self._send(200, "text/plain", ("\n".join(LOG) + "\n").encode("utf-8"))
            return
        LOG.append(f"GET {path} accept={self.headers.get('Accept', '')}")
        if path.startswith("/files/"):
            body = FILES.get(path[len("/files/"):])
            if body is None:
                self._send(404, "text/plain", b"not found")
            else:
                self._send(200, "application/octet-stream", body)
            return
        parts = [p for p in path.split("/") if p]
        if len(parts) == 3 and parts[0] == "pypi" and parts[2] == "json":
            if parts[1].lower().replace("_", "-") == PROJECT:
                self._send(200, "application/json", WAREHOUSE)
            else:
                self._send(404, "application/json", b'{"message": "Not Found"}')
            return
        if parts and parts[-1].lower().replace("_", "-") == PROJECT:
            if "application/vnd.pypi.simple.v1+json" in self.headers.get("Accept", ""):
                self._send(200, "application/vnd.pypi.simple.v1+json", SIMPLE_JSON)
            else:
                self._send(200, "text/html; charset=utf-8", SIMPLE_HTML)
            return
        self._send(404, "text/plain", b"not found")

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
