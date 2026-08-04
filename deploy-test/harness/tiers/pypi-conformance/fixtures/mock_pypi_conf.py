#!/usr/bin/env python3
# =============================================================================
# mock_pypi_conf.py — variant-route PyPI upstream for the conformance corpus
# =============================================================================
# ATTRIBUTION
#   The variant-route mock-server PATTERN here is modeled on uv's test PyPI
#   proxy:
#       astral-sh/uv — crates/uv-test/src/pypi_proxy.rs
#       Copyright (c) Astral Software Inc.  Licensed Apache-2.0 OR MIT.
#       https://github.com/astral-sh/uv
#   We learned the APPROACH (one server, many route families keyed by URL
#   prefix, each reproducing a protocol edge case) from that file. No source
#   code was copied; this is an independent stdlib reimplementation. Credit and
#   thanks to the uv authors. See deploy-test/conformance/CREDITS.md for the
#   full attribution ledger and the license discipline we follow.
# =============================================================================
# One stdlib server serves the same package under several route families, each
# reproducing one protocol edge case the corpus pins. The first path segment
# selects the variant:
#
#   /clean/simple/<pkg>/            valid PEP 691 JSON, absolute in-band URLs,
#                                   a real .metadata resource (200)
#   /meta404/simple/<pkg>/          advertises PEP 658 metadata, 404s it (#3077)
#   /relative/simple/<pkg>/         file URLs are RELATIVE (../../files/...)
#   /yanked/simple/<pkg>/           the single release is PEP 592 yanked
#
# Every variant serves the wheel + sdist bytes at <variant>/files/... so a real
# proxy pull completes. /__readyz is the readiness probe.
#
# Stdlib only, single file, stock python image. Env:
#   MOCK_PORT  listen port (default 80)
#   MOCK_PKG   package name (default dtfpkg)
# =============================================================================
import hashlib
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("MOCK_PORT", "80"))
PKG = os.environ.get("MOCK_PKG", "dtfpkg")

WHEEL = f"{PKG}-1.0.0-py3-none-any.whl"
SDIST = f"{PKG}-1.0.0.tar.gz"
WHEEL_BYTES = b"PK\x03\x04 mock wheel for " + PKG.encode() + b" " + b"x" * 512
SDIST_BYTES = b"mock sdist for " + PKG.encode() + b" " + b"y" * 256
METADATA_BYTES = (
    b"Metadata-Version: 2.1\n"
    b"Name: " + PKG.encode() + b"\n"
    b"Version: 1.0.0\n"
    b"Requires-Python: >=3.8\n"
)


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def simple_json(variant):
    """PEP 691 project-detail body for the variant."""
    if variant == "relative":
        wheel_url = f"../../files/{WHEEL}"
        sdist_url = f"../../files/{SDIST}"
    else:
        # absolute in-band URL (points back at this mock; a correct proxy
        # rewrites it under /pypi/<repo>/...)
        base = f"/{variant}/files"
        wheel_url = f"{base}/{WHEEL}"
        sdist_url = f"{base}/{SDIST}"

    wheel_file = {
        "filename": WHEEL,
        "url": wheel_url,
        "hashes": {"sha256": sha256(WHEEL_BYTES)},
        "requires-python": ">=3.8",
        "yanked": (variant == "yanked"),
    }
    # PEP 658 / 714 metadata advertisement on the wheel.
    if variant in ("clean", "meta404", "relative"):
        wheel_file["core-metadata"] = {"sha256": sha256(METADATA_BYTES)}
        wheel_file["dist-info-metadata"] = {"sha256": sha256(METADATA_BYTES)}
    sdist_file = {
        "filename": SDIST,
        "url": sdist_url,
        "hashes": {"sha256": sha256(SDIST_BYTES)},
        "yanked": (variant == "yanked"),
    }
    body = {
        "meta": {"api-version": "1.1"},
        "name": PKG,
        "files": [sdist_file, wheel_file],
        "versions": ["1.0.0"],
    }
    return json.dumps(body).encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, code, ctype, body):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        p = self.path.split("?", 1)[0]
        if p == "/__readyz":
            return self._send(200, "text/plain", b"ok")

        seg = [s for s in p.split("/") if s]
        variant = seg[0] if seg else "clean"

        # Simple project-detail index.
        if "/simple/" in p and p.rstrip("/").endswith(PKG):
            return self._send(
                200, "application/vnd.pypi.simple.v1+json",
                simple_json(variant),
            )
        # File serves.
        if p.endswith(WHEEL):
            return self._send(200, "application/octet-stream", WHEEL_BYTES)
        if p.endswith(SDIST):
            return self._send(200, "application/octet-stream", SDIST_BYTES)
        # PEP 658 metadata resource: present for clean/relative, 404 for meta404.
        if p.endswith(".metadata"):
            if variant == "meta404":
                return self._send(404, "text/plain", b"not found")
            return self._send(200, "application/octet-stream", METADATA_BYTES)

        return self._send(404, "text/plain", b"not found")

    do_HEAD = do_GET

    def log_message(self, *a):  # silence
        return


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
