#!/usr/bin/env python3
# =============================================================================
# mock_pypi.py — canned PyPI Simple-index upstream for the pypi-contenttype tier
# =============================================================================
# A deliberately hostile PyPI proxy/mirror for issue #2801: it serves a VALID
# PEP 691 JSON simple-index body but LIES about the Content-Type, returning
# `application/octet-stream` instead of `application/vnd.pypi.simple.v1+json`.
#
# This reproduces the real-world condition where a corporate proxy / broken
# mirror mangles the Content-Type header. A backend that TRUSTS the upstream
# Content-Type (pre-#2801) then:
#   * serves the raw upstream bytes un-rewritten — leaking the offsite
#     `files.pythonhosted.org` download URL baked into the JSON, and
#   * hands the client `application/octet-stream`, which uv/pip reject as a
#     non-simple-index media type.
#
# The #2801 fix sniffs the BODY (JSON vs HTML) rather than trusting the header,
# rewrites the download URLs under `/pypi/<repo>/...`, and 502s on binary
# garbage. See harness/tiers/pypi-contenttype/oracle.sh for the discriminator.
#
# Dependency-light: stdlib only, single file, stock python image.
#   MOCK_PORT    listen port (default 80)
#   MOCK_PKG     package name served (default dtfpkg)
#   MOCK_CTYPE   Content-Type to lie with (default application/octet-stream)
#
# It answers the canned index for ANY path (so it does not matter whether the
# backend requests `/simple/<pkg>/`, `/simple/<pkg>/index.v1+json`, or the flat
# form), except `/__readyz` which is a plain readiness probe.
# =============================================================================
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("MOCK_PORT", "80"))
PKG = os.environ.get("MOCK_PKG", "dtfpkg")
CTYPE = os.environ.get("MOCK_CTYPE", "application/octet-stream")

# The load-bearing detail: an OFFSITE files.pythonhosted.org URL. A correct
# proxy render must rewrite this to route through /pypi/<repo>/...; a header-
# trusting render leaks it verbatim.
OFFSITE_URL = (
    "https://files.pythonhosted.org/packages/source/d/"
    f"{PKG}/{PKG}-1.0.0.tar.gz"
)

# A valid PEP 691 (application/vnd.pypi.simple.v1+json) project detail body.
SIMPLE_JSON = {
    "meta": {"api-version": "1.1"},
    "name": PKG,
    "files": [
        {
            "filename": f"{PKG}-1.0.0.tar.gz",
            "url": OFFSITE_URL,
            "hashes": {
                "sha256": (
                    "e3b0c44298fc1c149afbf4c8996fb924"
                    "27ae41e4649b934ca495991b7852b855"
                )
            },
            "requires-python": ">=3.8",
            "yanked": False,
        }
    ],
    "versions": ["1.0.0"],
}
BODY = json.dumps(SIMPLE_JSON).encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, code, ctype, body):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/__readyz":
            self._send(200, "text/plain", b"ok")
            return
        # Canned PEP 691 JSON body served with a LYING Content-Type for every
        # simple-index request path.
        self._send(200, CTYPE, BODY)

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Type", CTYPE)
        self.send_header("Content-Length", str(len(BODY)))
        self.end_headers()

    def log_message(self, fmt, *args):
        # Quiet; the oracle asserts on AK's response, not the mock's stderr.
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
