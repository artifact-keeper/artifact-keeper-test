#!/usr/bin/env python3
"""Mock NuGet V3 upstream for the nuget-cred-scoping tier (#2925).

Two roles from one script (env ROLE):

  ROLE=index  -- the CONFIGURED upstream (host `mock-nuget-index`). Serves two
                 service indexes:
                   GET /foreign/index.json   -> bases point at the FOREIGN host
                                                (the exploit: a hostile/compromised
                                                 service index naming another host)
                   GET /samehost/index.json  -> bases point back at THIS host
                                                (the legitimate case)
                 It also serves the same-host flat-container/registration content
                 (`/sh-flat/*`, `/sh-reg/*`) and logs the Authorization header it
                 receives, so the tier can prove a SAME-host resource still gets
                 the configured credentials.

  ROLE=foreign -- the OTHER host (`mock-nuget-foreign`) the hostile index names.
                 Serves flat-container/registration content and logs the
                 Authorization header on every request. If AK ever fetches here
                 carrying the repo's upstream credentials, that is the #2925 leak;
                 the log line is the oracle's evidence.

Every received request is printed as a single stdout line the oracle greps via
`docker logs`:

    RECV <METHOD> <PATH> AUTH=<value-or-NONE>

Stdlib only (no pip install), mirroring fixtures/mock_pypi.py. Binds
0.0.0.0:80.
"""
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("MOCK_PORT", "80"))
ROLE = os.environ.get("ROLE", "index")

INDEX_HOST = os.environ.get("INDEX_HOST", "mock-nuget-index")
FOREIGN_HOST = os.environ.get("FOREIGN_HOST", "mock-nuget-foreign")


def service_index(pkg_base, reg_base):
    return {
        "version": "3.0.0",
        "resources": [
            {"@id": pkg_base, "@type": "PackageBaseAddress/3.0.0"},
            {"@id": reg_base, "@type": "RegistrationsBaseUrl"},
            {"@id": reg_base, "@type": "RegistrationsBaseUrl/3.6.0"},
        ],
    }


# A minimal-but-valid flat-container version list, returned 200 so that a
# pre-fix AK actually completes the credentialed off-host fetch (and the
# Authorization header is captured) rather than erroring first.
FLAT_VERSIONS = {"versions": ["1.0.0"]}
REGISTRATION = {"count": 0, "items": []}


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body_bytes, ctype="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body_bytes)))
        self.end_headers()
        if body_bytes:
            self.wfile.write(body_bytes)

    def _log_recv(self):
        auth = self.headers.get("Authorization", "NONE")
        # One grep-able line per request; the oracle keys on AUTH=Basic ...
        print("RECV {} {} AUTH={}".format(self.command, self.path, auth), flush=True)

    def do_GET(self):
        if self.path == "/__readyz":
            self._send(200, b"ok", "text/plain")
            return
        self._log_recv()

        if ROLE == "index":
            if self.path == "/foreign/index.json":
                # Hostile index: bases named on the FOREIGN host.
                idx = service_index(
                    "http://{}/v3-flat/".format(FOREIGN_HOST),
                    "http://{}/v3-reg/".format(FOREIGN_HOST),
                )
                self._send(200, json.dumps(idx).encode())
                return
            if self.path == "/samehost/index.json":
                # Legitimate index: bases named on THIS host.
                idx = service_index(
                    "http://{}/sh-flat/".format(INDEX_HOST),
                    "http://{}/sh-reg/".format(INDEX_HOST),
                )
                self._send(200, json.dumps(idx).encode())
                return
            if self.path.startswith("/sh-flat/"):
                self._send(200, json.dumps(FLAT_VERSIONS).encode())
                return
            if self.path.startswith("/sh-reg/"):
                self._send(200, json.dumps(REGISTRATION).encode())
                return
            self._send(404, b"{}")
            return

        # ROLE == foreign: serve whatever content so a pre-fix fetch completes.
        if self.path.startswith("/v3-flat/"):
            self._send(200, json.dumps(FLAT_VERSIONS).encode())
            return
        if self.path.startswith("/v3-reg/"):
            self._send(200, json.dumps(REGISTRATION).encode())
            return
        self._send(404, b"{}")

    def log_message(self, *args):  # silence default noisy logging
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
