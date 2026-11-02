#!/usr/bin/env python3
# =============================================================================
# mock_helm_literal.py - a Helm upstream whose index.yaml names chart URLs on IP
# literals, and the listeners those URLs point at, for the
# upstream-ip-literal-refused tier (artifact-keeper#5095)
# =============================================================================
# One script, three containers (profiles/upstreams.mock-helm-literal.yml):
#
#   mock-helm       MOCK_BIND 0.0.0.0:80. Serves /index.yaml and /charts/<file>.
#   mock-decoy      MOCK_BIND 0.0.0.0:80. A private address the backend's policy
#                   does not admit. Answers every path with chart bytes.
#   mock-loopback   MOCK_BIND 127.0.0.1:18099 inside the backend's network
#                   namespace. Answers every path with chart bytes.
#
# Index entries (chart name -> first url), every version 1.0.0:
#   lit-dotted   http://127.0.0.1:18099/...
#   lit-integer  http://2130706433:18099/...
#   lit-hex      http://0x7f.0.0.1:18099/...
#   lit-octal    http://0177.0.0.1:18099/...
#   lit-mapped   http://[::ffff:127.0.0.1]:18099/...
#   lit-metadata http://169.254.169.254/...
#   lit-decoy    http://<MOCK_DECOY_IP>/...
#   ok-literal   http://<MOCK_SELF_IP>/charts/...  (admitted /32)
#   ok-hostname  http://mock-helm/charts/...       (a host name)
#   ok-relative  charts/...                        (relative to the upstream)
#
# Control endpoints (never logged): /__readyz, /__log (requests, one per line).
# Stdlib only, single file, stock python image.
# =============================================================================
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST, PORT = os.environ.get("MOCK_BIND", "0.0.0.0:80").rsplit(":", 1)
ROLE = os.environ.get("MOCK_ROLE", "listener")
SELF_IP = os.environ.get("MOCK_SELF_IP", "")
DECOY_IP = os.environ.get("MOCK_DECOY_IP", "")
CHART = b"\x1f\x8b\x08\x00dtf-helm-literal-chart-bytes-from-" + ROLE.encode() + b"\n"
LOG = []


def url_for(name):
    file = f"{name}-1.0.0.tgz"
    return {
        "lit-dotted": f"http://127.0.0.1:18099/{file}",
        "lit-integer": f"http://2130706433:18099/{file}",
        "lit-hex": f"http://0x7f.0.0.1:18099/{file}",
        "lit-octal": f"http://0177.0.0.1:18099/{file}",
        "lit-mapped": f"http://[::ffff:127.0.0.1]:18099/{file}",
        "lit-metadata": f"http://169.254.169.254/{file}",
        "lit-decoy": f"http://{DECOY_IP}/{file}",
        "ok-literal": f"http://{SELF_IP}/charts/{file}",
        "ok-hostname": f"http://mock-helm/charts/{file}",
        "ok-relative": f"charts/{file}",
    }[name]


NAMES = ("lit-dotted", "lit-integer", "lit-hex", "lit-octal", "lit-mapped", "lit-metadata",
         "lit-decoy", "ok-literal", "ok-hostname", "ok-relative")


def index_yaml():
    lines = ["apiVersion: v1", "entries:"]
    for name in NAMES:
        lines += [f"  {name}:", "  - apiVersion: v2", f"    name: {name}", "    version: 1.0.0",
                  "    urls:", f'    - "{url_for(name)}"']
    lines.append('generated: "2026-01-01T00:00:00Z"')
    return ("\n".join(lines) + "\n").encode()


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/octet-stream"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/__readyz":
            return self._send(200, b"ok", "text/plain")
        if path == "/__log":
            return self._send(200, "\n".join(LOG).encode(), "text/plain")
        LOG.append(f"GET {path}")
        if ROLE == "helm":
            if path == "/index.yaml":
                return self._send(200, index_yaml(), "application/x-yaml")
            if path.startswith("/charts/"):
                return self._send(200, CHART, "application/gzip")
            return self._send(404, b"not found", "text/plain")
        return self._send(200, CHART, "application/gzip")

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer((HOST, int(PORT)), Handler).serve_forever()
