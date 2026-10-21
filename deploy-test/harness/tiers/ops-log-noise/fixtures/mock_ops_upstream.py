#!/usr/bin/env python3
# =============================================================================
# mock_ops_upstream.py - a slow file upstream plus a refusing OCI registry
# =============================================================================
# The ops-log-noise tier (artifact-keeper#4552, #4526) needs two upstream
# behaviours a real registry will not produce on demand:
#
#   GET /slow/<path>            deterministic bytes (MOCK_SLOW_BYTES long),
#                               streamed with an honest Content-Length over
#                               MOCK_SLOW_SECS seconds, so a proxy cache fill
#                               takes long enough for a second replica to wait
#                               on the cluster lock. <path>.sha1 / .md5 /
#                               .sha256 / .sha512 answer the checksum of the
#                               base file at once (Maven clients and proxies
#                               ask for them). Counted per path.
#   GET /v2/                    OCI API version check: 200 {}.
#   GET|HEAD /v2/<name>/manifests/<ref>
#                               by the LAST segment of <name>:
#                                 okimg    200, an OCI image manifest
#                                 deny401  401, WWW-Authenticate: Basic
#                                 deny403  403
#                                 bad400   400 (a non-auth refusal)
#                                 other    404
#                               Counted per path.
#   GET /v2/<name>/blobs/<digest>  the okimg config blob. Counted.
#   GET /__requests?path=P      {"path": P, "count": n}
#   GET /__sha256/slow/<path>   hex SHA-256 of what /slow/<path> serves.
#   GET /__manifest             the exact okimg manifest bytes.
#   GET /__readyz               container healthcheck.
#
# Stdlib only, single file, stock python image.
#   MOCK_PORT        listen port (default 80)
#   MOCK_SLOW_BYTES  bytes per /slow file (default 2097152)
#   MOCK_SLOW_SECS   seconds to stream one /slow file (default 4)
# =============================================================================
import hashlib
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

PORT = int(os.environ.get("MOCK_PORT", "80"))
SLOW_BYTES = int(os.environ.get("MOCK_SLOW_BYTES", "2097152"))
SLOW_SECS = float(os.environ.get("MOCK_SLOW_SECS", "4"))
CHUNKS = 40

LOCK = threading.Lock()
COUNTS = {}

CONFIG_BLOB = json.dumps(
    {"architecture": "amd64", "os": "linux", "rootfs": {"type": "layers", "diff_ids": []}},
    sort_keys=True,
).encode()
CONFIG_DIGEST = "sha256:" + hashlib.sha256(CONFIG_BLOB).hexdigest()
MANIFEST = json.dumps(
    {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": CONFIG_DIGEST,
            "size": len(CONFIG_BLOB),
        },
        "layers": [],
    },
    sort_keys=True,
).encode()
MANIFEST_DIGEST = "sha256:" + hashlib.sha256(MANIFEST).hexdigest()
CHECKSUMS = {".sha1": hashlib.sha1, ".md5": hashlib.md5, ".sha256": hashlib.sha256, ".sha512": hashlib.sha512}


def slow_body(name):
    out = bytearray()
    i = 0
    while len(out) < SLOW_BYTES:
        out += hashlib.sha256(f"{name}:{i}".encode()).digest()
        i += 1
    return bytes(out[:SLOW_BYTES])


def count(path):
    with LOCK:
        COUNTS[path] = COUNTS.get(path, 0) + 1


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        print("mock-ops: " + (fmt % args), flush=True)

    def _send(self, code, data=b"", ctype="text/plain", headers=None, body=True):
        if isinstance(data, str):
            data = data.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if body:
            self.wfile.write(data)

    def _manifest(self, path, body):
        count(path)
        parts = path.split("/")
        # /v2/<name...>/manifests/<ref>
        name_last = parts[-3] if len(parts) >= 5 else ""
        if name_last == "okimg":
            return self._send(
                200, MANIFEST, "application/vnd.oci.image.manifest.v1+json",
                {"Docker-Content-Digest": MANIFEST_DIGEST}, body,
            )
        if name_last == "deny401":
            return self._send(401, '{"errors":[{"code":"UNAUTHORIZED"}]}', "application/json",
                              {"WWW-Authenticate": 'Basic realm="mock-ops"'}, body)
        if name_last == "deny403":
            return self._send(403, '{"errors":[{"code":"DENIED"}]}', "application/json", None, body)
        if name_last == "bad400":
            return self._send(400, '{"errors":[{"code":"UNSUPPORTED"}]}', "application/json", None, body)
        return self._send(404, '{"errors":[{"code":"MANIFEST_UNKNOWN"}]}', "application/json", None, body)

    def do_HEAD(self):
        path = urlsplit(self.path).path
        if path.startswith("/v2/") and "/manifests/" in path:
            return self._manifest(path, False)
        return self._send(404, "not found", body=False)

    def do_GET(self):
        u = urlsplit(self.path)
        path = u.path
        if path == "/__readyz":
            return self._send(200, "ok")
        if path == "/__requests":
            p = parse_qs(u.query).get("path", [""])[0]
            with LOCK:
                n = COUNTS.get(p, 0)
            return self._send(200, json.dumps({"path": p, "count": n}), "application/json")
        if path == "/__manifest":
            return self._send(200, MANIFEST, "application/vnd.oci.image.manifest.v1+json")
        if path.startswith("/__sha256/slow/"):
            name = path[len("/__sha256"):]
            return self._send(200, hashlib.sha256(slow_body(name)).hexdigest())
        if path == "/v2/" or path == "/v2":
            return self._send(200, "{}", "application/json", {"Docker-Distribution-API-Version": "registry/2.0"})
        if path.startswith("/v2/") and "/manifests/" in path:
            return self._manifest(path, True)
        if path.startswith("/v2/") and path.endswith("/blobs/" + CONFIG_DIGEST):
            count(path)
            return self._send(200, CONFIG_BLOB, "application/octet-stream",
                              {"Docker-Content-Digest": CONFIG_DIGEST})
        if path.startswith("/slow/"):
            count(path)
            for ext, fn in CHECKSUMS.items():
                if path.endswith(ext):
                    return self._send(200, fn(slow_body(path[: -len(ext)])).hexdigest())
            data = slow_body(path)
            self.send_response(200)
            self.send_header("Content-Type", "application/java-archive")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            step = (len(data) + CHUNKS - 1) // CHUNKS
            pause = SLOW_SECS / CHUNKS
            try:
                for i in range(0, len(data), step):
                    self.wfile.write(data[i:i + step])
                    self.wfile.flush()
                    time.sleep(pause)
            except OSError:
                self.close_connection = True
            return
        return self._send(404, "not found")


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


if __name__ == "__main__":
    print(f"mock-ops: listening on :{PORT}", flush=True)
    Server(("0.0.0.0", PORT), Handler).serve_forever()
