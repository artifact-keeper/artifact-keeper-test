#!/usr/bin/env python3
"""A read-only OCI registry for DTF scanner-adapter tiers (stdlib only).

usage: ocireg.py [PORT]      (default 5000; data under /data, state under /tmp)

Content: the oracle builds a data directory with mkimage.py and copies it in
with `docker cp DIR <container>:/data`:
  /data/blobs/<hex>                    blob bytes (manifests are blobs too)
  /data/manifests/<repo with / as __>/<tag>   manifest bytes for a tag

Serves GET/HEAD /v2/, /v2/<repo>/manifests/<tag|digest>, /v2/<repo>/blobs/<digest>.
Every host name the container answers to (network aliases) serves the same
content, so several "registries" can share one container.

Request log: every request is appended to /tmp/reqlog as
  <epoch-ms> <method> <host header> <path>
and the first manifest request of each (host, repo) to /tmp/arrivals as
  <epoch-ms> <host header> <repo>
so the oracle can tell in which order scans reached the registry.

Holds: a manifest request for a repository whose last path element starts
with "hold-" blocks until /tmp/release/<repo with / as __> exists (or 240 s
pass, then it answers 503). The oracle releases a scan with
`docker exec <container> touch /tmp/release/<name>`.
"""
import hashlib, json, os, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DATA = "/data"
LOG_LOCK = threading.Lock()
SEEN = set()
os.makedirs("/tmp/release", exist_ok=True)
open("/tmp/reqlog", "a").close()
open("/tmp/arrivals", "a").close()


def now_ms():
    return int(time.time() * 1000)


def append(path, line):
    with LOG_LOCK:
        with open(path, "a") as f:
            f.write(line + "\n")


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def send(self, code, body=b"", ctype="application/octet-stream", extra=None, head=False):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Docker-Distribution-API-Version", "registry/2.0")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if not head:
            self.wfile.write(body)

    def handle_req(self, head):
        host = self.headers.get("Host", "")
        path = self.path.split("?", 1)[0]
        append("/tmp/reqlog", f"{now_ms()} {self.command} {host} {path}")
        if path in ("/v2", "/v2/"):
            return self.send(200, b"{}", "application/json", head=head)
        if not path.startswith("/v2/"):
            return self.send(404, b"not found", "text/plain", head=head)
        rest = path[4:]
        for kind in ("/manifests/", "/blobs/"):
            if kind in rest:
                repo, ref = rest.rsplit(kind, 1)
                break
        else:
            return self.send(404, b"not found", "text/plain", head=head)
        key = repo.replace("/", "__")
        if kind == "/blobs/":
            p = os.path.join(DATA, "blobs", ref.split(":", 1)[-1])
            if not os.path.isfile(p):
                return self.send(404, b'{"errors":[{"code":"BLOB_UNKNOWN"}]}', "application/json", head=head)
            body = open(p, "rb").read()
            return self.send(200, body, "application/octet-stream", {"Docker-Content-Digest": ref}, head=head)
        # manifests
        with LOG_LOCK:
            first = (host, repo) not in SEEN
            SEEN.add((host, repo))
        if first:
            append("/tmp/arrivals", f"{now_ms()} {host} {repo}")
        if repo.rsplit("/", 1)[-1].startswith("hold-"):
            deadline = time.time() + 240
            while not os.path.exists(os.path.join("/tmp/release", key)):
                if time.time() > deadline:
                    return self.send(503, b"held too long", "text/plain", head=head)
                time.sleep(0.1)
        if ref.startswith("sha256:"):
            p = os.path.join(DATA, "blobs", ref.split(":", 1)[1])
        else:
            p = os.path.join(DATA, "manifests", key, ref)
        if not os.path.isfile(p):
            return self.send(404, b'{"errors":[{"code":"MANIFEST_UNKNOWN"}]}', "application/json", head=head)
        body = open(p, "rb").read()
        mt = json.loads(body).get("mediaType", "application/vnd.oci.image.manifest.v1+json")
        dg = "sha256:" + hashlib.sha256(body).hexdigest()
        return self.send(200, body, mt, {"Docker-Content-Digest": dg}, head=head)

    def do_GET(self):
        self.handle_req(False)

    def do_HEAD(self):
        self.handle_req(True)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
    ThreadingHTTPServer.daemon_threads = True
    ThreadingHTTPServer(("0.0.0.0", port), H).serve_forever()
