#!/usr/bin/env python3
# =============================================================================
# mock_osv.py -- an OSV.dev stand-in for the DTF scanner tiers
# =============================================================================
# The backend's dependency scanner (AdvisoryClient in scanner_service.rs) asks
# the hard-coded https://api.osv.dev/v1/querybatch and, since 1.11.0 (#4150),
# fetches each matched record from https://api.osv.dev/v1/vulns/{id}. The
# upstreams.mock-osv profile resolves api.osv.dev to this container
# (extra_hosts) and makes the backend trust this mock's throwaway CA through
# CUSTOM_CA_CERT_PATH, so every advisory answer is one the oracle chose.
# Stdlib only, one file, stock python image.
#
# TWO LISTENERS
#   HTTPS :443 (what the backend talks to, as api.osv.dev)
#     POST /v1/querybatch  {"queries":[{"package":{"name","ecosystem"},
#                          "version"}, ...]} -> {"results":[{"vulns":[{"id",
#                          "modified"}]} | {}, ...]}, ONE RESULT PER QUERY IN
#                          QUERY ORDER, exactly the real API's positional
#                          contract, and as skeletal as the real API (id and
#                          modified only; no aliases, summary or fix).
#     GET  /v1/vulns/{id}  the full record the oracle registered, 404 if none.
#   HTTP :80 (the oracle's control port, published on 127.0.0.1:${TRIVY_PORT})
#     GET  /__readyz       "ok" once the TLS material exists
#     PUT  /__advisories   {"rules":[{"ecosystem","name","version"?,"ids":[..]}],
#                           "records":{"<id>":{full OSV record}}}
#                          replaces the advisory set. A rule without "version"
#                          matches every version; ecosystem/name compare
#                          case-insensitively.
#     PUT  /__mode         body "ok" | "down" | "records-down"
#                          down: querybatch answers 503 (a feed outage);
#                          records-down: /v1/vulns answers 503.
#     GET  /__requests     every HTTPS request so far, as a JSON array of
#                          {"method","path","body"} (body parsed when JSON)
#     POST /__reset        clears the request log
#   The advisory set and the mode are also the control files
#   ${MOCK_STATE_DIR}/advisories.json and ${MOCK_STATE_DIR}/mode, re-read on
#   every request, so `docker exec` can flip them as well.
#
# TLS: a throwaway CA and a server certificate for DNS:api.osv.dev are made at
# boot with the image's openssl into MOCK_TLS_DIR (a volume the backend mounts
# read-only); the CA key is deleted once it has signed. Nothing secret is
# committed; every stack gets its own CA.
# =============================================================================
import json
import os
import ssl
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HTTP_PORT = int(os.environ.get("MOCK_HTTP_PORT", "80"))
HTTPS_PORT = int(os.environ.get("MOCK_HTTPS_PORT", "443"))
TLS_DIR = os.environ.get("MOCK_TLS_DIR", "/tls")
TLS_HOSTS = [h for h in os.environ.get("MOCK_TLS_HOSTS", "api.osv.dev").split(",") if h]
STATE_DIR = os.environ.get("MOCK_STATE_DIR", "/state")
CERT = os.path.join(TLS_DIR, "server.crt")
KEY = os.path.join(TLS_DIR, "server.key")
ADVISORIES = os.path.join(STATE_DIR, "advisories.json")
MODE = os.path.join(STATE_DIR, "mode")
MODIFIED = "2026-01-01T00:00:00Z"

LOCK = threading.Lock()
REQUESTS = []


def write_atomic(path, data):
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, path)


def load_advisories():
    try:
        with open(ADVISORIES, "rb") as f:
            doc = json.loads(f.read() or b"{}")
    except (OSError, ValueError):
        doc = {}
    return doc.get("rules") or [], doc.get("records") or {}


def mode():
    try:
        with open(MODE) as f:
            return f.read().strip() or "ok"
    except OSError:
        return "ok"


def ids_for(rules, query):
    pkg = query.get("package") or {}
    name = (pkg.get("name") or "").lower()
    eco = (pkg.get("ecosystem") or "").lower()
    version = query.get("version")
    out = []
    for rule in rules:
        if (rule.get("name") or "").lower() != name:
            continue
        r_eco = (rule.get("ecosystem") or "").lower()
        if r_eco and eco and r_eco != eco:
            continue
        if rule.get("version") is not None and rule.get("version") != version:
            continue
        for vid in rule.get("ids") or []:
            if vid not in out:
                out.append(vid)
    return out


class Base(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # quiet
        pass

    def _send(self, code, body, ctype="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code, obj):
        self._send(code, json.dumps(obj).encode())

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n else b""


class OsvHandler(Base):
    def _record(self, method, raw):
        try:
            body = json.loads(raw) if raw else None
        except ValueError:
            body = raw.decode("utf-8", "replace")
        with LOCK:
            REQUESTS.append({"method": method, "path": self.path, "body": body})
        return body

    def do_POST(self):
        body = self._record("POST", self._body())
        if self.path.split("?")[0] != "/v1/querybatch":
            return self._json(404, {"code": 5, "message": "Not Found"})
        if mode() == "down":
            return self._json(503, {"code": 14, "message": "unavailable (dtf mock outage)"})
        rules, _ = load_advisories()
        queries = (body or {}).get("queries") or [] if isinstance(body, dict) else []
        results = []
        for q in queries:
            ids = ids_for(rules, q)
            results.append({"vulns": [{"id": i, "modified": MODIFIED} for i in ids]} if ids else {})
        return self._json(200, {"results": results})

    def do_GET(self):
        self._record("GET", b"")
        path = self.path.split("?")[0]
        if not path.startswith("/v1/vulns/"):
            return self._json(404, {"code": 5, "message": "Not Found"})
        if mode() == "records-down":
            return self._json(503, {"code": 14, "message": "unavailable (dtf mock outage)"})
        _, records = load_advisories()
        rec = records.get(path[len("/v1/vulns/"):])
        if rec is None:
            return self._json(404, {"code": 5, "message": "Bug not found."})
        return self._json(200, rec)


class ControlHandler(Base):
    def do_GET(self):
        if self.path == "/__readyz":
            ok = os.path.exists(os.path.join(TLS_DIR, "ca.crt"))
            return self._send(200 if ok else 503, b"ok" if ok else b"no", "text/plain")
        if self.path == "/__requests":
            with LOCK:
                return self._json(200, list(REQUESTS))
        return self._json(404, {"error": "unknown control path"})

    def do_PUT(self):
        raw = self._body()
        if self.path == "/__advisories":
            try:
                doc = json.loads(raw)
                assert isinstance(doc, dict)
            except (ValueError, AssertionError):
                return self._json(400, {"error": "body must be a JSON object"})
            write_atomic(ADVISORIES, json.dumps(doc).encode())
            return self._json(200, {"rules": len(doc.get("rules") or []),
                                    "records": len(doc.get("records") or {})})
        if self.path == "/__mode":
            m = raw.decode().strip()
            if m not in ("ok", "down", "records-down"):
                return self._json(400, {"error": "mode must be ok, down or records-down"})
            write_atomic(MODE, m.encode())
            return self._json(200, {"mode": m})
        return self._json(404, {"error": "unknown control path"})

    def do_POST(self):
        self._body()
        if self.path == "/__reset":
            with LOCK:
                REQUESTS.clear()
            return self._json(200, {"reset": True})
        return self._json(404, {"error": "unknown control path"})


def make_tls_material():
    """A throwaway CA and a server certificate signed by it, via openssl.

    ca.crt is written last, so its presence means the set is complete (the
    backend reads it at boot).
    """
    os.makedirs(TLS_DIR, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        ca_key, ca_crt = os.path.join(tmp, "ca.key"), os.path.join(tmp, "ca.crt")
        csr, ext = os.path.join(tmp, "server.csr"), os.path.join(tmp, "ext")
        san = ",".join(f"DNS:{h}" for h in TLS_HOSTS)
        with open(ext, "w") as f:
            f.write(
                "basicConstraints=critical,CA:FALSE\n"
                "keyUsage=critical,digitalSignature,keyEncipherment\n"
                "extendedKeyUsage=serverAuth\n"
                f"subjectAltName={san}\n"
            )

        def run(*argv):
            subprocess.run(argv, check=True, capture_output=True)

        run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", ca_key,
            "-out", ca_crt, "-days", "2", "-subj", "/CN=DTF mock-osv throwaway CA",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign")
        run("openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", KEY, "-out", csr,
            "-subj", f"/CN={TLS_HOSTS[0]}")
        run("openssl", "x509", "-req", "-in", csr, "-CA", ca_crt, "-CAkey", ca_key,
            "-CAcreateserial", "-out", CERT, "-days", "2", "-extfile", ext)
        for path in (CERT, KEY):
            os.chmod(path, 0o644)
        with open(ca_crt, "rb") as src:
            write_atomic(os.path.join(TLS_DIR, "ca.crt"), src.read())
        os.chmod(os.path.join(TLS_DIR, "ca.crt"), 0o644)


def serve_https():
    srv = ThreadingHTTPServer(("0.0.0.0", HTTPS_PORT), OsvHandler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT, KEY)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    srv.serve_forever()


if __name__ == "__main__":
    os.makedirs(STATE_DIR, exist_ok=True)
    if not os.path.exists(MODE):
        write_atomic(MODE, b"ok")
    make_tls_material()
    threading.Thread(target=serve_https, daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", HTTP_PORT), ControlHandler).serve_forever()
