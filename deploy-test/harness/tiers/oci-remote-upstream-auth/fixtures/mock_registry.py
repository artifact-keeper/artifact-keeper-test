#!/usr/bin/env python3
"""Mock OCI registry with a token service, for the oci-remote-upstream-auth tier.

stdlib only. One process, three listeners on the same host name (`mockreg`):

  :5000  http   the registry (/v2/...) plus the same-origin token service
                (/token) and the oracle's control endpoints (/__log, /__readyz)
  :5001  http   a CROSS-ORIGIN token service (different port = different origin)
  :5443  https  a cross-origin token service on TLS, for oci_trusted_bearer_realms
                (which accepts https origins only). The CA and leaf certificate
                are generated at start into $CERT_DIR (shared with the backend,
                which trusts the CA through CUSTOM_CA_CERT_PATH).

Behaviour is selected by the first path segment of the image name in
/v2/<image>/manifests/<ref> (GET and HEAD):

  good/*       Bearer challenge, same-origin realm. Token only for the good
               Basic credentials; the registry serves the manifest for that
               token.                                   (positive control)
  tokrefuse/*  Bearer challenge, same-origin realm. The token service answers
               401 to every request.                    (#4453)
  manrefuse/*  Bearer challenge, same-origin realm. The token service issues a
               token to anyone; the registry refuses every token with 401.
                                                        (#4518)
  basic/*      Basic challenge. The manifest is served for the good Basic
               credentials, anything else is 401.       (#4518 Basic)
  xorigin/*    Bearer challenge whose realm is http://mockreg:5001/token. Any
               token is refused by the registry (the image "does not exist").
                                                        (#4527 / #3591)
  trusted/*    Bearer challenge whose realm is https://mockreg:5443/token. The
               token service issues a GOOD token only for the good Basic
               credentials and an anonymous token otherwise; the registry
               serves the manifest only for the good token.  (#3591)

Every token request is recorded with its port, scope and whether (and for whom)
an Authorization header was presented; every registry request is recorded too.
GET /__log returns the records as JSON.
"""
import base64
import hashlib
import json
import os
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HOST = os.environ.get("MOCK_HOST", "mockreg")
GOOD_USER = os.environ.get("MOCK_GOOD_USER", "gooduser")
GOOD_PASS = os.environ.get("MOCK_GOOD_PASS", "goodpass")
CERT_DIR = os.environ.get("CERT_DIR", "/certs")

MANIFEST = json.dumps({
    "schemaVersion": 2,
    "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
    "config": {"mediaType": "application/vnd.docker.container.image.v1+json", "size": 2,
               "digest": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"},
    "layers": [],
}, separators=(",", ":")).encode()
MANIFEST_DIGEST = "sha256:" + hashlib.sha256(MANIFEST).hexdigest()
GOOD_TOKEN = "tok-good"
LOCK = threading.Lock()
RECORDS = []


def record(entry):
    with LOCK:
        RECORDS.append(entry)


def basic_user(header):
    """(user, password) from a Basic Authorization header, or None."""
    if not header or not header.lower().startswith("basic "):
        return None
    try:
        user, _, pw = base64.b64decode(header[6:].strip()).decode().partition(":")
        return user, pw
    except Exception:
        return None


def make_handler(port):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):
            pass

        def send(self, code, body=b"", headers=None, head=False):
            self.send_response(code)
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if not head:
                self.wfile.write(body)

        def challenge_bearer(self, realm, image, head):
            err = json.dumps({"errors": [{"code": "UNAUTHORIZED", "message": "authentication required"}]}).encode()
            self.send(401, err, {
                "Content-Type": "application/json",
                "WWW-Authenticate": f'Bearer realm="{realm}",service="{HOST}",scope="repository:{image}:pull"',
            }, head)

        def token(self):
            q = parse_qs(urlparse(self.path).query)
            scope = (q.get("scope") or [""])[0]
            auth = self.headers.get("Authorization")
            creds = basic_user(auth)
            record({"kind": "token", "port": port, "scope": scope,
                    "auth": bool(auth), "user": creds[0] if creds else None})
            image = scope.split(":")[1] if scope.count(":") >= 2 else ""
            mode = image.split("/")[0]
            good = creds == (GOOD_USER, GOOD_PASS)
            if mode == "tokrefuse":
                return self.send(401, b'{"details":"bad credentials"}', {"Content-Type": "application/json"})
            if mode in ("good", "trusted") and not good:
                if mode == "trusted":
                    tok = "tok-anon"
                else:
                    return self.send(401, b'{"details":"bad credentials"}', {"Content-Type": "application/json"})
            else:
                tok = GOOD_TOKEN if good else "tok-anon"
            body = json.dumps({"token": tok, "access_token": tok, "expires_in": 300}).encode()
            self.send(200, body, {"Content-Type": "application/json"})

        def registry(self, head):
            path = urlparse(self.path).path
            auth = self.headers.get("Authorization") or ""
            if path in ("/v2", "/v2/"):
                return self.send(200, b"{}", {"Content-Type": "application/json"}, head)
            if "/manifests/" not in path:
                return self.send(404, b'{"errors":[{"code":"NAME_UNKNOWN"}]}', {"Content-Type": "application/json"}, head)
            image = path[len("/v2/"):].split("/manifests/")[0]
            mode = image.split("/")[0]
            record({"kind": "registry", "port": port, "method": self.command, "image": image,
                    "auth": auth.split(" ")[0].lower() if auth else None})
            ok_headers = {"Content-Type": "application/vnd.docker.distribution.manifest.v2+json",
                          "Docker-Content-Digest": MANIFEST_DIGEST}
            if mode == "basic":
                if basic_user(auth) == (GOOD_USER, GOOD_PASS):
                    return self.send(200, MANIFEST, ok_headers, head)
                return self.send(401, b'{"errors":[{"code":"UNAUTHORIZED"}]}', {
                    "Content-Type": "application/json", "WWW-Authenticate": f'Basic realm="{HOST}"'}, head)
            realm = {"xorigin": f"http://{HOST}:5001/token",
                     "trusted": f"https://{HOST}:5443/token"}.get(mode, f"http://{HOST}:5000/token")
            bearer = auth[7:].strip() if auth.lower().startswith("bearer ") else None
            if bearer is None:
                return self.challenge_bearer(realm, image, head)
            if mode in ("good", "trusted") and bearer == GOOD_TOKEN:
                return self.send(200, MANIFEST, ok_headers, head)
            # manrefuse / xorigin / an anonymous token for good|trusted: refused
            return self.challenge_bearer(realm, image, head)

        def do_GET(self):
            path = urlparse(self.path).path
            if path == "/__readyz":
                return self.send(200, b"ok")
            if path == "/__log":
                with LOCK:
                    body = json.dumps(RECORDS).encode()
                return self.send(200, body, {"Content-Type": "application/json"})
            if path == "/token":
                return self.token()
            return self.registry(False)

        def do_HEAD(self):
            return self.registry(True)

    return Handler


def gen_certs():
    os.makedirs(CERT_DIR, exist_ok=True)
    ca_key, ca = f"{CERT_DIR}/ca.key", f"{CERT_DIR}/ca.pem"
    key, csr, crt = f"{CERT_DIR}/leaf.key", f"{CERT_DIR}/leaf.csr", f"{CERT_DIR}/leaf.pem"
    ext = f"{CERT_DIR}/leaf.ext"
    run = lambda *a: subprocess.run(list(a), check=True, capture_output=True)
    run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", ca_key, "-out", ca,
        "-days", "2", "-subj", "/CN=dtf-mockreg-ca",
        "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    run("openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", csr, "-subj", f"/CN={HOST}")
    with open(ext, "w") as f:
        f.write(f"subjectAltName=DNS:{HOST}\nbasicConstraints=CA:FALSE\n"
                "keyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n")
    run("openssl", "x509", "-req", "-in", csr, "-CA", ca, "-CAkey", ca_key, "-CAcreateserial",
        "-out", crt, "-days", "2", "-extfile", ext)
    for p in (ca, crt):
        os.chmod(p, 0o644)
    return crt, key


def serve(port, tls=None):
    srv = ThreadingHTTPServer(("0.0.0.0", port), make_handler(port))
    if tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(*tls)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()


if __name__ == "__main__":
    tls = gen_certs()
    serve(5001)
    serve(5443, tls)
    serve(5000)
    threading.Event().wait()
