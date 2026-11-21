"""Private TLS scanner fixture with an atomic CA publisher on its control port."""

import os
import ssl
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

TRUST = Path(os.environ.get("MOCK_TRUST_DIR", "/trust"))
HOSTNAME = "mock-ca-scanner"


def make_identity(directory, name):
    ca_key = directory / f"{name}.ca.key"
    ca_cert = directory / f"{name}.ca.pem"
    leaf_key = directory / f"{name}.leaf.key"
    leaf_cert = directory / f"{name}.leaf.pem"
    csr = directory / f"{name}.csr"
    ext = directory / "leaf.ext"
    ext.write_text(f"subjectAltName=DNS:{HOSTNAME}\nextendedKeyUsage=serverAuth\n")

    def openssl(*args):
        subprocess.run(
            ["openssl", *args], check=True, stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE, timeout=15,
        )

    openssl(
        "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
        "-subj", f"/CN=DTF rotation CA {name}", "-addext", "basicConstraints=critical,CA:TRUE",
        "-keyout", ca_key, "-out", ca_cert,
    )
    openssl(
        "req", "-newkey", "rsa:2048", "-nodes", "-subj", f"/CN={HOSTNAME}",
        "-keyout", leaf_key, "-out", csr,
    )
    openssl(
        "x509", "-req", "-days", "1", "-in", csr, "-CA", ca_cert, "-CAkey", ca_key,
        "-CAcreateserial", "-extfile", ext, "-out", leaf_cert,
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(leaf_cert, leaf_key)
    return ca_cert.read_bytes(), context


def publish(roots):
    # Staging in the mounted directory keeps rename atomic for the backend.
    with tempfile.NamedTemporaryFile(dir=TRUST, delete=False) as staged:
        staged.write(roots)
        os.fchmod(staged.fileno(), 0o644)
    os.replace(staged.name, TRUST / "ca-bundle.pem")


class Handler(BaseHTTPRequestHandler):
    def respond(self, status, body=b"ok"):
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class ProbeHandler(Handler):
    # A fresh TLS handshake each time isolates trust changes from HTTP reuse.
    def do_GET(self):
        self.respond(200 if self.path == "/healthz" else 404)


def main():
    TRUST.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as work:
        identities = {name: make_identity(Path(work), name) for name in ("a", "b")}
    selected = "a"
    publish(identities[selected][0])

    class ControlHandler(Handler):
        def do_GET(self):
            self.respond(200 if self.path == "/__readyz" else 404)

        def do_POST(self):
            nonlocal selected
            if self.path in ("/leaf/a", "/leaf/b"):
                selected = self.path[-1]
            elif self.path in ("/bundle/a", "/bundle/ab", "/bundle/b"):
                publish(b"".join(identities[name][0] for name in self.path.rsplit("/", 1)[1]))
            else:
                self.respond(404)
                return
            self.respond(200)

    https = ThreadingHTTPServer(("", int(os.environ.get("MOCK_HTTPS_PORT", "443"))), ProbeHandler)
    listener_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    def choose_leaf(connection, _hostname, _context):
        connection.context = identities[selected][1]

    listener_context.sni_callback = choose_leaf
    https.socket = listener_context.wrap_socket(https.socket, server_side=True)
    threading.Thread(target=https.serve_forever, daemon=True).start()
    ThreadingHTTPServer(
        ("", int(os.environ.get("MOCK_CONTROL_PORT", "80"))), ControlHandler
    ).serve_forever()


if __name__ == "__main__":
    main()
