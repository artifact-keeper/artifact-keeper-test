#!/usr/bin/env python3
# =============================================================================
# mock_ci_oidc.py -- a CI OIDC issuer for the DTF tier ci-oidc-exchange
# =============================================================================
# Plays a CI platform (GitLab / GitHub Actions shaped) for
# POST /api/v1/auth/ci/token. Stdlib only, one file, stock python image.
#
# TWO LISTENERS
#   HTTPS :443 (the issuer AK talks to; AK's CI OIDC discovery refuses http://)
#     GET /<iss>/.well-known/openid-configuration  {issuer, jwks_uri}
#     GET /<iss>/jwks                              the signing key's JWKS
#     <iss> is any single path segment, so one mock serves several issuers
#     (https://mock-ci-oidc/iss1, https://mock-ci-oidc/iss2, ...).
#     TLS material is generated at boot with the image's openssl into
#     MOCK_TLS_DIR (a volume the backend mounts read-only): a throwaway CA
#     (ca.crt, its key deleted right after signing) and a server certificate
#     for DNS:mock-ci-oidc. The backend trusts ca.crt through
#     CUSTOM_CA_CERT_PATH. Nothing secret is committed; every stack gets its
#     own CA.
#   HTTP :80 (the oracle's control port, published on 127.0.0.1:${TRIVY_PORT})
#     GET  /__readyz   "ok"
#     POST /mint       body {"claims": {...}, "key": "good" | "wrong",
#                            "kid": "<optional override>"}
#                      -> the compact RS256 JWT, as text/plain.
#                      The oracle chooses every claim (iss, aud, sub, exp, nbf,
#                      iat, repository, ...); the mock only signs. "good" signs
#                      with the key the JWKS publishes; "wrong" signs with a
#                      second key generated at boot that is published nowhere,
#                      under the SAME kid, so only the signature check can
#                      refuse it.
#     GET  /__requests -> {"discovery": N, "jwks": N} fetch counters.
#
# THE KEYS
#   "good" is the static RSA-2048 test keypair of
#   oidc-exchange-and-login/fixtures/mock_oidc.py (no security value; it exists
#   only to exercise AK's signature verification). "wrong" is a fresh
#   RSA-2048 pair generated at boot with a Miller-Rabin prime search (pure
#   Python, about a second).
# =============================================================================
import base64
import hashlib
import json
import os
import random
import ssl
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HTTP_PORT = int(os.environ.get("MOCK_HTTP_PORT", "80"))
HTTPS_PORT = int(os.environ.get("MOCK_HTTPS_PORT", "443"))
PUBLIC_BASE = os.environ.get("MOCK_PUBLIC_BASE", "https://mock-ci-oidc").rstrip("/")
TLS_DIR = os.environ.get("MOCK_TLS_DIR", "/tls")
TLS_HOST = os.environ.get("MOCK_TLS_HOST", "mock-ci-oidc")
CERT = os.path.join(TLS_DIR, "server.crt")
KEY = os.path.join(TLS_DIR, "server.key")
KID = "dtf-ci-oidc-key-1"

GOOD_N = 24499921756691674041864244875732876254420444691945723837024245461987965756515997487401055041768560334195560190857575667362289856442700981897312998279192999867070688667672736594555037600251653797363127362193598156049954923405125329217574334368180634836298236437296246670157078908060091457387280568920872362413092228020266979541430638461550253751092017660155824265324960841833280746033706892528524427883507933509153646386539949812279651595856357263948044976416530667991119414700007874532703546190333479352576582284039342365498033775092979205997845258514295919219547604858734320865756168480417719246368038717833058222391
GOOD_E = 65537
GOOD_D = 13682303680286178340971227893431546621172593736747386856815041639207768843378328395240529998759926579360628392898473677853118219415030531416477039489425268094889714287148056202766595605066001327242480758293569930137607003625853900077257436835305418847498595504906276273368464959259644892814356299838319246598221833013434813990932466220206715702420392965029583830131091912990278404347059377616010866506592275259054029286020943238463937483158598883943172194557289655154209599151129621047862509973523366945272928211087472292779548242368370096222122907337738349577599678957551004017800987557669125463650518843531429273

SHA256_DIGESTINFO = bytes.fromhex("3031300d060960864801650304020105000420")
COUNTS = {"discovery": 0, "jwks": 0}
COUNTS_LOCK = threading.Lock()


def _probable_prime(n: int) -> bool:
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    rng = random.SystemRandom()
    for _ in range(40):
        a = rng.randrange(2, n - 2)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _prime(bits: int) -> int:
    rng = random.SystemRandom()
    while True:
        c = rng.getrandbits(bits) | (1 << (bits - 1)) | (1 << (bits - 2)) | 1
        if _probable_prime(c):
            return c


def _keypair(bits: int = 2048):
    e = 65537
    while True:
        p, q = _prime(bits // 2), _prime(bits // 2)
        phi = (p - 1) * (q - 1)
        if p != q and phi % e != 0:
            n = p * q
            if n.bit_length() == bits:
                return n, e, pow(e, -1, phi)


WRONG_N, WRONG_E, WRONG_D = _keypair()
KEYS = {"good": (GOOD_N, GOOD_D), "wrong": (WRONG_N, WRONG_D)}


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_json(obj) -> str:
    return b64url(json.dumps(obj, separators=(",", ":")).encode("utf-8"))


def int_to_b64url(value: int) -> str:
    return b64url(value.to_bytes((value.bit_length() + 7) // 8, "big"))


def rs256_sign(signing_input: bytes, n: int, d: int) -> bytes:
    k = (n.bit_length() + 7) // 8
    t = SHA256_DIGESTINFO + hashlib.sha256(signing_input).digest()
    em = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    return pow(int.from_bytes(em, "big"), d, n).to_bytes(k, "big")


def mint(claims: dict, key: str, kid: str) -> str:
    n, d = KEYS[key]
    header = {"alg": "RS256", "typ": "JWT", "kid": kid}
    signing_input = f"{b64url_json(header)}.{b64url_json(claims)}".encode("ascii")
    return f"{signing_input.decode('ascii')}.{b64url(rs256_sign(signing_input, n, d))}"


JWKS = {
    "keys": [
        {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": KID,
            "n": int_to_b64url(GOOD_N),
            "e": int_to_b64url(GOOD_E),
        }
    ]
}


class Base(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, code, body: bytes, ctype: str):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code, obj):
        self._send(code, json.dumps(obj).encode("utf-8"), "application/json")

    def log_message(self, fmt, *args):
        pass


class IssuerHandler(Base):
    """HTTPS: discovery and JWKS for /<iss>/..."""

    def do_GET(self):
        parts = [p for p in self.path.split("?", 1)[0].split("/") if p]
        if len(parts) == 3 and parts[1:] == [".well-known", "openid-configuration"]:
            with COUNTS_LOCK:
                COUNTS["discovery"] += 1
            iss = f"{PUBLIC_BASE}/{parts[0]}"
            return self._json(
                200,
                {
                    "issuer": iss,
                    "jwks_uri": f"{iss}/jwks",
                    "id_token_signing_alg_values_supported": ["RS256"],
                    "response_types_supported": ["id_token"],
                    "subject_types_supported": ["public"],
                },
            )
        if len(parts) == 2 and parts[1] == "jwks":
            with COUNTS_LOCK:
                COUNTS["jwks"] += 1
            return self._json(200, JWKS)
        return self._json(404, {"error": "not_found", "path": self.path})


class ControlHandler(Base):
    """HTTP: readiness, minting, counters (the oracle's side door)."""

    def do_GET(self):
        if self.path == "/__readyz":
            return self._send(200, b"ok", "text/plain")
        if self.path == "/__requests":
            with COUNTS_LOCK:
                return self._json(200, dict(COUNTS))
        return self._json(404, {"error": "not_found"})

    def do_POST(self):
        if self.path != "/mint":
            return self._json(404, {"error": "not_found"})
        length = int(self.headers.get("Content-Length") or 0)
        try:
            req = json.loads(self.rfile.read(length) or b"{}")
            claims = req["claims"]
            key = req.get("key", "good")
            if key not in KEYS or not isinstance(claims, dict):
                raise ValueError("bad key or claims")
        except (ValueError, KeyError, TypeError) as e:
            return self._json(400, {"error": str(e)})
        return self._send(200, mint(claims, key, req.get("kid", KID)).encode("ascii"), "text/plain")


def make_tls_material():
    """A throwaway CA and a server certificate signed by it, via openssl.

    The CA key lives only in a temporary directory and is gone once the
    server certificate is signed. ca.crt is written last, so its presence
    means the set is complete (the backend reads it at boot).
    """
    os.makedirs(TLS_DIR, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        ca_key, ca_crt = os.path.join(tmp, "ca.key"), os.path.join(tmp, "ca.crt")
        csr, ext = os.path.join(tmp, "server.csr"), os.path.join(tmp, "ext")
        with open(ext, "w") as f:
            f.write(
                "basicConstraints=critical,CA:FALSE\n"
                "keyUsage=critical,digitalSignature,keyEncipherment\n"
                "extendedKeyUsage=serverAuth\n"
                f"subjectAltName=DNS:{TLS_HOST}\n"
            )

        def run(*argv):
            subprocess.run(argv, check=True, capture_output=True)

        run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", ca_key,
            "-out", ca_crt, "-days", "2", "-subj", "/CN=DTF ci-oidc-exchange throwaway CA",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign")
        run("openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", KEY, "-out", csr,
            "-subj", f"/CN={TLS_HOST}")
        run("openssl", "x509", "-req", "-in", csr, "-CA", ca_crt, "-CAkey", ca_key,
            "-CAcreateserial", "-out", CERT, "-days", "2", "-extfile", ext)
        for path in (CERT, KEY):
            os.chmod(path, 0o644)
        with open(ca_crt, "rb") as src, open(os.path.join(TLS_DIR, "ca.crt.tmp"), "wb") as dst:
            dst.write(src.read())
        os.chmod(os.path.join(TLS_DIR, "ca.crt.tmp"), 0o644)
        os.replace(os.path.join(TLS_DIR, "ca.crt.tmp"), os.path.join(TLS_DIR, "ca.crt"))


def serve_https():
    srv = ThreadingHTTPServer(("0.0.0.0", HTTPS_PORT), IssuerHandler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT, KEY)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    srv.serve_forever()


if __name__ == "__main__":
    make_tls_material()
    threading.Thread(target=serve_https, daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", HTTP_PORT), ControlHandler).serve_forever()
