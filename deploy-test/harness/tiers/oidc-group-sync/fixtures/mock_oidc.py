#!/usr/bin/env python3
# =============================================================================
# mock_oidc.py -- reusable headless OIDC Identity Provider for the DTF
# =============================================================================
# A tiny, stateless OpenID Connect provider that lets the DTF drive AK's real
# OIDC login -> callback flow WITHOUT a browser. It is the OIDC analogue of the
# SAML `sso` tier's Keycloak + probe: where SAML needs a live IdP that signs
# assertions, OIDC needs a live IdP that (a) publishes a discovery document and
# JWKS and (b) mints a signed `id_token` carrying attacker/operator-controlled
# claims (notably the `groups` claim) so group-sync behaviour can be asserted
# against the database.
#
# It is dependency-light on purpose (stdlib only, single file, stock python
# image), mirroring harness/tiers/pypi-contenttype/fixtures/mock_pypi.py:
#   * ID tokens are RS256-signed with a STATIC embedded RSA-2048 keypair using
#     pure-Python PKCS#1 v1.5 (hashlib + the builtin 3-arg pow). No PyJWT, no
#     `cryptography`, no key generation at boot. The JWKS exposes the matching
#     public key so AK's jsonwebtoken/aws_lc_rs path verifies the signature.
#   * 2048-bit modulus keeps it on AK's strict verification path (the sub-2048
#     legacy-RSA fallback is never engaged), so this mock also proves the
#     mainline signature check, not a compatibility shim.
#
# ---------------------------------------------------------------------------
# Headless flow (how the oracle drives login -> callback with no browser)
# ---------------------------------------------------------------------------
# AK generates the CSRF `state` and the replay `nonce` itself at
# /oidc/{id}/login and bakes them into the redirect to `authorization_endpoint`
# (this mock's /authorize). The oracle plays the user-agent:
#
#   1. GET AK /api/v1/auth/sso/oidc/{id}/login  -> 302 to
#      {MOCK_AUTHORIZE_URL}?...&state=S&nonce=Nc&redirect_uri=<AK callback>
#   2. The oracle re-issues that /authorize GET to THIS mock, appending the
#      per-case claim controls it wants this login to assert:
#          &sub=...&email=...&groups=a,b,c
#      (comma-separated; an explicit empty `groups=` means "no groups").
#   3. /authorize is STATELESS: it does not remember anything. It encodes the
#      claims it must later mint -- {nonce, sub, email, groups} -- into the
#      opaque `code` itself (base64url JSON), then 302s back to
#          {redirect_uri}?code=<opaque>&state=S
#      echoing AK's `state` verbatim so AK's CSRF/session lookup succeeds.
#   4. The oracle follows that 302 to AK's callback. AK (server-side) then
#      fetches this mock's /token with the `code`; /token decodes the code and
#      mints an id_token carrying exactly those claims (aud = the client_id AK
#      sends in the token request, iss = MOCK_ISSUER, nonce echoed so AK's
#      nonce check passes). AK verifies the signature against /jwks, extracts
#      the `groups` claim, and runs group sync.
#
# Because the claims ride inside the `code`, the oracle controls the groups (and
# which user) PER LOGIN with zero shared state and zero container restarts. Env
# vars (MOCK_OIDC_SUB / MOCK_OIDC_EMAIL / MOCK_OIDC_GROUPS) supply defaults when
# the query omits them.
#
# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
#   GET  /.well-known/openid-configuration  discovery (issuer + endpoints)
#   GET  /authorize                         302 back to redirect_uri w/ code
#   POST /token                             {access_token, id_token, token_type}
#   GET  /jwks                              public JWKS for the static key
#   GET  /__readyz                          readiness probe ("ok")
#
# ---------------------------------------------------------------------------
# Env
# ---------------------------------------------------------------------------
#   MOCK_PORT          listen port (default 80)
#   MOCK_ISSUER        issuer_url AK stores + fetches server-side; the `iss`
#                      claim. MUST equal the AK provider issuer_url exactly
#                      (e.g. http://mock-oidc).
#   MOCK_AUTHORIZE_URL browser/oracle-facing authorize endpoint advertised in
#                      discovery (e.g. http://127.0.0.1:8251/authorize). This
#                      is the ONE endpoint the user-agent hits, so it points at
#                      the slot's published host port; token/jwks stay on the
#                      docker-internal issuer host that AK reaches server-side.
#   MOCK_OIDC_SUB      default `sub` claim         (default dtf-oidc-user)
#   MOCK_OIDC_EMAIL    default `email` claim       (default dtf-oidc-user@dtf.test)
#   MOCK_OIDC_GROUPS   default groups, CSV         (default "")
#
# Nothing here is production code: it is a test double whose whole purpose is to
# emit claims a test tells it to. It never validates PKCE or the client secret;
# AK's behaviour, not the mock's rigour, is what the oracle asserts on.
# =============================================================================
import base64
import hashlib
import json
import os
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("MOCK_PORT", "80"))
ISSUER = os.environ.get("MOCK_ISSUER", "http://mock-oidc").rstrip("/")
AUTHORIZE_URL = os.environ.get("MOCK_AUTHORIZE_URL", f"{ISSUER}/authorize")
DEFAULT_SUB = os.environ.get("MOCK_OIDC_SUB", "dtf-oidc-user")
DEFAULT_EMAIL = os.environ.get("MOCK_OIDC_EMAIL", "dtf-oidc-user@dtf.test")
DEFAULT_GROUPS = os.environ.get("MOCK_OIDC_GROUPS", "")

KID = "dtf-oidc-mock-key-1"

# -----------------------------------------------------------------------------
# Static RSA-2048 keypair (test-only). Embedded so the mock needs no key
# generation and no crypto library: signing is s = pow(EM, D, N), verification
# is done by AK against the public (N, E) served at /jwks. This key is a fixture
# with NO security value; it exists solely to exercise AK's signature-verify.
# -----------------------------------------------------------------------------
RSA_N = 24499921756691674041864244875732876254420444691945723837024245461987965756515997487401055041768560334195560190857575667362289856442700981897312998279192999867070688667672736594555037600251653797363127362193598156049954923405125329217574334368180634836298236437296246670157078908060091457387280568920872362413092228020266979541430638461550253751092017660155824265324960841833280746033706892528524427883507933509153646386539949812279651595856357263948044976416530667991119414700007874532703546190333479352576582284039342365498033775092979205997845258514295919219547604858734320865756168480417719246368038717833058222391
RSA_E = 65537
RSA_D = 13682303680286178340971227893431546621172593736747386856815041639207768843378328395240529998759926579360628392898473677853118219415030531416477039489425268094889714287148056202766595605066001327242480758293569930137607003625853900077257436835305418847498595504906276273368464959259644892814356299838319246598221833013434813990932466220206715702420392965029583830131091912990278404347059377616010866506592275259054029286020943238463937483158598883943172194557289655154209599151129621047862509973523366945272928211087472292779548242368370096222122907337738349577599678957551004017800987557669125463650518843531429273

MODULUS_BYTES = (RSA_N.bit_length() + 7) // 8
# DER DigestInfo prefix for SHA-256 (RFC 8017 / PKCS#1 v1.5).
SHA256_DIGESTINFO = bytes.fromhex("3031300d060960864801650304020105000420")


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_json(obj) -> str:
    return b64url(json.dumps(obj, separators=(",", ":")).encode("utf-8"))


def b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def int_to_b64url(value: int) -> str:
    length = (value.bit_length() + 7) // 8
    return b64url(value.to_bytes(length, "big"))


def rs256_sign(signing_input: bytes) -> bytes:
    """PKCS#1 v1.5 RS256 signature over signing_input using the static key."""
    digest = hashlib.sha256(signing_input).digest()
    t = SHA256_DIGESTINFO + digest
    ps_len = MODULUS_BYTES - len(t) - 3
    em = b"\x00\x01" + (b"\xff" * ps_len) + b"\x00" + t
    m = int.from_bytes(em, "big")
    s = pow(m, RSA_D, RSA_N)
    return s.to_bytes(MODULUS_BYTES, "big")


def make_id_token(claims: dict) -> str:
    header = {"alg": "RS256", "typ": "JWT", "kid": KID}
    signing_input = f"{b64url_json(header)}.{b64url_json(claims)}".encode("ascii")
    sig = rs256_sign(signing_input)
    return f"{signing_input.decode('ascii')}.{b64url(sig)}"


def parse_groups(raw: str):
    """CSV -> list. An explicit empty string yields [] (no groups)."""
    if raw is None:
        return []
    return [g.strip() for g in raw.split(",") if g.strip()]


def encode_code(payload: dict) -> str:
    return b64url_json(payload)


def decode_code(code: str) -> dict:
    return json.loads(b64url_decode(code))


DISCOVERY = {
    "issuer": ISSUER,
    "authorization_endpoint": AUTHORIZE_URL,
    "token_endpoint": f"{ISSUER}/token",
    "jwks_uri": f"{ISSUER}/jwks",
    "response_types_supported": ["code"],
    "subject_types_supported": ["public"],
    "id_token_signing_alg_values_supported": ["RS256"],
    "scopes_supported": ["openid", "profile", "email", "groups"],
    "claims_supported": ["sub", "email", "preferred_username", "name", "groups"],
    "grant_types_supported": ["authorization_code"],
    "code_challenge_methods_supported": ["S256"],
}

JWKS = {
    "keys": [
        {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": KID,
            "n": int_to_b64url(RSA_N),
            "e": int_to_b64url(RSA_E),
        }
    ]
}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _json(self, code, obj):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _text(self, code, text):
        body = text.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _redirect(self, location):
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    # ---- GET -------------------------------------------------------------
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        if path == "/__readyz":
            return self._text(200, "ok")
        if path == "/.well-known/openid-configuration":
            return self._json(200, DISCOVERY)
        if path == "/jwks":
            return self._json(200, JWKS)
        if path == "/authorize":
            return self._authorize(urllib.parse.parse_qs(parsed.query))
        return self._text(404, "not found")

    # ---- POST ------------------------------------------------------------
    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/token":
            return self._token()
        return self._text(404, "not found")

    # ---- /authorize: mint an opaque code carrying this login's claims ----
    def _authorize(self, q):
        def one(name, default=None):
            vals = q.get(name)
            return vals[0] if vals else default

        redirect_uri = one("redirect_uri")
        state = one("state", "")
        nonce = one("nonce", "")
        if not redirect_uri:
            return self._text(400, "authorize: missing redirect_uri")

        # Per-login claim controls (query beats env default). `groups` present
        # but empty means "authenticate this user with NO group claim".
        sub = one("sub", DEFAULT_SUB)
        email = one("email", DEFAULT_EMAIL)
        groups_raw = one("groups", DEFAULT_GROUPS)

        code = encode_code(
            {
                "nonce": nonce,
                "sub": sub,
                "email": email,
                "groups": parse_groups(groups_raw),
            }
        )
        sep = "&" if urllib.parse.urlparse(redirect_uri).query else "?"
        location = (
            f"{redirect_uri}{sep}code={urllib.parse.quote(code)}"
            f"&state={urllib.parse.quote(state)}"
        )
        return self._redirect(location)

    # ---- /token: exchange the code for a signed id_token -----------------
    def _token(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length).decode("utf-8") if length else ""
        form = urllib.parse.parse_qs(body)

        def formone(name, default=""):
            vals = form.get(name)
            return vals[0] if vals else default

        code = formone("code")
        # aud MUST equal the client_id AK sends, or AK's set_audience check
        # rejects the token. AK includes client_id in the token-exchange form.
        client_id = formone("client_id", "dtf-oidc-client")
        if not code:
            return self._json(400, {"error": "invalid_request", "error_description": "missing code"})

        try:
            payload = decode_code(code)
        except Exception as exc:  # noqa: BLE001 - test double, surface as 400
            return self._json(
                400, {"error": "invalid_grant", "error_description": f"bad code: {exc}"}
            )

        now = int(time.time())
        sub = payload.get("sub", DEFAULT_SUB)
        claims = {
            "iss": ISSUER,
            "sub": sub,
            "aud": client_id,
            "iat": now,
            "nbf": now,
            "exp": now + 3600,
            "nonce": payload.get("nonce", ""),
            "email": payload.get("email", ""),
            "email_verified": True,
            "preferred_username": sub,
            "name": sub,
            "groups": payload.get("groups", []),
        }
        id_token = make_id_token(claims)
        return self._json(
            200,
            {
                "access_token": f"dtf-oidc-access-{now}",
                "token_type": "Bearer",
                "expires_in": 3600,
                "id_token": id_token,
                "scope": "openid profile email groups",
            },
        )

    def log_message(self, fmt, *args):
        # Quiet: the oracle asserts on AK's DB/HTTP behaviour, not mock stderr.
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
