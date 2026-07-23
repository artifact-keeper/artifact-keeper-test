#!/usr/bin/env python3
# =============================================================================
# mock_oidc.py -- reusable headless OIDC Identity Provider for the DTF
# =============================================================================
# A tiny, stateless OpenID Connect provider that lets the DTF drive AK's real
# OIDC login -> callback flow WITHOUT a browser. It is the OIDC analogue of the
# SAML `sso` tier's Keycloak + probe: where SAML needs a live IdP that signs
# assertions, OIDC needs a live IdP that (a) publishes a discovery document and
# JWKS, (b) mints a signed `id_token` carrying attacker/operator-controlled
# claims, and (c) -- for #2831 -- answers `/oauth/userinfo` with a group set
# that can DIFFER from the id_token (to emulate GitLab, whose id_token carries
# only DIRECT memberships under `groups_direct` while `/oauth/userinfo` returns
# the full EFFECTIVE set incl. inherited subgroups under `groups`).
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
#      per-case claim controls it wants this login to assert (see the /authorize
#      query table below).
#   3. /authorize is STATELESS: it does not remember anything. It encodes the
#      claims it must later mint -- {nonce, sub, email, iss, claims_spec,
#      userinfo} -- into the opaque `code` itself (base64url JSON), then 302s
#      back to {redirect_uri}?code=<opaque>&state=S echoing AK's `state`.
#   4. The oracle follows that 302 to AK's callback. AK (server-side) fetches
#      this mock's /token with the `code`; /token decodes the code and mints an
#      id_token carrying exactly the specified group claims plus an `access_token`
#      that itself carries the baked userinfo spec (still stateless). AK verifies
#      the id_token signature against /jwks, extracts groups from the id_token,
#      then -- for #2831 -- fetches /oauth/userinfo with that access_token and
#      merges the two group sets before running group sync.
#
# Because the claims ride inside the `code` (id_token) and the `access_token`
# (userinfo), the oracle controls both group sources PER LOGIN with zero shared
# state and zero container restarts.
#
# ---------------------------------------------------------------------------
# /authorize query interface (all optional; defaults preserve prior behaviour)
# ---------------------------------------------------------------------------
#   sub, email            the user (default from env)
#   iss                   `iss` claim baked into the id_token; MUST equal the
#                         AK provider issuer_url. Default MOCK_ISSUER. Used by
#                         the SSRF case, whose provider issuer is a sub-path.
#   groups                CSV values for the PRIMARY id_token group claim.
#   groups_claim          name of the primary claim (default `groups`).
#   groups_shape          `array` (default) or `string` (single JSON string,
#                         no CSV split -- a GitLab path stays intact).
#   groups2               CSV values for an optional SECOND id_token claim,
#                         emitted simultaneously (precedence tests).
#   groups_claim2         name of the second claim (default `groups_direct`).
#   groups_shape2         shape of the second claim (default `array`).
#   ui_groups             CSV values returned by /oauth/userinfo under
#                         `ui_groups_claim`. Unset => mirror the primary id_token
#                         values (so cases that never assert on userinfo are a
#                         union no-op).
#   ui_groups_claim       userinfo claim name (default `groups`, as GitLab).
#   ui_status             forced /oauth/userinfo HTTP status (default 200; set
#                         500 to drive the userinfo-DOWN graceful-degrade case).
#
# EMISSION RULE (faithfulness): /token emits ONLY the id_token claim keys that
# were specified. `groups_claim=groups_direct` yields `"groups_direct":[...]`
# and NO `groups` key -- letting the candidate fallback + explicit-override be
# tested honestly.
#
# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
#   GET  /.well-known/openid-configuration  discovery (issuer + endpoints)
#   GET  <prefix>/.well-known/openid-configuration  per-issuer discovery; when
#        <prefix> == MOCK_SSRF_ISSUER_PREFIX the advertised userinfo_endpoint is
#        an internal/blocked host (drives the userinfo SSRF-guard case).
#   GET  /authorize                         302 back to redirect_uri w/ code
#   POST /token                             {access_token, id_token, token_type}
#   GET  /oauth/userinfo                     Bearer access_token -> {sub, groups}
#   GET  /jwks                              public JWKS for the static key
#   GET  /__readyz                          readiness probe ("ok")
#
# ---------------------------------------------------------------------------
# Env
# ---------------------------------------------------------------------------
#   MOCK_PORT               listen port (default 80)
#   MOCK_ISSUER             issuer_url AK stores + fetches server-side; the base
#                           `iss` claim. MUST equal the AK provider issuer_url.
#   MOCK_AUTHORIZE_URL      browser/oracle-facing authorize endpoint advertised
#                           in discovery (the slot's published host port).
#   MOCK_OIDC_SUB/EMAIL/GROUPS  fixture defaults for sub/email/groups.
#   MOCK_SSRF_ISSUER_PREFIX issuer sub-path whose discovery advertises a blocked
#                           userinfo_endpoint (default `/ssrf`).
#   MOCK_SSRF_USERINFO      the blocked userinfo_endpoint advertised for that
#                           prefix (default a link-local metadata host).
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

# #2831: a provider whose issuer_url is ISSUER + this prefix gets a discovery
# doc advertising a userinfo_endpoint on an internal/blocked host, so the DTF
# can prove AK refuses the userinfo fetch via validate_oidc_fetch_url (SEC-1)
# and still logs the user in on id_token groups alone.
SSRF_ISSUER_PREFIX = os.environ.get("MOCK_SSRF_ISSUER_PREFIX", "/ssrf")
SSRF_USERINFO = os.environ.get(
    "MOCK_SSRF_USERINFO", "http://169.254.169.254/oauth/userinfo"
)
BASE_USERINFO = f"{ISSUER}/oauth/userinfo"

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


def emit_claim(claims: dict, name: str, shape: str, vals: list):
    """Apply one {name, shape, vals} spec entry to an id_token claims dict.

    `array` -> the key is a JSON array (possibly []); `string` -> the key is a
    single JSON string (the first value), omitted entirely when there are no
    values. Only the specified key is written, so an unspecified `groups`
    stays ABSENT rather than an empty array (candidate-fallback fidelity).
    """
    if shape == "string":
        if vals:
            claims[name] = vals[0]
    else:
        claims[name] = vals


def encode_code(payload: dict) -> str:
    return b64url_json(payload)


def decode_code(code: str) -> dict:
    return json.loads(b64url_decode(code))


ACCESS_TOKEN_PREFIX = "at."


def encode_access_token(payload: dict) -> str:
    """Bake the userinfo spec into the opaque access_token (stateless)."""
    return ACCESS_TOKEN_PREFIX + b64url_json(payload)


def decode_access_token(token: str):
    if not token or not token.startswith(ACCESS_TOKEN_PREFIX):
        return None
    try:
        return json.loads(b64url_decode(token[len(ACCESS_TOKEN_PREFIX):]))
    except Exception:  # noqa: BLE001 - test double
        return None


def build_discovery(prefix: str) -> dict:
    """Discovery doc for issuer ISSUER+prefix.

    token_endpoint/jwks_uri/authorization_endpoint stay on the base host (they
    work for every issuer). Only the advertised userinfo_endpoint varies: the
    SSRF-probe prefix advertises an internal/blocked host so AK's userinfo
    fetch is refused by validate_oidc_fetch_url.
    """
    userinfo = SSRF_USERINFO if prefix == SSRF_ISSUER_PREFIX else BASE_USERINFO
    return {
        "issuer": ISSUER + prefix,
        "authorization_endpoint": AUTHORIZE_URL,
        "token_endpoint": f"{ISSUER}/token",
        "userinfo_endpoint": userinfo,
        "jwks_uri": f"{ISSUER}/jwks",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile", "email", "groups"],
        "claims_supported": [
            "sub",
            "email",
            "preferred_username",
            "name",
            "groups",
            "groups_direct",
            "roles",
        ],
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

WELL_KNOWN = "/.well-known/openid-configuration"


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
        if path.endswith(WELL_KNOWN):
            # base "" or a per-issuer sub-path prefix (e.g. "/ssrf").
            prefix = path[: -len(WELL_KNOWN)]
            return self._json(200, build_discovery(prefix))
        if path == "/jwks":
            return self._json(200, JWKS)
        if path == "/oauth/userinfo":
            return self._userinfo()
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
        # but empty means "authenticate this user with NO group values".
        sub = one("sub", DEFAULT_SUB)
        email = one("email", DEFAULT_EMAIL)
        iss = one("iss", ISSUER)

        # id_token group claim spec. The primary claim is always present (name
        # defaults to `groups`) for backward compatibility with CASES 1-6.
        primary_vals = parse_groups(one("groups", DEFAULT_GROUPS))
        claims_spec = [
            {
                "name": one("groups_claim", "groups"),
                "shape": one("groups_shape", "array"),
                "vals": primary_vals,
            }
        ]
        g2 = one("groups2")
        if g2 is not None:
            claims_spec.append(
                {
                    "name": one("groups_claim2", "groups_direct"),
                    "shape": one("groups_shape2", "array"),
                    "vals": parse_groups(g2),
                }
            )

        # userinfo spec (#2831). Unset ui_groups mirrors the primary id_token
        # values so cases that never assert on userinfo see a union no-op.
        ui_groups_raw = one("ui_groups")
        ui_vals = parse_groups(ui_groups_raw) if ui_groups_raw is not None else primary_vals
        userinfo = {
            "claim": one("ui_groups_claim", "groups"),
            "vals": ui_vals,
            "status": int(one("ui_status", "200")),
        }

        code = encode_code(
            {
                "nonce": nonce,
                "sub": sub,
                "email": email,
                "iss": iss,
                "claims_spec": claims_spec,
                "userinfo": userinfo,
                # legacy fast-path field (see _token): a bare `groups` list for
                # any older caller that does not carry a claims_spec.
                "groups": primary_vals,
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
            return self._json(
                400, {"error": "invalid_request", "error_description": "missing code"}
            )

        try:
            payload = decode_code(code)
        except Exception as exc:  # noqa: BLE001 - test double, surface as 400
            return self._json(
                400, {"error": "invalid_grant", "error_description": f"bad code: {exc}"}
            )

        now = int(time.time())
        sub = payload.get("sub", DEFAULT_SUB)
        claims = {
            "iss": payload.get("iss", ISSUER),
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
        }
        # Emit only the specified id_token group claim keys (fidelity: an
        # unspecified `groups` stays ABSENT). Fall back to the legacy bare
        # `groups` field for any caller that predates claims_spec.
        spec = payload.get("claims_spec")
        if spec:
            for entry in spec:
                emit_claim(claims, entry["name"], entry.get("shape", "array"), entry["vals"])
        elif "groups" in payload:
            claims["groups"] = payload["groups"]

        id_token = make_id_token(claims)

        # Bake the userinfo spec into the opaque access_token so /oauth/userinfo
        # can recover it statelessly. Default (no baked userinfo) mirrors the
        # id_token `groups` under `groups`, status 200.
        userinfo = payload.get("userinfo") or {
            "claim": "groups",
            "vals": payload.get("groups", []),
            "status": 200,
        }
        access_token = encode_access_token({"sub": sub, "userinfo": userinfo})
        return self._json(
            200,
            {
                "access_token": access_token,
                "token_type": "Bearer",
                "expires_in": 3600,
                "id_token": id_token,
                "scope": "openid profile email groups",
            },
        )

    # ---- /oauth/userinfo: recover the baked userinfo group set -----------
    def _userinfo(self):
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return self._json(401, {"error": "invalid_token", "error_description": "missing bearer"})
        token = auth[len("Bearer "):].strip()
        payload = decode_access_token(token)
        if payload is None:
            return self._json(401, {"error": "invalid_token", "error_description": "unknown token"})
        ui = payload.get("userinfo") or {}
        status = int(ui.get("status", 200))
        if status != 200:
            # Drive the userinfo-DOWN graceful-degrade case (#2831 CASE 15).
            return self._json(
                status, {"error": "server_error", "error_description": "userinfo forced failure"}
            )
        claim = ui.get("claim", "groups")
        vals = ui.get("vals", [])
        return self._json(200, {"sub": payload.get("sub", DEFAULT_SUB), claim: vals})

    def log_message(self, fmt, *args):
        # Quiet: the oracle asserts on AK's DB/HTTP behaviour, not mock stderr.
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
