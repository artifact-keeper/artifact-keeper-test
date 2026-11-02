#!/usr/bin/env python3
# =============================================================================
# waf_oidc.py - the Entra-shaped mock IdP of oidc-exchange-and-login behind a
# mock WAF, for the sso-idp-user-agent-and-status tier (artifact-keeper#5036)
# =============================================================================
# Imports /app/mock_oidc.py and subclasses its handler:
#
#   * Every backend-facing request is recorded (method, path, User-Agent) and
#     served at GET /__seen. /authorize and /__* are the oracle's and are neither
#     recorded nor filtered.
#   * A request with no User-Agent to the base issuer (/.well-known/..., /token,
#     /jwks) gets a 403 HTML page, which is what the AWS WAF core rule set's
#     NoUserAgent_HEADER rule answers.
#   * /block/<anything> always answers that page, whatever the User-Agent.
#   * The issuer prefixes below are not behind the User-Agent rule, so each failure
#     is reached on an image that sends no User-Agent too, and the status report is
#     measured apart from the header. Discovery there points one endpoint at it:
#       /block/.well-known/...       the discovery document itself is the page
#       /bad-jwks/.well-known/...    jwks_uri -> /block/jwks,
#                                    token_endpoint -> /open/token (the real one)
#       /bad-token/.well-known/...   token_endpoint -> /block/token
#       /json-token/.well-known/...  token_endpoint -> /json400/token, which
#                                    answers an OAuth JSON 400 (invalid_grant)
# Stdlib only. Env: as mock_oidc.py.
# =============================================================================
import sys
import threading
import urllib.parse
from http.server import ThreadingHTTPServer

sys.path.insert(0, "/app")
import mock_oidc  # noqa: E402

PAGE = b"<html><body><h1>403 Forbidden</h1>WAF-BLOCK-PAGE</body></html>\n"
SEEN = []
SEEN_LOCK = threading.Lock()
OVERRIDES = {
    "/bad-jwks": {"jwks_uri": "/block/jwks", "token_endpoint": "/open/token"},
    "/bad-token": {"token_endpoint": "/block/token"},
    "/json-token": {"token_endpoint": "/json400/token"},
}


class Handler(mock_oidc.Handler):
    def _page(self):
        self.send_response(403)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(PAGE)))
        self.end_headers()
        self.wfile.write(PAGE)

    def _waf(self):
        """True when the request was answered here."""
        path = urllib.parse.urlparse(self.path).path
        if path.startswith("/__") or path == "/authorize":
            return False
        with SEEN_LOCK:
            SEEN.append({"method": self.command, "path": path, "ua": self.headers.get("User-Agent")})
        length = int(self.headers.get("Content-Length", "0") or "0")
        base_issuer = path in (mock_oidc.WELL_KNOWN, "/token", "/jwks", "/oauth/userinfo")
        if path.startswith("/block/") or (base_issuer and not self.headers.get("User-Agent")):
            if length:
                self.rfile.read(length)
            self._page()
            return True
        if path == "/open/token":
            self.path = "/token"
            return False
        if path == "/json400/token":
            if length:
                self.rfile.read(length)
            self._json(400, {"error": "invalid_grant", "error_description": "dtf"})
            return True
        for prefix, targets in OVERRIDES.items():
            if path == prefix + mock_oidc.WELL_KNOWN:
                doc = mock_oidc.build_discovery(prefix)
                for key, target in targets.items():
                    doc[key] = mock_oidc.ISSUER + target
                self._json(200, doc)
                return True
        return False

    def do_GET(self):
        if self.path == "/__seen":
            with SEEN_LOCK:
                return self._json(200, list(SEEN))
        if not self._waf():
            super().do_GET()

    def do_POST(self):
        if not self._waf():
            super().do_POST()


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", mock_oidc.PORT), Handler).serve_forever()
