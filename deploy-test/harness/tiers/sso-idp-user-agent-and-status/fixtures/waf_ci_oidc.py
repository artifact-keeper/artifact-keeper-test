#!/usr/bin/env python3
# =============================================================================
# waf_ci_oidc.py - the CI OIDC issuer of ci-oidc-exchange behind a mock WAF, for
# the sso-idp-user-agent-and-status tier (artifact-keeper#5036)
# =============================================================================
# Imports /app/mock_ci_oidc.py and subclasses its HTTPS issuer handler:
#
#   * Every issuer request is recorded (path, User-Agent), served at GET /__seen
#     on the control port.
#   * A request with no User-Agent gets a 403 HTML page, except under the issuers
#     below, so their failure is reached on an image that sends no User-Agent too.
#   * Issuer names starting `block-disc` answer that page for discovery; issuer
#     names starting `block-jwks` answer it for the JWKS.
# Stdlib only. Env: as mock_ci_oidc.py.
# =============================================================================
import sys
import threading
from http.server import ThreadingHTTPServer

sys.path.insert(0, "/app")
import mock_ci_oidc  # noqa: E402

PAGE = b"<html><body><h1>403 Forbidden</h1>WAF-BLOCK-PAGE</body></html>\n"
SEEN = []
SEEN_LOCK = threading.Lock()


class Issuer(mock_ci_oidc.IssuerHandler):
    def do_GET(self):
        path = self.path.split("?", 1)[0]
        with SEEN_LOCK:
            SEEN.append({"path": path, "ua": self.headers.get("User-Agent")})
        first = (path.strip("/").split("/") or [""])[0]
        blocked = (
            (not first.startswith("block-") and not self.headers.get("User-Agent"))
            or (first.startswith("block-disc") and path.endswith("openid-configuration"))
            or (first.startswith("block-jwks") and path.endswith("/jwks"))
        )
        if blocked:
            return self._send(403, PAGE, "text/html")
        return super().do_GET()


class Control(mock_ci_oidc.ControlHandler):
    def do_GET(self):
        if self.path == "/__seen":
            with SEEN_LOCK:
                return self._json(200, list(SEEN))
        return super().do_GET()


if __name__ == "__main__":
    mock_ci_oidc.IssuerHandler = Issuer
    mock_ci_oidc.make_tls_material()
    threading.Thread(target=mock_ci_oidc.serve_https, daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", mock_ci_oidc.HTTP_PORT), Control).serve_forever()
