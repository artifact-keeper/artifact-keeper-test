#!/usr/bin/env python3
# =============================================================================
# mock_vulndb_adapter.py - a scanner-adapter stand-in with an old, offline
#                          Trivy database (artifact-keeper#5177)
# =============================================================================
# The scan-vuln-db-age tier points the backend's TRIVY_ADAPTER_URL at this
# server. It answers the adapter's probes and its DB-status route the way an
# air-gapped adapter (SCANNER_OFFLINE=true) whose imported DB was built 30
# days ago does. It never scans.
#
#   GET /probe/healthy, /probe/ready   200 "ok"
#   GET /api/v1/vulndb                 the adapter's VulnDBStatus body, built
#                                      MOCK_DB_AGE_DAYS (default 30) days
#                                      before the container started; 401
#                                      without "Authorization: Bearer
#                                      $MOCK_TOKEN". Hits counted.
#   GET /__hits                        {"vulndb": n}
#   GET /__readyz                      container healthcheck
#
# Stdlib only, single file, stock python image. MOCK_PORT (default 80).
# =============================================================================
import json
import os
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

PORT = int(os.environ.get("MOCK_PORT", "80"))
TOKEN = os.environ.get("MOCK_TOKEN", "dtf-vulndb-token")
AGE_DAYS = int(os.environ.get("MOCK_DB_AGE_DAYS", "30"))
BUILT = datetime.now(timezone.utc) - timedelta(days=AGE_DAYS)
LOCK = threading.Lock()
HITS = {"vulndb": 0}


def iso(t):
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        print("mock-vulndb: " + (fmt % args), flush=True)

    def _send(self, code, data, ctype="text/plain"):
        if isinstance(data, str):
            data = data.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = urlsplit(self.path).path
        if path in ("/probe/healthy", "/probe/ready", "/__readyz"):
            return self._send(200, "ok")
        if path == "/__hits":
            with LOCK:
                body = json.dumps(HITS)
            return self._send(200, body, "application/json")
        if path == "/api/v1/vulndb":
            with LOCK:
                HITS["vulndb"] += 1
            if self.headers.get("Authorization", "") != f"Bearer {TOKEN}":
                return self._send(401, "invalid bearer token")
            now = datetime.now(timezone.utc)
            body = {
                "version": 2,
                "updated_at": iso(BUILT),
                "next_update": iso(BUILT + timedelta(days=1)),
                "downloaded_at": iso(BUILT + timedelta(hours=1)),
                "age_seconds": int((now - BUILT).total_seconds()),
                "stale": True,
                "offline": True,
            }
            return self._send(200, json.dumps(body), "application/json")
        return self._send(404, "not found")


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


if __name__ == "__main__":
    print(f"mock-vulndb: listening on :{PORT}, DB built {iso(BUILT)}", flush=True)
    Server(("0.0.0.0", PORT), Handler).serve_forever()
