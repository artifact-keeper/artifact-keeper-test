#!/usr/bin/env python3
"""Minimal VS Code gallery upstream for the ops-log-and-metrics-1112 tier.

Stdlib only. Every POST (the gallery `extensionquery`) answers an empty but
well-formed gallery result, so a Remote vscode repository can serve a query
end to end and the backend's gallery metadata sub-budget is exercised
(artifact-keeper#3914). Every request is appended to an in-memory log served
at GET /__requests so the oracle can prove the upstream was reached.
GET /__readyz answers "ok" for the compose healthcheck.
"""
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("MOCK_PORT", "80"))
REQUESTS = []
LOCK = threading.Lock()

EMPTY_RESULT = {
    "results": [
        {
            "extensions": [],
            "pagingToken": None,
            "resultMetadata": [
                {
                    "metadataType": "ResultCount",
                    "metadataItems": [{"name": "TotalCount", "count": 0}],
                }
            ],
        }
    ]
}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # quiet
        pass

    def _send(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _record(self):
        with LOCK:
            REQUESTS.append({"method": self.command, "path": self.path})

    def do_GET(self):
        if self.path == "/__readyz":
            return self._send(200, b"ok", "text/plain")
        if self.path == "/__requests":
            with LOCK:
                return self._send(200, json.dumps(REQUESTS))
        self._record()
        return self._send(404, json.dumps({"message": "not found"}))

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        self._record()
        return self._send(200, json.dumps(EMPTY_RESULT))


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
