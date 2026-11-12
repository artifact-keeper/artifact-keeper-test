#!/usr/bin/env python3
"""Request-recording HTTP listener for the upstream-probe-egress tier.

Answers every request with 200 and a short text body, and records the request
line exactly as received (an origin sees `GET /path`, a forward proxy sees the
absolute form `GET http://host/path`) plus the Host header. Used as:
  * an explicit egress proxy (MOCK_BIND=0.0.0.0:3128): it never forwards, it
    only records and answers, so "the proxy saw the request" is observable
    even when the destination host does not resolve;
  * a loopback listener inside the backend's network namespace
    (MOCK_BIND=127.0.0.1:18099): a request here means the backend dialled
    127.0.0.1.

Control paths (never recorded): GET /__readyz -> ok, GET /__log -> JSON list
of {method, target, host}.
"""
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG = []
LOCK = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _answer(self, body, ctype="text/plain"):
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _handle(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        if self.path == "/__readyz":
            return self._answer(b"ok")
        if self.path == "/__log":
            with LOCK:
                data = json.dumps(LOG).encode()
            return self._answer(data, "application/json")
        with LOCK:
            LOG.append({"method": self.command, "target": self.path,
                        "host": self.headers.get("Host", "")})
        return self._answer(b"dtf-egress-recorder\n")

    do_GET = do_HEAD = do_POST = do_PUT = _handle


if __name__ == "__main__":
    host, port = os.environ.get("MOCK_BIND", "0.0.0.0:80").rsplit(":", 1)
    ThreadingHTTPServer((host, int(port)), Handler).serve_forever()
