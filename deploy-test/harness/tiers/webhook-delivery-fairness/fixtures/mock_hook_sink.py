#!/usr/bin/env python3
"""Webhook receivers for the webhook-delivery-fairness tier.

One process, two listeners sharing one in-memory log:
  * LIVE_PORT (80): records every POST (path, lower-case headers, raw body as
    base64, arrival time) and answers 200 {"ok": true} at once.
  * HANG_PORT (81): a black hole. Records the arrival of every request, then
    holds the connection open without ever answering, so a sender waits out
    its own timeout.

Control paths on LIVE_PORT (never recorded): GET /__readyz -> ok,
GET /__log -> JSON list of {"port", "method", "path", "headers", "body_b64",
"t"}.
"""
import base64
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG = []
LOCK = threading.Lock()
LIVE_PORT = int(os.environ.get("LIVE_PORT", "80"))
HANG_PORT = int(os.environ.get("HANG_PORT", "81"))


def record(handler, port, body):
    entry = {"port": port, "method": handler.command, "path": handler.path,
             "headers": {k.lower(): v for k, v in handler.headers.items()},
             "body_b64": base64.b64encode(body).decode(), "t": time.time()}
    with LOCK:
        LOG.append(entry)


class Live(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _send(self, body, ctype="application/json"):
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        if self.path == "/__readyz":
            return self._send(b"ok", "text/plain")
        if self.path == "/__log":
            with LOCK:
                data = json.dumps(LOG).encode()
            return self._send(data)
        return self._send(b'{"ok":true}')

    def do_POST(self):  # noqa: N802
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n > 0 else b""
        record(self, LIVE_PORT, body)
        return self._send(b'{"ok":true}')


class Hang(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_POST(self):  # noqa: N802
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n > 0 else b""
        record(self, HANG_PORT, body)
        # Never answer: hold the socket until the sender gives up.
        while True:
            time.sleep(3600)

    do_GET = do_PUT = do_POST


def serve(port, handler):
    server = ThreadingHTTPServer(("0.0.0.0", port), handler)
    server.daemon_threads = True
    server.serve_forever()


if __name__ == "__main__":
    threading.Thread(target=serve, args=(HANG_PORT, Hang), daemon=True).start()
    serve(LIVE_PORT, Live)
