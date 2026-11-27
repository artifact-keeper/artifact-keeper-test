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
"t"}, GET /__sent -> JSON {path: response body bytes written} for the
sized-body paths below.

Sized response bodies (webhook-response-body-bound, artifact-keeper#6403): a
POST to LIVE_PORT whose path is /body/<mode>/<n>[/...] is recorded as usual
and answered 200 with <n> bytes of the repeating ASCII pattern
"0123456789abcdef", streamed in 64 KiB writes, framed by <mode>:
  cl       Content-Length: <n>
  close    no Content-Length, Connection: close (the body ends at EOF)
  chunked  Transfer-Encoding: chunked, 64 KiB chunks
A receiver that stops reading makes the write fail; /__sent then shows how
far the sender got.
"""
import base64
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG = []
SENT = {}
LOCK = threading.Lock()
PATTERN = b"0123456789abcdef" * 4096  # 64 KiB
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
        if self.path == "/__sent":
            with LOCK:
                data = json.dumps(SENT).encode()
            return self._send(data)
        return self._send(b'{"ok":true}')

    def do_POST(self):  # noqa: N802
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n > 0 else b""
        record(self, LIVE_PORT, body)
        parts = self.path.split("/")
        if len(parts) >= 4 and parts[1] == "body" and parts[3].isdigit():
            return self._sized(parts[2], int(parts[3]))
        return self._send(b'{"ok":true}')

    def _sized(self, mode, size):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        if mode == "cl":
            self.send_header("Content-Length", str(size))
        elif mode == "chunked":
            self.send_header("Transfer-Encoding", "chunked")
        else:
            self.send_header("Connection", "close")
            self.close_connection = True
        self.end_headers()
        sent = 0
        try:
            while sent < size:
                piece = PATTERN[: min(len(PATTERN), size - sent)]
                if mode == "chunked":
                    self.wfile.write(b"%x\r\n" % len(piece) + piece + b"\r\n")
                else:
                    self.wfile.write(piece)
                sent += len(piece)
                with LOCK:
                    SENT[self.path] = sent
            if mode == "chunked":
                self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()
        except OSError:
            self.close_connection = True
        with LOCK:
            SENT[self.path] = sent


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
