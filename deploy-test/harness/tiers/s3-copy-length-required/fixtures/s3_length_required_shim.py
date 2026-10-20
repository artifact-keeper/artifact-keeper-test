#!/usr/bin/env python3
"""S3 pass-through that answers 411 to a CopyObject sent without Content-Length.

Google Cloud Storage's S3-compatible (XML) API refuses a PUT that carries no
Content-Length header with `411 Length Required`, including the body-less
CopyObject (artifact-keeper#3737). MinIO accepts it, so this shim sits between
the backend and MinIO and reproduces exactly that one refusal:

  * PUT with `x-amz-copy-source` and no `Content-Length` -> 411, counted;
  * everything else is forwarded verbatim (method, path, query, every header
    including Host, so the SigV4 signature still verifies at MinIO) and the
    upstream response is relayed.

Control endpoints (not forwarded; reached by the oracle on the published port):
  GET /__shim/stats -> {"refused_411": n, "copies_with_length": n, "forwarded": n}
  GET /__shim/readyz -> ok

Environment: SHIM_PORT (default 9000), SHIM_UPSTREAM (default minio:9000).
"""
import http.client
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

UPSTREAM = os.environ.get("SHIM_UPSTREAM", "minio:9000")
PORT = int(os.environ.get("SHIM_PORT", "9000"))
STATS = {"refused_411": 0, "copies_with_length": 0, "forwarded": 0}
LOCK = threading.Lock()
HOP = {"connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade", "te", "trailer"}


class Shim(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # quiet
        pass

    def _send(self, code, body, ctype="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            out = b""
            while True:
                size = int(self.rfile.readline().strip().split(b";")[0], 16)
                if size == 0:
                    while self.rfile.readline() not in (b"\r\n", b"\n", b""):
                        pass
                    return out
                out += self.rfile.read(size)
                self.rfile.readline()
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n else b""

    def _handle(self):
        if self.path.startswith("/__shim/"):
            if self.path == "/__shim/readyz":
                return self._send(200, b"ok", "text/plain")
            with LOCK:
                body = json.dumps(STATS).encode()
            return self._send(200, body)
        is_copy = self.command == "PUT" and "x-amz-copy-source" in {k.lower() for k in self.headers}
        if is_copy and self.headers.get("Content-Length") is None:
            self._body()
            with LOCK:
                STATS["refused_411"] += 1
            msg = (b'<?xml version="1.0" encoding="UTF-8"?><Error><Code>MissingContentLength</Code>'
                   b"<Message>You must provide the Content-Length HTTP header.</Message></Error>")
            return self._send(411, msg, "application/xml")
        body = self._body()
        with LOCK:
            STATS["forwarded"] += 1
            if is_copy:
                STATS["copies_with_length"] += 1
        conn = http.client.HTTPConnection(UPSTREAM, timeout=120)
        conn.putrequest(self.command, self.path, skip_host=True, skip_accept_encoding=True)
        for k, v in self.headers.items():
            if k.lower() in HOP:
                continue
            if k.lower() == "content-length":
                continue
            conn.putheader(k, v)
        if body or self.command in ("PUT", "POST") or self.headers.get("Content-Length") is not None:
            conn.putheader("Content-Length", str(len(body)))
        conn.endheaders()
        if body:
            conn.send(body)
        resp = conn.getresponse()
        data = resp.read()
        self.send_response(resp.status, resp.reason)
        for k, v in resp.getheaders():
            if k.lower() in HOP or k.lower() == "content-length":
                continue
            self.send_header(k, v)
        if self.command == "HEAD":
            self.send_header("Content-Length", resp.getheader("Content-Length") or "0")
            self.end_headers()
        else:
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        conn.close()

    do_GET = do_PUT = do_POST = do_DELETE = do_HEAD = _handle


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", PORT), Shim).serve_forever()
