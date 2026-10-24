#!/usr/bin/env python3
"""S3 pass-through that holds the first N object deletes for a fixed time.

A slow object store (a remote region, a throttled bucket, a backend under
load) answers DELETE slowly. Storage GC must not keep a database transaction
open while it waits (artifact-keeper#2524). This shim sits between the backend
and MinIO and makes that wait observable:

  * a single-object DELETE (`DELETE /<bucket>/<key>`) and a multi-object
    delete (`POST /<bucket>?delete`) are forwarded after a delay, but only
    while the shim is armed and only for the first `n` such requests after
    arming; later deletes pass straight through, so a pass over thousands of
    keys stays short;
  * everything else is forwarded verbatim (method, path, query, every header
    including Host, so SigV4 still verifies at MinIO) and the upstream
    response is relayed.

Control endpoints (not forwarded; the oracle reaches them with `docker exec`):
  GET /__shim/readyz              -> ok
  GET /__shim/arm?n=8&delay=2.0   -> arm: delay the next n deletes by delay s
  GET /__shim/stats               -> JSON counters (see STATS below)

Environment: SHIM_PORT (default 9000), SHIM_UPSTREAM (default minio:9000).
The shim starts disarmed: uploads and their staging-key cleanup are never
delayed until the oracle arms it.
"""
import http.client
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

UPSTREAM = os.environ.get("SHIM_UPSTREAM", "minio:9000")
PORT = int(os.environ.get("SHIM_PORT", "9000"))
LOCK = threading.Lock()
HOP = {"connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade", "te", "trailer"}

ARM = {"left": 0, "delay": 0.0}
STATS = {
    "deletes": 0,            # single-object DELETE requests seen
    "multi_deletes": 0,      # POST ?delete requests seen
    "delayed": 0,            # deletes held since the last arm
    "delayed_in_flight": 0,  # held deletes currently waiting
    "max_delayed_in_flight": 0,
    "first_delay_at": None,  # epoch seconds of the first held delete
    "last_delay_end": None,  # epoch seconds the last held delete was released
    "delayed_keys": [],
    "forwarded": 0,
}


def is_delete(method, path):
    parts = urlsplit(path)
    if method == "DELETE":
        # /<bucket>/<key>: a bucket delete has no key part.
        return parts.path.strip("/").count("/") >= 1
    if method == "POST":
        return "delete" in parse_qs(parts.query, keep_blank_values=True)
    return False


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

    def _control(self):
        parts = urlsplit(self.path)
        if parts.path == "/__shim/readyz":
            return self._send(200, b"ok", "text/plain")
        if parts.path == "/__shim/arm":
            q = parse_qs(parts.query)
            with LOCK:
                ARM["left"] = int(q.get("n", ["0"])[0])
                ARM["delay"] = float(q.get("delay", ["0"])[0])
                STATS.update(delayed=0, max_delayed_in_flight=0, first_delay_at=None,
                             last_delay_end=None, delayed_keys=[])
                body = json.dumps(ARM).encode()
            return self._send(200, body)
        with LOCK:
            body = json.dumps(STATS).encode()
        return self._send(200, body)

    def _handle(self):
        if self.path.startswith("/__shim/"):
            return self._control()
        body = self._body()
        hold = 0.0
        if is_delete(self.command, self.path):
            with LOCK:
                STATS["multi_deletes" if self.command == "POST" else "deletes"] += 1
                if ARM["left"] > 0:
                    ARM["left"] -= 1
                    hold = ARM["delay"]
                    STATS["delayed"] += 1
                    STATS["delayed_in_flight"] += 1
                    STATS["max_delayed_in_flight"] = max(
                        STATS["max_delayed_in_flight"], STATS["delayed_in_flight"])
                    if STATS["first_delay_at"] is None:
                        STATS["first_delay_at"] = time.time()
                    STATS["delayed_keys"].append(urlsplit(self.path).path)
        if hold > 0:
            time.sleep(hold)
            with LOCK:
                STATS["delayed_in_flight"] -= 1
                STATS["last_delay_end"] = time.time()
        with LOCK:
            STATS["forwarded"] += 1
        conn = http.client.HTTPConnection(UPSTREAM, timeout=120)
        conn.putrequest(self.command, self.path, skip_host=True, skip_accept_encoding=True)
        for k, v in self.headers.items():
            if k.lower() in HOP or k.lower() == "content-length":
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
