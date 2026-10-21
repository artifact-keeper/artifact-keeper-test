#!/usr/bin/env python3
"""In-memory fake Azure Blob endpoint whose server-side copy can be made slow.

Azurite cannot exercise artifact-keeper#4858: it copies instantly and refuses
Put Blob From URL on a SAS destination. This stub answers just the Blob REST
calls the backend's Azure storage makes, keeps blobs in memory, and holds
every Put Blob From URL (a PUT carrying `x-ms-copy-source`) for COPY_DELAY
seconds before it answers, which is what real Azure does while it copies a
large source: the connection stays silent until the copy is done.

    PUT  <blob>                         Put Blob (body)          -> 201
    PUT  <blob>?comp=block&blockid=X    Put Block                -> 201
    PUT  <blob>?comp=blocklist          Put Block List (XML)     -> 201
    PUT  <blob> + x-ms-copy-source      Put Blob From URL        -> 201 after delay
    GET  <blob> [+ Range/x-ms-range]    Get Blob                 -> 200/206
    HEAD <blob>                         Get Blob Properties      -> 200/404
    DELETE <blob>                       Delete Blob              -> 202/404
    GET  /__ctl/readyz                  "ok"
    PUT  /__ctl/delay/<secs>            set COPY_DELAY at run time
    PUT  /__ctl/fail/<n>                close the next n Put Blob From URL
                                        connections without answering
    GET  /__ctl/stats                   JSON: copies seen, last copy timing

No signature checks (the backend signs with Shared Key; nothing secret is
verified here). Environment: STUB_PORT (10000), COPY_DELAY (0).
"""
import json
import os
import re
import socket
import sys
import threading
import time
import urllib.parse
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BLOBS = {}
BLOCKS = {}
LOCK = threading.Lock()
STATE = {"delay": float(os.environ.get("COPY_DELAY", "0")), "copies": 0, "copies_done": 0,
         "last_copy": None, "fail": 0, "copies_dropped": 0}


def etag(data):
    return '"0x%X"' % (hash(data) & 0xFFFFFFFFFFFF)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        sys.stderr.write("fake-azure %s\n" % (fmt % args))

    def _send(self, code, body=b"", headers=None):
        self.send_response(code)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("x-ms-request-id", "fake")
        self.send_header("x-ms-version", "2021-06-08")
        self.end_headers()
        if body and self.command != "HEAD":
            self.wfile.write(body)

    def _split(self):
        u = urllib.parse.urlsplit(self.path)
        return urllib.parse.unquote(u.path), dict(urllib.parse.parse_qsl(u.query))

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n else b""

    def do_GET(self):
        path, q = self._split()
        if path == "/__ctl/readyz":
            return self._send(200, b"ok")
        if path == "/__ctl/stats":
            with LOCK:
                return self._send(200, json.dumps(STATE).encode(), {"Content-Type": "application/json"})
        with LOCK:
            data = BLOBS.get(path)
        if data is None:
            return self._send(404, b"<Error><Code>BlobNotFound</Code></Error>")
        rng = self.headers.get("x-ms-range") or self.headers.get("Range")
        m = re.match(r"bytes=(\d+)-(\d*)", rng or "")
        if m:
            start = int(m.group(1))
            end = int(m.group(2)) if m.group(2) else len(data) - 1
            end = min(end, len(data) - 1)
            part = data[start:end + 1]
            return self._send(206, part, {"Content-Range": "bytes %d-%d/%d" % (start, end, len(data)),
                                          "ETag": etag(data), "Content-Type": "application/octet-stream"})
        return self._send(200, data, {"ETag": etag(data), "Content-Type": "application/octet-stream"})

    def do_HEAD(self):
        path, _ = self._split()
        with LOCK:
            data = BLOBS.get(path)
        if data is None:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("ETag", etag(data))
        self.send_header("x-ms-blob-type", "BlockBlob")
        self.end_headers()

    def do_DELETE(self):
        path, _ = self._split()
        with LOCK:
            found = BLOBS.pop(path, None) is not None
        return self._send(202 if found else 404)

    def do_PUT(self):
        path, q = self._split()
        body = self._body()
        m = re.match(r"^/__ctl/delay/([0-9.]+)$", path)
        if m:
            with LOCK:
                STATE["delay"] = float(m.group(1))
            return self._send(200, b"ok")
        m = re.match(r"^/__ctl/fail/([0-9]+)$", path)
        if m:
            with LOCK:
                STATE["fail"] = int(m.group(1))
            return self._send(200, b"ok")
        src = self.headers.get("x-ms-copy-source")
        if src:
            with LOCK:
                drop = STATE["fail"] > 0
                if drop:
                    STATE["fail"] -= 1
                    STATE["copies_dropped"] += 1
            if drop:
                # A transport failure: the request is read, nothing is sent.
                self.close_connection = True
                self.connection.shutdown(socket.SHUT_RDWR)
                return
            src_path = urllib.parse.unquote(urllib.parse.urlsplit(src).path)
            with LOCK:
                data = BLOBS.get(src_path)
                delay = STATE["delay"]
                STATE["copies"] += 1
            t0 = time.time()
            if data is None:
                return self._send(404, b"<Error><Code>CannotVerifyCopySource</Code></Error>")
            time.sleep(delay)
            with LOCK:
                BLOBS[path] = data
                STATE["copies_done"] += 1
                STATE["last_copy"] = {"dest": path, "bytes": len(data), "held_s": round(time.time() - t0, 1)}
            return self._send(201, b"", {"ETag": etag(data)})
        comp = q.get("comp")
        if comp == "block":
            with LOCK:
                BLOCKS[(path, q.get("blockid", ""))] = body
            return self._send(201)
        if comp == "blocklist":
            ids = [el.text or "" for el in ET.fromstring(body or b"<BlockList/>")]
            with LOCK:
                missing = [i for i in ids if (path, i) not in BLOCKS]
                if missing:
                    return self._send(400, b"<Error><Code>InvalidBlockList</Code></Error>")
                data = b"".join(BLOCKS[(path, i)] for i in ids)
                BLOBS[path] = data
                for i in ids:
                    BLOCKS.pop((path, i), None)
            return self._send(201, b"", {"ETag": etag(data)})
        if comp is None and q.get("restype") == "container":
            return self._send(201)
        with LOCK:
            BLOBS[path] = body
        return self._send(201, b"", {"ETag": etag(body)})


if __name__ == "__main__":
    port = int(os.environ.get("STUB_PORT", "10000"))
    srv = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    srv.daemon_threads = True
    print("fake-azure listening on %d, copy delay %.0fs" % (port, STATE["delay"]), flush=True)
    srv.serve_forever()
