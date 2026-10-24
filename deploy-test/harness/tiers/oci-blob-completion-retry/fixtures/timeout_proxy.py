#!/usr/bin/env python3
"""Reverse proxy with an Envoy-style response timeout (artifact-keeper#4902).

Envoy's route timeout (default 15 s, Envoy Gateway keeps it unless the
HTTPRoute sets `timeouts.request`) is measured from the end of the downstream
request to the end of the upstream response: upload time does not count, only
the work the upstream does after the body has arrived. When it expires Envoy
answers 504 and resets the upstream stream, which drops the backend's request.

This proxy does the same for the requests it is told to cut and is otherwise a
plain pass-through, one upstream connection per request:

  * the request body is pumped to the upstream on its own thread, so an
    upstream that answers before reading the whole body (a retry settled from
    another request's result) is forwarded instead of deadlocking;
  * PUT /__ctl/cut/<n>/<secs> arms a cut for the next <n> PUT requests whose
    path contains "/blobs/uploads/": <secs> after their body has been
    forwarded, if the upstream has not started answering, the proxy closes the
    upstream connection and answers 504 "upstream request timeout";
  * GET /__ctl/stats reports {"requests", "cut", "armed"}; GET /__ctl/readyz
    answers "ok".

Stdlib only. Env: PROXY_PORT (default 8080), UPSTREAM (host:port, default
backend:8080), PASS_TIMEOUT (seconds a non-cut request may take, default 600).
"""
import http.client
import http.server
import json
import os
import select
import socket
import socketserver
import sys
import threading
import time

PORT = int(os.environ.get("PROXY_PORT", "8080"))
UP_HOST, _, UP_PORT = os.environ.get("UPSTREAM", "backend:8080").rpartition(":")
UP_PORT = int(UP_PORT)
PASS_TIMEOUT = float(os.environ.get("PASS_TIMEOUT", "600"))
HOP = {"connection", "keep-alive", "proxy-connection", "transfer-encoding", "te",
       "trailer", "upgrade", "expect"}

LOCK = threading.Lock()
STATE = {"requests": 0, "cut": 0, "armed": 0, "cut_after": 0.0}


def take_cut(method, path):
    if method != "PUT" or "/blobs/uploads/" not in path:
        return None
    with LOCK:
        if STATE["armed"] > 0:
            STATE["armed"] -= 1
            return STATE["cut_after"]
    return None


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        if self.path.startswith("/__ctl/readyz"):
            return
        sys.stderr.write("timeout-proxy: " + (fmt % args) + "\n")

    def reply(self, code, body, ctype="text/plain"):
        data = body if isinstance(body, bytes) else body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)
        self.close_connection = True

    def control(self):
        parts = self.path.strip("/").split("/")
        if parts[1:] == ["readyz"]:
            return self.reply(200, "ok")
        if parts[1:] == ["stats"]:
            with LOCK:
                stats = {k: STATE[k] for k in ("requests", "cut", "armed")}
            return self.reply(200, json.dumps(stats), "application/json")
        if len(parts) == 4 and parts[1] == "cut" and self.command == "PUT":
            with LOCK:
                STATE["armed"] = int(parts[2])
                STATE["cut_after"] = float(parts[3])
            return self.reply(200, "armed")
        return self.reply(404, "unknown control path")

    def proxy(self):
        if self.path.startswith("/__ctl/"):
            return self.control()
        with LOCK:
            STATE["requests"] += 1
        cut_after = take_cut(self.command, self.path)
        length = int(self.headers.get("Content-Length") or 0)

        up = socket.create_connection((UP_HOST, UP_PORT))
        head = ["%s %s HTTP/1.1" % (self.command, self.path)]
        for k, v in self.headers.items():
            if k.lower() not in HOP:
                head.append("%s: %s" % (k, v))
        head.append("Connection: close")
        up.sendall(("\r\n".join(head) + "\r\n\r\n").encode("latin-1"))

        body_done = threading.Event()

        def pump():
            left, sending = length, True
            try:
                while left > 0:
                    chunk = self.rfile.read(min(1 << 20, left))
                    if not chunk:
                        break
                    left -= len(chunk)
                    if sending:
                        try:
                            up.sendall(chunk)
                        except OSError:
                            sending = False  # upstream answered early or went away
            finally:
                body_done.set()

        pumper = threading.Thread(target=pump, daemon=True)
        pumper.start()

        done_at = None
        deadline = time.monotonic() + PASS_TIMEOUT
        while True:
            readable, _, _ = select.select([up], [], [], 0.05)
            if readable:
                break
            now = time.monotonic()
            if body_done.is_set() and done_at is None:
                done_at = now
            if cut_after is not None and done_at is not None and now - done_at >= cut_after:
                up.close()
                with LOCK:
                    STATE["cut"] += 1
                self.log_message("cut %s %s after %.1fs", self.command, self.path, cut_after)
                return self.reply(504, "upstream request timeout")
            if now >= deadline:
                up.close()
                return self.reply(504, "upstream request timeout")

        resp = http.client.HTTPResponse(up, method=self.command)
        resp.begin()
        data = resp.read()
        up.close()
        # The client may still be sending a body the upstream did not read.
        body_done.wait(timeout=PASS_TIMEOUT)
        self.send_response(resp.status)
        for k, v in resp.getheaders():
            if k.lower() not in HOP and k.lower() != "content-length":
                self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)
        self.close_connection = True

    do_GET = do_HEAD = do_POST = do_PUT = do_PATCH = do_DELETE = proxy


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


if __name__ == "__main__":
    sys.stderr.write("timeout-proxy: :%d -> %s:%d\n" % (PORT, UP_HOST, UP_PORT))
    Server(("0.0.0.0", PORT), Handler).serve_forever()
