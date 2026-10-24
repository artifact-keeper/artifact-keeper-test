#!/usr/bin/env python3
"""Reverse proxy with a route timeout, like an ingress or load balancer in
front of Artifact Keeper (artifact-keeper#4311).

Every request is forwarded to UPSTREAM; if the upstream has not started its
response within ROUTE_TIMEOUT seconds of the request being forwarded, the
proxy drops the upstream connection and answers 504 "upstream request
timeout", as Envoy, nginx (`proxy_read_timeout`) and cloud load balancers do.
GET /__ctl/readyz answers "ok"; GET /__ctl/stats reports {"requests",
"timeouts"}.

Stdlib only. Env: PROXY_PORT (default 8080), UPSTREAM (host:port, default
backend:8080), ROUTE_TIMEOUT (seconds, default 30).
"""
import http.client
import http.server
import json
import os
import socket
import socketserver
import sys
import threading

PORT = int(os.environ.get("PROXY_PORT", "8080"))
UP_HOST, _, UP_PORT = os.environ.get("UPSTREAM", "backend:8080").rpartition(":")
UP_PORT = int(UP_PORT)
ROUTE_TIMEOUT = float(os.environ.get("ROUTE_TIMEOUT", "30"))
HOP = {"connection", "keep-alive", "proxy-connection", "transfer-encoding", "te",
       "trailer", "upgrade", "expect", "host", "content-length"}
LOCK = threading.Lock()
STATS = {"requests": 0, "timeouts": 0}


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        if not self.path.startswith("/__ctl/readyz"):
            sys.stderr.write("route-timeout-proxy: " + (fmt % args) + "\n")

    def reply(self, code, body, ctype="text/plain"):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)
        self.close_connection = True

    def proxy(self):
        if self.path == "/__ctl/readyz":
            return self.reply(200, "ok")
        if self.path == "/__ctl/stats":
            with LOCK:
                return self.reply(200, json.dumps(STATS), "application/json")
        with LOCK:
            STATS["requests"] += 1
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else None
        headers = {k: v for k, v in self.headers.items() if k.lower() not in HOP}
        conn = http.client.HTTPConnection(UP_HOST, UP_PORT, timeout=ROUTE_TIMEOUT)
        try:
            conn.request(self.command, self.path, body=body, headers=headers)
            resp = conn.getresponse()
            data = resp.read()
        except (socket.timeout, TimeoutError):
            conn.close()
            with LOCK:
                STATS["timeouts"] += 1
            return self.reply(504, "upstream request timeout")
        except OSError as e:
            conn.close()
            return self.reply(502, "upstream connect error: %s" % e)
        self.send_response(resp.status, resp.reason)
        for k, v in resp.getheaders():
            if k.lower() not in HOP:
                self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)
        self.close_connection = True
        conn.close()

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = proxy


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


if __name__ == "__main__":
    Server(("0.0.0.0", PORT), Handler).serve_forever()
