"""Logging reverse proxy for the conda-jlap-incremental tier.

Listens on 127.0.0.1:$PROXY_PORT inside a container that shares the backend's
network namespace and forwards every request to 127.0.0.1:$UPSTREAM_PORT.
One JSON line per request goes to $PROXY_LOG: method, path, Range header,
status and body bytes, so the oracle can tell which documents the conda
client actually downloaded.
"""
import http.client
import http.server
import json
import os
import socketserver
import threading

PORT = int(os.environ.get("PROXY_PORT", "9123"))
UPSTREAM = int(os.environ.get("UPSTREAM_PORT", "8080"))
LOG = os.environ.get("PROXY_LOG", "/tmp/proxy.log")
LOCK = threading.Lock()
HOP = {"connection", "keep-alive", "transfer-encoding", "te", "trailer", "upgrade",
       "proxy-authorization", "proxy-authenticate", "host"}


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _forward(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else None
        headers = {k: v for k, v in self.headers.items() if k.lower() not in HOP}
        conn = http.client.HTTPConnection("127.0.0.1", UPSTREAM, timeout=300)
        conn.request(self.command, self.path, body=body, headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        self.send_response(resp.status)
        for k, v in resp.getheaders():
            if k.lower() not in HOP and k.lower() != "content-length":
                self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)
        conn.close()
        with LOCK, open(LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps({
                "method": self.command,
                "path": self.path,
                "range": self.headers.get("Range"),
                "if_none_match": self.headers.get("If-None-Match"),
                "status": resp.status,
                "bytes": len(data),
            }) + "\n")

    do_GET = do_HEAD = do_POST = do_PUT = do_DELETE = _forward


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


if __name__ == "__main__":
    Server(("127.0.0.1", PORT), Handler).serve_forever()
