#!/usr/bin/env python3
# mock-bearer-upstream.py - Static upstream that requires a bearer token.
#
# Emulates a registry such as GitHub Packages that answers every request
# with 401 unless it carries "Authorization: Bearer <MOCK_BEARER_TOKEN>".
# Kept separate from mock-upstream.py so the shared mock stays unchanged.
#
# Env (all required): MOCK_STATE_DIR, MOCK_PORT, MOCK_BEARER_TOKEN.
#
# Layout under STATE_DIR:
#   files/<raw-path>   bytes returned for GET /<raw-path>. The path is NOT
#                      percent-decoded, so an npm scoped packument requested
#                      as /@scope%2Fname lives at files/@scope%2Fname.
#   request-log.txt    one line per request: "<unix_ts> <METHOD> <path> auth=<state>"
#                      where <state> is "ok" (correct bearer token), "wrong"
#                      (some other Authorization value) or "none".
#
# GET /__readyz answers 200 without auth and is not logged.

import http.server
import os
import sys
import threading
import time
from pathlib import Path

STATE_DIR = Path(os.environ.get("MOCK_STATE_DIR") or sys.exit("MOCK_STATE_DIR is required"))
PORT = int(os.environ.get("MOCK_PORT") or sys.exit("MOCK_PORT is required"))
TOKEN = os.environ.get("MOCK_BEARER_TOKEN") or sys.exit("MOCK_BEARER_TOKEN is required")
FILES_DIR = STATE_DIR / "files"
LOG_PATH = STATE_DIR / "request-log.txt"
LOG_LOCK = threading.Lock()


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # noqa: A003
        pass

    def _reply(self, code, body, ctype="text/plain"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        if code == 401:
            self.send_header("WWW-Authenticate", 'Bearer realm="mock"')
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        raw_path = self.path.split("?", 1)[0]
        if raw_path == "/__readyz":
            self._reply(200, b"ok\n")
            return
        header = self.headers.get("Authorization")
        if header is None:
            state = "none"
        elif header == f"Bearer {TOKEN}":
            state = "ok"
        else:
            state = "wrong"
        with LOG_LOCK, LOG_PATH.open("a") as f:
            f.write(f"{time.time():.6f} {self.command} {self.path} auth={state}\n")
        if state != "ok":
            self._reply(401, b'{"error":"unauthenticated"}\n', "application/json")
            return
        body_path = FILES_DIR / raw_path.lstrip("/")
        try:
            body_path.resolve().relative_to(FILES_DIR.resolve())
        except ValueError:
            self._reply(400, b"bad path\n")
            return
        if not body_path.is_file():
            self._reply(404, b'{"error":"not found"}\n', "application/json")
            return
        ctype = "application/json" if not raw_path.startswith("/download/") else "application/octet-stream"
        self._reply(200, body_path.read_bytes(), ctype)

    do_HEAD = do_GET  # noqa: N815


class ThreadedServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    FILES_DIR.mkdir(parents=True, exist_ok=True)
    LOG_PATH.touch()
    srv = ThreadedServer(("0.0.0.0", PORT), Handler)
    sys.stdout.write(f"mock-bearer-upstream listening on 0.0.0.0:{PORT}\n")
    sys.stdout.flush()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
