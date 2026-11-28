#!/usr/bin/env python3
"""A static conda channel upstream that counts what it is asked for.

Serves the gen-channel.sh tree mounted at MOCK_ROOT (default /srv). Every
package GET is counted, with the second it started in and the number of
requests in flight, so a tier can prove how many package fetches reached the
upstream, at what rate and how many at once.

* ``Last-Modified`` is 2020-01-01 for every file except those listed (one
  ``<subdir>/<file>`` per line) in ``MOCK_ROOT/.fresh``, which are served as
  published just now: inside any Package Age Policy hold.
* ``MOCK_DELAY_MS`` holds each package response that long before the body
  (default 0), so concurrency is observable.
* ``POST /__slow?path=<subdir>/<file>&ms=<n>`` sends one byte of that package,
  waits ``n`` milliseconds (noticing a closed socket every 100 ms), then sends
  the rest. A caller that drops the body at its own deadline stops the upstream
  request, so the tier can see whether a cancelled warm left a drain behind.
  ``POST /__reset`` clears it.
* ``GET /__stats`` -> {"packages": n, "per_path": {...}, "in_flight": n,
  "max_in_flight": n, "per_second": {epoch_second: n}}; ``POST /__reset``
  zeroes it; ``GET /__readyz`` -> ok. None of the three is counted.
"""

import json
import os
import select
import socket
import threading
import time
from email.utils import formatdate
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

ROOT = os.environ.get("MOCK_ROOT", "/srv")
PORT = int(os.environ.get("MOCK_PORT", "80"))
DELAY = int(os.environ.get("MOCK_DELAY_MS", "0")) / 1000.0
OLD = formatdate(1577836800, usegmt=True)

LOCK = threading.Lock()
STATE = {"per_path": {}, "per_second": {}, "in_flight": 0, "max_in_flight": 0}
SLOW = {}


def fresh_set():
    try:
        with open(os.path.join(ROOT, ".fresh")) as fh:
            return {line.strip() for line in fh if line.strip()}
    except OSError:
        return set()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # one line per request, for docker logs
        print("%s %s" % (self.command, self.path), flush=True)

    def _client_gone(self):
        readable, _, _ = select.select([self.connection], [], [], 0)
        if not readable:
            return False
        try:
            return self.connection.recv(1, socket.MSG_PEEK) == b""
        except OSError:
            return True

    def _json(self, code, obj):
        body = json.dumps(obj, sort_keys=True).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path == "/__reset":
            with LOCK:
                STATE["per_path"].clear()
                STATE["per_second"].clear()
                STATE["max_in_flight"] = STATE["in_flight"]
                SLOW.clear()
            return self._json(200, {"reset": True})
        if self.path.startswith("/__slow?"):
            q = parse_qs(urlsplit(self.path).query)
            rel = q.get("path", [""])[0].lstrip("/")
            try:
                ms = max(0, int(q.get("ms", ["0"])[0]))
            except ValueError:
                return self._json(400, {"error": "bad ms"})
            with LOCK:
                SLOW[rel] = ms / 1000.0
            return self._json(200, {"slow": rel, "ms": ms})
        self._json(405, {"error": "read-only"})

    def do_HEAD(self):
        self._serve(head=True)

    def do_GET(self):
        if self.path == "/__readyz":
            body = b"ok"
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/__stats":
            with LOCK:
                return self._json(200, {
                    "packages": sum(STATE["per_path"].values()),
                    "per_path": dict(STATE["per_path"]),
                    "per_second": dict(STATE["per_second"]),
                    "in_flight": STATE["in_flight"],
                    "max_in_flight": STATE["max_in_flight"],
                })
        self._serve(head=False)

    def _serve(self, head):
        rel = self.path.split("?", 1)[0].lstrip("/")
        path = os.path.normpath(os.path.join(ROOT, rel))
        if not path.startswith(os.path.normpath(ROOT) + os.sep) or not os.path.isfile(path):
            return self._json(404, {"error": "not found", "path": rel})
        is_pkg = rel.endswith(".conda") or rel.endswith(".tar.bz2")
        with LOCK:
            slow = SLOW.get(rel, 0) if is_pkg and not head else 0
        if is_pkg and not head:
            with LOCK:
                STATE["per_path"][rel] = STATE["per_path"].get(rel, 0) + 1
                sec = str(int(time.time()))
                STATE["per_second"][sec] = STATE["per_second"].get(sec, 0) + 1
                STATE["in_flight"] += 1
                STATE["max_in_flight"] = max(STATE["max_in_flight"], STATE["in_flight"])
        try:
            if is_pkg and DELAY and not head:
                time.sleep(DELAY)
            with open(path, "rb") as fh:
                data = fh.read()
            self.send_response(200)
            ctype = "application/json" if rel.endswith(".json") else "application/octet-stream"
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            lm = formatdate(time.time(), usegmt=True) if rel in fresh_set() else OLD
            self.send_header("Last-Modified", lm)
            self.end_headers()
            if not head:
                if slow and data:
                    self.wfile.write(data[:1])
                    self.wfile.flush()
                    data = data[1:]
                    end = time.monotonic() + slow
                    while data and not self._client_gone() and time.monotonic() < end:
                        time.sleep(min(0.1, end - time.monotonic()))
                if data and not self._client_gone():
                    try:
                        self.wfile.write(data)
                    except (BrokenPipeError, ConnectionResetError):
                        pass
        finally:
            if is_pkg and not head:
                with LOCK:
                    STATE["in_flight"] -= 1


if __name__ == "__main__":
    ThreadingHTTPServer.daemon_threads = True
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
