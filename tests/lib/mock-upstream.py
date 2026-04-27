#!/usr/bin/env python3
# mock-upstream.py - Controllable HTTP upstream for proxy/cache tests.
#
# Serves bytes from a state directory and counts every request so tests can
# assert "the backend only fetched once" for stampede tests, or "the backend
# rejected tampered content" for poisoning tests.
#
# Layout under STATE_DIR (env MOCK_STATE_DIR, default /tmp/mock-upstream):
#   files/<path>          bytes returned for GET /<path>
#   files/<path>.headers  optional. Lines like "Header-Name: value".
#   request-log.txt       one line per request: "<unix_ts> <METHOD> <path>"
#   request-count.<key>   counter incremented per GET. <key> is the URL path
#                         with slashes replaced by underscores.
#   peak-inflight         peak concurrent in-flight handlers. Used by stampede
#                         tests to assert the backend's semaphore caps upstream
#                         concurrency.
#   delay-ms              optional. Per-request artificial delay (server-wide).
#
# GET /__readyz is a readiness probe that bypasses logging, counters, and
# delay so test fixtures can wait on TCP readiness without polluting state.
#
# Bind: 0.0.0.0:<MOCK_PORT> (default 18080).
#
# Tests should write files into STATE_DIR before triggering proxy fetches,
# then read request-log.txt / request-count.* to assert behavior.

import http.server
import os
import sys
import threading
import time
from pathlib import Path

STATE_DIR = Path(os.environ.get("MOCK_STATE_DIR", "/tmp/mock-upstream"))
PORT = int(os.environ.get("MOCK_PORT", "18080"))
FILES_DIR = STATE_DIR / "files"
LOG_PATH = STATE_DIR / "request-log.txt"
PEAK_PATH = STATE_DIR / "peak-inflight"
LOG_LOCK = threading.Lock()
INFLIGHT = {"current": 0, "peak": 0}


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # noqa: A003 - silence default stderr spam
        pass

    def _log_request(self, path):
        ts = time.time()
        with LOG_LOCK:
            INFLIGHT["current"] += 1
            if INFLIGHT["current"] > INFLIGHT["peak"]:
                INFLIGHT["peak"] = INFLIGHT["current"]
                PEAK_PATH.write_text(str(INFLIGHT["peak"]))
            with LOG_PATH.open("a") as f:
                f.write(f"{ts:.6f} {self.command} {path}\n")
            key = path.lstrip("/").replace("/", "_") or "_root"
            counter = STATE_DIR / f"request-count.{key}"
            n = int(counter.read_text()) if counter.exists() else 0
            counter.write_text(str(n + 1))

    def _release_inflight(self):
        with LOG_LOCK:
            if INFLIGHT["current"] > 0:
                INFLIGHT["current"] -= 1

    def _maybe_delay(self):
        delay_path = STATE_DIR / "delay-ms"
        if delay_path.exists():
            try:
                ms = int(delay_path.read_text().strip())
                if ms > 0:
                    time.sleep(ms / 1000.0)
            except ValueError:
                pass

    def do_GET(self):  # noqa: N802 - http.server contract
        # Readiness probe path is excluded from logging, counters, and delay
        # so test fixtures can wait on TCP readiness without polluting state.
        if self.path.split("?", 1)[0] == "/__readyz":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ok\n")
            return
        self._log_request(self.path)
        try:
            self._maybe_delay()
            rel = self.path.lstrip("/").split("?", 1)[0]
            body_path = FILES_DIR / rel
            if not body_path.is_file():
                self.send_response(404)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"not found\n")
                return
            body = body_path.read_bytes()
            headers_path = body_path.with_suffix(body_path.suffix + ".headers")
            extra_headers = []
            if headers_path.is_file():
                for line in headers_path.read_text().splitlines():
                    if ":" in line:
                        k, v = line.split(":", 1)
                        extra_headers.append((k.strip(), v.strip()))
            self.send_response(200)
            seen = {k.lower() for k, _ in extra_headers}
            if "content-type" not in seen:
                self.send_header("Content-Type", "application/octet-stream")
            if "content-length" not in seen:
                self.send_header("Content-Length", str(len(body)))
            for k, v in extra_headers:
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)
        finally:
            self._release_inflight()


class ThreadedServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    FILES_DIR.mkdir(parents=True, exist_ok=True)
    LOG_PATH.touch()
    srv = ThreadedServer(("0.0.0.0", PORT), Handler)
    sys.stdout.write(f"mock-upstream listening on 0.0.0.0:{PORT} state={STATE_DIR}\n")
    sys.stdout.flush()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
