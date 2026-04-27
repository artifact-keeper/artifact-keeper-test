#!/usr/bin/env python3
# mock-upstream.py - Controllable HTTP upstream for proxy/cache tests.
#
# Serves bytes from a state directory and counts every request so tests can
# assert "the backend only fetched once" for stampede tests, or "the backend
# rejected tampered content" for poisoning tests.
#
# State directory MUST be supplied via MOCK_STATE_DIR. Each test run picks a
# unique mktemp -d path under WORK_DIR (which is itself mktemp -d) so parallel
# release-gate jobs and concurrent local invocations cannot collide. There is
# deliberately no default: if the env var is unset we exit 2 rather than
# scribble into a shared /tmp path.
#
# Layout under STATE_DIR:
#   files/<path>          bytes returned for GET /<path>
#   files/<path>.headers  optional. Lines like "Header-Name: value".
#   request-log.txt       one line per request: "<unix_ts> <METHOD> <path>"
#   request-count.<key>   counter incremented per GET. <key> is the URL path
#                         with slashes replaced by underscores; only
#                         [A-Za-z0-9_.-] are kept and the result is truncated
#                         to 128 chars to defeat path-traversal/long-name abuse.
#   peak-inflight         peak concurrent in-flight handlers. Used by stampede
#                         tests to assert the backend's semaphore caps upstream
#                         concurrency. Written via os.replace() for atomicity.
#   delay-ms              optional. Per-request artificial delay (server-wide).
#   error-status          optional. Integer HTTP code (e.g. "503" or "500").
#                         When present, the mock returns this status with a
#                         short text body for every non-readyz request. Used
#                         by stale-on-error / 5xx-handling tests.
#
# GET /__readyz is a readiness probe that bypasses logging, counters, and
# delay so test fixtures can wait on TCP readiness without polluting state.
#
# Bind: 0.0.0.0:<MOCK_PORT>. MOCK_PORT is required; tests/lib/common.sh's
# start_mock_upstream picks a free port via getsockname() and passes it in.

import http.server
import os
import re
import sys
import tempfile
import threading
import time
from pathlib import Path

_STATE_ENV = os.environ.get("MOCK_STATE_DIR")
if not _STATE_ENV:
    sys.stderr.write(
        "mock-upstream: MOCK_STATE_DIR is required (use tests/lib/common.sh's "
        "start_mock_upstream which provides a unique mktemp path)\n"
    )
    sys.exit(2)
STATE_DIR = Path(_STATE_ENV)

_PORT_ENV = os.environ.get("MOCK_PORT")
if not _PORT_ENV:
    sys.stderr.write("mock-upstream: MOCK_PORT is required\n")
    sys.exit(2)
PORT = int(_PORT_ENV)

FILES_DIR = STATE_DIR / "files"
LOG_PATH = STATE_DIR / "request-log.txt"
PEAK_PATH = STATE_DIR / "peak-inflight"
LOG_LOCK = threading.Lock()
INFLIGHT = {"current": 0, "peak": 0}

_KEY_SAFE = re.compile(r"[^A-Za-z0-9_.-]")


def _safe_counter_key(path: str) -> str:
    """Sanitize a URL path into a counter filename component.

    Strips query strings, replaces slashes with underscores, drops anything
    outside [A-Za-z0-9_.-], and truncates to 128 chars. Defends against
    request-count.<key> writes escaping STATE_DIR via path traversal or
    blowing up the filesystem with overlong keys.
    """
    base = path.split("?", 1)[0].lstrip("/")
    base = base.replace("/", "_") or "_root"
    base = _KEY_SAFE.sub("_", base)
    return base[:128]


def _atomic_write(path: Path, value: str) -> None:
    """Write VALUE to PATH atomically via tempfile + os.replace."""
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp-", suffix=".swap")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(value)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # noqa: A003 - silence default stderr spam
        pass

    def _log_request(self, path):
        ts = time.time()
        with LOG_LOCK:
            INFLIGHT["current"] += 1
            if INFLIGHT["current"] > INFLIGHT["peak"]:
                INFLIGHT["peak"] = INFLIGHT["current"]
                _atomic_write(PEAK_PATH, str(INFLIGHT["peak"]))
            with LOG_PATH.open("a") as f:
                f.write(f"{ts:.6f} {self.command} {path}\n")
            counter = STATE_DIR / f"request-count.{_safe_counter_key(path)}"
            n = int(counter.read_text()) if counter.exists() else 0
            _atomic_write(counter, str(n + 1))

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
            err_path = STATE_DIR / "error-status"
            if err_path.exists():
                try:
                    code = int(err_path.read_text().strip())
                except ValueError:
                    code = 500
                self.send_response(code)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(f"injected error {code}\n".encode())
                return
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
