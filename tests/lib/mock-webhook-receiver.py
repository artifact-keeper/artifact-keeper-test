#!/usr/bin/env python3
"""
mock-webhook-receiver.py - Local HTTP server that records webhook POSTs.

Used by tests/webhooks/test-webhook-retry-recover.sh and friends to capture
the headers and body of webhook deliveries from the artifact-keeper backend.

Behaviour:
  * Listens on $WEBHOOK_RECEIVER_BIND:$WEBHOOK_RECEIVER_PORT.
    Bind defaults to 0.0.0.0 so the backend in another pod can reach
    the receiver via the runner pod's RFC1918 IP. Local health checks
    inside the test pod still work via 127.0.0.1 (#199).
  * Records every POST as a JSON object appended to $WEBHOOK_RECEIVER_LOG
    (default /tmp/mock-webhook-receiver.log). Each line is one delivery.
  * Returns 500 for the first $WEBHOOK_FAIL_FIRST_N requests then 200 for the
    rest. Set WEBHOOK_FAIL_FIRST_N=999999 for "always fail" (dead-letter test).
  * $WEBHOOK_FAIL_MATCH scopes that forced failure to deliveries whose body
    contains the given substring. Only matching deliveries are counted against
    WEBHOOK_FAIL_FIRST_N; everything else is answered 200 and never consumes a
    forced failure. Leave it unset for the historical global-counter behaviour.

    Why this exists: the counter is process-global, but a webhook created
    without a repository_id is GLOBAL, so the backend fans every
    repository.created event out to it. In the release gate roughly a dozen
    suites create repositories against the same backend concurrently, so a
    sibling suite's delivery would routinely arrive first and consume the
    single forced 500. The test under injection then got a 200, no retry row
    was ever written, and it failed after waiting out its whole timeout window
    reporting that the retry scheduler had not delivered. The scheduler was
    fine; the injection had landed on somebody else's delivery. Scoping the
    failure to the test's own repository key makes the injection deterministic
    under concurrency.
  * $WEBHOOK_FAIL_PER_ENTITY=1 applies WEBHOOK_FAIL_FIRST_N to every distinct
    delivery-body .entity_id separately: the first N deliveries for EACH
    entity are answered 500, then that entity recovers. Bodies without an
    entity_id are answered 200 and never consume a forced failure.

    Why this exists (test#317): WEBHOOK_FAIL_MATCH must name the entity, but
    the entity is a repository UUID that does not exist until the test creates
    the repository, long after the receiver starts. Counting per entity needs
    no arming: the test's own repository fails its first N deliveries no matter
    how many sibling deliveries arrive before, after or between them, because a
    sibling's delivery only ever consumes its own entity's budget. Sibling
    entities are failed too, but only on this test's own webhook, so the only
    side effect is extra retry rows for a webhook nobody else reads.
  * GET /__count returns the number of POSTs received so far (for poll loops).
  * GET /__health returns 200 once the server is up.
  * GET /__reset truncates the log and resets both counters.

Run as a daemon:
  WEBHOOK_RECEIVER_PORT=18765 python3 mock-webhook-receiver.py &
"""

import http.server
import json
import os
import sys
import threading
import time

PORT = int(os.environ.get("WEBHOOK_RECEIVER_PORT", "18765"))
LOG_PATH = os.environ.get("WEBHOOK_RECEIVER_LOG", "/tmp/mock-webhook-receiver.log")
FAIL_FIRST_N = int(os.environ.get("WEBHOOK_FAIL_FIRST_N", "0"))
FAIL_MATCH = os.environ.get("WEBHOOK_FAIL_MATCH", "")
FAIL_PER_ENTITY = os.environ.get("WEBHOOK_FAIL_PER_ENTITY", "") == "1"

_lock = threading.Lock()
_count = 0
# Deliveries eligible for forced failure. Identical to _count when FAIL_MATCH is
# unset; otherwise counts only bodies containing FAIL_MATCH, so a sibling
# suite's delivery cannot consume this test's forced failure.
_eligible_count = 0
# Per-entity delivery counters for WEBHOOK_FAIL_PER_ENTITY=1.
_entity_counts = {}


def _entity_id(body):
    """The delivery body's .entity_id, or None when absent/unparseable."""
    try:
        parsed = json.loads(body)
    except ValueError:
        return None
    if isinstance(parsed, dict):
        value = parsed.get("entity_id")
        if isinstance(value, str) and value:
            return value
    return None


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # silence default access log
        return

    def do_GET(self):  # noqa: N802
        global _count, _eligible_count
        if self.path == "/__health":
            self._respond(200, b"ok")
        elif self.path == "/__count":
            self._respond(200, str(_count).encode())
        elif self.path == "/__reset":
            with _lock:
                _count = 0
                _eligible_count = 0
                _entity_counts.clear()
            try:
                open(LOG_PATH, "w").close()
            except OSError:
                pass
            self._respond(200, b"reset")
        else:
            self._respond(404, b"not found")

    def do_POST(self):  # noqa: N802
        global _count, _eligible_count
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8", errors="replace") if length else ""
        with _lock:
            _count += 1
            current = _count

            # Only deliveries matching FAIL_MATCH (when set) are candidates for
            # the forced failure, and only those advance the eligible counter.
            # In per-entity mode the counter is the delivery's own entity's.
            entity = _entity_id(body) if FAIL_PER_ENTITY else None
            eligible_seq = None
            if FAIL_PER_ENTITY:
                eligible = entity is not None
                if eligible:
                    _entity_counts[entity] = _entity_counts.get(entity, 0) + 1
                    eligible_seq = _entity_counts[entity]
            else:
                eligible = (not FAIL_MATCH) or (FAIL_MATCH in body)
                if eligible:
                    _eligible_count += 1
                    eligible_seq = _eligible_count

            status = 500 if (eligible and eligible_seq <= FAIL_FIRST_N) else 200

            record = {
                "seq": current,
                "ts": time.time(),
                "path": self.path,
                "method": "POST",
                # Status actually returned. Without this the forced-failure
                # decision is unrecoverable after the fact, which is what made
                # the cross-suite race invisible in CI.
                "status": status,
                "eligible": eligible,
                "eligible_seq": eligible_seq,
                "entity_id": entity,
                "headers": {k: v for k, v in self.headers.items()},
                "body": body,
            }
            try:
                with open(LOG_PATH, "a") as f:
                    f.write(json.dumps(record) + "\n")
            except OSError as e:
                print(f"mock-webhook-receiver: failed to write log: {e}", file=sys.stderr)

        if status == 500:
            self._respond(500, b'{"error":"forced failure"}')
        else:
            self._respond(200, b'{"ok":true}')

    def _respond(self, status, body):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    open(LOG_PATH, "w").close()
    BIND = os.environ.get("WEBHOOK_RECEIVER_BIND", "0.0.0.0")
    server = http.server.ThreadingHTTPServer((BIND, PORT), Handler)
    print(f"mock-webhook-receiver: listening on {BIND}:{PORT}", file=sys.stderr)
    print(f"mock-webhook-receiver: log -> {LOG_PATH}", file=sys.stderr)
    scope = "deliveries per entity_id" if FAIL_PER_ENTITY else "requests"
    print(f"mock-webhook-receiver: failing first {FAIL_FIRST_N} {scope}", file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
