#!/usr/bin/env python3
"""Open N concurrent uploads and hold them, for the upload-slot-exhaustion tier.

  slot_hold.py PORT METHOD PATH AUTH N DECLARED RATE HOLD_SECS OUT

Opens N connections in parallel. Each sends `METHOD PATH` (with `{i}`
replaced by the connection index) with `Authorization: AUTH` (`-` for none)
and `Content-Length: DECLARED`, then sends body bytes at RATE bytes per
second (RATE 0: one byte every 2 s, the advisory's trickle) until a response
arrives, HOLD_SECS elapse, or DECLARED bytes are sent. A connection that is
still waiting at HOLD_SECS is closed without a response ("none").

Writes one JSON line per connection to OUT
({"i", "status", "secs", "sent", "retry_after", "body"}) and prints a
one-line summary: `<status>x<count> ...`. Stdlib only; every wait is bounded.
"""
import json
import socket
import sys
import threading
import time


def one(i, port, method, path, auth, declared, rate, hold, results):
    t0 = time.monotonic()
    rec = {"i": i, "status": "none", "secs": 0.0, "sent": 0, "retry_after": "", "body": ""}
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
    except OSError as e:
        rec["status"] = "connect-error"
        rec["body"] = str(e)
        results[i] = rec
        return
    head = f"{method} {path.replace('{i}', str(i))} HTTP/1.1\r\nHost: dtf\r\n"
    if auth != "-":
        head += f"Authorization: {auth}\r\n"
    head += f"Content-Type: application/octet-stream\r\nContent-Length: {declared}\r\n\r\n"
    got = b""
    try:
        s.sendall(head.encode())
        tick = 0.25 if rate > 0 else 2.0
        per_tick = max(1, int(rate * tick)) if rate > 0 else 1
        next_send = time.monotonic()
        while True:
            now = time.monotonic()
            if now - t0 >= hold:
                break
            if now >= next_send and rec["sent"] < declared:
                n = min(per_tick, declared - rec["sent"])
                try:
                    s.sendall(b"a" * n)
                    rec["sent"] += n
                except (BrokenPipeError, ConnectionResetError):
                    pass
                next_send = now + tick
            s.settimeout(max(0.01, min(next_send, t0 + hold) - time.monotonic()))
            try:
                chunk = s.recv(65536)
            except socket.timeout:
                continue
            except (ConnectionResetError, OSError):
                break
            if not chunk:
                break
            got += chunk
            if b"\r\n\r\n" in got:
                s.settimeout(0.5)
                try:
                    got += s.recv(65536)
                except (socket.timeout, OSError):
                    pass
                break
    finally:
        rec["secs"] = round(time.monotonic() - t0, 1)
        s.close()
    if got.startswith(b"HTTP/"):
        rec["status"] = got.split(b" ", 2)[1].decode()
        headers, _, body = got.partition(b"\r\n\r\n")
        for line in headers.split(b"\r\n"):
            k, _, v = line.partition(b":")
            if k.strip().lower() == b"retry-after":
                rec["retry_after"] = v.strip().decode()
        rec["body"] = body[:160].decode("utf-8", "replace")
    elif got:
        rec["status"] = "garbled"
    results[i] = rec


def main(argv):
    port, method, path, auth = int(argv[1]), argv[2], argv[3], argv[4]
    n, declared, rate, hold, out = int(argv[5]), int(argv[6]), float(argv[7]), float(argv[8]), argv[9]
    results = [None] * n
    threads = [threading.Thread(target=one, args=(i, port, method, path, auth, declared, rate, hold, results))
               for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    counts = {}
    with open(out, "w") as f:
        for rec in results:
            f.write(json.dumps(rec) + "\n")
            counts[rec["status"]] = counts.get(rec["status"], 0) + 1
    print(" ".join(f"{k}x{v}" for k, v in sorted(counts.items())))


if __name__ == "__main__":
    main(sys.argv)
