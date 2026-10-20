#!/usr/bin/env python3
"""Raw-socket and archive helpers for the http-edge-limits tier.

Stdlib only. Every network probe bounds its own wait, so a RED backend that
never answers makes the probe report "open"/"none" instead of hanging.

  head  PORT PAYLOAD MAXWAIT
      connect, send PAYLOAD (Python escapes, e.g. 'GET / HTTP/1.1\\r\\n';
      empty sends nothing), then wait up to MAXWAIT seconds for the peer.
      Prints "closed <secs> <bytes-received>" or "open <secs> <bytes-received>".
  trickle PORT PATH SECS
      send a complete, valid request head for PATH one header line at a time
      spread over SECS seconds, then read the response.
      Prints "<status> <secs>".
  send  METHOD PORT PATH AUTH DECLARED SEND MAXWAIT
      send `METHOD PATH` with `Authorization: AUTH`, `Content-Length: DECLARED`,
      then SEND body bytes, and wait up to MAXWAIT seconds for a status line.
      Prints "<status|none> <secs> <sent> <body-first-200-chars>".
  vsix  OUT PUBLISHER NAME VERSION [EXTRA_ENTRY ...]
      write a minimal VSIX (extension/package.json + extension.vsixmanifest)
      plus each EXTRA_ENTRY as a 7-byte file.
  zip   OUT ENTRY [ENTRY ...]
      write a zip holding only ENTRY files (no manifest).
"""
import socket
import sys
import time
import zipfile
import json


def _recv_until_close(sock, deadline):
    got = b""
    while True:
        left = deadline - time.monotonic()
        if left <= 0:
            return got, False
        sock.settimeout(left)
        try:
            chunk = sock.recv(65536)
        except socket.timeout:
            return got, False
        except (ConnectionResetError, BrokenPipeError):
            return got, True
        if not chunk:
            return got, True
        got += chunk


def cmd_head(port, payload, maxwait):
    data = payload.encode().decode("unicode_escape").encode("latin-1")
    s = socket.create_connection(("127.0.0.1", int(port)), timeout=5)
    t0 = time.monotonic()
    if data:
        s.sendall(data)
    got, closed = _recv_until_close(s, t0 + float(maxwait))
    secs = time.monotonic() - t0
    s.close()
    print(f"{'closed' if closed else 'open'} {secs:.1f} {len(got)}")


def cmd_trickle(port, path, secs):
    lines = [f"GET {path} HTTP/1.1\r\n", "Host: dtf\r\n", "User-Agent: dtf-trickle\r\n",
             "Accept: */*\r\n", "Connection: close\r\n", "\r\n"]
    gap = float(secs) / (len(lines) - 1)
    s = socket.create_connection(("127.0.0.1", int(port)), timeout=5)
    t0 = time.monotonic()
    for i, line in enumerate(lines):
        if i:
            time.sleep(gap)
        s.sendall(line.encode())
    got, _ = _recv_until_close(s, time.monotonic() + 10)
    s.close()
    status = got.split(b" ", 2)[1].decode() if got.startswith(b"HTTP/") else "none"
    print(f"{status} {time.monotonic() - t0:.1f}")


def cmd_send(method, port, path, auth, declared, send, maxwait):
    s = socket.create_connection(("127.0.0.1", int(port)), timeout=5)
    head = (f"{method} {path} HTTP/1.1\r\nHost: dtf\r\nAuthorization: {auth}\r\n"
            f"Content-Type: application/octet-stream\r\nContent-Length: {declared}\r\n\r\n")
    t0 = time.monotonic()
    s.sendall(head.encode())
    sent = 0
    try:
        if int(send):
            s.sendall(b"\0" * int(send))
            sent = int(send)
    except (BrokenPipeError, ConnectionResetError):
        pass
    got = b""
    deadline = t0 + float(maxwait)
    while b"\r\n\r\n" not in got or len(got) < 64:
        left = deadline - time.monotonic()
        if left <= 0:
            break
        s.settimeout(left)
        try:
            chunk = s.recv(65536)
        except (socket.timeout, ConnectionResetError):
            break
        if not chunk:
            break
        got += chunk
        if b"\r\n\r\n" in got:
            # give the body a moment to arrive
            s.settimeout(0.5)
            try:
                got += s.recv(65536)
            except (socket.timeout, ConnectionResetError):
                pass
            break
    secs = time.monotonic() - t0
    s.close()
    if got.startswith(b"HTTP/"):
        status = got.split(b" ", 2)[1].decode()
        body = got.split(b"\r\n\r\n", 1)[1][:200].decode("utf-8", "replace").replace("\n", " ")
    else:
        status, body = "none", ""
    print(f"{status} {secs:.1f} {sent} {body}")


def _write_zip(out, entries):
    with zipfile.ZipFile(out, "w", zipfile.ZIP_STORED) as z:
        for name, data in entries:
            info = zipfile.ZipInfo(name)
            z.writestr(info, data)


def cmd_vsix(out, publisher, name, version, extra):
    pkg = json.dumps({"publisher": publisher, "name": name, "version": version,
                      "displayName": "DTF Edge", "description": "dtf http-edge-limits",
                      "engines": {"vscode": "^1.75.0"}, "categories": ["Other"]})
    manifest = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<PackageManifest Version="2.0.0"><Metadata>'
        f'<Identity Id="{name}" Version="{version}" Publisher="{publisher}" '
        'TargetPlatform="universal"/></Metadata></PackageManifest>')
    entries = [("extension/package.json", pkg), ("extension.vsixmanifest", manifest)]
    entries += [(e, "payload") for e in extra]
    _write_zip(out, entries)


def main(argv):
    cmd = argv[1]
    if cmd == "head":
        cmd_head(*argv[2:5])
    elif cmd == "trickle":
        cmd_trickle(*argv[2:5])
    elif cmd == "send":
        cmd_send(*argv[2:9])
    elif cmd == "vsix":
        cmd_vsix(argv[2], argv[3], argv[4], argv[5], argv[6:])
    elif cmd == "zip":
        _write_zip(argv[2], [(e, "payload") for e in argv[3:]])
    else:
        sys.exit(f"unknown command {cmd}")


if __name__ == "__main__":
    main(sys.argv)
