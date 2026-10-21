#!/usr/bin/env python3
"""Stdlib-only DNS server whose answer for one name changes between lookups.

Used by the plugin-fetch-pinned-address DTF tier (artifact-keeper#4827). The
backend checks a plugin git URL by resolving its host, then clones it. This
server answers the A query for REBIND_NAME with ADMITTED_IP for the first
`first` lookups after a reset and with INTERNAL_IP for every lookup after
that, so a fetch that resolves the host again on its own (instead of
connecting to an address the SSRF policy checked) lands on the internal
host. Mode `static` answers ADMITTED_IP every time (the control).

Every other name is relayed verbatim to the nameservers in this container's
own /etc/resolv.conf (the compose network resolvers), first useful answer
wins, so a backend whose resolver is this server still finds `postgres` and
every other service. AAAA and other types for REBIND_NAME get an empty
NOERROR answer. TTL is 0.

Control, from the oracle via `docker exec` on 127.0.0.1:8053:
  GET /__ctl?mode=rebind&first=N   reset the counter; N admitted answers first
  GET /__ctl?mode=static           reset; always the admitted address
  GET /__readyz                    "ok"
Each answer for REBIND_NAME is printed as
  MOCKDNS A #<n> <name> -> <ip>
so the oracle can count the lookups the backend made.
"""
import os
import socket
import struct
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

NAME = os.environ["REBIND_NAME"].lower().rstrip(".")
ADMITTED = os.environ["ADMITTED_IP"]
INTERNAL = os.environ["INTERNAL_IP"]
LOCK = threading.Lock()
STATE = {"mode": "static", "first": 1, "count": 0}


def upstreams():
    own = set()
    try:
        own = {a[4][0] for a in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET)}
    except OSError:
        pass
    out = []
    with open("/etc/resolv.conf") as fh:
        for line in fh:
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "nameserver" and parts[1] not in own:
                out.append(parts[1])
    return out


UPSTREAMS = upstreams()


def parse_question(msg):
    pos, labels = 12, []
    while True:
        n = msg[pos]
        if n == 0:
            pos += 1
            break
        labels.append(msg[pos + 1:pos + 1 + n].decode("ascii", "replace"))
        pos += 1 + n
    qtype, _qclass = struct.unpack(">HH", msg[pos:pos + 4])
    return ".".join(labels).lower(), qtype, pos + 4


def answer(query, qend, ip):
    tid = query[:2]
    flags = 0x8180  # response, RD, RA, NOERROR
    ancount = 1 if ip else 0
    hdr = tid + struct.pack(">HHHHH", flags, 1, ancount, 0, 0)
    out = hdr + query[12:qend]
    if ip:
        out += b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 0, 4) + socket.inet_aton(ip)
    return out


def relay(query):
    first = None
    for ns in UPSTREAMS:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        try:
            s.sendto(query, (ns, 53))
            resp, _ = s.recvfrom(4096)
        except OSError:
            continue
        finally:
            s.close()
        if first is None:
            first = resp
        rcode = resp[3] & 0x0F
        ancount = struct.unpack(">H", resp[6:8])[0]
        if rcode == 0 and ancount > 0:
            return resp
    if first is not None:
        return first
    # SERVFAIL, question echoed
    return query[:2] + b"\x81\x82" + query[4:]


def serve_dns():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 53))
    while True:
        query, peer = sock.recvfrom(4096)
        threading.Thread(target=handle, args=(sock, query, peer), daemon=True).start()


def handle(sock, query, peer):
    try:
        qname, qtype, qend = parse_question(query)
    except (IndexError, struct.error):
        return
    if qname == NAME:
        ip = None
        if qtype == 1:
            with LOCK:
                STATE["count"] += 1
                n = STATE["count"]
                ip = ADMITTED if STATE["mode"] == "static" or n <= STATE["first"] else INTERNAL
            print(f"MOCKDNS A #{n} {qname} -> {ip}", flush=True)
        sock.sendto(answer(query, qend, ip), peer)
        return
    sock.sendto(relay(query), peer)


class Ctl(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        parts = urlsplit(self.path)
        if parts.path == "/__ctl":
            q = parse_qs(parts.query)
            with LOCK:
                STATE["mode"] = q.get("mode", [STATE["mode"]])[0]
                STATE["first"] = int(q.get("first", [STATE["first"]])[0])
                STATE["count"] = 0
                body = f"mode={STATE['mode']} first={STATE['first']}".encode()
            print(f"MOCKDNS reset {body.decode()}", flush=True)
        elif parts.path == "/__readyz":
            body = b"ok"
        else:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    threading.Thread(target=serve_dns, daemon=True).start()
    print(f"MOCKDNS {NAME} admitted={ADMITTED} internal={INTERNAL} upstreams={UPSTREAMS}", flush=True)
    try:
        ThreadingHTTPServer(("127.0.0.1", 8053), Ctl).serve_forever()
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()
