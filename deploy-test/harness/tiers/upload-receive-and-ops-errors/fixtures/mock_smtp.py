#!/usr/bin/env python3
"""Steerable mock SMTP server (stdlib only) for the DTF mail tiers.

Used through profiles/mail.mock-smtp.yml by upload-receive-and-ops-errors and
ops-endpoints-1110.

Listeners
  :25   plaintext SMTP, no STARTTLS. Behaviour follows the mode file.
  :465  implicit TLS, always accepts.
  :587  plaintext with STARTTLS advertised, accepts mail only after STARTTLS.
        Both TLS listeners load /tmp/smtp/tls/smtp.crt and smtp.key on every
        connection. No key material is committed: a tier that needs TLS
        generates a throwaway CA and server certificate (CN/SAN mock-smtp)
        and copies them in with `docker cp`. Without them a TLS connection
        is closed at once.
  :8025 HTTP: GET /__readyz -> "ok" (the compose healthcheck).

Mode file /tmp/smtp/mode (port 25 only; write it with docker exec):
  accept       EHLO advertises AUTH PLAIN LOGIN, AUTH answers 235, mail is
               accepted and recorded.
  reject535    EHLO advertises AUTH PLAIN LOGIN, AUTH answers
               535 5.7.3 Authentication unsuccessful.
  silent-once  the next connection is accepted and never answered (no
               greeting); the mode then reverts to accept, so the backend's
               follow-up EHLO probe gets an answer.

Records (read with docker exec cat):
  /tmp/smtp/messages.jsonl  one JSON line per accepted message:
                            {"port", "tls", "mail_from", "rcpt", "subject"}
  /tmp/smtp/conns.log       one line per connection: "<port> <mode>"

Every connection carries at most one message and is closed after it, so a
client that pools connections (lettre does) dials again for the next message
and sees the current mode.
"""
import base64
import json
import os
import socket
import socketserver
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

STATE = "/tmp/smtp"
MODE_FILE = os.path.join(STATE, "mode")
MSG_FILE = os.path.join(STATE, "messages.jsonl")
CONN_FILE = os.path.join(STATE, "conns.log")
TLS_DIR = os.path.join(STATE, "tls")
CERT = os.path.join(TLS_DIR, "smtp.crt")
KEY = os.path.join(TLS_DIR, "smtp.key")
LOCK = threading.Lock()


def tls_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT, KEY)
    return ctx


def read_mode():
    try:
        with open(MODE_FILE) as f:
            return f.read().strip() or "accept"
    except OSError:
        return "accept"


def write_mode(mode):
    with open(MODE_FILE, "w") as f:
        f.write(mode + "\n")


def append(path, line):
    with LOCK:
        with open(path, "a") as f:
            f.write(line + "\n")


class Session(socketserver.BaseRequestHandler):
    def setup(self):
        self.port = self.server.server_address[1]
        self.tls = False
        self.sock = self.request

    def _io(self):
        self.rf = self.sock.makefile("rb")

    def send(self, line):
        self.sock.sendall((line + "\r\n").encode())

    def readline(self):
        raw = self.rf.readline(65536)
        if not raw:
            raise EOFError
        return raw.decode("utf-8", "replace").rstrip("\r\n")

    def handle(self):
        mode = read_mode() if self.port == 25 else "accept"
        if self.port == 25 and mode == "silent-once":
            write_mode("accept")
        append(CONN_FILE, "%d %s" % (self.port, mode))
        try:
            if self.port == 465:
                self.sock = tls_context().wrap_socket(self.sock, server_side=True)
                self.tls = True
            if mode == "silent-once":
                # Never greet. Hold the connection until the client gives up.
                self.sock.settimeout(180)
                try:
                    while self.sock.recv(4096):
                        pass
                except OSError:
                    pass
                return
            self._io()
            self.converse(mode)
        except (EOFError, OSError, ssl.SSLError):
            return

    def ehlo_lines(self):
        lines = ["mock-smtp greets you"]
        if self.port == 587 and not self.tls:
            lines.append("STARTTLS")
        lines.append("AUTH PLAIN LOGIN")
        lines.append("8BITMIME")
        return lines

    def auth(self, mode, arg):
        parts = arg.split(None, 1)
        mech = parts[0].upper() if parts else ""
        if mech == "PLAIN":
            if len(parts) < 2:
                self.send("334 ")
                self.readline()
        elif mech == "LOGIN":
            self.send("334 " + base64.b64encode(b"Username:").decode())
            self.readline()
            self.send("334 " + base64.b64encode(b"Password:").decode())
            self.readline()
        else:
            self.send("504 5.5.4 Unrecognized authentication type")
            return
        if mode == "reject535":
            self.send("535 5.7.3 Authentication unsuccessful")
        else:
            self.send("235 2.7.0 Authentication successful")

    def converse(self, mode):
        self.send("220 mock-smtp ESMTP ready")
        mail_from, rcpt = None, []
        while True:
            line = self.readline()
            verb, _, arg = line.partition(" ")
            verb = verb.upper()
            if verb in ("EHLO", "HELO"):
                lines = self.ehlo_lines()
                for l in lines[:-1]:
                    self.send("250-" + l)
                self.send("250 " + lines[-1])
            elif verb == "STARTTLS" and self.port == 587 and not self.tls:
                self.send("220 2.0.0 Ready to start TLS")
                self.sock = tls_context().wrap_socket(self.sock, server_side=True)
                self.tls = True
                self._io()
            elif verb == "AUTH":
                self.auth(mode, arg)
            elif verb == "MAIL":
                if self.port == 587 and not self.tls:
                    self.send("530 5.7.0 Must issue a STARTTLS command first")
                    continue
                mail_from, rcpt = arg, []
                self.send("250 2.1.0 OK")
            elif verb == "RCPT":
                rcpt.append(arg)
                self.send("250 2.1.5 OK")
            elif verb == "DATA":
                self.send("354 End data with <CR><LF>.<CR><LF>")
                subject = ""
                while True:
                    d = self.readline()
                    if d == ".":
                        break
                    if d.lower().startswith("subject:") and not subject:
                        subject = d.split(":", 1)[1].strip()
                append(MSG_FILE, json.dumps({
                    "port": self.port, "tls": self.tls,
                    "mail_from": mail_from, "rcpt": rcpt, "subject": subject}))
                self.send("250 2.0.0 OK queued")
                # One message per connection: lettre pools connections, and a
                # pooled connection would never see a new mode. Closing here
                # makes its NOOP liveness check fail so the next send dials
                # again and reads the mode file afresh.
                return
            elif verb == "RSET":
                mail_from, rcpt = None, []
                self.send("250 2.0.0 OK")
            elif verb == "NOOP":
                self.send("250 2.0.0 OK")
            elif verb == "QUIT":
                self.send("221 2.0.0 Bye")
                return
            else:
                self.send("502 5.5.2 Command not recognized")


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class Health(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        body = b"ok" if self.path == "/__readyz" else b"not found"
        self.send_response(200 if body == b"ok" else 404)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    os.makedirs(STATE, exist_ok=True)
    if not os.path.exists(MODE_FILE):
        write_mode("accept")
    for port in (25, 465, 587):
        srv = Server(("0.0.0.0", port), Session)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", 8025), Health).serve_forever()


if __name__ == "__main__":
    socket.setdefaulttimeout(None)
    main()
