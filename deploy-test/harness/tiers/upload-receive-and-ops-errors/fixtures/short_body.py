#!/usr/bin/env python3
"""Send an HTTP/1.1 request whose body is shorter than its Content-Length.

usage: short_body.py HOST PORT METHOD PATH DECLARED SENT [Header: value]...

Writes the request line and headers with Content-Length: DECLARED, then SENT
bytes of body, then half-closes the socket (FIN) and reads whatever the server
answers. Prints the status code on the first line and the response body after
it. Prints "000" and the error when no response arrives within 30 s.
"""
import socket
import sys


def main():
    host, port, method, path = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
    declared, sent = int(sys.argv[5]), int(sys.argv[6])
    headers = sys.argv[7:]
    head = "%s %s HTTP/1.1\r\nHost: %s:%d\r\nContent-Length: %d\r\nConnection: close\r\n" % (
        method, path, host, port, declared)
    for h in headers:
        head += h + "\r\n"
    head += "\r\n"
    s = socket.create_connection((host, port), timeout=30)
    try:
        s.sendall(head.encode())
        s.sendall(b"{" + b"x" * (sent - 1))
        s.shutdown(socket.SHUT_WR)
        chunks = []
        while True:
            c = s.recv(65536)
            if not c:
                break
            chunks.append(c)
    except OSError as e:
        print("000")
        print("client error: %s" % e)
        return
    finally:
        s.close()
    raw = b"".join(chunks)
    if not raw:
        print("000")
        print("connection closed without a response")
        return
    head, _, body = raw.partition(b"\r\n\r\n")
    status = head.split(b"\r\n", 1)[0].split(b" ")
    print(status[1].decode() if len(status) > 1 else "000")
    if b"transfer-encoding: chunked" in head.lower():
        out, rest = b"", body
        while rest:
            size_line, _, rest = rest.partition(b"\r\n")
            try:
                n = int(size_line.strip() or b"0", 16)
            except ValueError:
                break
            if n == 0:
                break
            out, rest = out + rest[:n], rest[n + 2:]
        body = out
    print(body.decode("utf-8", "replace"))


if __name__ == "__main__":
    main()
