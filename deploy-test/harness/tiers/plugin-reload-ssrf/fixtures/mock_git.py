#!/usr/bin/env python3
"""Stdlib-only git smart-HTTP server serving one WASM plugin repository.

Used by the plugin-reload-ssrf DTF tier (artifact-keeper#4757,
GHSA-r8fc-5fvw-rvh4). The backend clones plugins with libgit2, which speaks
only the smart HTTP protocol (no dumb HTTP), so this mock implements the
two endpoints a v0 clone needs:

  GET  <repo>.git/info/refs?service=git-upload-pack   ref advertisement
  POST <repo>.git/git-upload-pack                     NAK + packfile

The repository is built in memory (blob/tree/commit objects, pack v2) from
three files: plugin.toml, plugin.wasm (the smallest valid WebAssembly
component: magic plus component version and layer, no sections) and
plugin.wasm.sig (a detached Ed25519 signature over those exact bytes, made
once with a throwaway key whose private half was discarded; the public half
is the tier's PLUGINS_TRUSTED_PUBKEY).

Control, from the oracle via `docker exec`: GET /__ctl?version=X&sig=MODE
sets the manifest version and the signature mode (good | bad | none) for the
next clone; name=N sets the plugin name and format key (default PLUGIN_NAME
and PLUGIN_FORMAT_KEY). GET /__ctl?redirect=URL makes the reference advertisement
answer 302 to URL + "/info/refs?service=git-upload-pack" (the smart-HTTP
redirect a git client follows to a moved repository; added for the
plugin-fetch-pinned-address tier). A request for URL's own path is served,
so a redirect to this mock does not loop; an empty redirect= turns it off.
While redirect= is set, a plain GET whose path contains /__redir/ (an
artifact fetch through a Remote repository, not git) answers 302 to URL + "/"
+ the rest of the path after /__redir/ (the proxy-path case of
plugin-fetch-pinned-address, #4869). GET /__readyz answers "ok".

Every request line is printed to stdout as
  MOCKGIT <MOCK_NAME> <METHOD> <PATH>
so the oracle can prove from `docker logs` whether the backend connected.
"""
import hashlib
import os
import struct
import sys
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

NAME = os.environ.get("MOCK_NAME", "mock-git")
PORT = int(os.environ.get("MOCK_PORT", "80"))
PLUGIN_NAME = os.environ.get("PLUGIN_NAME", "dtf-reload-probe")
FORMAT_KEY = os.environ.get("PLUGIN_FORMAT_KEY", "dtf-reload-probe")

WASM = b"\x00asm\x0d\x00\x01\x00"
GOOD_SIG = (
    "lDfSSqhE7PrZgt6N7dmkw4jmzd9ejehsfs+7EsALwkL2F0Ke/OtXHKfmpaPTkFPj"
    "97zPxqtnD+ew74GuJRuMCQ==\n"
)
# Same length, last bytes flipped: a well-formed signature that does not
# verify against the trusted key.
BAD_SIG = (
    "lDfSSqhE7PrZgt6N7dmkw4jmzd9ejehsfs+7EsALwkL2F0Ke/OtXHKfmpaPTkFPj"
    "97zPxqtnD+ew74GuJRuMAA==\n"
)

STATE = {"version": "1.0.0", "sig": "good", "redirect": "", "name": ""}


def obj(kind, body):
    raw = kind.encode() + b" " + str(len(body)).encode() + b"\0" + body
    return hashlib.sha1(raw).digest(), kind, body


def build_repo():
    name = STATE["name"] or PLUGIN_NAME
    key = STATE["name"] or FORMAT_KEY
    toml = (
        "[plugin]\n"
        f'name = "{name}"\n'
        f'version = "{STATE["version"]}"\n'
        'description = "DTF plugin-reload-ssrf probe plugin"\n'
        "\n[format]\n"
        f'key = "{key}"\n'
        'display_name = "DTF reload probe"\n'
        'extensions = [".dtfprobe"]\n'
    ).encode()
    files = [("plugin.toml", toml), ("plugin.wasm", WASM)]
    if STATE["sig"] == "good":
        files.append(("plugin.wasm.sig", GOOD_SIG.encode()))
    elif STATE["sig"] == "bad":
        files.append(("plugin.wasm.sig", BAD_SIG.encode()))
    objs = []
    entries = b""
    for fname, data in sorted(files, key=lambda f: f[0].encode()):
        blob = obj("blob", data)
        objs.append(blob)
        entries += b"100644 " + fname.encode() + b"\0" + blob[0]
    tree = obj("tree", entries)
    objs.append(tree)
    ident = b"DTF <dtf@example.invalid> 1700000000 +0000"
    commit = obj(
        "commit",
        b"tree " + tree[0].hex().encode() + b"\nauthor " + ident
        + b"\ncommitter " + ident + b"\n\nplugin " + STATE["version"].encode()
        + b" sig=" + STATE["sig"].encode() + b"\n",
    )
    objs.append(commit)
    types = {"commit": 1, "tree": 2, "blob": 3}
    pack = b"PACK" + struct.pack(">II", 2, len(objs))
    for _sha, kind, body in objs:
        size = len(body)
        byte = (types[kind] << 4) | (size & 0x0F)
        size >>= 4
        hdr = b""
        while size:
            hdr += bytes([byte | 0x80])
            byte = size & 0x7F
            size >>= 7
        hdr += bytes([byte])
        pack += hdr + zlib.compress(body)
    pack += hashlib.sha1(pack).digest()
    return commit[0].hex(), pack


def pkt(line):
    data = line.encode() if isinstance(line, str) else line
    return b"%04x" % (len(data) + 4) + data


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # quiet the default access log
        pass

    def _send(self, code, ctype, body):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parts = urlsplit(self.path)
        if parts.path == "/__readyz":
            return self._send(200, "text/plain", b"ok")
        if parts.path == "/__ctl":
            q = parse_qs(parts.query, keep_blank_values=True)
            if "redirect" in q:
                STATE["redirect"] = q["redirect"][0]
            if "name" in q:
                STATE["name"] = q["name"][0]
            if "version" in q:
                STATE["version"] = q["version"][0]
            if "sig" in q:
                STATE["sig"] = q["sig"][0]
            return self._send(200, "text/plain",
                              (f"version={STATE['version']} sig={STATE['sig']} "
                               f"redirect={STATE['redirect']}").encode())
        print(f"MOCKGIT {NAME} GET {self.path}", flush=True)
        if STATE["redirect"] and "/__redir/" in parts.path:
            target = STATE["redirect"] + "/" + parts.path.split("/__redir/", 1)[1]
            print(f"MOCKGIT {NAME} 302 -> {target}", flush=True)
            self.send_response(302)
            self.send_header("Location", target)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return None
        if parts.path.endswith("/info/refs") and "service=git-upload-pack" in parts.query:
            moved = urlsplit(STATE["redirect"]).path
            if STATE["redirect"] and not parts.path.startswith(moved + "/"):
                target = STATE["redirect"] + "/info/refs?" + parts.query
                print(f"MOCKGIT {NAME} 302 -> {target}", flush=True)
                self.send_response(302)
                self.send_header("Location", target)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return None
            head, _pack = build_repo()
            body = (
                pkt("# service=git-upload-pack\n") + b"0000"
                + pkt(f"{head} HEAD\0symref=HEAD:refs/heads/main agent=git/dtf-mock\n")
                + pkt(f"{head} refs/heads/main\n") + b"0000"
            )
            return self._send(200, "application/x-git-upload-pack-advertisement", body)
        return self._send(404, "text/plain", b"not found\n")

    def do_POST(self):
        parts = urlsplit(self.path)
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        elif self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            while True:
                size = int(self.rfile.readline().strip() or b"0", 16)
                self.rfile.read(size + 2)
                if size == 0:
                    break
        print(f"MOCKGIT {NAME} POST {self.path}", flush=True)
        if parts.path.endswith("/git-upload-pack"):
            _head, pack = build_repo()
            return self._send(200, "application/x-git-upload-pack-result",
                              pkt("NAK\n") + pack)
        return self._send(404, "text/plain", b"not found\n")


def main():
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"MOCKGIT {NAME} listening on {PORT}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()
