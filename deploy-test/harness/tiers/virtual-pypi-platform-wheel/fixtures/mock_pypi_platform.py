#!/usr/bin/env python3
# =============================================================================
# mock_pypi_platform.py - canned PyPI upstream for the virtual-pypi-platform-wheel
# tier (#2937 / #2748, hardened for #2967 rounds 2 and 3)
# =============================================================================
# A stdlib-only PyPI simple-index upstream that advertises several wheels of a
# locally-owned project (`dtfwheel`), when this remote is a LOWER-priority member
# of a virtual whose LOCAL member owns the name and ships the LINUX
# `dtfwheel==2.0` wheel.
#
# HONEST anchors (double-quoted, closed, href back to this mock):
#   * CASE_A     dtfwheel-2.0-cp39-cp39-win_amd64.whl - platform-distinct wheel
#                of the OWNED 2.0. MUST surface (AK path) + download 200.
#   * CASE_B     dtfwheel-1.9-cp39-cp39-win_amd64.whl - remote-only version.
#                MUST be suppressed (absent + 404).
#   * UNIVERSAL  dtfwheel-2.0-py3-none-any.whl (#2967 R2 MEDIUM) - not a platform
#                build. MUST be suppressed.
#   * CASEVAR    dtfwheel-2.0-cp39-cp39-MANYLINUX_2_17_x86_64.whl (#2967 R2
#                MEDIUM) - case-variant of the local tag. MUST be suppressed.
#
# ATTACKER anchors (#2967 R3 - the residual #1600 bypass): every shape that a
# span-replace filter + double-quote-only rewriter let through - UNCLOSED and
# MALFORMED-close anchors in single-quote, uppercase-double-quote, and UNQUOTED
# forms, each pointing OFF-SITE at a distinct remote-only version. ALL must be
# absent from the rendered index (no off-site href, no remote-only version) and
# 404 on download.
#
# Each honest href points back at this mock so AK can stream the bytes; the mock
# serves those bytes at `/files/<filename>` (case-sensitive). The mock subnet is
# 172.16/12, allowlisted by AK_SSRF_ALLOW_PRIVATE_CIDRS.
# =============================================================================
import hashlib
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("MOCK_PORT", "80"))
PKG = os.environ.get("MOCK_PKG", "dtfwheel")
EVIL = "evilhost"  # off-site host the attacker anchors point at

# #2967 R4 (CRITICAL content-type bypass): a SECOND project the mock serves as an
# HTML body MISLABELED `Content-Type: application/json`. On the pre-R4 build the
# ownership filter trusted `ct.contains("json")`, echoed the HTML body verbatim,
# then sniffed it as HTML and ran it through the in-place `rewrite_upstream_urls`
# rewriter (NO ownership filter). Its `[^>]*?` cannot cross a `>`, so an anchor
# whose `href` follows a `>` inside an attribute is left off-site -> a raw evil
# href reaches pip AND a remote-only Case-B version surfaces. The R4 fix sniffs
# the BODY (not the header), routes the HTML through the ownership rebuild, and
# fails closed otherwise -> only owned Case-A AK paths survive.
PKG_R4 = "dtfjson"
R4_CASE_A_WHEEL = f"{PKG_R4}-1.0-cp39-cp39-win_amd64.whl"   # owned ver 1.0, win -> UNION (AK path)
R4_CASE_B_WHEEL = f"{PKG_R4}-2.0-cp39-cp39-win_amd64.whl"   # remote-only 2.0 -> SUPPRESS

CASE_A_WHEEL = f"{PKG}-2.0-cp39-cp39-win_amd64.whl"                 # union
CASE_B_WHEEL = f"{PKG}-1.9-cp39-cp39-win_amd64.whl"                 # remote-only version
UNIVERSAL_WHEEL = f"{PKG}-2.0-py3-none-any.whl"                     # universal (owned ver)
CASEVAR_WHEEL = f"{PKG}-2.0-cp39-cp39-MANYLINUX_2_17_x86_64.whl"    # case-variant of local tag

# Attacker off-site wheels, keyed by the remote-only version fragment used in the
# oracle assertions.
ATTACK_WHEELS = {
    "4.4": f"{PKG}-4.4-cp39-cp39-win_amd64.whl",   # UNCLOSED single-quote
    "5.5": f"{PKG}-5.5-cp39-cp39-win_amd64.whl",   # UNCLOSED uppercase double-quote
    "6.6": f"{PKG}-6.6-cp39-cp39-win_amd64.whl",   # </a > malformed close, single-quote
    "7.7": f"{PKG}-7.7-cp39-cp39-win_amd64.whl",   # </ a> malformed close, uppercase
    "8.8": f"{PKG}-8.8-cp39-cp39-win_amd64.whl",   # UNCLOSED unquoted
}

FILE_BYTES = {
    CASE_A_WHEEL: f"REMOTE-WINDOWS-WHEEL::{CASE_A_WHEEL}".encode("utf-8"),
    CASE_B_WHEEL: f"REMOTE-WINDOWS-WHEEL::{CASE_B_WHEEL}".encode("utf-8"),
    UNIVERSAL_WHEEL: f"REMOTE-UNIVERSAL-WHEEL::{UNIVERSAL_WHEEL}".encode("utf-8"),
    CASEVAR_WHEEL: f"REMOTE-CASEVARIANT-WHEEL::{CASEVAR_WHEEL}".encode("utf-8"),
}
for _fn in ATTACK_WHEELS.values():
    FILE_BYTES[_fn] = f"REMOTE-EVIL-OFFSITE::{_fn}".encode("utf-8")

# The R4 Case-A wheel is a REAL downloadable file (href back to this mock), so the
# fix's index-vs-download symmetry holds (Case-A downloads 200). The Case-B wheel
# is never served here (off-site + suppressed).
FILE_BYTES[R4_CASE_A_WHEEL] = f"REMOTE-R4-CASEA::{R4_CASE_A_WHEEL}".encode("utf-8")


def _sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _index_html() -> bytes:
    def honest(fn):
        h = _sha256(FILE_BYTES[fn])
        return f'<a href="http://mock-pypi/files/{fn}#sha256={h}">{fn}</a><br/>'

    a = ATTACK_WHEELS
    # Attacker block: placed AFTER the honest closed anchors, with NO valid `</a>`
    # among them, so a `.*?</a>` span filter cannot pair them and they pass
    # through untouched; each uses a quote/case form the double-quote-only
    # rewriter misses. Every href points OFF-SITE at a remote-only version.
    attackers = [
        # UNCLOSED single-quote.
        f"<a href='http://{EVIL}/files/{a['4.4']}#sha256=x'>text-{CASE_A_WHEEL}",
        # UNCLOSED uppercase double-quote.
        f'<A HREF="http://{EVIL}/files/{a["5.5"]}">text-{CASE_A_WHEEL}',
        # Malformed close `</a >`, single-quote.
        f"<a href='http://{EVIL}/files/{a['6.6']}'>zz</a >",
        # Malformed close `</ a>`, uppercase double-quote.
        f'<A HREF="http://{EVIL}/files/{a["7.7"]}">zz</ a>',
        # UNCLOSED unquoted.
        f"<a href=http://{EVIL}/files/{a['8.8']}>",
    ]

    lines = [
        "<!DOCTYPE html>",
        "<html><head>",
        '<meta name="pypi:repository-version" content="1.0"/>',
        f"<title>Links for {PKG}</title>",
        "</head><body>",
        f"<h1>Links for {PKG}</h1>",
        honest(CASE_A_WHEEL),
        honest(CASE_B_WHEEL),
        honest(UNIVERSAL_WHEEL),
        honest(CASEVAR_WHEEL),
        *attackers,
        "</body></html>",
    ]
    return ("\n".join(lines) + "\n").encode("utf-8")


def _index_html_r4() -> bytes:
    # HTML body deliberately mislabeled `application/json` by the handler below.
    #   * honest Case-A anchor (double-quoted, href back to this mock): the owned
    #     1.0 win wheel. Must UNION as an AK path + download 200.
    #   * off-site Case-B anchor: a remote-only 2.0 win wheel, off-site host, with
    #     a `>` INSIDE a prior `title` attribute so `rewrite_upstream_urls`'
    #     `[^>]*?` stops before `href`. On the pre-R4 build this raw off-site href
    #     leaks AND surfaces 2.0; on the fix it is suppressed entirely.
    a_h = _sha256(FILE_BYTES[R4_CASE_A_WHEEL])
    lines = [
        "<!DOCTYPE html>",
        "<html><head>",
        '<meta name="pypi:repository-version" content="1.0"/>',
        "</head><body>",
        f'<a href="http://mock-pypi/files/{R4_CASE_A_WHEEL}#sha256={a_h}">{R4_CASE_A_WHEEL}</a><br/>',
        f'<a title="x>y" href="http://{EVIL}/files/{R4_CASE_B_WHEEL}#sha256=cc">{R4_CASE_B_WHEEL}</a><br/>',
        "</body></html>",
    ]
    return ("\n".join(lines) + "\n").encode("utf-8")


INDEX_BODY = _index_html()
INDEX_BODY_R4 = _index_html_r4()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, code, ctype, body):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/__readyz":
            self._send(200, "text/plain", b"ok")
            return
        if self.path.startswith("/files/"):
            fn = self.path[len("/files/"):]
            body = FILE_BYTES.get(fn)
            if body is None:
                self._send(404, "text/plain", b"not found")
            else:
                self._send(200, "application/octet-stream", body)
            return
        # #2967 R4: the second project's simple index is an HTML body served with
        # a MISLABELED `application/json` Content-Type (the content-type bypass).
        if f"/{PKG_R4}/" in self.path or self.path.rstrip("/").endswith(PKG_R4):
            self._send(200, "application/json", INDEX_BODY_R4)
            return
        # Any other path is a simple-index request: honest text/html listing.
        self._send(200, "text/html; charset=utf-8", INDEX_BODY)

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(INDEX_BODY)))
        self.end_headers()

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
