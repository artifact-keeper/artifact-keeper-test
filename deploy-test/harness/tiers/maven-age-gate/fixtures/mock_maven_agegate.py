#!/usr/bin/env python3
# =============================================================================
# mock_maven_agegate.py - canned Maven upstream for the maven-age-gate tier
# (artifact-keeper#4702)
# =============================================================================
# A stdlib-only Maven repository serving one artifact, com.example.agegate:widget,
# in two versions:
#
#   1.0.0   deployed 2024-01-02 (old)       Last-Modified on every file
#   2.0.0   deployed now minus 1 day (young)
#
# Each version has a POM, a jar and their .sha1 sidecars; every response for a
# version's files carries that version's deploy time as Last-Modified (what a
# repository manager sends). The GA-level maven-metadata.xml lists both, with
# latest/release 2.0.0 and lastUpdated the young deploy.
#
# Jar bytes are generated at start-up (a real zip in memory), so no binary is
# committed. GET /__log returns every request path seen, one per line.
# =============================================================================
import hashlib
import io
import os
import zipfile
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("MOCK_PORT", "80"))
G = "com/example/agegate"
A = "widget"
NOW = datetime.now(timezone.utc)
VERSIONS = {
    "1.0.0": datetime(2024, 1, 2, 3, 4, 5, tzinfo=timezone.utc),
    "2.0.0": NOW - timedelta(days=1),
}


def _jar(version: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("META-INF/MANIFEST.MF", f"Manifest-Version: 1.0\nImplementation-Version: {version}\n")
        zf.writestr(
            f"META-INF/maven/com.example.agegate/{A}/pom.properties",
            f"groupId=com.example.agegate\nartifactId={A}\nversion={version}\n",
        )
        zf.writestr("com/example/agegate/Widget.txt", f"widget {version}\n")
    return buf.getvalue()


def _pom(version: str) -> bytes:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<project xmlns="http://maven.apache.org/POM/4.0.0">\n'
        "  <modelVersion>4.0.0</modelVersion>\n"
        "  <groupId>com.example.agegate</groupId>\n"
        f"  <artifactId>{A}</artifactId>\n"
        f"  <version>{version}</version>\n"
        "</project>\n"
    ).encode()


FILES = {}  # path -> (body, content-type, last-modified)
for _v, _at in VERSIONS.items():
    _lm = format_datetime(_at, usegmt=True)
    for _ext, _body, _ct in (("pom", _pom(_v), "text/xml"), ("jar", _jar(_v), "application/java-archive")):
        _p = f"/{G}/{A}/{_v}/{A}-{_v}.{_ext}"
        FILES[_p] = (_body, _ct, _lm)
        FILES[_p + ".sha1"] = (hashlib.sha1(_body).hexdigest().encode(), "text/plain", _lm)

_young = max(VERSIONS.values())
METADATA = (
    '<?xml version="1.0" encoding="UTF-8"?>\n<metadata>\n'
    "  <groupId>com.example.agegate</groupId>\n"
    f"  <artifactId>{A}</artifactId>\n"
    "  <versioning>\n"
    "    <latest>2.0.0</latest>\n"
    "    <release>2.0.0</release>\n"
    "    <versions>\n"
    "      <version>1.0.0</version>\n"
    "      <version>2.0.0</version>\n"
    "    </versions>\n"
    f"    <lastUpdated>{_young.strftime('%Y%m%d%H%M%S')}</lastUpdated>\n"
    "  </versioning>\n</metadata>\n"
).encode()
FILES[f"/{G}/{A}/maven-metadata.xml"] = (METADATA, "text/xml", format_datetime(_young, usegmt=True))
FILES[f"/{G}/{A}/maven-metadata.xml.sha1"] = (
    hashlib.sha1(METADATA).hexdigest().encode(),
    "text/plain",
    format_datetime(_young, usegmt=True),
)
LOG = []


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def _send(self, code, body, ctype, lm=None, head=False):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        if lm:
            self.send_header("Last-Modified", lm)
        self.end_headers()
        if not head:
            self.wfile.write(body)

    def _serve(self, head):
        path = self.path.split("?", 1)[0]
        if path == "/__readyz":
            return self._send(200, b"ok", "text/plain")
        if path == "/__log":
            return self._send(200, ("\n".join(LOG) + "\n").encode(), "text/plain")
        LOG.append(f"{self.command} {path}")
        entry = FILES.get(path)
        if entry is None:
            return self._send(404, b"not found", "text/plain", head=head)
        body, ctype, lm = entry
        self._send(200, body, ctype, lm, head=head)

    def do_GET(self):  # noqa: N802
        self._serve(False)

    def do_HEAD(self):  # noqa: N802
        self._serve(True)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
