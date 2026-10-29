#!/usr/bin/env python3
# =============================================================================
# mock_dup_entries.py - an npm + Maven + NuGet + Cargo sparse + conda upstream
# whose packages carry their manifest twice, for the
# scan-proxy-duplicate-entries tier
# =============================================================================
# Per format, two packages, built at start-up with stdlib zipfile / tarfile
# and FIXED timestamps so the bytes are identical on every run:
#
#   dtf-dup     the archive holds TWO entries at the manifest's path. The
#               first (npm, Cargo, conda, Maven) or the last (NuGet, which a
#               zip reader keyed on the raw name collapses to its last record)
#               names the requested coordinate; the other names another
#               package. A reader that takes one copy and an extractor that
#               keeps the other disagree about what the package is.
#   dtf-single  the same package with its manifest once (control).
#
#   npm    (upstream base http://<self>/npm)
#     <name>                        packument
#     <name>/-/<name>-1.0.0.tgz     tarball; dup: package/package.json twice
#   Maven  (upstream base http://<self>/maven2)
#     org/dtf/dup/<a>/1.0.0/<a>-1.0.0.{jar,jar.sha1,pom,pom.sha1}
#                                   dup: pom.properties again as ./META-INF/...
#   NuGet V3 (upstream base http://<self>/nuget/v3/index.json)
#     v3-flatcontainer/<id>/1.0.0/<id>.1.0.0.nupkg
#                                   dup: <Id>.nuspec twice, same raw name
#   Cargo sparse (upstream base http://<self>/cargo)
#     config.json, <prefix>/<name>, api/v1/crates/<name>/1.0.0/download
#                                   dup: <name>-1.0.0/Cargo.toml twice
#   conda  (upstream base http://<self>/conda)
#     noarch/<name>-1.0.0-0.tar.bz2 dup: info/index.json twice
#
# Control endpoints (never counted):
#   GET /__readyz                 healthcheck
#   GET /__sha256/<path>          sha256 hex of the bytes served at /<path>
#
# Stdlib only, single file, stock python image.
#   MOCK_PORT  listen port (default 80)
#   MOCK_SELF  absolute base URL the backend reaches this mock at
# =============================================================================
import bz2
import gzip
import hashlib
import io
import json
import os
import tarfile
import warnings
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

PORT = int(os.environ.get("MOCK_PORT", "80"))
SELF = os.environ.get("MOCK_SELF", "http://mock-dup").rstrip("/")
FIXED = (2020, 1, 1, 0, 0, 0)
FILES = {}

# zipfile warns on a repeated name and writes it anyway, which is the point.
warnings.simplefilter("ignore", UserWarning)


def b(data):
    return data.encode() if isinstance(data, str) else data


def sha1(data):
    return hashlib.sha1(data).hexdigest()


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def zip_bytes(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in entries:
            info = zipfile.ZipInfo(name, date_time=FIXED)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            z.writestr(info, b(data))
    return buf.getvalue()


def tar_bytes(entries):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as t:
        for name, data in entries:
            data = b(data)
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            ti.mtime = 1577836800
            ti.mode = 0o644
            t.addfile(ti, io.BytesIO(data))
    return raw.getvalue()


def tgz(entries):
    return gzip.compress(tar_bytes(entries), mtime=0)


def tbz2(entries):
    return bz2.compress(tar_bytes(entries))


# ------------------------------------------------------------------- npm
def add_npm(name, dup):
    manifest = json.dumps({"name": name, "version": "1.0.0", "main": "index.js"})
    entries = [("package/package.json", manifest), ("package/index.js", "module.exports = 1;\n")]
    if dup:
        other = json.dumps({"name": "dtf-other", "version": "9.9.9", "main": "index.js"})
        entries.append(("package/package.json", other))
    body = tgz(entries)
    tarball = f"npm/{name}/-/{name}-1.0.0.tgz"
    FILES[tarball] = body
    FILES[f"npm/{name}"] = json.dumps(
        {
            "name": name,
            "dist-tags": {"latest": "1.0.0"},
            "versions": {
                "1.0.0": {
                    "name": name,
                    "version": "1.0.0",
                    "dist": {"tarball": f"{SELF}/{tarball}", "shasum": sha1(body)},
                }
            },
        }
    ).encode()


add_npm("dtf-dup", dup=True)
add_npm("dtf-single", dup=False)


# ----------------------------------------------------------------- Maven
def pom(group, artifact, version):
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<project xmlns="http://maven.apache.org/POM/4.0.0">\n'
        "  <modelVersion>4.0.0</modelVersion>\n"
        f"  <groupId>{group}</groupId>\n  <artifactId>{artifact}</artifactId>\n"
        f"  <version>{version}</version>\n  <packaging>jar</packaging>\n</project>\n"
    ).encode()


def add_maven(artifact, dup):
    group = "org.dtf.dup"
    props = f"META-INF/maven/{group}/{artifact}/pom.properties"
    entries = [
        ("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\nCreated-By: dtf\n\n"),
        (props, f"groupId={group}\nartifactId={artifact}\nversion=1.0.0\n"),
        ("org/dtf/dup/Dtf.class", b"\xca\xfe\xba\xbe"),
    ]
    if dup:
        entries.append((f"./{props}", f"groupId={group}\nartifactId={artifact}\nversion=0.0.1\n"))
    body = zip_bytes(entries)
    base = f"maven2/{group.replace('.', '/')}/{artifact}/1.0.0/{artifact}-1.0.0"
    FILES[base + ".jar"] = body
    FILES[base + ".jar.sha1"] = sha1(body).encode()
    p = pom(group, artifact, "1.0.0")
    FILES[base + ".pom"] = p
    FILES[base + ".pom.sha1"] = sha1(p).encode()


add_maven("dtf-dup", dup=True)
add_maven("dtf-single", dup=False)


# ----------------------------------------------------------------- NuGet
def nuspec(pkg_id, version):
    return (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">\n'
        "  <metadata>\n"
        f"    <id>{pkg_id}</id>\n    <version>{version}</version>\n"
        "    <authors>dtf</authors>\n    <description>dtf fixture</description>\n"
        "  </metadata>\n</package>\n"
    ).encode()


def add_nuget(pkg_id, dup):
    low = pkg_id.lower()
    entries = [(f"{pkg_id}.nuspec", nuspec(pkg_id, "1.0.0")), ("lib/netstandard2.0/_._", b"")]
    if dup:
        # The other identity FIRST: a zip reader keyed on the raw name keeps
        # the last record, a client that takes the first gets this one.
        entries.insert(0, (f"{pkg_id}.nuspec", nuspec("Dtf.Other", "9.9.9")))
    base = f"nuget/v3-flatcontainer/{low}"
    FILES[f"{base}/1.0.0/{low}.1.0.0.nupkg"] = zip_bytes(entries)
    FILES[f"{base}/1.0.0/{low}.nuspec"] = nuspec(pkg_id, "1.0.0")
    FILES[f"{base}/index.json"] = json.dumps({"versions": ["1.0.0"]}).encode()


add_nuget("Dtf.Dup", dup=True)
add_nuget("Dtf.Single", dup=False)
FILES["nuget/v3/index.json"] = json.dumps(
    {
        "version": "3.0.0",
        "resources": [
            {"@id": f"{SELF}/nuget/v3-flatcontainer/", "@type": "PackageBaseAddress/3.0.0"},
            {"@id": f"{SELF}/nuget/v3/registration/", "@type": "RegistrationsBaseUrl/3.6.0"},
            {"@id": f"{SELF}/nuget/v3/query", "@type": "SearchQueryService"},
        ],
    }
).encode()


# ----------------------------------------------------------------- Cargo
def sparse_prefix(name):
    if len(name) <= 2:
        return str(len(name))
    if len(name) == 3:
        return f"3/{name[0]}"
    return f"{name[0:2]}/{name[2:4]}"


def add_crate(name, dup):
    toml = f'[package]\nname = "{name}"\nversion = "1.0.0"\nedition = "2018"\nlicense = "MIT"\n'
    entries = [(f"{name}-1.0.0/Cargo.toml", toml), (f"{name}-1.0.0/src/lib.rs", "pub fn dtf() {}\n")]
    if dup:
        other = '[package]\nname = "dtf-other"\nversion = "9.9.9"\nedition = "2018"\nlicense = "MIT"\n'
        entries.append((f"{name}-1.0.0/Cargo.toml", other))
    body = tgz(entries)
    FILES[f"cargo/api/v1/crates/{name}/1.0.0/download"] = body
    line = {"name": name, "vers": "1.0.0", "deps": [], "cksum": sha256(body), "features": {}, "yanked": False}
    FILES[f"cargo/{sparse_prefix(name)}/{name}"] = (json.dumps(line) + "\n").encode()


add_crate("dtf-dup", dup=True)
add_crate("dtf-single", dup=False)
FILES["cargo/config.json"] = json.dumps({"dl": f"{SELF}/cargo/api/v1/crates"}).encode()


# ----------------------------------------------------------------- conda
def add_conda(name, dup):
    index = json.dumps({"name": name, "version": "1.0.0", "build": "0", "build_number": 0, "subdir": "noarch"})
    entries = [("info/index.json", index), (f"site-packages/{name}/__init__.py", "")]
    if dup:
        other = json.dumps({"name": "dtf-other", "version": "9.9.9", "build": "0", "build_number": 0, "subdir": "noarch"})
        entries.append(("info/index.json", other))
    FILES[f"conda/noarch/{name}-1.0.0-0.tar.bz2"] = tbz2(entries)


add_conda("dtf-dup", dup=True)
add_conda("dtf-single", dup=False)


def ctype(path):
    if path.endswith(".json") or path.startswith("npm/") and "/-/" not in path:
        return "application/json"
    if path.endswith(".pom"):
        return "application/xml"
    if path.endswith(".sha1"):
        return "text/plain"
    return "application/octet-stream"


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        print("mock-dup: " + (fmt % args), flush=True)

    def _send(self, code, data, ct, head):
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if not head:
            self.wfile.write(data)

    def _serve(self, head):
        path = urlsplit(self.path).path
        if path == "/__readyz":
            return self._send(200, b"ok", "text/plain", head)
        if path.startswith("/__sha256/"):
            key = path[len("/__sha256/"):]
            if key in FILES:
                return self._send(200, sha256(FILES[key]).encode(), "text/plain", head)
            return self._send(404, b"no such fixture", "text/plain", head)
        key = path.lstrip("/")
        if key in FILES:
            return self._send(200, FILES[key], ctype(key), head)
        return self._send(404, b"not found", "text/plain", head)

    def do_GET(self):  # noqa: N802
        self._serve(False)

    def do_HEAD(self):  # noqa: N802
        self._serve(True)


if __name__ == "__main__":
    print(f"mock-dup: {len(FILES)} fixtures, self={SELF}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
