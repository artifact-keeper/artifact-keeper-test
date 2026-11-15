#!/usr/bin/env python3
# =============================================================================
# build_fixtures.py <out-dir> <upstream-base-url>
#   npm and Cargo packages for the scan-proxy-identity-npm-cargo tier
# =============================================================================
# Writes every file the tier's Remotes fetch into <out-dir> and an index,
# <out-dir>/files.tsv, with one line per file:
#     <upstream path>\t<local file>\t<content type>
# The oracle PUTs each one into the mock-files upstream (profiles/
# upstreams.mock-files.yml) at that path. <upstream-base-url> is the address
# the BACKEND reaches the mock at; it goes into the npm packuments' tarball
# URLs and the Cargo config.json "dl".
#
# Every archive is built with fixed timestamps, so the bytes and digests are
# the same on every run. Stdlib only.
#
# npm (packument at /npm/<name>, tarball at /npm/<name>/-/<file>.tgz)
#   dtf-idclean 1.0.0     package/package.json first          (control)
#   lodash 4.17.15        its own coordinate has advisories    (control)
#   dtf-late 1.0.0        10050 tiny entries BEFORE package/package.json
#                         (#5148: past the 10000-entry metadata cap)
#   dtf-late-liar 1.0.0   10050 entries, then a package.json that declares
#                         1.0.1 (#5148: a refusal must name the real cause)
#   @types/dtfnode 1.0.0  top-level directory dtfnode/, as DefinitelyTyped
#                         publishes (#5149)
#   dtf-burst-NN 1.0.0    NN = 01..BURST, ordinary packages, distinct bytes
#                         (#5231: a burst of first-time scans)
# Cargo sparse registry (/cargo/config.json, /cargo/<prefix>/<name>,
#   /cargo/api/v1/crates/<name>/<v>/download)
#   dtf-idcrate 1.0.0     readme = "README.md"                 (control)
#   regex 1.5.4           its own coordinate has an advisory   (control)
#   dtf-noreadme 1.0.0    readme = false   (#5140)
#   dtf-readmetrue 1.0.0  readme = true    (#5140)
#   dtf-withlock 1.0.0    ships a Cargo.lock locking crossbeam-deque 0.7.3
#                         (CVE-2021-32810, critical) and crossbeam-utils
#                         0.7.2 (#5143)
#   dtf-lockdeep 1.0.0    the same lockfile, nested at fuzz/Cargo.lock (#5143)
# =============================================================================
import gzip
import hashlib
import base64
import io
import json
import os
import sys
import tarfile

OUT = sys.argv[1]
SELF = sys.argv[2].rstrip("/")
BURST = int(os.environ.get("BURST", "16"))
MTIME = 1577836800
INDEX = []


def emit(path, data, ctype="application/octet-stream"):
    data = data.encode() if isinstance(data, str) else data
    local = os.path.join(OUT, f"f{len(INDEX):04d}")
    with open(local, "wb") as f:
        f.write(data)
    INDEX.append((path, local, ctype))
    return data


def tgz(entries):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as t:
        for name, data in entries:
            data = data.encode() if isinstance(data, str) else data
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            ti.mtime = MTIME
            ti.mode = 0o644
            t.addfile(ti, io.BytesIO(data))
    return gzip.compress(raw.getvalue(), mtime=0)


# ------------------------------------------------------------------ npm
def npm(name, version, entries):
    body = tgz(entries)
    short = name.split("/")[-1]
    fname = f"{short}-{version}.tgz"
    emit(f"/npm/{name}/-/{fname}", body)
    packument = {
        "name": name,
        "dist-tags": {"latest": version},
        "versions": {
            version: {
                "name": name,
                "version": version,
                "dist": {
                    "tarball": f"{SELF}/npm/{name}/-/{fname}",
                    "shasum": hashlib.sha1(body).hexdigest(),
                    "integrity": "sha512-" + base64.b64encode(hashlib.sha512(body).digest()).decode(),
                },
            }
        },
        "time": {"created": "2020-01-01T00:00:00.000Z", version: "2020-01-01T00:00:00.000Z"},
    }
    doc = json.dumps(packument)
    emit(f"/npm/{name}", doc, "application/json")
    if "/" in name:
        # npm clients and proxies spell a scoped name either way.
        emit(f"/npm/{name.replace('/', '%2f')}", doc, "application/json")
        emit(f"/npm/{name.replace('/', '%2F')}", doc, "application/json")
    return body


def pkg_json(name, version):
    return json.dumps({"name": name, "version": version, "description": "dtf scan fixture", "license": "MIT"})


npm("dtf-idclean", "1.0.0", [("package/package.json", pkg_json("dtf-idclean", "1.0.0")), ("package/index.js", "module.exports = 1;\n")])
npm("lodash", "4.17.15", [("package/package.json", pkg_json("lodash", "4.17.15")), ("package/lodash.js", "module.exports = {};\n")])
filler = [(f"package/lib/f{i:05d}.js", "") for i in range(10050)]
npm("dtf-late", "1.0.0", filler + [("package/package.json", pkg_json("dtf-late", "1.0.0"))])
npm("dtf-late-liar", "1.0.0", filler + [("package/package.json", pkg_json("dtf-late-liar", "1.0.1"))])
npm("@types/dtfnode", "1.0.0", [("dtfnode/package.json", pkg_json("@types/dtfnode", "1.0.0")), ("dtfnode/index.d.ts", "export {};\n")])
for i in range(1, BURST + 1):
    n = f"dtf-burst-{i:02d}"
    npm(n, "1.0.0", [("package/package.json", pkg_json(n, "1.0.0")), ("package/index.js", f"module.exports = {i};\n")])


# ------------------------------------------------------------------ Cargo
def sparse_prefix(name):
    n = len(name)
    if n <= 2:
        return str(n)
    if n == 3:
        return f"3/{name[0]}"
    return f"{name[0:2]}/{name[2:4]}"


CARGO_LOCK = """# This file is automatically @generated by Cargo.
# It is not intended for manual editing.
version = 3

[[package]]
name = "crossbeam-deque"
version = "0.7.3"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "9f02af974daeee82218205558e51ec8768b48cf524bd01d550abe5573a608285"

[[package]]
name = "crossbeam-utils"
version = "0.7.2"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "c3c7c73a2d1e9fc0886a08b93e98eb643461230d5f1925e4036204d5f2e261a8"

[[package]]
name = "dtf-withlock"
version = "1.0.0"
dependencies = [
 "crossbeam-deque",
]
"""


def crate(name, version, readme_line=None, files=()):
    toml = (
        "[package]\n"
        f'name = "{name}"\nversion = "{version}"\nedition = "2018"\n'
        'description = "dtf scan fixture"\nlicense = "MIT"\n'
    )
    if readme_line is not None:
        toml += readme_line + "\n"
    top = f"{name}-{version}"
    entries = [(f"{top}/Cargo.toml", toml), (f"{top}/src/lib.rs", "pub fn dtf() {}\n")]
    entries += [(f"{top}/{p}", d) for p, d in files]
    body = tgz(entries)
    emit(f"/cargo/api/v1/crates/{name}/{version}/download", body)
    line = json.dumps({"name": name, "vers": version, "deps": [], "cksum": hashlib.sha256(body).hexdigest(),
                       "features": {}, "yanked": False})
    emit(f"/cargo/{sparse_prefix(name)}/{name}", line + "\n", "text/plain")
    return body


crate("dtf-idcrate", "1.0.0", 'readme = "README.md"', [("README.md", "dtf\n")])
crate("regex", "1.5.4")
crate("dtf-noreadme", "1.0.0", "readme = false")
crate("dtf-readmetrue", "1.0.0", "readme = true", [("README.md", "dtf\n")])
crate("dtf-withlock", "1.0.0", None, [("Cargo.lock", CARGO_LOCK)])
crate("dtf-lockdeep", "1.0.0", None, [("fuzz/Cargo.lock", CARGO_LOCK.replace("dtf-withlock", "dtf-lockdeep-fuzz"))])
emit("/cargo/config.json", json.dumps({"dl": f"{SELF}/cargo/api/v1/crates"}), "application/json")

with open(os.path.join(OUT, "files.tsv"), "w") as f:
    for p, local, ct in INDEX:
        f.write(f"{p}\t{local}\t{ct}\n")
print(len(INDEX))
