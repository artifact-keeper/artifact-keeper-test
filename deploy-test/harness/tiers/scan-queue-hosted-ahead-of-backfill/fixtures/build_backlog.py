#!/usr/bin/env python3
# =============================================================================
# build_backlog.py <out-dir> <upstream-base-url> <group>:<count> [...]
#   npm packages for the scan-queue-hosted-ahead-of-backfill tier
# =============================================================================
# One ordinary npm package per entry, named dtf-bf<group>-NNN 1.0.0
# (package/package.json first, distinct bytes), so every first pull through a
# fail_open Remote with scan_on_proxy queues one `proxy_file` backfill job.
# Writes the files into <out-dir> and an index, <out-dir>/files.tsv:
#     <upstream path>\t<local file>\t<content type>
# and <out-dir>/<group>.list with one "<name>\t<tarball sha256>" per package.
# <upstream-base-url> is the address the BACKEND reaches the mock at; it goes
# into the packuments' tarball URLs. Fixed timestamps, stdlib only.
# =============================================================================
import base64
import gzip
import hashlib
import io
import json
import os
import sys
import tarfile

OUT = sys.argv[1]
SELF = sys.argv[2].rstrip("/")
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
            data = data.encode()
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            ti.mtime = MTIME
            ti.mode = 0o644
            t.addfile(ti, io.BytesIO(data))
    return gzip.compress(raw.getvalue(), mtime=0)


def npm(name, version):
    pj = json.dumps({"name": name, "version": version,
                     "description": "dtf scan backlog fixture", "license": "MIT"})
    body = tgz([("package/package.json", pj),
                ("package/index.js", f"module.exports = {json.dumps(name)};\n")])
    fname = f"{name}-{version}.tgz"
    emit(f"/npm/{name}/-/{fname}", body)
    doc = {
        "name": name,
        "dist-tags": {"latest": version},
        "versions": {version: {
            "name": name, "version": version,
            "dist": {
                "tarball": f"{SELF}/npm/{name}/-/{fname}",
                "shasum": hashlib.sha1(body).hexdigest(),
                "integrity": "sha512-" + base64.b64encode(hashlib.sha512(body).digest()).decode(),
            },
        }},
        "time": {"created": "2020-01-01T00:00:00.000Z", version: "2020-01-01T00:00:00.000Z"},
    }
    emit(f"/npm/{name}", json.dumps(doc), "application/json")
    return hashlib.sha256(body).hexdigest()


total = 0
for spec in sys.argv[3:]:
    group, count = spec.split(":")
    with open(os.path.join(OUT, f"{group}.list"), "w") as lst:
        for i in range(1, int(count) + 1):
            name = f"dtf-bf{group}-{i:03d}"
            lst.write(f"{name}\t{npm(name, '1.0.0')}\n")
            total += 1

with open(os.path.join(OUT, "files.tsv"), "w") as f:
    for p, local, ct in INDEX:
        f.write(f"{p}\t{local}\t{ct}\n")
print(total)
