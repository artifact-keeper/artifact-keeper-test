#!/usr/bin/env python3
# =============================================================================
# make_fixtures.py - deterministic package fixtures for the
# scan-on-upload-native-and-completeness tier
# =============================================================================
# Writes, into the directory given as argv[1], small packages built with
# stdlib zipfile/tarfile and FIXED timestamps (identical bytes on every run):
#
#   npm.tgz            npm tarball: package/package.json for <npm name>
#   npm-publish.json   the npm publish document (_attachments, base64 tarball)
#   oci-config.json    OCI image config (linux/amd64, one diff_id)
#   oci-layer.tar.gz   one gzip layer holding etc/os-release (alpine 3.12)
#   oci-manifest.json  image manifest naming the two blobs
#   conda.tar.bz2      conda v1 package: info/index.json (noarch)
#   cargo-publish.bin  cargo publish body: u32 json len, json, u32 crate len,
#                      crate (Cargo.toml + src/lib.rs)
#   docs.zip           a plain archive of text files (nothing to catalog)
#   fake.whl           a "wheel" that is a zip of one text file (nothing a
#                      scanner can catalog, package-shaped name)
#
# argv[2] is a suffix that goes into every package name/version so each run
# publishes coordinates no earlier run used.
# Stdlib only.
# =============================================================================
import base64
import bz2
import gzip
import hashlib
import io
import json
import os
import struct
import sys
import tarfile
import zipfile

OUT, SUF = sys.argv[1], sys.argv[2]
MTIME = 1577836800
FIXED = (2020, 1, 1, 0, 0, 0)


def tar_bytes(entries, fmt=tarfile.USTAR_FORMAT):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=fmt) as t:
        for name, data in entries:
            data = data.encode() if isinstance(data, str) else data
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            ti.mtime = MTIME
            ti.mode = 0o644
            t.addfile(ti, io.BytesIO(data))
    return raw.getvalue()


def zip_bytes(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in entries:
            info = zipfile.ZipInfo(name, date_time=FIXED)
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, data)
    return buf.getvalue()


def write(name, data):
    data = data.encode() if isinstance(data, str) else data
    with open(os.path.join(OUT, name), "wb") as f:
        f.write(data)
    return data


def sha256(b):
    return hashlib.sha256(b).hexdigest()


# --- npm -------------------------------------------------------------------
npm_name = f"dtf-sou-{SUF}"
npm_ver = "1.0.0"
pkg_json = json.dumps({"name": npm_name, "version": npm_ver, "description": "dtf", "license": "MIT"})
tgz = write("npm.tgz", gzip.compress(tar_bytes([("package/package.json", pkg_json),
                                                ("package/index.js", "module.exports = 1;\n")]), mtime=0))
write("npm-publish.json", json.dumps({
    "_id": npm_name, "name": npm_name, "dist-tags": {"latest": npm_ver},
    "versions": {npm_ver: {"name": npm_name, "version": npm_ver, "description": "dtf",
                           "dist": {"shasum": hashlib.sha1(tgz).hexdigest(),
                                    "tarball": f"http://localhost/{npm_name}/-/{npm_name}-{npm_ver}.tgz"}}},
    "_attachments": {f"{npm_name}-{npm_ver}.tgz": {"content_type": "application/octet-stream",
                                                   "data": base64.b64encode(tgz).decode(),
                                                   "length": len(tgz)}},
}))

# --- OCI image -------------------------------------------------------------
layer_tar = tar_bytes([("etc/os-release",
                        'NAME="Alpine Linux"\nID=alpine\nVERSION_ID=3.12.0\nPRETTY_NAME="Alpine Linux v3.12"\n'),
                       (f"etc/dtf-{SUF}", "dtf\n")])
layer = write("oci-layer.tar.gz", gzip.compress(layer_tar, mtime=0))
config = write("oci-config.json", json.dumps({
    "architecture": "amd64", "os": "linux",
    "config": {"Env": ["PATH=/usr/bin:/bin"]},
    "rootfs": {"type": "layers", "diff_ids": ["sha256:" + sha256(layer_tar)]},
    "history": [{"created": "2020-01-01T00:00:00Z", "created_by": "dtf"}],
}, separators=(",", ":")))
write("oci-manifest.json", json.dumps({
    "schemaVersion": 2,
    "mediaType": "application/vnd.oci.image.manifest.v1+json",
    "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
               "digest": "sha256:" + sha256(config), "size": len(config)},
    "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                "digest": "sha256:" + sha256(layer), "size": len(layer)}],
}, separators=(",", ":")))

# --- conda (v1 .tar.bz2) -----------------------------------------------------
conda_name = f"dtf-sou-{SUF}"
index = json.dumps({"name": conda_name, "version": "1.0.0", "build": "py_0", "build_number": 0,
                    "subdir": "noarch", "noarch": "python", "depends": [], "license": "MIT"})
write("conda.tar.bz2", bz2.compress(tar_bytes([
    ("info/index.json", index),
    ("info/paths.json", json.dumps({"paths": [], "paths_version": 1})),
    (f"site-packages/dtf_sou_{SUF}/__init__.py", "x = 1\n"),
])))

# --- cargo publish -------------------------------------------------------------
crate_name = f"dtf-sou-{SUF}"
crate = gzip.compress(tar_bytes([
    (f"{crate_name}-1.0.0/Cargo.toml",
     f'[package]\nname = "{crate_name}"\nversion = "1.0.0"\nedition = "2018"\n'
     'description = "dtf"\nlicense = "MIT"\n'),
    (f"{crate_name}-1.0.0/src/lib.rs", "pub fn dtf() {}\n"),
]), mtime=0)
meta = json.dumps({"name": crate_name, "vers": "1.0.0", "deps": [], "features": {}, "authors": ["dtf"],
                   "description": "dtf", "license": "MIT", "keywords": [], "categories": [],
                   "links": None}).encode()
write("cargo-publish.bin", struct.pack("<I", len(meta)) + meta + struct.pack("<I", len(crate)) + crate)

# --- generic archives that nothing catalogs ------------------------------------
write("docs.zip", zip_bytes([("README.txt", f"dtf docs {SUF}\n"), ("guide/intro.txt", "hello\n")]))
write("fake.whl", zip_bytes([("notes.txt", f"not a wheel {SUF}\n")]))
print(json.dumps({"npm": npm_name, "conda": conda_name, "crate": crate_name}))
