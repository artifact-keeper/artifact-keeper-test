#!/usr/bin/env python3
"""Write a one-layer alpine-shaped image (layer, config, manifest) to OUTDIR.

usage: mkimage.py OUTDIR TAG PAD_MIB

The layer carries /etc/os-release (Alpine 3.10) and an apk database that lists
libcrypto1.1 1.1.1c-r0 (origin openssl), so Trivy reports its CVEs, plus
PAD_MIB MiB of random bytes. TAG makes the image unique. Prints the manifest digest.
"""
import gzip, hashlib, io, json, os, sys, tarfile

out, tag, pad = sys.argv[1], sys.argv[2], int(sys.argv[3])
files = {
    "etc/os-release": ('NAME="Alpine Linux"\nID=alpine\nVERSION_ID=3.10.2\n'
                       'PRETTY_NAME="Alpine Linux v3.10"\n').encode(),
    "etc/alpine-release": b"3.10.2\n",
    "lib/apk/db/installed": ("C:Q1dtfdtfdtfdtfdtfdtfdtfdtfdtfdtfdtf=\nP:libcrypto1.1\nV:1.1.1c-r0\n"
                             "A:x86_64\nS:1\nI:1\nT:Crypto library from openssl\n"
                             "U:https://www.openssl.org\nL:OpenSSL\no:openssl\nm:dtf\nt:1\n"
                             "F:lib\nR:libcrypto.so.1.1\n\n").encode(),
    "lib/libcrypto.so.1.1": b"\x7fELF dtf placeholder\n",
    "srv/dtf-tag": (tag + "\n").encode(),
}
raw = io.BytesIO()
with tarfile.open(fileobj=raw, mode="w") as t:
    for d in ("etc", "lib", "lib/apk", "lib/apk/db", "srv"):
        i = tarfile.TarInfo(d); i.type = tarfile.DIRTYPE; i.mode = 0o755; t.addfile(i)
    for name, data in files.items():
        i = tarfile.TarInfo(name); i.size = len(data); i.mode = 0o644; t.addfile(i, io.BytesIO(data))
    if pad:
        data = os.urandom(pad * 1024 * 1024)
        i = tarfile.TarInfo("srv/pad.bin"); i.size = len(data); i.mode = 0o644
        t.addfile(i, io.BytesIO(data))
layer_tar = raw.getvalue()
layer = gzip.compress(layer_tar, compresslevel=1, mtime=0)
diff_id = "sha256:" + hashlib.sha256(layer_tar).hexdigest()
layer_dg = "sha256:" + hashlib.sha256(layer).hexdigest()
config = json.dumps({
    "architecture": "amd64", "os": "linux",
    "config": {"Env": ["PATH=/usr/sbin:/usr/bin:/sbin:/bin"], "Labels": {"dtf.tag": tag}},
    "rootfs": {"type": "layers", "diff_ids": [diff_id]},
    "history": [{"created_by": "dtf mkimage " + tag}],
}, separators=(",", ":")).encode()
config_dg = "sha256:" + hashlib.sha256(config).hexdigest()
manifest = json.dumps({
    "schemaVersion": 2,
    "mediaType": "application/vnd.oci.image.manifest.v1+json",
    "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": config_dg, "size": len(config)},
    "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": layer_dg, "size": len(layer)}],
}, separators=(",", ":")).encode()
os.makedirs(out, exist_ok=True)
for name, data in (("layer", layer), ("config", config), ("manifest", manifest)):
    with open(os.path.join(out, name), "wb") as f:
        f.write(data)
with open(os.path.join(out, "digests"), "w") as f:
    f.write(f"{layer_dg} {config_dg}\n")
print("sha256:" + hashlib.sha256(manifest).hexdigest())
