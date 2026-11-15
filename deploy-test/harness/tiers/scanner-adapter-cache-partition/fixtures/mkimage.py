#!/usr/bin/env python3
"""Write a one-layer alpine-shaped image into a registry data directory.

usage: mkimage.py DATADIR REPO TAG [--pad-mib N] [--mark TEXT] [--claim-diff-id ID]

Default layer: /etc/os-release (Alpine 3.10) and an apk database listing
libcrypto1.1 1.1.1c-r0 (origin openssl), so Trivy reports its CVEs. Without
--mark and --pad-mib the layer is byte-identical on every run (fixed mtimes),
so its diff ID is stable.
  --pad-mib N        add N MiB of random bytes (incompressible: the image's
                     compressed size grows by about N MiB)
  --mark TEXT        add /srv/dtf-mark with TEXT (makes the image unique)
  --claim-diff-id ID forge: the layer holds one text file and no packages,
                     but the config's rootfs.diff_ids claims ID
DATADIR gets blobs/<hex> and manifests/<repo with / as __>/<tag> (the layout
ocireg.py serves). Prints: <manifest digest> <layer digest> <diff id> <total
compressed bytes of config + layer>.
"""
import argparse, gzip, hashlib, io, json, os, tarfile

ap = argparse.ArgumentParser()
ap.add_argument("datadir"); ap.add_argument("repo"); ap.add_argument("tag")
ap.add_argument("--pad-mib", type=int, default=0)
ap.add_argument("--mark", default="")
ap.add_argument("--claim-diff-id", default="")
a = ap.parse_args()

if a.claim_diff_id:
    files = {"forged.txt": b"forged layer: no packages here\n"}
    dirs = ()
else:
    files = {
        "etc/os-release": ('NAME="Alpine Linux"\nID=alpine\nVERSION_ID=3.10.2\n'
                           'PRETTY_NAME="Alpine Linux v3.10"\n').encode(),
        "etc/alpine-release": b"3.10.2\n",
        "lib/apk/db/installed": ("C:Q1dtfdtfdtfdtfdtfdtfdtfdtfdtfdtfdtf=\nP:libcrypto1.1\nV:1.1.1c-r0\n"
                                 "A:x86_64\nS:1\nI:1\nT:Crypto library from openssl\n"
                                 "U:https://www.openssl.org\nL:OpenSSL\no:openssl\nm:dtf\nt:1\n"
                                 "F:lib\nR:libcrypto.so.1.1\n\n").encode(),
        "lib/libcrypto.so.1.1": b"\x7fELF dtf placeholder\n",
    }
    dirs = ("etc", "lib", "lib/apk", "lib/apk/db")
    if a.mark:
        files["srv/dtf-mark"] = (a.mark + "\n").encode()
if a.mark or a.pad_mib:
    dirs = tuple(dirs) + ("srv",)

raw = io.BytesIO()
with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as t:
    for d in dirs:
        i = tarfile.TarInfo(d); i.type = tarfile.DIRTYPE; i.mode = 0o755; i.mtime = 0; t.addfile(i)
    for name, data in files.items():
        i = tarfile.TarInfo(name); i.size = len(data); i.mode = 0o644; i.mtime = 0
        t.addfile(i, io.BytesIO(data))
    if a.pad_mib:
        data = os.urandom(a.pad_mib * 1024 * 1024)
        i = tarfile.TarInfo("srv/pad.bin"); i.size = len(data); i.mode = 0o644; i.mtime = 0
        t.addfile(i, io.BytesIO(data))
layer_tar = raw.getvalue()
layer = gzip.compress(layer_tar, compresslevel=1, mtime=0)
diff_id = "sha256:" + hashlib.sha256(layer_tar).hexdigest()
layer_dg = "sha256:" + hashlib.sha256(layer).hexdigest()
config = json.dumps({
    "architecture": "amd64", "os": "linux",
    "config": {"Env": ["PATH=/usr/sbin:/usr/bin:/sbin:/bin"]},
    "rootfs": {"type": "layers", "diff_ids": [a.claim_diff_id or diff_id]},
    "history": [{"created": "1970-01-01T00:00:00Z", "created_by": "dtf mkimage " + (a.mark or a.repo)}],
}, separators=(",", ":")).encode()
config_dg = "sha256:" + hashlib.sha256(config).hexdigest()
manifest = json.dumps({
    "schemaVersion": 2,
    "mediaType": "application/vnd.oci.image.manifest.v1+json",
    "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": config_dg, "size": len(config)},
    "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": layer_dg, "size": len(layer)}],
}, separators=(",", ":")).encode()
man_dg = "sha256:" + hashlib.sha256(manifest).hexdigest()

blobs = os.path.join(a.datadir, "blobs")
mdir = os.path.join(a.datadir, "manifests", a.repo.replace("/", "__"))
os.makedirs(blobs, exist_ok=True); os.makedirs(mdir, exist_ok=True)
for dg, data in ((layer_dg, layer), (config_dg, config), (man_dg, manifest)):
    with open(os.path.join(blobs, dg.split(":", 1)[1]), "wb") as f:
        f.write(data)
with open(os.path.join(mdir, a.tag), "wb") as f:
    f.write(manifest)
print(man_dg, layer_dg, diff_id, len(config) + len(layer))
