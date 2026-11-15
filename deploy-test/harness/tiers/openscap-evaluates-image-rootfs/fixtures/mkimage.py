#!/usr/bin/env python3
"""Write a two-layer RHEL 9 image (layers, config, manifest) to OUTDIR.

usage: mkimage.py OUTDIR VARIANT TAG [BASE_EXPORT_TAR]

VARIANT
  clean         base layer + a layer that only adds /etc/motd
  noncompliant  base layer + a layer that breaks two CIS Level 1 rules the
                base passes: /etc/shadow at mode 0644
                (file_permissions_etc_shadow) and a second group with GID 0
                (groups_no_zero_gid_except_root)
  debian        one layer: a Debian 12 os-release and /etc/passwd, which no
                shipped SCAP datastream describes

The base layer is the RHEL 9 configuration and RPM database of a container
export (BASE_EXPORT_TAR, `docker export` of the OpenSCAP sidecar, a UBI 9
system): /etc, /usr/lib/os-release and the rpmdb, nothing else, so the layer
stays small. TAG makes the image unique. Writes l0[, l1], config and manifest,
"layers" (one digest per line, in order) and "config_digest"; prints the
manifest digest.
"""
import gzip
import hashlib
import io
import json
import os
import sys
import tarfile

out, variant, tag = sys.argv[1], sys.argv[2], sys.argv[3]
base_export = sys.argv[4] if len(sys.argv) > 4 else None

KEEP_PREFIXES = ("etc/", "var/lib/rpm/", "usr/lib/sysimage/rpm/")
KEEP_FILES = ("usr/lib/os-release",)
KEEP_DIRS = ("etc", "usr", "usr/lib", "usr/lib/sysimage", "usr/lib/sysimage/rpm",
             "var", "var/lib", "var/lib/rpm")


def norm(name):
    while name.startswith("./"):
        name = name[2:]
    return name.lstrip("/")


def filtered_base(path):
    """Return (tar bytes, {name: bytes}) of the kept part of the export."""
    raw = io.BytesIO()
    contents = {}
    with tarfile.open(path, "r|*") as src, tarfile.open(fileobj=raw, mode="w") as dst:
        for m in src:
            n = norm(m.name)
            keep = (n in KEEP_FILES or n in KEEP_DIRS or n.startswith(KEEP_PREFIXES))
            if not keep or m.ischr() or m.isblk() or m.isfifo():
                continue
            m.name = n
            m.mtime = 0
            if m.isreg():
                data = src.extractfile(m).read()
                contents[n] = data
                dst.addfile(m, io.BytesIO(data))
            else:
                dst.addfile(m)
    return raw.getvalue(), contents


def layer_from(entries):
    """entries: list of (name, kind, mode, data_or_target)."""
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as t:
        for name, kind, mode, payload in entries:
            i = tarfile.TarInfo(name)
            i.mode = mode
            i.mtime = 0
            if kind == "dir":
                i.type = tarfile.DIRTYPE
                t.addfile(i)
            else:
                i.size = len(payload)
                t.addfile(i, io.BytesIO(payload))
    return raw.getvalue()


layers = []
if variant == "debian":
    layers.append(layer_from([
        ("etc", "dir", 0o755, None),
        ("etc/os-release", "file", 0o644,
         b'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nID=debian\nVERSION_ID="12"\n'),
        ("etc/passwd", "file", 0o644, b"root:x:0:0:root:/root:/bin/bash\n"),
        ("srv", "dir", 0o755, None),
        ("srv/dtf-tag", "file", 0o644, (tag + "\n").encode()),
    ]))
else:
    if not base_export:
        sys.exit("mkimage.py: the clean and noncompliant variants need BASE_EXPORT_TAR")
    base_tar, base = filtered_base(base_export)
    if "etc/shadow" not in base or "etc/group" not in base:
        sys.exit("mkimage.py: the base export has no /etc/shadow or /etc/group")
    layers.append(base_tar)
    top = [("etc", "dir", 0o755, None), ("srv", "dir", 0o755, None),
           ("srv/dtf-tag", "file", 0o644, (tag + "\n").encode())]
    if variant == "clean":
        top.append(("etc/motd", "file", 0o644, b"Authorized use only.\n"))
    elif variant == "noncompliant":
        top.append(("etc/shadow", "file", 0o644, base["etc/shadow"]))
        group = base["etc/group"]
        if not group.endswith(b"\n"):
            group += b"\n"
        top.append(("etc/group", "file", 0o644, group + b"dtfroot:x:0:\n"))
    else:
        sys.exit(f"mkimage.py: unknown variant {variant}")
    layers.append(layer_from(top))

os.makedirs(out, exist_ok=True)
diff_ids, descs = [], []
for i, tar_bytes in enumerate(layers):
    blob = gzip.compress(tar_bytes, compresslevel=1, mtime=0)
    dg = "sha256:" + hashlib.sha256(blob).hexdigest()
    diff_ids.append("sha256:" + hashlib.sha256(tar_bytes).hexdigest())
    descs.append({"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                  "digest": dg, "size": len(blob)})
    with open(os.path.join(out, f"l{i}"), "wb") as f:
        f.write(blob)
config = json.dumps({
    "architecture": "amd64", "os": "linux",
    "config": {"Env": ["PATH=/usr/sbin:/usr/bin:/sbin:/bin"], "Labels": {"dtf.tag": tag}},
    "rootfs": {"type": "layers", "diff_ids": diff_ids},
    "history": [{"created_by": f"dtf mkimage {variant} {tag}"}],
}, separators=(",", ":")).encode()
config_dg = "sha256:" + hashlib.sha256(config).hexdigest()
manifest = json.dumps({
    "schemaVersion": 2,
    "mediaType": "application/vnd.oci.image.manifest.v1+json",
    "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
               "digest": config_dg, "size": len(config)},
    "layers": descs,
}, separators=(",", ":")).encode()
with open(os.path.join(out, "config"), "wb") as f:
    f.write(config)
with open(os.path.join(out, "manifest"), "wb") as f:
    f.write(manifest)
with open(os.path.join(out, "layers"), "w") as f:
    f.write("".join(d["digest"] + "\n" for d in descs))
with open(os.path.join(out, "config_digest"), "w") as f:
    f.write(config_dg + "\n")
print("sha256:" + hashlib.sha256(manifest).hexdigest())
