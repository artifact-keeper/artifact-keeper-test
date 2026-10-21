#!/usr/bin/env python3
# =============================================================================
# build_payloads.py OUTDIR: the upload payloads for replicated-and-chunked-uploads
# =============================================================================
# Every payload is between 1 and 2 MiB unless noted, so a chunked upload with
# the backend's minimum chunk size (1 MiB) takes exactly two chunks and the
# oracle can send them through different replicas. The bulk is incompressible
# deterministic noise (a SHA-256 chain), so gzip keeps the size.
#
#   incus.tar.gz           Incus unified image: metadata.yaml (architecture
#                          x86_64, os DTFOS, release dtfrel) + rootfs/
#   dtfchunk_1.0_amd64.deb a real .deb whose control carries Depends and a
#                          Description no file name can supply
#   dtfbad_1.0_amd64.deb   a real .deb whose control says Package: dtfother
#                          (its file name says dtfbad): a mismatch
#   generic.bin            1.5 MiB of noise (the cross-replica CONTROL)
#   big.bin                8 MiB of noise (the slow spool-watch upload)
# Stdlib only; timestamps pinned.
# =============================================================================
import gzip
import hashlib
import io
import os
import sys
import tarfile

EPOCH = 1767225600


def noise(n, seed):
    out = bytearray()
    h = hashlib.sha256(seed.encode()).digest()
    while len(out) < n:
        h = hashlib.sha256(h).digest()
        out += h
    return bytes(out[:n])


def targz(members):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.GNU_FORMAT) as t:
        for name, body, mode in members:
            info = tarfile.TarInfo(name)
            info.size = len(body)
            info.mtime = EPOCH
            info.mode = mode
            info.uname = info.gname = "root"
            t.addfile(info, io.BytesIO(body))
    return gzip.compress(raw.getvalue(), mtime=0)


def ar(members):
    out = bytearray(b"!<arch>\n")
    for name, body in members:
        header = f"{name:<16}{EPOCH:<12}{0:<6}{0:<6}{'100644':<8}{len(body):<10}`\n".encode()
        out += header + body
        if len(body) % 2:
            out += b"\n"
    return bytes(out)


def deb(package, version, description, depends, bulk_seed):
    control = (
        f"Package: {package}\nVersion: {version}\nArchitecture: amd64\n"
        f"Maintainer: DTF <dtf@example.invalid>\nInstalled-Size: 1600\n"
        f"Depends: {depends}\nSection: misc\nPriority: optional\n"
        f"Description: {description}\n Built by the DTF replicated-and-chunked-uploads tier.\n"
    ).encode()
    data = targz([(f"./usr/share/{package}/blob", noise(1_500_000, bulk_seed), 0o644)])
    return ar([("debian-binary", b"2.0\n"),
               ("control.tar.gz", targz([("./control", control, 0o644)])),
               ("data.tar.gz", data)])


def write(path, data):
    with open(path, "wb") as fh:
        fh.write(data)


def main(out):
    os.makedirs(out, exist_ok=True)
    metadata = (
        "architecture: x86_64\ncreation_date: 1767225600\nproperties:\n"
        "  os: DTFOS\n  release: dtfrel\n  variant: default\n"
        "  description: DTF chunked incus image (artifact-keeper 4403)\n"
        "  serial: \"20261020\"\n"
    ).encode()
    write(os.path.join(out, "incus.tar.gz"), targz([
        ("metadata.yaml", metadata, 0o644),
        ("rootfs/etc/os-release", b"NAME=DTFOS\n", 0o644),
        ("rootfs/var/blob", noise(1_500_000, "incus"), 0o644),
    ]))
    write(os.path.join(out, "dtfchunk_1.0_amd64.deb"),
          deb("dtfchunk", "1.0", "DTF chunked debian fixture for artifact-keeper 1846",
              "libc6 (>= 2.31), dtf-runtime", "deb"))
    write(os.path.join(out, "dtfbad_1.0_amd64.deb"),
          deb("dtfother", "1.0", "DTF mismatched control fixture", "libc6", "bad"))
    write(os.path.join(out, "generic.bin"), noise(1_500_000, "generic"))
    write(os.path.join(out, "big.bin"), noise(8 * 1024 * 1024, "big"))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: build_payloads.py OUTDIR")
    main(sys.argv[1])
