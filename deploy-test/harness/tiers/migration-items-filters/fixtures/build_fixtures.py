#!/usr/bin/env python3
# =============================================================================
# build_fixtures.py OUTDIR - build the migration SOURCE for migration-items-filters
# =============================================================================
# Writes, under OUTDIR (copied into the mock's MOCK_CATALOG_DIR by the oracle):
#
#   dtfmi-debian/   (packageType debian)
#     pool/dtfmain_1.0_amd64.deb         deb.component=main      (control)
#     pool/dtfcontrib_1.0_amd64.deb      deb.component=contrib   (#4740)
#     pool/n/nfpkg/nfpkg_2.0_arm64.deb   deb.component=non-free  (#4740, the
#                                        pool/<letter>/<name>/ layout)
#     pool/main/Packages.gz              phantom: listed, 404 -> item SKIPPED
#                                        (a Debian index path the importer
#                                        treats as cache metadata; NOT under
#                                        dists/, which it drops before any
#                                        item row is written)
#
#   dtfmi-gen/      (packageType generic)
#     files/ok-1.txt, files/ok-2.txt     migrate cleanly         -> COMPLETED
#     files/broken.bin                   advertised digest wrong -> FAILED
#
#   _mock.json      the mock's control document (properties, bad_sha256,
#                   phantom); see mock_artifactory.py.
#
# The `.deb`s are real ar archives (debian-binary, control.tar.gz,
# data.tar.gz). Every timestamp is pinned, so the bytes are identical on every
# run and image and the oracle compares downloads by sha256. Stdlib only.
# =============================================================================
import gzip
import io
import json
import os
import sys
import tarfile

EPOCH = 1767225600  # 2026-01-01T00:00:00Z

DEBS = [
    # (path, package, version, arch, component)
    ("pool/dtfmain_1.0_amd64.deb", "dtfmain", "1.0", "amd64", "main"),
    ("pool/dtfcontrib_1.0_amd64.deb", "dtfcontrib", "1.0", "amd64", "contrib"),
    ("pool/n/nfpkg/nfpkg_2.0_arm64.deb", "nfpkg", "2.0", "arm64", "non-free"),
]


def write(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)


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
        header = (
            f"{name:<16}{EPOCH:<12}{0:<6}{0:<6}{'100644':<8}{len(body):<10}`\n"
        ).encode()
        assert len(header) == 60
        out += header + body
        if len(body) % 2:
            out += b"\n"
    return bytes(out)


def deb(package, version, arch, component):
    control = (
        f"Package: {package}\nVersion: {version}\nArchitecture: {arch}\n"
        f"Maintainer: DTF <dtf@example.invalid>\nInstalled-Size: 1\n"
        f"Section: {component}/misc\nPriority: optional\n"
        f"Description: DTF {component} fixture for artifact-keeper 4740\n"
        f" Built by the DTF migration-items-filters tier.\n"
    ).encode()
    control_tgz = targz([("./control", control, 0o644)])
    data_tgz = targz(
        [(f"./usr/share/doc/{package}/README", f"{package} {version}\n".encode(), 0o644)]
    )
    return ar(
        [("debian-binary", b"2.0\n"), ("control.tar.gz", control_tgz), ("data.tar.gz", data_tgz)]
    )


def main(out):
    props = {}
    for path, package, version, arch, component in DEBS:
        write(os.path.join(out, "dtfmi-debian", path), deb(package, version, arch, component))
        props[f"dtfmi-debian/{path}"] = {
            "deb.component": [component],
            "deb.distribution": ["stable"],
            "deb.architecture": [arch],
        }
    gen = os.path.join(out, "dtfmi-gen", "files")
    write(f"{gen}/ok-1.txt", b"dtf migration-items-filters ok 1\n")
    write(f"{gen}/ok-2.txt", b"dtf migration-items-filters ok 2\n")
    write(f"{gen}/broken.bin", b"dtf migration-items-filters: digest will not match\n")
    with open(os.path.join(out, "_mock.json"), "w") as fh:
        json.dump(
            {
                "properties": props,
                "bad_sha256": ["dtfmi-gen/files/broken.bin"],
                "phantom": ["dtfmi-debian/pool/main/Packages.gz"],
            },
            fh,
            indent=2,
            sort_keys=True,
        )


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: build_fixtures.py OUTDIR")
    main(sys.argv[1])
