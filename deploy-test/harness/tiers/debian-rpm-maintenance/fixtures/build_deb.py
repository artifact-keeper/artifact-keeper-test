#!/usr/bin/env python3
# =============================================================================
# build_deb.py OUT PACKAGE VERSION ARCH DESCRIPTION: write one real .deb
# =============================================================================
# A real ar archive (debian-binary, control.tar.gz, data.tar.gz) whose control
# file carries Package/Version/Architecture and DESCRIPTION. Two calls with the
# same package, version and architecture but different descriptions give two
# different packages that share one file name, which is what a "destination
# holds a different package" case needs. Timestamps are pinned, so the same
# arguments give the same bytes. Stdlib only (same shape as
# migration-package-catalog/fixtures/build_catalog.py).
# =============================================================================
import gzip
import io
import sys
import tarfile

EPOCH = 1767225600  # 2026-01-01T00:00:00Z


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


def deb(package, version, arch, description):
    control = (
        f"Package: {package}\nVersion: {version}\nArchitecture: {arch}\n"
        f"Maintainer: DTF <dtf@example.invalid>\nInstalled-Size: 1\n"
        f"Section: misc\nPriority: optional\n"
        f"Description: {description}\n"
        f" Built by the DTF debian-rpm-maintenance tier.\n"
    ).encode()
    control_tgz = targz([("./control", control, 0o644)])
    data_tgz = targz(
        [(f"./usr/share/doc/{package}/README", f"{package} {version} {description}\n".encode(), 0o644)]
    )
    return ar(
        [("debian-binary", b"2.0\n"), ("control.tar.gz", control_tgz), ("data.tar.gz", data_tgz)]
    )


def main(argv):
    if len(argv) != 6:
        sys.stderr.write("usage: build_deb.py OUT PACKAGE VERSION ARCH DESCRIPTION\n")
        return 2
    out, package, version, arch, description = argv[1:]
    with open(out, "wb") as fh:
        fh.write(deb(package, version, arch, description))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
