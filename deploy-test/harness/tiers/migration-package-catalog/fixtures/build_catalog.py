#!/usr/bin/env python3
# =============================================================================
# build_catalog.py OUTDIR — build the migration SOURCE's real files
# =============================================================================
# Writes, under OUTDIR, one directory per mock Artifactory repository:
#
#   dtfcat-mvn/   (packageType maven)
#     com/dtf/demo/1.0.0/demo-1.0.0.jar        a real jar (zip + MANIFEST.MF)
#     com/dtf/demo/1.0.0/demo-1.0.0.jar.sha1   checksum sidecars
#     com/dtf/demo/1.0.0/demo-1.0.0.jar.md5
#     com/dtf/demo/1.0.0/demo-1.0.0.pom
#     com/dtf/demo/1.0.0/demo-1.0.0.pom.sha1
#     com/dtf/demo/maven-metadata.xml          the source's metadata document
#
#   dtfcat-deb/   (packageType debian)
#     pool/main/d/dtfpkg/dtfpkg_1.0_amd64.deb  pool/<component>/ layout
#     pool/dtfflat_2.0_all.deb                 Artifactory "Set Me Up" layout
#
# The `.deb`s are real ar archives (debian-binary, control.tar.gz,
# data.tar.gz) whose control file carries Package/Version/Architecture and a
# Description no file name can supply, which is how the oracle tells "indexed
# from the control file" apart from "indexed from the file name". Every
# timestamp is pinned, so the bytes are identical on every run and image.
# Stdlib only.
# =============================================================================
import gzip
import hashlib
import io
import os
import sys
import tarfile
import zipfile

EPOCH = 1767225600  # 2026-01-01T00:00:00Z


def write(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)


def jar():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, body in (
            ("META-INF/MANIFEST.MF",
             "Manifest-Version: 1.0\r\nCreated-By: dtf migration-package-catalog\r\n"
             "Implementation-Title: demo\r\nImplementation-Version: 1.0.0\r\n\r\n"),
            ("com/dtf/demo/Demo.txt", "dtf demo payload for artifact-keeper#4691\n"),
        ):
            info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, body)
    return buf.getvalue()


POM = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.dtf</groupId>
  <artifactId>demo</artifactId>
  <version>1.0.0</version>
  <packaging>jar</packaging>
  <description>DTF migration-package-catalog fixture (artifact-keeper#4691)</description>
</project>
""".encode()

METADATA = """<?xml version="1.0" encoding="UTF-8"?>
<metadata>
  <groupId>com.dtf</groupId>
  <artifactId>demo</artifactId>
  <versioning>
    <latest>1.0.0</latest>
    <release>1.0.0</release>
    <versions><version>1.0.0</version></versions>
    <lastUpdated>20260101000000</lastUpdated>
  </versioning>
</metadata>
""".encode()


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
        f" Built by the DTF migration-package-catalog tier.\n"
    ).encode()
    control_tgz = targz([("./control", control, 0o644)])
    data_tgz = targz(
        [(f"./usr/share/doc/{package}/README", f"{package} {version}\n".encode(), 0o644)]
    )
    return ar(
        [("debian-binary", b"2.0\n"), ("control.tar.gz", control_tgz), ("data.tar.gz", data_tgz)]
    )


def main(out):
    mvn = os.path.join(out, "dtfcat-mvn", "com", "dtf", "demo")
    j = jar()
    write(f"{mvn}/1.0.0/demo-1.0.0.jar", j)
    write(f"{mvn}/1.0.0/demo-1.0.0.jar.sha1", hashlib.sha1(j).hexdigest().encode())
    write(f"{mvn}/1.0.0/demo-1.0.0.jar.md5", hashlib.md5(j).hexdigest().encode())
    write(f"{mvn}/1.0.0/demo-1.0.0.pom", POM)
    write(f"{mvn}/1.0.0/demo-1.0.0.pom.sha1", hashlib.sha1(POM).hexdigest().encode())
    write(f"{mvn}/maven-metadata.xml", METADATA)

    debs = os.path.join(out, "dtfcat-deb", "pool")
    write(
        f"{debs}/main/d/dtfpkg/dtfpkg_1.0_amd64.deb",
        deb("dtfpkg", "1.0", "amd64", "DTF pooled fixture for artifact-keeper 4657"),
    )
    write(
        f"{debs}/dtfflat_2.0_all.deb",
        deb("dtfflat", "2.0", "all", "DTF flat-layout fixture for artifact-keeper 4657"),
    )


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: build_catalog.py OUTDIR")
    main(sys.argv[1])
