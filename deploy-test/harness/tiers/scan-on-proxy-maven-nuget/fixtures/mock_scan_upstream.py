#!/usr/bin/env python3
# =============================================================================
# mock_scan_upstream.py - a Maven + NuGet V3 + Cargo sparse + Go + RubyGems +
# Composer + Pub + Conan + CocoaPods + Swift upstream whose packages carry
# KNOWN identities, for the scan-on-proxy tiers
# =============================================================================
# The scan-on-proxy gate (artifact-keeper#4098, #4100 Maven, #4101 Cargo,
# #4102 NuGet) buffers a proxied package, establishes what it is served as from
# the package's OWN manifest (pom.properties / Cargo.toml / .nuspec), and
# grades it with the backend's bundled Grype and its pre-seeded vulnerability
# DB (no network). So the tier needs an upstream whose bytes name real
# coordinates: some with long-published advisories (graded vulnerable by any
# Grype DB the backend images ship), some that no advisory names (clean), and
# some that lie about themselves (identity unestablished, checksum mismatch).
# Every package is a few hundred bytes, built at start-up with stdlib zipfile
# and tarfile and FIXED timestamps, so the bytes and digests are identical on
# every run.
#
#   Maven  (upstream base http://<self>/maven2)
#     org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.{jar,pom,jar.sha1}
#         Log4Shell (CVE-2021-44228, critical) via its pom.properties
#     org/apache/commons/commons-text/1.9/commons-text-1.9.{jar,pom,jar.sha1}
#         Text4Shell (CVE-2022-42889, critical); used by record-only tiers
#     com/example/dtfscan/dtf-clean/1.0.0/dtf-clean-1.0.0.{jar,pom,jar.sha1}
#         a coordinate no advisory names
#     com/example/dtfscan/dtf-liar/2.0.0/dtf-liar-2.0.0.jar
#         pom.properties declares version 1.0.0 (identity unestablished)
#     com/example/dtfscan/dtf-badsha/1.0.0/dtf-badsha-1.0.0.{jar,jar.sha1}
#         .sha1 sidecar names other bytes
#   NuGet V3 (upstream base http://<self>/nuget/v3/index.json)
#     v3/index.json                         PackageBaseAddress/3.0.0
#     v3-flatcontainer/<id>/index.json      versions
#     v3-flatcontainer/<id>/<v>/<id>.<v>.nupkg / <id>.nuspec
#       newtonsoft.json 12.0.1  (GHSA-5crp-9r3c-p9vr, high)
#       dtf.scanclean 1.0.0     (nuspec WITH an <?xml ?> declaration, #3603)
#       dtf.scanliar 2.0.0      (nuspec declares 1.0.0)
#   Cargo sparse (upstream base http://<self>/cargo)
#     config.json                           {"dl": ".../cargo/api/v1/crates"}
#     <sparse prefix>/<name>                index lines with the real cksum
#     api/v1/crates/<name>/<v>/download     the .crate
#       regex 1.5.4        (GHSA-m5pq-gvj9-9vr8, high)
#       dtf-scanclean 1.0.0
#       dtf-scanliar 2.0.0 (Cargo.toml declares 1.0.0)
#       dtf-badsum 1.0.0   (index cksum is NOT the crate's sha256)
#   Go module proxy (upstream base http://<self>/goproxy)       #4103
#     <module>/@v/list, <module>/@v/<v>.info, .mod, .zip
#       example.com/dtfscan/vulnmod v1.0.0   go.mod requires golang.org/x/text
#                                            v0.3.0 (GHSA-69ch-w2m2-3vjp, high)
#       example.com/dtfscan/cleanmod v1.0.0  no requirements
#       example.com/dtfscan/liarmod v2.0.0   zip entries are @v1.0.0/ (not the
#                                            module the request names)
#   RubyGems (upstream base http://<self>/rubygems)             #4104
#     gems/<name>-<v>.gem (plain tar with a gzipped gemspec metadata.gz)
#       rack 2.0.7          (GHSA-3h57-hmj3-gj3p and others, high)
#       dtf-scanclean 1.0.0
#       dtf-scanliar 2.0.0  (gemspec declares 1.0.0)
#   Composer (upstream base http://<self>/composer)             #4105
#     p2/<vendor>/<pkg>.json   dist.url -> <self>/composer/zipball/<pkg>.zip
#       dtf/vulnpkg 1.0.0   ships a composer.lock pinning guzzlehttp/guzzle
#                           6.5.0 (GHSA-f2wf-25xc-69c9 and others, high)
#       dtf/cleanpkg 1.0.0  no lockfile
#       dtf/liarpkg 1.0.0   composer.json names other/pkg
#   Pub (upstream base http://<self>/pub)                       #4107
#     packages/<name>/versions/<v>.tar.gz (root pubspec.yaml)
#       http 0.12.0         (GHSA-4rgh-jx4f-qfcq, medium)
#       dtf_scanclean 1.0.0
#       dtf_scanliar 2.0.0  (pubspec.yaml declares 1.0.0)
#   Conan v2 (upstream base http://<self>/conan)                #4108
#     v2/conans/<name>/<v>/_/_/revisions/<rrev>/files/<file>
#       dtfvuln 1.0.0   conan_sources.tgz ships a conanfile.txt requiring
#                       openssl/1.1.1k (CVE-2021-3711, critical)
#       dtfclean 1.0.0  conan_sources.tgz with no requirements
#       dtfliar 1.0.0   conan_sources.tgz is not a gzipped tar
#       (each also has conanfile.py and conanmanifest.txt)
#   CocoaPods (upstream base http://<self>/cocoapods)           #4109
#     pods/<name>-<v>.tar.gz (root <name>.podspec.json)
#       DtfVulnPod 1.0.0   ships a Gemfile.lock pinning rack 2.0.7 (the
#                          bundled scanner has no CocoaPods advisory data,
#                          so only a vendored component can be graded)
#       DtfCleanPod 1.0.0
#       DtfLiarPod 2.0.0   podspec declares 1.0.0
#   Swift registry (upstream base http://<self>/swift)          #4110
#     <scope>/<name>/<v>.zip (<name>/Package.swift)
#       dtf.vulnpkg 1.0.0  ships a Gemfile.lock pinning rack 2.0.7
#       dtf.cleanpkg 1.0.0
#       dtf.liarpkg 1.0.0  no Package.swift
#   Coordinate pins (#4952): the vulnerable coordinate as its own archive,
#   with nothing vulnerable inside, so only a pin on the request grades it
#     goproxy/golang.org/x/text/@v/v0.3.0.zip   (GHSA-69ch-w2m2-3vjp, high)
#     composer guzzlehttp/guzzle 6.5.0          (GHSA-f2wf-25xc-69c9, high)
#     conan openssl/1.1.1k conan_sources.tgz    (CVE-2021-3711, critical)
#   Debian (upstream base http://<self>/debian)                 #4111
#     dists/bookworm/Release                    Origin Debian, Version 12.7
#     pool/main/o/openssl/openssl_3.0.11-1~deb12u2_amd64.deb
#                                               (CVE-2024-5535 and others)
#     pool/main/d/dtf-scanclean/dtf-scanclean_1.0-1_amd64.deb
#     pool/main/d/dtf-scanliar/dtf-scanliar_2.0-1_amd64.deb  control says 1.0-1
#   debian-norel (no Release): pool/main/d/dtf-norelease/..._1.0-1_amd64.deb
#   RPM (upstream base http://<self>/rpm), under 9/BaseOS/x86_64/os/
#     Packages/o/openssl-libs-3.0.7-17.el9_2.x86_64.rpm  epoch 1, RHEL 9
#                                               (CVE-2023-0464 and others)
#     Packages/d/dtf-scanclean-1.0-1.el9.noarch.rpm
#     Packages/d/dtf-scanliar-2.0-1.el9.noarch.rpm   header says 1.0
#     Packages/d/dtf-notag-1.0-1.noarch.rpm          no dist tag
#     repodata/repomd.xml
#   Alpine (upstream base http://<self>/alpine)                 #4113
#     v3.19/main/x86_64/busybox-1.36.1-r15.apk       (CVE-2023-42363 and others)
#     v3.19/main/x86_64/dtf-scanclean-1.0-r0.apk
#     v3.19/main/x86_64/dtf-scanliar-2.0-r0.apk      .PKGINFO says 1.0-r0
#     latest-stable/main/x86_64/dtf-scanclean-1.0-r0.apk  (no fixed release)
#
# Control endpoints (never counted):
#   GET /__readyz                 healthcheck
#   GET /__hits?prefix=<p>        {"prefix": p, "count": n} GETs whose path
#                                 starts with <p> (raw request path, before
#                                 decoding)
#   GET /__golden/<path>          the exact bytes served at /<path>
#   GET /__sha256/<path>          their sha256 hex
#
# Stdlib only, single file, stock python image.
#   MOCK_PORT  listen port (default 80)
#   MOCK_SELF  absolute base URL the backend reaches this mock at (used in the
#              NuGet service index and the Cargo config.json)
# =============================================================================
import gzip
import hashlib
import io
import json
import os
import tarfile
import threading
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

PORT = int(os.environ.get("MOCK_PORT", "80"))
SELF = os.environ.get("MOCK_SELF", "http://mock-scan").rstrip("/")
FIXED = (2020, 1, 1, 0, 0, 0)

LOCK = threading.Lock()
HITS = []
FILES = {}


def zip_bytes(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in entries:
            info = zipfile.ZipInfo(name, date_time=FIXED)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            z.writestr(info, data)
    return buf.getvalue()


def crate_bytes(dirname, cargo_toml):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as t:
        for name, data in (
            (f"{dirname}/Cargo.toml", cargo_toml),
            (f"{dirname}/src/lib.rs", b"pub fn dtf() {}\n"),
        ):
            data = data.encode() if isinstance(data, str) else data
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            ti.mtime = 1577836800
            ti.mode = 0o644
            t.addfile(ti, io.BytesIO(data))
    return gzip.compress(raw.getvalue(), mtime=0)


def sha1(b):
    return hashlib.sha1(b).hexdigest()


def sha256(b):
    return hashlib.sha256(b).hexdigest()


# ----------------------------------------------------------------- Maven
def jar(group, artifact, declared_version):
    props = (
        "#Generated by Maven\n"
        f"groupId={group}\nartifactId={artifact}\nversion={declared_version}\n"
    )
    return zip_bytes(
        [
            ("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\nCreated-By: dtf\n\n"),
            (f"META-INF/maven/{group}/{artifact}/pom.properties", props),
            (f"META-INF/maven/{group}/{artifact}/pom.xml", pom(group, artifact, declared_version)),
        ]
    )


def pom(group, artifact, version):
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<project xmlns="http://maven.apache.org/POM/4.0.0">\n'
        "  <modelVersion>4.0.0</modelVersion>\n"
        f"  <groupId>{group}</groupId>\n  <artifactId>{artifact}</artifactId>\n"
        f"  <version>{version}</version>\n  <packaging>jar</packaging>\n</project>\n"
    ).encode()


def add_maven(group, artifact, version, declared=None, bad_sha=False, with_pom=True):
    base = f"maven2/{group.replace('.', '/')}/{artifact}/{version}/{artifact}-{version}"
    body = jar(group, artifact, declared or version)
    FILES[base + ".jar"] = body
    FILES[base + ".jar.sha1"] = (sha1(b"not-these-bytes") if bad_sha else sha1(body)).encode()
    if with_pom:
        p = pom(group, artifact, version)
        FILES[base + ".pom"] = p
        FILES[base + ".pom.sha1"] = sha1(p).encode()


add_maven("org.apache.logging.log4j", "log4j-core", "2.14.1")
add_maven("org.apache.commons", "commons-text", "1.9")
add_maven("com.example.dtfscan", "dtf-clean", "1.0.0")
add_maven("com.example.dtfscan", "dtf-liar", "2.0.0", declared="1.0.0", with_pom=False)
add_maven("com.example.dtfscan", "dtf-badsha", "1.0.0", bad_sha=True, with_pom=False)


# ----------------------------------------------------------------- NuGet
def nuspec(pkg_id, version, xml_decl):
    head = '<?xml version="1.0" encoding="utf-8"?>\n' if xml_decl else ""
    return (
        head
        + '<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">\n'
        "  <metadata>\n"
        f"    <id>{pkg_id}</id>\n    <version>{version}</version>\n"
        "    <authors>dtf</authors>\n    <description>dtf scan fixture</description>\n"
        "  </metadata>\n</package>\n"
    ).encode()


NUGET_VERSIONS = {}


def add_nuget(pkg_id, version, declared=None, xml_decl=True):
    low = pkg_id.lower()
    spec = nuspec(pkg_id, declared or version, xml_decl)
    body = zip_bytes(
        [
            (f"{pkg_id}.nuspec", spec),
            ("lib/netstandard2.0/_._", b""),
            (
                "[Content_Types].xml",
                '<?xml version="1.0" encoding="utf-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                '<Default Extension="nuspec" ContentType="application/octet" /></Types>',
            ),
        ]
    )
    base = f"nuget/v3-flatcontainer/{low}/{version}"
    FILES[f"{base}/{low}.{version}.nupkg"] = body
    FILES[f"{base}/{low}.nuspec"] = spec
    NUGET_VERSIONS.setdefault(low, []).append(version)


add_nuget("Newtonsoft.Json", "12.0.1")
add_nuget("Dtf.ScanClean", "1.0.0")
add_nuget("Dtf.ScanLiar", "2.0.0", declared="1.0.0")
for low, versions in NUGET_VERSIONS.items():
    FILES[f"nuget/v3-flatcontainer/{low}/index.json"] = json.dumps({"versions": versions}).encode()
FILES["nuget/v3/index.json"] = json.dumps(
    {
        "version": "3.0.0",
        "resources": [
            {"@id": f"{SELF}/nuget/v3-flatcontainer/", "@type": "PackageBaseAddress/3.0.0"},
            {"@id": f"{SELF}/nuget/v3/registration/", "@type": "RegistrationsBaseUrl/3.6.0"},
            {"@id": f"{SELF}/nuget/v3/query", "@type": "SearchQueryService"},
        ],
    }
).encode()


# ----------------------------------------------------------------- Cargo
def sparse_prefix(name):
    n = len(name)
    if n == 1:
        return "1"
    if n == 2:
        return "2"
    if n == 3:
        return f"3/{name[0]}"
    return f"{name[0:2]}/{name[2:4]}"


CARGO_INDEX = {}


def add_crate(name, version, declared=None, bad_cksum=False):
    body = crate_bytes(
        f"{name}-{version}",
        f'[package]\nname = "{name}"\nversion = "{declared or version}"\nedition = "2018"\n'
        'description = "dtf scan fixture"\nlicense = "MIT"\n',
    )
    FILES[f"cargo/api/v1/crates/{name}/{version}/download"] = body
    entry = {
        "name": name,
        "vers": version,
        "deps": [],
        "cksum": sha256(b"not-these-bytes") if bad_cksum else sha256(body),
        "features": {},
        "yanked": False,
    }
    CARGO_INDEX.setdefault(name, []).append(json.dumps(entry))


add_crate("regex", "1.5.4")
add_crate("dtf-scanclean", "1.0.0")
add_crate("dtf-scanliar", "2.0.0", declared="1.0.0")
add_crate("dtf-badsum", "1.0.0", bad_cksum=True)
for name, lines in CARGO_INDEX.items():
    FILES[f"cargo/{sparse_prefix(name)}/{name}"] = ("\n".join(lines) + "\n").encode()
FILES["cargo/config.json"] = json.dumps({"dl": f"{SELF}/cargo/api/v1/crates"}).encode()


# ----------------------------------------------------------------- Go
def go_zip(module, version, gomod, prefix_version=None):
    prefix = f"{module}@{prefix_version or version}/"
    return zip_bytes([(prefix + "go.mod", gomod), (prefix + "dtf.go", "package dtf\n")])


def add_go(module, version, requires=(), prefix_version=None):
    gomod = f"module {module}\n\ngo 1.21\n" + "".join(f"\nrequire {m} {v}\n" for m, v in requires)
    base = f"goproxy/{module}/@v"
    FILES[f"{base}/{version}.zip"] = go_zip(module, version, gomod, prefix_version)
    FILES[f"{base}/{version}.mod"] = gomod.encode()
    FILES[f"{base}/{version}.info"] = json.dumps({"Version": version, "Time": "2020-01-01T00:00:00Z"}).encode()
    FILES[f"{base}/list"] = f"{version}\n".encode()


add_go("example.com/dtfscan/vulnmod", "v1.0.0", requires=[("golang.org/x/text", "v0.3.0")])
add_go("example.com/dtfscan/cleanmod", "v1.0.0")
add_go("example.com/dtfscan/liarmod", "v2.0.0", prefix_version="v1.0.0")
# #4952: a module whose own coordinate has an advisory and whose zip requires
# nothing; graded vulnerable only when the scan pins the requested module.
add_go("golang.org/x/text", "v0.3.0")


# ----------------------------------------------------------------- RubyGems
def gem_bytes(name, declared_version):
    spec = (
        "--- !ruby/object:Gem::Specification\n"
        f"name: {name}\n"
        "version: !ruby/object:Gem::Version\n"
        f"  version: {declared_version}\n"
        "platform: ruby\n"
        "summary: dtf scan fixture\n"
    ).encode()
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as t:
        for entry, data in (
            ("metadata.gz", gzip.compress(spec, mtime=0)),
            ("data.tar.gz", gzip.compress(b"", mtime=0)),
        ):
            ti = tarfile.TarInfo(entry)
            ti.size = len(data)
            ti.mtime = 1577836800
            ti.mode = 0o644
            t.addfile(ti, io.BytesIO(data))
    return raw.getvalue()


def add_gem(name, version, declared=None):
    FILES[f"rubygems/gems/{name}-{version}.gem"] = gem_bytes(name, declared or version)


add_gem("rack", "2.0.7")
add_gem("dtf-scanclean", "1.0.0")
add_gem("dtf-scanliar", "2.0.0", declared="1.0.0")


# ----------------------------------------------------------------- Composer
COMPOSER_REF = "0123456789abcdef0123456789abcdef01234567"


def add_composer(name, version, declared=None, lock_packages=()):
    pkg = name.split("/")[1]
    top = f"{name.replace('/', '-')}-0123456/"
    entries = [(top + "composer.json", json.dumps({"name": declared or name, "type": "library"}))]
    if lock_packages:
        lock = {
            "packages": [
                {"name": n, "version": v, "type": "library",
                 "dist": {"type": "zip", "url": "https://example.invalid/x.zip", "reference": "x"}}
                for n, v in lock_packages
            ],
            "packages-dev": [],
        }
        entries.append((top + "composer.lock", json.dumps(lock)))
    entries.append((top + "src/Dtf.php", "<?php\n"))
    FILES[f"composer/zipball/{pkg}.zip"] = zip_bytes(entries)
    FILES[f"composer/p2/{name}.json"] = json.dumps(
        {
            "packages": {
                name: [
                    {
                        "name": name,
                        "version": version,
                        "dist": {
                            "type": "zip",
                            "url": f"{SELF}/composer/zipball/{pkg}.zip",
                            "reference": COMPOSER_REF,
                        },
                    }
                ]
            }
        }
    ).encode()


add_composer("dtf/vulnpkg", "1.0.0", lock_packages=[("guzzlehttp/guzzle", "6.5.0")])
add_composer("dtf/cleanpkg", "1.0.0")
add_composer("dtf/liarpkg", "1.0.0", declared="other/pkg")
# #4952: the vulnerable package itself, with no lockfile inside.
add_composer("guzzlehttp/guzzle", "6.5.0")
FILES["composer/packages.json"] = json.dumps({"metadata-url": "/composer/p2/%package%.json", "packages": []}).encode()


# ----------------------------------------------------------------- tar.gz
def tar_gz(entries):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as t:
        for entry, data in entries:
            data = data.encode() if isinstance(data, str) else data
            ti = tarfile.TarInfo(entry)
            ti.size = len(data)
            ti.mtime = 1577836800
            ti.mode = 0o644
            t.addfile(ti, io.BytesIO(data))
    return gzip.compress(raw.getvalue(), mtime=0)


# ----------------------------------------------------------------- Pub
def add_pub(name, version, declared=None):
    spec = f"name: {name}\nversion: {declared or version}\ndescription: dtf scan fixture\nenvironment:\n  sdk: '>=2.12.0 <4.0.0'\n"
    FILES[f"pub/packages/{name}/versions/{version}.tar.gz"] = tar_gz(
        [("pubspec.yaml", spec), ("lib/dtf.dart", "void dtf() {}\n")]
    )


add_pub("http", "0.12.0")
add_pub("dtf_scanclean", "1.0.0")
add_pub("dtf_scanliar", "2.0.0", declared="1.0.0")


# ----------------------------------------------------------------- Conan
CONAN_RREV = "0123456789abcdef0123456789abcdef"


def add_conan(name, version, requires=(), broken=False, note=None):
    base = f"conan/v2/conans/{name}/{version}/_/_/revisions/{CONAN_RREV}/files"
    conanfile = f"from conan import ConanFile\nclass Dtf(ConanFile):\n    name = '{name}'\n    version = '{version}'\n"
    FILES[f"{base}/conanfile.py"] = conanfile.encode()
    FILES[f"{base}/conanmanifest.txt"] = b"1577836800\nconanfile.py: 0\n"
    if broken:
        FILES[f"{base}/conan_sources.tgz"] = b"this is not a gzipped tar"
        return
    txt = "[requires]\n" + "".join(f"{r}\n" for r in requires)
    if note:
        # Distinct bytes per reference: verdicts are stored per digest.
        txt = f"# {note}\n" + txt
    FILES[f"{base}/conan_sources.tgz"] = tar_gz(
        [("conanfile.txt", txt), ("src/dtf.c", "int dtf(void) { return 0; }\n")]
    )


add_conan("dtfvuln", "1.0.0", requires=["openssl/1.1.1k"])
add_conan("dtfclean", "1.0.0")
add_conan("dtfliar", "1.0.0", broken=True)
# #4952: the vulnerable reference itself, requiring nothing.
add_conan("openssl", "1.1.1k", note="openssl/1.1.1k")


# ----------------------------------------------------------------- CocoaPods / Swift
RACK_GEMFILE_LOCK = (
    "GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (2.0.7)\n\n"
    "PLATFORMS\n  ruby\n\nDEPENDENCIES\n  rack (= 2.0.7)\n"
)


def add_pod(name, version, declared=None, vendored_lock=False):
    spec = json.dumps({"name": name, "version": declared or version, "summary": "dtf scan fixture"})
    entries = [(f"{name}.podspec.json", spec), ("Sources/Dtf.swift", "struct Dtf {}\n")]
    if vendored_lock:
        entries.append(("Gemfile.lock", RACK_GEMFILE_LOCK))
    FILES[f"cocoapods/pods/{name}-{version}.tar.gz"] = tar_gz(entries)


add_pod("DtfVulnPod", "1.0.0", vendored_lock=True)
add_pod("DtfCleanPod", "1.0.0")
add_pod("DtfLiarPod", "2.0.0", declared="1.0.0")


def add_swift(scope, name, version, vendored_lock=False, manifest=True):
    entries = [(f"{name}/Sources/Dtf/Dtf.swift", "struct Dtf {}\n")]
    if manifest:
        entries.insert(0, (f"{name}/Package.swift",
                           "// swift-tools-version:5.5\nimport PackageDescription\n"
                           f"let package = Package(name: \"{name}\")\n"))
    if vendored_lock:
        entries.append((f"{name}/Gemfile.lock", RACK_GEMFILE_LOCK))
    FILES[f"swift/{scope}/{name}/{version}.zip"] = zip_bytes(entries)


add_swift("dtf", "vulnpkg", "1.0.0", vendored_lock=True)
add_swift("dtf", "cleanpkg", "1.0.0")
add_swift("dtf", "liarpkg", "1.0.0", manifest=False)


# ----------------------------------------------------------------- OS packages
# Debian, RPM and Alpine packages (#4111, #4112, #4113). A lone OS package
# names no distribution release, so the backend grades it through a synthetic
# installed system on the release the remote names (Debian: the cached
# Release; RPM: the dist tag; Alpine: the branch). The packages are minimal
# but real: an ar .deb with control.tar.gz and data.tar.gz, an RPM v3 lead +
# signature header + main header + cpio.gz payload, and an .apk of three
# gzip members (signature, control with .PKGINFO, data).
def tar_raw(entries, eof=True):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as t:
        for name, data in entries:
            data = data.encode() if isinstance(data, str) else data
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            ti.mtime = 1577836800
            ti.mode = 0o644
            t.addfile(ti, io.BytesIO(data))
    out = raw.getvalue()
    if not eof:
        # apk segments are tar streams cut before the end-of-archive blocks.
        out = out.rstrip(b"\0")
        out += b"\0" * ((-len(out)) % 512)
    return out


def ar_member(name, data):
    head = f"{name:<16}{0:<12}{0:<6}{0:<6}{'100644':<8}{len(data):<10}`\n".encode()
    return head + data + (b"\n" if len(data) % 2 else b"")


def deb_bytes(package, version, arch="amd64", source=None, declared=None):
    control = f"Package: {package}\n"
    if source:
        control += f"Source: {source}\n"
    control += (
        f"Version: {declared or version}\nArchitecture: {arch}\n"
        "Maintainer: DTF <dtf@example.invalid>\nDescription: dtf scan fixture\n"
    )
    ctl = gzip.compress(tar_raw([("./control", control)]), mtime=0)
    data = gzip.compress(tar_raw([("./usr/share/doc/" + package + "/README", "dtf\n")]), mtime=0)
    return b"!<arch>\n" + ar_member("debian-binary", b"2.0\n") + ar_member(
        "control.tar.gz", ctl
    ) + ar_member("data.tar.gz", data)


def add_deb(base, component, package, version, arch="amd64", source=None, declared=None):
    src = source or package
    path = f"pool/{component}/{src[0]}/{src}/{package}_{version}_{arch}.deb"
    FILES[f"{base}/{path}"] = deb_bytes(package, version, arch, source, declared)
    return path


def rpm_header(entries):
    # entries: [(tag, type, bytes, count)]; type 6 STRING, 4 INT32, 8 STRING_ARRAY
    index, store = b"", b""
    for tag, typ, data, count in entries:
        if typ == 4:
            store += b"\0" * ((-len(store)) % 4)
        index += tag.to_bytes(4, "big") + typ.to_bytes(4, "big")
        index += len(store).to_bytes(4, "big") + count.to_bytes(4, "big")
        store += data
    return (
        b"\x8e\xad\xe8\x01\0\0\0\0"
        + len(entries).to_bytes(4, "big")
        + len(store).to_bytes(4, "big")
        + index
        + store
    )


def rpm_bytes(name, version, release, arch, epoch=None, declared=None, sourcerpm=None):
    s = lambda v: v.encode() + b"\0"
    lead = b"\xed\xab\xee\xdb\x03\x00\x00\x00\x00\x01"
    lead += name.encode()[:65].ljust(66, b"\0")
    lead += b"\x00\x01\x00\x05" + b"\0" * 16
    assert len(lead) == 96
    sig = rpm_header([(1000, 4, (0).to_bytes(4, "big"), 1)])  # RPMSIGTAG_SIZE
    sig += b"\0" * ((-len(sig)) % 8)
    entries = [
        (1000, 6, s(name), 1),
        (1001, 6, s(declared or version), 1),
        (1002, 6, s(release), 1),
        (1004, 6, s("dtf scan fixture"), 1),  # SUMMARY
        (1014, 6, s("MIT"), 1),  # LICENSE
        (1022, 6, s(arch), 1),
        (1044, 6, s(sourcerpm or f"{name}-{version}-{release}.src.rpm"), 1),
        (1124, 6, s("cpio"), 1),  # PAYLOADFORMAT
        (1125, 6, s("gzip"), 1),  # PAYLOADCOMPRESSOR
    ]
    if epoch is not None:
        entries.append((1003, 4, int(epoch).to_bytes(4, "big"), 1))
    entries.sort(key=lambda e: e[0])
    trailer = b"070701" + b"0" * 8 * 13 + b"0000000B" + b"00000000" + b"TRAILER!!!\0"
    trailer += b"\0" * ((-len(trailer)) % 4)
    return lead + sig + rpm_header(entries) + gzip.compress(trailer, mtime=0)


def add_rpm(base, name, version, release, arch, epoch=None, declared=None, sourcerpm=None):
    path = f"9/BaseOS/x86_64/os/Packages/{name[0]}/{name}-{version}-{release}.{arch}.rpm"
    FILES[f"{base}/{path}"] = rpm_bytes(name, version, release, arch, epoch, declared, sourcerpm)
    return path


def apk_bytes(pkgname, pkgver, arch="x86_64", origin=None, declared=None, desc="dtf scan fixture"):
    info = (
        f"# Generated by dtf\npkgname = {pkgname}\npkgver = {declared or pkgver}\n"
        f"pkgdesc = {desc}\narch = {arch}\nlicense = MIT\n"
    )
    if origin:
        info += f"origin = {origin}\n"
    sig = gzip.compress(tar_raw([(".SIGN.RSA.dtf.rsa.pub", b"not a signature")], eof=False), mtime=0)
    ctl = gzip.compress(tar_raw([(".PKGINFO", info)], eof=False), mtime=0)
    data = gzip.compress(tar_raw([("usr/share/doc/" + pkgname + "/README", "dtf\n")]), mtime=0)
    return sig + ctl + data


def add_apk(base, branch, pkgname, pkgver, arch="x86_64", origin=None, declared=None):
    path = f"{branch}/main/{arch}/{pkgname}-{pkgver}.apk"
    # The branch is in the description so each branch's bytes (and so its
    # digest-keyed verdict) are its own.
    FILES[f"{base}/{path}"] = apk_bytes(pkgname, pkgver, arch, origin, declared, f"dtf scan fixture ({branch})")
    return path


# Debian (upstream base http://<self>/debian): a bookworm Release, so the
# packages are graded on Debian 12. debian-norel has no Release at all.
FILES["debian/dists/bookworm/Release"] = (
    "Origin: Debian\nLabel: Debian\nSuite: stable\nVersion: 12.7\nCodename: bookworm\n"
    "Date: Wed, 01 Jan 2020 00:00:00 UTC\nArchitectures: amd64\nComponents: main\n"
    "Description: dtf scan fixture\n"
).encode()
add_deb("debian", "main", "openssl", "3.0.11-1~deb12u2")
add_deb("debian", "main", "dtf-scanclean", "1.0-1")
add_deb("debian", "main", "dtf-scanliar", "2.0-1", declared="1.0-1")
add_deb("debian-norel", "main", "dtf-norelease", "1.0-1")
# RPM (upstream base http://<self>/rpm): the yum layout dnf fetches.
add_rpm("rpm", "openssl-libs", "3.0.7", "17.el9_2", "x86_64", epoch=1,
        sourcerpm="openssl-3.0.7-17.el9_2.src.rpm")
add_rpm("rpm", "dtf-scanclean", "1.0", "1.el9", "noarch")
add_rpm("rpm", "dtf-scanliar", "2.0", "1.el9", "noarch", declared="1.0")
add_rpm("rpm", "dtf-notag", "1.0", "1", "noarch")
# A non-package file in the yum tree (install media): an RPM Remote cannot
# establish what it is served as; no scanner catalogs anything in it.
FILES["rpm/9/BaseOS/x86_64/os/images/boot.iso"] = b"".join(
    b"dtf install media block %06d\n" % i for i in range(2048)
)
FILES["rpm/9/BaseOS/x86_64/os/repodata/repomd.xml"] = (
    b'<?xml version="1.0" encoding="UTF-8"?>\n<repomd xmlns="http://linux.duke.edu/metadata/repo">'
    b"<revision>1577836800</revision></repomd>\n"
)
# Alpine (upstream base http://<self>/alpine).
add_apk("alpine", "v3.19", "busybox", "1.36.1-r15", origin="busybox")
add_apk("alpine", "v3.19", "dtf-scanclean", "1.0-r0")
add_apk("alpine", "v3.19", "dtf-scanliar", "2.0-r0", declared="1.0-r0")
add_apk("alpine", "latest-stable", "dtf-scanclean", "1.0-r0")


def ctype(path):
    if path.endswith(".json") or path.endswith("config.json"):
        return "application/json"
    if path.endswith(".pom") or path.endswith(".nuspec"):
        return "application/xml"
    if path.endswith(".sha1"):
        return "text/plain"
    return "application/octet-stream"


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        print("mock-scan: " + (fmt % args), flush=True)

    def _send(self, code, data, ct="application/octet-stream", head=False):
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if not head:
            self.wfile.write(data)

    def _serve(self, head):
        raw = self.path
        url = urlsplit(raw)
        q = parse_qs(url.query)
        if url.path == "/__readyz":
            return self._send(200, b"ok", "text/plain", head)
        if url.path == "/__hits":
            p = q.get("prefix", [""])[0]
            with LOCK:
                n = sum(1 for h in HITS if h.startswith(p))
            return self._send(200, json.dumps({"prefix": p, "count": n}).encode(), "application/json", head)
        if url.path.startswith("/__golden/"):
            key = url.path[len("/__golden/"):]
            if key in FILES:
                return self._send(200, FILES[key], "application/octet-stream", head)
            return self._send(404, b"no such fixture", "text/plain", head)
        if url.path.startswith("/__sha256/"):
            key = url.path[len("/__sha256/"):]
            if key in FILES:
                return self._send(200, sha256(FILES[key]).encode(), "text/plain", head)
            return self._send(404, b"no such fixture", "text/plain", head)
        if not head:
            with LOCK:
                HITS.append(raw)
        key = url.path.lstrip("/")
        if key in FILES:
            return self._send(200, FILES[key], ctype(key), head)
        return self._send(404, b"not found", "text/plain", head)

    def do_GET(self):
        self._serve(False)

    def do_HEAD(self):
        self._serve(True)


if __name__ == "__main__":
    print(f"mock-scan: {len(FILES)} fixtures, self={SELF}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
