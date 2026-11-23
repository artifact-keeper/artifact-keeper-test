#!/usr/bin/env python3
"""Deterministic conda fixture channel generator (artifact-keeper#4187).

Writes a conda channel of N package names x V versions x B builds, as both
``.conda`` (v2) and ``.tar.bz2`` (v1) packages, with real ``info/index.json``
dependency edges, plus lockfiles (pixi.lock v6 and ``@EXPLICIT``) for
environments of the first K names. Same arguments and seed, same bytes:
every archive is built with fixed timestamps, owners, modes and member order,
and ``MANIFEST.sha256`` lists the sha256 of every file it wrote.

Stdlib only. ``.conda`` needs ``compression.zstd`` (Python 3.14+);
``gen-channel.sh`` runs this in ``python:3.14-slim`` when the host Python
lacks it.

Subcommands:
  channel  generate the channel (and, with --locks, its lockfiles)
  locks    write lockfiles for an already generated channel, for any
           channel URL (so a test can point a lock at its own server)
  package  build one package (fixtures/conda/build.sh delegates here)
"""

from __future__ import annotations

import argparse
import bz2
import hashlib
import io
import json
import os
import random
import sys
import tarfile
import time
import zipfile
from concurrent.futures import ProcessPoolExecutor

GENERATOR_VERSION = "1"
# Fixed package timestamp (ms): 2020-01-01T00:00:00Z. Upstream mocks serve a
# matching Last-Modified, so a Package Age Policy hold does not apply to them
# unless a test asks for it.
FIXED_TIMESTAMP_MS = 1577836800000
ZIP_EPOCH = (1980, 1, 1, 0, 0, 0)
ZSTD_LEVEL = 3
NAME_PREFIX = "dtfs"


def _zstd():
    try:
        from compression import zstd  # type: ignore[import-not-found]
    except ImportError:
        return None
    return zstd


# --------------------------------------------------------------------------
# Archive helpers: everything fixed, so output is byte-identical.
# --------------------------------------------------------------------------
def _tar_bytes(members: list[tuple[str, bytes]]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for path, data in members:
            info = tarfile.TarInfo(path)
            info.size = len(data)
            info.mtime = 0
            info.mode = 0o644
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _zip_bytes(members: list[tuple[str, bytes]]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
        for path, data in members:
            zi = zipfile.ZipInfo(path, date_time=ZIP_EPOCH)
            zi.external_attr = 0o644 << 16
            zi.create_system = 3
            zf.writestr(zi, data)
    return buf.getvalue()


def _json(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def build_package(name, version, build, build_number, subdir, depends, fmt, marker):
    """Return (filename, bytes, index_record) for one package."""
    marker_path = f"share/{name}/marker.txt"
    marker_data = (marker + "\n").encode()
    index = {
        "name": name,
        "version": version,
        "build": build,
        "build_number": build_number,
        "depends": depends,
        "license": "MIT",
        "subdir": subdir,
        "timestamp": FIXED_TIMESTAMP_MS,
    }
    if subdir == "noarch":
        index["noarch"] = "generic"
    else:
        index["platform"] = subdir.split("-", 1)[0]
        index["arch"] = {"64": "x86_64", "aarch64": "aarch64"}.get(
            subdir.split("-", 1)[-1], subdir.split("-", 1)[-1]
        )
    paths = {
        "paths_version": 1,
        "paths": [
            {
                "_path": marker_path,
                "path_type": "hardlink",
                "sha256": hashlib.sha256(marker_data).hexdigest(),
                "size_in_bytes": len(marker_data),
            }
        ],
    }
    info_members = [
        ("info/files", (marker_path + "\n").encode()),
        ("info/index.json", _json(index)),
        ("info/paths.json", _json(paths)),
    ]
    pkg_members = [(marker_path, marker_data)]
    stem = f"{name}-{version}-{build}"
    if fmt == "conda":
        zstd = _zstd()
        if zstd is None:
            raise SystemExit(
                "gen_channel: .conda needs compression.zstd (Python 3.14+); "
                "run through gen-channel.sh, which falls back to python:3.14-slim"
            )
        outer = [
            ("metadata.json", _json({"conda_pkg_format_version": 2})),
            (f"info-{stem}.tar.zst", zstd.compress(_tar_bytes(info_members), level=ZSTD_LEVEL)),
            (f"pkg-{stem}.tar.zst", zstd.compress(_tar_bytes(pkg_members), level=ZSTD_LEVEL)),
        ]
        data = _zip_bytes(outer)
        filename = stem + ".conda"
    else:
        data = bz2.compress(_tar_bytes(info_members + pkg_members), compresslevel=9)
        filename = stem + ".tar.bz2"
    record = dict(index)
    record["md5"] = hashlib.md5(data).hexdigest()
    record["sha256"] = hashlib.sha256(data).hexdigest()
    record["size"] = len(data)
    return filename, data, record


# --------------------------------------------------------------------------
# The channel model: pure functions of (args, seed), shared by every worker.
# --------------------------------------------------------------------------
class Model:
    def __init__(self, names, versions, builds, subdirs, deps, seed, formats, noarch_every):
        self.names = names
        self.versions = versions
        self.builds = builds
        self.subdirs = subdirs
        self.deps = deps
        self.seed = seed
        self.formats = formats
        self.noarch_every = noarch_every

    def name(self, i):
        return f"{NAME_PREFIX}-{i:05d}"

    def subdir(self, i):
        arch = [s for s in self.subdirs if s != "noarch"]
        if "noarch" in self.subdirs and (not arch or i % self.noarch_every == 0):
            return "noarch"
        return arch[i % len(arch)]

    def version(self, i, j):
        # Major j+1 orders the versions; the minor varies per name.
        rng = random.Random(f"{self.seed}:ver:{i}:{j}")
        return f"{j + 1}.{rng.randrange(10)}.0"

    def build_string(self, i, j, b):
        h = hashlib.sha256(f"{self.seed}:build:{i}:{j}:{b}".encode()).hexdigest()[:8]
        return f"h{h}_{b}"

    def fmt(self, i, b):
        if self.formats != "mixed":
            return self.formats
        return "conda" if (i + b) % 2 == 0 else "tar.bz2"

    def dep_indices(self, i):
        """D distinct names below i: a DAG, so any prefix of names is closed."""
        if i == 0 or self.deps == 0:
            return []
        rng = random.Random(f"{self.seed}:deps:{i}")
        k = min(self.deps, i)
        # Mostly near neighbours (deep chains), sometimes far back (fan-in).
        picks = set()
        while len(picks) < k:
            if rng.random() < 0.7:
                picks.add(max(0, i - 1 - rng.randrange(min(i, 25))))
            else:
                picks.add(rng.randrange(i))
        return sorted(picks)

    def depends(self, i, j):
        # Version j+1 of a package needs each dependency at major >= j+1
        # (capped at the dependency's own newest major) and below the next
        # major after that, so older dependency versions are real solver
        # rejections, and the newest of everything is always consistent.
        out = []
        for d in self.dep_indices(i):
            lo = min(j + 1, self.versions)
            out.append(f"{self.name(d)} >={lo},<{lo + 1}")
        return out


def _gen_name(args):
    model, i, out = args
    name = model.name(i)
    subdir = model.subdir(i)
    records = []
    for j in range(model.versions):
        version = model.version(i, j)
        depends = model.depends(i, j)
        for b in range(model.builds):
            build = model.build_string(i, j, b)
            fmt = model.fmt(i, b)
            marker = f"DTF-SCALE {name} {version} {build}"
            filename, data, record = build_package(
                name, version, build, b, subdir, depends, fmt, marker
            )
            path = os.path.join(out, subdir, filename)
            with open(path, "wb") as fh:
                fh.write(data)
            records.append((subdir, filename, record))
    return records


def write_repodata(out, subdirs, records):
    for subdir in subdirs:
        doc = {
            "info": {"subdir": subdir},
            "packages": {},
            "packages.conda": {},
            "removed": [],
            "repodata_version": 1,
        }
        for sd, filename, record in records:
            if sd != subdir:
                continue
            key = "packages.conda" if filename.endswith(".conda") else "packages"
            doc[key][filename] = record
        with open(os.path.join(out, subdir, "repodata.json"), "wb") as fh:
            fh.write(json.dumps(doc, sort_keys=True, indent=1).encode() + b"\n")


def write_manifest(out, header):
    lines = []
    for root, _dirs, files in os.walk(out):
        for f in files:
            if f == "MANIFEST.sha256":
                continue
            p = os.path.join(root, f)
            rel = os.path.relpath(p, out)
            with open(p, "rb") as fh:
                lines.append(f"{hashlib.sha256(fh.read()).hexdigest()}  {rel}")
    lines.sort(key=lambda s: s.split("  ", 1)[1])
    with open(os.path.join(out, "MANIFEST.sha256"), "w") as fh:
        for h in header:
            fh.write(f"# {h}\n")
        fh.write("\n".join(lines) + "\n")


# --------------------------------------------------------------------------
# Lockfiles
# --------------------------------------------------------------------------
def load_channel(channel):
    """{name: (subdir, filename, record)} for the newest build of each name."""
    best = {}
    for subdir in sorted(os.listdir(channel)):
        rd = os.path.join(channel, subdir, "repodata.json")
        if not os.path.isfile(rd):
            continue
        with open(rd) as fh:
            doc = json.load(fh)
        for key in ("packages", "packages.conda"):
            for filename, rec in doc.get(key, {}).items():
                rank = (int(rec["version"].split(".")[0]), rec["build_number"])
                cur = best.get(rec["name"])
                if cur is None or rank > cur[0]:
                    best[rec["name"]] = (rank, subdir, filename, rec)
    return {n: v[1:] for n, v in best.items()}


def write_locks(channel, sizes, channel_url, out, platform):
    channel_url = channel_url.rstrip("/")
    newest = load_channel(channel)
    names = sorted(newest)
    os.makedirs(out, exist_ok=True)
    written = []
    for size in sizes:
        chosen = names[: min(size, len(names))]
        label = f"env-{size // 1000}k" if size % 1000 == 0 else f"env-{size}"
        entries = []
        for n in chosen:
            subdir, filename, rec = newest[n]
            entries.append((f"{channel_url}/{subdir}/{filename}", rec))
        entries.sort(key=lambda e: e[0])
        # pixi.lock v6. Hand-written YAML: every scalar here is safe unquoted
        # except the depends specs, which are quoted.
        y = ["version: 6", "environments:", "  default:", "    channels:",
             f"    - url: {channel_url}/", "    packages:", f"      {platform}:"]
        for url, _ in entries:
            y.append(f"      - conda: {url}")
        y.append("packages:")
        for url, rec in entries:
            y.append(f"- conda: {url}")
            y.append(f"  sha256: {rec['sha256']}")
            y.append(f"  md5: {rec['md5']}")
            if rec["depends"]:
                y.append("  depends:")
                for d in rec["depends"]:
                    y.append(f"  - {json.dumps(d)}")
            else:
                y.append("  depends: []")
            if rec.get("noarch"):
                y.append(f"  noarch: {rec['noarch']}")
            y.append("  license: MIT")
            y.append(f"  size: {rec['size']}")
            y.append(f"  timestamp: {rec['timestamp']}")
        base = os.path.join(out, label)
        os.makedirs(base, exist_ok=True)
        with open(os.path.join(base, "pixi.lock"), "w") as fh:
            fh.write("\n".join(y) + "\n")
        with open(os.path.join(base, "explicit.txt"), "w") as fh:
            fh.write(f"# platform: {platform}\n@EXPLICIT\n")
            for url, rec in entries:
                fh.write(f"{url}#{rec['md5']}\n")
        with open(os.path.join(base, "urls.tsv"), "w") as fh:
            for url, rec in entries:
                fh.write(f"{url}\t{rec['sha256']}\t{rec['size']}\n")
        written.append((label, len(entries)))
    return written


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def cmd_channel(a):
    t0 = time.monotonic()
    subdirs = [s for s in a.subdirs.split(",") if s]
    model = Model(a.names, a.versions, a.builds, subdirs, a.deps_per_package, a.seed,
                  a.formats, a.noarch_every)
    if a.formats in ("mixed", "conda") and _zstd() is None:
        raise SystemExit("gen_channel: .conda output needs compression.zstd (Python 3.14+)")
    os.makedirs(a.out, exist_ok=True)
    used = sorted({model.subdir(i) for i in range(a.names)} | ({"noarch"} if "noarch" in subdirs else set()))
    for sd in used:
        os.makedirs(os.path.join(a.out, sd), exist_ok=True)
    jobs = a.jobs or min(32, os.cpu_count() or 1)
    work = [(model, i, a.out) for i in range(a.names)]
    records = []
    if jobs == 1:
        for w in work:
            records.extend(_gen_name(w))
    else:
        with ProcessPoolExecutor(max_workers=jobs) as pool:
            for recs in pool.map(_gen_name, work, chunksize=max(1, a.names // (jobs * 8))):
                records.extend(recs)
    write_repodata(a.out, used, records)
    locks = []
    if a.locks:
        sizes = [int(s) for s in a.locks.split(",") if s]
        locks = write_locks(a.out, sizes, a.channel_url, os.path.join(a.out, "locks"),
                            a.lock_platform)
    zstd = _zstd()
    header = [
        f"gen_channel v{GENERATOR_VERSION} names={a.names} versions={a.versions} "
        f"builds={a.builds} subdirs={a.subdirs} deps={a.deps_per_package} seed={a.seed} "
        f"formats={a.formats} noarch_every={a.noarch_every} locks={a.locks or '-'} "
        f"channel_url={a.channel_url}",
        f"python={sys.version.split()[0]} zstd={getattr(zstd, 'zstd_version', 'n/a') if zstd else 'n/a'}",
    ]
    write_manifest(a.out, header)
    n_conda = sum(1 for _, f, _ in records if f.endswith(".conda"))
    summary = {
        "out": a.out,
        "artifacts": len(records),
        "conda": n_conda,
        "tar_bz2": len(records) - n_conda,
        "edges": sum(len(r["depends"]) for _, _, r in records),
        "subdirs": used,
        "locks": dict(locks),
        "seconds": round(time.monotonic() - t0, 2),
        "jobs": jobs,
    }
    print(json.dumps(summary, sort_keys=True))


def cmd_locks(a):
    sizes = [int(s) for s in a.sizes.split(",") if s]
    written = write_locks(a.channel, sizes, a.channel_url, a.out, a.lock_platform)
    print(json.dumps(dict(written), sort_keys=True))


def cmd_package(a):
    depends = [d for d in (a.depends or "").split(";") if d]
    filename, data, _ = build_package(a.name, a.version, a.build, a.build_number, a.subdir,
                                      depends, a.format, a.marker)
    os.makedirs(a.out, exist_ok=True)
    path = os.path.join(a.out, filename)
    with open(path, "wb") as fh:
        fh.write(data)
    print(path)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("channel")
    c.add_argument("--names", type=int, default=3000)
    c.add_argument("--versions", type=int, default=5)
    c.add_argument("--builds", type=int, default=2)
    c.add_argument("--subdirs", default="linux-64,noarch")
    c.add_argument("--deps-per-package", type=int, default=3)
    c.add_argument("--seed", default="4187")
    c.add_argument("--formats", choices=["mixed", "conda", "tar.bz2"], default="mixed")
    c.add_argument("--noarch-every", type=int, default=10,
                   help="every Nth name is noarch (when noarch is a subdir)")
    c.add_argument("--locks", default="", help="comma list of lock sizes, e.g. 1000,2000,3000")
    c.add_argument("--channel-url", default="https://fixtures.invalid/dtf-scale")
    c.add_argument("--lock-platform", default="linux-64")
    c.add_argument("--jobs", type=int, default=0)
    c.add_argument("--out", required=True)
    c.set_defaults(func=cmd_channel)

    lk = sub.add_parser("locks")
    lk.add_argument("--channel", required=True)
    lk.add_argument("--sizes", default="1000,2000,3000")
    lk.add_argument("--channel-url", required=True)
    lk.add_argument("--lock-platform", default="linux-64")
    lk.add_argument("--out", required=True)
    lk.set_defaults(func=cmd_locks)

    pk = sub.add_parser("package")
    pk.add_argument("--out", required=True)
    pk.add_argument("--name", required=True)
    pk.add_argument("--version", required=True)
    pk.add_argument("--build", required=True)
    pk.add_argument("--build-number", type=int, default=0)
    pk.add_argument("--subdir", default="noarch")
    pk.add_argument("--format", choices=["conda", "tar.bz2"], default="tar.bz2")
    pk.add_argument("--depends", default="", help="';'-separated match specs")
    pk.add_argument("--marker", required=True)
    pk.set_defaults(func=cmd_package)

    a = p.parse_args(argv)
    a.func(a)


if __name__ == "__main__":
    main()
