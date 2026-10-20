#!/usr/bin/env python3
# =============================================================================
# mock_conda_sharded.py: upstream conda channels that publish CEP-16 sharded
#   repodata, for the conda-sharded-remote-virtual and conda-virtual-shards
#   tiers (artifact-keeper#4577, #4607, #4612, #4608)
# =============================================================================
# Stdlib only, Python 3.14+ (`compression.zstd`); msgpack comes from cep16.py
# beside this file. Every channel lives under its own path prefix, so one
# container serves every upstream a tier points a Remote at:
#
#   /main/    shards ./shards/<sha256>.msgpack.zst (the prefix.dev layout):
#             dtfsh-alpha     2 records, the shard every client reads
#             dtfsh-blocked   1 record, the allowlist's victim
#             dtfsh-owned     1 record (99.0); a hosted member of the tier's
#                             virtual publishes dtfsh-owned too
#             dtfsh-tampered  LISTED at sha256(A), SERVED as different bytes B
#                             (a corrupt or malicious upstream)
#             dtfsh-smuggle   listed under its own name, but its record is
#                             named dtfsh-owned (a name smuggled past the
#                             virtual's ownership guard)
#             `GET /__heal` makes the mock serve the tampered shard's
#             correct bytes from then on (the upstream recovering)
#   /beside/  dtfsh-alpha only, shards_base_url "" (conda.anaconda.org's
#             layout: shards beside the index)
#   /clean/   dtfsh-alpha, dtfsh-beta and dtfsh-gone: a shard that holds no
#             record and one `removed` entry (conda-forge's 90-byte
#             cuda-nvcc_linux-64 shard, #4607)
#   /big/     dtfsh-alpha plus random filler names: the index is served at
#             MOCK_BIG_INDEX_MIB (default 9.5) MiB, past the 8 MiB first-try
#             tier and under the 64 MiB ceiling (#4612)
#   /huge/    the same at MOCK_HUGE_INDEX_MIB (default 70) MiB, past 64 MiB
#   /slow/    no shard index; EVERY request under it is answered after
#             MOCK_SLOW_SECS (default 8) seconds (holds a virtual merge slot,
#             #4608)
#
# Every channel also serves `noarch/repodata.json` (the same packages,
# monolithic, hex digests as JSON requires) and `channeldata.json`; anything
# else (repodata.json.zst / .bz2, other subdirs) is 404.
#
# Each index's `info.base_url` points at the upstream's own (unresolvable)
# host, "https://upstream.invalid/<channel>/noarch/", so a registry that
# forwards the upstream index unrewritten is caught: the rewritten index must
# say "./".
#
# Every request is counted per path; `/__requests` answers the JSON map
# path -> count (the oracles read upstream hits from it), and each request is
# also logged to stdout.
# `/__readyz` answers `ok` once every document is built; `/__manifest` is the
# JSON map of channel -> {name: shard address hex, ...} plus the tampered
# shard's served sha256, so an oracle never recomputes a fixture.
# =============================================================================
import hashlib
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cep16  # noqa: E402

PORT = int(os.environ.get("MOCK_PORT", "80"))
MARKER = os.environ.get("MOCK_MARKER", "dtfmockcondash")
SLOW_SECS = float(os.environ.get("MOCK_SLOW_SECS", "8"))
BIG_MIB = float(os.environ.get("MOCK_BIG_INDEX_MIB", "9.5"))
HUGE_MIB = float(os.environ.get("MOCK_HUGE_INDEX_MIB", "70"))

SUBDIR = "noarch"


def fake_digests(seed):
    return hashlib.sha256(seed.encode()).digest(), hashlib.md5(seed.encode()).digest()  # noqa: S324


def record(name, version):
    sha, md5 = fake_digests(f"{MARKER}/{name}-{version}")
    return {
        "build": "0",
        "build_number": 0,
        "depends": [],
        "license": "MIT",
        "md5": md5,
        "name": name,
        "noarch": "generic",
        "sha256": sha,
        "size": 1024,
        "subdir": SUBDIR,
        "timestamp": 1700000000000,
        "version": version,
    }


def fn(name, version):
    return f"{name}-{version}-0.tar.bz2"


def shard(records, removed=()):
    doc = {
        "packages": {fn(r["name"], r["version"]): r for r in records},
        "packages.conda": {},
        "removed": list(removed),
    }
    return cep16.zstd_frame(cep16.packb(doc))


def json_record(rec):
    out = dict(rec)
    out["sha256"] = rec["sha256"].hex()
    out["md5"] = rec["md5"].hex()
    return out


class Channel:
    def __init__(self, name, shards_base_url="./shards/"):
        self.name = name
        self.shards_base_url = shards_base_url
        self.listed = {}      # package name -> address (bytes)
        self.served = {}      # address hex -> shard bytes served
        self.records = []     # monolithic repodata records
        self.index = b""
        self.filler = b""     # pre-encoded msgpack map entries (big/huge)
        self.filler_count = 0

    def add(self, name, records, removed=(), serve=None):
        body = shard(records, removed)
        address = hashlib.sha256(body).digest()
        self.listed[name] = address
        self.served[address.hex()] = body if serve is None else serve
        self.records.extend(records)

    def build_index(self):
        info = {
            "base_url": f"https://upstream.invalid/{self.name}/{SUBDIR}/",
            "shards_base_url": self.shards_base_url,
            "subdir": SUBDIR,
        }
        shards = bytearray(cep16.map_header(len(self.listed) + self.filler_count))
        for name, address in self.listed.items():
            shards += cep16.packb(name) + cep16.packb(address)
        shards += self.filler
        doc = cep16.map_header(2) + cep16.packb("info") + cep16.packb(info) \
            + cep16.packb("shards") + bytes(shards)
        self.index = cep16.zstd_frame(doc, level=1)

    def fill_to(self, mib):
        """Grow the index with random-address filler names until it is served
        at `mib` MiB or more (32 random bytes per name do not compress)."""
        target = int(mib * 1024 * 1024)
        per_entry = 40  # measured: ~38-39 bytes per filler entry at level 1
        count = target // per_entry
        while True:
            rnd = os.urandom(32 * count)
            parts = []
            for i in range(count):
                parts.append(cep16.packb(f"dtfbig-{i:08d}"))
                parts.append(b"\xc4\x20" + rnd[32 * i:32 * i + 32])
            self.filler = b"".join(parts)
            self.filler_count = count
            self.build_index()
            if len(self.index) >= target:
                return
            count = int(count * (target / len(self.index)) * 1.02) + 1000

    def repodata(self):
        return {
            "info": {"subdir": SUBDIR},
            "packages": {fn(r["name"], r["version"]): json_record(r) for r in self.records},
            "packages.conda": {},
            "removed": [],
            "repodata_version": 1,
        }


def build():
    channels = {}

    main = Channel("main")
    main.add("dtfsh-alpha", [record("dtfsh-alpha", "1.0"), record("dtfsh-alpha", "2.0")])
    main.add("dtfsh-blocked", [record("dtfsh-blocked", "1.0")])
    main.add("dtfsh-owned", [record("dtfsh-owned", "99.0")])
    tampered_served = shard([record("dtfsh-tampered", "6.6.6")])
    main.add("dtfsh-tampered", [record("dtfsh-tampered", "1.0")], serve=tampered_served)
    main.add("dtfsh-smuggle", [record("dtfsh-owned", "66.0")])
    main.build_index()
    channels["main"] = main

    beside = Channel("beside", shards_base_url="")
    beside.add("dtfsh-alpha", [record("dtfsh-alpha", "1.0"), record("dtfsh-alpha", "2.0")])
    beside.build_index()
    channels["beside"] = beside

    clean = Channel("clean")
    clean.add("dtfsh-alpha", [record("dtfsh-alpha", "1.0"), record("dtfsh-alpha", "2.0")])
    clean.add("dtfsh-beta", [record("dtfsh-beta", "3.0")])
    clean.add("dtfsh-gone", [], removed=[fn("dtfsh-gone", "1.0")])
    clean.build_index()
    channels["clean"] = clean

    for name, mib in (("big", BIG_MIB), ("huge", HUGE_MIB)):
        ch = Channel(name)
        ch.add("dtfsh-alpha", [record("dtfsh-alpha", "1.0"), record("dtfsh-alpha", "2.0")])
        ch.fill_to(mib)
        channels[name] = ch

    slow = Channel("slow")
    slow.records.append(record("dtfsh-slow", "1.0"))
    channels["slow"] = slow

    files = {}
    for name, ch in channels.items():
        base = f"/{name}/{SUBDIR}/"
        files[f"{base}repodata.json"] = (
            "application/json", json.dumps(ch.repodata(), sort_keys=True).encode())
        files[f"/{name}/channeldata.json"] = ("application/json", json.dumps({
            "channeldata_version": 1,
            "packages": {r["name"]: {"version": r["version"], "subdirs": [SUBDIR]}
                         for r in ch.records},
            "subdirs": [SUBDIR],
        }).encode())
        if ch.index:
            files[f"{base}repodata_shards.msgpack.zst"] = ("application/x-msgpack", ch.index)
            shard_dir = base + ("shards/" if ch.shards_base_url == "./shards/" else "")
            for hex_address, body in ch.served.items():
                files[f"{shard_dir}{hex_address}.msgpack.zst"] = ("application/x-msgpack", body)

    manifest = {
        name: {
            "shards": {n: a.hex() for n, a in ch.listed.items()},
            "index_bytes": len(ch.index),
            "index_sha256": hashlib.sha256(ch.index).hexdigest() if ch.index else "",
            "shards_base_url": ch.shards_base_url,
        }
        for name, ch in channels.items()
    }
    manifest["main"]["tampered_served_sha256"] = hashlib.sha256(tampered_served).hexdigest()
    tampered_hex = main.listed["dtfsh-tampered"].hex()
    HEAL[f"/main/{SUBDIR}/shards/{tampered_hex}.msgpack.zst"] = (
        "application/x-msgpack", shard([record("dtfsh-tampered", "1.0")]))
    files["/__manifest"] = ("application/json", json.dumps(manifest, sort_keys=True).encode())
    return files, manifest


FILES = {}
HEAL = {}
READY = False
REQUESTS = {}
REQUESTS_LOCK = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, code, ctype, body, head=False):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if not head:
            self.wfile.write(body)

    def _route(self, head):
        path = self.path.split("?", 1)[0]
        while "//" in path:
            path = path.replace("//", "/")
        if path == "/__readyz":
            self._send(200 if READY else 503, "text/plain", b"ok" if READY else b"building", head)
            return
        if path == "/__requests":
            with REQUESTS_LOCK:
                body = json.dumps(REQUESTS, sort_keys=True).encode()
            self._send(200, "application/json", body, head)
            return
        if path == "/__heal":
            FILES.update(HEAL)
            self._send(200, "text/plain", b"healed", head)
            return
        if not path.startswith("/__"):
            with REQUESTS_LOCK:
                REQUESTS[path] = REQUESTS.get(path, 0) + 1
        if path.startswith("/slow/"):
            time.sleep(SLOW_SECS)
        hit = FILES.get(path)
        if hit is None:
            self._send(404, "text/plain", b"not found", head)
            return
        self._send(200, hit[0], hit[1], head)

    def do_GET(self):  # noqa: N802
        self._route(False)

    def do_HEAD(self):  # noqa: N802
        self._route(True)

    def log_message(self, fmt, *args):
        if self.path.startswith("/__readyz"):
            return
        print("mock-conda-sharded: " + fmt % args, flush=True)


if __name__ == "__main__":
    started = time.time()
    FILES, MANIFEST = build()
    READY = True
    print("mock-conda-sharded: built in %.1fs; index bytes: %s" % (
        time.time() - started,
        {k: v["index_bytes"] for k, v in MANIFEST.items()}), flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
