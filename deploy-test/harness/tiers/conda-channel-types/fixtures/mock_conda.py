#!/usr/bin/env python3
# =============================================================================
# mock_conda.py — a canned upstream conda channel for the conda-channel-types
#                 tier (artifact-keeper#4708 / #4711)
# =============================================================================
# A static, stdlib-only conda channel. At startup it builds, in memory, one
# `noarch` subdir carrying EVERY sibling document a real channel can publish,
# each stamped with a marker string so the oracle can tell an UPSTREAM document
# apart from one Artifact Keeper built itself:
#
#   noarch/repodata.json            three records: dtfup-alpha 1.0 and 2.0, and
#                                   dtfup-blocked 1.0 (the allowlist's victim)
#   noarch/current_repodata.json    ONLY dtfup-alpha 2.0, `info.dtf_marker`
#                                   = "<MARKER>-current"
#   noarch/run_exports.json         dtfup-alpha 2.0 with weak run_export
#                                   "<MARKER>-runexp"
#   noarch/patch_instructions.json  `remove` names "<MARKER>-removed-1.0-0.tar.bz2"
#   noarch/repodata.json.sig        the bytes "<MARKER>-SIG\n" (opaque: a remote
#                                   must proxy it, never re-sign it)
#   noarch/dtfup-alpha-2.0-0.tar.bz2  a real v1 package (info/index.json), whose
#                                   size + sha256 are the ones repodata.json lists
#   channeldata.json                minimal
#
# Anything else (repodata.json.zst / .bz2, other subdirs) answers 404, which is
# what makes AK's virtual merge fall through its candidate list to the plain
# JSON (virtual_merge::fetch_remote_members moves on only on a 404).
#
# Three further channels live under path prefixes, for the
# conda-virtual-merge-policy tier (artifact-keeper#4555 / #4192 / #4601); a
# remote whose upstream URL ends in the prefix sees only that channel:
#
#   /m2/    publishes noarch/repodata.json ONLY as repodata.json.bz2 (one
#           record, dtfm2-only 1.0), and no channeldata.json and no other
#           subdir: a virtual must try the compressed encodings and treat a
#           404 for channeldata / a subdir as "contributes nothing".
#   /fail/  answers 500 to everything: a member that cannot be fetched.
#   /big/   publishes a ~2 MiB noarch/repodata.json (padding records): over a
#           lowered CONDA_VIRTUAL_MEMBER_MAX_BYTES.
#   /huge/  publishes a ~140 MiB noarch/repodata.json, past the backend's
#           128 MiB LARGE_METADATA_MAX_BYTES buffered ceiling (conda-channel-
#           types, artifact-keeper#4149). Built on first request, not at
#           startup, so tiers that never ask for it pay nothing.
#
#   /synth/ publishes noarch/repodata.json ONLY as repodata.json.bz2 and no
#           CEP-16 shard index, and its record set can grow at run time:
#           `POST /__synth/add?name=<n>&version=<v>` adds a record (the
#           conda-remote-shards-synth tier, artifact-keeper#4178, adds a
#           package upstream and expects it after the remote's refresh).
#           Starts with dtfsyn-alpha 1.0 (.tar.bz2), dtfsyn-alpha 2.0 (.conda)
#           and dtfsyn-beta 1.0.
#
# Env: MOCK_PORT (default 80), MOCK_MARKER (default dtfmockconda).
# `/__readyz` answers `ok` for the compose healthcheck.
# =============================================================================
import bz2
import hashlib
import io
import json
import os
import tarfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("MOCK_PORT", "80"))
MARKER = os.environ.get("MOCK_MARKER", "dtfmockconda")


def build_package(name, version, build):
    """A minimal conda v1 package: a bzip2 tar holding info/index.json."""
    index = {
        "name": name,
        "version": version,
        "build": build,
        "build_number": 0,
        "noarch": "generic",
        "platform": None,
        "subdir": "noarch",
        "depends": [],
        "license": "MIT",
    }
    raw = json.dumps(index).encode()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:bz2") as tar:
        info = tarfile.TarInfo("info/index.json")
        info.size = len(raw)
        info.mtime = 0
        tar.addfile(info, io.BytesIO(raw))
    return buf.getvalue()


def record(name, version, blob=None):
    rec = {
        "name": name,
        "version": version,
        "build": "0",
        "build_number": 0,
        "depends": [],
        "license": "MIT",
        "noarch": "generic",
        "subdir": "noarch",
        "timestamp": 1700000000000,
    }
    if blob is not None:
        rec["size"] = len(blob)
        rec["sha256"] = hashlib.sha256(blob).hexdigest()
        rec["md5"] = hashlib.md5(blob).hexdigest()  # noqa: S324 (conda field)
    else:
        rec["size"] = 1024
        rec["sha256"] = hashlib.sha256(f"{name}-{version}".encode()).hexdigest()
        rec["md5"] = hashlib.md5(f"{name}-{version}".encode()).hexdigest()  # noqa: S324
    return rec


ALPHA2 = build_package("dtfup-alpha", "2.0", "0")
ALPHA1_FN = "dtfup-alpha-1.0-0.tar.bz2"
ALPHA2_FN = "dtfup-alpha-2.0-0.tar.bz2"
BLOCKED_FN = "dtfup-blocked-1.0-0.tar.bz2"

REPODATA = {
    "info": {"subdir": "noarch"},
    "packages": {
        ALPHA1_FN: record("dtfup-alpha", "1.0"),
        ALPHA2_FN: record("dtfup-alpha", "2.0", ALPHA2),
        BLOCKED_FN: record("dtfup-blocked", "1.0"),
    },
    "packages.conda": {},
    "removed": [],
    "repodata_version": 1,
}

CURRENT = {
    "info": {"subdir": "noarch", "dtf_marker": f"{MARKER}-current"},
    "packages": {ALPHA2_FN: REPODATA["packages"][ALPHA2_FN]},
    "packages.conda": {},
    "removed": [],
    "repodata_version": 1,
}

RUN_EXPORTS = {
    "info": {"subdir": "noarch"},
    "packages": {ALPHA2_FN: {"run_exports": {"weak": [f"{MARKER}-runexp"]}}},
    "packages.conda": {},
}

PATCH = {
    "patch_instructions_version": 1,
    "packages": {},
    "packages.conda": {},
    "remove": [f"{MARKER}-removed-1.0-0.tar.bz2"],
    "revoke": [],
}

CHANNELDATA = {
    "channeldata_version": 1,
    "packages": {"dtfup-alpha": {"version": "2.0", "subdirs": ["noarch"]}},
    "subdirs": ["noarch"],
}


def js(doc):
    return json.dumps(doc, indent=2, sort_keys=True).encode()


M2_FN = "dtfm2-only-1.0-0.tar.bz2"
M2_REPODATA = {
    "info": {"subdir": "noarch"},
    "packages": {M2_FN: record("dtfm2-only", "1.0")},
    "packages.conda": {},
    "removed": [],
    "repodata_version": 1,
}
BIG_REPODATA = {
    "info": {"subdir": "noarch"},
    "packages": {
        f"dtfbig-pad{i:05d}-1.0-0.tar.bz2": dict(record(f"dtfbig-pad{i:05d}", "1.0"), summary="x" * 512)
        for i in range(2600)
    },
    "packages.conda": {},
    "removed": [],
    "repodata_version": 1,
}

HUGE_PATH = "/huge/noarch/repodata.json"
HUGE_RECORDS = 1400
HUGE_PAD = 100 * 1024
_huge = []
_huge_lock = threading.Lock()


def huge_repodata():
    """~140 MiB repodata.json: HUGE_RECORDS records with 100 KiB summaries."""
    with _huge_lock:
        if not _huge:
            pad = "p" * HUGE_PAD
            doc = {
                "info": {"subdir": "noarch"},
                "packages": {
                    f"dtfhuge-{i:05d}-1.0-0.tar.bz2": dict(record(f"dtfhuge-{i:05d}", "1.0"), summary=pad)
                    for i in range(HUGE_RECORDS)
                },
                "packages.conda": {},
                "removed": [],
                "repodata_version": 1,
            }
            _huge.append(json.dumps(doc, separators=(",", ":")).encode())
        return _huge[0]


PREFIXED = {
    "/m2/noarch/repodata.json.bz2": ("application/x-bzip2", bz2.compress(js(M2_REPODATA))),
    "/big/noarch/repodata.json": ("application/json", js(BIG_REPODATA)),
}

FILES = {
    "/noarch/repodata.json": ("application/json", js(REPODATA)),
    "/noarch/current_repodata.json": ("application/json", js(CURRENT)),
    "/noarch/run_exports.json": ("application/json", js(RUN_EXPORTS)),
    "/noarch/patch_instructions.json": ("application/json", js(PATCH)),
    "/noarch/repodata.json.sig": ("application/octet-stream", f"{MARKER}-SIG\n".encode()),
    f"/noarch/{ALPHA2_FN}": ("application/x-bzip2", ALPHA2),
    "/channeldata.json": ("application/json", js(CHANNELDATA)),
}


SYNTH_LOCK = threading.Lock()
SYNTH = {"packages": {}, "packages.conda": {}}


def synth_add(name, version, ext=".tar.bz2"):
    fn = f"{name}-{version}-0{ext}"
    section = "packages.conda" if ext == ".conda" else "packages"
    with SYNTH_LOCK:
        SYNTH[section][fn] = record(name, version)


synth_add("dtfsyn-alpha", "1.0")
synth_add("dtfsyn-alpha", "2.0", ".conda")
synth_add("dtfsyn-beta", "1.0")


def synth_repodata_bz2():
    with SYNTH_LOCK:
        doc = {
            "info": {"subdir": "noarch"},
            "packages": dict(SYNTH["packages"]),
            "packages.conda": dict(SYNTH["packages.conda"]),
            "removed": [],
            "repodata_version": 1,
        }
    return bz2.compress(js(doc))


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
        if path == "/__readyz":
            self._send(200, "text/plain", b"ok", head)
            return
        # Tolerate a doubled slash from an upstream URL that ends in "/".
        while "//" in path:
            path = path.replace("//", "/")
        if path.startswith("/fail/"):
            self._send(500, "text/plain", b"mock-conda: forced failure", head)
            return
        if path == "/synth/noarch/repodata.json.bz2":
            self._send(200, "application/x-bzip2", synth_repodata_bz2(), head)
            return
        if path.startswith("/synth/"):
            self._send(404, "text/plain", b"not found", head)
            return
        if path == HUGE_PATH:
            self._send(200, "application/json", huge_repodata(), head)
            return
        if path.startswith(("/m2/", "/big/", "/huge/")):
            hit = PREFIXED.get(path)
        else:
            hit = FILES.get(path)
        if hit is None:
            self._send(404, "text/plain", b"not found", head)
            return
        self._send(200, hit[0], hit[1], head)

    def do_GET(self):  # noqa: N802
        self._route(False)

    def do_HEAD(self):  # noqa: N802
        self._route(True)

    def do_POST(self):  # noqa: N802
        from urllib.parse import parse_qs, urlsplit

        parts = urlsplit(self.path)
        if parts.path != "/__synth/add":
            self._send(404, "text/plain", b"not found")
            return
        q = parse_qs(parts.query)
        name, version = q.get("name", [""])[0], q.get("version", ["1.0"])[0]
        if not name:
            self._send(400, "text/plain", b"name required")
            return
        synth_add(name, version)
        self._send(200, "text/plain", b"ok")

    def log_message(self, fmt, *args):
        print("mock-conda: " + fmt % args, flush=True)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
