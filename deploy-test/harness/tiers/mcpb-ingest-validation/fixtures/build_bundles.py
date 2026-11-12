#!/usr/bin/env python3
"""Build the MCPB fixtures of the mcpb-ingest-validation tier.

usage: build_bundles.py OUT_DIR SLUG VERSION

Writes one .mcpb per case into OUT_DIR. Every archive is otherwise a valid
bundle: a root manifest.json whose name is SLUG and whose version is VERSION,
plus server/index.js. Each case adds exactly one defect, so a refusal can
only be about that defect.

The ZIP writer is hand-rolled (stored entries, no compression) because the
defects need byte-level control that zipfile does not give: a name that is
not UTF-8 under the UTF-8 flag, a local header name that differs from the
central directory name, and a symlink mode.
"""
import json
import os
import struct
import sys
import zlib

UNIX = 3
S_IFREG = 0o100644
S_IFLNK = 0o120777
FLAG_UTF8 = 0x0800


def entry(name, data=b"", mode=S_IFREG, local_name=None, flags=FLAG_UTF8):
    """name and local_name are bytes; data is bytes."""
    return {"name": name, "local": local_name if local_name is not None else name,
            "data": data, "mode": mode, "flags": flags}


def write_zip(path, entries):
    out = bytearray()
    central = bytearray()
    for e in entries:
        crc = zlib.crc32(e["data"]) & 0xFFFFFFFF
        size = len(e["data"])
        offset = len(out)
        out += struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, e["flags"], 0, 0, 0x21,
                           crc, size, size, len(e["local"]), 0)
        out += e["local"] + e["data"]
        central += struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, (UNIX << 8) | 20, 20,
                               e["flags"], 0, 0, 0x21, crc, size, size, len(e["name"]),
                               0, 0, 0, 0, (e["mode"] << 16) & 0xFFFFFFFF, offset)
        central += e["name"]
    cd_offset = len(out)
    out += central
    n = len(entries)
    out += struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, n, n, len(central), cd_offset, 0)
    with open(path, "wb") as f:
        f.write(out)


def manifest(slug, version, description="Release-gate MCPB fixture"):
    return {
        "manifest_version": "0.2",
        "name": slug,
        "display_name": "AK DTF echo",
        "version": version,
        "description": description,
        "author": {"name": "Artifact Keeper DTF"},
        "server": {"type": "node", "entry_point": "server/index.js",
                   "mcp_config": {"command": "node", "args": ["${__dirname}/server/index.js"]}},
        "tools": [{"name": "echo", "description": "Return the text argument unchanged."}],
    }


def main():
    out_dir, slug, version = sys.argv[1:4]
    os.makedirs(out_dir, exist_ok=True)
    m = json.dumps(manifest(slug, version), indent=2).encode()
    js = b"process.stdin.pipe(process.stdout);\n"
    base = [entry(b"manifest.json", m), entry(b"server/index.js", js)]

    def case(name, entries):
        write_zip(os.path.join(out_dir, name + ".mcpb"), entries)

    # controls
    case("ok", base)
    # exactly 10,000 entries in all (manifest + server/index.js + 9,998 fillers)
    case("entries-10000", base + [entry(b"filler/%05d" % i) for i in range(9998)])
    # #5467: 10,001 entries in all
    case("entries-10001", base + [entry(b"filler/%05d" % i) for i in range(9999)])
    # #5468: a second manifest.json (also valid, other description)
    m2 = json.dumps(manifest(slug, version, "A second, different manifest")).encode()
    case("dup-manifest", base + [entry(b"manifest.json", m2)])
    # #5468: one manifest whose description key appears twice (both values valid)
    dupkey = m.replace(b'"description": "Release-gate MCPB fixture",',
                       b'"description": "first value", "description": "Release-gate MCPB fixture",', 1)
    assert dupkey != m
    case("dup-json-key", [entry(b"manifest.json", dupkey), entry(b"server/index.js", js)])
    # #5469: unsafe paths and a symlink
    case("path-parent", base + [entry(b"../escape.txt", b"x")])
    case("path-absolute", base + [entry(b"/etc/escape.txt", b"x")])
    case("path-drive", base + [entry(b"C:/escape.txt", b"x")])
    case("path-backslash", base + [entry(b"server\\escape.txt", b"x")])
    case("symlink", base + [entry(b"server/link", b"/etc/passwd", mode=S_IFLNK)])
    # #5470: a name that is not UTF-8 under the UTF-8 flag, and a local
    # header whose name differs from the central directory's
    case("name-not-utf8", base + [entry(b"server/bad-\xff\xfe.txt", b"x")])
    case("name-central-local", base + [entry(b"server/aaa.js", js, local_name=b"server/bbb.js")])


if __name__ == "__main__":
    main()
