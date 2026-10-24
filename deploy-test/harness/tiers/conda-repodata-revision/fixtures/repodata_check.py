#!/usr/bin/env python3
# =============================================================================
# repodata_check.py: decode one served repodata document and report where a
#   package filename appears (conda-repodata-revision tier)
# =============================================================================
# Stdlib only; needs Python 3.14+ for `compression.zstd`, so the tier runs it in
# a throwaway python:3.14-slim container.
#
#   repodata_check.py <encoding> <filename> < document
#
# <encoding> is json, zst or bz2. Prints one JSON object:
#   {"packages": <n records>, "listed": bool, "removed": bool,
#    "trailing_bytes": <bytes after the first bzip2 stream, bz2 only>}
#   or {"error": "<why>"}
# =============================================================================
import bz2
import json
import sys


def main():
    encoding, filename = sys.argv[1], sys.argv[2]
    raw = sys.stdin.buffer.read()
    out = {}
    try:
        if encoding == "zst":
            from compression import zstd
            plain = zstd.decompress(raw)
        elif encoding == "bz2":
            # One stream only: the file 1.11 served and every reader handles.
            dec = bz2.BZ2Decompressor()
            plain = dec.decompress(raw)
            out["trailing_bytes"] = len(dec.unused_data)
        else:
            plain = raw
        doc = json.loads(plain)
    except Exception as e:  # noqa: BLE001 - reported to the oracle
        print(json.dumps({"error": f"{type(e).__name__}: {e}"}))
        return
    pkgs = dict(doc.get("packages") or {})
    pkgs.update(doc.get("packages.conda") or {})
    out["packages"] = len(pkgs)
    out["listed"] = filename in pkgs
    out["removed"] = filename in (doc.get("removed") or [])
    print(json.dumps(out))


main()
