#!/usr/bin/env python3
# =============================================================================
# repodata_records.py: decode one repodata document read from stdin and print
# {"records": {filename: indexed_timestamp-or-null}, "error": null}.
# =============================================================================
# argv[1] is the encoding: json, bz2 or zst. Stdlib only; zst needs Python
# 3.14 (`compression.zstd`), so the tiers run it in python:3.14-slim. Used by
# the conda-age-gate and conda-cep47-coverage tiers (artifact-keeper#6526,
# #6530).
# =============================================================================
import bz2
import json
import sys


def main():
    enc = sys.argv[1] if len(sys.argv) > 1 else "json"
    raw = sys.stdin.buffer.read()
    try:
        if enc == "bz2":
            raw = bz2.decompress(raw)
        elif enc == "zst":
            from compression import zstd

            raw = zstd.decompress(raw)
        doc = json.loads(raw)
    except Exception as e:  # noqa: BLE001 - report, never crash the oracle
        print(json.dumps({"records": {}, "error": f"{type(e).__name__}: {e}"}))
        return
    out = {}
    for section in ("packages", "packages.conda"):
        for fn, rec in (doc.get(section) or {}).items():
            out[fn] = rec.get("indexed_timestamp") if isinstance(rec, dict) else None
    print(json.dumps({"records": out, "error": None}, sort_keys=True))


if __name__ == "__main__":
    main()
