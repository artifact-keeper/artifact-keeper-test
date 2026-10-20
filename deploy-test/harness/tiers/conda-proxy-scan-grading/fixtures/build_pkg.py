#!/usr/bin/env python3
# =============================================================================
# build_pkg.py - build a conda v1 (.tar.bz2) package with a chosen payload,
#                for the conda scan-on-proxy tiers
# =============================================================================
#   build_pkg.py OUT_DIR NAME VERSION BUILD [PATH=CONTENT ...]
#
# Writes OUT_DIR/NAME-VERSION-BUILD.tar.bz2 (noarch) holding info/index.json,
# info/paths.json, info/files and every PATH=CONTENT payload file (CONTENT is
# literal text; "\n" is a newline). A payload of
#   site-packages/<Dist>-<ver>.dist-info/METADATA=Metadata-Version: 2.1\n...
# is what a scanner catalogs as the vendored Python distribution <Dist>; no
# payload at all is a data-only package with nothing to catalog. Members are
# written in sorted order with mtime 0, so the bytes (and the digest the
# proxy verdict is keyed on) depend only on the arguments.
# =============================================================================
import hashlib
import io
import json
import os
import sys
import tarfile


def main(argv):
    if len(argv) < 5:
        print(__doc__ or "usage: build_pkg.py OUT NAME VERSION BUILD [PATH=CONTENT ...]", file=sys.stderr)
        return 2
    out_dir, name, version, build = argv[1:5]
    payload = {}
    for spec in argv[5:]:
        path, _, content = spec.partition("=")
        payload[path] = content.replace("\\n", "\n").encode()
    index = {
        "name": name, "version": version, "build": build, "build_number": 0,
        "noarch": "generic", "platform": None, "subdir": "noarch",
        "depends": [], "license": "MIT",
    }
    paths = {
        "paths_version": 1,
        "paths": [
            {"_path": p, "path_type": "hardlink", "sha256": hashlib.sha256(b).hexdigest(),
             "size_in_bytes": len(b)}
            for p, b in sorted(payload.items())
        ],
    }
    members = {
        "info/index.json": json.dumps(index, sort_keys=True).encode(),
        "info/paths.json": json.dumps(paths, sort_keys=True).encode(),
        "info/files": "".join(p + "\n" for p in sorted(payload)).encode(),
    }
    members.update(payload)
    os.makedirs(out_dir, exist_ok=True)
    fn = os.path.join(out_dir, f"{name}-{version}-{build}.tar.bz2")
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:bz2") as tar:
        for path in sorted(members, key=lambda p: (not p.startswith("info/"), p)):
            data = members[path]
            ti = tarfile.TarInfo(path)
            ti.size = len(data)
            ti.mtime = 0
            ti.mode = 0o644
            tar.addfile(ti, io.BytesIO(data))
    with open(fn, "wb") as fh:
        fh.write(buf.getvalue())
    print(fn)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
