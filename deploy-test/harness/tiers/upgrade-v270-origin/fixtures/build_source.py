#!/usr/bin/env python3
# =============================================================================
# build_source.py OUTDIR: the migration SOURCE files for upgrade-v270-origin
# =============================================================================
# Writes, under OUTDIR, one directory per mock Artifactory repository (see
# profiles/upstreams.mock-artifactory-docker.yml):
#
#   dtfcat-gen/   (packageType generic)
#     upg/alpha.bin        64 KiB of deterministic bytes
#     upg/beta.txt         a short text file
#
#   dtfcat-docker/ (packageType docker), Artifactory's on-disk image layout
#     dtfmig/1.0/manifest.json        a schema-2 manifest (config + 1 layer)
#     dtfmig/1.0/sha256__<config>     the config blob
#     dtfmig/1.0/sha256__<layer>      the layer blob
#
# Every byte is deterministic, so the oracle can recompute digests. Stdlib only.
# =============================================================================
import hashlib
import json
import os
import sys


def write(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)


def main(out):
    alpha = b"".join(hashlib.sha256(b"alpha-%d" % i).digest() for i in range(2048))
    write(os.path.join(out, "dtfcat-gen", "upg", "alpha.bin"), alpha)
    write(os.path.join(out, "dtfcat-gen", "upg", "beta.txt"),
          b"upgrade-v270-origin beta fixture (artifact-keeper#4153)\n")

    config = json.dumps(
        {"architecture": "amd64", "os": "linux",
         "rootfs": {"type": "layers", "diff_ids": []},
         "dtf": "upgrade-v270-origin migrated image"},
        separators=(",", ":"), sort_keys=True).encode()
    layer = b"".join(hashlib.sha256(b"layer-%d" % i).digest() for i in range(1024))
    cfg_d = hashlib.sha256(config).hexdigest()
    lay_d = hashlib.sha256(layer).hexdigest()
    manifest = json.dumps(
        {"schemaVersion": 2,
         "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
         "config": {"mediaType": "application/vnd.docker.container.image.v1+json",
                    "size": len(config), "digest": "sha256:" + cfg_d},
         "layers": [{"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                     "size": len(layer), "digest": "sha256:" + lay_d}]},
        separators=(",", ":")).encode()
    img = os.path.join(out, "dtfcat-docker", "dtfmig", "1.0")
    write(os.path.join(img, "manifest.json"), manifest)
    write(os.path.join(img, "sha256__" + cfg_d), config)
    write(os.path.join(img, "sha256__" + lay_d), layer)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: build_source.py OUTDIR")
    main(sys.argv[1])
