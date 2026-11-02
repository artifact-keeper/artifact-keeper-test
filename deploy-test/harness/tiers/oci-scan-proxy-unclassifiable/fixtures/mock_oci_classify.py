#!/usr/bin/env python3
# =============================================================================
# mock_oci_classify.py - an OCI upstream serving manifests the backend's serde
# parser and a Go client read differently, for the oci-scan-proxy-unclassifiable
# tier (artifact-keeper#5097)
# =============================================================================
# Manifest bodies are raw strings on purpose: duplicate keys and case-variant
# keys do not survive a JSON serializer. Every tag serves under image `app`.
#
#   Unclassifiable (runnable to Docker, unclassifiable to the gate):
#     case-keys       "Config" / "Layers"
#     dup-config      a Helm "config", then the image "config" (Go: last wins)
#     manifests-null  "manifests": null next to a real image
#     layer-case      a layer descriptor with an in-toto mediaType and a rootfs
#                     "MediaType"
#     non-ascii-key   "confİg", which Go folds onto "config"
#     unknown-config  an unknown config media type over a rootfs layer
#   Refused by the schema1 rule:
#     schema1         a Docker schema1 manifest
#   Positively not an image (the gate skips them):
#     pure-index, helm-chart, flux-artifact, cosign-attestation
#   Runnable (the gate scans it; config and layer are real blobs):
#     runnable        an ordinary one-layer image
#
# Endpoints:
#   GET /v2/                                       200 {}
#   GET /v2/<image>/manifests/<tag or digest>      the body above
#   GET /v2/<image>/blobs/<digest>                 config and layer of `runnable`
#   GET /__digests                                 {tag: digest}
#   GET /__log                                     requests seen, one per line
#   GET /__readyz                                  healthcheck
# Stdlib only, single file, stock python image. MOCK_PORT: listen port (80).
# =============================================================================
import gzip
import hashlib
import io
import json
import os
import tarfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("MOCK_PORT", "80"))
IMAGE_MT = "application/vnd.oci.image.manifest.v1+json"
INDEX_MT = "application/vnd.oci.image.index.v1+json"
CONFIG_MT = "application/vnd.oci.image.config.v1+json"
LAYER_MT = "application/vnd.oci.image.layer.v1.tar+gzip"
A = "sha256:" + "a" * 64
B = "sha256:" + "b" * 64
CFG = '{"mediaType":"%s","digest":"%s","size":3}' % (CONFIG_MT, A)
HELM_CFG = '{"mediaType":"application/vnd.cncf.helm.config.v1+json","digest":"%s","size":3}' % A
LAYERS = '[{"mediaType":"%s","digest":"%s","size":3}]' % (LAYER_MT, B)
HEAD = '"schemaVersion":2,"mediaType":"%s"' % IMAGE_MT


def runnable_blobs():
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tar:
        # One inert npm package, so the scanner grades a non-empty catalog: a
        # scan that finds no components is inconclusive, not clean.
        for name, data in (
            ("etc/os-release", b'ID="dtf"\nVERSION_ID="1"\n'),
            ("app/node_modules/dtf-inert/package.json", b'{"name":"dtf-inert","version":"1.0.0"}\n'),
        ):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mtime = 0
            tar.addfile(info, io.BytesIO(data))
    layer = gzip.compress(raw.getvalue(), mtime=0)
    diff_id = "sha256:" + hashlib.sha256(raw.getvalue()).hexdigest()
    config = json.dumps(
        {"architecture": "amd64", "os": "linux", "config": {},
         "rootfs": {"type": "layers", "diff_ids": [diff_id]}},
        separators=(",", ":"),
    ).encode()
    return config, layer


RUN_CONFIG, RUN_LAYER = runnable_blobs()


def sha(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


BLOBS = {sha(RUN_CONFIG): RUN_CONFIG, sha(RUN_LAYER): RUN_LAYER}
BODIES = {
    "case-keys": ('{%s,"Config":%s,"Layers":%s}' % (HEAD, CFG, LAYERS), IMAGE_MT),
    "dup-config": ('{%s,"config":%s,"layers":%s,"config":%s}' % (HEAD, HELM_CFG, LAYERS, CFG), IMAGE_MT),
    "manifests-null": ('{%s,"config":%s,"layers":%s,"manifests":null}' % (HEAD, CFG, LAYERS), IMAGE_MT),
    "layer-case": (
        '{%s,"config":%s,"layers":[{"mediaType":"application/vnd.in-toto+json","MediaType":"%s","digest":"%s","size":3}]}'
        % (HEAD, CFG, LAYER_MT, B),
        IMAGE_MT,
    ),
    "non-ascii-key": ('{%s,"confİg":%s,"layers":%s}' % (HEAD, CFG, LAYERS), IMAGE_MT),
    "unknown-config": (
        '{%s,"config":{"mediaType":"application/vnd.example.config.v1+json","digest":"%s","size":3},"layers":%s}'
        % (HEAD, A, LAYERS),
        IMAGE_MT,
    ),
    "schema1": (
        json.dumps({"schemaVersion": 1, "name": "app", "tag": "schema1",
                    "fsLayers": [{"blobSum": A}], "history": [{"v1Compatibility": "{}"}],
                    "signatures": [{"protected": "e30"}]}),
        "application/vnd.docker.distribution.manifest.v1+prettyjws",
    ),
    "pure-index": (
        json.dumps({"schemaVersion": 2, "mediaType": INDEX_MT,
                    "manifests": [{"mediaType": IMAGE_MT, "digest": A, "size": 3,
                                   "platform": {"architecture": "amd64", "os": "linux"}}]}),
        INDEX_MT,
    ),
    "helm-chart": (
        json.dumps({"schemaVersion": 2,
                    "config": {"mediaType": "application/vnd.cncf.helm.config.v1+json", "digest": A, "size": 3},
                    "layers": [{"mediaType": "application/vnd.cncf.helm.chart.content.v1.tar+gzip", "digest": B, "size": 3}]}),
        IMAGE_MT,
    ),
    "flux-artifact": (
        json.dumps({"schemaVersion": 2,
                    "config": {"mediaType": "application/vnd.cncf.flux.config.v1+json", "digest": A, "size": 3},
                    "layers": [{"mediaType": "application/vnd.cncf.flux.content.v1.tar+gzip", "digest": B, "size": 3}]}),
        IMAGE_MT,
    ),
    "cosign-attestation": (
        json.dumps({"schemaVersion": 2, "mediaType": IMAGE_MT,
                    "config": {"mediaType": CONFIG_MT, "digest": A, "size": 3},
                    "layers": [{"mediaType": "application/vnd.dsse.envelope.v1+json", "digest": B, "size": 3}]}),
        IMAGE_MT,
    ),
    "runnable": (
        json.dumps({"schemaVersion": 2, "mediaType": IMAGE_MT,
                    "config": {"mediaType": CONFIG_MT, "digest": sha(RUN_CONFIG), "size": len(RUN_CONFIG)},
                    "layers": [{"mediaType": LAYER_MT, "digest": sha(RUN_LAYER), "size": len(RUN_LAYER)}]}),
        IMAGE_MT,
    ),
}
MANIFESTS = {}
DIGESTS = {}
for tag, (text, media_type) in BODIES.items():
    raw_body = text.encode("utf-8")
    DIGESTS[tag] = sha(raw_body)
    MANIFESTS[tag] = (raw_body, media_type)
    MANIFESTS[DIGESTS[tag]] = (raw_body, media_type)
LOG = []


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, code, body, ctype="application/json", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/__readyz":
            return self._send(200, b"ok", "text/plain")
        if path == "/__digests":
            return self._send(200, json.dumps(DIGESTS).encode())
        if path == "/__log":
            return self._send(200, "\n".join(LOG).encode(), "text/plain")
        LOG.append(f"{self.command} {path}")
        if path == "/v2/":
            return self._send(200, b"{}")
        parts = path.split("/")
        if len(parts) >= 5 and parts[1] == "v2" and parts[-2] == "manifests":
            hit = MANIFESTS.get(parts[-1])
            if hit:
                return self._send(200, hit[0], hit[1], {"Docker-Content-Digest": sha(hit[0])})
        if len(parts) >= 5 and parts[1] == "v2" and parts[-2] == "blobs":
            blob = BLOBS.get(parts[-1])
            if blob:
                return self._send(200, blob, "application/octet-stream", {"Docker-Content-Digest": parts[-1]})
        return self._send(404, b'{"errors":[{"code":"MANIFEST_UNKNOWN"}]}')

    do_HEAD = do_GET

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
